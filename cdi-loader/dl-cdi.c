/* CDI extensions to the linker/loader
   Copyright (C) 1995-2016 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

// shotgun the dependencies for now: use all headers that rtld.c does
#include <errno.h>                                                              
#include <dlfcn.h>                                                              
#include <fcntl.h>                                                              
#include <stdbool.h>                                                            
#include <stdlib.h>                                                             
#include <string.h>                                                             
#include <unistd.h>                                                             
#include <sys/mman.h>                                                           
#include <sys/param.h>                                                          
#include <sys/stat.h>                                                           
#include <ldsodefs.h>                                                           
#include <_itoa.h>                                                              
#include <entry.h>                                                              
#include <fpu_control.h>                                                        
#include <hp-timing.h>                                                          
#include <libc-lock.h>                                                          
#include "dynamic-link.h"                                                       
#include <dl-librecon.h>                                                        
#include <unsecvars.h>                                                          
#include <dl-cache.h>                                                           
#include <dl-osinfo.h>                                                          
#include <dl-procinfo.h>                                                        
#include <tls.h>                                                                
#include <stap-probe.h>                                                         
#include <stackinfo.h>                                                          

#include <assert.h>              

#include <link.h>
#include <dl-cdi.h>

Elf64_Word _clb_tablen = 0;
CLB *_clb_table = 0;
CDI_Metadata_Sections *_cdi_mdata = 0;

void _cdi_init(CDI_Header *cdi_header) {
    _cdi_mdata = malloc(sizeof(CDI_Metadata_Sections));
    _cdi_mdata->header    = cdi_header;
    _cdi_mdata->strtab    = 0;
    _cdi_mdata->libstrtab = 0;
    _cdi_mdata->multtab   = 0;

    /* Fill _cdi_mdata with the metadata sections */
    for (int i = 0; i < cdi_header->num_entries; i++) {
        switch (cdi_header->entries[i].sect_id) {
            case 0:
                _cdi_mdata->strtab = ((char*)cdi_header) 
                    + cdi_header->entries[i].hdr_off;
                break;
            case 1:
                _cdi_mdata->multtab = (void*)(((char*)cdi_header) 
                    + cdi_header->entries[i].hdr_off);
                break;
            case 2:
                _cdi_mdata->libstrtab = ((char*)cdi_header) 
                    + cdi_header->entries[i].hdr_off;
                break;
        }
    }

    /* the multiplicity table begins with the number of shared libraries */
    _clb_tablen = *((Elf64_Word*) _cdi_mdata->multtab);
    _clb_table = malloc(_clb_tablen * sizeof(CLB));

    CDI_Multtab_Block *multtab_block = (CDI_Multtab_Block*)((char*)_cdi_mdata->multtab + 4);
    for (int i = 0; i < _clb_tablen; i++) {
        /* Each multtab_block is associated with a code object. Create their
         * CLBs here. Initialize as much as we can */
        _clb_table[i].soname = _cdi_mdata->libstrtab + multtab_block->soname_idx;
        _clb_table[i].multtab_block = multtab_block;
        _clb_table[i].slt_size = _cdi_slt_size(
                multtab_block->total_mult, multtab_block->num_used_globals);

        /* advance to the next multiplicity table block */
        multtab_block = (CDI_Multtab_Block*)((char*)multtab_block 
                + sizeof(Elf64_Word) * (4 + multtab_block->num_global_syms));
    }
    _cdi_print_clbs();
}

Elf64_Word _cdi_slt_size(Elf64_Word total_mult, Elf64_Word num_used_syms) {
    /* lea: 7 bytes, cmp: 5 bytes, je: 6 bytes */
    const Elf64_Word sled_mult_size = 7 + 5 + 6;

    /* jmp: 5 bytes */
    const Elf64_Word abort_size = 5;

    /* while this calculation is simple now, it might get complicated in
     * the future if we choose to align SLT sleds */
    return sled_mult_size * total_mult + num_used_syms * abort_size;

}

CLB *_cdi_clb_from_soname(const char *soname_path) {
    /* we need to get rid of the path if it exists */
    int basename_idx = 0;
    for (const char *ptr = soname_path; *ptr; ptr++) {
        if (*ptr == '/') {
            basename_idx = (ptr - soname_path) + 1;
        }
    }

    /* now do a linear search for the matching CLB */
    const char *soname = soname_path + basename_idx;
    for (int i = 0; i < _clb_tablen; i++) {
        if (!_cdi_strcmp(soname, _clb_table[i].soname)) {
            return &_clb_table[i];
        }
    }
    return 0;
}

int _cdi_strcmp(const char *str1, const char *str2) {
    while (*str1) {
        if (*str1 != *str2) {
            return *str1 > *str2 ? 1 : -1;
        }
        str1++;
        str2++;
    }
    return *str2 ? -1 : 0;
}

void _cdi_print_header(const CDI_Header *cdi_header) {
    _dl_debug_printf_c("number of header entries: %u\n", cdi_header->num_entries);
    for (int i = 0; i < cdi_header->num_entries; i++) {
        _dl_debug_printf_c("Header %u\n", i);
        _dl_debug_printf_c("\nheader offset: %u\n",
                cdi_header->entries[i].hdr_off);
        _dl_debug_printf_c("\tsection id: %u\n",
                cdi_header->entries[i].sect_id);
    }
}

void _cdi_print_clbs(void) {
    for (int i = 0; i < _clb_tablen; i++) {
        _cdi_print_clb(_clb_table + i);
    }
}

ElfW(Addr) _cdi_lookup(const char *sym_str, struct link_map *l) {
    const ElfW(Sym) *ref = 0;

    struct r_scope_elem scope;
    struct r_scope_elem *scope_ptr = &scope;

    /* only lookup in the map that was given */
    scope.r_list = &l;
    scope.r_nlist = 1;

    lookup_t lookup = _dl_lookup_symbol_x (sym_str, l, &ref, &scope_ptr, 
            0, 0, DL_LOOKUP_RETURN_NEWEST, 0);
    if (ref != 0) {
        return (ElfW(Addr)) DL_SYMBOL_ADDRESS (lookup, ref);
    }
    else {
        return 0;
    }
}

void _cdi_print_link_map(const struct link_map *l) {
    _dl_debug_printf_c("Link Map for '%s'\n", l->l_name);
    _dl_debug_printf_c("--------------------+------------------\n");
    _dl_debug_printf_c("    l_addr          | %lx\n", l->l_addr);
    _dl_debug_printf_c("    l_ld (dyn sect) | %lx\n", (uintptr_t)l->l_ld);
    _dl_debug_printf_c("    l_removed       | %u\n", l->l_removed);
    _dl_debug_printf_c("    l_real          | %s\n", l->l_real->l_name);
    _dl_debug_printf_c("    l_used          | %u\n", l->l_used);
    _dl_debug_printf_c("    l_origin        | %s\n", l->l_origin);
    _dl_debug_printf_c("                    | \n");
    _dl_debug_printf_c("    l_map_start     | %lx\n", l->l_map_start);
    _dl_debug_printf_c("    l_map_end       | %lx\n", l->l_map_end);
    _dl_debug_printf_c("    l_text_end      | %lx\n", l->l_text_end);
    _dl_debug_printf_c("                    | \n");
    _dl_debug_printf_c("    l_prev          | %s\n", l->l_prev ? l->l_prev->l_name : "N/A");
    _dl_debug_printf_c("    l_next          | %s\n", l->l_next ? l->l_next->l_name : "N/A");
    _dl_debug_printf_c("                    | \n");
    _dl_debug_printf_c("    link_map addr   | %lx\n", (uintptr_t)l);
    _dl_debug_printf_c("    l_real addr     | %lx\n", (uintptr_t)l->l_real);
    _dl_debug_printf_c("--------------------+------------------\n");
    _dl_debug_printf_c("\n");
}

void _cdi_print_clb(const CLB *clb) {
    _dl_debug_printf_c("CLB for '%s' (libstrtab idx %u)\n", 
            clb->soname, (unsigned)(clb->soname - _cdi_mdata->libstrtab));
    _dl_debug_printf_c("--------------------+------------------\n");
    _dl_debug_printf_c("    slt             | %lx\n", (uintptr_t)clb->slt);
    _dl_debug_printf_c("    slt_size        | %u\n", clb->slt_size);
    _dl_debug_printf_c("    slt_tramptab    | %lx\n", (uintptr_t)clb->slt_tramptab);
    _dl_debug_printf_c("                    | \n");
    _dl_debug_printf_c("    multtab_block   | %lx\n", (uintptr_t)clb->multtab_block);
    _dl_debug_printf_c("    total mult      | %u\n", clb->multtab_block->total_mult);
    _dl_debug_printf_c("    num globl fns   | %u\n", clb->multtab_block->num_global_syms);
    _dl_debug_printf_c("    num used globls | %u\n", clb->multtab_block->num_used_globals);
    _dl_debug_printf_c("    parent libname  | %s\n", clb->multtab_block->soname_idx + _cdi_mdata->libstrtab);
    _dl_debug_printf_c("--------------------+------------------\n");
    _dl_debug_printf_c("\n");
}
