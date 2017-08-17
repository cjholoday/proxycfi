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
        _clb_table[i].sl_name = _cdi_mdata->libstrtab + multtab_block->sl_name;
        _clb_table[i].multtab_block = multtab_block;
        _clb_table[i].slt_size = _cdi_slt_size(
                multtab_block->total_mult, multtab_block->num_used_globals);

        /* advance to the next multiplicity table block */
        multtab_block = (CDI_Multtab_Block*)((char*)multtab_block 
                + sizeof(Elf64_Word) * (3 + multtab_block->num_global_syms));
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

void _cdi_print_header(CDI_Header *cdi_header) {
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

void _cdi_print_clb(CLB *clb) {
    _dl_debug_printf_c("CLB for '%s' (libstrtab idx %u)\n", 
            clb->sl_name, (unsigned)(clb->sl_name - _cdi_mdata->libstrtab));
    _dl_debug_printf_c("--------------------+------------------\n");
    _dl_debug_printf_c("    slt             | %lx\n", (uintptr_t)clb->slt);
    _dl_debug_printf_c("    slt_size        | %u\n", clb->slt_size);
    _dl_debug_printf_c("    slt_tramptab    | %lx\n", (uintptr_t)clb->slt_tramptab);
    _dl_debug_printf_c("                    | \n");
    _dl_debug_printf_c("    multtab_block   | %lx\n", (uintptr_t)clb->multtab_block);
    _dl_debug_printf_c("    total mult      | %u\n", clb->multtab_block->total_mult);
    _dl_debug_printf_c("    num globl fns   | %u\n", clb->multtab_block->num_global_syms);
    _dl_debug_printf_c("    num used globls | %u\n", clb->multtab_block->num_used_globals);
    _dl_debug_printf_c("    parent libname  | %s\n", clb->multtab_block->sl_name + _cdi_mdata->libstrtab);
    _dl_debug_printf_c("--------------------+------------------\n");
    _dl_debug_printf_c("\n");
}
