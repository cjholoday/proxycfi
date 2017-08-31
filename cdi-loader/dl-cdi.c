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

    _cdi_find_mdata(cdi_header, _cdi_mdata);

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

void _cdi_build_slt(CLB *clb, struct link_map *main_map) {
    void *slt_used_tail = (char*)clb->slt;
    ElfW(Xword) num_slt_tramps = *((ElfW(Xword)*) clb->tramtab);
    _cdi_print_link_map(clb->l);

    ElfW(Addr) cdi_abort_addr = _cdi_lookup("_CDI_abort", clb->l);

    /* Do a sanity check for compatibility */
    if (num_slt_tramps != clb->multtab_block->num_global_syms) {
        _dl_debug_printf_c("executable and shared library are "
                "incompatible: the executable expected %u global symbols, but "
                "'%s' has %lu global symbols\n", 
                clb->multtab_block->num_global_syms, clb->soname,
                num_slt_tramps);
    }

    /* we'll grab a bit extra from mdata_end but that's okay */
    ElfW(Addr) cdi_strtab_start_page = (uintptr_t)clb->mdata.strtab & ~(GLRO(dl_pagesize) - 1);
    ElfW(Addr) cdi_strtab_end_page = (uintptr_t)clb->mdata.mdata_end & ~(GLRO(dl_pagesize) - 1);

    ElfW(Xword) cdi_strtab_size = cdi_strtab_end_page - cdi_strtab_start_page;
    if (!cdi_strtab_size) {
        /* .cdi_strtab starts and ends on the same page */
        cdi_strtab_size = GLRO(dl_pagesize);
    }

    /* we need to set .cdi_strtab as writable since we'll be prefixing 
     * symbols with _CDI_RLT_. We'll make it read-only after we're done */
    mprotect((void*)cdi_strtab_start_page, cdi_strtab_size, PROT_READ | PROT_WRITE);
    
    /* enable writing into the SLT trampoline table so that we can patch it up 
       notice that the SLT trampoline table is guaranteed to be aligned */
    ElfW(Xword) tramptab_size = (num_slt_tramps + 1) * sizeof(CDI_Trampoline);
    mprotect(clb->tramtab, tramptab_size, PROT_READ | PROT_WRITE);

    /* Index with respect to the second entry so that we increment in 
       lockstep with the multtab block */
    CDI_Trampoline *slt_tramptab = clb->tramtab + 1;
    for (int i = 0; i < num_slt_tramps; i++) {
        /* make the SLT trampoline jump down to the SLT sled */
        ElfW(Sword) offset_to_sled = _cdi_signed_offset(
                (ElfW(Addr))slt_tramptab[i].jmp_bytes + 5, (ElfW(Addr))slt_used_tail);
        memcpy(&slt_tramptab[i].jmp_bytes[1], &offset_to_sled, sizeof(offset_to_sled));
        slt_tramptab[i].jmp_bytes[0] = 0xe9;

        slt_used_tail = _cdi_write_slt_sled(slt_used_tail, &slt_tramptab[i],
                clb->multtab_block->mults[i], clb, main_map, cdi_abort_addr);
    }
        
    mprotect((void*)cdi_strtab_start_page, cdi_strtab_size, PROT_READ);

    /* Disable write access to the SLT and SLT tramploline tables */
    ElfW(Addr) aligned_slt = (ElfW(Addr))clb->slt & ~(GLRO(dl_pagesize) - 1);
    mprotect((void*)aligned_slt, (ElfW(Addr))slt_used_tail - aligned_slt, 
            PROT_READ | PROT_EXEC);
    mprotect(clb->tramtab, tramptab_size, PROT_READ | PROT_EXEC);
}

char *_cdi_write_slt_sled(char *sled_addr, CDI_Trampoline *tramp, 
        ElfW(Word) mult, CLB *clb, struct link_map *main_map, ElfW(Addr) abort_addr) {
    if (mult == 0) {
        return sled_addr;
    }
    char *sled_tail = sled_addr;
    int num_matches_found = 0;

    ElfW(Word) cdi_strtab_idx = tramp->symtab_idx_bytes[0]
        | tramp->symtab_idx_bytes[1] << 8
        | tramp->symtab_idx_bytes[2] << 16;

    /* temporarily overwrite the preceding chars to prefix with _CDI_RLT */
    const int RLT_PREFIX_LEN = 9;
    char *rlt_str = clb->mdata.strtab + cdi_strtab_idx - RLT_PREFIX_LEN;

    char saved_chars[RLT_PREFIX_LEN];
    memcpy(saved_chars, rlt_str, RLT_PREFIX_LEN);
    memcpy(rlt_str, "_CDI_RLT_", RLT_PREFIX_LEN);

    /* inspect the main map first so that it's put first in each SLT sled */
    ElfW(Addr) rlt_addr = _cdi_lookup(rlt_str, main_map);
    if (rlt_addr) {
        sled_tail = _cdi_write_slt_sled_entry(sled_tail, rlt_addr, 0);
        if (++num_matches_found == mult) {
            goto finish_sled;
        }
    }
    for (int j = 0; j < _clb_tablen; j++) {
        /* skip the CLB for which we are building an SLT */
        if (clb == _clb_table + j) {
            continue;
        }

        rlt_addr = _cdi_lookup(rlt_str, _clb_table[j].l);
        if (rlt_addr) {
            sled_tail = _cdi_write_slt_sled_entry(sled_tail, rlt_addr, _clb_table[j].l->l_addr);
            /*
            _dl_debug_printf_c("\tRLT: %lx\n", rlt_addr);
            _dl_debug_printf_c("\tPLT ret addr: %lx\n", *((ElfW(Addr) *)(rlt_addr - 8)));
            */
            if (++num_matches_found == mult) break;
        }
    }

finish_sled:
    /* restore .cdi_strtab */
    memcpy(rlt_str, saved_chars, RLT_PREFIX_LEN);

    /* jmp _CDI_abort */
    ElfW(Sword) offset_to_abort = _cdi_signed_offset(
            (uintptr_t)sled_tail + 5, abort_addr);

    *sled_tail++ = 0xe9;
    memcpy(sled_tail, &offset_to_abort, sizeof(ElfW(Sword)));
    sled_tail += sizeof(ElfW(Sword));

    return sled_tail;
}

ElfW(Sword) _cdi_signed_offset(ElfW(Addr) from_addr, ElfW(Addr) to_addr) {
    if (from_addr > to_addr) {
        return (ElfW(Sword))(from_addr - to_addr) * -1;
    }
    else {
        return (ElfW(Sword))(to_addr - from_addr);
    }
}



char *_cdi_write_slt_sled_entry(char *sled_tail, ElfW(Addr) rlt_addr,
        ElfW(Xword) target_l_addr) {
    /* We compare with the PLT return address, which is stored right before
       the RLT address */
    ElfW(Addr) plt_return_addr = *((ElfW(Addr)*)(rlt_addr - sizeof(ElfW(Addr))));

    /* we need to adjust the plt return address so that it takes into account
       the variability of shared library load addresses */
    plt_return_addr += target_l_addr;

    /* Fill %r10 with the PLT return address with a movabs instruction */
    *sled_tail++ = 0x49;
    *sled_tail++ = 0xba;
    memcpy(sled_tail, &plt_return_addr, sizeof(ElfW(Addr)));
    sled_tail += sizeof(ElfW(Addr));

    /* Compare %r10 with the return address on the stack 
       i.e. cmp %r10, -0x16(%rsp) */
    memcpy(sled_tail, "\x4c\x39\x54\x24\xf0", 5);
    sled_tail += 5;

    /* Goto the next sled entry (jne) */
    *sled_tail++ = 0x75;
    *sled_tail++ = 0x0d;

    /* mov the rlt address into %r10 */
    *sled_tail++ = 0x49;
    *sled_tail++ = 0xba;
    memcpy(sled_tail, &rlt_addr, sizeof(ElfW(Addr)));
    sled_tail += sizeof(ElfW(Addr));

    /* Jump to %r10 */
    *sled_tail++ = 0x41;
    *sled_tail++ = 0xff;
    *sled_tail++ = 0xe2;

    return sled_tail;
}

/*
void _cdi_write_ret__branch(ElfW(Addr) cmp_addr, ElfW(Addr), target_addr) {
*/


Elf64_Word _cdi_slt_size(Elf64_Word total_mult, Elf64_Word num_used_syms) {
    /*
     * Per multiplicity:
     * * * * * * * * * * * * * * *
     * movabs plt_ret_addr, %r10   [10 bytes]
     * cmp    %r10, -8(%rsp)       [5 bytes]
     * jne    next_sled_entry      [2 bytes]
     * movabs rlt_addr, %r10       [10 bytes]
     * jmp    %r10                 [3 bytes]
     *                           = [30 bytes]
     * Per sled
     * * * * * * * * * * * * * * *
     * jmp _CDI_abort              [5 bytes]
     */

    const Elf64_Word mult_size = 30;
    const Elf64_Word abort_size = 5;

    /* while this calculation is simple now, it might get complicated in
     * the future if we choose to align SLT sleds */
    return mult_size * total_mult + num_used_syms * abort_size;
}

void _cdi_find_mdata(CDI_Header *cdi_header, CDI_Metadata_Sections *mdata) {
    mdata->header = cdi_header;
    mdata->strtab = mdata->libstrtab = mdata->multtab = mdata->mdata_end = 0; 

    for (int i = 0; i < cdi_header->num_entries; i++) {
        switch (cdi_header->entries[i].sect_id) {
            case 0:
                mdata->strtab = ((char*)cdi_header) 
                    + cdi_header->entries[i].hdr_off;
                break;
            case 1:
                mdata->multtab = (void*)(((char*)cdi_header) 
                    + cdi_header->entries[i].hdr_off);
                break;
            case 2:
                mdata->libstrtab = ((char*)cdi_header) 
                    + cdi_header->entries[i].hdr_off;
                break;
            case 3:
                mdata->ftypetab = ((unsigned char*)cdi_header) 
                    + cdi_header->entries[i].hdr_off;
                break;
            case 4:
                mdata->fptypetab = ((unsigned char*)cdi_header) 
                    + cdi_header->entries[i].hdr_off;
                break;
            case 5:
                mdata->floctab = (ElfW(Word) *)(((char*)cdi_header) 
                    + cdi_header->entries[i].hdr_off);
                break;
            case 6:
                mdata->fploctab = (ElfW(Word) *)(((char*)cdi_header) 
                    + cdi_header->entries[i].hdr_off);
                break;
            case 100:
                mdata->mdata_end = ((char*)cdi_header) 
                    + cdi_header->entries[i].hdr_off;
                break;
        }
    }
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

/*
 * Implementation taken from http://clc-wiki.net/wiki/C_standard_library:string.h:strcmp
 */
int _cdi_strcmp(const char *str1, const char *str2) {
    while(*str1 && (*str1==*str2)) {
        str1++,str2++;
    }
    return *(const unsigned char*)str1-*(const unsigned char*)str2;
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

void _cdi_print_link_map(const struct link_map *l) {
    _dl_debug_printf_c("Link Map for '%s'\n", l->l_name);
    _dl_debug_printf_c("--------------------+------------------\n");
    _dl_debug_printf_c("    l_addr          | %lx\n", l->l_addr);
    _dl_debug_printf_c("    l_ld (.dynamic) | %lx\n", (uintptr_t)l->l_ld);
    _dl_debug_printf_c("    l_removed       | %u\n", l->l_removed);
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
    _dl_debug_printf_c("    link map addr   | %lx\n", (uintptr_t)l);
    _dl_debug_printf_c("--------------------+------------------\n");
    _dl_debug_printf_c("\n");
}

void _cdi_print_clb(const CLB *clb) {
    _dl_debug_printf_c("CLB for '%s' (libstrtab idx %u)\n", 
            clb->soname, (unsigned)(clb->soname - _cdi_mdata->libstrtab));
    _dl_debug_printf_c("--------------------+------------------\n");
    _dl_debug_printf_c("    slt             | %lx\n", (uintptr_t)clb->slt);
    _dl_debug_printf_c("    slt_size        | %u\n", clb->slt_size);
    _dl_debug_printf_c("    tramtab         | %lx\n", (uintptr_t)clb->tramtab);
    _dl_debug_printf_c("                    | \n");
    _dl_debug_printf_c("    multtab_block   | %lx\n", (uintptr_t)clb->multtab_block);
    _dl_debug_printf_c("    total mult      | %u\n", clb->multtab_block->total_mult);
    _dl_debug_printf_c("    num globl fns   | %u\n", clb->multtab_block->num_global_syms);
    _dl_debug_printf_c("    num used globls | %u\n", clb->multtab_block->num_used_globals);
    _dl_debug_printf_c("    mblock soname   | %s\n", clb->multtab_block->soname_idx + _cdi_mdata->libstrtab);
    _dl_debug_printf_c("                    | \n");
    _dl_debug_printf_c("    cdi_header      | %lx\n", (uintptr_t)clb->mdata.header);
    _dl_debug_printf_c("    cdi_multtab     | %lx\n", (uintptr_t)clb->mdata.multtab);
    _dl_debug_printf_c("    cdi_floctab     | %lx\n", (uintptr_t)clb->mdata.floctab);
    _dl_debug_printf_c("    cdi_fploctab    | %lx\n", (uintptr_t)clb->mdata.fploctab);
    _dl_debug_printf_c("    cdi_ftypetab    | %lx\n", (uintptr_t)clb->mdata.ftypetab);
    _dl_debug_printf_c("    cdi_fptypetab   | %lx\n", (uintptr_t)clb->mdata.fptypetab);
    _dl_debug_printf_c("    cdi_libstrtab   | %lx\n", (uintptr_t)clb->mdata.libstrtab);
    _dl_debug_printf_c("    cdi_strtab      | %lx\n", (uintptr_t)clb->mdata.strtab);
    _dl_debug_printf_c("    mdata_end       | %lx\n", (uintptr_t)clb->mdata.mdata_end);
    _dl_debug_printf_c("--------------------+------------------\n");
    _dl_debug_printf_c("\n");
}
