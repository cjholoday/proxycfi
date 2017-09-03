/* CDI function pointer sled generation
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

/* do not modify the first two members of the ftypes/fptypes struct. They
 * must be first and they must be identical between the two structs so that
 * type_cmp can be polymorphic */

typedef struct {
    /* data in the ftypetab */
    ElfW(Xword) type_len;
    unsigned char *type;

    /* data in the floctab */
    ElfW(Word) num_f_reloffs;
    ElfW(Word) num_fret_reloffs;

    ElfW(Word) *f_reloffs;
    ElfW(Word) *fret_reloffs;

    unsigned char is_finished;

    /* add this to reloffs to account for changes in the relative offsets
     * since they were calcuated by the CDI converter */
    ElfW(Sword) reloff_adjust;
} Ftype_Iter;

typedef struct {
    /* data in the fptypetab */
    ElfW(Xword) type_len;
    unsigned char *type;

    /* data in the fploctab */
    ElfW(Word) num_sites;
    ElfW(Word) *site_reloffs;

    unsigned char is_finished;

    /* add this to reloffs to account for changes in the relative offsets
     * since they were calcuated by the CDI converter */
    ElfW(Sword) reloff_adjust;
} Fptype_Iter;

/*
 * Compares type iterators prioritizing type length first then using a strcmp
 * of the types. ftype or fptype iterator pointers can be passed in 
 */
int type_cmp(void *type_iter1, void *type_iter2) {
    /* we could also cast to Fptype_Iter *. Both have the same first two fields */
    Ftype_Iter *iter1 = (Ftype_Iter *)type_iter1;
    Ftype_Iter *iter2 = (Ftype_Iter *)type_iter2;

    if (iter1->type_len != iter2->type_len) {
        return iter1->type_len - iter2->type_len;
    }
    else {
        return strcmp((char*)iter1->type, (char*)iter2->type);
    }
}

Ftype_Iter *ftype_iter_init(CDI_Metadata_Sections *mdata) {
    Ftype_Iter *iter = malloc(sizeof(Ftype_Iter));

    iter->type_len = *((unsigned char*) mdata->ftypetab);
    if (iter->type_len == 0) return 0;

    iter->type = mdata->ftypetab + 1;

    iter->num_f_reloffs = mdata->floctab[0];
    iter->num_fret_reloffs = mdata->floctab[1];

    iter->f_reloffs = mdata->floctab + 2;
    iter->fret_reloffs = iter->f_reloffs + iter->num_f_reloffs;
    iter->is_finished = iter->num_f_reloffs == 0;

    /* reloff calculations didn't account for the cdi_header or the multtab
     * enlargements between the floctab/fploctab and executable code
     *
     * adding this to a reloff will normalize it */
    iter->reloff_adjust = (char*)mdata->header - (char*)mdata->floctab + 16;

    return iter;
}

Fptype_Iter *fptype_iter_init(CDI_Metadata_Sections *mdata) {
    Fptype_Iter *iter = malloc(sizeof(Fptype_Iter));

    iter->type_len = *((unsigned char*) mdata->fptypetab);
    if (iter->type_len == 0) return 0;

    iter->type = mdata->fptypetab + 1;
    iter->num_sites = mdata->fploctab[0];
    iter->site_reloffs = mdata->fploctab + 1;
    iter->is_finished = iter->num_sites == 0;

    /* reloff calculations didn't account for the cdi_header or the multtab
     * enlargements between the floctab/fploctab and executable code
     *
     * adding this to a reloff will normalize it */
    iter->reloff_adjust = (char*)mdata->header - (char*)mdata->floctab + 16;

    return iter;
}

void print_ftypes_iter(Ftype_Iter *iter) { 
    _dl_debug_printf_c("--------------------+------------------\n");
    _dl_debug_printf_c("num_f_reloffs       | %u\n", iter->num_f_reloffs);
    _dl_debug_printf_c("num_fret_reloffs    | %u\n", iter->num_fret_reloffs);
    _dl_debug_printf_c("                    | \n");
    _dl_debug_printf_c("f_reloffs           | %lx\n", (uintptr_t)iter->f_reloffs);
    _dl_debug_printf_c("fret_reloffs        | %lx\n", (uintptr_t)iter->fret_reloffs);
    _dl_debug_printf_c("                    | \n");
    _dl_debug_printf_c("type                | %s\n", iter->type);
    _dl_debug_printf_c("type_len            | %lu\n", iter->type_len);
    _dl_debug_printf_c("--------------------+------------------\n");
    _dl_debug_printf_c("\n");
}

void print_fptypes_iter(Fptype_Iter *iter) {
    if (!iter) {
        return;
    }
    _dl_debug_printf_c("--------------------+------------------\n");
    _dl_debug_printf_c("num_sites           | %u\n", iter->num_sites);
    _dl_debug_printf_c("site_reloffs        | %lx\n", (uintptr_t)iter->site_reloffs);
    _dl_debug_printf_c("                    | \n");
    _dl_debug_printf_c("type                | %s\n", iter->type);
    _dl_debug_printf_c("type_len            | %lu\n", iter->type_len);
    _dl_debug_printf_c("--------------------+------------------\n");
    _dl_debug_printf_c("\n");
}



/* 
 * Returns the number of fptypes that are equally the smallest according to
 * type_cmp. The matching iter are written into match_buf, for which
 * the caller is responsible regarding allocation. match_buf must be large
 * enough to hold num_iters type iterators
 */
ElfW(Word) find_smallest_fptypes(Fptype_Iter **iters, ElfW(Word) num_iters, 
        Fptype_Iter **match_buf) {
    if (!num_iters) {
        return 0;
    }


    /* find the first unfinished, valid fptype iter*/
    ElfW(Word) num_matches = 0;
    int idx = 0;
    for (; idx < num_iters; idx++) {
        if (iters[idx] && !iters[idx]->is_finished) {
            match_buf[num_matches++] = iters[idx++];
            break;
        }
    }
    if (!num_matches) {
        return 0;
    }

    for (; idx < num_iters; idx++) {
        /* skip finished and invalid iters */
        if (!iters[idx] || iters[idx]->is_finished) {
            continue;
        }

        int cmp = type_cmp(iters[idx], match_buf[0]);
        if (cmp == 0) {
            match_buf[num_matches++] = iters[idx];
        }
        else if (cmp < 0) {
            match_buf[0] = iters[idx];
            num_matches = 1;
        }
    }

    return num_matches;
}

/* Advance the ftype/fptype iterators
 *
 * On reaching the end of the type table, iter will be set to NULL
*/
void advance_ftype_iter(Ftype_Iter *iter) { 
    iter->f_reloffs += iter->num_f_reloffs + iter->num_fret_reloffs + 2;
    iter->num_f_reloffs = iter->f_reloffs[-2];

    /* type table termination is indicated in the number of f_reloffs */
    if (!iter->num_f_reloffs) {
        iter->is_finished = 1;
        return;
    }

    iter->num_fret_reloffs = iter->f_reloffs[-1];
    iter->fret_reloffs = iter->f_reloffs + iter->num_f_reloffs;

    /* the next type is past a null byte and a length accumulation byte */
    iter->type += iter->type_len + 2;
    iter->type_len += iter->type[-1];
}
void advance_fptype_iter(Fptype_Iter *iter) {
    iter->site_reloffs += iter->num_sites + 1;
    iter->num_sites = iter->site_reloffs[-1];

    /* type table termination is indicated in the number of site_reloffs */
    if (!iter->num_sites) {
        iter->is_finished = 1;
        return;
    }

    /* the next type is past a null byte and a length accumulation byte */
    iter->type += iter->type_len + 2;
    iter->type_len += iter->type[-1];
}

typedef struct {
    /* points to the first page mmap'ed */
    unsigned char *head;

    /* points to one page after the last that was mapped */
    unsigned char *tail;

    /* points to the next unused byte in the mmap'ed region */
    unsigned char *used_tail;
} Sled_Allocation;

static void sled_allocate(Sled_Allocation *alloc) {
    const int alloc_size = 16;
    alloc->head = mmap(0, GLRO(dl_pagesize) * alloc_size, PROT_WRITE | PROT_READ,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    alloc->tail = alloc->head + GLRO(dl_pagesize) * alloc_size;
    alloc->used_tail = alloc->head;
}

static void code_prot(Sled_Allocation *alloc) {
    mprotect(alloc->head, alloc->tail - alloc->head, PROT_READ | PROT_EXEC);
}

static ElfW(Addr) abs_addr(ElfW(Sword) *reloff) {
    _dl_debug_printf_c("\treloff addr: %lx\n", (uintptr_t)reloff);
    if (*reloff >= 0) {
        _dl_debug_printf_c("\treloff: %lx\n", (long unsigned)*reloff);
    }
    else {
        _dl_debug_printf_c("\treloff: -%lx\n", (long unsigned)(*reloff * -1));
    }
    ElfW(Addr) abs_addr = (uintptr_t)reloff;
    if (*reloff >= 0) {
        return abs_addr + *reloff;
    }
    else { 
        return abs_addr - (ElfW(Addr))(*reloff * -1);
    }
}
void unaligned_memcpy(void *dst, void *src, ElfW(Word) size) {
    unsigned char *d = dst;
    unsigned char *s = src;
    for (unsigned i = 0; i < size; i++) {
        *d++ = *s++;
    }
}

void _cdi_gen_fp_call_sled(Sled_Allocation *alloc,
        Ftype_Iter **f_iters, ElfW(Word) num_f_iters,
        Fptype_Iter **fp_iters, ElfW(Word) num_fp_iters) {
    /* by not writing into the trampoline table, the trampoline table 
     * jumps will, by default, be pointed at _CDI_abort symbols */
    if (!num_f_iters) {
        return;
    }

    /*
     * Per function target
     * * * * * * * * * * * * * * *
     * movabs candidate, %r11      [10 bytes]
     * cmp    %r10, %r11           [3 bytes]
     * jne    next_sled_entry      [2 bytes]
     * call   *%r11                [3 bytes]
     *                           = [18 bytes]
     * Per sled
     * * * * * * * * * * * * * * *
     * movabs $_CDI_abort, %r10    [10 bytes]
     * jmp %r10                    [3  bytes]
     *                           = [13 bytes]
     */
    const int branch_size = 18;
    const int abort_size = 13;


    /* allocate new sled block if we can't fit at least 5 targets & chain */
    int mem_avail = alloc->tail - alloc->used_tail;
    if (mem_avail < branch_size * 5 + abort_size) {
        _dl_debug_printf_c("allocating new page\n");
        code_prot(alloc);
        sled_allocate(alloc);
        mem_avail = alloc->tail - alloc->used_tail;
        _dl_debug_printf_c("mem_avail: %lx\n", (long unsigned)mem_avail);
    }

    ElfW(Addr) sled_start = (uintptr_t)alloc->used_tail;

    for (int i = 0; i < num_f_iters; i++) {
        _dl_debug_printf_c("mem_avail: %lx\n", (long unsigned)mem_avail);
        for (int j = 0; j < f_iters[i]->num_f_reloffs; j++, mem_avail -= branch_size) {
            if (mem_avail < branch_size + abort_size) {
                _dl_debug_printf_c("allocating new page and chaining\n");

                Sled_Allocation tmp = *alloc;
                sled_allocate(alloc);

                /* Chain the sled into the next allocation */
                *alloc->used_tail++ = 0x49;
                *alloc->used_tail++ = 0xbb;
                memcpy(tmp.used_tail, &alloc->head, sizeof(ElfW(Addr)));

                code_prot(&tmp);
                mem_avail = alloc->tail - alloc->used_tail;
            }


            /* calculate the function address as an offset from the floctab */
            ElfW(Addr) f_addr = abs_addr((ElfW(Sword)*)(&f_iters[i]->f_reloffs[j])) 
                + sizeof(ElfW(Word)) + f_iters[i]->reloff_adjust;
            _dl_debug_printf_c("f_addr: %lx\n", f_addr);

            /* Fill %r11 with the candidate function */
            *alloc->used_tail++ = 0x49;
            *alloc->used_tail++ = 0xbb;
            memcpy(alloc->used_tail, &f_addr, sizeof(ElfW(Addr)));
            alloc->used_tail += sizeof(ElfW(Addr));

            /* cmp %r10, %r11 */
            *alloc->used_tail++ = 0x4d;
            *alloc->used_tail++ = 0x39;
            *alloc->used_tail++ = 0xd3;

            /* Goto the next sled branch (jne) */
            *alloc->used_tail++ = 0x75;
            *alloc->used_tail++ = 0x03;

            /* Call *%r11 */
            *alloc->used_tail++ = 0x41;
            *alloc->used_tail++ = 0xff;
            *alloc->used_tail++ = 0xd3;
        }
    }
    for (int i = 0; i < num_fp_iters; i++) {
        ElfW(Addr) fp_site = abs_addr((ElfW(Sword)*)fp_iters[i]->site_reloffs) 
            + sizeof(ElfW(Word)) + fp_iters[i]->reloff_adjust;
        _dl_debug_printf_c("fp_site: %lx; fptr sled addr: %lx\n", fp_site, sled_start);

        /* If the fp site is in a shared library we are looking at a relative
         * jump to the trampoline table. Otherwise, the relative jump goes to
         * _CDI_abort. We tell the difference by the first four bytes at 
         * the target: trampoline table entries start with 4 null bytes
         * whereas _CDI_abort doesn't */
        ElfW(Sword) jmp_reloff = 0;
        memcpy(&jmp_reloff, (void *)(fp_site + 1), sizeof(ElfW(Sword)));

        ElfW(Addr) jmp_target = fp_site + 5 + jmp_reloff;


        unsigned char *sled_link = (unsigned char *) fp_site;
        if (*((ElfW(Word)*)(jmp_target)) == 0) {
            /* we are looking at a trampoline table entry. Link it to fptr
             * call sled we just created */
            sled_link = (unsigned char *)jmp_target;
        }
        else {
            /* we are looking at _CDI_abort, so we need to link to the fptr
             * sled from the function pointer site */
            //TODO unprotect main executable code
            sled_link = (unsigned char *) fp_site;
        }

        /* store the sled address into %r11 */
        *sled_link++ = 0x49;
        *sled_link++ = 0xbb;
        memcpy(sled_link, &sled_start, sizeof(ElfW(Addr)));
        sled_link += sizeof(ElfW(Addr));

        /* jmp *%r11 */
        *sled_link++ = 0x41;
        *sled_link++ = 0xff;
        *sled_link++ = 0xe3;
    }
}

/*
void _cdi_gen_fp_ret_sled(Sled_Allocation *alloc,
        Ftype_Iter *f_iter, ElfW(Word) num_f_iters),
        Fptype_Iter *fp_iters, ElfW(Word) num_fp_iters) {

}
*/


void _cdi_gen_fp_sleds(void) {
    Ftype_Iter **ftype_iters = malloc((_clb_tablen + 1) * sizeof(Ftype_Iter *));
    Fptype_Iter **fptype_iters = malloc((_clb_tablen + 1) * sizeof(Fptype_Iter *));

    Ftype_Iter **f_matches = malloc((_clb_tablen + 1) * sizeof(Ftype_Iter *));
    Fptype_Iter **fp_matches = malloc((_clb_tablen + 1) * sizeof(Fptype_Iter *));

    for (int i = 0; i < _clb_tablen; i++) {
        _dl_debug_printf_c("%s\n", _clb_table[i].soname);
        ftype_iters[i] = ftype_iter_init(&_clb_table[i].mdata);
        fptype_iters[i] = fptype_iter_init(&_clb_table[i].mdata);
        /*
        while (ftype_iters[i]) {
            print_ftypes_iter(ftype_iters[i]);
            advance_ftype_iter(ftype_iters[i]);
        }
        while (fptype_iters[i]) {
            print_fptypes_iter(fptype_iters[i]);
            advance_fptype_iter(fptype_iters[i]);
        }
        _dl_debug_printf_c("\n");
        _dl_debug_printf_c("\n");
        _dl_debug_printf_c("\n");
        _dl_debug_printf_c("\n");
        */
    }

    /* place the executable iters at the end */
    ftype_iters[_clb_tablen] = ftype_iter_init(_cdi_mdata);
    fptype_iters[_clb_tablen] = fptype_iter_init(_cdi_mdata);

    /* Do not mmap the memory for a sled allocation yet. Wait until we KNOW
     * there are function pointers */
    Sled_Allocation alloc;
    alloc.head = alloc.tail = alloc.used_tail = 0;

    int num_sm_fptypes = find_smallest_fptypes(fptype_iters, _clb_tablen + 1, fp_matches);
    _dl_debug_printf_c("num matches: %u\n", num_sm_fptypes);
    while (num_sm_fptypes) {
        int num_sm_ftypes = 0;
        for (int i = 0; i < _clb_tablen + 1; i++) {
            /* skip exhausted ftypes iters */
            if (ftype_iters[i]->is_finished) {
                continue;
            }

            int cmp = type_cmp(fp_matches[0], ftype_iters[i]);
            while (!ftype_iters[i]->is_finished && cmp > 0) {
                advance_ftype_iter(ftype_iters[i]);
                cmp = type_cmp(fp_matches[0], ftype_iters[i]);
            }

            if (cmp == 0) {
                f_matches[num_sm_ftypes++] = ftype_iters[i];
            }
        }
        if (num_sm_fptypes > 0) {
            _dl_debug_printf_c("building sleds for type '%s'\n", fp_matches[0]->type);
        }
        _cdi_gen_fp_call_sled(&alloc, f_matches, num_sm_ftypes,
                fp_matches, num_sm_fptypes);
        /*
        _cdi_gen_fp_ret_sled(&alloc, f_matches, num_sm_ftypes, 
                fp_matches, num_sm_fptypes);
                */

        for (int i = 0; i < num_sm_ftypes; i++) { 
            print_ftypes_iter(f_matches[i]);
            advance_ftype_iter(f_matches[i]);
        }
        _dl_debug_printf_c("\n");
        for (int i = 0; i < num_sm_fptypes; i++) { 
            print_fptypes_iter(fp_matches[i]);
            advance_fptype_iter(fp_matches[i]);
        }
        _dl_debug_printf_c("\n");

        num_sm_fptypes = find_smallest_fptypes(fptype_iters, _clb_tablen + 1, fp_matches);
        _dl_debug_printf_c("num matches: %u\n", num_sm_fptypes);
    }
}



