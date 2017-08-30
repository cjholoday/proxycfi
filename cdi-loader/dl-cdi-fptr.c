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

typedef struct {
    /* data in the floctab */
    ElfW(Word) num_f_reloffs;
    ElfW(Word) num_fret_reloffs;

    ElfW(Word) *f_reloffs;
    ElfW(Word) *fret_reloffs;

    /* data in the ftypetab */
    ElfW(Xword) type_len;
    unsigned char *type;

} Ftype_Iter;

typedef struct {
    /* data in the fploctab */
    ElfW(Word) num_sites;
    ElfW(Word) *site_reloffs;

    /* data in the fptypetab */
    ElfW(Xword) type_len;
    unsigned char *type;
} Fptype_Iter;


Ftype_Iter *ftype_iter_init(CLB *clb) {
    Ftype_Iter *iter = malloc(sizeof(Ftype_Iter));

    iter->type_len = *((unsigned char*) clb->mdata.ftypetab);
    if (iter->type_len == 0) return 0;

    iter->type = clb->mdata.ftypetab + 1;

    iter->num_f_reloffs = clb->mdata.floctab[0];
    iter->num_fret_reloffs = clb->mdata.floctab[1];

    iter->f_reloffs = clb->mdata.floctab + 2;
    iter->fret_reloffs = iter->f_reloffs + iter->num_f_reloffs;

    return iter;
}

Fptype_Iter *fptype_iter_init(CLB *clb) {
    Fptype_Iter *iter = malloc(sizeof(Fptype_Iter));

    iter->type_len = *((unsigned char*) clb->mdata.fptypetab);
    if (iter->type_len == 0) return 0;

    iter->type = clb->mdata.fptypetab + 1;
    iter->num_sites = clb->mdata.fploctab[0];
    iter->site_reloffs = clb->mdata.fploctab + 1;

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
void find_smallest_fptypes(Fptype_Iter *iters, ElfW(Word) num_iters, 
        unsigned char *bitset) {

} */

/* Advance the ftype/fptype iterators
 *
 * On reaching the end of the type table, iter will be set to NULL
*/
void advance_ftype_iter(Ftype_Iter **iter_ptr) { 
    Ftype_Iter *iter = *iter_ptr;

    iter->f_reloffs += iter->num_f_reloffs + iter->num_fret_reloffs + 2;
    iter->num_f_reloffs = iter->f_reloffs[-2];

    /* type table termination is indicated in the number of f_reloffs */
    if (!iter->num_f_reloffs) {
        *iter_ptr = 0;
        return;
    }

    iter->num_fret_reloffs = iter->f_reloffs[-1];
    iter->fret_reloffs = iter->f_reloffs + iter->num_f_reloffs;

    /* the next type is past a null byte and a length accumulation byte */
    iter->type += iter->type_len + 2;
    iter->type_len += iter->type[-1];
}
void advance_fptype_iter(Fptype_Iter **iter_ptr) {
    Fptype_Iter *iter = *iter_ptr;

    iter->site_reloffs += iter->num_sites + 1;
    iter->num_sites = iter->site_reloffs[-1];

    /* type table termination is indicated in the number of site_reloffs */
    if (!iter->num_sites) {
        *iter_ptr = 0;
        return;
    }

    /* the next type is past a null byte and a length accumulation byte */
    iter->type += iter->type_len + 2;
    iter->type_len += iter->type[-1];
}

void _cdi_gen_fptr_sleds(void) {
    Ftype_Iter **ftype_iters = malloc((_clb_tablen + 1) * sizeof(Ftype_Iter *));
    Fptype_Iter **fptype_iters = malloc((_clb_tablen + 1) * sizeof(Fptype_Iter *));
    for (int i = 0; i < _clb_tablen; i++) {
        _dl_debug_printf_c("%s\n", _clb_table[i].soname);
        ftype_iters[i] = ftype_iter_init(&_clb_table[i]);
        fptype_iters[i] = fptype_iter_init(&_clb_table[i]);
        while (ftype_iters[i]) {
            print_ftypes_iter(ftype_iters[i]);
            advance_ftype_iter(&ftype_iters[i]);
        }
        while (fptype_iters[i]) {
            print_fptypes_iter(fptype_iters[i]);
            advance_fptype_iter(&fptype_iters[i]);
        }
        _dl_debug_printf_c("\n");
        _dl_debug_printf_c("\n");
        _dl_debug_printf_c("\n");
        _dl_debug_printf_c("\n");
    }

}

