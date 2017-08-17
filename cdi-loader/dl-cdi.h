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

#ifndef _DL_CDI_H
#define _DL_CDI_H

/* The .cdi segment begins with this header. It tells us where the CDI metadata
 * can be found
 */
typedef struct {
    Elf64_Word num_entries;

    /* the actual length is num_header_entries. Since we only ever create struct
     * pointers and point them at statically constructed structs, we can get 
     * away with simply ignoring the official size
     */
    struct {
        Elf64_Word hdr_off; /* offset from .cdi_header */
        Elf64_Word sect_id;
    } entries[1];
} CDI_Header;

/*
   section id    | section name                                                    
   --------------+-----------------
   0             | .cdi_strtab                                                     
   1             | .cdi_multtab                                                    
   2             | .cdi_libstrtab                                                  
   3 -> (2^32-1) | undefined                    
*/

typedef struct {
    Elf64_Word sl_name; /* an index into .cdi_libstrtab */
    Elf64_Word total_mult;
    Elf64_Word num_global_syms;

    /* the number of global syms that are called from outside this code object */
    Elf64_Word num_used_globals;

    /* we use the same trick as with header_entries[] */
    Elf64_Word mults[1];
} CDI_Multtab_Block;

typedef struct {
    /* bytes for a jmp to an SLT sled */
    unsigned char jmp_bytes[5]; 

    /* a 3 byte integer index into .cdi_strtab. the integer is little endian */
    unsigned char symtab_idx_bytes[3];
} SLT_Trampoline;

/* CDI Linkage Block
 *
 * It contains information associated with each code object
 */
typedef struct CDI_Linkage_Block {
    Elf64_Word slt_size;
    void *slt;

    SLT_Trampoline *slt_tramptab;
    char *sl_name;

    /* points to the part of the multiplicity table associated with this code object */
    CDI_Multtab_Block *multtab_block;
} CLB; 

/* CDI metadata section pointers */
typedef struct {
    CDI_Header *header;
    char *strtab;
    char *libstrtab;
    void *multtab;
} CDI_Metadata_Sections;

/* CDI Globals */
extern CLB *_clb_table;
extern Elf64_Word _clb_tablen;
extern CDI_Metadata_Sections *_cdi_mdata;


/*
 * Initializes CDI globals (_clb_table, _clb_tablen, and _cdi_mdata)
 *
 * The CLBs in _clb_list will not have slt or slt_tramptab
 * initialized because we need them to be mmapped first
 */
void _cdi_init(CDI_Header *cdi_header);

/*
 * Calculates the size of an SLT
 */
Elf64_Word _cdi_slt_size(Elf64_Word total_mult, Elf64_Word num_called_syms);

/*
 * Debugging Functions
 */
void _cdi_print_header(CDI_Header *cdi_header);
void _cdi_print_clb(CLB *clb);
void _cdi_print_clbs(void);

#endif
