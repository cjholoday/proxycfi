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
    /* these magic bytes mark a shared library as CDI: '\x7fCDI\x7fELF' */
    unsigned char cdi_magic[8];
    ElfW(Word) num_entries;

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
   3             | .cdi_ftypetab   
   4             | .cdi_fptypetab
   5             | .cdi_floctab
   6             | .cdi_fploctab
   100           | .cdi_seg_end
   all others    | undefined                    
*/

typedef struct {
    Elf64_Word soname_idx; /* an index into .cdi_libstrtab */
    Elf64_Word total_mult;
    Elf64_Word num_global_syms;

    /* the number of global syms that are called from outside this code object */
    Elf64_Word num_used_globals;

    /* we use the same trick as with header_entries[] */
    Elf64_Word mults[1];
} CDI_Multtab_Block;

typedef struct {
    /* bytes for a trampoline jump. We don't know whether it will be relative
     * to the SLT or an absolute jmp to a fptr return sled. 13 bytes are 
     * reserved so that we can handle either case
     */
    unsigned char jmp_bytes[13]; 

    /* a 3 byte integer index into .cdi_strtab. the integer is little endian */
    unsigned char symtab_idx_bytes[3];
} CDI_Trampoline;

/*
 * Type Table Format:
 *
 * Each entry in the table is of the form: 
 *      [len increase][cstring mangling], where the 
 * cstring represents a 
 *
 */

/* CDI metadata section pointers */
typedef struct {
    CDI_Header *header;

    unsigned char *ftypetab;
    unsigned char *fptypetab;
    ElfW(Word) *floctab;
    ElfW(Word) *fploctab;

    char *strtab;
    char *libstrtab;
    void *multtab;
    void *mdata_end;
} CDI_Metadata_Sections;

/* CDI Linkage Block
 *
 * It contains information associated with each code object
 */
typedef struct CDI_Linkage_Block {
    struct link_map *l;

    Elf64_Word slt_size;
    Elf64_Addr slt;

    CDI_Trampoline *tramtab;

    char *soname;
    CDI_Metadata_Sections mdata;

    /* points to the part of the multiplicity table associated with this code object */
    CDI_Multtab_Block *multtab_block;
} CLB; 


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
 * Returns a pointer to the CLB associated with soname. soname may be 
 * expressed as a path
 */
CLB *_cdi_clb_from_soname(const char *soname);

/*
 * Implements strcmp. This is needed because we need strcmp before libc is mapped
 */
int _cdi_strcmp(const char *str1, const char *str2);

/*
 * Calculates the size of an SLT
 */
Elf64_Word _cdi_slt_size(Elf64_Word total_mult, Elf64_Word num_called_syms);

/*
 * Returns the address of symbol in a link_map given a string *
 */
ElfW(Addr) _cdi_lookup(const char *sym_str, struct link_map *l);

/*
 * Fills a CDI metadata struct with metadata locations
 */
void _cdi_find_mdata(CDI_Header *cdi_header, CDI_Metadata_Sections *mdata);

/*
 * Builds the SLT and SLT trampoline table for a given clb
 *
 * This function assumes that every CLB is fully initialized and that
 * each code object's hash table is ready for use
 */
void _cdi_build_slt(CLB *clb, struct link_map *main_map);

/*
 * Builds function pointer call and return sleds. The address of the generated
 * sleds are handled depending on the type:
 *
 * For call function pointer sleds, the trampoline in .cdi_tramtab associated 
 * with the function pointer is fixed up to jmp to the new sled
 *
 * For return function pointer sleds, the address is written into bytes 4-11
 * of the trampoline associated with the function that was indirectly called
 * If bytes 4-11 of a trampoline are NULL after this function, then the function
 * associated with the trampoline is not indirectly called outside of its own
 * shared library
 *
 * The sleds are placed in an anonymous page chosen by the kernel
 */
void _cdi_gen_fp_sleds(void);

void _cdi_write_direct_plt(void *loc, void *to_addr, int is_call);
/*
 * Returns true if addr is in the range of a CDI shared library 
 */

int _cdi_addr_is_in_cdi_sl(ElfW(Addr) addr);

/* Change the protections on the executable code or shared library tramtabs
 *
 * If to_data is != 0 then the PROT_READ | PROT_EXEC is set
 * If to_data is == 0 then the PROT_READ | PROT_WRITE  is set
 *
 * Code/data will never be writeable and executable at the same time
 */
void _cdi_prot_exe(struct link_map *main_map, signed char to_data);
void _cdi_prot_tramtabs(signed char to_data);

/*
 * Writes an SLT sled and returns a pointer to the next available address in
 * the SLT. This function doen't modify the SLT trampoline table
 */
char *_cdi_write_slt_sled(char *sled_addr,  CDI_Trampoline *tram, 
        ElfW(Word) mult, CLB *clb, struct link_map *main_map,  ElfW(Addr) abort_addr);

/*
 * Writes a piece of an SLT sled. Each call of this function is responsible for
 * handling one code object to which the associated shared library returns from
 */
char *_cdi_write_slt_sled_entry(char *sled_tail, ElfW(Addr) rlt_addr,
        ElfW(Xword) target_l_addr);

/*
 * Returns a signed offset as it would be calculated in an x86 instruction
 */
ElfW(Sword) _cdi_signed_offset(ElfW(Addr) from_addr, ElfW(Addr) to_addr);

/*
 * Debugging Functions
 */
void _cdi_print_header(const CDI_Header *cdi_header);
void _cdi_print_clb(const CLB *clb);
void _cdi_print_clbs(void);

/* warning: this function will segfault if used with the main map */
void _cdi_print_link_map(const struct link_map *l);

#endif
