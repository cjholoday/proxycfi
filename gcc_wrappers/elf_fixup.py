import __init__

import spec
import os
import sys
import struct
import itertools
import subprocess

import error
import lib_utils
import common.elf
import multtab

from common.eprint import eprint
from common.elf import strtab_grab
from common.elf import strtab_startswith

def cdi_fixup_elf(lspec):
    """Prepare an elf binary for the CDI loader by overwriting/adding data"""

    target_elf = common.elf.Elf64(lspec.target, error.fatal_error)
    globl_funct_mults = multtab.get_funct_mults(target_elf, lspec)

    # _CDI_abort multiplicity doesn't affect SLT size, so remove info on it
    if '_CDI_abort' in globl_funct_mults:
        del globl_funct_mults['_CDI_abort']

    ftypetab_size = target_elf.find_section('.cdi_ftypetab').sh_size
    fptypetab_size = target_elf.find_section('.cdi_fptypetab').sh_size
    floctab_size = target_elf.find_section('.cdi_floctab').sh_size
    fploctab_size = target_elf.find_section('.cdi_fploctab').sh_size

    # put the floctab and fploctab sections first to mirror the linker script
    type_sect_strs  = ['.cdi_floctab', '.cdi_fploctab', '.cdi_ftypetab', '.cdi_fptypetab']
    type_sect_sizes = [floctab_size, fploctab_size, ftypetab_size, fptypetab_size]

    # fixup_plt must be run before getting rlt fixups so that we can find the
    # slow plts from the GOT entries we see from .rela.dyn relocations
    fixup_plt(target_elf)
    rrel32_fixups = get_rrel32_fixups(target_elf)
    rlt_fixups = get_rlt_fixups(target_elf)

    target_elf.fixup(rrel32_fixups + rlt_fixups)

    fixup_plt_loc_metadata(target_elf)

    objcopy_opts = []
    if lspec.target_is_shared:
        target_elf.init_strtab('.cdi_strtab')
        
        write_cdi_header(type_sect_strs + ['.cdi_plt_ranges', '.cdi_strtab', '.cdi_seg_end'],
                type_sect_sizes + [32, len(target_elf.cdi_strtab), 8])

        objcopy_opts.extend(['--update-section', '.cdi_header=.cdi/cdi_header'])
        objcopy_opts.extend(['--remove-section', '.cdi_multtab'])
        objcopy_opts.extend(['--remove-section', '.cdi_libstrtab'])
    else:
        multtab.build_multtab(target_elf, lspec, globl_funct_mults, '.cdi')

        updated_sects = ['.cdi_multtab', '.cdi_libstrtab']
        updated_sizes = get_sect_sizes(updated_sects)
        write_cdi_header(updated_sects[:1] + type_sect_strs + updated_sects[-1:] 
                + ['.cdi_plt_ranges', '.cdi_seg_end'],
                updated_sizes[:1] + type_sect_sizes + updated_sizes[-1:] + [32, 8])
        objcopy_opts.extend(['--update-section', '.cdi_multtab=.cdi/cdi_multtab'])
        objcopy_opts.extend(['--update-section', '.cdi_libstrtab=.cdi/cdi_libstrtab'])
        objcopy_opts.extend(['--update-section', '.cdi_header=.cdi/cdi_header'])
        objcopy_opts.extend(['--remove-section', '.cdi_strtab'])

    write_removable_syms(target_elf, '.cdi/removable_cdi_syms')
    try:
        subprocess.check_call(['objcopy', 
            '--strip-symbols=.cdi/removable_cdi_syms', lspec.target]
            + objcopy_opts, stdout=open(os.devnull, 'wb'), stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        error.fatal_error("couldn't update symbols and/or sections of target '{}'".format(lspec.target))

def write_cdi_header(sect_strs, sect_sizes):
    """Writes .cdi_header, which tells where CDI metadata can be found
    
    The sections MUST be passed in the order specified in the linker script
    """

    # 12 bytes for num_entris and CDI magic. Then 8 bytes for each header entry
    cdi_header_size = 12 + 8 * len(sect_strs)

    # the offset of each section from the .cdi segment. Starting with .cdi_header
    segment_offsets = [0, cdi_header_size]
    for sect_size in sect_sizes:
        # write the start offset of the next section
        segment_offsets.append(segment_offsets[-1] + sect_size)

    # we wrote more than one offset than is necessary
    del segment_offsets[-1]

    with open('.cdi/cdi_header', 'w') as header:
        # write CDI identifier bytes (CDI magic bytes)
        header.write('\x7fCDI\x7fELF')

        # write the number of header entries
        header.write(struct.pack('<I', len(sect_strs)))
        for sect_idx in xrange(1, len(segment_offsets)):
            sect_id = -1
            if sect_strs[sect_idx - 1]   == '.cdi_strtab':
                sect_id = 0
            elif sect_strs[sect_idx - 1] == '.cdi_multtab':
                sect_id = 1
            elif sect_strs[sect_idx - 1] == '.cdi_libstrtab':
                sect_id = 2
            elif sect_strs[sect_idx - 1] == '.cdi_ftypetab':
                sect_id = 3
            elif sect_strs[sect_idx - 1] == '.cdi_fptypetab':
                sect_id = 4
            elif sect_strs[sect_idx - 1] == '.cdi_floctab':
                sect_id = 5
            elif sect_strs[sect_idx - 1] == '.cdi_fploctab':
                sect_id = 6
            elif sect_strs[sect_idx - 1] == '.cdi_plt_ranges':
                sect_id = 7
            elif sect_strs[sect_idx - 1] == '.cdi_seg_end':
                sect_id = 100
            else:
                error.fatal_error("unknown CDI metadata section: '{}'"
                        .format(sect_strs[sect_idx - 1]))
            header.write(struct.pack('<II', segment_offsets[sect_idx], sect_id))


def get_sect_sizes(sect_strs):
    """Get the size of each section in the list sect_strs
    
    This function assumes sect_strs can be found at .cdi/<sect_str> where 
    <sect_str> is the section name without a dot. 
    """
    sect_sizes = []
    for sect_str in sect_strs:
        try:
            sect_sizes.append(int(subprocess.check_output(['wc', '-c', '.cdi/'
                + sect_str[1:]]).split()[0]))
        except subprocess.CalledProcessError:
            error.fatal_error("Cannot get file size of '{}' in bytes".format(
                sect_str))
    return sect_sizes

def get_rlt_fixups(elf):
    try:
        rlt_sh = elf.find_section('.cdi_rlt')
    except common.elf.Elf64.MissingSection:
        eprint('cdi-ld: warning: no .cdi_rlt section in target')
        return []

    plt_ret_addrs = extract_plt_ret_addrs(elf)
    
    rlt_fixups = []
    for sym in elf.get_symbols('.symtab'):
        if strtab_startswith(elf.strtab, sym.st_name, '_CDI_RLT_'):
            sym_str = strtab_grab(elf.strtab, sym.st_name)
            rlt_entry_offset = sym.st_value - rlt_sh.sh_addr + rlt_sh.sh_offset
            try:
                plt_ret_addr = plt_ret_addrs[sym_str[len('_CDI_RLT_'):]]
            except: # TODO: DELETE THIS EXCEPT AND LET ERRORS TERMINATE MODULE
                eprint("FATAL ERROR BEING IGNORED FOR DEBUGGING: No PLT found "
                        "for '{}'".format(sym_str[len('_CDI_RLT_'):]))
                continue

            # associate PLT callq return address with this RLT entry
            rlt_fixups.append(common.elf.Elf64.Fixup(
                rlt_entry_offset - 8, struct.pack('<Q', plt_ret_addr)))
    return rlt_fixups

def fixup_plt_loc_metadata(target_elf):
    plt_sh = target_elf.find_section('.plt')
    fast_plt_sh = target_elf.find_section('.plt.got')
    plt_ranges_sh = target_elf.find_section('.cdi_plt_ranges')

    with open(target_elf.path, 'r+b') as elf:
        elf.seek(plt_ranges_sh.sh_offset)
        elf.write(struct.pack('<Q', plt_sh.sh_addr))
        elf.write(struct.pack('<Q', plt_sh.sh_size))
        elf.write(struct.pack('<Q', fast_plt_sh.sh_addr))
        elf.write(struct.pack('<Q', fast_plt_sh.sh_size))

def get_rrel32_fixups(elf):
    # maps each [tdd] of an RREL32 CDI symbol to a list of fixups
    # See cdi/converter/gen_cdi_asm.py for info on RREL32 symbols
    rrel32_fixup_dict = dict() 
    for sym in elf.get_symbols('.symtab'):
        # only look at RREL32 symbols
        if not strtab_startswith(elf.strtab, sym.st_name, '_CDIX_RREL32'):
            continue

        sym_str = strtab_grab(elf.strtab, sym.st_name)

        tdd_sym_str = ''
        binary_prefix = ''
        if sym_str[len('_CDIX_RREL32')] == 'P':
            tdd = sym_str[len('_CDIX_RREL32P_'):]

            # skip the dummy info in [tdd]
            hex_prefix, garbage, tdd_sym_str = tdd.split('_', 2)

            # split the hex prefix into equal 2 character chunks, then ints
            hex_prefix = [int(hex_prefix[i:i+2], 16) for i in range(0, len(hex_prefix), 2)]
            binary_prefix = ''.join([chr(part) for part in hex_prefix])
        else:
            tdd_sym_str = sym_str[sym_str.find('_',len('_CDIX_RREL32_')) + 1:]

        sym_sh = elf.shtab(sym.st_shndx)
        sym_offset = sym.st_value - sym_sh.sh_addr + sym_sh.sh_offset

        rrel32_fixup = common.elf.Elf64.Fixup(
            sym_offset - 4 - len(binary_prefix), binary_prefix)
        rrel32_fixup.vaddr = sym.st_value

        try:
            rrel32_fixup_dict[tdd_sym_str].append(rrel32_fixup)
        except KeyError:
            rrel32_fixup_dict[tdd_sym_str] = [rrel32_fixup]

    # complete the rrel32 fixups by looking for the accompanying symbols
    for sym in elf.get_symbols('.symtab'):
        sym_str = strtab_grab(elf.strtab, sym.st_name)
        if sym_str in rrel32_fixup_dict:
            for fixup in rrel32_fixup_dict[sym_str]:
                fixup.patch += struct.pack('<i', sym.st_value - fixup.vaddr)

    # collapse the lists of fixups into a single list of fixups
    return list(itertools.chain.from_iterable(rrel32_fixup_dict.values()))

def fixup_plt(elf):
    fast_plt_sh = elf.find_section('.plt.got')
    slow_plt_sh = elf.find_section('.slow_plt')
    got_sh = elf.find_section('.got')

    # __cxa_finalize goes through the fast plt, but it is part of the 
    # startup/cleanup code that will not be made CDI compliant in this 
    # version of CDI. We therefore find it's got addr and skip fixing up
    # the slow plt
    cxa_finalize_sym_idx = -1
    for idx, sym in enumerate(elf.get_symbols('.dynsym')):
        sym_str = strtab_grab(elf.dynstr, sym.st_name)
        if sym_str == '__cxa_finalize':
            cxa_finalize_sym_idx = idx
            break

    cxa_finalize_got_addr = -1
    dyn_relocs = elf.get_rela_relocs('.rela.dyn')
    for reloc in dyn_relocs:
        rela_st_idx = reloc.r_info >> 32
        if rela_st_idx == cxa_finalize_sym_idx:
            cxa_finalize_got_addr = reloc.r_offset

    
    with open(elf.path, 'r+b') as elf_file:
        for idx in xrange(fast_plt_sh.sh_size / 8):
            elf_file.seek(fast_plt_sh.sh_offset + idx * 8 + 2)

            # reloff from the fast plt to the GOT entry
            fast_to_got_reloff = struct.unpack('<i', elf_file.read(4))[0] + 6

            # reloff from the slow plt to the fast plt
            slow_to_fast_reloff = fast_plt_sh.sh_addr - slow_plt_sh.sh_addr - 8 * idx

            # reloff from the beginning of the slow plt entry to the GOT entry
            slow_to_got_reloff = slow_to_fast_reloff + fast_to_got_reloff

            # jmp <slow_plt entry>
            elf_file.seek(fast_plt_sh.sh_offset + idx * 8)
            elf_file.write('\xe9' + struct.pack('<i', (slow_to_fast_reloff + 5) * -1)
                    + '\x90' * 3)

            # write the reloff from the slow plt to the GOT into slow plt
            elf_file.seek(slow_plt_sh.sh_offset + idx * 16)
            elf_file.write(struct.pack('<i', slow_to_got_reloff))

            # signal to the loader that there should be a jump not a call, but
            # only if this slow plt is for __cxa_finalize
            got_addr = slow_plt_sh.sh_addr + idx * 16 + slow_to_got_reloff
            if got_addr == cxa_finalize_got_addr:
                # we signal by writing 0xCC to the last byte of the PLT entry
                elf_file.seek(11, 1)
                print 'hit\n\n\n\n\n\n\n'
                elf_file.write('\xcc')

            # write the reloff from the GOT to the slow PLT
            elf_file.seek(slow_plt_sh.sh_addr + idx * 16 
                    + slow_to_got_reloff - got_sh.sh_addr + got_sh.sh_offset)
            # print (hex(slow_plt_sh.sh_addr), idx, hex(slow_to_got_reloff),
            #         hex(got_sh.sh_addr), hex(got_sh.sh_offset)
            elf_file.write(struct.pack('<q', slow_to_got_reloff * -1))

def extract_plt_ret_addrs(elf):
    """Returns a dict mapping {PLT symbol -> ret address}. This includes fast PLTs"""
    ret_addrs = dict()

    try:
        plt_relocs = elf.get_rela_relocs('.rela.plt')
    except common.elf.Elf64.MissingSection:
        # it's possibel there are no regular PLT entries
        pass 

    plt_sh = elf.find_section('.plt')
    got_sh = elf.find_section('.got')
    slow_plt_sh = elf.find_section('.slow_plt')
    for sym in elf.get_symbols('.dynsym'):
        try:
            rela_st_idx = plt_relocs[len(ret_addrs)].r_info >> 32
        except IndexError:
            break # we're finished since we ran out of PLT relocs

        if sym.idx == rela_st_idx:
            sym_str = strtab_grab(elf.dynstr, sym.st_name)
            entry_vaddr = plt_sh.sh_addr + plt_sh.sh_entsize * (len(ret_addrs) + 1)
            ret_addrs[sym_str] = entry_vaddr + 13 # after movabs, callq
    print "len(ret_addrs) = %d, len(plt_relocs) = %d\n" % (len(ret_addrs), len(plt_relocs))
    # assert len(ret_addrs) == len(plt_relocs)

    dyn_relocs = elf.get_rela_relocs('.rela.dyn')
    dyn_relocs_by_idx = {reloc.r_info >> 32 : reloc for reloc in dyn_relocs}
    
    with open(elf.path, 'r+b') as elf_file:
        for sym in elf.get_symbols('.dynsym'):
            if sym.idx in dyn_relocs_by_idx:
                sym_str = strtab_grab(elf.dynstr, sym.st_name)
                got_addr = dyn_relocs_by_idx[sym.idx].r_offset
                elf_file.seek(got_addr - got_sh.sh_addr + got_sh.sh_offset)

                slow_plt_reloff = struct.unpack('<q', elf_file.read(8))[0]
                slow_plt_addr = got_addr + slow_plt_reloff
                ret_addrs[sym_str] = slow_plt_addr + 13

    return ret_addrs

def write_removable_syms(elf, path):
    """Saves all the removable symbol names in filename at path"""
    with open(path, 'w') as log:
        for sym in elf.get_symbols('.symtab'):
            if strtab_startswith(elf.strtab, sym.st_name, '_CDIX_'):
                log.write(strtab_grab(elf.strtab, sym.st_name) + '\n')
