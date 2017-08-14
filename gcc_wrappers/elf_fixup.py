import __init__

import spec
import os
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
    plt_sym_strs  = extract_plt_sym_strs(target_elf)

    rrel32_fixups = get_rrel32_fixups(target_elf)
    rlt_fixups    = get_rlt_fixups(target_elf, plt_sym_strs)
    target_elf.fixup(rrel32_fixups + rlt_fixups)


    globl_funct_mults = multtab.get_funct_mults(target_elf, lspec)

    # _CDI_abort multiplicity doesn't affect SLT size, so remove info on it
    if '_CDI_abort' in globl_funct_mults:
        del globl_funct_mults['_CDI_abort']

    plt_fixups = get_plt_fixups(target_elf, globl_funct_mults, plt_sym_strs)

    if not lspec.target_is_shared:
        multtab.build_multtab(target_elf, lspec, globl_funct_mults, '.cdi/cdi_multtab')

    for sym, gmult in globl_funct_mults.iteritems():
        print '{}\t\t{}\t{}'.format(gmult.sym, gmult.mult, gmult.is_claimed) 
    write_removable_syms(target_elf, '.cdi/removable_cdi_syms')
    try:
        subprocess.check_call(['objcopy',
            '--strip-symbols={}/.cdi/removable_cdi_syms'.format(os.getcwd()), lspec.target])
    except subprocess.CalledProcessError:
        error.fatal_error("couldn't remove symbols from target '{}'".format(lspec.target))

def get_slt_tramptab_fixups(elf, globl_funct_mults):
    pass

def get_rlt_fixups(elf, plt_sym_strs):
    try:
        rlt_sh = elf.find_section('.cdi_rlt')
    except common.elf.Elf64.MissingSection:
        eprint('cdi-ld: warning: no .cdi_rlt section in target')
        return []

    plt_ret_addrs = get_plt_ret_addr_dict(elf, plt_sym_strs)
    
    rlt_fixups = []
    for sym in elf.get_symbols('.symtab'):
        if strtab_startswith(elf.strtab, sym.st_name, '_CDI_RLT_'):
            sym_str = strtab_grab(elf.strtab, sym.st_name)
            rlt_entry_offset = sym.st_value - rlt_sh.sh_addr + rlt_sh.sh_offset
            plt_ret_addr = plt_ret_addrs[sym_str[len('_CDI_RLT_'):]]

            # associate PLT callq return address with this RLT entry
            rlt_fixups.append(common.elf.Elf64.Fixup(
                rlt_entry_offset - 8, struct.pack('<Q', plt_ret_addr)))
    return rlt_fixups

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

def get_plt_fixups(elf, globl_funct_mults, plt_sym_strs):
    """Returns fixups to replace each CDI plt's indirect jump with an indirect call 
    
    PLT entries that are associated with a non CDI shared library (if any exist)
    are not fixed up

    While this isn't CDI compliant, it will be changed in the future
    """

    plt_sh = elf.find_section('.plt')
    num_entries = plt_sh.sh_size / plt_sh.sh_entsize

    # Go through all PLT entries except the first, which is special
    fixups = []
    for idx in xrange(1, num_entries):
        plt_sym_str = plt_sym_strs[idx - 1]
        try:
            # only fix up PLT entries that are for CDI libraries
            if globl_funct_mults[plt_sym_str].is_claimed:
                fixups.append(common.elf.Elf64.Fixup(plt_sh.sh_offset + idx * 16 + 1, '\x15'))
        except KeyError:
            # this PLT can't be for a CDI library. Othwerise, it would've been
            # in the function multiplicity table. Do not fix up this PLT
            pass 
    return fixups

def extract_plt_sym_strs(elf):
    """Returns the name of each .plt entry, in order"""

    plt_relocs = elf.get_rela_relocs('.rela.plt')
    if plt_relocs == []:
        return []

    reloc_strs = []
    for sym in elf.get_symbols('.dynsym'):
        if sym.idx == (plt_relocs[len(reloc_strs)].r_info >> 32):
            reloc_strs.append(strtab_grab(elf.dynstr, sym.st_name))
        if len(plt_relocs) == len(reloc_strs):
            return reloc_strs
    else:
        error.fatal_error('could not find a string for each plt relocation')

def get_plt_ret_addr_dict(elf, plt_sym_strs):
    """Returns a dict mapping {PLT symbol name -> address after call}"""
    plt_sh = elf.find_section('.plt')

    plt_ret_addrs = dict()
    for idx, sym_str in enumerate(plt_sym_strs):
        entry_vaddr = plt_sh.sh_addr + plt_sh.sh_entsize * (idx + 1)
        plt_ret_addrs[sym_str] = entry_vaddr + 6 # after the callq
    return plt_ret_addrs
    

def write_removable_syms(elf, path):
    """Saves all the removable symbol names in filename at path"""
    with open(path, 'w') as log:
        for sym in elf.get_symbols('.symtab'):
            if strtab_startswith(elf.strtab, sym.st_name, '_CDIX_'):
                log.write(strtab_grab(elf.strtab, sym.st_name) + '\n')
