import __init__

import os

import error
import common.elf
import struct
import lib_utils

from common.elf import strtab_grab
from common.elf import strtab_startswith

class GlobalMultiplicity:
    def __init__(self, sym_name, multiplicity, is_claimed):
        self.sym = sym_name
        self.mult = multiplicity

        # True if claimed by a CDI shared library. This is used to check if a
        # symbol belongs to a CDI code object. If not, then the PLT entry for
        # this symbol should not be modified
        self.is_claimed = is_claimed 

def build_multtab(target_elf, lspec, globl_funct_mults, write_dir):
    """Builds and writes multtab in write_dir. Same for multtab_strtab
    
    In particular, multtab is written to [write_path]/cdi_multtab and
    multtab_strtab is written to [write_path]/cdi_mstrtab
    """
    print '========= Multiplicity Table ========='
    for sym_str, mult in globl_funct_mults.iteritems():
        print sym_str, mult.mult
    print '======================================'
    multtab_strtab = '\x00'
    with open(os.path.join(write_dir, 'cdi_multtab'), 'w') as multtab:
        elf_deps = target_elf.get_deps(lspec)

        # record the number of libraries for the loader's sake
        multtab.write(struct.pack('<I', len(elf_deps)))

        for elf in elf_deps:
            try:
                slt_tramptab_sh = elf.find_section('.cdi_slt_tramptab')
                elf.init_strtab('.cdi_strtab')
            except common.elf.Elf64.MissingSection:
                continue # this file is not CDI

            elf_file = open(elf.path, 'r')
            elf_file.seek(slt_tramptab_sh.sh_offset)
            num_tramptab_entries = struct.unpack('<Q', elf_file.read(8))[0]

            total_mult = 0
            mult_bytes = ''
            for idx in xrange(num_tramptab_entries):
                cdi_strtab_idx_pieces = struct.unpack('<xxxxxBBB', elf_file.read(8))
                cdi_strtab_idx = (cdi_strtab_idx_pieces[0] 
                        + (cdi_strtab_idx_pieces[1] << 8)
                        + (cdi_strtab_idx_pieces[2] << 16))
                sym_str = strtab_grab(elf.cdi_strtab, cdi_strtab_idx)

                try:
                    globl_sym = globl_funct_mults[sym_str]
                except KeyError:
                    error.fatal_error("'{}' not found in global multiplicity dict'"
                            .format(sym_str))
                total_mult += globl_sym.mult
                mult_bytes += struct.pack('<I', globl_sym.mult)

            multtab.write(struct.pack('<I', len(multtab_strtab)))
            multtab_strtab += lib_utils.sl_linker_name(elf.path) + '\x00'

            multtab.write(struct.pack('<I', total_mult))
            multtab.write(struct.pack('<I', num_tramptab_entries))
            multtab.write(mult_bytes)
            elf_file.close()
    with open(os.path.join(write_dir, 'cdi_mstrtab'), 'w') as strtab:
        strtab.write(multtab_strtab)


def get_funct_mults(target_elf, lspec):
    """Returns a dict mapping {symbol string -> GlobalMultiplicity object}"""

    # maps a global symbol name to a GlobalMultiplicity object
    globl_funct_mults = dict()

    elf_deps = target_elf.get_deps(lspec)
    for elf in elf_deps:
        try:
            elf.find_section('.cdi')
        except common.elf.Elf64.MissingSection:
            continue # this file isn't CDI. Do not get metadata from it
        for sym in elf.get_symbols('.symtab'):
            update_mults(sym, elf.strtab, globl_funct_mults)

    for sym in target_elf.get_symbols('.symtab'):
        if sym.st_value == 0: # only update multiplicities of defined symbols
            update_mults(sym, target_elf.strtab, globl_funct_mults)

    return globl_funct_mults

def update_mults(sym, strtab, globl_funct_mults):
    sym_type = sym.st_info & 15 # take the lower four bits
    sym_bind = (sym.st_info & 240) >> 4 # take the higher four bits

    sym_str = strtab_grab(strtab, sym.st_name)
    # insist that the symbol is for a function of global scope
    if sym_type != 2 or ((not sym_bind == 1) and (not sym_bind == 2)):
        return

    # if this symbol is defined elsewhere update the multiplicity. Otherwise,
    # claim the symbol for this code object
    sym_str = strtab_grab(strtab, sym.st_name)
    sym_str = common.elf.strip_versioning(sym_str)
    if sym.st_value == 0: 
        try:
            globl_funct_mults[sym_str].mult += 1
        except KeyError:
            globl_funct_mults[sym_str] = GlobalMultiplicity(sym_str, 1, False)
    else:
        try:
            globl_funct_mults[sym_str].is_claimed = True
        except KeyError:
            globl_funct_mults[sym_str] = GlobalMultiplicity(sym_str, 0, True)
