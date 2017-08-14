import __init__

import common.elf

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

def build_multtab(globl_funct_mults, write_path):
    pass

def get_funct_mults(target_elf, lspec):
    """Returns a dict mapping {symbol string -> GlobalMultiplicity object}"""

    # maps a global symbol name to a GlobalMultiplicity object
    globl_funct_mults = dict()

    elf_deps = target_elf.get_deps(lspec)
    for elf in elf_deps:
        print elf.path
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

    # insist that the symbol is for a function of global scope
    if sym_type != 2 or ((not sym_bind == 1) and (not sym_bind == 2)):
        return

    # if this symbol is defined elsewhere update the multiplicity. Otherwise,
    # claim the symbol for this code object
    sym_name = strtab_grab(strtab, sym.st_name)
    sym_name = common.elf.strip_versioning(sym_name)
    if sym.st_value == 0: 
        try:
            globl_funct_mults[sym_name].mult += 1
        except KeyError:
            globl_funct_mults[sym_name] = GlobalMultiplicity(sym_name, 1, False)
    else:
        try:
            globl_funct_mults[sym_name].is_claimed = True
        except KeyError:
            globl_funct_mults[sym_name] = GlobalMultiplicity(sym_name, 0, True)
