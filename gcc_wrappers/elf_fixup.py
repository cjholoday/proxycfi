import lib_utils
import common.elf
import error
import spec
import os

class GlobalMultiplicity:
    def __init__(self, sym_name, multiplicity, is_claimed):
        self.sym = sym_name
        self.mult = multiplicity

        # True if claimed by a CDI shared library. This is used to check if a
        # symbol belongs to a CDI code object. If not, then the PLT entry for
        # this symbol should not be modified
        self.is_claimed = is_claimed 
        
def cdi_fixup_elf(lspec):
    """Prepare an elf binary for the CDI loader by overwriting/adding data"""
    # maps a global symbol name to a GlobalMultiplicity object
    globl_funct_mults = dict()

    target_elf = common.elf.Elf64(lspec.target, error.fatal_error)

    target_fixups = [] 
    elf_deps = target_elf.get_deps(lspec)
    for elf in elf_deps:
        print elf.path
        try:
            elf.find_section('.cdi')
        except common.elf.Elf64.MissingSection:
            continue # this file isn't CDI. Do not get metadata from it
        for sym in elf.get_symbols('.symtab'):
            update_mults(sym, elf.strtab, globl_funct_mults)

    plt_sym_strs = extract_plt_sym_strs(target_elf)
    plt_return_addrs = dict()

    for sym in target_elf.get_symbols('.symtab'):
        # only update multiplicities of existing symbols
        if sym.st_value == 0:
            update_mults(sym, target_elf.strtab, globl_funct_mults)


    print plt_sym_strs

    # _CDI_abort multiplicity doesn't affect SLT size, so remove info on it
    if '_CDI_abort' in globl_funct_mults:
        del globl_funct_mults['_CDI_abort']
        
    for sym, gmult in globl_funct_mults.iteritems():
        print '{}\t\t{}\t{}'.format(gmult.sym, gmult.mult, gmult.is_claimed)
            

def extract_plt_sym_strs(elf):
    """Returns a list of names. Each name is associated with a PLT entry, respectively"""

    plt_relocs = elf.get_rela_relocs('.rela.plt')
    if plt_relocs == []:
        return []

    reloc_strs = []
    for sym in elf.get_symbols('.dynsym'):
        if sym.idx == (plt_relocs[len(reloc_strs)].r_info >> 32):
            reloc_strs.append(common.elf.strtab_cstring(elf.dynstr, sym.st_name))
        if len(plt_relocs) == len(reloc_strs):
            return reloc_strs
    else:
        error.fatal_error('could not find a string for each plt relocation')

def get_plt_return_addr_dict(elf, plt_sym_strs):
    """Returns a dict mapping {PLT symbol -> address after call}"""
    # plt_offset, plt_size = elf.find_section('.plt')
    # for sym_str in plt_sym_strs:


def cdi_plt_fixups(elf, globl_funct_mults, plt_sym_strs):
    """Returns fixups to replace each CDI plt's indirect jump with an indirect call 
    
    PLT entries that are associated with a non CDI shared library (if any exist)
    are not fixed up

    While this isn't CDI compliant, it will be changed in the future
    """

    plt_sh = elf.find_section('.plt')
    num_entries = plt_sh.size / 16

    # Go through all PLT entries except the first, which is special
    fixups = []
    for idx in xrange(1, num_entries):
        plt_sym_str = plt_sym_strs[idx]
        try:
            # only fix up PLT entries that are for CDI libraries
            if globl_funct_mults[plt_sym_str].is_claimed:
                fixups.append(common.elf.Elf64.Fixup(plt_sh.offset + idx * 16 + 1, '\x15'))
        except KeyError:
            # this PLT can't be for a CDI library. Othwerise, it would've been
            # in the function multiplicity table. Do not fix up this PLT
            pass 
    return fixups
    
def update_mults(sym, strtab, globl_funct_mults):
    sym_type = sym.st_info & 15 # take the lower four bits
    sym_bind = (sym.st_info & 240) >> 4 # take the higher four bits

    # insist that the symbol is for a function of global scope
    if sym_type != 2 or ((not sym_bind == 1) and (not sym_bind == 2)):
        return

    # if this symbol is defined elsewhere update the multiplicity. Otherwise,
    # claim the symbol for this code object
    sym_name = common.elf.strtab_cstring(strtab, sym.st_name)
    sym_name = strip_versioning(sym_name)
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

def strip_versioning(sym_name):
    versioning_idx = sym_name.find('@@')
    if versioning_idx == -1:
        return sym_name
    else:
        return sym_name[:versioning_idx]
        


def process_symbol(sym, fixups):
    pass


            




