from eprint import eprint
import struct
import os
import gcc_wrappers.spec

class Symbol:
    def __init__(self, buf = None):
        if buf:
            (self.st_name,
                    self.st_info,
                    self.st_other,
                    self.st_shndx,
                    self.st_value,
                    self.st_size) = struct.unpack('<IBBHQQ', buf)
        else:
            self.st_name = None
            self.st_other = None
            self.st_shndx = None
            self.st_value = None
            self.st_size = None

class SectionHeader:
    def __init__(self, buf):
        (self.sh_name,
                self.sh_type,
                self.sh_flags,
                self.sh_addr,
                self.sh_offset,
                self.sh_size,
                self.sh_link,
                self.sh_info,
                self.sh_addralign,
                self.sh_entsize) = struct.unpack('<IIQQQQIIQQ', buf)


class Elf64:
    class Fixup:
        def __init__(self, offset, patch):
            self.offset = offset # byte offset at which to overwrite with patch
            self.patch = patch   # data used to overwrite the elf file

    def __init__(self, path, error_callback):
        self.path = path
        self.error_callback = error_callback

    class MissingSection(Exception):
        pass

    def find_section(self, wanted_sect):
        """Returns a section header which as 'sect_name'
        
        raises Elf64.MissingSection if the section cannot be found
        """
        if hasattr(self, 'sect_headers_dict'):
            try:
                return self.sect_headers_dict[wanted_sect]
            except KeyError:
                raise Elf64.MissingSection

        self.sect_headers_dict = dict()
        self.sect_headers = []
        with open(self.path, 'rb') as elf:
            elf_magic = elf.read(4)
            if elf_magic != '\x7f\x45\x4c\x46':
                self.error_callback("elf file '{}' doesn't have the right bits at its"
                        " start".format(self.path))

            # Get the section header table offset
            elf.seek(16 + 2 + 2 + 4 + 8 + 8)
            sh_table_offset = struct.unpack('<Q', elf.read(8))[0]
            if sh_table_offset == 0:
                self.error_callback("elf file '{}' is missing its section header table"
                        .format(self.path))

            # Get the number of entries in the section header table
            elf.seek(16 + 2 + 2 + 4 + 8 + 8 + 8 + 4 + 2 + 2 + 2 + 2)
            num_sect_headers = struct.unpack('<H', elf.read(2))[0]
            if num_sect_headers == 0:
                self.error_callback("elf file '{}' has no section headers in its "
                        "section header table".format(self.path))

            # get the section header table index of the section header strtab
            elf.seek(64 - 2)
            e_shstrndx = struct.unpack('<H', elf.read(2))[0]

            # load the section header table string table
            elf.seek(sh_table_offset + e_shstrndx * 64)
            shstrtab_offset = struct.unpack('<IIQQQ', elf.read(4 * 2 + 8 * 3))[4]
            shstrtab_size = struct.unpack('<Q', elf.read(8))[0]

            # load the strtab for ourselves
            elf.seek(shstrtab_offset)
            shstrtab = elf.read(shstrtab_size)

            # now build a dictionary of section headers
            elf.seek(sh_table_offset)
            for idx in xrange(num_sect_headers):
                read = elf.read(64)
                sect_header = SectionHeader(read)
                sect_name = strtab_grab(shstrtab, sect_header.sh_name)
                self.sect_headers_dict[sect_name] = sect_header
                self.sect_headers.append(sect_header)

        # self.sect_headers is set up. Call ourselves to finish the job
        return self.find_section(wanted_sect)

    def shtab(self, sect_header_index):
        if not hasattr(self, 'sect_headers'):
            try:
                self.find_section('')
            except Elf64.MissingSection:
                pass
        return self.sect_headers[sect_header_index]

    def init_strtab(self, strtab_name):
        """Sets self.[strtab_name] if not already initialized"""
        if hasattr(self, strtab_name):
            return

        with open(self.path, 'rb') as elf:
            sh = self.find_section(strtab_name)
            elf.seek(sh.sh_offset)
            setattr(self, strtab_name[1:], elf.read(sh.sh_size))

    def get_symbols(self, symtab_name):
        if symtab_name == '.symtab':
            self.init_strtab('.strtab')
        elif symtab_name == '.dynsym':
            self.init_strtab('.dynstr')

        with open(self.path, 'rb') as elf:
            symtab_header = self.find_section(symtab_name)
            elf.seek(symtab_header.sh_offset)

            num_symtab_entries = symtab_header.sh_size / 24
            for idx in xrange(num_symtab_entries):
                sym = Symbol(elf.read(24))
                sym.idx = idx
                yield sym

    def get_rela_relocs(self, sect_name):
        sh = self.find_section(sect_name)
        num_entries = sh.sh_size / 24

        relocs = []
        with open(self.path, 'rb') as elf:
            elf.seek(sh.sh_offset)
            for idx in xrange(num_entries):
                relocs.append(Rela(elf.read(24)))
        return relocs

    def get_needed_sls(self):
        self.init_strtab('.dynstr')
        dyn_sh = self.find_section('.dynamic')

        sonames = []
        with open(self.path, 'rb') as elf:
            num_dyn_entries = dyn_sh.sh_size / 16
            for idx in xrange(num_dyn_entries):
                elf.seek(dyn_sh.sh_offset + idx * 16)
                d_tag = struct.unpack('<q', elf.read(8))[0]
                if d_tag == 1:
                    d_val = struct.unpack('<Q', elf.read(8))[0]
                    sonames.append(strtab_grab(self.dynstr, d_val))
        return sonames

    def get_deps(self, lspec):
        """Return a list of Elf64 objects on which elf_path depends
        
        lspec is a linker spec. See cdi/gcc_wrappers/spec.py
        """
        return self.get_deps_helper(lspec, None)[1:]

    def get_deps_helper(self, lspec, elf_path, paths_seen = None):
        if paths_seen == None:
            paths_seen = dict()

        elf = None
        if elf_path == None:
            elf = self
            elf_path = self.path
        else:
            elf = Elf64(elf_path, self.error_callback)
        elfs = [elf]

        for sl_name in elf.get_needed_sls():
            sl_path = ''
            if os.path.isabs(sl_name):
                sl_path = sl_name
            else:
                # Do not add ld.so as a dependency
                if gcc_wrappers.lib_utils.sl_linker_name(sl_name) == 'ld-linux-x86-64.so':
                    continue

                # we were given a SONAME. Get the path
                sl_path = gcc_wrappers.spec.find_lib(sl_name, lspec)

            try:
                if paths_seen[sl_path]:
                    continue
            except KeyError:
                paths_seen[sl_path] = True
                elfs += self.get_deps_helper(lspec, sl_path, paths_seen)
        return elfs

    def fixup(self, elf_fixups):
        with open(self.path, 'r+b') as elf:
            for fixup in elf_fixups:
                elf.seek(fixup.offset)
                elf.write(fixup.patch)


class Rela:
    def __init__(self, buf):
        self.r_offset, self.r_info, self.r_addend = struct.unpack('<QQq', buf)


def strtab_grab(strtab, idx):
    """Returns the string at index idx of strtab"""
    return strtab[idx:strtab.find('\x00', idx)]

def strtab_startswith(strtab, start_idx, desired):
    """Returns true if string at idx starts with desired"""
    for idx in xrange(start_idx, start_idx + len(desired)):
        if strtab[idx] != desired[idx - start_idx]:
            return False
    return True

def strip_sym_versioning(sym_name):
    versioning_idx = sym_name.find('@@')
    if versioning_idx == -1:
        return sym_name
    else:
        return sym_name[:versioning_idx]

def strip_sl_versioning(sl_path):
    """Assumes that 'sl_path' contains a '.so'"""
    return sl_path[:sl_path.rfind('.so') + len('.so')]

def get_soname(sl_path):
    """Transforms a path into an SONAME i.e. /path/to/libc.so.6.1.2 -> libc.so.6

    If there is no versioning, this is equivalent to getting the lib filename
    """
    so_idx = sl_path.rfind('.so')
    soname_end_idx = sl_path.find('.', so_idx + len('.so') + 1)
    if soname_end_idx == -1:
        return os.path.basename(sl_path)
    else:
        return os.path.basename(sl_path[:soname_end_idx])
