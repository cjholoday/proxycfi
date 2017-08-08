from eprint import eprint
import struct

class Elf64:
    class Fixup:
        def __init__(self, offset, patch):
            self.offset = offset # byte offset at which to overwrite with patch
            self.patch = patch   # data used to overwrite the elf file

    def __init__(self, path, error_callback):
        self.path = path
        self.error_callback = error_callback

    def section_offset(self, sect_name):
        if hasattr(self, 'sect_offsets'):
            return self.sect_offsets[sect_name]

        self.sect_offsets = dict()
        with open(self.path, 'rb') as elf:
            elf_magic = elf.read(4)
            if elf_magic != '\x7f\x45\x4c\x46':
                self.error_callback("elf file '{}' doesn't have the right bits at its"
                        " start".format(self.path))

            # Get the section header table offset
            elf.seek(16 + 2 + 2 + 4 + 8 + 8)
            sect_header_offset = struct.unpack('<Q', elf.read(8))[0]
            if sect_header_offset == 0:
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
            elf.seek(sect_header_offset + e_shstrndx * 64)
            shstrtab_offset = struct.unpack('<IIQQQ', elf.read(4 * 2 + 8 * 3))[4]
            shstrtab_size = struct.unpack('<Q', elf.read(8))[0]

            # load the strtab for ourselves
            elf.seek(shstrtab_offset)
            shstrtab = elf.read(shstrtab_size)

            # now build a dictionary of section header offsets
            elf.seek(sect_header_offset)
            for idx in xrange(num_sect_headers):
                sh_name = struct.unpack('<I', elf.read(4))[0]
                sh_offset = struct.unpack('<IQQQ', elf.read(4 + 8 * 3))[3]
                self.sect_offsets[strtab_cstring(shstrtab, sh_name)] = sh_offset
                elf.seek(sect_header_offset + idx * 64)

        return self.sect_offsets[sect_name]

    def fixup(self, elf_fixups):
        pass


def strtab_cstring(strtab, idx):
    """Returns the string at index idx of strtab"""
    return strtab[idx:strtab.find('\x00', idx)]
