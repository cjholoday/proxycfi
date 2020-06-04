import subprocess
import sys
import re
import types
import random
import getopt
import struct
from eprint import eprint
from operator import attrgetter
from capstone import *

SIGNED_INT32_MIN = -1 * (1 << 31)
SIGNED_INT32_MAX = (1 << 31) - 1


class ExecSection:
    def __init__(self, name, size, file_offset, virtual_address, index):
        self.name = name
        self.size = size
        self.elf_index = index

        # stored as integers. Use hex() to get a hex string representation
        self.file_offset = file_offset
        self.virtual_address = virtual_address

        assert type(self.file_offset) is types.IntType
        assert type(self.virtual_address) is types.IntType

    def contains_address(self, virtual_address):
        return (virtual_address >= self.virtual_address and 
                virtual_address < self.virtual_address + self.size)

class Function:
    def __init__(self, name, size, file_offset, virtual_address):
        self.name = name
        self.verified = False

        # stored as integers. Use hex() to get a hex string representation
        self.size = size
        self.file_offset = file_offset
        self.addr = virtual_address



        # forbid pointer proxies with value 0
        self.ptr_proxy_set = set()
        self.ptr_proxy_set.add(0)
        self.ptr_proxies = dict()

        # a list tuples (old_proxy, new_proxy, addr, callback) where callback will rewrite a proxy
        # if needed when called with the instruction before addr
        self.proxy_rewrites = []

        # virtual addresses of all "return" jumps to this function
        self.incoming_flow = []

        assert type(self.size) is types.IntType
        assert type(self.file_offset) is types.IntType
        assert type(self.addr) is types.IntType
        
    def foffset(self, addr):
        """Returns the file offset given an address within this function"""
        return addr - self.addr + self.file_offset
    
    def contains_address(self, virtual_address):
        return (virtual_address >= self.addr and 
                virtual_address < self.addr + self.size)

    def proxy_for(self, rett):
        """Returns a proxy ptr addr for returning from [this fn] -> [rett]
        
        rett should be the label at which execution will resume on return

        proxy addresses are encoded using a signed 32 bit signed int because 
        the GNU assembler requires constants be in that format
        """
        # if we've seen this return target before, return the same proxy
        if rett in self.ptr_proxies:
            return self.ptr_proxies[rett]

        new_proxy = 0
        while new_proxy in self.ptr_proxy_set:
            new_proxy = random.randrange(SIGNED_INT32_MIN, SIGNED_INT32_MAX)
        self.ptr_proxy_set.add(new_proxy)
        self.ptr_proxies[rett] = new_proxy

        return new_proxy

class Rlt:
    def __init__(self, name, start_offset, virtual_address, size):
        self.name = name
        self.start_offset = start_offset
        self.virtual_address = virtual_address
        self.size = size

def gather_exec_sections(binary_name, must_be_exec=True):
    """Outputs a list of the executable sections found in file object <binary>"""
    
    raw_section_info = ''
    
    try:
        raw_section_info = (
                subprocess.check_output(['readelf', '-S', binary_name]))
    
    except subprocess.CalledProcessError:
        eprint('FATAL ERROR: Cannot use readelf -S on ' + binary_name)
        sys.exit(1)
    
    raw_section_lines = raw_section_info.split('\n')
    
    exec_sections = []
    

    # find first pair of lines that define a section
    i = 0
    while i < len(raw_section_lines):
        if raw_section_lines[i].find('[') != -1:
            break
        else:
            i += 1

    while i + 1 < len(raw_section_lines):
        extract_section(raw_section_lines[i], raw_section_lines[i + 1],
                exec_sections, must_be_exec)
        i += 2

    assert len(exec_sections) > 0
    
    return exec_sections


def gather_functions(binary_name, exec_sections):
    """Outputs a list of functions from the ExecSections passed
    
    exec_sections should be a list of ExecSections
    binary_name should be a string path for the executable being analyzed
    """
    functions = []

    try:
        readelf_text = subprocess.check_output(['readelf', '-s', binary_name])
    except subprocess.CalledProcessError as e:
        eprint('FATAL ERROR: Cannot use readelf -s on ' + binary_name)
        sys.exit(1)
    
    table_lines = readelf_text.splitlines()

    # Ignore the dynamic symbol table because everything in the
    # the dynamic symbol table is also in the regular symbol table
    i = 0
    while i < len(table_lines):
        symbols = table_lines[i].split()
        if len(symbols) >= 2 and symbols[2] == "'.symtab'":
            break
        i += 1
    else:
        eprint('FATAL ERROR: Symbol table (".symtab") not found in ' + binary_name)
        sys.exit(1)

    while i < len(table_lines):
        symbols = table_lines[i].split()
        if len(symbols) > 3:
            if symbols[3] == "FUNC":
                offset = 0
                in_ex_sec = False
                for es in exec_sections:
                    try:
                        ind = int(symbols[6])
                        print es.elf_index
                        if ind == es.elf_index:
                            in_ex_sec = True
                            offset = int(symbols[1], 16) - es.virtual_address
                            file_offset = es.file_offset + offset
                    except ValueError:
                        pass # bad index
                if in_ex_sec:

                    # function size is displayed in hex when very large
                    # try to extract an int using both formats
                    funct_size = 0
                    try:
                        funct_size = int(symbols[2])
                    except ValueError:
                        funct_size = int(symbols[2], 16)

                    functions.append( Function(symbols[7], funct_size,
                        file_offset, int(symbols[1], 16)))

        i += 1
    return functions

class FptrProxyRewrite:
    # maps function label to corresponding global proxy. Function pointers only
    fptr_proxies = dict()
    proxies_taken = set([0])
    verifier = None
    
    def __init__(self, label, instr_addr, type):
        self.type = type
        self.instr_addr = instr_addr
        self.label = label

    def rewrite(self):
        exe = FptrProxyRewrite.verifier.rewritten_exe
        if self.type == 'QUAD':
            foffset = self.foffset
            exe.seek(foffset)
            exe.write(struct.pack('<q', self.proxy_for(self.label)))
            return
        target_funct = FptrProxyRewrite.verifier.enclosing_funct(self.instr_addr)
        foffset = target_funct.foffset(self.instr_addr)


        exe.seek(foffset)
        buf = exe.read(16)

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        instr = next(md.disasm(buf,self.instr_addr))

        exe.seek(foffset + instr.size - 4)
        exe.write(struct.pack('<i', self.proxy_for(self.label)))

    def proxy_for(self, label):
        try:
            match = FptrProxyRewrite.fptr_proxies[label]
            return match
        except KeyError:
            new_proxy = 0
            while new_proxy in FptrProxyRewrite.proxies_taken:
                new_proxy = random.randrange(SIGNED_INT32_MIN, SIGNED_INT32_MAX)
            FptrProxyRewrite.proxies_taken.add(new_proxy)
            FptrProxyRewrite.fptr_proxies[label] = new_proxy
            return new_proxy

def gather_fptr_proxy_rewrites(binary_name, exec_sections):
    """Outputs a list of functions from the ExecSections passed
    
    exec_sections should be a list of ExecSections
    binary_name should be a string path for the executable being analyzed
    """
    label_matcher = re.compile('_CDI_PROXY_(CMP|MOVQ|MOVL|QUAD)_([0-9a-f]+)_(\w+)')
    functions = []

    try:
        readelf_text = subprocess.check_output(['readelf', '--wide', '-s', binary_name])
    except subprocess.CalledProcessError as e:
        eprint('FATAL ERROR: Cannot use readelf -s on ' + binary_name)
        sys.exit(1)
    
    table_lines = readelf_text.splitlines()

    # Ignore the dynamic symbol table because everything in the
    # the dynamic symbol table is also in the regular symbol table
    symtab_idx = 0
    for i in range(len(table_lines)):
        symbols = table_lines[i].split()
        if len(symbols) >= 2 and symbols[2] == "'.symtab'":
            symtab_idx = i + 2 # skip table header
            break
    else:
        eprint('FATAL ERROR: Symbol table (".symtab") not found in ' + binary_name)
        sys.exit(1)

    fptr_rewrites = []
    for i in range(symtab_idx, len(table_lines)):
        print symbols 
        symbols = table_lines[i].split()
        if len(symbols) <= 7:
            continue
        label = symbols[7]
        if not label.startswith('_CDI_PROXY_'):
            continue

        foffset = 0
        in_ex_sec = False
        index = int(symbols[6])
        for es in exec_sections:
            if index == int(es.elf_index):
                sect_offset = int(symbols[1], 16) - es.virtual_address
                foffset = es.file_offset + sect_offset
                print foffset
                break
        else:
            eprint("verifier: error: no corresponding section found for idx '{}'".format(index))
            sys.exit(1)
            
        match = label_matcher.match(label)
        if match is None:
            eprint("verifier: error: no match on label '{}'".format(label))
            sys.exit(1)

        rewrite_type = match.group(1)
        funct_label = match.group(3)

        fptr_rewrites.append(FptrProxyRewrite(funct_label, int(symbols[1], 16), rewrite_type))

        # time pressure
        fptr_rewrites[-1].foffset = foffset

    return fptr_rewrites
    

def gather_rlts(binary_name, exec_sections, rlt_start_addr, rlt_section_offset, rlt_section_size):
    """Outputs a list of functions from the ExecSections passed
    
    exec_sections should be a list of ExecSections
    binary_name should be a string path for the executable being analyzed
    """
    rlts = []
    try:
        readelf_text = subprocess.check_output(['readelf', '-s', binary_name])
    except subprocess.CalledProcessError as e:
        eprint('FATAL ERROR: Cannot use readelf -s on ' + binary_name)
        sys.exit(1)
    
    table_lines = readelf_text.splitlines()

    # Ignore the dynamic symbol table because everything in the
    # the dynamic symbol table is also in the regular symbol table
    i = 0
    while i < len(table_lines):
        symbols = table_lines[i].split()
        if len(symbols) >= 2 and symbols[2] == "'.symtab'":
            break
        i += 1
    else:
        eprint('FATAL ERROR: Symbol table (".symtab") not found in ' + binary_name)
        sys.exit(1)

    while i < len(table_lines):
        symbols = table_lines[i].split()
        if len(symbols) > 7 and '_CDI_RLT' in symbols[7]:
            rlt_addr = int(symbols[1], 16)
            rlt_name = symbols[7]
            rlt_offset = (rlt_addr - rlt_start_addr) + rlt_section_offset
            rlts.append(Rlt(rlt_name, rlt_offset, rlt_addr, int(symbols[6], 16)))

        i += 1
    rlts = sorted(rlts, key=attrgetter('start_offset'))
    
    if rlts:
        for i in range(len(rlts) - 1):
            rlts[i].size = rlts[i+1].start_offset - rlts[i].start_offset

        rlts[len(rlts) - 1].size = rlt_section_offset + rlt_section_size - rlts[len(rlts) - 1].start_offset
    return rlts


def gather_plts_tram(binary):
    """ Outputs list of plt entries in a given binary
    binary should be a file object for the executable being analyzed
    """
    plts = []
    try:
        sections = subprocess.check_output(['readelf', '-S', binary.name])
    except subprocess.CalledProcessError as e:
        print e.output
    found_plt = False
    found_tramtab = False
    start_address = 0
    plt_size = 0
    tramtab_start_address = 0
    tramtab_size = 0
    entry_size = 0
    size = 0
    for section in sections.splitlines():
        column = section.split()
        if found_tramtab:
            tramtab_size = int(column[0],16)
            found_tramtab = False
        if found_plt:
            plt_size = int(column[0],16)
            entry_size = int(column[1], 16)
            break
        if len(column) > 1:
            if column[1] == ".plt":
                start_address = int(column[3], 16)
                found_plt = True
            if column[1] == '.cdi_tramtab':
                tramtab_start_address = int(column[3], 16)
                found_tramtab = True

    return start_address, plt_size, entry_size, tramtab_start_address, tramtab_size



def rlt_addr(binary):
    """ Outputs list of plt entries in a given binary
    binary should be a file object for the executable being analyzed
    """
    try:
        sections = subprocess.check_output(['readelf', '-S', binary.name])
    except subprocess.CalledProcessError as e:
        print e.output
    found_rlt = False
    start_address = 0
    rlt_size = 0
    entry_size = 0
    offset = 0
    for section in sections.splitlines():
        column = section.split()

        if found_rlt:
            rlt_size = int(column[0],16)
            entry_size = int(column[1], 16)
            break
        if len(column) > 1:
            if column[1] == ".cdi_rlt":
                start_address = int(column[3], 16)
                offset = int(column[4], 16) 
                found_rlt = True

    return start_address, offset, rlt_size

#############################
# Helper Functions
#############################

def extract_section(line1, line2, section_list, exec_only):
    """Extracts ExecSection from the two lines in readelf that define it

    Returns ExecSection with '' as name if the lines define no ExecSection
    """
    print line1
    print line2
    
    idx_left_bound = line1.find('[')
    idx_right_bound = line1.find(']')
    if idx_left_bound == -1 or idx_right_bound == -1:
        return
    
    try:
        section_index = int(line1[idx_left_bound + 1:idx_right_bound])
    except ValueError:
        return

    if section_index == 0:
        return 
    
    line1_fields = line1[idx_right_bound + 1:].strip().split()
    line2_fields = line2.strip().split()
    if exec_only and 'X' not in line2_fields[2]:
        return 
    
    name = line1_fields[0];
    virtual_address = int(line1_fields[2], 16)
    file_offset = int(line1_fields[3], 16)
    size = int(line2_fields[0], 16)

    
    sect = ExecSection(name, size, file_offset, virtual_address, section_index)
    section_list.append(sect)




