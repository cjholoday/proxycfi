import subprocess
import sys
import re
import types
import getopt
from eprint import eprint

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
        assert type(virtual_address) is types.IntType
        
        return (virtual_address >= self.virtual_address and 
                virtual_address < self.virtual_address + self.size)

class Function:
    def __init__(self, name, size, file_offset, virtual_address):
        self.name = name
        self.verified = False

        # stored as integers. Use hex() to get a hex string representation
        self.size = size
        self.file_offset = file_offset
        self.virtual_address = virtual_address

        # virtual addresses of all "return" jumps to this function
        self.incoming_returns = []

        assert type(self.size) is types.IntType
        assert type(self.file_offset) is types.IntType
        assert type(self.virtual_address) is types.IntType
    
    def contains_address(self, virtual_address):
        assert type(virtual_address) is types.IntType
        assert virtual_address > 0
        
        return (virtual_address >= self.virtual_address and 
                virtual_address < self.virtual_address + self.size)

def gather_exec_sections(binary):
    """Outputs a list of the executable sections found in file object <binary>
    """
    
    raw_section_info = ''
    
    try:
        raw_section_info = (
                subprocess.check_output(['readelf', '-S', binary.name]))
    
    except subprocess.CalledProcessError:
        eprint('FATAL ERROR: Cannot use readelf -S on ' + binary.name)
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
                exec_sections)
        i += 2

    assert len(exec_sections) > 0
    
    return exec_sections


def gather_functions(binary, exec_sections):
    """Outputs a list of functions from the ExecSections passed
    
    exec_sections should be a list of ExecSections
    binary should be a file object for the executable being analyzed
    """
    functions = []
    try:
        readelf_text = subprocess.check_output(['readelf', '-s', binary.name])
    except subprocess.CalledProcessError as e:
        eprint('FATAL ERROR: Cannot use readelf -s on ' + binary.name)
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
        eprint('FATAL ERROR: Symbol table (".symtab") not found in ' + binary.name)
        sys.exit(1)

    while i < len(table_lines):
        symbols = table_lines[i].split()
        if len(symbols) > 3:
            if symbols[3] == "FUNC":
                offset = 0
                in_ex_sec = False
                for es in exec_sections:
                    ind = symbols[6]
                    section_index = re.search(r"\d+(\.\d+)?", es.elf_index).group(0)
                    if ind == section_index:
                        in_ex_sec = True
                        offset = int(symbols[1], 16) - es.virtual_address
                        file_offset = es.file_offset + offset
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


def gather_plts(binary):
    """ Outputs list of plt entries in a given binary
    binary should be a file object for the executable being analyzed
    """
    plts = []
    try:
        sections = subprocess.check_output(['readelf', '-S', binary.name])
    except subprocess.CalledProcessError as e:
        print e.output
    found_plt = False
    start_address = 0
    plt_size = 0
    entry_size = 0
    size = 0
    for section in sections.splitlines():
        column = section.split()

        if found_plt:
            plt_size = int(column[0],16)
            entry_size = int(column[1], 16)
            break
        if len(column) > 1:
            if column[1] == ".plt":
                start_address = int(column[3], 16)
                found_plt = True

    return start_address, plt_size, entry_size

#############################
# Helper Functions
#############################

def extract_section(line1, line2, section_list):
    """Extracts ExecSection from the two lines in readelf that define it

    Returns ExecSection with '' as name if the lines define no ExecSection
    """
    
    idx_left_bound = line1.find('[')
    idx_right_bound = line1.find(']')
    if idx_left_bound == -1 or idx_right_bound == -1:
        return
    
    section_index = repr(line1[idx_left_bound + 1:idx_right_bound])
    if section_index == 0:
        return 
    
    line1_fields = line1[idx_right_bound + 1:].strip().split()
    line2_fields = line2.strip().split()
    if 'X' not in line2_fields[2]:
        return 
    
    name = line1_fields[0];
    virtual_address = int(line1_fields[2], 16)
    file_offset = int(line1_fields[3], 16)
    size = int(line2_fields[0], 16)

    
    sect = ExecSection(name, size, file_offset, virtual_address, section_index)
    section_list.append(sect)




