import subprocess
import sys
import re

class ExecSection:
    def __init__(self, name, size, file_offset, virtual_address, index):
        self.name = name
        self.size = size
        self.file_offset = file_offset
        self.virtual_address = virtual_address
        self.elf_index = index
        
        functions = []

class Function:
    def __init__(self, name, size, file_offset, virtual_address):
        self.name = name
        self.size = size
        self.file_offset = file_offset
        self.virtual_address = virtual_address
        verified = False
        
        # Will contain 2-tuples: (outgoing_vma, site_virtual_address) 
        calls = []
    
    def contains_address(self, virtual_address):
        assert virtual_address > 0
        
        return (virtual_address >= self.virtual_address and 
                virtual_address < self.virtual_address + self.size)

    def add_call(self, outgoing_vma, site_vma):
        assert outgoing_vma > 0
        assert self.contains_address(site_vma)
        
        calls.append((outgoing_vma, site_vma))

def gather_exec_sections(binary):
    """Outputs a list of the executable sections found in file object <binary>
    """
    
    raw_section_info = ''
    
    try:
        raw_section_info = (
                subprocess.check_output(['readelf', '-S', binary.name]))
    
    except subprocess.CalledProcessError:
        sys.stderr.write('readelf failed in gathering executable sections')
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


def gather_functions(binary, exec_section):
    """Outputs a list of functions from the ExecSection object passed
    
    exec_sections should be a list of ExecSections
    binary should be a file object for the executable being analyzed
    """
    functions = []
    try:
            symbols = subprocess.check_output("readelf -s "+binary.name, stderr=subprocess.STDOUT, shell=True)
    except subprocess.CalledProcessError as e:
            print e.output

    for symbol in symbols.splitlines():
        column = symbol.split()
        if len(column) > 3:
            if column[3] == "FUNC":
                offset = 0
                in_ex_sec = False
                for es in exec_section:
                    ind = column[6]
                    section_index = re.search(r"\d+(\.\d+)?", es.elf_index).group(0)
                    if ind == section_index:
                        in_ex_sec = True
                        offset = int(column[1], 16) - int(es.virtual_address, 16)
                if in_ex_sec:
                    functions.append(Function(column[7],column[2],offset,column[1]))
    return functions

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
    virtual_address = hex(int(line1_fields[2], 16))
    file_offset = int(line1_fields[3], 16)
    size = int(line2_fields[0], 16)
    
    sect = ExecSection(name, size, file_offset, virtual_address, section_index)
    section_list.append(sect)




