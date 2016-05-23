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
    
    pass # TODO

def gather_functions(binary, exec_section):
    """Outputs a list of functions from the ExecSection object passed

    exec_sections should be a list of ExecSections
    binary should be a file object for the executable being analyzed
    """

    pass # TODO

