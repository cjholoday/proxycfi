import elfparse
import sys
import binascii
from capstone import *

# functor used to avoid excessive parameter passing
class Verifier:
    def __init__(self, file_object, exec_sections, function_list, plt_addresses):
        self.binary = file_object
        self.exec_sections = exec_sections
        self.function_list = function_list
        self.plt_addresses = plt_addresses

    def verify(self, function):
        """Recursively verifies that function is CDI compliant"""
        
        calls, jumps, instruction_addresses = inspect(function)
        
        # check that call target first instruction of some function
        
        # check that each jump goes to a function in this code object
        # store the outgoing address of the jump with the function it points to
        
        # recursively analyze functions that are called by this function
        
        pass # TODO
    def judge(self):
        """Returns true iff the file object is CDI compliant
        
        Wrapper for Verifier.verify
        """
        
        # find main in function_list (TODO)
        # try:
        #     # verify(main) TODO
        #     verify(main)
        # except InsecureJump as err:
        #     err.print_debug_info()
        #     raise

        # check that no jumps go to middle of instruction (TODO)
        # verify shared library portion (TODO)
        # verify .init, _start, etc. (TODO)
        
        return True

 
    def inspect(self, function):
        """Returns a list of calls, jumps, and valid instr addresses as tuple
        
        Raises IndirectJump if there are any indirect jumps
        """
        jmps = []
        calls = []
        loops = []
        addresses = []

        jmp_list = ["jo","jno","jb","jnae","jc","jnb","jae","jnc","jz","je","jnz",
                "jne","jbe","jna","jnbe","ja","js"]
         
        call_list = ["call"]

        loop_list = ["loopz","loopnz", "loope","loopne", "loop"]
        file = open(self.binary.name, 'rb')
        file.seek(function.file_offset)
        buff = file.read(int(function.size))
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for i in md.disasm(buff, int(function.virtual_address,16)):
            addresses.append(i.address)
            print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            addresses
            if i.mnemonic in jmp_list:
                jmps.append(i.op_str)
            elif i.mnemonic in call_list:
                calls.append(i.op_str)
            elif i.mnemonic in loop_list:
                loops.append(i.op_str)

        print len(jmps),len(calls),len(loops),len(addresses)

        return jmps,calls,loops,addresses


#############################
# Exception Types
#############################

class Error(Exception):
    pass

class InsecureJump(Error):
    def __init__(self, section, function, site_address, jump_address):
        self.section = section
        self.function = function
        self.site_address = site_address
        self.jump_address = jump_address

    def print_debug_info(self):
        pass # TODO

class IndirectJump(InsecureJump):
    """Exception for unconstrained indirect jump"""
    
    def print_debug_info(self):
        super(InsecureJump, self).print_debug_info()
        pass # TODO

class IntraInstructionJump(InsecureJump):
    """Exception for jump pointing to the middle of an instruction"""
    
    def print_debug_info(self):
        super(InsecureJump, self).print_debug_info()
        pass # TODO

class IntraFunctionCall(InsecureJump):
    """Exception for a call-instruction pointing to the middle of a function"""
    
    def print_debug_info(self):
        super(InsecureJump, self).print_debug_info()
        pass # TODO

class OutOfObjectJump(InsecureJump):
    """Exception for a jump out of the same code object"""
    
    def print_debug_info(self):
        super(InsecureJump, self).print_debug_info()
        pass # TODO

#############################
# Script
#############################

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print 'Usage: python verify_cdi <filename>'
    
    binary = open(sys.argv[1], 'rb')
    exec_sections = elfparse.gather_exec_sections(binary)

    functions = elfparse.gather_functions(binary, exec_sections)
    plt_start_addr, plt_size = elfparse.gather_plts(binary)
    # print plt_start_addr, plt_size 
    verifier = Verifier(binary, exec_sections, functions, []) # TODO plt_addresses
    # for f in functions:
    #     print f.name
    verifier.inspect(functions[8])
    if verifier.judge():
        sys.exit(0)
    else:
        sys.exit(1)


