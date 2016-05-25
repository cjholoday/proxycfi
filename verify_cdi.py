import elfparse
import sys

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
        try:
            pass
            # verify(main) TODO
            
        except InsecureJump as err:
            err.print_debug_info()
            raise

        # check that no jumps go to middle of instruction (TODO)
        # verify shared library portion (TODO)
        # verify .init, _start, etc. (TODO)
        
        return True

 
    def inspect(self, function):
        """Returns a list of calls, jumps, and valid instr addresses as tuple
        
        Raises IndirectJump if there are any indirect jumps
        """
        
        pass # TODO
        return [], [], []


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
    
    if verifier.judge():
        sys.exit(0)
    else:
        sys.exit(1)


