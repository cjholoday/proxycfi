import elfparse
import sys
from operator import attrgetter

# functor used to avoid excessive parameter passing
class Verifier:
    def __init__(self, file_object, exec_sections, function_list, plt_start_addr,
            plt_size):
        self.binary = file_object
        self.exec_sections = exec_sections
        self.plt_start_addr = plt_start_addr
        self.plt_size = plt_size
        
        self.function_list = sorted(function_list, 
                key=attrgetter('virtual_address'))

    def verify(self, function):
        """Recursively verifies that function is CDI compliant"""
        
        calls, jumps, instruction_addresses = self.inspect(function)
        
        
        
        # check that each jump goes to a function in this code object
        # store the outgoing address of the jump with the function it points to
        
        # recursively analyze functions that are called by this function
        
        pass # TODO
    def judge(self):
        """Returns true iff the file object is CDI compliant
        
        Wrapper for Verifier.verify 
        """
        
        for f in self.function_list:
            if f.name == 'main':
                main = f
                break

        try:
            self.verify(main)
            
        except InsecureJump as err:
            err.print_debug_info()
            raise

        # check that no jumps go to middle of instruction (TODO)
        # verify shared library portion (TODO)
        # verify .init, _start, etc. (TODO)
        
        return True

    def containing_function(self, virtual_address):
        """Returns a function that contains the address. Otherwise, None
        
        Assumes the function list is sorted by virtual_address
            (it's sorted in __init__)
        There really is no standard library function for this purpose"""

        # candidate function found by modified binary search
        candidate = None 
        address = int(virtual_address, 16)
        
        left = 0
        right = len(self.function_list) - 1
        
        # modified binary search: 
        #   invariant: left_address <= max({f | function f contains address})
        #   'larger' functions have larger addresses
        #   invariant only makes sense if there is a function that contains address

        # while size 3 subarray or larger
        while (right - left >= 2):
            middle = (right + left) / 2 

            if address < int(self.function_list[middle].virtual_address, 16):
                right = middle - 1
            elif address > int(self.function_list[middle].virtual_address, 16):
                # maintains invariant
                left = middle 
            else:
                candidate = self.function_list[middle]
                break

        # case subarray of size 0
        if left > right:
            candidate = None

        # case subarray of size 1
        elif left == right:
            if address >= int(self.function_list[left].virtual_address, 16):
                candidate = self.function_list[left]
            else:
                candidate = None

        # case subarray size 2
        elif left == right - 1:
            if address >= int(self.function_list[right].virtual_address, 16):
                candidate = self.function_list[right]
            elif address >= int(self.function_list[left].virtual_address, 16):
                candidate = self.function_list[left]
            else:
                candidate = None

        # check that the address is in candidate's address range 
        # address might be in the whitespace between functions!
        if candidate == None:
            # no candidate even found in the search so no containing function exists
            return None
        elif address < int(candidate.virtual_address, 16) + int(candidate.size, 16):
            return candidate
        else:
            # address in whitespace between functions
            return None
 
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
    def __init__(self, section, function, site_address, jump_address, message):
        self.section = section
        self.function = function
        self.site_address = site_address
        self.jump_address = jump_address
        self.message = message

    def print_debug_info(self):
        print 'Insecure jump details: '
        print '\tsection: \t' + self.section.name
        print '\tfunction: \t' + self.function.name
        print '\tsite address: \t' + self.site_address
        print '\tjump address: \t' + self.jump_address
        print '\tmessage: \t' + self.message

class IndirectJump(InsecureJump):
    """Exception for unconstrained indirect jump"""
    
    def print_debug_info(self):
        print '--INDIRECT JUMP--'
        InsecureJump.print_debug_info(self)

class MiddleOfInstructionJump(InsecureJump):
    """Exception for jump pointing to the middle of an instruction"""
    
    def print_debug_info(self):
        print '--MIDDLE OF INSTRUCTION JUMP--'
        InsecureJump.print_debug_info(self)

class MiddleOfFunctionCall(InsecureJump):
    """Exception for a call-instruction pointing to the middle of a function"""
    
    def print_debug_info(self):
        print '--CALL TO MIDDLE OF FUNCTION--'
        InsecureJump.print_debug_info(self)

class OutOfObjectJump(InsecureJump):
    """Exception for a jump out of the same code object"""
    
    def print_debug_info(self):
        print '--JUMP TO OUTSIDE OF OBJECT--'
        InsecureJump.print_debug_info(self)

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

    verifier = Verifier(binary, exec_sections, functions, plt_start_addr, 
            plt_size)

    for f in functions:
        print f.name, f.virtual_address
    
    if verifier.judge():
        sys.exit(0)
    else:
        sys.exit(1)


