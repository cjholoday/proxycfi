import elfparse
import sys

# functor used to avoid excessive parameter passing
class Verifier:
    def __init__(self, file_object, exec_sections, function_list):
        self.binary = file_object
        self.exec_sections = exec_sections
        self.function_list = function_list
        call_number = 0 # unique identifier for each function

    def judge(self):
        """Returns true iff the file object is CDI compliant
        
        Wrapper for Verifier.verify
        """
        
        # find main in function_list TODO
        
        try:
            # verify(main) TODO
            return True
        
        except IndirectJump:
            raise # TODO
        except IntraInstructionJump:
            raise # TODO
        except IntraFunctionCall:
            raise # TODO
        except OutOfObjectJump:
            raise # TODO
        
        return False

    def verify(self, function):
        """Recursively verifies that function is CDI compliant"""
        
        pass # TODO

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print 'Usage: python verify_cdi <filename>'
    
    binary = open(sys.argv[1], 'rb')
    exec_sections = elfparse.gather_exec_sections(binary)
    
    functions = []
    for section in exec_sections:
        functions += elfparse.gather_functions(binary, section)
    
    verifier = Verifier(binary, exec_sections, functions)
    
    if verifier.judge():
        sys.exit(0)
    else:
        sys.exit(1)

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

class IndirectJump(InsecureJump):
    """Exception for unconstrained indirect jump"""

class IntraInstructionJump(InsecureJump):
    """Exception for jump pointing to the middle of an instruction"""

class IntraFunctionCall(InsecureJump):
    """Exception for a call-instruction pointing to the middle of a function"""

class OutOfObjectJump(InsecureJump):
    """Exception for a jump out of the same code object"""

