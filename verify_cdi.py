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
        
        # find main in function_list
        # verify(main)
        pass # TODO

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


