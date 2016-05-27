import bisect
import elfparse
import sys
import binascii
from capstone import *
from operator import attrgetter


# functor used to avoid excessive parameter passing
class Verifier:
    def __init__(self, file_object, exec_sections, function_list, plt_start_addr,
            plt_size, exit_on_insecurity = True):
        self.binary = file_object
        self.exec_sections = exec_sections
        self.plt_start_addr = plt_start_addr
        self.plt_size = plt_size
        self.exit_on_insecurity = exit_on_insecurity
        self.secure = True # secure until proven otherwise
        
        self.function_list = sorted(function_list, 
                key=attrgetter('virtual_address'))

    def verify(self, function):
        """Recursively verifies that function is CDI compliant"""

        function.verified = True

        try:
            calls, jumps, loops, instruction_addresses = self.inspect(function,
                    self.plt_start_addr, self.plt_size)
            functions_called = []

            for addr in calls:
                function_of_addr = self.containing_function(addr)
                if function_of_addr.virtual_address != addr:
                    raise InvalidFunctionCall(self.containing_section(addr),
                            function, 'not calculated', addr, None)

                functions_called.append(function_of_addr)

            for addr in loops:
                candidate_idx = bisect_left(instruction_addreses, addr)
                if (candidate_idx == len(instruction_addresses) or 
                        instruction_addresses[candidate_idx] != addr):
                    raise LoopOutOfFunction(self.containing_section(addr),
                            function, 'not calculated', addr, None)

            for addr in jumps:
                target_function = self.containing_function(addr)
                if target_function == None:
                    raise OutOfObjectJump(self.containing_section(addr, function,
                            'not calculated', addr, 'jump may target whitespace'
                            'between functions'))
                # check that jumps back into function don't go to middle of instrs
                elif target_function == function:
                    candidate_idx = bisect.bisect_left(instruction_addresses, addr)
                    if (candidate_idx == len(instruction_addresses) or 
                            instruction_addresses[candidate_idx] != addr):
                        raise MiddleOfInstructionJump(self.containing_section(addr),
                                function, 'not calculated', addr, 'the rogue jump'
                                'is from ' + function.name)

                # handle jumps to other functions at end of depth first search
                else:
                    target_function.incoming_returns.append(addr)

        except InsecureJump as err:
            self.secure = False
            err.print_debug_info()
            if self.exit_on_insecurity:
                raise

        for funct in functions_called:
            if not funct.verified:
                verify(funct)

    def judge(self):
        """Returns true iff the file object is CDI compliant
        
        Wrapper for Verifier.verify 
        """

        main = None
        for f in self.function_list:
            if f.name == 'main':
                main = f
                break
        else:
            raise NoMainFunction()

        self.verify(main)

        # check that no jumps go to middle of instruction (TODO)
        # verify shared library portion (TODO)
        # verify .init, _start, etc. (TODO)
        
        return self.secure

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
    
    def containing_section(self, virtual_address):
        """Returns section that the virtual_address is in
        
        Inefficient, but suitable for our purposes"""

        for sect in self.exec_sections:
            if sect.contains_address(virtual_address):
                return sect
        return None
 
    def inspect(self, function,plt_start_addr, plt_size):
        """Returns a list of calls, jumps, and valid instr addresses as tuple
        
        Raises IndirectJump if there are any indirect jumps
        """
        jmps = []
        calls = []
        loops = []
        addresses = []
        plt_calls = []

        jmp_list = ["jo","jno","jb","jnae","jc","jnb","jae","jnc","jz","je","jnz",
                "jne","jbe","jna","jnbe","ja","js","jns","jp","jpe","jnp","jpo","jl",
                "jnge","jnl","jge","jle","jng","jnle","jg","jecxz","jrcxz","jmp","jmpe"]
         
        call_list = ["call","callf","sysenter","syscall"]

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
                addr = int(i.op_str,16)
                if addr >= plt_start_addr and addr <= plt_start_addr + plt_size:
                    if (addr - plt_start_addr) % 16 != 0:
                        raise JumpToMiddleofPLT()

                else:
                    calls.append(i.op_str)
            elif i.mnemonic in loop_list:
                loops.append(i.op_str)

        print len(jmps),len(calls),len(loops),len(addresses), len(plt_calls)

        return jmps,calls,loops,addresses


#############################
# Exception Types
#############################

class Error(Exception):
    pass

class NoMainFunction(Error):
    pass
class JumpToMiddleofPLT(Error):
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

class InvalidFunctionCall(InsecureJump):
    """Exception for a call instruction pointing anywhere but start of function"""
    
    def print_debug_info(self):
        print '--CALL DOESN\'T POINT TO START OF FUNCTION--'
        InsecureJump.print_debug_info(self)

class OutOfObjectJump(InsecureJump):
    """Exception for a jump out of the same code object"""
    
    def print_debug_info(self):
        print '--JUMP TO OUTSIDE OF OBJECT--'
        InsecureJump.print_debug_info(self)

class LoopOutOfFunction(InsecureJump):
    """Exception for a loop jump that points out of the function it's in"""

    def print_debug_info(self):
        print '--LOOP JUMP TO OUT OF FUNCTION--'
        InsecureJump.print_debug_info(self)

#############################
# Script
#############################

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print 'Usage: python verify_cdi.py <filename>'
    
    binary = open(sys.argv[1], 'rb')
    exec_sections = elfparse.gather_exec_sections(binary)

    functions = elfparse.gather_functions(binary, exec_sections)
    plt_start_addr, plt_size = elfparse.gather_plts(binary)

    verifier = Verifier(binary, exec_sections, functions, plt_start_addr, 
            plt_size, False)

    

    if verifier.judge():
        sys.exit(0)
    else:
        sys.exit(1)


