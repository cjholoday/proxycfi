#!/usr/bin/env python

import __init__

import bisect
import sys
import binascii
import types
from common import elfparse
from common.eprint import eprint
from capstone import *
from operator import attrgetter
from getopt import getopt

IGNORE_RET_FROM_MAIN = False

# functor used to avoid excessive parameter passing
class Verifier:
    def __init__(self, file_object, exec_sections, function_list, rlts, plt_start_addr,
            plt_size, plt_entry_size, tramtab_start_addr, tramtab_size, exit_on_insecurity,
             print_instr_as_decoded):
        self.binary = file_object
        self.exec_sections = exec_sections
        self.plt_start_addr = plt_start_addr
        self.plt_size = plt_size
        self.plt_entry_size = plt_entry_size
        self.secure = True # secure until proven otherwise
        self.exit_on_insecurity = exit_on_insecurity
        self.print_instr_as_decoded = print_instr_as_decoded
        
        self.function_list = sorted(function_list, 
                key=attrgetter('virtual_address'))
        self.rlts = rlts
        self.tramtab_start_addr = tramtab_start_addr
        self.tramtab_size = tramtab_size

    def verify(self, function):
        """Recursively verifies that function is CDI compliant"""

        function.verified = True

        try:
            functions_called = []
            calls, jumps, loops, instruction_addresses = self.inspect(function,
                    self.plt_start_addr, self.plt_size, self.plt_entry_size)

            for addr in calls:
                target_function = self.target_function(addr)
                if target_function == None:
                    raise InvalidFunctionCall(self.target_section(addr), function,
                            '', addr, 'call targets no function but '
                            'may point to whitespace between functions')

                if target_function.virtual_address != addr:
                    raise InvalidFunctionCall(self.target_section(addr),
                            function, '', addr)

                functions_called.append(target_function)

            for addr in loops:
                if not function.contains_address(addr):
                    raise LoopOutOfFunction(self.target_section(addr),
                            function, '', addr)

                candidate_idx = bisect_left(instruction_addreses, addr)
                if (candidate_idx == len(instruction_addresses) or 
                        instruction_addresses[candidate_idx] != addr):
                    raise MiddleOfInstructionLoopJump(self.target_section(addr),
                            function, '', addr)

            for addr in jumps:
                target_function = self.target_function(addr)

                if target_function == None:
                    raise OutOfObjectJump(self.target_section(addr), function,
                            '', addr, 'jump may target whitespace '
                            'between functions')

                # check that jumps back into function don't go to middle of instrs
                elif target_function == function:
                    candidate_idx = bisect.bisect_left(instruction_addresses, addr)
                    if (candidate_idx == len(instruction_addresses) or 
                            instruction_addresses[candidate_idx] != addr):
                        raise MiddleOfInstructionJump(self.target_section(addr),
                                function, '', addr, 'the rogue jump '
                                'goes back into ' + function.name)

                # handle jumps to other functions at end of depth first search
                else:
                    target_function.incoming_returns.append(addr)

        except InsecureJump as insecurity:
            self.secure = False
            insecurity.print_debug_info()
            if self.exit_on_insecurity:
                raise

        for funct in functions_called:
            if not funct.verified:
                self.verify(funct)

    def judge(self):
        """Returns true iff the file object is CDI compliant
        
        Wrapper for Verifier.verify 
        """

        whitelist = ['__libc_csu_init', '__libc_csu_fini']
        for funct in self.function_list:
            # sections must have size > 0 to be considered
            # NOTE: _fini and company have size 0 so they are not verified
            if funct.name not in whitelist:
                self.verify(funct)

        # check that incoming "return" jumps are valid
        for funct in self.function_list:
            try:
                self.check_return_jumps_are_valid(funct)
            except InsecureJump as insecurity:
                insecurity.print_debug_info()
                self.secure = False

        # check rlts
        for r in self.rlts:
            verifier.check_rlt(r)
        # verify shared library portion (TODO)
        # verify .init, _start, etc. (TODO)
        
        return self.secure

    def check_return_jumps_are_valid(self, funct):
        if funct.incoming_returns == []:
            return # no returns to check!

        instruction_addresses = self.instr_addresses(funct)

        return_addr_iter = iter(sorted(funct.incoming_returns))
        return_addr = return_addr_iter.next()

        valid_addr_iter = '0'
        valid_addr = '0'
        try:
            valid_addr_iter = iter(instruction_addresses)
            valid_addr = valid_addr_iter.next()

        except StopIteration:
            sys.stderr.write('ERROR: A function wants to jump to ' +
                    funct.name + ' but ' + funct.name + ' has no instructions!\n')
            sys.exit(1)

        try:
            # python requires a while true for manual iterating...
            while True:
                if valid_addr < return_addr:
                    try:
                        valid_addr = valid_addr_iter.next()
                    except StopIteration:
                        raise MiddleOfInstructionJump(
                                self.target_section(funct.virtual_address),
                                elfparse.Function('Unknown', 0, 0, 0), 'Unknown',
                                return_addr, 'Jump goes to ' + funct.name)
                elif valid_addr > return_addr:
                        raise MiddleOfInstructionJump(
                                self.target_section(funct.virtual_address),
                                elfparse.Function('Unknown', 0, 0, 0), 'Unknown',
                                return_addr, 'Jump goes to ' + funct.name)
                else: # valid_addr == return_addr
                    return_addr = return_addr_iter.next()
        except StopIteration:
            pass 

    def target_function(self, virtual_address):
        """Returns a function that contains the address. Otherwise, None
        
        Assumes the function list is sorted by virtual_address
            (it's sorted in __init__)
        Note that addresses can be in whitespace between functions, if addr
        is in one of these whitespace areas, None will be returned

        There really is no standard library function for this purpose"""

        # candidate function found by modified binary search
        candidate = None 
        address = virtual_address
        
        left = 0
        right = len(self.function_list) - 1
        
        # modified binary search: 
        #   invariant: left_address <= max({f | function f contains address})
        #   'larger' functions have larger addresses
        #   invariant only makes sense if there is a function that contains address

        # while size 3 subarray or larger
        while (right - left >= 2):
            middle = (right + left) / 2 

            if address < self.function_list[middle].virtual_address:
                right = middle - 1
            elif address > self.function_list[middle].virtual_address:
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
            if address >= self.function_list[left].virtual_address:
                candidate = self.function_list[left]
            else:
                candidate = None

        # case subarray size 2
        elif left == right - 1:
            if address >= self.function_list[right].virtual_address:
                candidate = self.function_list[right]
            elif address >= self.function_list[left].virtual_address:
                candidate = self.function_list[left]
            else:
                candidate = None

        # check that the address is in candidate's address range 
        # address might be in the whitespace between functions!
        if candidate == None:
            # no candidate even found in the search so no containing function exists
            return None
        elif address < candidate.virtual_address + candidate.size:
            return candidate
        else:
            # address in whitespace between functions
            return None
    
    def target_section(self, virtual_address):
        """Returns section that the virtual_address is in
        
        Inefficient, but suitable for our purposes"""

        for sect in self.exec_sections:
            if sect.contains_address(virtual_address):
                return sect
        return None
 
    def inspect(self, function, plt_start_addr, plt_size, plt_entry_size):
        """Returns a list of calls, jumps, loop addresses, and valid instr addresses as tuple
        
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
         
        call_list = ["call","callf", "callq"]

        loop_list = ["loopz","loopnz", "loope","loopne", "loop"]

        # Insecure instructions list
        returns = ["ret", "retf", "iret", "retq", "iretq"]
        
        file = open(self.binary.name, 'rb')
        file.seek(function.file_offset)
        buff = file.read(int(function.size))
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        if self.print_instr_as_decoded:
            print '--------------:  ' + function.name
        prev_instruction = None
        for i in md.disasm(buff, function.virtual_address):
            addresses.append(int(i.address))
            if self.print_instr_as_decoded:
                print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            if i.mnemonic in jmp_list:
                try:
                    # Indirect calls and jumps have a * after the instruction and before the location
                    # which raises a value error exception in the casting
                    addr = int(i.op_str,16)
                    if addr >= plt_start_addr and addr <= plt_start_addr + plt_size:
                        if (addr - plt_start_addr) % plt_entry_size != 0:
                            raise MiddleOfPltEntryJump(target_section(function.virtual_address),
                                    function, '', addr, 'plt starts at ' + hex(plt_start_addr))

                    elif addr > self.tramtab_start_addr and addr <= tramtab_start_addr + tramtab_size:
                        if (addr - self.tramtab_start_addr) % 0x10 != 0:
                            raise MiddleOfTramtabEntryJump(target_section(function.virtual_address),
                                    function, '', addr, 'tramtab starts at ' + hex(tramtab_start_addr))
                    else:
                        jmps.append(addr)
                except ValueError:
                    if prev_instruction and prev_instruction.mnemonic == 'movabs':
                        register = prev_instruction.op_str.split(', ')[0]
                        mov_addr = prev_instruction.op_str.split(', ')[1]
                        if i.op_str == register:
                            jmps.append(addr)
                            prev_instruction = i
                            continue
                    if self.exit_on_insecurity:
                        raise IndirectJump(self.target_section(function.virtual_address),
                                function, hex(int(i.address)), i.op_str, 'Indirect Jmp/Jcc')
                    else:
                        IndirectJump(self.target_section(function.virtual_address),
                                function, hex(int(i.address)), i.op_str, 'Indirect Jmp/Jcc').print_debug_info()
            elif i.mnemonic in call_list:
                try:
                    addr = int(i.op_str,16)
                    if addr >= plt_start_addr and addr <= plt_start_addr + plt_size:
                        if (addr - plt_start_addr) % plt_entry_size != 0:
                            raise MiddleOfPltEntryJump(target_section(function.virtual_address),
                                    function, '', addr, 'plt starts at ' + hex(plt_start_addr))

                    else:
                        calls.append(addr)
                except ValueError:
                    if self.exit_on_insecurity:
                        raise IndirectCall(self.target_section(function.virtual_address),
                                function, hex(int(i.address)), i.op_str, 'Indirect Call')
                    else:
                        IndirectCall(self.target_section(function.virtual_address), 
                                function, hex(int(i.address)), i.op_str, 'Indirect Call').print_debug_info()

            elif i.mnemonic in returns:
                if function.name == 'main' and IGNORE_RET_FROM_MAIN:
                    # ignore the return
                    pass

                elif self.exit_on_insecurity:
                    raise IndirectJump(self.target_section(function.virtual_address), 
                            function, hex(int(i.address)), i.op_str, 'Return Instruction')
                else:
                    IndirectJump(self.target_section(function.virtual_address),
                            function, hex(int(i.address)), i.op_str, 'Return Instruction').print_debug_info()


            elif i.mnemonic in loop_list:
                loops.append(int(i.op_str, 16))
            prev_instruction = i
        if self.print_instr_as_decoded:
            print '--------------:  ' + function.name + '\n'

        return calls, jmps, loops, addresses


    def instr_addresses(self, function):
        """Returns a list of valid instr addresses for a function
        
        """
        addresses = []
        file = open(self.binary.name, 'rb')
        file.seek(function.file_offset)
        buff = file.read(int(function.size))
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for i in md.disasm(buff, function.virtual_address):
            addresses.append(int(i.address))
            
        return addresses


    def check_rlt(self, rlt):
        """ Check if the jmp address of rlt entry is not following a direct call to plt

        """
        file = open(self.binary.name, 'rb')
        file.seek(rlt.start_offset)
        buff = file.read(int(rlt.size))
        md = Cs(CS_ARCH_X86, CS_MODE_64)
       	if self.print_instr_as_decoded:
        	print '--------------:  ' + rlt.name

        for i in md.disasm(buff, rlt.virtual_address):
            if i.mnemonic == 'je':
            	# op = i.op_str.split(',') # if we are checking the 'cmp'
                addr_to_chk = int(i.op_str,16)
                for f in self.function_list:
                    if f.contains_address(addr_to_chk):
                        chk_offset = (addr_to_chk - f.virtual_address) + f.file_offset - 5

                        file.seek(0)
                        file.seek(chk_offset)
                        bf = file.read(5)

                        dis = md.disasm(bf, addr_to_chk - 5)

                        for inst in dis:
                            if (inst.mnemonic != 'call'):
                                raise RltNotAfterDirectCall(self.target_section(addr_to_chk),
                                     rlt, hex(int(i.address)), i.op_str, 'RLT_Inst.')

#############################
# Exception Types
#############################

class Error(Exception):
    pass

class InsecureJump(Error):
    def __init__(self, section, function, site_address, jump_address, message = ''):
        self.section = section
        self.function = function
        self.site_address = site_address
        self.jump_address = jump_address
        self.message = message

        if type(self.site_address) is types.IntType:
            self.site_address = hex(self.site_address)
            
        if type(self.jump_address) is types.IntType:
            self.jump_address = hex(self.jump_address)

    def print_debug_info(self):
        print 'Insecure jump details: '
        print '\tsection: \t' + self.section.name
        print '\tfunction: \t' + self.function.name
        print '\tsite address: \t' + self.site_address
        print '\tjump address: \t' + self.jump_address
        print '\tmessage: \t' + self.message + '\n'

class Return(InsecureJump):
    """Exception for return instruction"""

    def print_debug_info(self):
        print '--RETURN INSTRUCTION--'
        InsecureJump.print_debug_info(self)

class MiddleOfPltEntryJump(InsecureJump):
    """Exception for jump to middle of PLT"""

    def print_debug_info(self):
        print '--JUMP TO MIDDLE OF PLT ENTRY--'
        InsecureJump.print_debug_info(self)
class MiddleOfTramtabEntryJump(InsecureJump):
    """Exception for jump to middle of tramtab"""

    def print_debug_info(self):
        print '--JUMP TO MIDDLE OF TRAMTAB ENTRY--'
        InsecureJump.print_debug_info(self)
class IndirectCall(InsecureJump):
    """Exception for unconstrained indirect jump"""
    
    def print_debug_info(self):
        print '--INDIRECT CALL--'
        InsecureJump.print_debug_info(self)

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

class MiddleOfInstructionLoopJump(InsecureJump):
    """Exception for a loop jump that points to the middle of an instruction"""

    def print_debug_info(self):
        print '--LOOP JUMP POINTS TO MIDDLE OF INSTRUCTION--'
        InsecureJump.print_debug_info(self)

class RltNotAfterDirectCall(InsecureJump):
    """Exception for rlt not jmping back after a direct call"""

    def print_debug_info(self):
        print '--RLT JUMP DOESN"T POINT AFTER A DIRECT CALL--'
        InsecureJump.print_debug_info(self)

#############################
# Script
#############################

def print_help():
    print '----------------------------------------------'
    print 'Usage: ./verify_cdi.py <options> <binary_name>'
    print 'Options:'
    print '  -c : continue finding indirections even after one is found'
    print '  -p : print instructions as they are decoded'
    print '  -i : ignore the return from main'
    print '  -h : print this help'
    print '----------------------------------------------'

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_help()
        sys.exit(1)

    optlist, args = getopt(sys.argv[1:], 'cphi')
    
    # defaults
    exit_on_insecurity = True
    print_instr_as_decoded = False

    # options can flip defaults
    if ('-c', '') in optlist:
        exit_on_insecurity = False
    if ('-i', '') in optlist:
        IGNORE_RET_FROM_MAIN = True
    if ('-p', '') in optlist:
        print_instr_as_decoded = True
    if ('-h', '') in optlist:
        print_help()
        sys.exit(0)

    if not args:
        print_help()
        sys.exit(1)

    binary = open(args[0], 'rb')
    exec_sections = elfparse.gather_exec_sections(binary.name)
    rlt_start_addr, rlt_start_offset, rlt_section_size = elfparse.rlt_addr(binary)
    plt_start_addr, plt_size, plt_entry_size, tramtab_start_addr, tramtab_size = elfparse.gather_plts_tram(binary)

    functions =  elfparse.gather_functions (binary.name, exec_sections)
    rlts = elfparse.gather_rlts (binary.name, exec_sections, rlt_start_addr, rlt_start_offset, rlt_section_size)
    
    verifier = Verifier(binary, exec_sections, functions, rlts, plt_start_addr, 
            plt_size, plt_entry_size, tramtab_start_addr, tramtab_size, 
            exit_on_insecurity, print_instr_as_decoded)


    if verifier.judge():
        sys.exit(0)
    else:
        sys.exit(1)


