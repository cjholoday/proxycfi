#!/usr/bin/env python

import __init__

import bisect
import sys
import binascii
import types
import collections
from common import elfparse
from common.eprint import eprint
from capstone import *
from operator import attrgetter
from getopt import getopt

IGNORE_RET_FROM_MAIN = False


STARTUP_FUNCTIONS = [
        'start_c',
        '__libc_start_main',
        'libc_start_main',
        '__init_libc',
        'static_init_tls',
        '__copy_tls',
        '__init_tp',
        '__set_thread_area',
        'dummy1',
        '__libc_start_init',
        'libc_start_init',
        '_init',
        'frame_dummy',
        'register_tm_clones',
        '__libc_csu_init'  # GLIBC only
]
CLEANUP_FUNCTIONS = [
        'exit',
        'dummy',
        '__libc_exit_fini',
        'libc_exit_fini',
        '__do_global_dtors_aux',
        'deregister_tm_clones',
        '_fini',
        '__libc_csu_fini' # GLIBC only
]
WHITELIST = STARTUP_FUNCTIONS + CLEANUP_FUNCTIONS

class Flow:
    def __init__(self, src, dst, type):
        self.src = src
        self.dst = dst

        # Should be 'call', 'jump', 'loop', 'ret', or 'plt'
        self.type = type

# functor used to avoid excessive parameter passing
class Verifier:
    def __init__(self, file_object, exec_sections, functions, rlts, plt_start_addr,
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
        
        self.functions = sorted(functions, 
                key=attrgetter('addr'))
        self.funct_addrs = map(lambda f: f.addr, self.functions)
        self.rlts = rlts
        self.tramtab_start_addr = tramtab_start_addr
        self.tramtab_size = tramtab_size

        # functions are processed breadth first
        self.funct_q = collections.deque()

        self.verification_handlers = {
                'jump': self.verify_jump,
                'call': self.verify_call,
                'loop': self.verify_loop
        }

    def set_insecure(self, insecure_flow):
        self.secure = False
        insecure_flow.print_debug_info()
        if self.exit_on_insecurity:
            raise insecure_flow


    def verify(self, function):
        """Recursively verifies that function is CDI compliant"""

        function.verified = True

        # If we see a function on the whitelist, then a non-whitelisted function
        # calls a whitelisted function. This should never happen because the 
        # whitelisted functions should be disjointly used compared to normal functions
        if function in WHITELIST:
            eprint("verifier: error: attempting to verify function on whitelist")
            sys.exit(1)

        #functions_called = []
        #calls, jumps, loops, instruction_addresses = self.inspect(function,
        #        self.plt_start_addr, self.plt_size, self.plt_entry_size)

        instr_addrs = self.instr_addrs(function)
        for flow in self.inspect(function, self.plt_start_addr, 
                self.plt_size, self.plt_entry_size):
            self.verification_handlers[flow.type](flow, instr_addrs)
            


            #for addr in calls:
            #    target_function = self.target_funct(addr)
            #    if target_function == None:
            #        raise InvalidFunctionCall(self.enclosing_sect(addr), function,
            #                '', addr, 'call targets no function but '
            #                'may point to whitespace between functions')

            #    if target_function.addr != addr:
            #        raise InvalidFunctionCall(self.enclosing_sect(addr),
            #                function, '', addr)

            #    functions_called.append(target_function)

            #for addr in loops:
            #    if not function.contains_address(addr):
            #        raise LoopOutOfFunction(self.enclosing_sect(addr),
            #                function, '', addr)

            #    candidate_idx = bisect_left(instruction_addreses, addr)
            #    if (candidate_idx == len(instruction_addresses) or 
            #            instruction_addresses[candidate_idx] != addr):
            #        raise MiddleOfInstructionLoopJump(self.enclosing_sect(addr),
            #                function, '', addr)

            #for addr in jumps: 
            #    target_function = self.target_funct(addr)

            #    if target_function == None:
            #        raise OutOfObjectJump(self.enclosing_sect(addr), function,
            #                '', addr, 'jump may target whitespace '
            #                'between functions')

            #    # check that jumps back into function don't go to middle of instrs
            #    elif target_function == function:
            #        candidate_idx = bisect.bisect_left(instruction_addresses, addr)
            #        if (candidate_idx == len(instruction_addresses) or 
            #                instruction_addresses[candidate_idx] != addr):
            #            raise MiddleOfInstructionJump(self.enclosing_sect(addr),
            #                    function, '', addr, 'the rogue jump '
            #                    'goes back into ' + function.name)

            #    # handle jumps to other functions at end of depth first search
            #    else:
            #        target_function.incoming_returns.append(addr)

        #except InsecureFlow as insecurity:
        #    self.set_insecure(
        #    self.secure = False
        #    insecurity.print_debug_info()
        #    if self.exit_on_insecurity:
        #        raise

        #for funct in functions_called:
        #    if not funct.verified:
        #        self.verify(funct)

    def verify_jump(self, flow, instr_addrs):
        target_funct = self.enclosing_funct(flow.dst)
        src_funct = self.enclosing_funct(flow.src)

        if target_funct == None:
            self.set_insecure(OutOfObjectJump(self, flow, None))

        # check that jumps back into this funct don't go to middle of instrs
        if target_funct == src_funct:
            if not in_sorted_list(instr_addrs, flow.dst):
                self.set_insecure(MiddleOfInstructionJump(self, flow,
                    "the rogue jump goes back into '{}'".format(src_funct)))

        # check if this jump is acting like a function call
        if target_funct.addr == flow.dst:
            # TODO: check the whitelist
            if target_funct and not target_funct.verified:
                self.funct_q.append(target_funct)
                target_funct.verified = True

        # keep track of the incoming returns so that we can check if they go
        # to the middle of instructions later on, after the breadth first search
        target_funct.incoming_returns.append(flow)

    def verify_call(self, flow, instr_addrs):
        target_funct = self.target_funct(flow.dst)
        if target_funct == None:
            self.set_insecure(InvalidFunctionCall(self, flow,
                "call doesn't target a function"))

        # TODO enable this
        #if target_funct.name in WHITELIST:
        #    self.set_insecure(

        if target_funct and target_funct.verified:
            self.funct_q.append(target_funct)
            target_funct.verified = True

    def verify_loop(self, flow, instr_addrs):
        src_funct = self.enclosing_funct(flow.src)
        if not src_funct.contains_address(flow.dst):
            raise LoopOutOfFunction(self, flow, None)

        if not in_sorted_list(instr_addrs, flow.dst):
            raise MiddleOfInstructionLoopJump(self, flow, None)

    def judge(self):
        """Returns true iff the file object is CDI compliant
        
        Wrapper for Verifier.verify 
        """

        for funct in self.functions:
            # sections must have size > 0 to be considered
            # NOTE: _fini and company have size 0 so they are not verified
            if funct.name not in WHITELIST:
                self.funct_q.append(funct)
                funct.verified = True
        
        while self.funct_q:
            funct = self.funct_q.popleft()
            print("verifying function '{}'".format(funct.name))
            self.verify(funct)

        # TODO: remove this
        return self.secure

        # check that incoming "return" jumps are valid
        for funct in self.functions:
            try:
                self.check_return_jumps_are_valid(funct)
            except InsecureFlow as insecurity:
                insecurity.print_debug_info()
                self.secure = False

        # check rlts
        for r in self.rlts:
            verifier.check_rlt(r)
        
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
                                self.enclosing_sect(funct.addr),
                                elfparse.Function('Unknown', 0, 0, 0), 'Unknown',
                                return_addr, 'Jump goes to ' + funct.name)
                elif valid_addr > return_addr:
                        raise MiddleOfInstructionJump(
                                self.enclosing_sect(funct.addr),
                                elfparse.Function('Unknown', 0, 0, 0), 'Unknown',
                                return_addr, 'Jump goes to ' + funct.name)
                else: # valid_addr == return_addr
                    return_addr = return_addr_iter.next()
        except StopIteration:
            pass 

    def target_funct(self, addr):
        """Returns a function that contains the address. Otherwise, None
        
        Assumes that self.functions is sorted by addr
        Assumes that self.funct_addrs is sorted and corresponds to self.functions
        """
        funct = self.enclosing_funct(addr)
        if funct and funct.addr != addr:
            funct = None
        return funct

    def enclosing_funct(self, addr):
        """Returns the function in which the address belongs

        Note that addresses can be in whitespace between functions, if addr
        is in one of these whitespace areas, None will be returned
        """
        idx = bisect.bisect_right(self.funct_addrs, addr)
        if idx == 0:
            return None

        cand = self.functions[idx - 1]
        if addr >= cand.addr and addr < (cand.addr + cand.size):
            return cand
        else:
            return None
    
    def enclosing_sect(self, virtual_address):
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
        prev_instr = None
        for i in md.disasm(buff, function.addr):
            addresses.append(int(i.address))
            if self.print_instr_as_decoded:
                print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            if i.mnemonic in jmp_list:
                try:
                    # Indirect calls and jumps have a * after the instruction and before the location
                    # which raises a value error exception in the casting
                    addr = int(i.op_str,16)
                    yield Flow(i.address, addr, 'jump')

                    # TODO: move to jump handler
                    if addr >= plt_start_addr and addr <= plt_start_addr + plt_size:
                        if (addr - plt_start_addr) % plt_entry_size != 0:
                            raise MiddleOfPltEntryJump(enclosing_sect(function.addr),
                                    function, '', addr, 'plt starts at ' + hex(plt_start_addr))

                    elif addr > self.tramtab_start_addr and addr <= tramtab_start_addr + tramtab_size:
                        if (addr - self.tramtab_start_addr) % 0x10 != 0:
                            raise MiddleOfTramtabEntryJump(enclosing_sect(function.addr),
                                    function, '', addr, 'tramtab starts at ' + hex(tramtab_start_addr))
                except ValueError:
                    if prev_instr and prev_instr.mnemonic == 'movabs':
                        register = prev_instr.op_str.split(', ')[0]
                        mov_addr = prev_instr.op_str.split(', ')[1]
                        if i.op_str == register:
                            yield Flow(i.address, addr, 'jump')
                            prev_instr = i
                            continue
                    self.set_insecure(IndirectJump(self, Flow(i.address, 0, 'jump')),
                            "indirect jmp/jcc")
            elif i.mnemonic in call_list:
                try:
                    addr = int(i.op_str,16)
                    yield Flow(i.address, addr, 'call')

                    # TODO: move to call handler
                    if addr >= plt_start_addr and addr <= plt_start_addr + plt_size:
                        if (addr - plt_start_addr) % plt_entry_size != 0:
                            raise MiddleOfPltEntryJump(enclosing_sect(function.addr),
                                    function, '', addr, 'plt starts at ' + hex(plt_start_addr))
                except ValueError:
                    self.set_insecure(IndirectCall(self, Flow(i.address, 0, 'call'), None))

            elif i.mnemonic in returns:
                if function.name == 'main' and IGNORE_RET_FROM_MAIN:
                    pass # ignore the return
                else:
                    self.set_insecure(ReturnUsed(self, Flow(i.address, 0, 'ret'), None))
            elif i.mnemonic in loop_list:
                yield Flow(i.address, int(i.op_str, 16), 'loop')
            prev_instr = i
        if self.print_instr_as_decoded:
            print '--------------:  ' + function.name + '\n'


    def instr_addrs(self, function):
        """Returns a list of valid instr addresses for a function
        
        """
        addresses = []
        file = open(self.binary.name, 'rb')
        file.seek(function.file_offset)
        buff = file.read(int(function.size))
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for i in md.disasm(buff, function.addr):
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
                for f in self.functions:
                    if f.contains_address(addr_to_chk):
                        chk_offset = (addr_to_chk - f.addr) + f.file_offset - 5

                        file.seek(0)
                        file.seek(chk_offset)
                        bf = file.read(5)

                        dis = md.disasm(bf, addr_to_chk - 5)

                        for inst in dis:
                            if (inst.mnemonic != 'call'):
                                raise RltNotAfterDirectCall(self.enclosing_sect(addr_to_chk),
                                     rlt, hex(int(i.address)), i.op_str, 'RLT_Inst.')

#############################
# Exception Types
#############################

class Error(Exception):
    pass

# old args:
# section, function, site_address, jump_address, message = ''):

class InsecureFlow(Error):
    def __init__(self, verifier, flow, msg):
        self.src_sect = verifier.enclosing_sect(flow.src)
        self.dst_sect = verifier.enclosing_sect(flow.dst)

        src_funct = verifier.enclosing_funct(flow.src)
        dst_funct = verifier.enclosing_funct(flow.dst)

        def get_funct_loc(funct, addr):
            if funct == None:
                return ''
            else:
                return '{} (0x{:x} + 0x{:x})'.format(funct.name,
                        funct.addr, addr - funct.addr)
        self.flow_src = get_funct_loc(src_funct, flow.src)
        self.flow_dst = get_funct_loc(dst_funct, flow.dst)

        self.msg = msg
        self.flow = flow

    def print_debug_info(self):
        print 'Insecure Flow Details:'
        print '\tsections:  {} -> {}'.format(self.src_sect.name, self.dst_sect.name)
        print '\taddrs:     0x{:x} -> 0x{:x}'.format(self.flow.src, self.flow.dst)
        print '\tflow src:  {}'.format(self.flow_src)
        print '\tflow dst:  {}'.format(self.flow_dst)
        print '\tmessage:   ' + self.msg
        print ''

class ReturnUsed(InsecureFlow):
    def print_debug_info(self):
        print '--RETURN INSTRUCTION--'
        InsecureFlow.print_debug_info(self)

class MiddleOfPltEntryJump(InsecureFlow):
    def print_debug_info(self):
        print '--JUMP TO MIDDLE OF PLT ENTRY--'
        InsecureFlow.print_debug_info(self)
class MiddleOfTramtabEntryJump(InsecureFlow):
    def print_debug_info(self):
        print '--JUMP TO MIDDLE OF TRAMTAB ENTRY--'
        InsecureFlow.print_debug_info(self)
class IndirectCall(InsecureFlow):
    def print_debug_info(self):
        print '--INDIRECT CALL--'
        InsecureFlow.print_debug_info(self)

class IndirectJump(InsecureFlow):
    def print_debug_info(self):
        print '--INDIRECT JUMP--'
        InsecureFlow.print_debug_info(self)

class MiddleOfInstructionJump(InsecureFlow):
    def print_debug_info(self):
        print '--MIDDLE OF INSTRUCTION JUMP--'
        InsecureFlow.print_debug_info(self)

class InvalidFunctionCall(InsecureFlow):
    def print_debug_info(self):
        print '--CALL DOESN\'T POINT TO START OF FUNCTION--'
        InsecureFlow.print_debug_info(self)

class OutOfObjectJump(InsecureFlow):
    def print_debug_info(self):
        print '--JUMP TO OUTSIDE OF OBJECT--'
        InsecureFlow.print_debug_info(self)

class LoopOutOfFunction(InsecureFlow):
    def print_debug_info(self):
        print '--LOOP JUMP TO OUT OF FUNCTION--'
        InsecureFlow.print_debug_info(self)

class MiddleOfInstructionLoopJump(InsecureFlow):
    def print_debug_info(self):
        print '--LOOP JUMP POINTS TO MIDDLE OF INSTRUCTION--'
        InsecureFlow.print_debug_info(self)

class RltNotAfterDirectCall(InsecureFlow):
    def print_debug_info(self):
        print '--RLT JUMP DOESN"T POINT AFTER A DIRECT CALL--'
        InsecureFlow.print_debug_info(self)

def in_sorted_list(l, val):
    candidate_idx = bisect.bisect_left(l, val)
    if candidate_idx == len(l):
        return False
    return l[candidate_idx] == val

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
    for funct in functions:
        print(funct.name, hex(funct.addr))
    rlts = elfparse.gather_rlts (binary.name, exec_sections, rlt_start_addr, rlt_start_offset, rlt_section_size)
    
    verifier = Verifier(binary, exec_sections, functions, rlts, plt_start_addr, 
            plt_size, plt_entry_size, tramtab_start_addr, tramtab_size, 
            exit_on_insecurity, print_instr_as_decoded)


    if verifier.judge():
        sys.exit(0)
    else:
        sys.exit(1)


