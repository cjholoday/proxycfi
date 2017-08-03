#!/usr/bin/env python

import __init__

import sys
from capstone import *

from common import elfparse
from common.eprint import eprint

class Error(Exception):
    pass

class FunctionPrologueError(Error):
    pass
    

# Prints all function pointer return addresses in the following format:
#       format: [ret address] : [funct name] + [funct offset] + [instruction length]
#
# Invoke find_fptrs.py with the following syntax:
#       ./find_fptrs.py [binary path] [associated symbol table binary]
#
prologue_whitelist = ['deregister_tm_clones', 'register_tm_clones', '__do_global_dtors_aux', 'frame_dummy']
call_list = ["call","callf", "callq"]
jmp_list = ["jo","jno","jb","jnae","jc","jnb","jae","jnc","jz","je","jnz",
        "jne","jbe","jna","jnbe","ja","js","jns","jp","jpe","jnp","jpo","jl",
        "jnge","jnl","jge","jle","jng","jnle","jg","jecxz","jrcxz","jmp","jmpe"]
returns = ["ret", "retf", "iret", "retq", "iretq"]

def get_fptr_sites(binary_path, funct):
    if funct.name in prologue_whitelist:
        return

    binary = open(binary_path, 'rb')
    binary.seek(funct.file_offset)
    buff = binary.read(int(funct.size))
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    instrs = md.disasm(buff, funct.virtual_address)

    is_missing_funct_prologue = False
    try:
        prologue_instr = instrs.next()
        if prologue_instr.mnemonic != 'push' or prologue_instr.op_str   != 'rbp':
            is_missing_funct_prologue = True

        prologue_instr = instrs.next()
        if prologue_instr.mnemonic != 'mov' or prologue_instr.op_str != 'rbp, rsp':
            is_missing_funct_prologue = True
    except StopIteration:
        is_missing_funct_prologue = True

    for i in md.disasm(buff, funct.virtual_address):
        if is_indirect_call(i):
            ret_addr = hex(i.address + i.size).rstrip('L')
            funct_offset = hex(i.address - funct.virtual_address).rstrip('L')
            print ('{} : {} + {} + {}'
                    .format(ret_addr, funct.name, funct_offset, hex(i.size)))
        elif is_missing_funct_prologue and is_indirect_jmp(i):
            eprint("find_fptrs: warning: indirect jump in prologueless function"
                    " '{}'".format(funct.name))

def is_indirect_call(instr):
    if instr.mnemonic not in call_list:
        return False
    try:
        int(instr.op_str, 16)
        return False
    except ValueError:
        return True

def is_indirect_jmp(instr):
    if instr.mnemonic not in jmp_list:
        return False
    try:
        int(instr.op_str, 16)
        return False
    except ValueError:
        return True

if __name__ == '__main__':
    binary_path = sys.argv[1]

    # sometimes it's useful to have the symbol table (.symtab) section separated from
    # binary since it's so rarely used. This is the case with, for example, libc
    try:
        symbol_binary_path = sys.argv[2]
    except IndexError:
        # No separate symbol binary was specified so use the binary itself
        symbol_binary_path = binary_path

    exec_sections = elfparse.gather_exec_sections(binary_path)
    functions = elfparse.gather_functions(symbol_binary_path, exec_sections)

    for funct in functions:
        try:
            get_fptr_sites(binary_path, funct)
        except FunctionPrologueError:
            eprint("find_fptrs.py: function '{}' in shared library '{}' with symbol "
                    "reference binary '{}' lacks a valid function prologue"
                    .format(funct.name, binary_path, symbol_binary_path))
            sys.exit(1)

