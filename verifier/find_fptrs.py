#!/usr/bin/env python

from capstone import *
import elfparse
from eprint import eprint
import sys


# Prints all function pointer return addresses in the following format:
#       format: [ret address] : [funct name] + [funct offset] + [instruction length]
#
# Invoke find_fptrs.py with the following syntax:
#       ./find_fptrs.py [binary path] [associated symbol table binary]
#

def get_fptr_sites(binary_path, funct):
    call_list = ["call","callf", "callq"]

    # Insecure instructions list
    returns = ["ret", "retf", "iret", "retq", "iretq"]
    
    binary = open(binary_path, 'rb')
    binary.seek(funct.file_offset)
    buff = binary.read(int(funct.size))
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in md.disasm(buff, funct.virtual_address):
        # print("{}:\t{}\t{}\t{}".format(hex(i.address).rstrip('L'), i.size, i.mnemonic, i.op_str))
        if i.mnemonic in call_list:
            try:
                int(i.op_str,16)
            except ValueError:
                ret_addr = hex(i.address + i.size).rstrip('L')
                funct_offset = hex(i.address - funct.virtual_address).rstrip('L')
                print ('{} : {} + {} + {}'
                        .format(ret_addr, funct.name, funct_offset, hex(i.size)))

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
    # print funct.name
    get_fptr_sites(binary_path, funct)
