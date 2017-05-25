#!/usr/bin/env python

from capstone import *
import elfparse
from eprint import eprint
import sys

def get_fptr_sites(filename, funct):
    call_list = ["call","callf", "callq"]

    # Insecure instructions list
    returns = ["ret", "retf", "iret", "retq", "iretq"]
    
    binary = open(filename, 'rb')
    binary.seek(funct.file_offset)
    buff = binary.read(int(funct.size))
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in md.disasm(buff, funct.virtual_address):
        if i.mnemonic in call_list:
            try:
                int(i.op_str,16)
            except ValueError:
                print '{} + {}'.format(funct.name, hex(i.address - funct.virtual_address).rstrip('L'))



binary_filename = sys.argv[1]
binary = open(binary_filename, 'rb')
exec_sections = elfparse.gather_exec_sections(binary)

functions = elfparse.gather_functions(binary, exec_sections)

binary.close()

for funct in functions:
    get_fptr_sites(binary_filename, funct)
