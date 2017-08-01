#!/usr/bin/env python

import sys
import subprocess

def funct_name(exec_name, funct_addr):
    """Returns the name associated with address given. Requires -g
    
    funct_addr should be a hexadecimal string (e.g. '0x401c05')
    """
    
    return subprocess.check_output(['addr2line', '-f', '-p', '-s',
        '-e', exec_name, '-a', funct_addr]).split(' ')[1]



# Print the trace table but with function addresses replaced by names. Syntax:
#       ./addr_translation executable trace_table.out
if __name__ == '__main__':
    exec_name = sys.argv[1]
    trace_table = open(sys.argv[2], 'r')
    
    for line in trace_table:
        print line.split(' ')[0],
        print funct_name(exec_name, line.split(' ')[1])
