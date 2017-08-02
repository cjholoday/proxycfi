#!/usr/bin/env python

import sys
import subprocess

##############################################################################
# cdi-gcc 
#
# This script is a wrapper for the CDI modified version of gcc. The custom
# gcc calls cdi-as.py and cdi-ld.py, which are wrappers for the assembler
# and linker respectively. This wrapper ensures that the proper arguments are
# supplied to cdi-gcc
##############################################################################

gcc_opts = sys.argv[1:]

gcc_opts.append('-g')
gcc_opts.append('--save-temps')
gcc_opts.append('-fno-jump-tables')
gcc_opts.append('-fno-omit-frame-pointer')

try:
    subprocess.check_call(['cdi-gcc-proper'] + gcc_opts)
except:
    sys.exit(1)
