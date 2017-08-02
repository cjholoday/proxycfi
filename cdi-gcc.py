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


# debug information is needed to link function pointers to indirect calls
gcc_opts.append('-g')

# assembly files need to be outputted for the converter
gcc_opts.append('--save-temps')

# jump tables use indirect jumps
gcc_opts.append('-fno-jump-tables')

# Enforce function prologues so that a function cannot end by jumping to another function
gcc_opts.append('-fno-omit-frame-pointer')

# NOTE: we cannot use -Wl,-z,now to force non-lazy binding. Using this option
# will replace the PLT with a series of 6 byte indirect jumps into shared libraries
# With padding, this leaves only 8 bytes per access into a shared library, but 
# we need at least 13 bytes for our fake 64 bit absolute jump:
#
#   mov     <addr>, %r11
#   call    *%r11
#
# As a result, it's up to the runtime linker to enforce non-lazy binding

try:
    subprocess.check_call(['cdi-gcc-proper'] + gcc_opts)
except:
    sys.exit(1)
