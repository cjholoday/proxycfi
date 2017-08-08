#!/usr/bin/env python

import sys
import os
import subprocess

from common.eprint import eprint

##############################################################################
# cdi-gcc 
#
# This script is a wrapper for the CDI modified version of gcc. The custom
# gcc calls cdi-as.py and cdi-ld.py, which are wrappers for the assembler
# and linker respectively. This wrapper ensures that the proper arguments are
# supplied to cdi-gcc
##############################################################################

SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))

def make_sl(gcc_opts, libname):
    """Create a shared library named 'libname'
    
    '--make-sl=LIBNAME' should be removed
    '-o' is not supported for --make-sl
    """
    try:
        subprocess.check_call(['cdi-gcc-proper', '-c', '-fPIC'] + gcc_opts)
    except subprocess.CalledProcessError:
        sys.exit(1) # cdi-gcc-proper will give an error message for us

    for idx, opt in enumerate(gcc_opts):
        # this wil fail if any other option/argument that is not a c source
        # file ends with '.c'. Again, this is not production code
        if opt.endswith('.c'):
            gcc_opts[idx] = opt[:-2] + '.o'

    try:
        subprocess.check_call(['cdi-gcc-proper', '-shared', '-o', libname] + gcc_opts)
    except subprocess.CalledProcessError:
        sys.exit(1)


if __name__ == '__main__':
    gcc_opts = sys.argv[1:]

    # debug information is needed to link function pointers to indirect calls
    gcc_opts.append('-g')

    # assembly files need to be outputted for the converter
    gcc_opts.append('--save-temps')

    # jump tables use indirect jumps
    gcc_opts.append('-fno-jump-tables')

    # Enforce function prologues so that a function cannot end by jumping to another function
    gcc_opts.append('-fno-omit-frame-pointer')

    # Use our own linker script to create a CDI segment and CDI sections 
    gcc_opts.append('-Wl,--script=' + SCRIPT_PATH + '/cdi-gcc/cdi-elf64-x86-64-lscript')

    # Add convenience options for constructing and using shared libraries
    #
    # --make-sl=SHARED_LIB_NAME: the shared library is placed in the current working directory
    #
    # --use-sl=PATH,PATH2,...: used to compile against a shared library at PATH. The base directory
    #                of PATH is added as search path for linking. PATH's base 
    #                directory is also added as a runtime library search path. The 
    #                side effects are undesirable but fine for testing purposes
    #                If multiple shared libraries are to be used, they should be separated
    #                by commas
    for idx, opt in enumerate(gcc_opts):
        if opt.startswith('--make-sl='):
            if '-o' in gcc_opts:
                eprint("cdi-gcc wrapper: '-o' is not supported with use of '--make-sl'")

            libname = opt[len('--make-sl='):]
            del gcc_opts[idx]
            make_sl(gcc_opts, libname)
            sys.exit(0)
        elif opt.startswith('--use-sl='):
            lib_paths = opt[len('--use-sl='):].split(',')
            del gcc_opts[idx]

            lib_search_options = []
            for lib_path in lib_paths:
                base_dir = os.path.dirname(os.path.realpath(lib_path))
                lib_search_options.append('-L' + base_dir)
                lib_search_options.append('-Wl,-rpath=' + base_dir)

                # cut off the 'lib' and '.so' parts for the -llibname option
                gcc_opts.append('-l' + os.path.basename(lib_path)[3:-3])
            gcc_opts = lib_search_options + gcc_opts
            break

    # NOTE: we cannot use -Wl,-z,now to force non-lazy binding. Using this option
    # will replace the PLT with a series of 6 byte indirect jumps into shared libraries
    # With padding, this leaves only 8 bytes per access into a shared library, but 
    # we need at least 13 bytes for our fake 64 bit absolute jump:
    #
    #   mov     <addr>, %r11
    #   call    *%r11
    #
    # Furthermore, we shouldn't rely on the user setting LD_BIND_NOW=1. As a 
    # result, it's up to the runtime linker to enforce non-lazy binding

    try:
        subprocess.check_call(['cdi-gcc-proper'] + gcc_opts)
    except subprocess.CalledProcessError:
        sys.exit(1)
