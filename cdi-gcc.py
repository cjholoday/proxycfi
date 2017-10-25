#!/usr/bin/env python

import sys
import os
import subprocess

import common.elf
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
    """Create a shared library named 'libname', which may have versioning

    opts_idx should be the index of the --cdi-make-sl option
    make_sl assumes that '--cdi-use-sl' has been handled if it exists
    '-o' is not supported for --cdi-make-sl
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
        subprocess.check_call(['cdi-gcc-proper', '-shared', 
            '-Wl,-soname,' + common.elf.get_soname(libname), '-o', libname]
            + gcc_opts)

        if libname != common.elf.strip_sl_versioning(libname):
            # set up symlinks from the bare name and the soname to the 
            # full libname.  i.e. libname.so   -> libname.so.1.0.0 
            #                     libname.so.1 -> libname.so.1.0.0
            subprocess.check_call(['ln', '-s', os.path.abspath(libname),
                os.path.abspath(common.elf.strip_sl_versioning(libname))])
            subprocess.check_call(['ln', '-s', os.path.abspath(libname),
                os.path.abspath(common.elf.get_soname(libname))])
    except subprocess.CalledProcessError:
        sys.exit(1)



def prepare_to_use_sls(gcc_opts, opts_idx):
    """Returns gcc_opts prepared to use 1 or more libs specified at opts_idx

    opts_idx should be the index of the --cdi-use-sl option
    """
    lib_paths = gcc_opts[opts_idx][len('--cdi-use-sl='):].split(',')
    del gcc_opts[opts_idx]

    lib_search_options = []
    for lib_path in lib_paths:
        base_dir = os.path.dirname(os.path.realpath(lib_path))
        lib_search_options.append('-L' + base_dir)
        lib_search_options.append('-Wl,-rpath=' + base_dir)

        # cut off the 'lib' and '.so.X.Y.Z' parts for the -llibname option
        gcc_opts.append('-l' + 
                common.elf.strip_sl_versioning(os.path.basename(lib_path))[3:-3])
    return lib_search_options + gcc_opts


def print_cdi_help():
    print 'cdi options' 
    print '----------------------------------------------------------\n'

    print '--cdi-spec'
    print 'Prints out the linker spec and immediately terminates at linker stage'
    print ''

    print '--cdi-converter-[converter_option]'
    print '--cdi-converter-[converter_option=VALUE]'
    print ('Passes converter_option to the converter as --converter_option '
            ' or as --converter_optoin=VALUE, depending on which is used. ')
    print ''

    print '--cdi-abandon-cdi'
    print ('Intercept assembler and linker calls as normal but generate a'
            ' non-cdi executable/shared library instead. Useful for debugging')
    print ''

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

    # Use the CDI loader
    gcc_opts.append('-Wl,--dynamic-linker=' + SCRIPT_PATH + '/cdi-loader/dest/lib/ld-2.23.so')

    gcc_opts.append('-rdynamic')

    cdi_options = []
    for idx, opt in enumerate(gcc_opts):
        if (opt.startswith('--cdi-') 
                and not opt.startswith('--cdi-make-sl=')
                and not opt.startswith('--cdi-use-sl=')):
            cdi_options.append(opt)
            gcc_opts[idx] = '-g' # void this option
    if cdi_options:
        gcc_opts.append("-Wl,--cdi-options={}".format('|'.join(cdi_options)))

    if '--cdi-help' in cdi_options:
        print_cdi_help()
        sys.exit(0)

    # Add convenience options for constructing and using shared libraries
    #
    # --cdi-make-sl=SHARED_LIB_NAME: the shared library is placed in the current working directory
    #
    # --cdi-use-sl=PATH,PATH2,...: used to compile against a shared library at PATH. The base directory
    #                of PATH is added as search path for linking. PATH's base 
    #                directory is also added as a runtime library search path. The 
    #                side effects are undesirable but fine for testing purposes
    #                If multiple shared libraries are to be used, they should be separated
    #                by commas.
    #
    # At most, only one option of each --cdi-make-sl and --cdi-use-sl should be present
    # in the optoins passed 
    make_sl_idx = -1
    use_sl_idx = -1
    for idx, opt in enumerate(gcc_opts):
        if opt.startswith('--cdi-make-sl='):
            if make_sl_idx != -1:
                eprint("cdi-gcc wrapper: error: '--cdi-make-sl' can only be specified once")
            if '-o' in gcc_opts:
                eprint("cdi-gcc wrapper: error: '-o' is not supported with use of '--cdi-make-sl'")
            make_sl_idx = idx
        elif opt.startswith('--cdi-use-sl='):
            if use_sl_idx != -1:
                eprint("cdi-gcc wrapper: error: '--cdi-use-sl' can only be specified once")
            use_sl_idx = idx

    if make_sl_idx != -1:
        make_sl_libname = gcc_opts[make_sl_idx][len('--cdi-make-sl='):]
        del gcc_opts[make_sl_idx]
        if use_sl_idx != -1:
            if use_sl_idx > make_sl_idx:
                use_sl_idx -= 1
            gcc_opts = prepare_to_use_sls(gcc_opts, use_sl_idx)
        make_sl(gcc_opts, make_sl_libname)
        sys.exit(0)
    if use_sl_idx != -1:
        gcc_opts = prepare_to_use_sls(gcc_opts, use_sl_idx)
    
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
