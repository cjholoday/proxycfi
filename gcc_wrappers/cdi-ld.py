#!/usr/bin/env python

import __init__

import sys
import os
import subprocess
import re
import copy
import time

import spec
import normify
import lib_utils
import fake_types
import error
import elf_fixup

from error import fatal_error
from common.eprint import eprint
import common.elf
import run_profile

def chop_suffix(string, cutoff = ''):
    if cutoff == '':
        return string[:string.rfind('.')]
    return string[:string.rfind(cutoff)]

########################################################################
# cdi-ld: a cdi wrapper for the gnu linker 'ld'
#   Identifies necessary fake object files in archives, converts fake object
#   files to real, cdi-compliant object files, and runs the gnu linker on them
#
########################################################################


def main():
    error.raw_ld_spec = raw_ld_spec = sys.argv[1:]

    lspec = spec.LinkerSpec(raw_ld_spec, fatal_error)
    if lspec.cdi_options:
        if '--cdi-spec' in lspec.cdi_options:
            print ' '.join(lspec.raw())
            sys.exit(0)

    # filter out the converter options
    lspec.converter_options = []
    for opt in lspec.cdi_options:
        if opt.startswith('--cdi-converter-'):
            lspec.converter_options.append('--' + opt[len('--cdi-converter-'):])

    archives = []
    for i, path in enumerate(lspec.ar_paths):
        # FIXME: This is VERY unportable
        # To get a CDI version of libc_nonshared.a we would need to (presumably) 
        # compile GCC, which is simply not possible right now.
        if path != '/usr/lib/x86_64-linux-gnu/libc_nonshared.a':
            archives.append(fake_types.Archive(path))
            archives[-1].fixup_idx = i

    # the fake object files directly listed in the ld spec
    for i, path in enumerate(lspec.obj_paths):
        fake_obj_name = chop_suffix(path) + '.fake.o'
        subprocess.check_call(['mv', path, fake_obj_name])


    # the fake objs will need to be moved back to their original filename in case
    # another compilation wants to use them as well. This code ASSUMES that
    # explicit_original_objs will not be modified in any way
    #
    # This is called on error or at the end of cdi-ld
    def restore_original_objects():
        eprint("restoring objects: {}".format(' '.join(
            list(map(lambda obj: obj.path, explicit_fake_objs)))))
        for i, fake_obj in enumerate(explicit_fake_objs):
            subprocess.check_call(['mv', fake_obj.path, lspec.obj_paths[i]])

    # used by fatal_error()
    error.restore_original_objects_fptr = restore_original_objects

    # All fake objects must be constructed after the filenames are moved
    # Otherwise fatal_error cannot restore them on error in this brief window
    cdi_obj_fixups = []
    explicit_fake_objs = []
    for i, obj_path in enumerate(lspec.obj_paths):
        try:
            cdi_obj_name = chop_suffix(obj_path) + '.fake.o'
            explicit_fake_objs.append(fake_types.FakeObjectFile(cdi_obj_name))
            explicit_fake_objs[-1].fixup_idx = i
            cdi_obj_fixups.append(spec.LinkerSpec.Fixup('obj', i, 
                chop_suffix(obj_path) + '.cdi.o'))
            explicit_fake_objs[-1].fixup_idx = i
        except fake_types.NonDeferredObjectFile:
            fatal_error("'{}' is not a deferred object file".format(obj_path))

    # create unsafe, non-cdi shared libraries. CDI shared libraries are for a 
    # future version
    #if lspec.target_is_shared:
    #    print 'Building non-CDI shared library (CDI shared libraries not implemented yet)'
    #    sys.stdout.flush()
    #
    #    # stale files in .cdi can cause trouble
    #    subprocess.check_call(['rm', '-rf', '.cdi'])
    #    subprocess.check_call(['mkdir', '.cdi'])
    #
    #    normification_fixups = []
    #    normification_fixups += normify.fake_objs_normify(explicit_fake_objs)
    #    normification_fixups += normify.ar_normify(archives)
    #    normification_fixups += normify.sl_normify(lspec, lspec.sl_paths)
    #    print "Linking shared library '{}'\n".format(lspec.target)
    #
    #    ld_command = ['ld'] + lspec.fixup(normification_fixups)
    #    try:
    #        verbose_linker_output = subprocess.check_output(ld_command)
    #    except subprocess.CalledProcessError:
    #        fatal_error("Unable to compile without CDI using linker command '{}'"
    #                .format(' '.join(ld_command)))
    #    restore_original_objects()
    #    sys.exit(0)

    ###############################################################################
    # Compile without CDI to learn the needed objects, exact shared libraries used,
    # and the shared library load addresses
    #
    # only the needed object files are included from a given archive. Hence, we must
    # check which of the objects are needed for every archive. Instead of coding this
    # ourselves, we use the existing gcc infastructure to find the needed
    # object files: the linker spits out which object files are needed with the 
    # --verbose flag. To get this output, however, we need to compile the code
    # without CDI. The linker needs object files and we simply don't have the CDI
    # object files ready
    ###############################################################################

    fptr_addrs = []
    ar_fake_objs = []
    ar_fixups = []

    print 'Compiling normally to learn which objects are needed for archives...'
    sys.stdout.flush()

    normification_fixups = []
    normification_fixups += normify.ar_normify(archives)
    normification_fixups += normify.fake_objs_normify(explicit_fake_objs)
    normification_fixups += normify.sl_normify(lspec, lspec.sl_paths)

    # get a fixup to use the regular linker
    loader_fixup = spec.LinkerSpec.Fixup(None, None, None)
    for idx, entry in enumerate(lspec.miscs):
        if entry.startswith('--dynamic-linker='):
            rtld_realpath = os.path.realpath(entry[len('--dynamic-linker='):])
            if '/cdi/cdi-loader/dest/lib/' in rtld_realpath:
                loader_fixup.idx = idx
                loader_fixup.entry_type = 'misc'
                loader_fixup.replacement = ''
                break
    else:
        fatal_error("Unable to find --dynamic-linker specification for CDI loader")

    normification_fixups.append(loader_fixup)

    try:
        normified_spec = lspec.fixup(normification_fixups)
        eprint("normified_spec", normified_spec)
        ld_command = ['ld'] + normified_spec + ['--verbose']
        verbose_linker_output = subprocess.check_output(ld_command)
    except subprocess.CalledProcessError:
        fatal_error("Unable to compile without CDI using linker command '{}'"
                .format(' '.join(ld_command)))


    if '--abandon-cdi' in lspec.cdi_options:
        print 'WARNING: CREATING NON CDI EXECUTABLE AS REQUESTED'
        sys.exit(0)

    # Extract needed fake objects out of archives
    ar_fake_objs, ar_fixups = lib_utils.ar_extract_req_objs(verbose_linker_output, archives)

    if not lspec.target_is_shared and lib_utils.sl_aslr_is_enabled(lspec.target):
        fatal_error("load addresses aren't deterministic. Disable ASLR"
                " (this can be done with "
                "'echo 0 | sudo tee /proc/sys/kernel/randomize_va_space')")



    # Find all function pointer calls from shared libraries back into the 
    # executable code. We need jumps back to the shared libraries, even if those
    # shared libraries are not CDI. Since non-CDI shared libraries have unknown
    # function and fptr type information, every return sled must contain an entry
    # fptr calls in shared libraries. TODO: get ftypes/fptypes info for CDI
    # shared libraries and use that information to narrow the list of return
    # sleds that need an entry for shared library fptr calls
    #
    # The callback sled is constructed by executables only
    restore_rt_vaddrs = None
    sl_load_addrs = None
    if not lspec.target_is_shared:
        # list of addresses to which signal handlers return
        restore_rt_vaddrs = lib_utils.get_restore_rt_vaddrs(lspec)

        sl_load_addrs = dict() # maps shared lib realpath -> lib load address (in hex)
        sl_callback_table =  open('.cdi/sl_callback_table', 'w')
        for sl_path, lib_load_addr in lib_utils.sl_trace_bin(lspec.target, lspec.target_is_shared):
            if sl_path.startswith('/usr/local/cdi/lib/'):
                continue # this shared library is CDI so fptr analysis is unneeded

            # if it's in /usr/local/lib, then the reference contains code in addition
            # to the symbol table. Therefore, it's unassociated with the shared
            # library in the spec. Use this new binary instead
            # FIXME: replace spec args
            symbol_reference = lib_utils.sl_symbol_ref(sl_path)
            if symbol_reference.startswith('/usr/local/lib/'):
                sl_path = symbol_reference
            fptr_addrs = lib_utils.sl_get_fptr_addrs(sl_path, symbol_reference, lib_load_addr)

            assert '"' not in sl_path
            sl_callback_table.write('"{}" load-addr: {}\n'.format(sl_path, hex(lib_load_addr)))
            sl_callback_table.write('\n'.join(fptr_addrs) + '\n')
            if fptr_addrs:
                sl_callback_table.write('\n')

            sl_load_addrs[os.path.realpath(sl_path)] = lib_load_addr

        sl_callback_table.write('__restore_rt (for returns from signal handlers)\n')
        sl_callback_table.write('\n'.join(restore_rt_vaddrs) + '\n\n')
        sl_callback_table.close()

    sl_fixups = lib_utils.sl_cdi_fixups(lspec, lspec.target)
    # remove executable/shared library since it isn't CDI compiled
    subprocess.check_call(['rm', lspec.target])

    fake_objs = explicit_fake_objs + ar_fake_objs

    sys.stdout.flush()

    cdi_ld_real_path = subprocess.check_output(['readlink', '-f', sys.argv[0]])
    cdi_ld_real_path = chop_suffix(cdi_ld_real_path, '/')
    converter_path = cdi_ld_real_path + '/../converter/gen_cdi.py'
    fake_obj_paths = [fake_obj.path for fake_obj in fake_objs]

    if lspec.target_is_shared: 
        lspec.converter_options.append('--shared-library')

    print 'Converting fake objects to cdi-asm files: ' + ' '.join(fake_obj_paths)


    if sl_load_addrs:
        lspec.converter_options.append('--sl-fptr-addrs')
        lspec.converter_options.append('.cdi/sl_callback_table')
    if '--cdi-profile' in lspec.cdi_options:
        lspec.converter_options.append('--profile-gen')

    converter_command = [converter_path] + lspec.converter_options + fake_obj_paths
    try:
        subprocess.check_call(converter_command)
    except subprocess.CalledProcessError:
        fatal_error("conversion to CDI assembly failed with command: '{}'".format(
            ' '.join(converter_command)))


    print 'Assembling cdi asm files...'
    sys.stdout.flush()

    for fake_obj in fake_objs:
        cdi_asm_fname = chop_suffix(fake_obj.path, '.fake.o') + '.cdi.s'
        cdi_obj_fname = chop_suffix(fake_obj.path, '.fake.o') + '.cdi.o'
        gcc_as_command = (['as'] + fake_obj.as_spec_no_io + 
                [cdi_asm_fname, '-o', cdi_obj_fname])
        try:
            subprocess.check_call(gcc_as_command)
        except subprocess.CalledProcessError:
            fatal_error("assembling '{}' failed with command '{}'".format(
                cdi_asm_fname, ' '.join(gcc_as_command)))

    target_type = ''
    if lspec.target_is_shared:
        target_type = 'shared library'
    else:
        target_type = 'executable'

    print "Linking {} '{}'\n".format(target_type, lspec.target)
    sys.stdout.flush()

    # assemble cdi_abort.cdi.s every time to avoid using a stale version
    subprocess.check_call(['as', 
        lib_utils.get_script_dir() + '/../converter/cdi_abort.cdi.s', '-o',
        '.cdi/cdi_abort.cdi.o'])

    subprocess.check_call(['as',
        lib_utils.get_script_dir() + '/cdi_sections.cdi.s', '-o',
        '.cdi/cdi_sections.cdi.o'])

    # put cdi_abort.cdi.o and cdi_sections.cdi.o with the other obj files
    cdi_obj_fixups[-1].replacement = [
            cdi_obj_fixups[-1].replacement, '.cdi/cdi_abort.cdi.o', '.cdi/cdi_sections.cdi.o']

    cdi_fixups = ar_fixups + cdi_obj_fixups + sl_fixups


    try:
        cdi_spec = lspec.fixup(cdi_fixups)
        eprint("cdi_spec: ", cdi_spec)
        subprocess.check_call(['ld'] + cdi_spec)
    except subprocess.CalledProcessError:
        fatal_error("calling 'ld' with the following spec failed:\n\n{}"
                .format(' '.join(cdi_spec)))

    error.file_deleted_on_error = lspec.target

    # do some sanity checks for executables
    if not lspec.target_is_shared:
        pass



        # disable these checks for now. They'll be turned on again once the CDI 
        # loader accepts non-CDI code

        # check that the predicted shared library load addresses are accurate
        #for sl_path, lib_load_addr in lib_utils.sl_trace_bin(lspec.target, lspec.target_is_shared):
        #    try:
        #        if sl_load_addrs[os.path.realpath(sl_path)] != lib_load_addr:
        #            fatal_error("load address shifted upon recompilation for shared "
        #                    "library '{}'. Original: {}. New: {}." .format(os.path.realpath(sl_path), 
        #                        sl_load_addrs[os.path.realpath(sl_path)], lib_load_addr))
        #    except KeyError:
        #        if '/cdi/cdi-loader/' not in sl_path:
        #            raise

        # signal handling will break because we swap out the normal rtld with the 
        # CDI one when we do a normified compilation. In the future, a better 
        # alternative is to have the CDI loader check if the executable is CDI
        # and compile as CDI if it is

        # check that at least one predicted address for __restore_rt is correct
        #if lib_utils.get_vaddr('__restore_rt', lspec.target) not in restore_rt_vaddrs:
        #    fatal_error("__restore_rt address '{}' is different than all predicted addrs: {}"
        #            .format(lib_utils.get_vaddr('__restore_rt', lspec.target), ', '.join(restore_rt_vaddrs)))

    # fix up the ELF file for loading with shared libraries
    elf_fixup.cdi_fixup_elf(lspec)
    # PROFILE:
    # calls run_profiler.py on the object file generated to generate execution profile
    # re-runs gen_cdi.py with the profiled file.
    if not lspec.target_is_shared and '--cdi-profile' in lspec.cdi_options:
        print "doingggggggggggggggggg profiling"
        profiler_command = run_profile.run_profile(lspec.target)
        profiled_file = lspec.target + '.profile'
        lspec.converter_options.remove('--profile-gen')
        lspec.converter_options.append('--profile-use')
        lspec.converter_options.append(profiled_file)
        converter_command = [converter_path] + lspec.converter_options + fake_obj_paths
        try:
            subprocess.check_call(converter_command)
        except subprocess.CalledProcessError:
            fatal_error("conversion to CDI assembly failed with command: '{}'".format(
                ' '.join(converter_command)))


            print 'Assembling cdi asm files...'
        sys.stdout.flush()

        for fake_obj in fake_objs:
            cdi_asm_fname = chop_suffix(fake_obj.path, '.fake.o') + '.cdi.s'
            cdi_obj_fname = chop_suffix(fake_obj.path, '.fake.o') + '.cdi.o'
            gcc_as_command = (['as'] + fake_obj.as_spec_no_io + 
                    [cdi_asm_fname, '-o', cdi_obj_fname])
            try:
                subprocess.check_call(gcc_as_command)
            except subprocess.CalledProcessError:
                fatal_error("assembling '{}' failed with command '{}'".format(
                    cdi_asm_fname, ' '.join(gcc_as_command)))

        target_type = ''
        if lspec.target_is_shared:
            target_type = 'shared library'
        else:
            target_type = 'executable'

        print "Linking {} '{}'\n".format(target_type, lspec.target)
        sys.stdout.flush()

        # assemble cdi_abort.cdi.s every time to avoid using a stale version
        subprocess.check_call(['as', 
            lib_utils.get_script_dir() + '/../converter/cdi_abort.cdi.s', '-o',
            '.cdi/cdi_abort.cdi.o'])

        subprocess.check_call(['as',
            lib_utils.get_script_dir() + '/cdi_sections.cdi.s', '-o',
            '.cdi/cdi_sections.cdi.o'])

        # put cdi_abort.cdi.o and cdi_sections.cdi.o with the other obj files
        cdi_obj_fixups[-1].replacement = [
                cdi_obj_fixups[-1].replacement, '.cdi/cdi_abort.cdi.o', '.cdi/cdi_sections.cdi.o']

        cdi_fixups = ar_fixups + cdi_obj_fixups + sl_fixups


        try:
            # cdi_spec = lspec.fixup(cdi_fixups)
            subprocess.check_call(['ld'] + cdi_spec)
        except subprocess.CalledProcessError:
            fatal_error("calling 'ld' with the following spec failed:\n\n{}"
                    .format(' '.join(cdi_spec)))

        error.file_deleted_on_error = lspec.target
            # do some sanity checks for executables
        if not lspec.target_is_shared:
            pass

        elf_fixup.cdi_fixup_elf(lspec)

    restore_original_objects()
    error.restore_original_objects_fptr = None



if __name__ == "__main__":
    try:
        main()
    except:
        # restore the directory to consistent state before exiting. This grants
        # idempotence with respect to compilation-- A failed compilation will
        # not cause future compilations to fail
        if error.restore_original_objects_fptr:
            error.restore_original_objects_fptr()
        raise 
