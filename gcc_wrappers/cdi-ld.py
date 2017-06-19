#!/usr/bin/env python
import sys
import os
import subprocess
from eprint import eprint
import re
import copy

import spec
import normify
import lib_utils
import fake_types

raw_ld_spec = sys.argv[1:]

restore_original_objects_fptr = None
def fatal_error(message):
    eprint('\n----------------------------------------------\n'
            'cdi-ld: error: {}'.format(message))
    eprint('\nSpec passed to cdi-ld.py: {}'.format(' '.join(raw_ld_spec)))
    if restore_original_objects_fptr:
        restore_original_objects_fptr()
    sys.exit(1)
 
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

lspec = spec.LinkerSpec(raw_ld_spec, fatal_error)

archives = []
for i, path in enumerate(lspec.ar_paths):
    archives.append(fake_types.Archive(path))
    archives[-1].fixup_idx = i

# the fake object files directly listed in the ld spec
for path in lspec.obj_paths:
    fake_obj_name = chop_suffix(path) + '.fake.o'
    subprocess.check_call(['mv', path, fake_obj_name])


# the fake objs will need to be moved back to their original filename in case
# another compilation wants to use them as well. This code ASSUMES that
# explicit_original_objs will not be modified in any way
#
# This is called on error or at the end of cdi-ld
explicit_original_objs = copy.deepcopy(lspec.obj_paths)
def restore_original_objects():
    for i, fake_obj in enumerate(explicit_fake_objs):
        subprocess.check_call(['mv', fake_obj.path, explicit_original_objs[i]])

# used by fatal_error()
restore_original_objects_fptr = restore_original_objects


# All fake objects must be constructed after the filenames are moved
# Otherwise fatal_error cannot restore them on error in this brief window
explicit_fake_objs = []
for i, obj_path in enumerate(lspec.obj_paths):
    try:
        cdi_obj_name = chop_suffix(obj_path) + '.fake.o'
        explicit_fake_objs.append(fake_types.FakeObjectFile(cdi_obj_name))
        explicit_fake_objs[-1].fixup_idx = i
    except NonDeferredObjectFile:
        fatal_error("'{}' is not a deferred object file".format(obj_path))

# create unsafe, non-cdi shared libraries. CDI shared libraries are for a 
# future version
if lspec.target_is_shared:
    for i, fake_obj in enumerate(explicit_fake_objs):
        subprocess.call(['as', fake_obj.path, '-o',
            linker.obj_fnames[i]] + fake_obj.as_spec_no_io)

    print 'Building non-CDI shared library (CDI shared libraries not implemented yet)'
    print '   Converting CDI archives to non-CDI archives'
    sys.stdout.flush()

    # stale files in .cdi can cause trouble
    subprocess.check_call(['rm', '-rf', '.cdi'])
    subprocess.check_call(['mkdir', '.cdi'])

    # we need to create non-cdi archives (see above). Therefore we need
    # to remember the association between the non-cdi archives and the cdi-archives
    # so that we can conclude which objects are needed for each cdi-archive
    os.chdir('.cdi')
    for archive in archives:
        lines = subprocess.check_output(['ar', 'xv', archive.path]).strip().split('\n')
        fnames = map(lambda x: x[len('x - '):], lines)
        for fname in fnames:
            with open(fname, 'r') as fake_obj:
                elf_signature = '\x7FELF'
                is_elf = fake_obj.read(4) == elf_signature
            if is_elf:
                continue # already real object file
            else:
                correct_fname = chop_suffix(fname, '.') + '.fake.o'
                subprocess.check_call(['mv', fname, correct_fname])
                subprocess.check_call(['as', correct_fname, '-o', fname])

        subprocess.check_call(['ar', 'rc', os.path.basename(archive.path)] + fnames)

    # create spec for non-cdi compilation
    ld_spec_unsafe_archives = copy.deepcopy(ld_spec)
    for i, entry in enumerate(linker.spec):
        if linker.entry_types[i] == linker.entry_type.ARCHIVE:
            ld_spec_unsafe_archives[i] = '.cdi/' + os.path.basename(linker.spec[i])

    os.chdir('..')

    print "Linking shared library '{}'\n".format(linker.target)

    ld_command = ['ld'] + ld_spec_unsafe_archives
    try:
        verbose_linker_output = subprocess.check_output(ld_command)
    except subprocess.CalledProcessError:
        fatal_error("Unable to compile without CDI using linker command '{}'"
                .format(' '.join(ld_command)))
    restore_original_objects()
    sys.exit(0)

# only the needed object files are included from a given archive. Hence, we must
# check which of the objects are needed for every archive. Instead of coding this
# ourselves, we use the existing gcc infastructure to find the needed
# object files: the linker spits out which object files are needed with the 
# --verbose flag. To get this output, however, we need to compile the code
# without CDI. The linker needs object files and we simply don't have the CDI
# object files ready

fptr_addrs = []
ar_fake_objs = []
ar_fixups = []
if archives != []:
    print 'Compiling normally to learn which objects are needed for archives...'
    sys.stdout.flush()

    normification_fixups = normify.ar_normify(archives)
    normify.fake_objs_normify(explicit_fake_objs)

    try:
        normified_spec = lspec.fixup(normification_fixups)
        ld_command = ['ld'] + normified_spec + ['--verbose']
        verbose_linker_output = subprocess.check_output(ld_command)
    except subprocess.CalledProcessError:
        fatal_error("Unable to compile without CDI using linker command '{}'"
                .format(' '.join(ld_command)))

    if '--abandon-cdi' in lspec.cdi_options:
        print 'WARNING: CREATING NON CDI EXECUTABLE AS REQUESTED'
        sys.exit(0)

    # TODO always create a non-CDI executable not just when there are archives
    #
    # For now, this code will always run since there is always an archive
    # listed in the spec. This may not always be the case?

    # check that ASLR is disabled
    traced_output1 = subprocess.check_output(['./' + lspec.target], 
            env=dict(os.environ, **{'LD_TRACE_LOADED_OBJECTS':'1'}))
    traced_output2 = subprocess.check_output(['./' + lspec.target], 
            env=dict(os.environ, **{'LD_TRACE_LOADED_OBJECTS':'1'}))
    if traced_output1 != traced_output2:
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

    # the shared library paths from sl_load_addrs() are more precise 
    # than the shared libs passed to the linker as options. The ones passed as
    # options are occasionally linker scripts, which complicates analysis since
    # we would have to parse through the scripts. Even then, we wouldn't be sure
    # what is used in the end. sl_load_addrs() instead asks the non-CDI
    # executable what shared libraries are used, which makes the GNU linker do
    # the work for us

    fptr_addrs = []
    for sl_path, lib_load_addr in lib_utils.sl_load_addrs(lspec.target):
        eprint("cdi-ld: warning: linking with non-CDI shared library '{}'"
                .format(sl_path))

        # if it's in /usr/local/lib, then the reference contains code in addition
        # to the symbol table. Therefore, it's unassociated with the shared
        # library in the spec. Use this new binary instead
        # FIXME: replace spec args
        symbol_reference = lib_utils.sl_find_unstripped(sl_path)
        if symbol_reference.startswith('/usr/local/lib/'):
            sl_path = symbol_reference
        fptr_addrs += lib_utils.sl_get_fptr_addrs(sl_path, symbol_reference, lib_load_addr)

    # remove executable since it isn't CDI compiled
    subprocess.check_call(['rm', lspec.target])

    # Extract needed fake objects out of archives
    ar_fake_objs, ar_fixups = lib_utils.ar_extract_req_objs(verbose_linker_output, archives)
    print ar_fake_objs

fake_objs = explicit_fake_objs + ar_fake_objs

sys.stdout.flush()

cdi_ld_real_path = subprocess.check_output(['readlink', '-f', sys.argv[0]])
cdi_ld_real_path = chop_suffix(cdi_ld_real_path, '/')
converter_path = cdi_ld_real_path + '/../converter/gen_cdi.py'
fake_obj_paths = [fake_obj.path for fake_obj in fake_objs]

converter_options = []
if lspec.target_is_shared: 
    converter_options.append('--shared-library')

print 'Converting fake objects to cdi-asm files: ' + ' '.join(fake_obj_paths)


if fptr_addrs:
    converter_options.append('--shared-lib-fptr-addrs')
    converter_options.append(','.join(fptr_addrs))

converter_command = [converter_path] + converter_options + fake_obj_paths
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


fake_obj_fixups = []
for obj in explicit_fake_objs:
    fake_obj_fixups.append(spec.LinkerSpec.Fixup('obj', obj.fixup_idx,
        obj.path.replace('.fake.o', '.cdi.o')))

# put cdi_abort.cdi.o with the other obj files
fake_obj_fixups[-1].replacement = [
        fake_obj_fixups[-1].replacement, '.cdi/cdi_abort.cdi.o']

cdi_fixups = ar_fixups + fake_obj_fixups

try:
    cdi_spec = lspec.fixup(cdi_fixups)
    subprocess.check_call(['ld'] + cdi_spec)
except subprocess.CalledProcessError:
    fatal_error("calling 'ld' with the following spec failed:\n\n{}"
            .format(' '.join(cdi_spec)))

restore_original_objects()

