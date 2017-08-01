import spec
import subprocess
import os
import sys

import lib_utils
from error import fatal_error

def ar_normify(archives):
    """Creates non-CDI archives and returns a list of fixups
    
    Deletes and modifies ./.cdi
    """

    ar_fixups = []

    # stale files in .cdi can cause trouble
    subprocess.check_call(['rm', '-rf', '.cdi'])
    subprocess.check_call(['mkdir', '.cdi'])

    os.chdir('.cdi')
    for archive in archives:
        ar_fixups.append(spec.LinkerSpec.Fixup('ar', archive.fixup_idx, 
            '.cdi/' + os.path.basename(archive.path)))

        ar_effective_path = ''
        if archive.path.startswith('/'):
            ar_effective_path = archive.path
        else:
            ar_effective_path = '../' + archive.path

        lines = subprocess.check_output(['ar', 'xv', ar_effective_path]).strip().split('\n')
        obj_fnames = map(lambda x: x[len('x - '):], lines)
        for obj_fname in obj_fnames:
            with open(obj_fname, 'r') as fake_obj:
                elf_signature = '\x7FELF'
                is_elf = fake_obj.read(4) == elf_signature
            if is_elf:
                continue # already real object file
            else:
                correct_obj_fname = chop_suffix(obj_fname, '.') + '.fake.o'
                subprocess.check_call(['mv', obj_fname, correct_obj_fname])
                subprocess.check_call(['as', correct_obj_fname, '-o', obj_fname])


        # TODO handle case where two archives have diff path but same names
        assert os.path.basename(archive.path) not in archives
        subprocess.check_call(['ar', 'rc', os.path.basename(archive.path)] + obj_fnames)
    os.chdir('..')
    return ar_fixups

def fake_objs_normify(fake_objs):
    """Assembles fake objects into non-CDI objects. Returns a list of fixups"""

    fixups = []
    for i, fake_obj in enumerate(fake_objs):
        target = fake_obj.path.replace('.fake.o', '.o')
        subprocess.call(['as', fake_obj.path, '-o', target] + fake_obj.as_spec_no_io)
        fixups.append(spec.LinkerSpec.Fixup('obj', fake_obj.fixup_idx, target))
    return fixups


def sl_normify(lspec, sl_paths):
    """Returns fixups for shared libraries

    We need the load addresses of shared libraries in order to generate callback
    sleds that handle function pointer calls back into the executable code from
    a shared library. The fixups that are returned ensure that we use the same
    shared library that a CDI compilation will use. FIXME: Once CDI shared libraries
    are supported this won't be sufficient because CDI shared libraries cannot 
    be built with non-CDI code. Hence, we cannot obtain the load addresses
    while doing a normified compilation. As it currently stands an executable
    is generated two times: first, a non-CDI executable is generated; then, a CDI
    executable is generated. One might think we could generate a third CDI executable
    and use the second executable's shared library load addresses to create the 
    callback sleds. Unfortunately, I suspect this will fail. Modifying the executable
    code might change the library load addresses (unconfirmed). Once CDI
    shared libraries are being built, we'll have control of loading libraries, 
    and therefore putting the solution in the loader makes more sense
    """
    sl_fixups = []
    for idx, sl_path in enumerate(sl_paths):
        if lib_utils.has_symbol_table(sl_path):
            continue # fptr analysis only needs a symbol table

        # Unsafe, unstripped non-CDI shared libraries are stored in cdi/ulib
        candidate = '/usr/local/cdi/ulib/' + os.path.basename(os.path.realpath(sl_path))
        if os.path.isfile(candidate):
            sl_fixups.append(spec.LinkerSpec.Fixup('sl', idx, candidate))
        else:
            # this will throw an error if a symbol reference cannot be found
            lib_utils.sl_symbol_ref(sl_path)

    sl_fixups.append(lib_utils.get_cdi_runtime_search_path_fixup(lspec))
    return sl_fixups


def chop_suffix(string, cutoff = ''):
    if cutoff == '':
        return string[:string.rfind('.')]
    return string[:string.rfind(cutoff)]
