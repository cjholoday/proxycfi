import __init__

import spec
import subprocess
import os
import shutil
import sys
import tempfile

import lib_utils
from error import fatal_error
from common.eprint import vprint
from common.eprint import vvprint

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


        ar_effective_path = ''
        if archive.path.startswith('/'):
            ar_effective_path = archive.path
        else:
            ar_effective_path = '../' + archive.path

        lines = subprocess.check_output(['ar', 'xv', ar_effective_path]).strip().split('\n')
        obj_fnames = map(lambda x: x[len('x - '):], lines)
        #vprint("CWD: ", os.getcwd())
        #vprint("Archive Info:")
        vprint(archive.path)
        #vprint(archive.fake_objs)
        #vprint(archive.thin)
        vprint(' '.join(obj_fnames))
        vprint("--------------")

        if not obj_fnames:
            continue
        empty = 0
        for obj_fname in obj_fnames:
            if obj_fname == '':
                vprint("archive %s has an obj file with obj_fname = ''" % (archive.path))
                empty = 1
                break
        if empty:
            continue
        ar_fixups.append(spec.LinkerSpec.Fixup('ar', archive.fixup_idx, 
            '.cdi/' + os.path.basename(archive.path)))

        # maps obj_fname -> int (where int is the number of times this object
        # has already been seen. Not in the map if not already seen)
        internally_duplicated = dict()

        temp_dir = tempfile.mkdtemp()

        unique_obj_fnames = []
        for obj_fname in obj_fnames:
            vvprint("normifying {}".format(obj_fname))
            ar_dir = os.path.dirname(ar_effective_path)

            default_fname = obj_fname
            unique_fname = default_fname
            known_mult = 1
            if default_fname in internally_duplicated:
                to_path = os.path.join(temp_dir, default_fname)
                subprocess.check_call(['mv', default_fname, to_path])

                known_mult += internally_duplicated[unique_fname]
                unique_fname = '{}_DUP_{}'.format(
                        known_mult, default_fname)
                if unique_fname in internally_duplicated:
                    # prepending a duplicate count may collide with other 
                    # existing files. This is extremely unlikely but possible
                    # TODO: handle this issue
                    fatal_error("attempt to make '{}' unique caused collision with"
                            " file '{}'".format(default_fname, unique_fname))
            
            vvprint("unique_fname: {}".format(unique_fname))
            vvprint("collision idx: {}".format(known_mult))
            subprocess.check_call(['ar', 'xN', str(known_mult), ar_effective_path, default_fname])
            unique_obj_fnames.append(unique_fname)

            if default_fname in internally_duplicated:
                subprocess.check_call(['mv', default_fname, unique_fname])

                from_path = os.path.join(temp_dir, default_fname)
                subprocess.check_call(['mv', from_path, default_fname])
            if os.path.isfile(unique_fname): # XXX this should always be true
                with open(unique_fname, 'r') as fake_obj:
                    elf_signature = '\x7FELF'
                    is_elf = fake_obj.read(4) == elf_signature
                if is_elf:
                    continue # already real object file
                else:
                    correct_obj_fname = chop_suffix(unique_fname, '.') + '.fake.o'
                    subprocess.check_call(['mv', unique_fname, correct_obj_fname])
                    subprocess.check_call(['as', correct_obj_fname, '-o', unique_fname])
            try:
                #
                internally_duplicated[default_fname] += 1
            except KeyError:
                internally_duplicated[default_fname] = 1

        shutil.rmtree(temp_dir)


        # TODO handle case where two archives have diff path but same names
        assert os.path.basename(archive.path) not in archives
        subprocess.check_call(['ar', 'cq', os.path.basename(archive.path)] + unique_obj_fnames)
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
