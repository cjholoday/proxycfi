import __init__
import subprocess
import lib_utils
import os
import sys

import lscript_parsing
from error import fatal_error
from common.eprint import eprint

class LinkerSpec():
    class Fixup():
        """Pass instances of these to LinkerSpec.fixup()
        
        Valid entry types: 'obj', 'ar', 'sl', 'misc'
        Index corresponds to the spec's obj_paths, ar_paths, sl_paths, miscs
        Replacement can be a string or a list. 
        """
        def __init__(self, entry_type, idx, replacement):
            self.entry_type = entry_type
            self.idx = idx
            self.replacement = replacement

    def __init__(self, raw_spec, fatal_error_fptr):
        self.raw_spec = raw_spec
        self.fatal_error = fatal_error_fptr

        # Within each list, the objects are populated 
        # in the order in which they are found
        self.obj_paths = []
        self.ar_paths = []
        self.sl_paths = []
        self.miscs = []
        self.cdi_options = []
        self.entry_types = []
        self.target = 'a.out' # default target
        self.target_is_shared = False # unshared unless '-shared' is found

        self.entry_lists = { 
                'obj'  : self.obj_paths,
                'ar'   : self.ar_paths,
                'sl'   : self.sl_paths,
                'misc' : self.miscs,
                'cdi_options' : self.cdi_options}

        self.decompose_raw_spec(raw_spec)

    def fixup(self, fixups):
        """Returns a fixed up spec for given a list of LinkerSpec.Fixup instances"""

        # each dict maps { idx -> replacement }
        obj_fixups = dict()
        sl_fixups = dict()
        ar_fixups = dict()
        misc_fixups = dict()
        fixup_dicts = {
                'obj'  : obj_fixups,
                'sl'   : sl_fixups,
                'ar'   : ar_fixups,
                'misc' : misc_fixups}

        for fixup in fixups:
            if fixup_dicts[fixup.entry_type].has_key(fixup.idx):
                fatal_error("Conflicting fixups of type '{}' at idx '{}' with "
                        "replacements '{}' and '{}'".format(fixup.entry_type,
                            fixup.idx, fixup_dicts[fixup.entry_type][fixup.idx],
                            fixup.replacement))
            else:
                fixup_dicts[fixup.entry_type][fixup.idx] = fixup.replacement

        obj_paths_idx = 0
        sl_paths_idx = 0
        ar_paths_idx = 0
        misc_paths_idx = 0

        fixed_spec = []
        for i, entry in enumerate(self.reconstruct_spec()):
            # get the fixup if it exists
            replacement = None
            if self.entry_types[i] == 'obj':
                replacement = obj_fixups.get(obj_paths_idx)
                obj_paths_idx += 1
            elif self.entry_types[i] == 'ar':
                replacement = ar_fixups.get(ar_paths_idx)
                ar_paths_idx += 1
            elif self.entry_types[i] == 'sl':
                replacement = sl_fixups.get(sl_paths_idx)
                sl_paths_idx += 1
            elif self.entry_types[i] == 'misc':
                replacement = misc_fixups.get(misc_paths_idx)
                misc_paths_idx += 1
            elif self.entry_types[i] == 'cdi_options':
                continue
            else:
                fatal_error("Invalid entry type found in LinkerSpec: '{}'"
                        .format(self.entry_types[i]))

            if replacement == None:
                fixed_spec.append(entry)
            elif replacement == '' or replacement == []:
                continue # do not include this entry in the spec
            elif replacement:
                if isinstance(replacement, basestring):
                    fixed_spec.append(replacement)
                else:
                    fixed_spec += replacement
            else:
                fatal_error("Unknown replacement type: '{}' (type={})"
                        .format(replacement, type(replacement)))
        return fixed_spec


    def decompose_raw_spec(self, raw_spec):
        """Fills member lists associated with the spec
        
        Fills self.obj_paths, self.ar_paths, self.sl_paths, self.miscs 
              self.options, self.cdi_options, self.entry_types
        Objects in each list are ordered by what came first in the spec 

        self.target and self.target_is_shared are also set if found

        Shared libraries specified as -llibname are replaced with a path to the
        shared library that will be used
        """
        # true when --as-needed is enabled
        link_as_needed = False

        prev_entry = ''
        for entry in raw_spec:
            if entry == '-l':
                prev_entry = entry
                continue
            entry_type = self.get_entry_type(entry, prev_entry)
            if entry_type == 'libstem':
                if entry[:2] == '-l':
                    entry = entry[2:]
                try:
                    entry = find_lib(entry, self)
                except NoMatchingLibrary as err:
                    self.fatal_error('no matching library for -l{}'.format(err.libstem))
                if entry.endswith('.so') and not is_elf(entry):
                    script_spec = lscript_parsing.extract_spec_entries(entry)
                    # retain the enable/disable state of --as-needed
                    if link_as_needed:
                        script_spec.append('--as-needed')
                    else:
                        script_spec.append('--no-as-needed')
                    self.decompose_raw_spec(script_spec)

                    # Leave off the linker script because its implicit spec 
                    # entries have already been decomposed
                    continue
                elif entry.endswith('.a'):
                    entry_type = 'ar'
                else:
                    entry_type = 'sl'

            self.entry_types.append(entry_type)
            try:
                self.entry_lists[entry_type].append(entry)
            except KeyError:
                self.fatal_error("Unknown spec entry type '{}'".format(entry_type))

            if entry_type == 'cdi_options':
                self.cdi_options = entry[len('--cdi-options='):].split('|')
            elif entry_type == 'misc':
                if prev_entry == '-o':
                    self.target = entry
                elif entry == '-shared':
                    self.target_is_shared = True
                elif entry == '--as-needed':
                    link_as_needed = True
                elif entry == '--no-as-needed':
                    link_as_needed = False
            prev_entry = entry

    def get_entry_type(self, entry, prev_entry):
        if prev_entry == '-l' or (entry[:2] == '-l' and len(entry) > 2): 
            return 'libstem'
        elif entry.startswith('--cdi-options='):
            return 'cdi_options'
        elif entry[0] != '-' and prev_entry not in LD_ARG_REQUIRED_OPTIONS:
            # three valid possibilities: object file, shared lib, archive
            try:
                mystery_file = open(entry, 'rb')
            except IOError:
                try:
                    # this might capture an unintended library?
                    print entry
                    find_lib(entry, self)
                    return 'libstem' # could check that it is archive/sharedlib
                except NoMatchingLibrary:
                    self.fatal_error("non existent file '{}' passed to linker"
                            .format(entry))

            discriminator = mystery_file.read(7)
            if discriminator.startswith('\x7FELF'):
                # use elf header to find type of elf file
                mystery_file.seek(16)
                e_type = mystery_file.read(1)
                mystery_file.close()

                if e_type == '\x03': # shared object file
                    return 'sl'
                elif e_type == '\x00': # no type
                    self.fatal_error("linker passed elf file '{}' with e_type=NULL"
                            .format(mystery_file.name))
                elif e_type == '\x01': # relocatable
                    # Fixing up startup objects is not very important since
                    # attackers will only have access to attack after a server starts
                    if (os.path.basename(entry) == 'crt1.o' 
                            or os.path.basename(entry) == 'crti.o'
                            or os.path.basename(entry) == 'crtbegin.o'
                            or os.path.basename(entry) == 'crtend.o'
                            or os.path.basename(entry) == 'crtn.o'
                            or os.path.basename(entry) == 'crtbeginS.o'
                            or os.path.basename(entry) == 'crtendS.o'):
                        return 'misc'
                    self.fatal_error("linker passed non-CDI object file '{}'"
                            .format(mystery_file.name))
                elif e_type == '\x02': # executable
                    self.fatal_error("executable '{}' passed to linker"
                            .format(mystery_file.name))
                elif e_type == '\x04': # core file
                    self.fatal_error("core file '{}' passed to linker"
                            .format(mystery_file.name))
                else:
                    self.fatal_error("linker passed elf file '{}' with undefined"
                            " e_type: {}".format(mystery_file.name, repr(e_type)))

            mystery_file.close()
            if discriminator == '!<arch>':
                return 'ar'
            elif discriminator == '#<deff>':
                return 'obj'
            else:
                eprint("cdi-ld: warning: unknown file type passed to "
                        "linker. It will be treated as a linker script:"
                        " '{}'".format(mystery_file.name))
                return 'misc'
        else:
            return 'misc'

    def norm(self):
        """Returns a spec for non-cdi linking"""
        normal_spec = []
        for entry in self.reconstruct_spec():
            if entry:
                normal_spec.append(entry)
        return normal_spec


    def raw(self):
        """Returns the spec as it was passed on initialization"""
        return self.raw_spec

    def reconstruct_spec(self):
        objs = iter(self.obj_paths)
        ars = iter(self.ar_paths)
        sls = iter(self.sl_paths)
        miscs = iter(self.miscs)

        for entry_type in self.entry_types:
            try:
                if entry_type == 'obj':
                    yield objs.next()
                elif entry_type == 'ar':
                    yield ars.next()
                elif entry_type == 'sl':
                    yield sls.next()
                elif entry_type == 'misc':
                    yield miscs.next()
                elif entry_type.startswith('cdi_options'):
                    yield ''
                else:
                    self.fatal_error("Invalid spec entry type '{}'".format(entry_type))
            except StopIteration:
                self.fatal_error("Constructing a new spec requires more entries "
                        "of type '{}' than were recorded".format(entry_type))


class NoMatchingLibrary(Exception):
    def __init__(self, libstem):
        self.libstem = libstem

def find_lib(libstem, lspec):
    if not hasattr(find_lib, 'search_dirs'):
        find_lib.search_dirs = gen_lib_search_dirs(lspec)

    if libstem[:2] == '-l':
        libstem = libstem[2:]
    elif libstem.startswith('lib') and (libstem.endswith('.a')
            or lib_utils.sl_chop_versioning(libstem).endswith('.so')):
        # print path
        # print find_lib.search_dirs
        for path in find_lib.search_dirs:
            candidate = '{}/{}'.format(path, libstem)
            print candidate
            if os.path.isfile(candidate):
                # print "found"
                return os.path.abspath(candidate)
        else:
            raise NoMatchingLibrary(libstem)
    for path in find_lib.search_dirs:
        candidate_stem = '{}/lib{}'.format(path, libstem)
        if os.path.isfile(candidate_stem + '.so'):
            return os.path.abspath(candidate_stem + '.so')
        elif os.path.isfile(candidate_stem + '.a'):
            return os.path.abspath(candidate_stem + '.a')
    else:
        raise NoMatchingLibrary(libstem)

def chop_suffix(string, cutoff = ''):
    if cutoff == '':
        return string[:string.rfind('.')]
    return string[:string.rfind(cutoff)]


def gen_lib_search_dirs(linker_spec):
    # first find directories in which libraries are searched for
    builtin_search_dirs_t = subprocess.check_output(
            '''$(which ld) --verbose | grep SEARCH_DIR | tr -s ' ;' '''
            ''' '\\n' | sed 's/^[^"]*"//g' | sed 's/".*$//g' ''', shell=True).split()
    builtin_search_dirs = []
    # fix paths strating with '='
    for b in builtin_search_dirs_t:
        if b[0] == '=':
            builtin_search_dirs.append(b[1:])
        else:
            builtin_search_dirs.append(b)
    added_search_dirs = []
    prev = ''
    for word in linker_spec.raw():
        if word[:2] == '-L' and len(word) > 2:
            added_search_dirs.append(os.path.realpath(word[2:]))
        elif prev == '--library-path' or prev == '-L':
            added_search_dirs.append(os.path.realpath(word))
        prev = word

    # note the order: -L/--library-path directories are favored
    return added_search_dirs + builtin_search_dirs 

def is_elf(mystery_file_path):
    with open(mystery_file_path, 'rb') as mystery_file:
        return mystery_file.read(len('\x7FELF')) == '\x7FELF'

LD_ARG_REQUIRED_OPTIONS = ['-m', '-o', '-a', '-audit', '-A', '-b', '-c', '--depaudit', '-P', '-e', '--exclude-libs', '--exclude-modules-for-implib', '-f', '-F', '-G', '-h', '-l', '-L', '-O', '-R', '-T', '-dT', '-u', '-y', '-Y', '-z', '-assert', '-z', '--exclude-symbols', '--heap', '--image-base', '--major-image-version', '--major-os-version', '--major-subsystem-version', '--minor-image-version', '--minor-os-version', '--minor-subsystem-version', '--output-def', '--out-implib', '--dll-search-prefix', '--stack', '--subsystem', '--bank-window', '--got', '-soname', '--soname']



