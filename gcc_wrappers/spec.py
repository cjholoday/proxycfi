import subprocess
import os

class LinkerSpec():
    class Fixup():
        """Pass instances of these to LinkerSpec.cdi()
        
        Valid entry types: 'obj', 'ar', 'sl', 'misc'
        Index corresponds to the spec's obj_paths, ar_paths, sl_paths, miscs
        Replacement can be a string or a list
        """
        def __init__(self, entry_type, idx, replacement):
            self.entry_type = entry_type
            self.idx = idx
            self.replacement = replacement

    def __init__(self, raw_spec, fatal_error_fptr):
        self.raw_spec = raw_spec
        self.fatal_error = fatal_error_fptr
        self.decompose_raw_spec(raw_spec)

    def cdi(self, fixups):
        """Returns a cdi-spec for given a list of LinkerSpec.Fixup instances"""
        obj_fixups = dict()
        sl_fixups = dict()
        ar_fixups = dict()
        misc_fixups = dict()

        for fixup in fixups:
            if fixup.entry_type == 'obj':
                obj_fixups[fixup.idx] = fixup.replacement
            elif fixup.entry_type == 'ar':
                ar_fixups[fixup.idx] = fixup.replacement
            elif fixup.entry_type == 'sl':
                sl_fixups[fixup.idx] = fixup.replacement
            elif fixup.entry_type == 'misc':
                misc_fixups[fixup.idx] = fixup.replacement
            else:
                fatal_error("Invalid entry type for fixup: '{}'"
                        .format(fixup.entry_type))

        obj_paths_idx = 0
        sl_paths_idx = 0
        ar_paths_idx = 0
        misc_paths_idx = 0

        cdi_spec = []
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

            if replacement:
                if isinstance(replacement, basestring):
                    cdi_spec.append(replacement)
                else:
                    cdi_spec += replacement
            else:
                cdi_spec.append(entry)
        return cdi_spec


    def decompose_raw_spec(self, raw_spec):
        """Initializes member lists associated with the spec
        
        Initializes obj_paths, ar_paths, sl_paths, misc options, cdi_options, entry_types
        Objects in each list are ordered by what came first in the spec 

        Shared libraries specified as -llibname are replaced with a path to the
        shared library that will be used
        """

        self.obj_paths = []
        self.ar_paths = []
        self.sl_paths = []
        self.miscs = []
        self.cdi_options = []
        self.entry_types = []

        prev_entry = ''
        for entry in raw_spec:
            entry_type = self.get_entry_type(entry, prev_entry)
            if entry_type == 'libstem':
                if entry[:2] == '-l':
                    entry = entry[2:]
                try:
                    entry = find_lib(entry, self)
                except NoMatchingLibrary as err:
                    self.fatal_error('no matching library for -l{}'.format(err.libstem))
                if entry.endswith('.a'):
                    entry_type = 'ar'
                else:
                    entry_type = 'sl'

            self.entry_types.append(entry_type)
            if entry_type == 'obj':
                self.obj_paths.append(entry)
            elif entry_type == 'ar':
                self.ar_paths.append(entry)
            elif entry_type == 'sl':
                self.sl_paths.append(entry)
            elif entry_type == 'misc':
                self.miscs.append(entry)
                if prev_entry == '-o':
                    self.target = entry
                elif entry == '-shared':
                    self.target_is_shared = True
            elif word.startswith('--cdi-options='):
                self.cdi_options = word[len('--cdi-options='):].split(' ')
            else:
                self.fatal_error("Unknown spec entry type '{}'".format(entry_type))
            prev_entry = entry
        if self.target == '':
            self.target = 'a.out'

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
                    if (trim_path(entry) == 'crt1.o' 
                            or trim_path(entry) == 'crti.o'
                            or trim_path(entry) == 'crtbegin.o'
                            or trim_path(entry) == 'crtend.o'
                            or trim_path(entry) == 'crtn.o'
                            or trim_path(entry) == 'crtbeginS.o'
                            or trim_path(entry) == 'crtendS.o'):
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
                elif word.startswith('--cdi-options='):
                    yield ''
                else:
                    self.fatal_error("Invalid spec entry type '{}'".format(entry_type))
            except StopIteration:
                self.fatal_error("Constructing a new spec requires more entries "
                        "of type '{}' than were recorded".format(entry_type))


class NoMatchingLibrary(Exception):
    def __init__(self, libstem):
        self.libstem = libstem

def find_lib(libstem, linker_spec):
    if not hasattr(find_lib, 'search_dirs'):
        find_lib.search_dirs = gen_lib_search_dirs(linker_spec)

    if libstem[:2] == '-l':
        libstem = libstem[2:]
    for directory in find_lib.search_dirs:
        candidate_stem = '{}/lib{}'.format(directory, libstem)
        if os.path.isfile(candidate_stem + '.so'):
            return os.path.realpath(candidate_stem + '.so')
        elif os.path.isfile(candidate_stem + '.a'):
            return os.path.realpath(candidate_stem + '.a')
    else:
        raise NoMatchingLibrary(libstem)

def gen_lib_search_dirs(linker_spec):
    # first find directories in which libraries are searched for
    builtin_search_dirs = subprocess.check_output(
            '''$(which ld) --verbose | grep SEARCH_DIR | tr -s ' ;' '''
            ''' '\\n' | sed 's/^[^"]*"//g' | sed 's/".*$//g' ''', shell=True).split()
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


def trim_path(path):
    """Removes excess path e.g. /usr/local/bin/filename -> filename"""
    slash_index = path.rfind('/') 
    if slash_index == -1:
        return path
    elif slash_index == len(path) - 1:
        slash_index = path[:-1].rfind('/')
    return path[slash_index + 1:]

LD_ARG_REQUIRED_OPTIONS = ['-m', '-o', '-a', '-audit', '-A', '-b', '-c', '--depaudit', '-P', '-e', '--exclude-libs', '--exclude-modules-for-implib', '-f', '-F', '-G', '-h', '-l', '-L', '-O', '-R', '-T', '-dT', '-u', '-y', '-Y', '-z', '-assert', '-z', '--exclude-symbols', '--heap', '--image-base', '--major-image-version', '--major-os-version', '--major-subsystem-version', '--minor-image-version', '--minor-os-version', '--minor-subsystem-version', '--output-def', '--out-implib', '--dll-search-prefix', '--stack', '--subsystem', '--bank-window', '--got']



