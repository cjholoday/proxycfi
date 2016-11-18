#!/usr/bin/env python
import sys
import os
import subprocess
from eprint import eprint
import re

LD_ARG_REQUIRED_OPTIONS = ['-m', '-o', '-a', '-audit', '-A', '-b', '-c', '--depaudit', '-P', '-e', '--exclude-libs', '--exclude-modules-for-implib', '-f', '-F', '-G', '-h', '-l', '-L', '-O', '-R', '-T', '-dT', '-u', '-y', '-Y', '-z', '-assert', '-z', '--exclude-symbols', '--heap', '--image-base', '--major-image-version', '--major-os-version', '--major-subsystem-version', '--minor-image-version', '--minor-os-version', '--minor-subsystem-version', '--output-def', '--out-implib', '--dll-search-prefix', '--stack', '--subsystem', '--bank-window', '--got']

class FakeObjectFile:
    def __init__(self, path):
        self.construct_from_file(path)
        self.path = path

        if self.has_missing_dep:
            pass
            # try to find it now TODO

    def construct_from_file(self, path):
        """Extracts info from fake object file

        initializes...
            self.src_directory 
            self.has_missing_dep
            self.deps
            self.as_spec 
            self.as_spec_non_io"""
        self.has_missing_dep = False
        self.as_spec_non_io = ''
        with open(path, 'r') as fake_obj:
            elf_signature = '\x7FELF'
            if fake_obj.read(4) == elf_signature:
                eprint("cdi-ld: error: linking non-deferred object file: '{}'"
                        .format(path))
                sys.exit(1)
            fake_obj.seek(0)

            reading_typeinfo = False
            for line in fake_obj:
                if reading_typeinfo:
                    if line == '\n':
                        reading_typeinfo = False
                    continue
                elif line == '\n':
                    continue

                words = line.split()
                command = words[1]
                if command == 'assembly':
                    break
                elif command == 'typeinfo':
                    reading_typeinfo = True
                elif command == 'as_spec_non_io':
                    self.as_spec_non_io = words[2:]
                elif command == 'source_directory':
                    self.src_directory = words[2]
                elif command == 'dependencies':
                    self.deps = words[2:]
                elif command == 'warning':
                    if words[2] == 'missing_dependency':
                        self.has_missing_dep = True
                elif command == 'as_spec':
                    self.as_spec = words[2:]
                else:
                    eprint("cdi-ld: warning: invalid command '{}' in "
                            " fake object '{}'".format(command, path))


class Archive:
    def __init__(self, name):
        self.path = path
        self.fake_objs = []
        self.thin = False


class Linker:
    def __init__(self, spec):
        self.spec = spec

    def parse_spec(self):
        """Extracts info from the spec and stores it in object variables
        
        initializes...
            self.obj_fnames
            self.archive_paths
            self.shared_lib_paths
            self.library_positions (dict used for converting spec to cdi)
            self.bad_spec_indices (condemned indices for cdi spec conversion)

        The linker also remembers how to convert the spec to CDI given a dict
        mapping [archive name] -> [list of needed fake objects]"""

        self.obj_fnames = []
        self.archive_paths = []
        self.shared_lib_paths = []
        self.library_positions = dict()
        self.obj_file_indices = []

        # indices that shouldn't be included in cdi spec
        self.bad_spec_indices = [] 
        
        lib_search_dirs = self.lib_search_dirs()

        prev = ''
        for i, word in enumerate(self.spec):
            if word[:2] == '-l' and word != '-l':
                prev = '-l'
                word = word[2:]
            if prev == '-l': 
                try:
                    lib_path = self.find_lib(lib_search_dirs, word)
                    lib_path = os.path.realpath(lib_path)

                    # don't allow duplicate archives/shared-libs
                    if self.library_positions.has_key(lib_path):
                        self.bad_spec_indices.append(i)
                    else:
                        self.library_positions[lib_path] = i
                        if lib_path[-2:] == '.a':
                            self.archive_paths.append(lib_path)
                        else:
                            self.shared_lib_paths.append(lib_path)
                except Linker.NoMatchingLibrary as err:
                    eprint('cdi-ld: error: no matching library for -l{}'.format(
                        err.libname))
                    sys.exit(1)
            elif word[0] != '-' and prev not in LD_ARG_REQUIRED_OPTIONS:
                path_record = None
                if word[-2:] == '.a':
                    path_record = self.archive_paths
                elif word[-3:] == '.so':
                    path_record = self.shared_lib_paths

                if word[-2:] == '.a' or word[-3:] == '.so':
                    lib_path = os.path.realpath(word)
                    if self.library_positions.has_key(lib_path):
                        self.bad_spec_indices.append(i)
                    elif os.path.isfile(lib_path):
                        self.library_positions[lib_path] = i
                        path_record.append(lib_path)
                    else:
                        eprint("cdi-ld: error: library file doesn't exist: '{}'"
                                .format(lib_path))
                        sys.exit(1)
                # object files are listed without a path
                elif word == trim_path(word): 
                    assert word[-2:] == '.o'
                    self.obj_fnames.append(word)
                    self.obj_file_indices.append(i)
            elif word == '-l':
                self.bad_spec_indices.append(i)
            prev = word

    def cdi_spec(self, required_objs):
        """Returns a CDI-compliant spec"""
        pass

    def link(self, spec_addition = None):
        """Run the GNU linker on self.spec||spec_addition """
        pass

    def lib_search_dirs(self):
        # first find directories in which libraries are searched for
        builtin_search_dirs = subprocess.check_output(
                '''$(which ld) --verbose | grep SEARCH_DIR | tr -s ' ;' '''
                ''' '\\n' | sed 's/^[^"]*"//g' | sed 's/".*$//g' ''', shell=True).split()
        added_search_dirs = []
        prev = ''
        for word in self.spec:
            if word[:2] == '-L':
                added_search_dirs.append(word[2:])
            elif prev == '--library-path' or prev == '-L':
                added_search_dirs.append(word)

        # note the order: -L/--library-path directories are favored
        return added_search_dirs + builtin_search_dirs 

    def find_lib(self, search_dirs, libname):
        for directory in search_dirs:
            candidate_stem = '{}/lib{}'.format(directory, libname)
            if os.path.isfile(candidate_stem + '.so'):
                return candidate_stem + '.so'
            elif os.path.isfile(candidate_stem + '.a'):
                return candidate_stem + '.a'
        else:
            raise Linker.NoMatchingLibrary(libname)

    class NoMatchingLibrary(Exception):
        def __init__(self, libname):
            self.libname = libname


def required_archive_objs(verbose_output):
    """Given output from --verbose, returns dict {archive -> objs needed}"""
    objs_needed = dict()
    
    # matching strings in the form '(libname.a)obj_name.o'
    # characters are allowed after '.o' since some build systems do it
    matcher = re.compile(r'^\([^()\s]+\.a\)[^()\s]+\.o[^()\s]*$')

    for line in verbose_output:
        if matcher.match(line):
            end_paren_idx = line.find(')')
            archive_path = os.path.realpath(line[1:end_paren_idx])
            obj_fname = line[end_paren_idx + 1:]
            try:
                objs_needed[archive_path].append(obj_fname)
            except KeyError:
                objs_needed[archive_path] = [obj_fname]

def trim_path(path):
    """Removes excess path e.g. /usr/local/bin/filename -> filename"""
    slash_index = path.rfind('/') 
    if slash_index == -1:
        return path
    elif slash_index == len(path) - 1:
        slash_index = path[:-1].rfind('/')
    return path[slash_index + 1:]

########################################################################
# cdi-ld: a cdi wrapper for the gnu linker 'ld'
#   Identifies necessary fake object files in archives, converts fake object
#   files to real, cdi-compliant object files, and runs the gnu linker on them
#
########################################################################

ld_spec = sys.argv[1:]
linker = Linker(ld_spec)
linker.parse_spec()

archives = []
for path in linker.archive_paths:
    archives.append(Archive(path))

# the fake object files directly listed in the ld spec
explicit_fake_objs = []
for fname in linker.obj_fnames:
    cdi_obj_name = fname[:fname.rfind('.')] + '.cdi.o'
    subprocess.call(['mv', fname, cdi_obj_name])
    explicit_fake_objs.append(FakeObjectFile(cdi_obj_name))

    print 'directory: ' + explicit_fake_objs[-1].src_directory
    print 'missing dep? ' + str(explicit_fake_objs[-1].has_missing_dep)
    print 'deps: ' + ' '.join(explicit_fake_objs[-1].deps)
    print 'cdi as spec: ' + ' '.join(explicit_fake_objs[-1].as_spec)

# only the needed object files are included from a given archive. Hence, we must
# check which of the objects are needed for every archive. Instead of coding this
# ourselves, we instead use the existing gcc infastructure to find the needed
# object files: the linker spits out which object files are needed with the 
# --verbose flag. To get this output, however, we need to compile the code
# without CDI. The linker needs object files and we simply don't have the CDI
# object files ready

if archives != []:
    # generate non-cdi object files
    for fake_obj in explicit_fake_objs:
        subprocess.call(['as', fake_obj.path, '-o', 
            fake_obj.path[:-1 * len('.cdi.o')] + '.o'] + fake_obj.as_spec_non_io)

    verbose_linker_output = subprocess.check_output(['ld'] + ld_spec + ['--verbose'])
    implicit_fake_objs = required_archive_objs(verbose_linker_output)
    print implicit_fake_objs

