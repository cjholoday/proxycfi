#!/usr/bin/env python
import sys
import os
import subprocess
from eprint import eprint
import re
import copy

CONVERTER_ARGS = []

LD_ARG_REQUIRED_OPTIONS = ['-m', '-o', '-a', '-audit', '-A', '-b', '-c', '--depaudit', '-P', '-e', '--exclude-libs', '--exclude-modules-for-implib', '-f', '-F', '-G', '-h', '-l', '-L', '-O', '-R', '-T', '-dT', '-u', '-y', '-Y', '-z', '-assert', '-z', '--exclude-symbols', '--heap', '--image-base', '--major-image-version', '--major-os-version', '--major-subsystem-version', '--minor-image-version', '--minor-os-version', '--minor-subsystem-version', '--output-def', '--out-implib', '--dll-search-prefix', '--stack', '--subsystem', '--bank-window', '--got']

# implement enum for python adapted from: 
# http://pythoncentral.io/how-to-implement-an-enum-in-python/
def enum(**named_values):
    return type('Enum', (), named_values)

class FakeObjectFile:
    def __init__(self, path):
        assert path.endswith('.fake.o')
        self.path = path # could be absolute or relative to current directory
        self.construct_from_file(path)

        if self.has_missing_dep:
            pass
            # try to find it now TODO

    def fname_stem(self):
        fname = self.path
        if '/' in self.path:
            fname = self.path[fname.rfind('/') + 1:]
        return basename(fname, '.fake.o')

    def construct_from_file(self, path):
        """Extracts info from fake object file

        initializes...
            self.src_directory 
            self.has_missing_dep
            self.deps
            self.as_spec 
            self.as_spec_no_io"""
        self.has_missing_dep = False
        self.as_spec_no_io = ''
        with open(path, 'r') as fake_obj:
            elf_signature = '\x7FELF' # TODO verify #<deff> instead
            if fake_obj.read(4) == elf_signature:
                fake_obj.seek(0)
                raise NonDeferredObjectFile()
            fake_obj.seek(0)

            reading_typeinfo = False
            for line in fake_obj:
                if line == '#<deff>\n':
                    continue
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
                elif command == 'as_spec_no_io':
                    self.as_spec_no_io = words[2:]
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
    def __init__(self, path):
        self.path = path
        self.fake_objs = []
        self.thin = False

    def is_thin(self):
        return subprocess.check_output(['head', '-1', self.path]) == '!<thin>'

class Linker:
    def __init__(self, spec):
        self.spec = spec
        self.lib_search_dirs = self.gen_lib_search_dirs()
        self.entry_type = enum(OBJECT='object', ARCHIVE='archive', OMIT='omit',
                SHARED_LIB='shared_lib', NORMAL='normal',
                LIBSTEM='libstem') # libstem is '-lm' or the 'm' in '-l m'

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
        self.entry_types = [] # types of spec words

        # indices that shouldn't be included in cdi spec
        self.bad_spec_indices = [] 
        

        prev = ''
        for i, word in enumerate(self.spec):
            if word[:2] == '-l' and word != '-l':
                prev = '-l'
                word = word[2:]
            if prev == '-l': 
                try:
                    lib_path = self.find_lib(word)

                    # don't allow duplicate archives/shared-libs
                    if (lib_path in self.archive_paths
                            or lib_path in self.shared_lib_paths):
                        self.entry_types.append(self.entry_type.OMIT)
                    else:
                        self.entry_types.append(self.entry_type.LIBSTEM)
                        if lib_path[-2:] == '.a':
                            self.archive_paths.append(lib_path)
                        else:
                            self.shared_lib_paths.append(lib_path)
                except Linker.NoMatchingLibrary as err:
                    eprint('cdi-ld: error: no matching library for -l{}'.format(
                        err.libstem))
                    sys.exit(1)
            elif word[0] != '-' and prev not in LD_ARG_REQUIRED_OPTIONS:
                # three valid possibilities: object file, shared lib, archive
                record = None
                entry_type = None
                with open(word, 'rb') as mystery_file:
                    discriminator = mystery_file.read(7) # TODO handle exception
                    if discriminator[:len('\x7FELF')] == '\x7FELF':
                        # use elf header to find type of elf file
                        mystery_file.seek(16)
                        e_type = mystery_file.read(1)
                        if e_type == '\x00': # no type
                            assert False # TODO: error message
                        elif e_type == '\x01': # relocatable
                            entry_type = self.entry_type.OBJECT
                            record = self.obj_fnames
                        elif e_type == '\x02': # executable
                            assert False # TODO: error message
                        elif e_type == '\x03': # shared object file
                            entry_type = self.entry_type.SHARED_LIB
                            record = self.shared_lib_paths
                        elif e_type == '\x04': # core file
                            assert False # TODO: error message
                        else:
                            print repr(e_type)
                            assert False # TODO: error message
                    elif discriminator == '!<arch>':
                        entry_type = self.entry_type.ARCHIVE
                        record = self.archive_paths
                    elif discriminator == '#<deff>':
                        entry_type = self.entry_type.OBJECT
                        record = self.obj_fnames
                    else:
                        print mystery_file.name
                        assert False # TODO error message (not obj, lib, arch)

                self.entry_types.append(entry_type)
                if (entry_type == self.entry_type.ARCHIVE 
                        or entry_type == self.entry_type.SHARED_LIB):
                    lib_path = os.path.realpath(word)
                    if (lib_path in self.archive_paths
                            or lib_path in self.shared_lib_paths):
                        self.entry_types[-1] = self.entry_type.OMIT
                    elif os.path.isfile(lib_path):
                        record.append(lib_path)
                    else:
                        eprint("cdi-ld: error: library file doesn't exist: '{}'"
                                .format(lib_path))
                        sys.exit(1)
                elif entry_type == self.entry_type.OBJECT:
                    # TODO: handle crt1.o properly
                    if (trim_path(word) == 'crt1.o' 
                            or trim_path(word) == 'crti.o'
                            or trim_path(word) == 'crtbegin.o'
                            or trim_path(word) == 'crtend.o'
                            or trim_path(word) == 'crtn.o'):
                        self.entry_types[-1] = self.entry_type.NORMAL
                    else:
                        record.append(word)
            elif word == '-l':
                self.entry_types.append(self.entry_type.OMIT)
            else:
                self.entry_types.append(self.entry_type.NORMAL)
            prev = word
        assert len(self.spec) == len(self.entry_types)

    def get_cdi_spec(self, required_objs):
        """Returns CDI-compliant spec given dict: <archive name -> objs to use>"""
        if required_objs == None:
            required_objs = dict()

        cdi_abort_added = False
        cdi_spec = []
        for i, word in enumerate(self.spec):
            is_libstem_archive = False
            if self.entry_types[i] == self.entry_type.LIBSTEM:
                if word[:2] == '-l':
                    word = word[2:]
                lib_path = self.find_lib(word)
                if lib_path[-2:] == '.a':
                    is_libstem_archive = True
                    word = lib_path
                else:
                    cdi_spec.append(lib_path)
                    continue

            if self.entry_types[i] == self.entry_type.OBJECT:
                # add cdi_abort.cdi.o with the other object files
                # it's possible we could put this at the beginning or end
                # but it's less likely to cause an error here
                if not cdi_abort_added:
                    cdi_spec.append('/usr/local/cdi/cdi_abort.cdi.o')
                    cdi_abort_added = True
                cdi_spec.append(basename(word, '.o') + '.cdi.o')
            elif self.entry_types[i] == self.entry_type.ARCHIVE or is_libstem_archive:
                try:
                    qualified_obj_fnames = []
                    for obj_fname in required_objs[os.path.realpath(word)]:

                        # ld will need the CDI "fake" object file, which is extracted
                        # into .cdi in the compilation directory. The object files 
                        # are extracted into .cdi so that they do not conflict with
                        # any files in the compilation directory. Furthermore,
                        # the extracted object files are prefixed with the archive
                        # from which they came so that there aren't naming collisions
                        qualified_obj_fname = ('.cdi/' + trim_path(word) 
                                + '__' + basename(obj_fname, '') + '.cdi.o')
                        qualified_obj_fnames.append(qualified_obj_fname)
                    cdi_spec += qualified_obj_fnames
                except KeyError:
                    pass # it is a possible an archive has no useful objects
            elif self.entry_types[i] == self.entry_type.SHARED_LIB:
                cdi_spec.append(word)
                pass # maybe do superficial test to see if shared lib is CDI
            elif self.entry_types[i] == self.entry_type.NORMAL:
                cdi_spec.append(word)
        return cdi_spec

    def link(self, spec):
        try:
            subprocess.check_call(['ld'] + spec)
        except subprocess.CalledProcessError:
            eprint("\ncdi-ld: calling 'ld' with the following spec failed:\n\n{}"
                    .format(' '.join(spec)))

    def gen_lib_search_dirs(self):
        # first find directories in which libraries are searched for
        builtin_search_dirs = subprocess.check_output(
                '''$(which ld) --verbose | grep SEARCH_DIR | tr -s ' ;' '''
                ''' '\\n' | sed 's/^[^"]*"//g' | sed 's/".*$//g' ''', shell=True).split()
        added_search_dirs = []
        prev = ''
        for word in self.spec:
            if word[:2] == '-L' and len(word) > 2:
                added_search_dirs.append(os.path.realpath(word[2:]))
            elif prev == '--library-path' or prev == '-L':
                added_search_dirs.append(os.path.realpath(word))
            prev = word

        # note the order: -L/--library-path directories are favored
        return added_search_dirs + builtin_search_dirs 

    def find_lib(self, libstem):
        if libstem[:2] == '-l':
            libstem = libstem[2:]
        for directory in self.lib_search_dirs:
            candidate_stem = '{}/lib{}'.format(directory, libstem)
            if os.path.isfile(candidate_stem + '.so'):
                return os.path.realpath(candidate_stem + '.so')
            elif os.path.isfile(candidate_stem + '.a'):
                return os.path.realpath(candidate_stem + '.a')
        else:
            raise Linker.NoMatchingLibrary(libstem)

    class NoMatchingLibrary(Exception):
        def __init__(self, libstem):
            self.libstem = libstem


def required_archive_objs(verbose_output, cdi_archives):
    """Given output from --verbose, returns dict {archive path -> objs needed}"""
    objs_needed = dict()
    print verbose_output
    
    # matching strings in the form '(libname.a)obj_name.o'
    # characters are allowed after '.o' since some build systems do it
    matcher = re.compile(r'^\([^()\s]+\.a\)[^()\s]+\.o[^()\s]*$')

    for line in verbose_output.split('\n'):
        if matcher.match(line):
            print 'MATCHING LINE: ' + line
            end_paren_idx = line.find(')')
            archive_path = ''
            rel_archive_path = line[1:end_paren_idx]
            try:
                if rel_archive_path[:len('.cdi/')] == '.cdi/':
                    archive_path = cdi_archives[rel_archive_path[len('.cdi/'):]]
                else:
                    archive_path = os.path.realpath(line[1:end_paren_idx])
            except IndexError:
                archive_path = os.path.realpath(line[1:end_paren_idx])

            print archive_path
            obj_fname = line[end_paren_idx + 1:]
            try:
                objs_needed[archive_path].append(obj_fname)
            except KeyError:
                objs_needed[archive_path] = [obj_fname]
    return objs_needed

def get_archive_fake_objs(archive, objs_needed):
    try:
        os.chdir('.cdi')
    except OSError:
        subprocess.check_call(['mkdir', '.cdi'])
        os.chdir('.cdi')

    fake_objs = []
    if archive.is_thin() and archive.path in objs_needed.keys():
        for fname in objs_needed[archive.path]:
            corrected_fname = basename(fname, '.') + '.fake.o'
            subprocess.check_call(['cp', basename(archive.path, '/')
                + '/' + fname, corrected_fname])
            fake_objs.append(FakeObjectFile(corrected_fname))
    elif archive.path in objs_needed.keys():
        obj_fnames = objs_needed[archive.path]
        conflict_list = []
        try:
            print "obj fnames: " + str(obj_fnames)
            subprocess.check_call(['ar', 'x', archive.path] + obj_fnames)
        except subprocess.CalledProcessError:
            eprint("cdi-ld: error: cannot extract '{}' from non-thin "
                    "archive '{}'"
                    .format( "' '".join(obj_fnames), archive.path))
            sys.exit(1)

        os.chdir('..')
        for fname in obj_fnames:
            qualified_fname = '{}__{}'.format(trim_path(archive.path), fname)
            if not qualified_fname.endswith('.fake.o'):
                qualified_fname = basename(qualified_fname, '') + '.fake.o'
            print ' '
            print qualified_fname
            print ' '
            subprocess.check_call(['mv', '.cdi/' + fname, '.cdi/' + qualified_fname])
            fake_objs.append(FakeObjectFile('.cdi/' + qualified_fname))
    return fake_objs

def basename(string, cutoff):
    if cutoff == '':
        return string[:string.rfind('.')]
    return string[:string.rfind(cutoff)]

def trim_path(path):
    """Removes excess path e.g. /usr/local/bin/filename -> filename"""
    slash_index = path.rfind('/') 
    if slash_index == -1:
        return path
    elif slash_index == len(path) - 1:
        slash_index = path[:-1].rfind('/')
    return path[slash_index + 1:]

class NonDeferredObjectFile(Exception):
    pass
    
########################################################################
# cdi-ld: a cdi wrapper for the gnu linker 'ld'
#   Identifies necessary fake object files in archives, converts fake object
#   files to real, cdi-compliant object files, and runs the gnu linker on them
#
########################################################################

ld_spec = sys.argv[1:]
print ' '.join(ld_spec)

linker = Linker(ld_spec)
linker.parse_spec()

archives = []
for path in linker.archive_paths:
    archives.append(Archive(path))

# the fake object files directly listed in the ld spec
explicit_fake_objs = []
for fname in linker.obj_fnames:
    cdi_obj_name = basename(fname, '.') + '.fake.o'
    subprocess.check_call(['mv', fname, cdi_obj_name])
    try:
        explicit_fake_objs.append(FakeObjectFile(cdi_obj_name))
    except NonDeferredObjectFile:
        eprint("cdi-ld: error: '{}' is not a deferred object file"
                .format(fname))
        sys.exit(1)

# only the needed object files are included from a given archive. Hence, we must
# check which of the objects are needed for every archive. Instead of coding this
# ourselves, we instead use the existing gcc infastructure to find the needed
# object files: the linker spits out which object files are needed with the 
# --verbose flag. To get this output, however, we need to compile the code
# without CDI. The linker needs object files and we simply don't have the CDI
# object files ready

archive_fake_objs = []
unsafe_archives = []
if archives != []:
    print 'Compiling normally to learn which objects are needed for archives...'
    print '   Generating non-archive object files...'
    sys.stdout.flush()

    for fake_obj in explicit_fake_objs:
        subprocess.call(['as', fake_obj.path, '-o', 
            fake_obj.path[:-1 * len('.fake.o')] + '.o'] + fake_obj.as_spec_no_io)

    print '   Generating objects from archives...'
    sys.stdout.flush()


    # stale files in .cdi can cause trouble
    subprocess.check_call(['rm', '-rf', '.cdi'])
    subprocess.check_call(['mkdir', '.cdi'])

    # we need to create non-cdi archives (see above). Therefore we need
    # to remember the association between the non-cdi archives and the cdi-archives
    # so that we can conclude which objects are needed for each cdi-archive
    cdi_archives = dict() # mapping [non-cdi archive path -> cdi archive path]

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
                correct_fname = basename(fname, '.') + '.fake.o'
                subprocess.check_call(['mv', fname, correct_fname])
                subprocess.check_call(['as', correct_fname, '-o', fname])


        # TODO handle case where two archives have the same path but diff names
        assert trim_path(archive.path) not in cdi_archives
        cdi_archives[trim_path(archive.path)] = archive.path

        subprocess.check_call(['ar', 'rc', trim_path(archive.path)] + fnames)

    # create spec for non-cdi compilation
    ld_spec_unsafe_archives = copy.deepcopy(ld_spec)
    for i, entry in enumerate(linker.spec):
        if linker.entry_types[i] == linker.entry_type.ARCHIVE:
            ld_spec_unsafe_archives[i] = '.cdi/' + trim_path(linker.spec[i])
        elif linker.entry_types[i] == linker.entry_type.LIBSTEM:
            lib_path = linker.find_lib(entry)
            if lib_path[-2:] == '.a':
                ld_spec_unsafe_archives[i] = '.cdi/' + trim_path(lib_path)

    os.chdir('..')
    verbose_linker_output = subprocess.check_output(['ld'] 
            + ld_spec_unsafe_archives + ['--verbose'])
    outfile_next = False

    # remove executable since it is non-CDI compiled
    for word in ld_spec_unsafe_archives:
        if word == '-o':
            outfile_next = True
        elif outfile_next:
            subprocess.check_call(['rm', word])
            break

    objs_needed = required_archive_objs(verbose_linker_output, cdi_archives)
    print str(objs_needed)
    
    # construct fake objects from archives
    if objs_needed:
        for archive_path in objs_needed.keys(): 
            try:
                archive_fake_objs += get_archive_fake_objs(Archive(archive_path),
                    objs_needed)
            except NonDeferredObjectFile:
                print ("Unable to find objects needed from archive '{}'."
                        " This archive will remain non-CDI".format(archive_path))
                unsafe_archives.append(Archive(archive_path))


fake_objs = explicit_fake_objs + archive_fake_objs

print 'Converting asm files to cdi-asm files...'
sys.stdout.flush()

cdi_ld_real_path = subprocess.check_output(['readlink', '-f', sys.argv[0]])
cdi_ld_real_path = basename(cdi_ld_real_path, '/')
converter_path = cdi_ld_real_path + '/../converter/gen_cdi.py'
fake_obj_paths = [fake_obj.path for fake_obj in fake_objs]
print 'fake obj paths: ' + ' '.join(fake_obj_paths)
subprocess.check_call([converter_path] + CONVERTER_ARGS + fake_obj_paths)

print 'Assembling cdi asm files...'
sys.stdout.flush()

for fake_obj in fake_objs:
    print ' '.join(['as'] + fake_obj.as_spec_no_io
            + [basename(fake_obj.path, '.fake.o') + '.cdi.s',
                '-o', basename(fake_obj.path, '.fake.o') + '.cdi.o'])
    subprocess.check_call(['as'] + fake_obj.as_spec_no_io
            + [basename(fake_obj.path, '.fake.o') + '.cdi.s',
                '-o', basename(fake_obj.path, '.fake.o') + '.cdi.o'])

# the fake objs need to be moved back to their original filename in case
# another compilation wants to use them as well. This code ASSUMES that
# linker.obj_fnames and explicit_fake_objs correspond index to index
for i, fake_obj in enumerate(explicit_fake_objs):
    subprocess.check_call(['mv', fake_obj.path, linker.obj_fnames[i]])

print 'Linking...'
sys.stdout.flush()
cdi_spec = linker.get_cdi_spec(objs_needed)
linker.link(cdi_spec)

