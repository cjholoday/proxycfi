#!/usr/bin/env python
import sys
import os
import subprocess
from eprint import eprint
import re
import copy
import fcntl

ld_spec = sys.argv[1:]

restore_original_objects_fptr = None
def fatal_error(message):
    eprint('\n----------------------------------------------\n'
            'cdi-ld: error: {}'.format(message))
    eprint('\nSpec passed to cdi-ld.py: {}'.format(' '.join(ld_spec)))
    if restore_original_objects_fptr:
        restore_original_objects_fptr()
    sys.exit(1)
 

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
                    eprint("\ncdi-ld: warning: invalid command '{}' in "
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
                SHARED_LIB='shared_lib', NORMAL='normal', DUPLICATE='duplicate')

        # available options:
        #   --spec : Print out the spec as passed to cdi-ld.py. Do not finish compilation
        #   --abandon-cdi : Produce a non-CDI executable. This is useful for
        #                   creating non-CDI code with CDI archives
        self.cdi_options = []
        self.cdi_test = ''

        self.target = ''
        self.is_building_shared_lib = False

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
                        self.entry_types.append(self.entry_type.DUPLICATE)
                        self.spec[i] = '-g'
                    else:
                        print lib_path, self.spec[i]
                        self.spec[i] = lib_path
                        if lib_path[-2:] == '.a':
                            self.entry_types.append(self.entry_type.ARCHIVE)
                            self.archive_paths.append(lib_path)
                        else:
                            self.entry_types.append(self.entry_type.SHARED_LIB)
                            self.shared_lib_paths.append(lib_path)
                except Linker.NoMatchingLibrary as err:
                    fatal_error('no matching library for -l{}'.format(err.libstem))
            elif prev == '-o':
                self.target = word
                self.entry_types.append(self.entry_type.NORMAL)
            elif word == '-shared':
                self.is_building_shared_lib = True
                self.entry_types.append(self.entry_type.NORMAL)
            elif word.startswith('--cdi-options='):
                self.cdi_options = word[len('--cdi-options='):].split(' ')
                if '--spec' in self.cdi_options:
                    print ' '.join(ld_spec)
                    sys.exit(0)

                # set this entry in the spec so that ld will work when 
                # the spec is used to compile without CDI. -g is ignored by
                # ld so this effectively deletes this entry
                self.spec[i] = '-g'
                self.entry_types.append(self.entry_type.OMIT)
            elif word.startswith('--cdi-test='):
                self.cdi_test = word[len('--cdi-test='):]
                self.spec[i] = '-g'
                self.entry_types.append(self.entry_type.OMIT)
            elif word[0] != '-' and prev not in LD_ARG_REQUIRED_OPTIONS:
                # three valid possibilities: object file, shared lib, archive
                record = None
                entry_type = None
                try:
                    mystery_file = open(word, 'rb')
                except IOError:
                    fatal_error("non existent file '{}' passed to linker"
                            .format(word))

                discriminator = mystery_file.read(7) # TODO handle exception
                if discriminator.startswith('\x7FELF'):
                    # use elf header to find type of elf file
                    mystery_file.seek(16)
                    e_type = mystery_file.read(1)
                    if e_type == '\x00': # no type
                        fatal_error('linker passed elf file with e_type=NULL')
                    elif e_type == '\x01': # relocatable
                        entry_type = self.entry_type.OBJECT
                        record = self.obj_fnames
                    elif e_type == '\x02': # executable
                        fatal_error('executable passed to linker')
                    elif e_type == '\x03': # shared object file
                        entry_type = self.entry_type.SHARED_LIB
                        record = self.shared_lib_paths
                    elif e_type == '\x04': # core file
                        fatal_error('core file passed to linker')
                    else:
                        fatal_error("linker passed elf file with undefined"
                                " e_type: {}".format(repr(e_type)))
                elif discriminator == '!<arch>':
                    entry_type = self.entry_type.ARCHIVE
                    record = self.archive_paths
                elif discriminator == '#<deff>':
                    entry_type = self.entry_type.OBJECT
                    record = self.obj_fnames
                else:
                    entry_type = self.entry_type.NORMAL
                    eprint("cdi-ld: warning: unknown file type passed to "
                            "linker. It will be treated as a linker script:"
                            " '{}'".format(mystery_file.name))
                mystery_file.close()

                self.entry_types.append(entry_type)
                if (entry_type == self.entry_type.ARCHIVE 
                        or entry_type == self.entry_type.SHARED_LIB):
                    lib_path = os.path.realpath(word)
                    if (lib_path in self.archive_paths
                            or lib_path in self.shared_lib_paths):
                        self.entry_types[-1] = self.entry_type.DUPLICATE
                        self.spec[i] = '-g'
                    elif os.path.isfile(lib_path):
                        record.append(lib_path)
                    else:
                        fatal_error("library file doesn't exist: '{}'"
                                .format(lib_path))
                elif entry_type == self.entry_type.OBJECT:
                    # TODO: handle these objects properly
                    if (trim_path(word) == 'crt1.o' 
                            or trim_path(word) == 'crti.o'
                            or trim_path(word) == 'crtbegin.o'
                            or trim_path(word) == 'crtend.o'
                            or trim_path(word) == 'crtn.o'
                            or trim_path(word) == 'crtbeginS.o'
                            or trim_path(word) == 'crtendS.o'):
                        self.entry_types[-1] = self.entry_type.NORMAL
                    else:
                        record.append(word)
            elif word == '-l':
                self.spec[i] = '-g'
                self.entry_types.append(self.entry_type.OMIT)
            else:
                self.entry_types.append(self.entry_type.NORMAL)
            prev = word
        assert len(self.spec) == len(self.entry_types)
        if self.target == '':
            self.target = 'a.out'

    def get_cdi_spec(self, required_objs):
        """Returns CDI-compliant spec given dict: <archive name -> objs to use>"""
        if required_objs == None:
            required_objs = dict()

        cdi_abort_added = False
        cdi_spec = []
        for i, word in enumerate(self.spec):
            if self.entry_types[i] == self.entry_type.OBJECT:
                # add cdi_abort.cdi.o with the other object files
                # it's possible we could put this at the beginning or end
                # of the spec but it's less likely to cause an error here
                if not cdi_abort_added:
                    if not self.is_building_shared_lib:
                        cdi_spec.append('/usr/local/cdi/cdi_abort.cdi.o')
                    cdi_abort_added = True
                cdi_spec.append(basename(word, '') + '.cdi.o')
            elif self.entry_types[i] == self.entry_type.ARCHIVE:
                try:
                    qualified_obj_fnames = []
                    for obj_fname in required_objs[os.path.realpath(word)]:

                        # ld will need the CDI "fake" object file, which is extracted
                        # into .cdi in the compilation directory. The object files 
                        # are extracted into .cdi so that they do not conflict with
                        # any files in the compilation directory. Furthermore,
                        # the extracted object files are prefixed with the archive
                        # from which they came so that there aren't naming collisions
                        # among the archive objects
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
            fatal_error("calling 'ld' with the following spec failed:\n\n{}"
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
    
    # matching strings in the form '(libname.a)obj_name.o'
    # characters are allowed after '.o' since some build systems do it
    matcher = re.compile(r'^\([^()\s]+\.a\)[^()\s]+\.o[^()\s]*$')

    for line in verbose_output.split('\n'):
        if matcher.match(line):
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
        try:
            subprocess.check_call(['ar', 'x', archive.path] + obj_fnames)
        except subprocess.CalledProcessError:
            fatal_error("cannot extract '{}' from non-thin archive '{}'"
                    .format( "' '".join(obj_fnames), archive.path))

        os.chdir('..')
        for fname in obj_fnames:
            qualified_fname = '{}__{}'.format(trim_path(archive.path), fname)
            if not qualified_fname.endswith('.fake.o'):
                qualified_fname = basename(qualified_fname, '') + '.fake.o'
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



def get_script_dir():
    return os.path.dirname(os.path.realpath(__file__))

def shared_lib_load_addrs(linker):
    """Get pairs of (shared lib path, load address). 

    There must be an ELF executable CDI or otherwise already generated. Since
    a non-CDI executable is generated for archive analysis, this is always the
    case
    """
    lib_addr_pairs = []
    traced_output = subprocess.check_output(['./' + linker.target], 
            env=dict(os.environ, **{'LD_TRACE_LOADED_OBJECTS':'1'}))
    for line in traced_output.splitlines():
        # format of trace output: [symlink path] => [actual elf path] ([load addr])
        symlink = line.split()[0]
        path = ''
        if len(line.split()) == 2:
            # in this case the format is [actual elf path] ([load addr])
            path = symlink
        else:
            path = line.split()[2]

        if symlink.startswith('linux-vdso.so'):
            # linux-vdso is injected into each process by the kernel, so we 
            # must ignore it. Admittedly, if a user names their shared library
            # linux-vdso.so then it won't be handled by cdi-ld.py. However, 
            # they really do deserve to get burned for their naming abuse
            continue
        addr = int(line.split()[-1].lstrip('(').rstrip(')'), 16)
        lib_addr_pairs.append((path, addr))
    return lib_addr_pairs
    
def has_symbol_table(elf_path):
    """Returns true if the elf executable at elf_path has a ".symtab" section"""

    section_info = subprocess.check_output(['readelf', '-S', elf_path])
    symtab_matcher = re.compile(r'\s*\[[\s0-9]*\] .symtab\s*SYMTAB')
    for line in section_info.splitlines():
        if symtab_matcher.match(line):
            return True
    else:
        return False

def sl_linker_name(shared_lib_path):
    """ /path/to/libshared_lib.so.1.0.0 -> libshared_lib.so """
    trimmed_name = trim_path(shared_lib_path)
    while not trimmed_name.endswith('.so'):
        trimmed_name = trimmed_name[:-1]
    return trimmed_name
    
def sl_find_unstripped(binary_path):
    if has_symbol_table(binary_path):
        return binary_path

    candidate_path = '/usr/local/lib/' + sl_linker_name(binary_path)
    print candidate_path
    if os.path.isfile(candidate_path) and has_symbol_table(candidate_path):
        return candidate_path

    for root, dirs, files in os.walk('/usr/lib/debug', topdown=True):
        sl_trimmed_realpath = trim_path(os.path.realpath(binary_path))
        if sl_trimmed_realpath in files:
            return os.path.join(root, sl_trimmed_realpath)
    else:
        fatal_error("cannot find unstripped version of shared library '{}'"
                ". Either compile it with CDI or install an unstripped"
                " version".format(os.path.realpath(binary_path)))

find_fptrs_script = get_script_dir() + '/../verifier/find_fptrs.py'
def sl_get_fptr_addrs(binary_path, symbol_ref, lib_load_addr):
    cached_analysis_path = (get_script_dir() 
            + '/../cdi-gcc/cached_fptr_analysis/' 
            + trim_path(os.path.realpath(binary_path)))

    fptr_analysis = []
    # either use cached analysis or create a new analysis and cache it
    if (os.path.isfile(cached_analysis_path)
            and os.path.getmtime(cached_analysis_path) >= os.path.getmtime(binary_path)
            and os.path.getmtime(cached_analysis_path) >= os.path.getmtime(symbol_ref)):
        with open(cached_analysis_path, 'r') as cached_analysis:
            fptr_analysis = cached_analysis.readlines()
    else:
        try:
            fptr_analysis = subprocess.check_output([find_fptrs_script, binary_path,
                symbol_ref]).strip()
            print fptr_analysis
        except subprocess.CalledProcessError as err:
            fatal_error("couldn't analyze '{}' for fptrs despite "
                    "having an associated symbol table (.symtab) in file '{}'"
                    .format(sl_path, symbol_binary_path))
        try:
            with open(cached_analysis_path, 'w') as cached_analysis:
                cached_analysis.write(fptr_analysis)
        except IOError:
            eprint("cdi-ld: warning: failed to cache fptr analysis for "
                    "shared library '{}'".format(trim_path(sl_realpath)))
        fptr_analysis = fptr_analysis.splitlines()

    fptr_addrs = []
    for line in fptr_analysis:
        fptr_lib_offset = int(line.split()[0], 16)
        fptr_addr = hex(lib_load_addr + fptr_lib_offset)
        fptr_addrs.append(fptr_addr)

    return fptr_addrs


########################################################################
# cdi-ld: a cdi wrapper for the gnu linker 'ld'
#   Identifies necessary fake object files in archives, converts fake object
#   files to real, cdi-compliant object files, and runs the gnu linker on them
#
########################################################################

linker = Linker(ld_spec)
linker.parse_spec()

converter_options = []
if linker.cdi_test:
    converter_options += ['--test', linker.cdi_test]



archives = []
for path in linker.archive_paths:
    archives.append(Archive(path))

# the fake object files directly listed in the ld spec
explicit_fake_objs = []
for fname in linker.obj_fnames:
    cdi_obj_name = basename(fname, '.') + '.fake.o'
    subprocess.check_call(['mv', fname, cdi_obj_name])

# the fake objs will need to be moved back to their original filename in case
# another compilation wants to use them as well. This code ASSUMES that
# linker.obj_fnames and explicit_fake_objs correspond index to index
#
# This is called on error or at the end of cdi-ld
def restore_original_objects():
    for i, fake_obj in enumerate(explicit_fake_objs):
        subprocess.check_call(['mv', fake_obj.path, linker.obj_fnames[i]])

# used by fatal_error()
restore_original_objects_fptr = restore_original_objects


# All fake objects must be constructed after the filenames are moved
# Otherwise fatal_error cannot restore them on error in this brief window
for fname in linker.obj_fnames:
    try:
        cdi_obj_name = basename(fname, '.') + '.fake.o'
        explicit_fake_objs.append(FakeObjectFile(cdi_obj_name))
    except NonDeferredObjectFile:
        fatal_error("'{}' is not a deferred object file".format(fname))

# create unsafe, non-cdi shared libraries. CDI shared libraries are for a 
# future version
if linker.is_building_shared_lib:
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
                correct_fname = basename(fname, '.') + '.fake.o'
                subprocess.check_call(['mv', fname, correct_fname])
                subprocess.check_call(['as', correct_fname, '-o', fname])

        subprocess.check_call(['ar', 'rc', trim_path(archive.path)] + fnames)

    # create spec for non-cdi compilation
    ld_spec_unsafe_archives = copy.deepcopy(ld_spec)
    for i, entry in enumerate(linker.spec):
        if linker.entry_types[i] == linker.entry_type.ARCHIVE:
            ld_spec_unsafe_archives[i] = '.cdi/' + trim_path(linker.spec[i])

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
archive_fake_objs = []
unsafe_archives = []
objs_needed = dict()
if archives != []:
    print 'Compiling normally to learn which objects are needed for archives...'
    print '   Generating non-archive object files...'
    sys.stdout.flush()

    # assemble non-cdi object files. Note that the object name must be the same
    # as the object filename that was passed into cdi-ld.py
    for i, fake_obj in enumerate(explicit_fake_objs):
        subprocess.call(['as', fake_obj.path, '-o',
            linker.obj_fnames[i]] + fake_obj.as_spec_no_io)

    print '   Finding needed objects from archives: '
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

    os.chdir('..')
    ld_command = ['ld'] + ld_spec_unsafe_archives + ['--verbose']
    try:
        verbose_linker_output = subprocess.check_output(ld_command)
    except subprocess.CalledProcessError:
        fatal_error("Unable to compile without CDI using linker command '{}'"
                .format(' '.join(ld_command)))
    outfile_next = False

    if '--abandon-cdi' in linker.cdi_options:
        print 'WARNING: CREATING NON CDI EXECUTABLE AS REQUESTED'
        sys.exit(0)

    # TODO always create a non-CDI executable not just when there are archives
    #
    # For now, this code will always run since there is always an archive
    # listed in the spec. This may not always be the case?

    # check that ASLR is disabled
    traced_output1 = subprocess.check_output(['./' + linker.target], 
            env=dict(os.environ, **{'LD_TRACE_LOADED_OBJECTS':'1'}))
    traced_output2 = subprocess.check_output(['./' + linker.target], 
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

    # the shared library paths from shared_lib_load_addrs() are more precise 
    # than the shared libs passed to the linker as options. The ones passed as
    # options are occasionally linker scripts, which complicates analysis since
    # we would have to parse through the scripts. Even then, we wouldn't be sure
    # what is used in the end. shared_lib_load_addrs() instead asks the non-CDI
    # executable what shared libraries are used, which makes the GNU linker do
    # the work for us

    fptr_addrs = []
    for sl_path, lib_load_addr in shared_lib_load_addrs(linker):
        eprint("cdi-ld: warning: linking with non-CDI shared library '{}'"
                .format(sl_path))

        # if it's in /usr/local/lib, then the reference contains code in addition
        # to the symbol table. Therefore, it's unassociated with the shared
        # library in the spec. Use this new binary instead
        # FIXME: replace spec args
        symbol_reference = sl_find_unstripped(sl_path)
        if symbol_reference.startswith('/usr/local/lib/'):
            sl_path = symbol_reference
        fptr_addrs += sl_get_fptr_addrs(sl_path, symbol_reference, lib_load_addr)

    # remove executable since it isn't CDI compiled
    subprocess.check_call(['rm', linker.target])

    objs_needed = required_archive_objs(verbose_linker_output, cdi_archives)

    # for code visibility, print all objects that are needed from archives
    for archive_path in objs_needed.keys():
        print '        {} - {}'.format(archive_path, ' '.join(objs_needed[archive_path]))
    
    # construct fake objects from archives
    for archive_path in objs_needed.keys(): 
        try:
            archive_fake_objs += get_archive_fake_objs(Archive(archive_path),
                objs_needed)
        except NonDeferredObjectFile:
            print ("        Unable to find objects from archive '{}'."
                    " It will remain non-CDI".format(archive_path))
            unsafe_archives.append(Archive(archive_path))


fake_objs = explicit_fake_objs + archive_fake_objs

sys.stdout.flush()

cdi_ld_real_path = subprocess.check_output(['readlink', '-f', sys.argv[0]])
cdi_ld_real_path = basename(cdi_ld_real_path, '/')
converter_path = cdi_ld_real_path + '/../converter/gen_cdi.py'
fake_obj_paths = [fake_obj.path for fake_obj in fake_objs]
if linker.is_building_shared_lib: 
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
    cdi_asm_fname = basename(fake_obj.path, '.fake.o') + '.cdi.s'
    cdi_obj_fname = basename(fake_obj.path, '.fake.o') + '.cdi.o'
    gcc_as_command = (['as'] + fake_obj.as_spec_no_io + 
            [cdi_asm_fname, '-o', cdi_obj_fname])
    try:
        subprocess.check_call(gcc_as_command)
    except subprocess.CalledProcessError:
        fatal_error("assembling '{}' failed with command '{}'".format(
            cdi_asm_fname, ' '.join(gcc_as_command)))

target_type = ''
if linker.is_building_shared_lib:
    target_type = 'shared library'
else:
    target_type = 'executable'

print "Linking {} '{}'\n".format(target_type, linker.target)

sys.stdout.flush()
cdi_spec = linker.get_cdi_spec(objs_needed)
linker.link(cdi_spec)

restore_original_objects()

