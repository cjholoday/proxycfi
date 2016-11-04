import sys
import os

LD_ARG_REQUIRED_OPTIONS = ['m', '-o', '-a', '-audit', '-A', '-b', '-c', '--depaudit', '-P', '-e', '--exclude-libs', '--exclude-modules-for-implib', '-f', '-F', '-G', '-h', '-l', '-L', '-O', '-R', '-T', '-dT', '-u', '-y', '-Y', '-z', '-assert', '-z', '--exclude-symbols', '--heap', '--image-base', '--major-image-version', '--major-os-version', '--major-subsystem-version', '--minor-image-version', '--minor-os-version', '--minor-subsystem-version', '--output-def', '--out-implib', '--dll-search-prefix', '--stack', '--subsystem', '--bank-window', '--got']

class FakeObjectFile:
    def __init__(self, fname):
        self.construct_from_file(fname)
        self.fname = fname

        if self.has_missing_dep:
            # try to find it now TODO

    def construct_from_file(fname):
        """Extracts info from fake object file

        initializes...
            self.src_directory 
            self.has_missing_dep
            self.deps
            self.cdi_as_spec """
        self.has_missing_dep = False
        with open(fname, 'r') as fake_obj:
            for line in fake_obj:
                if len(line) == 1:
                    continue
                line = line.split()
                command = line[1]
                if command == 'assembly':
                    break
                elif command == 'source_directory':
                    self.src_directory = line[2]
                elif command == 'dependencies':
                    self.deps = line[2:]
                elif command == 'warning' and line[2] == 'missing_dependency':
                    self.has_missing_dep = True
                elif command == 'cdi_as_spec':
                    self.cdi_as_spec = line[2:]
                else:
                    eprint("cdi-ld: warning: invalid command '{}' in "
                            " fake object '{}'".format(command, fname))


class Archive:
    def __init__(self, name):
        self.fname = name
        self.fake_objs = []
        self.thin = False


class Linker:
    def __init__(self, spec):
        self.spec = spec
        parse_spec()

    def parse_spec(self):
        """Extracts info from the spec and stores it in object variables
        
        initializes...
            self.obj_fnames 
            self.archive_names
            self.shared_lib_names
            self.archive_position (dict used for converting spec to cdi)

        The linker also remembers how to convert the spec to CDI given a dict
        mapping [archive name] -> [list of needed fake objects]"""
        pass
        
    def cdi_fixup_spec(self, required_objs):
        """Converts spec to be CDI compliant"""
        pass

    def link(self, spec_addition = None):
        """Run the GNU linker on self.spec||spec_addition """
        pass

########################################################################
# cdi-ld: a cdi wrapper for the gnu linker 'ld'
#   Identifies necessary fake object files in archives, converts fake object
#   files to real, cdi-compliant object files, and runs the gnu linker on them
#
########################################################################

linker = Linker(sys.argv[1:])
sys.exit(1)

# fake objects necessary for compilation: explicitly listed objects and those
# implicitly needed in archives
req_fake_objs = []
for fake_obj_fname in linker.obj_fnames:
    req_fake_objs.append(FakeObjectFile(fake_obj_fname))


archives = []
for archive_fname in linker.archive_fnames:
    archives.append(Archive(archive_fname))




