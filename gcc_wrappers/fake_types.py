import subprocess
import os

"""
These object files and archives passed to cdi-ld.py are considered "fake"
because they do not actually contain binary code. Instead, the fake object files
are composed of assembly with notes on how to assemble. Archives contain fake
objects and are therefore also considered fake
"""


class FakeObjectFile:
    def __init__(self, path):
        assert path.endswith('.fake.o')
        self.path = path # could be absolute or relative to current directory
        self.construct_from_file(path)

    def fname_stem(self):
        fname = self.path
        if '/' in self.path:
            fname = self.path[fname.rfind('/') + 1:]
        return chop_suffix(fname, '.fake.o')

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
        self.path = os.path.realpath(path)
        self.fake_objs = []
        self.thin = False

    def is_thin(self):
        return subprocess.check_output(['head', '-1', self.path]) == '!<thin>'

class NonDeferredObjectFile(Exception):
    pass

