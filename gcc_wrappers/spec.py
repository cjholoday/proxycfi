class LinkerSpec():
    def __init__(self, raw_spec):
        self.raw_spec = raw_spec
        (self.obj_paths, self.ar_paths, self.sl_paths, self.miscs,
                self.cdi_options, self.entry_types) = decompose_raw_spec(raw_spec)

        target_is_shared = False
        target = ''

    def decompose_raw_spec(self, raw_spec):
        """Returns tuple of information associated with the raw spec
        
        Returns obj_paths, ar_paths, sl_paths, misc options, cdi_options, entry_types
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

        prev = ''
        for i, entry in enumerate(raw_spec):
            entry_type = get_entry_type(entry)
            if entry_type == 'libstem':
                if entry[:2] == '-l':
                    entry = entry[2:]
                try:
                    entry = find_lib(entry)
                except Linker.NoMatchingLibrary as err:
                    fatal_error('no matching library for -l{}'.format(err.libstem))
                if entry.endswith('.a'):
                    entry_type = 'ar'
                else:
                    entry_type = 'sl'

            entry_types.append(entry_type)
            if entry_type == 'obj':
                obj_paths.append(entry)
            elif entry_type == 'ar':
                ar_paths.append(entry)
            elif entry_type == 'sl':
                sl_paths.append(entry)
            elif entry_type == 'misc':
                self.miscs.append(entry)
                if prev == '-o':
                    self.target = entry
                elif entry == '-shared':
                    self.target_is_shared = True
            elif word.startswith('--cdi-options='):
                self.cdi_options = word[len('--cdi-options='):].split(' ')
            else:
                fatal_error("Unknown spec entry type '{}'".format(entry_type))
            prev = word
        if self.target == '':
            self.target = 'a.out'

        return obj_paths, ar_paths, sl_paths, miscs, cdi_options, entry_types

    def get_entry_type(entry, prev_entry):
        if prev_entry == '-l' or (entry[:2] == '-l' and len(entry) > 2): 
            return 'libstem'
        elif entry.startswith('--cdi-options='):
            return 'cdi_options'
        elif entry[0] != '-' and prev not in LD_ARG_REQUIRED_OPTIONS:
            # three valid possibilities: object file, shared lib, archive
            try:
                mystery_file = open(entry, 'rb')
            except IOError:
                fatal_error("non existent file '{}' passed to linker"
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
                    fatal_error("linker passed elf file '{}' with e_type=NULL"
                            .format(myster_file.name))
                elif e_type == '\x01': # relocatable
                    fatal_error("linker passed non-CDI object file '{}'"
                            .format(myster_file.name))
                elif e_type == '\x02': # executable
                    fatal_error("executable '{}' passed to linker"
                            .format(myster_file.name))
                elif e_type == '\x04': # core file
                    fatal_error("core file '{}' passed to linker"
                            .format(myster_file.name))
                else:
                    fatal_error("linker passed elf file '{}' with undefined"
                            " e_type: {}".format(mystery_file.name, repr(e_type)))

            mystery_file.close()
            if discriminator == '!<arch>':
                return 'ar'
            elif discriminator == '#<deff>':
                # TODO: handle these objects properly
                if (trim_path(word) == 'crt1.o' 
                        or trim_path(word) == 'crti.o'
                        or trim_path(word) == 'crtbegin.o'
                        or trim_path(word) == 'crtend.o'
                        or trim_path(word) == 'crtn.o'
                        or trim_path(word) == 'crtbeginS.o'
                        or trim_path(word) == 'crtendS.o'):
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
        pass

    def cdi(self, ar_objs_needed):
        """Returns a cdi-spec for given an {archive -> [objs paths needed]} dict"""
        pass

    def raw(self):
        """Returns the spec as it was passed on initialization"""
        return raw_spec

    def reconstruct_spec(self):
        objs = iter(self.obj_paths)
        ars = iter(self.ar_paths)
        sls = iter(self.sl_paths)
        miscs = iter(self.misc)

        for entry_type in entry_types:
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
                    continue
                else:
                    fatal_error("Invalid spec entry type '{}'".format(entry_type))
            except StopIteration:
                fatal_error("Constructing a new spec requires more entries "
                        "of type '{}' than were recorded".format(entry_type))







