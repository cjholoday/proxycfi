import types
import jsonpickle

class FunctControlFlowGraph:
    """A CFG class with functions as vertices instead of basic blocks

    Function are accessed by their "uniq_label" which is in the form:

        <source filename>.<assembly function name>

    Notice that in C the assembly function name is simply the source name, while
    in C++ it is the source function name but mangled
    """

    def __init__(self):
        # don't touch this attribute; it's internal
        self._funct_vertices = dict()

    def add_funct(self, funct):
        uniq_label = funct.asm_filename + '.' + funct.asm_name
        self._funct_vertices[uniq_label] = funct

    def funct(self, uniq_label):
        return self._funct_vertices[uniq_label]

    def __iter__(self):
        return iter(FunctControlFlowGraphIterator(self))

    def __contains__(self, funct):
        return funct in self._funct_vertices.values()

    def print_json_to(self, filename):
        with open(filename, 'w') as cfg_file:
            encoding = jsonpickle.encode(self)
            cfg_file.write(encoding)

class FunctControlFlowGraphIterator:
    def __init__(self, cfg):
        self.cfg_iter = iter(cfg._funct_vertices.values())

    def __iter__(self):
        return self

    def next(self):
        return self.cfg_iter.next()

class Function:
    def __init__(self, asm_name, asm_filename, sites, return_dict, line_num = -1):
        self.asm_name = asm_name
        self.asm_filename = asm_filename
        self.uniq_label = asm_filename + '.' + asm_name
        self.ftype = None # function type

        self.return_dict = return_dict
        self.sites = sites
        self.asm_line_num = line_num
        self.is_global = True

class FunctionType:
    """A function signature type. May be associated with a particular function"""
    def __init__(self, mangled_str):
        self.mangled_str = mangled_str
        self.src_name = '' # optional (used for function definitions)
        self.matched = False

        # location
        self.src_filename = ''
        self.line_no = -1
        self.enclosing_funct_name = '' # optional (used for fp location)

    def __str__(self):
        if not self.src_name:
            return self.mangled_str
        after_z_index = self.mangled_str.find('_Z') + len('_Z')
        name_index = self.mangled_str.find(self.src_name, after_z_index)
        return (self.mangled_str[:after_z_index] + 
                self.mangled_str[name_index + len(self.src_name):])

    def is_local(self):
        """Returns true if signature associated with particular funct is static"""

        # must be associated with particular function
        assert self.src_name
        z_index = self.mangled_str.find('_Z')
        return self.mangled_str[z_index + len('_Z')] == 'L'

    def __eq__(self, other):
        return str(self) == str(other)

    def __ne__(self, other):
        return not __eq__(self, other)

class SledIdFaucet:
    def __init__(self):
        self.__sled_id = 0

    def __call__(self):
        self.__sled_id += 1
        return self. __sled_id

class Site:
    CALL_SITE = 0
    RETURN_SITE = 1
    INDIR_JMP_SITE = 2
    PLT_SITE = 3

    def __init__(self, line_num, targets, type_of_site):
        assert type(line_num) is types.IntType
        assert type(type_of_site) is types.IntType
        assert (type_of_site == Site.CALL_SITE or 
                type_of_site == Site.RETURN_SITE or
                type_of_site == Site.INDIR_JMP_SITE)

        self.line_num = line_num
        self.group = type_of_site
        self.targets = targets
