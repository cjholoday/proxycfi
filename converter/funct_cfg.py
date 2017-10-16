import __init__

import types
import jsonpickle
import random

from common.eprint import eprint

class FunctControlFlowGraph:
    """A CFG class with functions as vertices instead of basic blocks

    Function are accessed by their "uniq_label" which is in the form:

        <asm filename>.<assembly function name>

    Notice that in C the assembly function name is simply the source name, while
    in C++ it is the source function name but mangled
    """

    def __init__(self):
        # don't touch this attribute; it's internal
        self._funct_vertices = dict()

    def add_funct(self, funct):
        uniq_label = funct.asm_filename + '.' + funct.asm_name
        self._funct_vertices[uniq_label] = funct

    def size(self):
        """Returns the number of functions in the CFG"""
        return len(self._funct_vertices)

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

    def functs(self):
        return self._funct_vertices.values()

    def size(self):
        return len(self._funct_vertices) 

    def __contains__(self, item):
        return item in self._funct_vertices

    def print_uniq_labels(self):
        eprint("cfg unique labels:")
        for uniq_label in sorted(self._funct_vertices.keys()):
            eprint('\t' + uniq_label)


class FunctControlFlowGraphIterator:
    def __init__(self, cfg):
        self.cfg_iter = iter(cfg._funct_vertices.values())

    def __iter__(self):
        return self

    def next(self):
        return self.cfg_iter.next()

SIGNED_INT32_MIN = -1 * (1 << 31)
SIGNED_INT32_MAX = (1 << 31) - 1

class Function:
    def __init__(self, asm_name, asm_filename, src_filename, sites, asm_line_num):
        self.asm_name = asm_name
        self.uniq_label = asm_filename + '.' + asm_name
        self.sites = sites

        self.asm_filename = asm_filename
        self.asm_line_num = asm_line_num

        self.src_filename = src_filename 

        # differentiate between returns using an id. This is used to generate
        # labels at the end of each return site so that the loader can patch
        # the last jmp in the sled to go to an inter-shared-library
        # function pointer return sled
        #
        # we do the same for indirect calls
        self.num_rets = 0
        self.num_indir_calls = 0
        for site in self.sites:
            if site.group == Site.RETURN_SITE:
                site.ret_id = self.num_rets
                self.num_rets += 1
            elif site.group == Site.CALL_SITE and len(site.targets) != 1:
                site.indir_call_id = self.num_indir_calls
                self.num_indir_calls += 1

        # ALL following members are unitialized or in an inconsistent state
        # until gen_cfg() finishes
        self.ret_dict = dict()
        self.is_global = True

        # filled with FptrCall's from metadata
        self.fptr_calls = []

        # format: [return_type] || _ || [C++ mangling after fn name]
        self.ftype = None

        # filled with Site instances which are matched with FptrCall's 
        # via source line numbers.
        self.fptr_sites = []

        # Contains a mapping from a label to a pointer proxy (int32). This attribute
        # should not be used directly. Use the proxy_for function instead
        self.ptr_proxies = dict()

        # contains all proxy pointers (int32) that have been used for this function
        # this is used to prevent collisions between proxies used to return in 
        # this function. Proxies may collide with other functions' proxies
        self.ptr_proxy_set = set()

        # forbid pointer proxies with value 0
        self.ptr_proxy_set.add(0)


    def proxy_for(self, rett):
        """Returns a proxy ptr addr for returning from [this fn] -> [rett]
        
        rett should be the label at which execution will resume on return

        proxy addresses are encoded using a signed 32 bit signed int because 
        the GNU assembler requires constants be in that format
        """
        # if we've seen this return target before, return the same proxy
        if rett in self.ptr_proxies:
            return self.ptr_proxies[rett]

        new_proxy = 0
        while new_proxy in self.ptr_proxy_set:
            new_proxy = random.randrange(SIGNED_INT32_MIN, SIGNED_INT32_MAX)
        new_proxy 
        self.ptr_proxy_set.add(new_proxy)
        self.ptr_proxies[rett] = new_proxy

        return new_proxy

class FptrCall:
    def __init__(self, type_sig, src_line_num):
        self.type = type_sig
        self.src_line_num = src_line_num

class SledIdFaucet:
    def __init__(self):
        self.__sled_id = 0

    def __call__(self):
        self.__sled_id += 1
        return self.__sled_id

class Site:
    CALL_SITE = 0
    RETURN_SITE = 1
    INDIR_JMP_SITE = 2
    PLT_SITE = 3

    # These sites are grab data from the GOT, which may create an problematic,
    # optimized PLT that doesn't have enough space for us. We keep track of these
    # sites and apply a workaround if the site grabs a function address form the GOT
    GOTPCREL_SITE = 4

    def __init__(self, line_num, targets, type_of_site, dwarf_loc, uniq_label):
        assert type(line_num) is types.IntType
        assert type(type_of_site) is types.IntType
        assert (type_of_site == Site.CALL_SITE
                or type_of_site == Site.RETURN_SITE 
                or type_of_site == Site.INDIR_JMP_SITE 
                or type_of_site == Site.GOTPCREL_SITE)

        self.enclosing_funct_uniq_label = uniq_label
        self.asm_line_num = line_num
        self.group = type_of_site

        # this is set for indirect call sites by the time gen_cfg finishes
        self.fptype = None

        # targets are of "Function" type. len(targets) == 1 for a direct call site 
        self.targets = targets 

        if dwarf_loc.valid():
            self.src_line_num = dwarf_loc.line_num
        else:
            self.src_line_num = ''

