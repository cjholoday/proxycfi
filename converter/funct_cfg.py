import __init__

import types
import jsonpickle
import random

from common.eprint import eprint
from common.eprint import vvprint

descr_path = ""
STARTUP_FUNCTIONS = [                                                           
        'start_c',                                                              
        '__libc_start_main',                                                    
        'libc_start_main',                                                      
        '__init_libc',                                                          
        'static_init_tls',                                                      
        '__copy_tls',                                                           
        '__init_tp',                                                            
        '__set_thread_area',                                                    
        'dummy1',                                                               
        '__libc_start_init',                                                    
        'libc_start_init',                                                      
        '_init',                                                                
        'frame_dummy',                                                          
        'register_tm_clones',                                                   
        '__libc_csu_init'  # GLIBC only                                         
]                                                                               
CLEANUP_FUNCTIONS = [                                                           
        'exit',                                                                 
        'dummy',                                                                
        '__libc_exit_fini',                                                     
        'libc_exit_fini',                                                       
        '__do_global_dtors_aux',                                                
        'deregister_tm_clones',                                                 
        '_fini',                                                                
        '__libc_csu_fini' # GLIBC only                                          
]                               
WHITELIST = STARTUP_FUNCTIONS + CLEANUP_FUNCTIONS

class FunctControlFlowGraph:
    """A CFG class with functions as vertices instead of basic blocks

    Function are accessed by their "uniq_label" which is in the form:

        <asm filename>.<assembly function name>

    Notice that in C the assembly function name is simply the source name, while
    in C++ it is the source function name but mangled
    """

    def __init__(self):
        # don't touch these attributes; they're internal
        self._funct_vertices = dict()
        self._aliases = dict()
        # used to 
        self._alias_is_weak = dict()

        # These functions are non cdi. This is useful for some edge case functions
        # that libc uses on startup. Allowing these to be non-cdi does not
        # compromise our threat model. Example '_init'
        self.non_cdi_functs = set()

    def add_funct(self, funct):
        uniq_label = funct.asm_filename + '.' + funct.asm_name

        if uniq_label in self._aliases:
            if self._alias_is_weak[uniq_label]:
                del(self._aliases[uniq_label])
                del(self._alias_is_weak[uniq_label])
            else:
                eprint("gen_cdi: error: adding function to cfg whose uniq_label "
                        "collides with a non-weak alias")
                sys.exit(1)

        self._funct_vertices[uniq_label] = funct

    def ul_is_cdi(self, uniq_label):
        try:
            # note that this handles aliases as well
            funct = self.funct(uniq_label)
            return funct not in self.non_cdi_functs
        except KeyError:
            eprint("KEYERROR")
            return True

    def size(self):
        """Returns the number of functions in the CFG"""
        return len(self._funct_vertices)

    def funct(self, uniq_label):
        if uniq_label in self._aliases and uniq_label in self._funct_vertices:
            eprint("gen_cdi: error: uniq_label '{}' is not unique: "
                    "it has both an alias ('{}' -> '{}') and a regular definition"
                    .format(uniq_label, uniq_label, self._aliases(uniq_label)))
            sys.exit(1)
        if uniq_label in self._aliases:
            return self._funct_vertices[self._aliases[uniq_label]]
        else:
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

    def set_global(self, uniq_label):
        """Create an alias mapping [bare funct name] -> [funct]

        This allows the function to be obtained using only its name rather than
        the uniq_label. The function will remain accessible by its uniq_label
        """
        bare_name = uniq_label.split('.')[-1]
        self.add_alias(bare_name, uniq_label)


    def add_alias(self, alias, uniq_label, weak=False):
        if alias in self._aliases:
            # XXX Does it matter which version we take?
            if weak:
                return # stick with the already defined weak alias
            elif not self._alias_is_weak[alias]:
                eprint("gen_cdi: error: attempted overwriting a non-weak alias: '{}' -> [old: '{}', new: '{}']"
                        .format(alias, self._aliases[alias], uniq_label))
                sys.exit(1)
                

        if alias in self._funct_vertices:
            if weak:
                return # stick with the already defined function, weak or not
            else:
                # XXX This may be possible: override a function with a non weak alias. Forbid it for now
                eprint("gen_cdi: error: alias ['{}' -> '{}'] will hide function with uniq_label '{}'"
                        .format(alias, uniq_label, self._funct_vertices[alias]))
                sys.exit(1)
        
        global descr_path # XXX debugging
        vvprint("\nadding alias: {} -> {} [{}]\n".format(alias, uniq_label, descr_path))
        descr_path = ""

        if alias in ['_init', 'libc_start_init']:
            eprint("\nadding function with alias [{} -> {}] to non cdi functs"
                    .format(alias, uniq_label))
            self.non_cdi_functs.add(self.funct(uniq_label))

        self._aliases[alias] = uniq_label
        self._alias_is_weak[alias] = weak

    def print_uniq_labels(self):
        eprint("cfg unique labels:")
        for uniq_label in sorted(self._funct_vertices.keys()):
            eprint('\t' + uniq_label)

    def print_aliases(self):
        eprint("cfg aliases:")
        for alias_pair in self._aliases.iteritems():
            eprint("{:<40} -> {:>40}".format(alias_pair[0], alias_pair[1]))


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
        self.ptr_proxy_set = set() # TODO: remove this

        # forbid pointer proxies with value 0
        self.ptr_proxy_set.add(0)

        # True if the function is compiled to be CDI compliant. This won't be 
        # true for startup/cleanup functions. These functions are oustide of our
        # threat model. CDI functions cannot use proxies with non-cdi functions
        self.is_cdi = True
        if asm_name in WHITELIST:
            self.is_cdi = False

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

