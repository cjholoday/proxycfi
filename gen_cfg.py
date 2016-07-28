import funct_cfg
import asm_parsing
from eprint import eprint
import sys

def gen_cfg(asm_file_descrs, options):
    """Generate cfg from a list of asm_files. Produce funct names for each description

    asm_files should be a list containing objects of type 'AsmFile'
    """

    global_functs = []

    cfg = funct_cfg.FunctControlFlowGraph()
    for descr in asm_file_descrs:
        descr.global_functs = []
        asm_file = open(descr.filename, 'r')
        line_num = 0

        is_global = False
        funct_name, line_num, is_global = asm_parsing.goto_next_funct(asm_file, line_num)
        
        while funct_name:
            funct_line_num = line_num + 1 # +1 so points at first instr
            funct, line_num = extract_funct(asm_file, funct_name, line_num)
            funct.asm_filename = descr.filename
            funct.line_num = funct_line_num
            funct.is_global = is_global

            if funct.is_global:
                global_functs.append(funct)

            cfg.add_funct(funct)
            descr.funct_names.append(funct.asm_name)

            funct_name, line_num, is_global = asm_parsing.goto_next_funct(asm_file, line_num)

        asm_file.close()

    # fix the direct calls so that they point to functions instead of strings
    for descr in asm_file_descrs:
        descr_functs = [cfg.funct(descr.filename + '.' + n) for n in descr.funct_names]
        for funct in descr_functs:
            for dir_call_site in funct.direct_call_sites:
                target_name = dir_call_site.targets[0]
                if target_name in descr.funct_names:
                    dir_call_site.targets[0] = cfg.funct(descr.filename + '.' + target_name)
                else:
                    for glob_funct in global_functs:
                        if glob_funct.asm_name == target_name:
                            dir_call_site.targets[0] = (
                                    cfg.funct(glob_funct.asm_filename + '.' + target_name))
                            break
                    else:
                        # the function is not defined in the source files
                        # so it must be from a shared library
                        dir_call_site.group = dir_call_site.PLT_SITE

    # the direct call lists shouldn't be used because they are polluted with the
    # PLT calls, for which only the plt function name is known
    for funct in cfg:
        del(funct.direct_call_sites)
                        
    try:
        build_indir_targets(cfg, asm_file_descrs, options)
        build_return_dicts(cfg)
    except NoTypeFile as warning:
        build_return_dicts(cfg, True)
        eprint(warning)


    return cfg



def extract_funct(asm_file, funct_name, line_num):
    """Constructs a function from the assembly file. 

    File pointer must point at first instruction of the function. The return 
    dictionary and target list of site are not built here.

    """
    start_line_num = line_num
    call_list = ["call","callf", "callq"]
    returns = ["ret", "retf", "iret", "retq", "iretq"]
    jmp_list = ["jo","jno","jb","jnae","jc","jnb","jae","jnc","jz","je","jnz",
                "jne","jbe","jna","jnbe","ja","js","jns","jp","jpe","jnp","jpo","jl",
                "jnge","jnl","jge","jle","jng","jnle","jg","jecxz","jrcxz","jmp","jmpe"]
    asm_line = asm_file.readline()
    line_num += 1
    try:
        first_word = asm_line.split()[0]
    except IndexError:
        pass # ignore empty line
    comment_continues = False
    sites = []
    return_dict = dict()
    direct_call_sites = []
    while asm_line:
        try:
            first_word = asm_line.split()[0]
        except IndexError:
            pass # ignore empty line
        if (first_word[:len('.LFE')] == '.LFE'):
            break
        targets = []
        labels, key_symbol, arg_str, comment_continues = asm_parsing.decode_line(asm_line, comment_continues)
        if key_symbol in call_list:
            new_site = funct_cfg.Site(line_num, targets, 0)
            if '%' not in arg_str:
                new_site.targets.append(arg_str)
                direct_call_sites.append(new_site)
            sites.append(new_site)
        elif key_symbol in returns:
            sites.append(funct_cfg.Site(line_num, return_dict, 1))
        elif key_symbol in jmp_list:
            if '%' in arg_str:
                sites.append(funct_cfg.Site(line_num, targets, 2))
        asm_line = asm_file.readline()
        line_num += 1

    new_funct = funct_cfg.Function(funct_name, asm_file.name, sites, return_dict, start_line_num)
    new_funct.direct_call_sites = direct_call_sites

    return new_funct, line_num
    
def build_indir_targets(cfg, asm_file_descrs, options):
    """Builds the target set of each function's indirect calls/jumps"""

    
    funct_types = read_function_types(options)
    # associate function types with assembly functions
    for descr in asm_file_descrs:
        for funct_type in funct_types:
            if funct_type.src_filename in descr.dependencies:
                assert funct_type.src_name in descr.funct_names
                assert funct_type.is_local() or not funct_type.matched
                cfg.funct(descr.filename + '.' + funct_type.src_name).ftype = funct_type
                funct_type.matched = True

    
    indir_call_types_in = read_indir_call_types(options)

    def is_indir_call_site(site):
        return (site.group == funct_cfg.Site.CALL_SITE 
                and site.targets == [])
    
    for descr in asm_file_descrs:
        descr_functs = [cfg.funct(descr.filename + '.' + n) for n in descr.funct_names]
        for funct in descr_functs:
            indir_sites = filter(is_indir_call_site, funct.sites)

            # Problem: the dictonary indir_call_types_in maps function name to
            # function pointer type information, but there may be two functions
            # with the same name!
            #
            # In C, a function name is unique in each translation unit. Since
            # each assembly file contains the assembly for a translation unit
            # we only need to check that the indir call type is from the same
            # translation unit as the function we're examining
            indir_types = []
            for indir_type in indir_call_types_in.get(funct.asm_name, []):
                if indir_type.src_filename in descr.dependencies:
                    indir_types.append(indir_type)

            num_arbitrary_fptrs = len(indir_sites) - len(indir_types)
            assert num_arbitrary_fptrs >= 0
            assign_targets(funct, funct_types, indir_types, indir_sites, 
                    num_arbitrary_fptrs, cfg, options)


def assign_targets(funct, funct_types, indir_types, indir_sites, 
        num_arbitrary_fptrs, cfg, options):

    if options.use_profile:
        assign_targets_profiled(funct, funct_types, indir_types, indir_sites, 
        num_arbitrary_fptrs, cfg, options)
        return

    funct_targets = []
    if num_arbitrary_fptrs > 0:
        if options.verbose:
            print funct.uniq_label + ': arbitrary function pointer '
        funct_targets = [f for f in cfg]
    else:
        type_str_set = set([str(i) for i in indir_types])
        
        for type_str in type_str_set:
            for funct in cfg:
                if type_str == str(funct.ftype):
                    funct_targets.append(funct)

    # sanity check
    for target in funct_targets:
        if target not in cfg:
            eprint("warning: function in target list but not found in the cfg: '" +
                    target.asm_name + "'")

    for site in indir_sites:
        site.targets = funct_targets



def assign_targets_profiled(funct, funct_types, indir_types, indir_sites, 
        num_arbitrary_fptrs, cfg, options):
    pass # TODO
    
def matching_functs(indir_type, funct_types):
    return [t.name for t in funct_types if t == indir_type]


def build_return_dicts(cfg, no_typefile = False):
    """Builds return dictionaries of all functions in the CFG

    Notice that when a given function is being examined, it is all the other
    functions' return dictionaries that are being built. After all, a function foo's
    return dictionary depends on which functions call foo
    """

    for funct in cfg:
        call_dict = dict()
        for site in funct.sites:
            if site.group == site.CALL_SITE:
                for target in site.targets:
                    if target.uniq_label in call_dict:
                        call_dict[target.uniq_label] += 1
                    else:
                        call_dict[target.uniq_label] = 1
                if no_typefile and site.targets == []:
                    for f in cfg:
                        site.targets.append(f)
                        if f in call_dict:
                            call_dict[f.uniq_label] += 1
                        else:
                            call_dict[f.uniq_label] = 1
                        
        for target_label, multiplicity in call_dict.iteritems():
            try:
                cfg.funct(target_label).return_dict[funct.uniq_label] = multiplicity
            except KeyError:
                eprint("warning: function cannot be found: " + target_label )

def read_function_types(options):
    if options.verbose:
        print 'read function types:\n===================='

    funct_types = []
    try:
        funct_typefile = open('funct_types.txt', 'r')
    except IOError:
        raise NoTypeFile('funct_types.txt couldn\'t be opened')

    for line in funct_typefile:
        loc, mangled_str = line.split()[0], line.split()[1]
        loc_list = loc.split(':')

        funct_type = funct_cfg.FunctionType(mangled_str)
        funct_type.src_filename = loc_list[0]
        funct_type.line_no = loc_list[1]
        funct_type.src_name = loc_list[3]
        funct_types.append(funct_type)
        if options.verbose:
            print funct_type.src_name + ': ' + str(funct_type)

    if options.verbose:
        print '\n',

    funct_typefile.close()
    return funct_types

def read_indir_call_types(options):
    """Returns a dict with mapping: function name -> list indirect call types

    Note that two static functions can have the same name in C, so some care is
    needed. Furthermore, functions can be overloaded in C++ so even more care is
    needed
    """

    if options.verbose:
        print 'read function pointer types:\n============================'
    indir_call_types_in = dict()
    try:
        fp_typefile = open('fp_types.txt', 'r')
    except IOError:
        raise NoTypeFile('fp_types.txt couldn\'t be opened')

    for line in fp_typefile:
        loc, type_str = line.split()[0], line.split()[1]
        loc_list = loc.split(':')

        fp_type = funct_cfg.FunctionType(type_str)
        fp_type.src_filename = loc_list[0]
        fp_type.line_no = loc_list[1]
        fp_type.enclosing_funct_name = loc_list[3]

        if fp_type.enclosing_funct_name in indir_call_types_in:
            indir_call_types_in[fp_type.enclosing_funct_name].append(fp_type)
        else:
            indir_call_types_in[fp_type.enclosing_funct_name] = [fp_type]
        if options.verbose:
            print 'In ' + fp_type.enclosing_funct_name + ': ' + str(fp_type)
            
    if options.verbose:
        print '\n',

    fp_typefile.close()
    return indir_call_types_in

class NoTypeFile(IOError):
    pass
