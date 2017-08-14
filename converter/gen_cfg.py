import __init__

import funct_cfg
import asm_parsing
import operator
import sys
import os
import re
import copy

from common.eprint import eprint

def gen_cfg(asm_file_descrs, plt_sites, options):
    """Generate cfg from a list of asm files. Produce funct names for each description

    asm_file_descrs should be a list containing objects of type 'AsmFileDescription'
    plt_sites should be empty and will be filled with all site that call the PLT

    """

    global_functs = []

    cfg = funct_cfg.FunctControlFlowGraph()
    for descr in asm_file_descrs:
        dwarf_loc = asm_parsing.DwarfSourceLoc()
        descr.global_functs = []
        asm_file = open(descr.filename, 'r')
        line_num = 0

        is_global = False
        funct_name, line_num, is_global, symbol_tuples = (
                asm_parsing.goto_next_funct(asm_file, line_num, dwarf_loc))
        
        dirname = os.path.dirname(descr.filename) + '/'
        if dirname == '/':
            dirname = ''

        while funct_name:
            funct, line_num = extract_funct(asm_file, funct_name, line_num, dwarf_loc, options)
            funct.asm_filename = descr.filename
            funct.is_global = is_global
            funct.src_filename = dirname + funct.src_filename

            if funct.is_global:
                global_functs.append(funct)

            cfg.add_funct(funct)
            descr.funct_names.append(funct.asm_name)

            funct_name, line_num, is_global, symbol_tuples = (
                    asm_parsing.goto_next_funct(asm_file, line_num, dwarf_loc))

        asm_file.close()

    # fix the direct calls so that they point to functions instead of strings
    for descr in asm_file_descrs:
        descr_functs = [cfg.funct(descr.filename + '.' + n) for n in descr.funct_names]
        for funct in descr_functs:
            for dir_call_site in funct.direct_call_sites:
                target_name = dir_call_site.targets[0].replace('@PLT', '')
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
                        plt_sites.append(dir_call_site)

    # the direct call lists shouldn't be used because they are polluted with the
    # PLT calls, for which only the plt function name is known
    for funct in cfg:
        del(funct.direct_call_sites)

    # try:
    build_indir_targets(cfg, asm_file_descrs, options)
    build_ret_dicts(cfg)
    # except NoTypeFile as warning:
    # build_ret_dicts(cfg, True)
    # eprint(warning)

    return cfg

def extract_funct(asm_file, funct_name, line_num, dwarf_loc, options):
    """Constructs a function from the assembly file. 

    File pointer must point at first instruction of the function. The return 
    dictionary and target list of site are not built here.

    Only fields initialized in a function's contstructor are initialized. However,
    each site of a function has its return dictionary linked to the function's 
    return dictionary
    """
    uniq_label = asm_file.name + '.' + funct_name

    start_line_num = line_num
    call_list = ["call","callf", "callq"]
    returns = ["ret", "retf", "iret", "retq", "iretq"]
    jmp_list = ["jo","jno","jb","jnae","jc","jnb","jae","jnc","jz","je","jnz",
                "jne","jbe","jna","jnbe","ja","js","jns","jp","jpe","jnp","jpo","jl",
                "jnge","jnl","jge","jle","jng","jnle","jg","jecxz","jrcxz","jmp","jmpe"]
    CALL_SITE, RETURN_SITE, INDIR_JMP_SITE, PLT_SITE, = 0, 1, 2, 3

    asm_line = asm_file.readline()
    line_num += 1
    try:
        first_word = asm_line.split()[0]
    except IndexError:
        pass # ignore empty line

    comment_continues = False
    sites = []
    direct_call_sites = []
    empty_ret_dict = dict()

    while asm_line:
        asm_parsing.update_dwarf_loc(asm_line, dwarf_loc)
        try:
            first_word = asm_line.split()[0]
        except IndexError:
            # ignore empty line
            asm_line = asm_file.readline()
            line_num += 1
            continue

        if (first_word[:len('.LFE')] == '.LFE'):
            break
        else:
            targets = []
            labels, key_symbol, arg_str, comment_continues = (
                    asm_parsing.decode_line(asm_line, comment_continues))

        if key_symbol in call_list:
            new_site = funct_cfg.Site(line_num, targets, CALL_SITE, dwarf_loc, uniq_label)
            if '%' not in arg_str:
                new_site.targets.append(arg_str)
                direct_call_sites.append(new_site)
            sites.append(new_site)
        elif key_symbol in returns:
            # empty return dict passed so that every site's return dict is
            # a reference to the function's return dict
            sites.append(funct_cfg.Site(line_num, empty_ret_dict, RETURN_SITE, dwarf_loc, uniq_label))
        elif key_symbol in jmp_list:
            if '%' in arg_str:
                sites.append(funct_cfg.Site(line_num, targets, INDIR_JMP_SITE, dwarf_loc, uniq_label))
        asm_line = asm_file.readline()
        line_num += 1
    else:
        eprint(dwarf_loc.filename() + ':' + asm_file.name + ':' 
                + start_line_num + ' error: unterminated function: ', funct_name)
        sys.exit(1)

    new_funct = funct_cfg.Function(funct_name, asm_file.name, 
            dwarf_loc.filename(), sites, start_line_num)
    new_funct.direct_call_sites = direct_call_sites
    new_funct.ret_dict = empty_ret_dict

    return new_funct, line_num
    
def build_indir_targets(cfg, asm_file_descrs, options):
    """Builds the target set of each function's indirect calls/jumps
    
    Currently only builds the targets for indirect calls
    """

    def is_indir_call_site(site):
        return (site.group == funct_cfg.Site.CALL_SITE 
                and site.targets == [])


    if options['--no-narrowing']:
        for funct in cfg:
            fptr_sites = filter(is_indir_call_site, funct.sites)
            for fptr_site in fptr_sites:
                fptr_site.targets = [f for f in cfg]
        return

    funct_types = dict()
    fptr_types = dict()
    for descr in asm_file_descrs:
        try:
            parse_cdi_metadata(descr, funct_types, fptr_types, options)
        except:
            eprint("gen_cdi: error: parsing CDI metadata from file '{}' failed. Aborting..."
                    .format(descr.filename))
            raise
    
    # associate function types with assembly functions (need to fix for C++)
    optimized_functs_children = []
    for funct in cfg:
        try:
            funct.ftype = funct_types[funct.asm_filename + '.' + funct.asm_name]
        except KeyError:
            # gcc may optimize functions by splitting, cloning, or otherwise
            # modifying them. In all cases (it seems), gcc appends 
            # '.[optimization name].[number]' to the original function
            # 
            # these functions are not in the type information gcc spits out 
            # because type info is gathered at the preprocessing stage. Since
            # not all functions have had their ftype information assigned, wait
            # until after this loop to copy the type info from the original function
            function_part_matcher = re.compile(r'^[^\s0-9][^\s.]*\.[^\s]*\.[0-9]*$')
            if function_part_matcher.match(funct.asm_name):
                optimized_functs_children.append(funct)
            else:
                eprint("error: no type found for function '{}' from file '{}'"
                        .format(funct.asm_name, funct.asm_filename))
                exit(1)

    # grab type information from the unoptimized version
    for funct in optimized_functs_children:
        try:
            parent_funct_asm_name = funct.asm_name.split('.')[0]
            optimization_name = funct.asm_name.split('.')[1]

            # part      -> function splitting optimization
            # isra      -> scalar replacement of Aggregates
            # constprop -> function cloning
            if optimization_name not in ['part', 'isra', 'constprop']:
                eprint("warning: unknown optimization '{}' on function "
                        "'{}' in file '{}'".format(optimization_name, 
                            funct.asm_name, funct.asm_filename))

            # we use funct_types and not cfg.funct(...) below since it's possible 
            # to have only the optimized version available. In that case, the 
            # original function wouldn't be in the cfg

            # deepcopy just in case (future additions could make it necessary)
            funct.ftype = copy.deepcopy(funct_types[funct.asm_filename + '.' 
                + parent_funct_asm_name])
            
        except KeyError:
            eprint("error: '{}' from file '{}' appears to be optimized from"
                    " a function named '{}', but no such function can be found"
                    .format(funct.asm_name, funct.asm_filename, parent_funct_asm_name))
            exit(1)
            
    for funct in cfg:
        fptr_sites = filter(is_indir_call_site, funct.sites)
        # TODO: what about object files with the same name?
        funct.fptr_types = fptr_types.get(
                funct.asm_filename + '.' + funct.asm_name, []) # fix for C++
        if fptr_sites:
            assign_targets(fptr_sites, funct, cfg, options)
        del(funct.fptr_types)


def assign_targets(fptr_sites, funct, cfg, options):
    """Assigns each fptr site a target list filled with function references
    
    fptr_sites is a list of sites in funct that have indirect calls
    """

    if options['--profile-use']:
        assign_targets_profiled(fptr_sites, funct, cfg, options)
        return

    fptr_sites = sorted(fptr_sites, key=operator.attrgetter('src_line_num'))
    funct.fptr_types = sorted(funct.fptr_types, key=operator.attrgetter('src_line_num'))

    arbitrary_ftype = funct_cfg.FunctionType.arbitrary

    i = j = 0
    def print_fptr_type_unmatched_msg():
        eprint(funct.src_filename + ':' + str(funct.fptr_types[i].src_line_num)
                + ': warning: fptr type not associated with any indirect '
                + 'call. The fptr call may have been inlined. '
                + 'fptr type: ' + str(funct.fptr_types[i]))
    def print_fptr_site_unmatched_msg():
        eprint(funct.src_filename + ':' + str(fptr_sites[j].src_line_num) + ':'
                + funct.asm_filename + ':' + str(fptr_sites[j].asm_line_num)
                + ': warning: no type for indirect call site in function '
                'named \'' + funct.asm_name + '\'') # fix for C++

    # associate each fptr type with a site
    while (i < len(funct.fptr_types) and j < len(fptr_sites)):
        if funct.fptr_types[i].src_line_num < fptr_sites[j].src_line_num:
            print_fptr_type_unmatched_msg()
            i += 1
        elif funct.fptr_types[i].src_line_num > fptr_sites[j].src_line_num:
            print_fptr_site_unmatched_msg()
            fptr_sites[j].fptr_type = arbitrary_ftype
            j += 1
        else:
            fptr_sites[j].fptr_type = funct.fptr_types[i]
            i += 1
            j += 1
    while i < len(funct.fptr_types):
        print_fptr_type_unmatched_msg()
        i += 1
    while j < len(fptr_sites):
        print_fptr_site_unmatched_msg()
        fptr_sites[j].fptr_type = arbitrary_ftype
        j += 1

    for site in fptr_sites:
        if site.fptr_type is arbitrary_ftype:
            site.targets = [f for f in cfg]
        else:
            site.targets = [f for f in cfg if site.fptr_type == f.ftype]

def assign_targets_profiled(fptr_sites, funct, cfg, options):
    pass # TODO
    
def increment_dict(dictionary, key, start = 1):
    dictionary[key] = dictionary.get(key, start - 1) + 1
    return dictionary[key]

def build_ret_dicts(cfg):
    """Builds return dictionaries of all functions in the CFG

    Notice that when a given function is being examined, it is all the other
    functions' return dictionaries that are being built. After all, a function foo's
    return dictionary depends on which functions call foo
    """

    arbitrary_ftype = funct_cfg.FunctionType.arbitrary
    beg_multiplicity = 1

    for funct in cfg:
        call_dict = dict()
        for site in funct.sites:
            if site.group == site.CALL_SITE:
                for target in site.targets:
                    increment_dict(call_dict, target.uniq_label, beg_multiplicity)

        for target_label, multiplicity in call_dict.iteritems():
            try:
                cfg.funct(target_label).ret_dict[funct.uniq_label] = multiplicity
            except KeyError:
                eprint("warning: function cannot be found: " + target_label )

def read_function_types(asm_descrs, options):
    """Reads in function type information and stores it in a dict

    The dict has the following mapping:
        
        <src filename>.<src function name>   -->  <function type>

    For C++, we'll have to change <src function name> to a mangling of the 
    function since there can be multiple functions with the same name in a 
    source file (e.g. overloading)
    """


    if options['--verbose']:
        print 'read function types:\n===================='

    funct_types = dict()

    for src_filename in src_filename_set:
        try:
            funct_typefile = open(src_filename + '.ftypes', 'r')
        except IOError:
            continue # source files don't NEED functions (e.g. header files)

        for line in funct_typefile:
            if options['--verbose']:
                print line,     # don't print newline in file
            loc, mangled_str = line.split()[0], line.split()[1]
            loc_list = loc.split(':')

            funct_type = funct_cfg.FunctionType(mangled_str)
            funct_type.src_filename = src_filename
            funct_type.src_line_num = int(loc_list[1])
            funct_type.src_name = loc_list[3]
            key = src_filename + '.' + funct_type.src_name
            funct_types[key] = funct_type
        funct_typefile.close()

    if options['--verbose']:
        print '\n',

    return funct_types

def parse_cdi_metadata(asm_descr, funct_types, fptr_types, options):
    with open(asm_descr.filename, 'r') as asm_file:
        state = 'normal'
        for line in asm_file:
            if line == '# assembly\n':
                break
            elif state == 'normal' and '# typeinfo' in line:
                if line.endswith('ftypes\n'):
                    state = 'parsing ftypes'
                elif line.endswith('fptypes\n'):
                    state = 'parsing fptypes'

            elif state == 'parsing ftypes':
                if line == '\n':
                    state = 'normal'
                    continue
                if options['--verbose']:
                    print line[2:-1] # don't print newline or '#'
                loc, mangled_str = line.split()[1], line.split()[2]
                loc_list = loc.split(':')

                if '?' in mangled_str:
                    eprint("gen_cdi: warning: mangling '{}' from '{}' contains unknown type"
                            .format(mangled_str, asm_descr.filename))
                    if options['--no-mystery-types']:
                        eprint("gen_cdi: error: '--no-mystery-types' means unknown type in mangling is fatal")
                        sys.exit(1)


                funct_type = funct_cfg.FunctionType(mangled_str)
                funct_type.src_line_num = int(loc_list[1])
                funct_type.src_name = loc_list[3]
                key = asm_descr.filename + '.' + funct_type.src_name
                funct_types[key] = funct_type
            elif state == 'parsing fptypes':
                if line == '\n':
                    state = 'normal'
                    continue
                if options['--verbose']:
                    print line [2:-1] # don't print newline or '#'
                loc, type_str = line.split()[1], line.split()[2]
                loc_list = loc.split(':')

                fp_type = funct_cfg.FunctionType(type_str)
                fp_type.src_filename = loc_list[0]
                fp_type.src_line_num = int(loc_list[1])
                fp_type.enclosing_funct_name = loc_list[3]

                key = asm_descr.filename + '.' + fp_type.enclosing_funct_name
                if key in fptr_types:
                    fptr_types[key].append(fp_type)
                else:
                    fptr_types[key] = [fp_type]
                if options['--verbose']:
                    print 'In ' + fp_type.enclosing_funct_name + ': ' + str(fp_type)

