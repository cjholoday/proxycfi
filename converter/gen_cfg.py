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

    cfg = funct_cfg.FunctControlFlowGraph()
    for descr in asm_file_descrs:
        dwarf_loc = asm_parsing.DwarfSourceLoc()
        descr.global_functs = []
        asm_file = open(descr.filename, 'r')
        line_num = 0

        is_global = False
        funct_name, line_num, is_global, set_cmds = (
                asm_parsing.goto_next_funct(asm_file, line_num, dwarf_loc))

        descr.set_cmds += set_cmds
        
        dirname = os.path.dirname(descr.filename) + '/'
        if dirname == '/':
            dirname = ''

        while funct_name:
            funct, line_num = extract_funct(asm_file, funct_name, line_num, dwarf_loc, options)
            funct.asm_filename = descr.filename
            funct.is_global = is_global
            funct.src_filename = dirname + funct.src_filename


            cfg.add_funct(funct)
            if funct.is_global:
                cfg.set_global(funct.uniq_label)

            descr.funct_names.append(funct.asm_name)

            funct_name, line_num, is_global, set_cmds = (
                    asm_parsing.goto_next_funct(asm_file, line_num, dwarf_loc))
            descr.set_cmds += set_cmds

        asm_file.close()

    # Add aliases to the cfg with all the set commands
    for descr in asm_file_descrs:
        for set_cmd in descr.set_cmds:
            from_ul = descr.ul(set_cmd[0])
            to_ul = descr.ul(set_cmd[1])

            if to_ul in cfg:
                cfg.add_alias(from_ul, to_ul)
                # all set commands are seen globally as well
                cfg.add_alias(set_cmd[0], to_ul)
    
    if options['--verbose']:
        cfg.print_aliases()
        cfg.print_uniq_labels()

    # fix the direct calls so that they point to functions instead of strings
    for descr in asm_file_descrs:
        descr_functs = [cfg.funct(descr.ul(n)) for n in descr.funct_names]
        for funct in descr_functs:
            for dir_call_site in funct.direct_call_sites:
                target_name = dir_call_site.targets[0].replace('@PLT', '')

                # Three cases: The function target is... 
                #   1. local to this assembly file
                #   2. globally visible from all assembly files
                #   3. outside this code object (in another shared library/obj)

                try:
                    dir_call_site.targets[0] = cfg.funct(descr.ul(target_name))
                    continue
                except KeyError:
                    pass
                
                try:
                    dir_call_site.targets[0] = cfg.funct(target_name)
                except KeyError:
                    dir_call_site.group = dir_call_site.PLT_SITE
                    plt_sites.append(dir_call_site)
                    if options['--verbose']:
                        eprint("Found PLT target '{}".format(dir_call_site.targets[0]))
                

    # the direct call lists shouldn't be used because they are polluted with the
    # PLT calls, for which only the plt function name is known
    for funct in cfg:
        del(funct.direct_call_sites)

    build_indir_targets(cfg, asm_file_descrs, options)
    build_ret_dicts(cfg)

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
    CALL_SITE, RETURN_SITE, INDIR_JMP_SITE, PLT_SITE, GOTPCREL_SITE = 0, 1, 2, 3, 4

    asm_line = asm_file.readline()
    line_num += 1
    try:
        first_word = asm_line.split()[0]
    except IndexError:
        pass # ignore empty line

    comment_continues = False

    sites = []
    fptr_sites = []
    direct_call_sites = []
    empty_ret_dict = dict()
    gotpcrel_matcher = re.compile(r'^[A-Za-z][A-Za-z0-9_]*@GOTPCREL\(%rip\),')

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
            else:
                fptr_sites.append(new_site)
            sites.append(new_site)
        elif key_symbol in returns:
            # empty return dict passed so that every site's return dict is
            # a reference to the function's return dict
            sites.append(funct_cfg.Site(line_num, empty_ret_dict, RETURN_SITE, dwarf_loc, uniq_label))
        elif key_symbol in jmp_list:
            if '%' in arg_str:
                sites.append(funct_cfg.Site(line_num, targets, INDIR_JMP_SITE, dwarf_loc, uniq_label))
        elif gotpcrel_matcher.match(arg_str):
            sites.append(funct_cfg.Site(line_num, None, GOTPCREL_SITE, dwarf_loc, uniq_label))
            sites[-1].got_name = arg_str[:arg_str.find('@')]

        asm_line = asm_file.readline()
        line_num += 1
    else:
        eprint(dwarf_loc.filename() + ':' + asm_file.name + ':' 
                + start_line_num + ' error: unterminated function: ', funct_name)
        sys.exit(1)

    new_funct = funct_cfg.Function(funct_name, asm_file.name, 
            dwarf_loc.filename(), sites, start_line_num)
    new_funct.direct_call_sites = direct_call_sites
    new_funct.fptr_sites = fptr_sites
    new_funct.ret_dict = empty_ret_dict

    return new_funct, line_num
    
def build_indir_targets(cfg, asm_file_descrs, options):
    """Builds the target set of each function's indirect calls/jumps
    
    Currently only builds the targets for indirect calls
    """

    for descr in asm_file_descrs:
        try:
            dangling_metadata = parse_cdi_metadata(cfg, descr, options)
        except:
            eprint("gen_cdi: error: parsing CDI metadata from file '{}' failed. Aborting..."
                    .format(descr.filename))
            raise

    failed = False
    for funct in cfg:
        if funct.ftype == None:
            eprint("gen_cdi: error: function with uniq_label '{}' has no ftype"
                    .format(funct.uniq_label))
            failed = True
    if failed:
        eprint("gen_cdi: dangling (uniq_label, ftype) pairs:")
        for md_pair in dangling_metadata:
            eprint("{} : {}".format(md_pair[0], md_pair[1]))
        cfg.print_uniq_labels()
        sys.exit(1)


    for funct in cfg:
        # TODO: what about object files with the same name?
        assign_targets(cfg, funct, options)


def assign_targets(cfg, funct, options):
    """Assigns each fptr site a target list filled with function references
    
    fptr_sites is a list of sites in funct that have indirect calls
    """

    # if options['--profile-use']:
    #     assign_targets_profiled(fptr_sites, funct, cfg, options)
    #     return

    funct.fptr_sites.sort(key=operator.attrgetter('src_line_num'))
    funct.fptr_calls.sort(key=operator.attrgetter('src_line_num'))

    arbitrary_type = ''

    i = j = 0
    def print_fptr_type_unmatched_msg():
        eprint(funct.src_filename + ':' + str(funct.fptr_types[i].src_line_num)
                + ': warning: fptr type not associated with any indirect '
                + 'call. The fptr call may have been inlined. '
                + 'fptr type: ' + str(funct.fptr_types[i]))
    def print_fptr_site_unmatched_msg():
        eprint(funct.src_filename + ':' + str(funct.fptr_sites[j].src_line_num) + ':'
                + funct.asm_filename + ':' + str(funct.fptr_sites[j].asm_line_num)
                + ': warning: no type for indirect call site in function '
                'named \'' + funct.asm_name + '\'') # fix for C++

    # associate each fptr type with a site
    while (i < len(funct.fptr_calls) and j < len(funct.fptr_sites)):
        if funct.fptr_calls[i].src_line_num < funct.fptr_sites[j].src_line_num:
            print_fptr_type_unmatched_msg()
            i += 1
        elif funct.fptr_calls[i].src_line_num > funct.fptr_sites[j].src_line_num:
            print_fptr_site_unmatched_msg()
            funct.fptr_sites[j].fptype = arbitrary_type
            j += 1
        else:
            funct.fptr_sites[j].fptype = funct.fptr_calls[i].type
            i += 1
            j += 1
    while i < len(funct.fptr_calls):
        print_fptr_type_unmatched_msg()
        i += 1
    while j < len(funct.fptr_sites):
        print_fptr_site_unmatched_msg()
        funct.fptr_sites[j].fptype = arbitrary_type
        j += 1

    for site in funct.fptr_sites:
        if site.fptype is arbitrary_type:
            site.targets = [f for f in cfg]
        else:
            site.targets = [f for f in cfg if site.fptype == f.ftype]
    
def increment_dict(dictionary, key, start = 1):
    dictionary[key] = dictionary.get(key, start - 1) + 1
    return dictionary[key]

def build_ret_dicts(cfg):
    """Builds return dictionaries of all functions in the CFG

    Notice that when a given function is being examined, it is all the other
    functions' return dictionaries that are being built. After all, a function foo's
    return dictionary depends on which functions call foo
    """

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

def parse_cdi_metadata(cfg, asm_descr, options):
    """Fills the cfg with ftypes and fptypes using info from asm_descr

    returns and list of pairs (uniq_label, ftype) that describe function types
    which were unable to be attached to any function in the cfg. This is 
    possible when functions are inlined
    """

    dangling_metadata = []
    optimized_functs_children = []
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
                loc, type_sig = line.split()[1], line.split()[2]
                funct_name = loc.split(':')[3]

                if '?' in type_sig:
                    eprint("gen_cdi: warning: type signature '{}' from '{}' contains unknown type"
                            .format(type_sig, asm_descr.filename))
                    if options['--no-mystery-types']:
                        eprint("gen_cdi: error: '--no-mystery-types' disallows unknown types")
                        sys.exit(1)

                try: 
                    uniq_label = asm_descr.filename + '.' + funct_name
                    cfg.funct(uniq_label).ftype = type_sig
                except KeyError:
                    eprint("warning: no function found with uniq_label '{}'"
                            .format(uniq_label))

                    dangling_metadata.append((uniq_label, type_sig))
                    continue

                    # The code below handles optimizations, but is incomplete
                    # For now, we exit with error above

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
            elif state == 'parsing fptypes':
                if line == '\n':
                    state = 'normal'
                    continue
                if options['--verbose']:
                    print line [2:-1] # don't print newline or '#'

                loc, type_sig = line.split()[1], line.split()[2]
                loc_list = loc.split(':')

                src_line_num = int(loc_list[1])
                enclosing_funct_name = loc_list[3]
                fptr_call = funct_cfg.FptrCall(type_sig, src_line_num)

                uniq_label = asm_descr.filename + '.' + enclosing_funct_name
                cfg.funct(uniq_label).fptr_calls.append(fptr_call)
                #if options['--verbose']:
                #print 'In ' + fp_type.enclosing_funct_name + ': ' + str(fp_type)

    # the following is code attempted to deal with tricky gcc optimizations
    # it's commented out for now because shared libraries / the verifier are
    # top priority and the code's correctness is questionable/incompatible with
    # some necessary refactoring

    # grab type information from the unoptimized version
    #for funct in optimized_functs_children:
    #    try:
    #        parent_funct_asm_name = funct.asm_name.split('.')[0]
    #        optimization_name = funct.asm_name.split('.')[1]

    #        # part      -> function splitting optimization
    #        # isra      -> scalar replacement of Aggregates
    #        # constprop -> function cloning
    #        if optimization_name not in ['part', 'isra', 'constprop']:
    #            eprint("warning: unknown optimization '{}' on function "
    #                    "'{}' in file '{}'".format(optimization_name, 
    #                        funct.asm_name, funct.asm_filename))

    #        # we use funct_types and not cfg.funct(...) below since it's possible 
    #        # to have only the optimized version available. In that case, the 
    #        # original function wouldn't be in the cfg

    #        # deepcopy just in case (future additions could make it necessary)
    #        funct.ftype = copy.deepcopy(funct_types[funct.asm_filename + '.' 
    #            + parent_funct_asm_name])
    #        
    #    except KeyError:
    #        eprint("error: '{}' from file '{}' appears to be optimized from"
    #                " a function named '{}', but no such function can be found"
    #                .format(funct.asm_name, funct.asm_filename, parent_funct_asm_name))
    #        exit(1)

