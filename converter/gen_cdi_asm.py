import funct_cfg
import operator
import asm_parsing
import subprocess
import sys
from eprint import eprint
import re
import os

import obj_parse

def gen_cdi_asm(cfg, asm_file_descrs, plt_sites, options):
    """Writes cdi compliant assembly from cfg and assembly file descriptions"""

    sled_id_faucet = funct_cfg.SledIdFaucet()

    rlts_written = False
    slts_written = False
    callback_sled_written = False

###################Cloning Changes#############################
    # gather eligible functions for cloning
    functs_to_clone_sleds = {}
    functs_to_clone_count = {}
    if options['profile_use']:
        profile_file = options.get('profile_use')
        sled_profile = obj_parse.load_obj(profile_file)
        caller_labels_to_fix = {} # label from caller functions to be converted
        sleds_to_remove = {}
        sled_labels_to_add = {}
        functs_to_clone = []
        for descr in asm_file_descrs:
            descr_functs = [cfg.funct(descr.filename + '.' + n) for n in descr.funct_names]
            functs = sorted(descr_functs, key=operator.attrgetter('asm_line_num'))
            
            for funct in functs:
                sled_keyword = '"_CDI_' + (fix_label(funct.uniq_label)) + '_TO_'
                sleds_from_func = {key:value for key, value in sled_profile.items() if sled_keyword in key}
                sled_cnt = len(sleds_from_func)
                if sled_cnt > 5:
                    functs_to_clone.append(fix_label(funct.uniq_label))

            
            for funct_name in functs_to_clone:
                sled_from_keyword = '"_CDI_' + funct_name + '_TO_'
                sleds_from_func = {key:value for key, value in sled_profile.items() if sled_from_keyword in key}
                sorted_sled = sorted(sleds_from_func, key=sleds_from_func.get, reverse=True)

                clone_funct_name = funct_name + '_clone_' + str(1)
                sled_count = len(sorted_sled)
                sled_index = 0
                sleds_to_remove[clone_funct_name] = []
                sleds_to_remove[funct_name] = []
                sled_labels_to_add[funct_name] = []
                sled_labels_to_add[clone_funct_name] = []
                for sled in sorted_sled:
                    caller_func = sled[sled.index('_TO_') + 4 : -3]
                    
                    fixed_sled = sled.replace(funct_name, clone_funct_name)
 

                    
                    if sled_index < sled_count/2: # make half the calls to point to the cloned function
                        sleds_to_remove[clone_funct_name].append(fixed_sled)
                        if caller_func in functs_to_clone:
                            new_sled = sled.replace(caller_func, caller_func + '_clone_' + str(1))
                            sled_labels_to_add[funct_name].append(new_sled)

                    else:
                        sleds_to_remove[funct_name].append(sled)
                        if caller_func in functs_to_clone:
                            new_sled = fixed_sled.replace(caller_func, caller_func + '_clone_' + str(1))
                            sled_labels_to_add[clone_funct_name].append(new_sled)
                        # if calling function in the functions to be cloned
                        # take care of the calls from the cloned functions
                        # sled_count += no. of calls from the calling function
                        # create sleds to this calling funct
                        if caller_func in caller_labels_to_fix:
                            if funct_name in caller_labels_to_fix[caller_func]:
                                caller_labels_to_fix[caller_func][funct_name][sled] = fixed_sled
                            else:
                                caller_labels_to_fix[caller_func][funct_name] = {}
                                caller_labels_to_fix[caller_func][funct_name][sled] = fixed_sled
                                
                        else:
                            caller_labels_to_fix[caller_func] = {}
                            caller_labels_to_fix[caller_func][funct_name] = {}
                            caller_labels_to_fix[caller_func][funct_name][sled] = fixed_sled
                    sled_index += 1

                
###############################################################

    for descr in asm_file_descrs:
        asm_parsing.DwarfSourceLoc.wipe_filename_mapping()
        dwarf_loc = asm_parsing.DwarfSourceLoc()
        asm_src = open(descr.filename, 'r')
        asm_dest = open(cdi_asm_name(descr.filename), 'w')
        descr_functs = [cfg.funct(descr.filename + '.' + n) for n in descr.funct_names]
        functs = sorted(descr_functs, key=operator.attrgetter('asm_line_num'))
        abort_data = [] # used for aborting from sleds

        asm_line_num = 1
        first_funct = True
        funct_write = ''
        for funct in functs:
            num_lines_to_write = funct.asm_line_num - asm_line_num
            pre_funct_write = write_lines(num_lines_to_write, asm_src, asm_dest, dwarf_loc)
            if options['profile_use']:
                pre_funct_lines = pre_funct_write.splitlines(True)
                if first_funct:
                    first_funct = False
                    i = 0
                    for l in pre_funct_lines:
                        if l.endswith(':\n'):
                            break
                        else:
                            asm_dest.write(l)
                            i += 1
                    funct_write = ''.join(pre_funct_lines[i:])
                    
                else:
                    # remaining lines of previous function
                    funct_write = funct_write + ''.join(pre_funct_lines[:3])
                    # fix labels labels of cloning
                    
                    if funct_asm_label in caller_labels_to_fix:
                        funct_write = fix_caller_funct_labels(funct_write, caller_labels_to_fix[funct_asm_label])
                    
                    
                    if funct_asm_label in functs_to_clone:
                        cloned_funct = clone_funct(funct_write)
                        if funct_asm_label in sled_labels_to_add:
                            funct_write_sleds_fixed = clone_fix_sleds(funct_write, sleds_to_remove[funct_asm_label], sled_labels_to_add[funct_asm_label])
                            cloned_funct_sleds_fixed = clone_fix_sleds(cloned_funct, sleds_to_remove[funct_asm_label + '_clone_' + str(1)], sled_labels_to_add[funct_asm_label + '_clone_' + str(1)])
                        else:
                            funct_write_sleds_fixed = clone_fix_sleds(funct_write, sleds_to_remove[funct_asm_label], [])
                            cloned_funct_sleds_fixed = clone_fix_sleds(cloned_funct, sleds_to_remove[funct_asm_label + '_clone_' + str(1)], [])
                        
                        asm_dest.write(funct_write_sleds_fixed)
                        asm_dest.write(cloned_funct_sleds_fixed)

                    else:
                        asm_dest.write(funct_write)

                    funct_write = ''.join(pre_funct_lines[3:])
                
            else:
                funct_write = funct_write + pre_funct_write
                # remove sleds going to the cloned funct
                asm_dest.write(funct_write)
                funct_write = ''
            asm_line_num = funct.asm_line_num

            # unique labels are always global so that even static functions
            # can be reached from anywhere with sleds (Function pointers can
            # point to ANY function with the same signature, even static 
            # functions in a different translation unit)
            # asm_dest.write('.globl\t"{}"\n'.format(fix_label(funct.uniq_label)))
            funct_write = funct_write + '.globl\t"{}"\n'.format(fix_label(funct.uniq_label))
            # asm_dest.write('"{}":\n'.format(fix_label(funct.uniq_label)))
            funct_asm_label = fix_label(funct.uniq_label)
            funct_write = funct_write + '"{}":\n'.format(fix_label(funct.uniq_label))
            funct.label_fixed_count = dict()
            for site in funct.sites:
                num_lines_to_write = site.asm_line_num - asm_line_num
                funct_write = funct_write + write_lines(num_lines_to_write, asm_src, asm_dest, dwarf_loc)

                line_to_fix = asm_src.readline()
                asm_line_num = site.asm_line_num + 1
                
                funct_write = funct_write + convert_to_cdi(site, funct, line_to_fix, asm_dest, cfg,
                        sled_id_faucet, abort_data, dwarf_loc, options)

        # write the last function
        if options['profile_use']:
            if funct_asm_label in caller_labels_to_fix:
                funct_write = fix_caller_funct_labels(funct_write, caller_labels_to_fix[funct_asm_label])
            if funct_asm_label in functs_to_clone:
                cloned_funct = clone_funct(funct_write)
                if funct_asm_label in sled_labels_to_add:
                    funct_write_sleds_fixed = clone_fix_sleds(funct_write, sleds_to_remove[funct_asm_label], sled_labels_to_add[funct_asm_label])
                    cloned_funct_sleds_fixed = clone_fix_sleds(cloned_funct, sleds_to_remove[funct_asm_label + '_clone_' + str(1)], sled_labels_to_add[funct_asm_label + '_clone_' + str(1)])
                else:
                    funct_write_sleds_fixed = clone_fix_sleds(funct_write, sleds_to_remove[funct_asm_label], [])
                    cloned_funct_sleds_fixed = clone_fix_sleds(cloned_funct, sleds_to_remove[funct_asm_label + '_clone_' + str(1)], [])
                
                asm_dest.write(funct_write_sleds_fixed)
                asm_dest.write(cloned_funct_sleds_fixed)

            else:
                asm_dest.write(funct_write)

        else:
            asm_dest.write(funct_write)

########################################################
        debug_section_matcher = re.compile(r'^\t\.section\t\.debug_info.+')
        debug_section_found = False


        if options['--sl-fptr-addrs'] and not callback_sled_written:
            callback_sled_written = True
            write_callback_sled(asm_dest, options)

        # write the rest of the normal asm lines over
        src_line = asm_src.readline()
        while src_line:
            if not debug_section_found and debug_section_matcher.match(src_line):
                asm_dest.write(''.join(abort_data))
            asm_dest.write(src_line)
            src_line = asm_src.readline()

        if not rlts_written:
            rlts_written = True
            write_rlts(cfg, plt_sites, asm_dest, sled_id_faucet, options)


        # write the SLT for shared lib
        if options['--shared-library'] and not slts_written:
            slts_written = True

            page_size = subprocess.check_output(['getconf', 'PAGESIZE'])
            asm_dest.write('\t.text\n')
            asm_dest.write('\t.align {}\n'.format(page_size))
            asm_dest.write('\t.globl _CDI_SLT\n')
            asm_dest.write('\t.type _CDI_SLT, @function\n')
            asm_dest.write('_CDI_SLT:\n')
            for funct in cfg:
                slt_entry_label = '"_CDI_SLT_{}"'.format(fix_label(funct.uniq_label))
                asm_dest.write('\t.globl {}\n'.format(slt_entry_label))
                asm_dest.write(slt_entry_label + ':\n')
                asm_dest.write('\tjmp 0\n')
            asm_dest.write('\t.size _CDI_SLT, .-_CDI_SLT\n')
        
        asm_src.close()
        asm_dest.close()
            
def clone_funct(funct_write):
    cloned_funct = funct_write
    lines = funct_write.splitlines(True)
    labels_to_fix = []
    for line in lines:
        if line.endswith(':\n'):
            labels_to_fix.append(line[:-2])
        if line.startswith('\t.file '):
            lines.pop(lines.index(line))
    cloned_funct = ''.join(lines)

    for label in labels_to_fix:
        if label.endswith('"'):
            cloned_funct = cloned_funct.replace(label[1:-1], label[1:-1] + '_clone_' + str(1))
        else:
            cloned_funct = cloned_funct.replace(label + '\n', label + '_clone_' + str(1) + '\n')
            cloned_funct = cloned_funct.replace(label + ',', label + '_clone_' + str(1) + ',') 
            cloned_funct = cloned_funct.replace(label + ':', label + '_clone_' + str(1) + ':')    
    return cloned_funct

def fix_caller_funct_labels(funct_write, labels_to_fix):
    funct_write_fixed = funct_write
    lines = funct_write_fixed.splitlines(True)
 
    for called_function, sled_dict in labels_to_fix.iteritems():
        for sled, fixed_sled in sled_dict.iteritems():
            line_index =  lines.index(sled + ':\n')
            if lines[line_index - 1].startswith('\tcall'):
                lines[line_index - 1] = lines[line_index - 1][:-1] + '_clone_' + str(1) + '\n'
            else:
                lines[line_index - 2] = lines[line_index - 2][:-1] + '_clone_' + str(1) + '\n'
            if lines[line_index - 1].startswith('.globl'):
                lines[line_index - 1] = '.globl ' + fixed_sled + '\n'
            lines[line_index] = fixed_sled + ':\n'

    funct_write_fixed = ''.join(lines)
    return funct_write_fixed

def clone_fix_sleds (funct_write, sleds_to_remove, sled_labels_to_add):
    # print "///////////////******* sleds to remove:"
    # print sleds_to_remove
    funct_write_fixed = funct_write
    lines = funct_write_fixed.splitlines(True)
    # print "from:"
    # print lines
    for sled in sleds_to_remove:
        for line in lines:
            # print "trying to remove %s from %s" % (sled, line)
            if sled in line:
                index_to_remove = lines.index(line) 
                p = lines.pop(index_to_remove)
                p = lines.pop(index_to_remove) #remove the comparison and the je
                # print "removing... %s" % p

    # add new sleds if the caller function is also cloned 
    if sled_labels_to_add:
        for line in lines:
            if '.CDI_sled_id_' in line:
                new_sleds_to_add = ''
                for sled in sled_labels_to_add:
                    new_sleds_to_add += '\tcmpq\t$' + sled + ', -8(%rsp)\n'
                    new_sleds_to_add += '\tje\t' + sled + '\n'
                lines = lines[:lines.index(line)] + [new_sleds_to_add] + lines[lines.index(line):]

    funct_write_fixed = ''.join(lines)

    return funct_write_fixed


def cdi_asm_name(asm_name):
    if asm_name.endswith('.fake.o'):
        return asm_name[:-1 * len('.fake.o')] + '.cdi.s'
    elif asm_name.endswith('.s'):
        return asm_name[:-2] + '.cdi.s'
    else:
        assert False

def write_lines(num_lines, asm_src, asm_dest, dwarf_loc):
    """Writes from file obj asm_src to file obj asm_dest num_lines lines"""
    funct_write = ''
    i = 0
    while i < num_lines:
        asm_line = asm_src.readline()
        asm_parsing.update_dwarf_loc(asm_line, dwarf_loc)
        # asm_dest.write(asm_line)
        funct_write = funct_write + asm_line
        i += 1
    return funct_write

def convert_to_cdi(site, funct, asm_line, asm_dest, cfg, 
        sled_id_faucet, abort_data, dwarf_loc, options):
    """Converts asm_line to cdi compliant code then writes it to asm_dest"""
    funct_write = ''
    if site.group == site.CALL_SITE:
        funct_write = funct_write + convert_call_site(site, funct, asm_line, asm_dest, 
                sled_id_faucet, abort_data, dwarf_loc, options)
    elif site.group == site.RETURN_SITE:
        funct_write = funct_write + convert_return_site(site, funct, asm_line, asm_dest, cfg, 
                sled_id_faucet, abort_data, dwarf_loc, options)
    elif site.group == site.INDIR_JMP_SITE:
        funct_write = funct_write + convert_indir_jmp_site(site, funct, asm_line, asm_dest)
    elif site.group == site.PLT_SITE:
        funct_write = funct_write + convert_plt_site(site, asm_line, funct, asm_dest)
    else:
        eprint('warning: site has invalid type: line ' + site.asm_line_num, 
                'in function named \'' + funct.asm_name + '\'')
    return funct_write

def increment_dict(dictionary, key, start = 1):
    dictionary[key] = dictionary.get(key, start - 1) + 1
    return dictionary[key]

def convert_call_site(site, funct, asm_line, asm_dest, 
        sled_id_faucet, abort_data, dwarf_loc, options):
    
    funct_write = ''

    arg_str = asm_parsing.decode_line(asm_line, False)[2]

    # add in return label for return sleds if we're not at an indirect call site
    indirect_call = '%' in arg_str
    if not indirect_call:
        assert len(site.targets) == 1
        target_name = fix_label(site.targets[0].uniq_label)
        times_fixed = increment_dict(funct.label_fixed_count, target_name)
        label = '"_CDI_{}_TO_{}_{}"'.format(
                target_name, fix_label(funct.uniq_label), str(times_fixed))

        globl_decl = ''
        if funct.asm_filename != site.targets[0].asm_filename:
            globl_decl = '.globl\t' + label + '\n'

        # asm_dest.write(asm_line + globl_decl + label + ':\n')
        funct_write = funct_write + asm_line + globl_decl + label + ':\n'
        return funct_write
    

    call_sled = ''
    assert len(arg_str.split()) == 1

    if site.targets == []:
        eprint('gen_cdi: warning: indirect call sled is empty on line {} of {} in function {}'
                .format(site.asm_line_num, funct.asm_filename, site.enclosing_funct_uniq_label))

    call_operand = arg_str.replace('*', '')
    for target in site.targets:
        target_name = fix_label(target.uniq_label)
        return_target = fix_label(funct.uniq_label)
        times_fixed = increment_dict(funct.label_fixed_count, target_name)

        return_label = '_CDI_' + target_name + '_TO_' + return_target
        return_label += '_' + str(times_fixed)

        globl_decl = ''
        if funct.asm_filename != target.asm_filename:
            globl_decl = '.globl\t"{}"\n'.format(return_label)

        call_sled += '1:\n'
        if options['--shared-library']:
            call_sled += '\tcmpq\t$"{}(%rip)", {}\n'.format(target_name, call_operand)
        else:
            call_sled += '\tcmpq\t$"{}", {}\n'.format(target_name, call_operand)
            call_sled += '\tjne\t1f\n'
            call_sled += '\tcall\t"{}"\n'.format(target_name)
        call_sled += globl_decl
        call_sled += '"{}":\n'.format(return_label)
        call_sled += '\tjmp\t2f\n'

    call_sled += '1:\n'
    # put the unsafe target address in %rax so that cdi_abort prints it out
    if call_operand != '%rax':
        call_sled += '\tmovq\t{}, %rax\n'.format(call_operand)
    code, data =cdi_abort(sled_id_faucet(), funct.asm_filename, 
            dwarf_loc, False, options)
    call_sled += code
    abort_data.append(data)
    call_sled += '2:\n'
    # asm_dest.write(call_sled)
    funct_write = funct_write + call_sled
    return funct_write

        
cpp_whitelist = ['_Z41__static_initialization_and_destruction_0ii',
        '_GLOBAL__sub_I__Z3barv']

def convert_return_site(site, funct, asm_line, asm_dest, cfg,
        sled_id_faucet, abort_data, dwarf_loc, options):
    # don't fix 'main' in this version
    funct_write = ''
    if (funct.asm_name == 'main' or 
            funct.asm_name == '_Z41__static_initialization_and_destruction_0ii' or
            funct.asm_name[:len('_GLOBAL__sub_I__')] == '_GLOBAL__sub_I__'):
        # asm_dest.write(asm_line)
        funct_write = funct_write + asm_line
        return funct_write

    # constructors/destructors run before/after main so they do not need to be
    # fixed up, at least for this version
    if funct.ftype.mangled_str == '(CON/DE)STRUCTOR':
        # asm_dest.write(asm_line)
        funct_write = funct_write + asm_line
        return funct_write

    # PROFILE: Extract sled execution counts
    # If '--profile_use' is supplied sorted_sled is sleds sorted in descending order of execution count
    # Else sorted_sleds is just list of generated sled labels
    if options['profile_use']:
        profile_file = options.get('profile_use')
        sled_profile = obj_parse.load_obj(profile_file)
    
    cdi_ret_prefix = '_CDI_' + fix_label(funct.uniq_label) + '_TO_'

    ret_sled = '\taddq $8, %rsp\n'

    sled_count = {}
    sled_labels = []
    for target_label, multiplicity in site.targets.iteritems(): # PROFILE: generate all sleds of the return site
        i = 1
        while i <= multiplicity:
            sled_label = '"{}{}_{}"'.format(cdi_ret_prefix, fix_label(target_label), str(i))
            if options['profile_use']:
                sled_count[sled_label] = sled_profile[sled_label]
            else:
                sled_labels.append(sled_label)
            i += 1

    # PROFILE: sort sled labels on decreasing order of excution count
    if options['profile_use']:
        sorted_sled = sorted(sled_count, key=sled_count.get, reverse=True)
    else:
        sorted_sled = sled_labels


    for sl_lbl in sorted_sled:
        ret_sled += '\tcmpq\t$' + sl_lbl + ', -8(%rsp)\n'
        ret_sled += '\tje\t' + sl_lbl + '\n'


    if options['--shared-library']:
        # TODO: implement callback sled for shared library
        ret_sled += '\tjmp\t"_CDI_SLT_{}"\n'.format(fix_label(funct.uniq_label))
    else:
        code, data = cdi_abort(sled_id_faucet(), funct.asm_filename,
                dwarf_loc, True, options)
        ret_sled += code
        abort_data.append(data)

    # asm_dest.write(ret_sled)
    funct_write = funct_write + ret_sled
    return funct_write

def convert_indir_jmp_site(site, funct, asm_line, asm_dest):
    pass

def cdi_abort(sled_id, asm_filename, dwarf_loc, try_callback_sled, options):
    """Return (code, data) that allows for aborting with sled-specific info.
    
    Code should be placed at the end of a return/call sled. data should be 
    placed away from code so that the verifier works correctly.
    """

    loc_str = asm_filename.replace('.fake.o', '.cdi.s')
    if dwarf_loc.valid():
        loc_str = '{}:{}/{}'.format(str(dwarf_loc), os.path.basename(os.getcwd()), loc_str)

    cdi_abort_code = cdi_abort_data = ''
    if options['--shared-library']:
        eprint('cdi-ld: error: --shared-library unsupported in this version')
        sys.exit(1)
        cdi_abort_code += '\tmovq\t.CDI_sled_id_' + str(sled_id) + '(%rip), %rsi\n'
        cdi_abort_code += '\tmovq\t.CDI_sled_id_' + str(sled_id) +'_len(%rip), %rdx\n'
        #cdi_abort_code += '\tcall\t_CDI_abort\n' TODO: write fpic version of cdi abort

        cdi_abort_data += '.CDI_sled_id_' + str(sled_id) + ':\n'
        cdi_abort_data += '\t.string\t"' + loc_str + ' id=' + str(sled_id) + '"\n'
        cdi_abort_data += '\t.set\t.CDI_sled_id_' + str(sled_id) + '_len, '
        cdi_abort_data += '.-.CDI_sled_id_' + str(sled_id) + '\n'
    else:
        if options['--sl-fptr-addrs'] and try_callback_sled:
            cdi_abort_code += '\tmovq\t $.CDI_sled_id_' + str(sled_id) + ', %r11\n'
            cdi_abort_code += '\tjmp\t_CDI_callback_sled\n'
        else:
            cdi_abort_code += '\tmovq\t $.CDI_sled_id_' + str(sled_id) + ', %rsi\n'
            cdi_abort_code += '\tcall\t_CDI_abort\n'

        cdi_abort_msg = loc_str + ' id=' + str(sled_id)
        cdi_abort_data += '.CDI_sled_id_' + str(sled_id) + ':\n'
        cdi_abort_data += '\t.quad\t' + str(len(cdi_abort_msg)) + '\n'
        cdi_abort_data += '\t.string\t"' + cdi_abort_msg + '"\n'

    return (cdi_abort_code, cdi_abort_data)

def convert_plt_site(site, asm_line, funct, asm_dest):
    funct_write = ''
    if not hasattr(funct, 'plt_call_multiplicity'):
        funct.plt_call_multiplicity = dict()

    try:
        funct.plt_call_multiplicity[(site.targets[0], funct.uniq_label)] += 1
    except KeyError:
        funct.plt_call_multiplicity[(site.targets[0], funct.uniq_label)] = 1

    # create label for RLT to return to
    rlt_return_label = ('"_CDI_{}_TO_{}_{}"'
            .format(fix_label(site.targets[0]), fix_label(funct.uniq_label), 
                str(funct.plt_call_multiplicity[(site.targets[0], funct.uniq_label)])))

    #globl_decl = '.globl\t' + rlt_return_label + '\n'
    globl_decl = ''
    restore_rbp = '\tmovq\t-16(%rsp), %rbp\n'

    # do not restore rbp because shared libraries are not working yet
    # asm_dest.write(asm_line + globl_decl + rlt_return_label + ':\n') # + restore_rbp)
    funct_write = funct_write + asm_line + globl_decl + rlt_return_label + ':\n'
    return funct_write

def write_rlts(cfg, plt_sites, asm_dest, sled_id_faucet, options):
    """Write the RLT to asm_dest"""

    # maps (shared library uniq label, rlt return target) -> multiplicity
    multiplicity = dict()

    # maps shared library uniq label -> set of potential functions to which to return
    rlt_return_targets = dict()

    # populate the multiplicity and rlt_return_targets dicts
    for plt_site in plt_sites:
        call_return_pair = (plt_site.targets[0], plt_site.enclosing_funct_uniq_label)

        if plt_site.targets[0] not in rlt_return_targets:
            rlt_return_targets[plt_site.targets[0]] = set()
        rlt_return_targets[call_return_pair[0]].add(call_return_pair[1])

        try:
            multiplicity[call_return_pair] += 1
        except KeyError:
            multiplicity[call_return_pair] = 1

    # create the RLT jump table
    # TEMPORARILY REMOVED UNTIL MISIKER TELLS ME THE FIX:
    # rlt_jump_table = '\t.section\t.CDI_RLT, "x"\n'
    rlt_jump_table = '\t.type\t_CDI_RLT_JUMP_TABLE, @function\n'
    rlt_jump_table += '_CDI_RLT_JUMP_TABLE:\n'
    for sl_funct_uniq_label in rlt_return_targets.keys():
        entry_label = '"_CDI_RLT_{}"'.format(fix_label(sl_funct_uniq_label))
        rlt_jump_table += '\tjmp {}\n'.format(entry_label)

    rlt_jump_table += '\t.size\t_CDI_RLT_JUMP_TABLE, .-_CDI_RLT_JUMP_TABLE\n'
    
    asm_dest.write(rlt_jump_table)

    # create an RLT entry for each shared library function
    for sl_funct_uniq_label, rlt_target_set in rlt_return_targets.iteritems():
        rlt_entry = ''

        entry_label = '"_CDI_RLT_{}"'.format(fix_label(sl_funct_uniq_label))

        asm_dest.write('\t.type {}, @function\n'.format(entry_label))
        asm_dest.write(entry_label + ':\n')

        # Add sled entries for each RLT target
        for rlt_target in rlt_target_set:
            cdi_ret_prefix = '_CDI_' + fix_label(sl_funct_uniq_label)
            i = 1
            while i <= multiplicity[(sl_funct_uniq_label, rlt_target)]:
                sled_label = '"{}_TO_{}_{}"'.format(cdi_ret_prefix, fix_label(rlt_target) , str(i))
                if options['--shared-library']:
                    # rbp is restored after the jump equal (je)
                    rlt_entry += '\tlea\t' + sled_label + '(%rip), %rbp\n'
                    rlt_entry += '\tcmpq\t%rbp, -8(%rsp)\n'
                else:
                    rlt_entry += '\tcmpq\t$' + sled_label + ', -8(%rsp)\n'
                rlt_entry += '\tje\t' + sled_label + '\n'
                i += 1

        code, data = cdi_abort(sled_id_faucet(), '',
            asm_parsing.DwarfSourceLoc(), False, options)
        rlt_entry += code + data
        rlt_entry += '\t.size {}, .-{}\n'.format(entry_label, entry_label)
        asm_dest.write(rlt_entry)

def write_callback_sled(asm_dest, options):
    callback_sled = '.globl _CDI_callback_sled\n'
    callback_sled += '_CDI_callback_sled:\n'

    # the callback table is in the following format:
    #
    # "/path/to/library.so" load-addr: 0xADDRESS
    # fptr address 1
    # fptr address 2
    # ...
    #
    # "/path/to/library2.so" load-addr: 0xADDRESS
    # ...
    #
    #
    # The end of a library is indicated by two consecutive newlines

    # populated with pairs of (library metadata, list of fptrs)
    fptr_table = []
    with open(options['--sl-fptr-addrs'], 'r') as callback_table:
        lines = iter(callback_table)
        for lib_metadata in lines:
            lib_fptrs = []
            line = lines.next()
            while line != '\n':
                lib_fptrs.append(line.rstrip())
                line = lines.next()
            fptr_table.append((lib_metadata.rstrip(), lib_fptrs))

    for lib_metadata, fptrs in fptr_table:
        upper_to_lower_addrs = dict()
        for addr in fptrs:
            lower_addr = '0x' + addr[-8:]
            upper_addr = addr[:-8]
            try:
                upper_to_lower_addrs[upper_addr].append(lower_addr)
            except KeyError:
                upper_to_lower_addrs[upper_addr] = [lower_addr]

        callback_sled += '/* {} */\n'.format(lib_metadata)
        for upper_addr, lower_addrs in upper_to_lower_addrs.iteritems():
            callback_sled += '\tcmpl\t$'+upper_addr+', -4(%rsp)\n'
            callback_sled += '\tjne\t1f\n'
            for addr in lower_addrs:
                callback_sled += '\tcmpl\t$'+addr+', -8(%rsp)\n'
                callback_sled += '\tjne\t2f\n'
                callback_sled += '\tmov\t$'+upper_addr+addr[2:]+', %r11\n'
                callback_sled += '\tjmp\t*%r11\n'
                callback_sled += '2:\n'
            callback_sled += '1:\n'
    callback_sled += '\tmovq\t-8(%rsp), %rax\n'
    callback_sled += '\tmovq\t%r11, %rsi\n'
    callback_sled += '\tcall _CDI_abort\n'
    asm_dest.write(callback_sled)

def fix_label(label):
    return label.replace('@', '_AT_').replace('/', '__').replace('.fake.o', '.cdi.s')

