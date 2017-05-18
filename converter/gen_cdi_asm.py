import funct_cfg
import operator
import asm_parsing
import subprocess
from eprint import eprint

def gen_cdi_asm(cfg, asm_file_descrs, plt_sites, options):
    """Writes cdi compliant assembly from cfg and assembly file descriptions"""

    sled_id_faucet = funct_cfg.SledIdFaucet()

    rlts_written = False
    slts_written = False
    for descr in asm_file_descrs:
        asm_parsing.DwarfSourceLoc.wipe_filename_mapping()
        dwarf_loc = asm_parsing.DwarfSourceLoc()
        asm_src = open(descr.filename, 'r')
        asm_dest = open(cdi_asm_name(descr.filename), 'w')
        descr_functs = [cfg.funct(descr.filename + '.' + n) for n in descr.funct_names]
        functs = sorted(descr_functs, key=operator.attrgetter('asm_line_num'))

        asm_line_num = 1
        for funct in functs:
            num_lines_to_write = funct.asm_line_num - asm_line_num
            write_lines(num_lines_to_write, asm_src, asm_dest, dwarf_loc)
            asm_line_num = funct.asm_line_num

            # unique labels are always global so that even static functions
            # can be reached from anywhere with sleds (Function pointers can
            # point to ANY function with the same signature, even static 
            # functions in a different translation unit)
            asm_dest.write('.globl\t"{}"\n'.format(fix_label(funct.uniq_label)))
            asm_dest.write('"{}":\n'.format(fix_label(funct.uniq_label)))

            funct.label_fixed_count = dict()
            for site in funct.sites:
                num_lines_to_write = site.asm_line_num - asm_line_num
                write_lines(num_lines_to_write, asm_src, asm_dest, dwarf_loc)

                line_to_fix = asm_src.readline()
                asm_line_num = site.asm_line_num + 1
                
                convert_to_cdi(site, funct, line_to_fix, asm_dest, cfg,
                        sled_id_faucet, dwarf_loc, options)
                        


        # write the rest of the normal asm lines over
        src_line = asm_src.readline()
        while src_line:
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
            
def cdi_asm_name(asm_name):
    if asm_name.endswith('.fake.o'):
        return asm_name[:-1 * len('.fake.o')] + '.cdi.s'
    elif asm_name.endswith('.s'):
        return asm_name[:-2] + '.cdi.s'
    else:
        assert False

def write_lines(num_lines, asm_src, asm_dest, dwarf_loc):
    """Writes from file obj asm_src to file obj asm_dest num_lines lines"""
    i = 0
    while i < num_lines:
        asm_line = asm_src.readline()
        asm_parsing.update_dwarf_loc(asm_line, dwarf_loc)
        asm_dest.write(asm_line)
        i += 1

def convert_to_cdi(site, funct, asm_line, asm_dest, cfg, 
        sled_id_faucet, dwarf_loc, options):
    """Converts asm_line to cdi compliant code then writes it to asm_dest"""

    if site.group == site.CALL_SITE:
        convert_call_site(site, funct, asm_line, asm_dest, 
                sled_id_faucet, dwarf_loc, options)
    elif site.group == site.RETURN_SITE:
        convert_return_site(site, funct, asm_line, asm_dest, cfg, 
                sled_id_faucet, dwarf_loc, options)
    elif site.group == site.INDIR_JMP_SITE:
        convert_indir_jmp_site(site, funct, asm_line, asm_dest)
    elif site.group == site.PLT_SITE:
        convert_plt_site(site, asm_line, funct, asm_dest)
    else:
        eprint('warning: site has invalid type: line ' + site.asm_line_num, 
                'in function named \'' + funct.asm_name + '\'')

def increment_dict(dictionary, key, start = 1):
    dictionary[key] = dictionary.get(key, start - 1) + 1
    return dictionary[key]

def convert_call_site(site, funct, asm_line, asm_dest, 
        sled_id_faucet, dwarf_loc, options):

    arg_str = asm_parsing.decode_line(asm_line, False)[2]

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

        asm_dest.write(asm_line + globl_decl + label + ':\n')
        return
    

    call_sled = ''
    assert len(arg_str.split()) == 1

    for target in site.targets:
        target_name = fix_label(target.uniq_label)
        return_target = fix_label(funct.uniq_label)
        call_operand = arg_str.replace('*', '')
        times_fixed = increment_dict(funct.label_fixed_count, target_name)

        return_label = '_CDI_' + target_name + '_TO_' + funct.uniq_label 
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
    call_sled += cdi_abort_str(sled_id_faucet(), funct.asm_filename, 
            dwarf_loc, options)
    call_sled += '2:\n'
    asm_dest.write(call_sled)

        
cpp_whitelist = ['_Z41__static_initialization_and_destruction_0ii',
        '_GLOBAL__sub_I__Z3barv']

def convert_return_site(site, funct, asm_line, asm_dest, cfg,
        sled_id_faucet, dwarf_loc, options):
    # don't fix 'main' in this version
    if (funct.asm_name == 'main' or 
            funct.asm_name == '_Z41__static_initialization_and_destruction_0ii' or
            funct.asm_name[:len('_GLOBAL__sub_I__')] == '_GLOBAL__sub_I__'):
        asm_dest.write(asm_line)
        return

    cdi_ret_prefix = '_CDI_' + fix_label(funct.uniq_label) + '_TO_'

    ret_sled= '\taddq $8, %rsp\n'

    for target_label, multiplicity in site.targets.iteritems():
        i = 1
        while i <= multiplicity:
            sled_label = '"{}{}_{}"'.format(cdi_ret_prefix, fix_label(target_label), str(i))
            ret_sled += '\tcmpq\t$' + sled_label + ', -8(%rsp)\n'
            ret_sled += '\tje\t' + sled_label + '\n'
            i += 1

    if options['--shared-library']:
        ret_sled += '\tjmp\t"_CDI_SLT_{}"\n'.format(fix_label(funct.uniq_label))
    else:
        ret_sled += cdi_abort_str(sled_id_faucet(), funct.asm_filename,
                dwarf_loc, options)

    asm_dest.write(ret_sled)

def convert_indir_jmp_site(site, funct, asm_line, asm_dest):
    pass

def cdi_abort_str(sled_id, asm_filename, dwarf_loc, options):
    """Return string that aborts from cdi code with a useful debug message"""

    loc_str = asm_filename
    if dwarf_loc.valid():
        loc_str = str(dwarf_loc) + ':' + loc_str

    
    call_cdi_abort = ''
    if options['--shared-library']:
        call_cdi_abort += '\tmovq\t.CDI_sled_id_' + str(sled_id) + '(%rip), %rsi\n'
        call_cdi_abort += '\tmovq\t.CDI_sled_id_' + str(sled_id) +'_len(%rip), %rdx\n'
        #call_cdi_abort += '\tcall\t_CDI_abort\n' TODO: write fpic version of cdi abort
        call_cdi_abort += '.CDI_sled_id_' + str(sled_id) + ':\n'
        call_cdi_abort += '\t.string\t"' + loc_str + ' id=' + str(sled_id) + '"\n'
        call_cdi_abort += '\t.set\t.CDI_sled_id_' + str(sled_id) + '_len, '
        call_cdi_abort += '.-.CDI_sled_id_' + str(sled_id) + '\n'
    else:
        call_cdi_abort += '\tmovq\t $.CDI_sled_id_' + str(sled_id) + ', %rsi\n'
        call_cdi_abort += '\tmovq\t$.CDI_sled_id_' + str(sled_id) +'_len, %rdx\n'
        call_cdi_abort += '\tcall\t_CDI_abort\n'
        call_cdi_abort += '.CDI_sled_id_' + str(sled_id) + ':\n'
        call_cdi_abort += '\t.string\t"' + loc_str + ' id=' + str(sled_id) + '"\n'
        call_cdi_abort += '\t.set\t.CDI_sled_id_' + str(sled_id) + '_len, '
        call_cdi_abort += '.-.CDI_sled_id_' + str(sled_id) + '\n'

    return call_cdi_abort

def convert_plt_site(site, asm_line, funct, asm_dest):
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
    asm_dest.write(asm_line + globl_decl + rlt_return_label + ':\n') # + restore_rbp)

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
                print rlt_target
                print fix_label(rlt_target)
                sled_label = '"{}_TO_{}_{}"'.format(cdi_ret_prefix, fix_label(rlt_target) , str(i))
                if options['--shared-library']:
                    # rbp is restored after the jump equal (je)
                    rlt_entry += '\tlea\t' + sled_label + '(%rip), %rbp\n'
                    rlt_entry += '\tcmpq\t%rbp, -8(%rsp)\n'
                else:
                    rlt_entry += '\tcmpq\t$' + sled_label + ', -8(%rsp)\n'
                rlt_entry += '\tje\t' + sled_label + '\n'
                i += 1

        rlt_entry += cdi_abort_str(sled_id_faucet(), '',
            asm_parsing.DwarfSourceLoc(), options)
        rlt_entry += '\t.size {}, .-{}\n'.format(entry_label, entry_label)
        asm_dest.write(rlt_entry)

def fix_label(label):
    return label.replace('@', '_AT_').replace('/', '__')
