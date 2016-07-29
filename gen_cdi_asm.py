import funct_cfg
import operator
import asm_parsing

def gen_cdi_asm(cfg, asm_file_descrs, options):
    """Writes cdi compliant assembly from cfg and assembly file descriptions"""

    sled_id_faucet = funct_cfg.SledIdFaucet()

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
            asm_dest.write('.globl\t' + funct.uniq_label + '\n')
            asm_dest.write(funct.uniq_label + ':\n')

            funct.label_fixed_count = dict()
            for site in funct.sites:
                num_lines_to_write = site.asm_line_num - asm_line_num
                write_lines(num_lines_to_write, asm_src, asm_dest, dwarf_loc)

                line_to_fix = asm_src.readline()
                asm_line_num = site.asm_line_num + 1
                
                convert_to_cdi(site, funct, line_to_fix, asm_dest, cfg,
                        sled_id_faucet, dwarf_loc, options)
                        

        # write the rest of the lines over
        src_line = asm_src.readline()
        while src_line:
            asm_dest.write(src_line)
            src_line = asm_src.readline()

        asm_src.close()
        asm_dest.close()
            
def cdi_asm_name(asm_name):
    assert asm_name[-2:] == '.s'
    return asm_name[:-2] + '.cdi.s'

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
        asm_dest.write(asm_line)
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
        target_name = site.targets[0].uniq_label
        times_fixed = increment_dict(funct.label_fixed_count, target_name)
        label = '_CDI_' + target_name + '_TO_' + funct.uniq_label + '_' + str(times_fixed)

        globl_decl = ''
        if funct.asm_filename != site.targets[0].asm_filename:
            globl_decl = '.globl\t' + label + '\n'

        asm_dest.write(asm_line + globl_decl + label + ':\n')
        return
    

    call_sled = ''
    assert len(arg_str.split()) == 1

    for target in site.targets:
        target_name = target.uniq_label
        call_operand = arg_str.replace('*', '')
        times_fixed = increment_dict(funct.label_fixed_count, target_name)

        return_label = '_CDI_' + target_name + '_TO_' + funct.uniq_label 
        return_label += '_' + str(times_fixed)

        globl_decl = ''
        if funct.asm_filename != target.asm_filename:
            globl_decl = '.globl\t' + return_label + '\n'

        call_sled += '1:\n'
        call_sled += '\tcmpq\t$' + target_name + ', ' + call_operand + '\n'
        call_sled += '\tjne\t1f\n'
        call_sled += '\tcall\t' + target_name + '\n'
        call_sled += globl_decl
        call_sled += return_label + ':\n'
        call_sled += '\tjmp\t2f\n'

    call_sled += '1:\n'
    call_sled += cdi_exit_str(sled_id_faucet(), funct.asm_filename, 
            options.debug_mode, dwarf_loc)
    call_sled += '2:\n'
    asm_dest.write(call_sled)

        
def convert_return_site(site, funct, asm_line, asm_dest, cfg,
        sled_id_faucet, dwarf_loc, options):
    # don't fix 'main' in this version
    if funct.asm_name == 'main':
        asm_dest.write(asm_line)
        return

    cdi_ret_prefix = '_CDI_' + funct.uniq_label + '_TO_'

    ret_sled= '\taddq $8, %rsp\n'

    for target_label, multiplicity in site.targets.iteritems():
        i = 1
        while i <= multiplicity:
            sled_label = cdi_ret_prefix + target_label + '_' + str(i)
            ret_sled += '\tcmpq\t$' + sled_label + ', -8(%rsp)\n'
            ret_sled += '\tje\t' + sled_label + '\n'
            i += 1

    ret_sled += cdi_exit_str(sled_id_faucet(), funct.asm_filename,
            options.debug_mode, dwarf_loc)
    asm_dest.write(ret_sled)


def convert_indir_jmp_site(site, funct, asm_line, asm_dest):
    pass

def cdi_exit_str(sled_id, asm_filename, debug_mode, dwarf_loc):
    """Return string that exits from cdi code with a useful debug message"""

    loc_str = asm_filename
    if dwarf_loc.valid():
        loc_str = str(dwarf_loc) + ':' + loc_str

    call_cdi_exit = ''
    if debug_mode:
        call_cdi_exit += '\tmovq\t $.CDI_sled_id_' + str(sled_id) + ', %rsi\n'
        call_cdi_exit += '\tmovq\t$.CDI_sled_id_' + str(sled_id) +'_len, %rdx\n'
        call_cdi_exit += '\tcall\t_CDI_exit\n'
        call_cdi_exit += '.CDI_sled_id_' + str(sled_id) + ':\n'
        call_cdi_exit += '\t.string\t"' + loc_str + ' id=' + str(sled_id) + '"\n'
        call_cdi_exit += '\t.set\t.CDI_sled_id_' + str(sled_id) + '_len, '
        call_cdi_exit += '.-.CDI_sled_id_' + str(sled_id) + '\n'
    else:
        call_cdi_exit = '\tmovq\t$0, %rdx\n\tcall _CDI_exit\n'

    return call_cdi_exit

