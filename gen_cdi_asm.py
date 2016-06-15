import control_flow_graph
from control_flow_graph import Site
import operator
import asm_parsing

def gen_cdi_asm(cfg, asm_file_descrs):
    """Writes cdi compliant assembly from cfg and assembly file descriptions"""

    for descr in asm_file_descrs:
        asm_src = open(descr.name, 'r')
        asm_dest = open('cdi_' + descr.name, 'w')

        functs = sorted(map(cfg.funct, descr.funct_names), key=operator.attrgetter('line_num'))

        src_line_num = 0
        for funct in functs:
            funct.label_to_times_fixed = dict()
            for site in funct.sites:
                num_lines_to_write = site.line_num - src_line_num - 1
                write_lines(num_lines_to_write, asm_src, asm_dest)

                line_to_fix = asm_src.readline()
                src_line_num = site.line_num
                
                convert_to_cdi(site, funct, line_to_fix, asm_dest,
                        lambda funct_name: funct_name in descr.funct_names)

        # write the rest of the lines over
        src_line = asm_src.readline()
        while src_line:
            asm_dest.write(src_line)
            src_line = asm_src.readline()

        asm_src.close()
        asm_dest.close()
            

def write_lines(num_lines, asm_src, asm_dest):
    """Writes from file obj asm_src to file obj asm_dest num_lines lines"""
    i = 0
    while i < num_lines:
        asm_dest.write(asm_src.readline())
        i += 1

def convert_to_cdi(site, funct, asm_line, asm_dest, funct_name_in_same_file):
    """Converts asm_line to cdi compliant code then writes it to asm_dest"""

    if site.site_type == Site.CALL_SITE:
        convert_call_site(site, funct, asm_line, asm_dest, funct_name_in_same_file)
    elif site.site_type == Site.RETURN_SITE:
        convert_return_site(site, funct, asm_line, asm_dest)
    elif site.site_type == Site.INDIR_JMP_SITE:
        convert_indir_jmp_site(site, funct, asm_line, asm_dest)
    else:
        assert site.site_type == Site.INVALID_SITE
        eprint('WARNING: Site has invalid type!')


def convert_call_site(site, funct, asm_line, asm_dest, funct_name_in_same_file):
    arg_str = asm_parsing.decode_line(asm_line, False)[2]

    indirect_call = '%' in arg_str
    if not indirect_call:
        assert len(site.targets) == 1
        target_name = site.targets[0]
        times_fixed = get_times_fixed_and_increment(target_name, funct)
        label = '_CDI_' + target_name + '_TO_' + funct.name + '_' + str(times_fixed)

        globl_decl = ''
        if not funct_name_in_same_file(target_name):
            globl_decl = '.globl\t' + label + '\n'

        asm_dest.write(asm_line + globl_decl + label + ':\n')
        return
    

    call_sled = ''
    assert len(arg_str.split()) == 1

    for target_name in site.targets:
        call_operand = arg_str.replace('*', '')
        times_fixed = get_times_fixed_and_increment(target_name, funct)

        return_label = '_CDI_' + target_name + '_TO_' + funct.name + '_' + str(times_fixed)

        globl_decl = ''
        if not funct_name_in_same_file(target_name):
            globl_decl = '.globl\t' + return_label + '\n'

        call_sled += '1:\n'
        call_sled += '\tcmpq\t$' + target_name + ', ' + call_operand + '\n'
        call_sled += '\tjne\t1f\n'
        call_sled += '\tcall\t' + target_name + '\n'
        call_sled += globl_decl
        call_sled += return_label + ':\n'
        call_sled += '\tjmp\t2f\n'

    call_sled += '1:\n'
    call_sled += '\tjmp 1b\n'
    call_sled += '2:\n'
    asm_dest.write(call_sled)
        
def get_times_fixed_and_increment(target_name, funct):
    if target_name in funct.label_to_times_fixed:
        funct.label_to_times_fixed[target_name] += 1
    else:
        funct.label_to_times_fixed[target_name] = 1

    return funct.label_to_times_fixed[target_name]


    
def convert_return_site(site, funct, asm_line, asm_dest):
    cdi_ret_prefix = '_CDI_' + funct.name + '_TO_'

    ret_sled= '\taddq $8, %rsp\n' + '\t2:\n'

    for target_name, multiplicity in site.targets.iteritems():
        i = 1
        while i <= multiplicity:
            target_label = cdi_ret_prefix + target_name + '_' + str(i)
            ret_sled += '\tcmpq\t$' + target_label + ', -8(%rsp)\n'
            ret_sled += '\tje\t' + target_label + '\n'
            i += 1

    ret_sled += '\tjmp\t 2b\n'
    asm_dest.write(ret_sled)


def convert_indir_jmp_site(site, funct, asm_line, asm_dest):
    pass

