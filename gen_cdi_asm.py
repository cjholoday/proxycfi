import control_flow_graph
import operator

def gen_cdi_asm(cfg, asm_file_descrs):
    """Writes cdi compliant assembly from cfg and assembly file descriptions"""

    for descr in asm_file_descrs:
        asm_src = open(descr.name, 'r')
        asm_dest = open('cdi_' + descr.name, 'w')

        functs = sorted(map(cfg.funct, descr.funct_names), key=operator.attrgetter('line_num'))

        src_line_num = 0
        for funct in functs:
            for site in funct.sites:
                num_lines_to_write = site.line_num - src_line_num - 1
                write_lines(num_lines_to_write, asm_src, asm_dest)

                line_to_fix = asm_src.readline()
                src_line_num = site.line_num
                
                convert_to_cdi(site, funct, line_to_fix, asm_dest)

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

def convert_to_cdi(site, funct, asm_line, asm_dest):
    """Converts asm_line to cdi compliant code then writes it to asm_dest"""
    pass
