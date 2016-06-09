import control_flow_graph

def gen_cdi_asm(cfg, asm_file_descrs):
    """Writes cdi compliant assembly from cfg and assembly file descriptions"""

    for descr in asm_file_descrs:
        asm_src = open(descr.name, 'r')
        asm_dest = open('cdi_' + descr.name, 'w')

        functs = sorted(map(cfg.funct, descr.funct_names))
        
        src_line_num = 0
        for funct in functs:
            for site in funct.sites:
                # write lines from src to dest until site.line_num
                # fixup site
                pass

        asm_src.close()
        asm_dest.close()
            

def write_lines(num_lines, asm_src, asm_dest):
    """Writes from file obj asm_src to file obj asm_dest num_lines lines"""
    pass

def convert_to_cdi(site, funct, asm_line, asm_dest):
    """Converts asm_line to cdi compliant code then writes it to asm_dest"""
    pass
