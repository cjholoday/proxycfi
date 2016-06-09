import control_flow_graph
import asm_parsing

def gen_cfg(asm_file_descrs):
    """Generate cfg from a list of asm_files. Produce funct names for each description

    asm_files should be a list containing objects of type 'AsmFile'
    """

    cfg = control_flow_graph.ControlFlowGraph()
    for descr in asm_file_descrs:
        asm_file = open(descr.name, 'r')

        done = asm_parsing.goto_next_funct(asm_file)
        while not done:
            funct = extract_funct(asm_file)

            cfg.add_funct(funct)
            descr.funct_names.append(funct.name)

            done = asm_parsing.goto_next_funct(asm_file)

        asm_file.close()

    return cfg


def extract_funct(asm_file):
    """Constructs a function from the assembly file. Begins at label of funct

    The asm_file pointer must point to the label of the function
    """
    pass
