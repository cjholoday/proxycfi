import control_flow_graph
import asm_file_sig

def gen_cfg(asm_file_sigs):
    """Generate cfg from a list of asm_files. Produce funct names for each sig

    asm_files should be a list containing objects of type 'AsmFile'
    """

    cfg = control_flow_graph.ControlFlowGraph()
    for sig in asm_file_sigs:
        asm_file = open(sig.name, 'r')

        done = goto_next_funct(asm_file)
        while not done:
            funct = extract_funct(asm_file)

            cfg.add_funct(funct)
            sig.funct_names.append(funct.name)

            done = goto_next_funct(asm_file)

    return cfg

def goto_next_funct(asm_file):
    """Moves file pointer to next funct label. Return true if no functs left"""

    return True

def extract_funct(asm_file):
    """Constructs a function from the assembly file. Begins at label of funct

    The asm_file pointer must point to the label of the function
    """
    pass
