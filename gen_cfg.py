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

    # build return dictionaries
    for funct in cfg:
        call_dict = dict()
        for site in funct.sites:
            if site.site_type == Site.CALL_SITE:
                for label in site.targets:
                    if label in call_dict:
                        call_dict[label] += 1
                    else:
                        call_dict[label] = 1
        for target_label, multiplicity in call_dict.iteritems():
            cfg.funct(target_label).return_dict[funct.name] = multiplicity

    return cfg


def extract_funct(asm_file):
    """Constructs a function from the assembly file. 

    File pointer must point at first instruction of the function
    """
    pass
