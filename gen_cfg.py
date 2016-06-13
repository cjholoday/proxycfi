import control_flow_graph
import asm_parsing

def gen_cfg(asm_file_descrs):
    """Generate cfg from a list of asm_files. Produce funct names for each description

    asm_files should be a list containing objects of type 'AsmFile'
    """

    cfg = control_flow_graph.ControlFlowGraph()
    for descr in asm_file_descrs:
        asm_file = open(descr.name, 'r')

        func_name = asm_parsing.goto_next_funct(asm_file)
        
        while func_name:
            funct = extract_funct(asm_file, func_name)

            cfg.add_funct(funct)
            descr.funct_names.append(funct.name)

            func_name = asm_parsing.goto_next_funct(asm_file)

        asm_file.close()

    # build return dictionaries
    for funct in cfg:
        call_dict = dict()
        for site in funct.sites:
            if site.site_type == site.CALL_SITE:
                for label in site.targets:
                    if label in call_dict:
                        call_dict[label] += 1
                    else:
                        call_dict[label] = 1
        for target_label, multiplicity in call_dict.iteritems():
            cfg.funct(target_label).return_dict[funct.name] = multiplicity

    return cfg



def extract_funct(asm_file, func_name):
    """Constructs a function from the assembly file. 


    File pointer must point at first instruction of the function
    """
    call_list = ["call","callf", "callq"]
    returns = ["ret", "retf", "iret", "retq", "iretq"]
    jmp_list = ["jo","jno","jb","jnae","jc","jnb","jae","jnc","jz","je","jnz",
                "jne","jbe","jna","jnbe","ja","js","jns","jp","jpe","jnp","jpo","jl",
                "jnge","jnl","jge","jle","jng","jnle","jg","jecxz","jrcxz","jmp","jmpe"]
    func_line = 0
    asm_line = asm_file.readline()
    first_word = asm_line.split()[0]
    comment_continues = False
    Sites = []
    return_dict = dict()
    print func_name
    while asm_line:
        first_word = asm_line.split()[0]
        if (first_word[:len('.LFE')] == '.LFE'):
            break
        targets = []
        labels, key_symbol, arg_str, comment_continues = asm_parsing.decode_line(asm_line, comment_continues)
        if key_symbol in call_list:
            targets.append(arg_str)
            Sites.append(control_flow_graph.Site(func_line, targets, 0))
        elif key_symbol in returns:
            Sites.append(control_flow_graph.Site(func_line, targets, 1))
        elif key_symbol in jmp_list:
            if '%' in arg_str:
                Sites.append(control_flow_graph.Site(func_line, targets, 2))
        asm_line = asm_file.readline()
        func_line += 1

    return control_flow_graph.Function(func_name, Sites, return_dict)
    
