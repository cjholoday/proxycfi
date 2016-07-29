#!/usr/bin/env python

import sys
import asm_parsing
import jsonpickle
from gen_cfg import gen_cfg
from gen_cdi_asm import gen_cdi_asm

class Options:
    def __init__(self):
        self.verbose = False
        self.profile = False
        self.use_profile = False
        # if true, sled id will be printed on unsafe movement
        self.debug_mode = False 

############################
# Script
############################

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Usage: ./gen_cdi.py <asm_file1> <asm_file2> ... <asm_fileN>"

    # temporary defaults
    options = Options()
    options.verbose = True
    options.profile = False
    options.use_profile = False
    options.debug_mode = True

    asm_filenames = sys.argv[1:]
    asm_file_descrs = []
    for filename in asm_filenames:
        asm_file_descrs.append(asm_parsing.AsmFileDescription(filename))
        asm_file_descrs[-1].check_filename()

    cfg = gen_cfg(asm_file_descrs, options)
    cfg.print_json_to('cdi_cfg.json')

    gen_cdi_asm(cfg, asm_file_descrs, options)
