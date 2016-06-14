import sys
import asm_parsing
import jsonpickle
from gen_cfg import gen_cfg
from gen_cdi_asm import gen_cdi_asm

############################
# Script
############################

def print_cfg_as_json(cfg):
    with open('cdi_cfg.json', 'w') as cfg_file:
        encoding = jsonpickle.encode(cfg)
        cfg_file.write(encoding)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Usage: ./gen_cdi.py <asm_file1> <asm_file2> ... <asm_fileN>"

    asm_filenames = sys.argv[1:]
    asm_file_descrs = []
    for filename in asm_filenames:
        asm_file_descrs.append(asm_parsing.AsmFileDescription(filename))

    cfg = gen_cfg(asm_file_descrs)
    print_cfg_as_json(cfg)

    gen_cdi_asm(cfg, asm_file_descrs)
