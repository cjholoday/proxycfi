import sys
from asm_file_description import AsmFileDescription
from gen_cfg import gen_cfg

############################
# Script
############################

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Usage: ./gen_cdi.py <asm_file1> <asm_file2> ... <asm_fileN>"

    asm_filenames = sys.argv[1:]
    asm_file_descr = []
    for filename in asm_filenames:
        asm_file_descr.append(AsmFileDescription(filename))

    cfg = gen_cfg(asm_file_descr)

    # write second batch of .s files
