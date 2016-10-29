#!/usr/bin/env python

import argparse
import sys
import asm_parsing
import jsonpickle
from gen_cfg import gen_cfg
from gen_cdi_asm import gen_cdi_asm
from eprint import eprint


############################
# Script
############################

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=
            'Convert N assembly files to N cdi-compliant assembly files')
    parser.add_argument('asm_filenames', nargs='+', 
            help='filenames of assembly files to be converted to CDI')
    parser.add_argument('--no-abort-messages', action='store_true',
            help='if set, abort location won\'t be printed. Saves space',
            dest='--no-abort-messages')
    parser.add_argument('-v', '--verbose', action='store_true',
            help='prints out extra information', dest='--verbose')
    parser.add_argument('-pg', '--profile-gen', metavar='PROFILE',
            help='generates a profile for use next time in compilation. TODO',
            dest='--profile-gen', default='')
    parser.add_argument('-pu', '--profile-use', type=str, metavar='PROFILE',
            help='uses profile data to optimize the CDI sleds. TODO',
            dest='--profile-use', default='')
    parser.add_argument('-nn', '--no-narrowing', action='store_true',
            help='if set, sleds won\'t be narrowed based on type signature',
            dest='--no-narrowing')

    options = vars(parser.parse_args(sys.argv[1:]))
    if options.get('--help'):
        sys.exit(0)

    asm_filenames = options['asm_filenames']
    asm_file_descrs = []
    for filename in asm_filenames:
        asm_file_descrs.append(asm_parsing.AsmFileDescription(filename))
        asm_file_descrs[-1].check_filename()

    cfg = gen_cfg(asm_file_descrs, options)
    cfg.print_json_to('cdi_cfg.json')

    gen_cdi_asm(cfg, asm_file_descrs, options)
