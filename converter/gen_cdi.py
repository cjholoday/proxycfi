#!/usr/bin/env python

import __init__
import sys
import argparse

import asm_parsing
import jsonpickle

from gen_cfg import gen_cfg
from gen_cdi_asm import gen_cdi_asm
from common.eprint import eprint
from common.eprint import vprint
import common


############################
# Script
############################

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=
            'Convert N assembly files to N cdi-compliant assembly files')
    parser.add_argument('asm_filenames', nargs='+', 
            help='filenames of assembly files to be converted to CDI')
    parser.add_argument('-v', '--verbose', action='store_true',
            help='prints out extra information', dest='--verbose')
    parser.add_argument('-pg', '--profile-gen', action='store_true',
            help='generates a profile for use next time in compilation.',
            dest='--profile-gen')
    parser.add_argument('-pu', '--profile-use', type=str, metavar='PROFILE',
            help='uses profile data to optimize the CDI sleds.',
            dest='--profile-use', default='')
    parser.add_argument('-sl', '--shared-library', action='store_true',
            help='if set, generate code for use as a CDI shared library',
            dest='--shared-library')
    # TODO implement this functionality
    parser.add_argument('-t', '--test', action='store', 
            metavar='/path/to/file1.c:funct1 /path/to/file2.c:funct2',
            help='tells the converter to set the return address of funct1 to funct2+offset\n'
            'format: /path/to/file1.c:funct1 /path/to/file2.c:funct2+offset',
            dest='--test')
    parser.add_argument('-s', '--sl-fptr-addrs', action='store', 
            metavar='sl_callback_table',
            default='',
            help='a file containing fptr addresses that may jump from shared libs to executable code',
            dest='--sl-fptr-addrs')
    parser.add_argument('-nm', '--no-mystery-types', action='store_true',
            help='if set, manglings must not contain unknown types',
            dest='--no-mystery-types')
    parser.add_argument('-np', '--no-fp-punt', action='store_true',
            help='if set, function pointers must associated witha a type',
            dest='--no-fp-punt')
    parser.add_argument('--no-plt', action='store_true',
            help='if set, all functions must be static',
            dest='--no-plt')
    parser.add_argument('--log', action='store',
            help='if set, all non fatal output will go to the given file',
            dest='--log')
    parser.add_argument('--quiet', action='store_true',
            help='if set, supress all non fatal output',
            dest='--quiet')

    options = vars(parser.parse_args(sys.argv[1:]))
    if options.get('--help'):
        sys.exit(0)

    if options['--log']:
        common.eprint.STDOUT = common.eprint.STDERR = open(options['--log'], 'a')
    if options.get('--quiet'):
        common.eprint.VERBOSE = False
    
    asm_filenames = options['asm_filenames']
    asm_file_descrs = []
    for filename in asm_filenames:
        vprint(filename)
        asm_file_descrs.append(asm_parsing.AsmFileDescription(filename))
        asm_file_descrs[-1].check_filename()

    plt_sites = []
    cfg = gen_cfg(asm_file_descrs, plt_sites, options)
    # cfg.print_json_to('cdi_cfg.json')

    gen_cdi_asm(cfg, asm_file_descrs, plt_sites, options)
