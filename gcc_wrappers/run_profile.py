import __init__

import argparse
import os
import sys
import glob
import re
import subprocess


from common.eprint import vprint
import obj_parse

# fix these paths to the absolute paths of the pin directory and pin tool directories respectively
script_dir = os.path.dirname(os.path.realpath(sys.argv[0]))

pin_dir = script_dir + "/../profiling/pin-3.2-81205-gcc-linux/"
pin_tool = script_dir + "/../profiling/pin_trace/obj-intel64/itrace.so"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--program', required = True, help='executable being profiled')
    # parser.add_argument('-o', '--output', default = "sled_profile.csv", help='Output file name')

    args = parser.parse_args()

    if not os.path.isfile(args.program):
        vprint("-E-: executable program not found")
        sys.exit(1)

    out_file = run_profile(args.program)#args.itrace, args.pedata, args.output, args.program)
    return out_file

def get_map(objdump_file): # Extracts all the (Ip,sled mapping) for a given objdump file
    ip_sled = []
    with open(objdump_file) as f:
        for line in f:
            if ".symtab"in line:
                break
            if "_CDIX_FROM_" in line and "_TO_" in line:
                l = line.split()
                ip = int(l[1], 16)
                sled = l[7]
                ip_sled.append((ip, sled))
    return ip_sled


def run_profile(program):
    
    # Get Ip to sled mapping using gdb
    objdump_file = program + '.readelf'
    readelf_cmd = []
    readelf_cmd.append('readelf')
    readelf_cmd.append('-s')
    readelf_cmd.append('--wide')
    readelf_cmd.append(program)
    f = open(objdump_file,'w')
    subprocess.call(readelf_cmd,stdout=f)
    ip_sled = get_map(objdump_file)

    # Generate Execution trace using pin
    addr = '0x400000'
    size = '0x100000'
    itrace_file = program + ".itrace"

    pin_cmdline = []
    pin_cmd = pin_dir +"pin"
    pin_cmdline.append(pin_cmd)
    pin_cmdline += ['-ifeellucky'] # work around bug in pin
    pin_cmdline += ['-injection','child']
    pin_cmdline += ['-t',pin_tool]
    pin_cmdline += ['-i',itrace_file]
    pin_cmdline += ['-a', addr]
    pin_cmdline += ['-s', size]
    pin_cmdline += ['--', './' + program]


    subprocess.call(pin_cmdline)


    # Extract execution trace
    itrace = obj_parse.load_csv_data(itrace_file)
    exec_iptrs = []
    for line in itrace:
        exec_iptrs.append(int(line.iptr, 16))

    # Count execution count of each sled entry in the dump and write to file
    output_file = program + '.profile'
    sled_count = {}
    for ip,sled in ip_sled:
        count = exec_iptrs.count(ip)
        sled_count[sled] = count
    for sl,cnt in sled_count.iteritems():
        vprint(sl,cnt)
    obj_parse.save_obj(sled_count,output_file )
    return output_file


if __name__ == "__main__":
    main()
