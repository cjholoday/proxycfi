import argparse
import os
import sys
import glob
import re
import subprocess


import obj_parse

# fix these paths to the absolute paths of the pin directory and pin tool directories respectively
cwd = os.path.dirname(os.path.realpath(sys.argv[0]))

pin_dir = cwd + "/pin-3.2-81205-gcc-linux/"
pin_tool = cwd + "/pin_trace/obj-intel64/itrace.so"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--program', required = True, help='executable being profiled')
    # parser.add_argument('-o', '--output', default = "sled_profile.csv", help='Output file name')

    args = parser.parse_args()

    if not os.path.isfile(args.program):
        print "-E-: executable program not found"
        sys.exit(1)

    out_file = run_profile(args.program)#args.itrace, args.pedata, args.output, args.program)
    return out_file

def get_map(objdump_file): # Extracts all the (Ip,sled mapping) for a given objdump file
    ip_sled = []
    with open(objdump_file) as f:
        for line in f:
            if "_CDI_" in line and "_TO_" in line and line[-2] == (':'):
                l = line.split()
                ip = int(l[0], 16)
                sled = l[1][1:-2]
                ip_sled.append((ip, '"'+ sled +'"'))
    return ip_sled


def run_profile(program):
    
    # Get Ip to sled mapping using gdb
    objdump_file = program + ".objdump"
    os.system("objdump -D " + program + " > " + objdump_file)
    ip_sled = get_map(objdump_file)

    # Generate Execution trace using pin
    addr = " -a 0x400000 "
    size = " -s 0x100000 "
    itrace_file = program + ".itrace"

    pin_cmd = pin_dir +"pin"

    pin_cmdline = pin_cmd + " -ifeellucky -injection child -t " + pin_tool + " -i " +  itrace_file + addr + size + " -- ./" + program
    subprocess.check_output([pin_cmdline])


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

    obj_parse.save_obj(sled_count,output_file )
    return output_file


if __name__ == "__main__":
    main()