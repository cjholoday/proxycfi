#!/bin/bash

#############################
# How to use this script
#############################
# 
# gen_sl /path/to/new/libname.so source1.c [source2.c ...]
#
# The first argument is the new library to be generated
#
# Subsequent arguments are the source files that will be
# compiled into the shared library

args=($@)
libname="${args[0]}"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

srcs="${args[@]:1}"


if [ "${#srcs[@]}" -eq 0 ]; then
    echo "No files passed!"
    exit 1
fi

# compile to assembly files
for src in $srcs; do
    gcc -S -g -Wall -Wextra -fpic "$src" 
done

# deduce assembly file names from src names
asms=""
for src in $srcs; do
    asms="$asms ${src/.c/.s}"
done

gcc --save-temps -shared -o "$libname" $asms
