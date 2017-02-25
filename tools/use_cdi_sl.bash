#!/bin/bash

#############################
# How to use this script
#############################
# 
# use_sl /path/to/libname.so [source files and gcc options]
# use_sl /path/to/libs/ [source files and gcc options]
#
# The first argument is either the shared library to be used or
# it's a directory of shared libraries to use
#
# Subsequent arguments are passed onto gcc for compilation
#
# Since a CDI shared library is being used, the application code
# will also be converted into CDI

args=($@)

# lib must be in directory from which use_sl is called
libname="${args[0]}"
gcc_args="${args[@]:1}"
libs_dir="$(pwd)"

# if libname is a file, then there is one shared library
# if libname is a directory, then use all files in that directory
# as shared libraries
if [ -f "$libname" ]; then
    libnames="$libname"
elif [ -d "$libname" ]; then
    libs_dir="$(cd "$libname" && pwd)"
    libnames=""
    for sl in $(ls $libs_dir); do
        libnames="$libnames $libs_dir/$sl"
    done
else
    echo "\'$libname\' is invalid: neither file nor directory"
fi

rm -f out
cdi-gcc -L"$libs_dir" -Wl,-rpath="$libs_dir" -g -Wall -o out --save-temps $gcc_args $libnames


