#!/bin/bash 

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

ln -sf "$(pwd)"/rtld.c   "$(pwd)"/glibc-2.23/elf/rtld.c
ln -sf "$(pwd)"/dl-cdi.c "$(pwd)"/glibc-2.23/elf/dl-cdi.c
ln -sf "$(pwd)"/dl-cdi.h "$(pwd)"/glibc-2.23/elf/dl-cdi.h
ln -sf "$(pwd)"/dl-map-segments.h "$(pwd)"/glibc-2.23/elf/dl-map-segments.h
ln -sf "$(pwd)"/dl-load.c "$(pwd)"/glibc-2.23/elf/dl-load.c
ln -sf "$(pwd)"/dl-lookup.c "$(pwd)"/glibc-2.23/elf/dl-lookup.c
ln -sf "$(pwd)"/dl-cdi-fptr.c "$(pwd)"/glibc-2.23/elf/dl-cdi-fptr.c

# we can't symbolic link this one because Make will complain about symlinks
cp Makefile glibc-2.23/elf/Makefile

cd build
make 2> e | tee m && make install


