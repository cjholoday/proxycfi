#!/bin/bash

# This script assumes:
#   1. gcc-6.1.0 is placed at cdi/cdi-gcc/gcc-6.1.0
#   2. This script is in cdi/cdi-gcc
#   3. the assembler and linker are customly specified as /usr/local/cdi/cdi-as
#      and /usr/local/cdi/cdi-ld respectively
#   4. GCC has been successfully compiled with CDI changes already
#   5. you have sudo access

# Use this script to recompile gcc with newly added gcc modifications. If you're
# new to compiling cdi-gcc, see the README in this directory

BASEDIR="$(pwd)"

# set up assembler and linker interception
cd /usr/local/cdi
sudo rm -f cdi-as cdi-ld
sudo ln -s $(which as) cdi-as
sudo ln -s $(which ld) cdi-ld 

# ensure gcc modifications are added into the new compilation
cd "$BASEDIR/build"
ln -sf "$(pwd)/../../type_drop/cdi-c-typeck.c" ../gcc-6.1.0/gcc/c/c-typeck.c 
ln -sf "$(pwd)/../../type_drop/cdi-c-parser.c" ../gcc-6.1.0/gcc/c/c-parser.c 
touch ../gcc-6.1.0/gcc/c/c-typeck.c                                            
touch ../gcc-6.1.0/gcc/c/c-parser.c                                            
ln -sf "$(pwd)/../../type_drop/type_drop.c" ../gcc-6.1.0/gcc/c/cdi.c           
ln -sf "$(pwd)/../../type_drop/type_drop.h" ../gcc-6.1.0/gcc/c/cdi.h       

cd "$BASEDIR/build"
make 2> errlog2.txt | tee makelog2.txt
if [ "$?" != 0 ]; then
    echo 'recompile_gcc.bash: compilation failed'
    exit 1
fi

cd "$BASEDIR/build"
make install
if [ "$?" != 0 ]; then
    echo 'recompile_gcc.bash: installation failed'
    exit 1
fi

# intercept assembler and linker calls with the cdi versions
cd "$BASEDIR/build"
sudo ln -sf "$(pwd)/../../gcc_wrappers/cdi-as.py" /usr/local/cdi/cdi-as     
sudo ln -sf "$(pwd)/../../gcc_wrappers/cdi-ld.py" /usr/local/cdi/cdi-ld
sudo ln -sf "$(pwd)/../../converter/gen_cdi.py" /usr/local/cdi/gen_cdi
sudo ln -sf "$(pwd)/../dest/bin/gcc" /usr/local/bin/cdi-gcc-proper
sudo ln -sf "$(pwd)/../../cdi-gcc.py" /usr/local/bin/cdi-gcc
sudo ln -sf "$(pwd)/../../converter/cdi_abort.cdi.s" /usr/local/cdi/cdi_abort.cdi.s
cd /usr/local/cdi/ && sudo gcc -c cdi_abort.cdi.s       

# run a basic test case
cd "$BASEDIR/../tests/converter/return_site"
./run_test.bash
if [ "$?" != "0" ]; then
    echo 'recompile_gcc.bash: cdi-gcc failed tests/converter/return_site'
    exit 1
fi

