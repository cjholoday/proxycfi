#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.fptypes output out *.so
  
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )" 

# purpose: generate an unsafe (non-CDI) shared library and link with it

cdi_flags="-g --save-temps -fno-jump-tables"
tools_dir="$SCRIPT_DIR/../../../tools"
gen_sl="$tools_dir/gen_sl.bash"

"$gen_sl" libcaller.so caller.c

cdi-gcc $cdi_flags main.c -L. libcaller.so -o out \
    -Wl,-rpath="$SCRIPT_DIR" 

if [ "$?" != 0 ]; then
    echo ERROR: Compilation failed!
    exit 1
fi

./out > output

if [ "$?" != 0 ]; then
    echo ERROR: Running the executable for the test failed!
    exit 1
fi

diff output correct_output

if [ "$?" != 0 ]; then
    echo ERROR: Incorrect output!
    exit 1
fi
