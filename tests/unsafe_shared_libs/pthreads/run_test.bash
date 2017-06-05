#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.fptypes output out *.so
  
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )" 

# purpose: generate an unsafe (non-CDI) shared library and link with it

cdi_flags="-g --save-temps -fno-jump-tables"

cdi-gcc $cdi_flags -pthread main.c -o out

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
