#!/bin/bash

# purpose: test linking of archives where each archive has a function with
# an identical function name
rm -f *.o *.s *.json *.i *.ftypes *.fptypes

cdi_flags="-g --save-temps -fno-jump-tables"
cdi-gcc $cdi_flags main.c -L. -lprint1 -l print2 libprint3.a -o out

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
