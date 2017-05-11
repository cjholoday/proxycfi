#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.fptypes output out

cdi_flags="-g --save-temps -fno-jump-tables"
cdi-gcc $cdi_flags main.c libprint.a -o out

if [ "$?" != 0 ]; then
    echo ERROR: Compilation failed!
    exit 1
fi

./out > output

if [ "$?" != 0 ]; then
    echo ERROR: Running the executable for the test failed!
    exit 1
fi

diff output correct_output1

if [ "$?" != 0 ]; then
    echo ERROR: Incorrect output!
    exit 1
fi

cdi-gcc $cdi_flags main_extended.c libprint.a -o out

if [ "$?" != 0 ]; then
    echo ERROR: Compilation failed!
    exit 1
fi

./out > output

if [ "$?" != 0 ]; then
    echo ERROR: Running the executable for the test failed!
    exit 1
fi

diff output correct_output2

if [ "$?" != 0 ]; then
    echo ERROR: Incorrect output!
    exit 1
fi
