#!/bin/bash

rm -f *.s *.json *.i *.ftypes *.fptypes output out

cdi_flags="-g --save-temps -fno-jump-tables"
cdi-gcc $cdi_flags main.o.fakename.o libprint.a.fakename.a -o out

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
