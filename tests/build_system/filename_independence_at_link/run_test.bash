#!/bin/bash

rm -f *.s *.json *.i *.ftypes *.fptypes output out *fakename*

cdi_flags="-g --save-temps -fno-jump-tables"

cdi-gcc $cdi_flags main.c -c -o main.fakename.o
cdi-gcc $cdi_flags print.c -c -o print.other_fakename.o
rm -f libprint.fakename.a
ar rcs libprint.fakename.a print.other_fakename.o
cdi-gcc $cdi_flags main.fakename.o libprint.fakename.a -o out

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
