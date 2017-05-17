#!/bin/bash

# purpose: test that fake object files do not depend on source files

rm -f *.o *.s *.json *.i *.ftypes *.fptypes output out
rm -f libprint.a

cdi_flags="-g --save-temps -fno-jump-tables"
cdi-gcc $cdi_flags src/main.c -c
cdi-gcc $cdi_flags src/print.c -c
ar rcs libprint.a print.o
rm print.o

mv src hidden
cdi-gcc $cdi_flags main.o -L. -lprint -o out
mv hidden src


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
