#!/bin/bash

# purpose: link in a different directory after assembling separately

rm -f *.o *.s *.json *.i *.ftypes *.fptypes output out

cdi_flags="-g --save-temps -fno-jump-tables"
cd assemble
cdi-gcc $cdi_flags main.c -c 
cdi-gcc $cdi_flags print.c -c
ar rcs libprint.a print.o

mv main.o ../link
mv libprint.a ../link
cd ../link

cdi-gcc $cdi_flags main.o libprint.a -o out

if [ "$?" != 0 ]; then
    echo ERROR: Compilation failed!
    exit 1
fi

mv out ..
cd ..
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
