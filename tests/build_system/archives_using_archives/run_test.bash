#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.fptypes output out *.a

cdi-gcc call_print.c -c
ar rcs libcall_print.a call_print.o

cdi-gcc print.c -c
ar rcs libprint.a print.o

cdi-gcc main.c libcall_print.a libprint.a -o out

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
