#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.fptypes output out

cdi-gcc unused.c -c
ar rcs libunused.a unused.o

cdi-gcc main.c libunused.a -o out

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
