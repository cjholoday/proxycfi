#!/bin/bash

cdi-gcc print1.c -c
cdi-gcc print2.c -c
cdi-gcc print3.c -c

ar rcs libprint1.a print1.o
ar rcs libprint2.a print2.o
ar rcs libprint3.a print3.o

cdi-gcc main.c -L. -lprint1 -l print2 libprint3.a -o out

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
