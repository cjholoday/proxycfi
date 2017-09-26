#!/bin/bash

rm -f main.custom_object_suffix

# purpose: test that cdi-gcc will give objects a custom name if requested
#          (objects don't NEED to be suffixed with .o)

cdi-gcc print.c -c
ar rcs libprint.a print.o

cdi-gcc main.c libprint.a -c -o main.custom_object_suffix

if [ "$?" != 0 ]; then
    echo ERROR: Compilation failed!
    exit 1
fi

if [ ! -f main.custom_object_suffix ]; then
    echo ERROR: cdi-gcc failed to generate custom suffixed object file
    exit 1
fi

cdi-gcc $cdi_flags main.custom_object_suffix libprint.a -o out

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
