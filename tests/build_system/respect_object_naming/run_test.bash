#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.fptypes output out main.custom_object_suffix

# purpose: test that cdi-gcc will give objects a custom name if requested
#          (objects don't NEED to be suffixed with .o)

cdi_flags="-g --save-temps -fno-jump-tables"
cdi-gcc $cdi_flags main.c -c -o main.custom_object_suffix

if [ "$?" != 0 ]; then
    echo ERROR: Compilation failed!
    exit 1
fi

if [ ! -f main.custom_object_suffix ]; then
    echo ERROR: cdi-gcc failed to generate custom suffixed object file
    exit 1
fi

