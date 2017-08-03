#!/bin/bash

rm -f *.o *.json *.i *.ftypes *.fptypes output out *.s

verifier="../../../verifier/verify.py"

# purpose 1: Check that the verifier catches indirect jumps

cdi_flags="-g --save-temps -fno-jump-tables"

gcc main.c -o out
./"$verifier" -i out

if [ "$?" != 1 ]; then
    echo ERROR: Verifier failed to catch invalid control flow
    exit 1
fi

cdi-gcc $cdi_flags main.c -o out
./"$verifier" -i out

if [ "$?" != 0 ]; then
    echo ERROR: The verifier found issue with a cdi executable
    exit 1
fi

