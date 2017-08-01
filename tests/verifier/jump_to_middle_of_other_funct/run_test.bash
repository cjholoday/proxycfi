#!/bin/bash

rm -f *.o *.json *.i *.ftypes *.fptypes output out

verifier="../../../verifier/verify.py"

# purpose 1: Check that verifier catches jumps to non-function addresses

gcc main.s -o out
./"$verifier" -i out

if [ "$?" != 1 ]; then
    echo ERROR: Verifier failed to catch invalid control flow
    exit 1
fi
