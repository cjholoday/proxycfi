#!/bin/bash

rm -f *.o *.json *.i *.ftypes *.fptypes output 

verifier="../../../verifier/verify.py"

# purpose: Check for a middle of instruction jump
# note: the middle of instruction jump was hard coded into executable 'out'

./"$verifier" -i out

if [ "$?" != 1 ]; then
    echo ERROR: Verifier failed to catch invalid control flow
    exit 1
fi

