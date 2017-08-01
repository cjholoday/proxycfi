#!/bin/bash

rm -f *.o *.json *.i *.ftypes *.fptypes output out

verifier="../../../verifier/verify.py"

# purpose 1: Check if returns are caught by the verifier
# purpose 2: Check if indirect function calls are caught by the verifier

cdi_flags="-g --save-temps -fno-jump-tables"


gcc has_return.c -o out
./"$verifier" out

if [ "$?" != 1 ]; then
    echo ERROR: Verifier failed to catch invalid control flow
    exit 1
fi

gcc has_indir_call.cdi.s ../../../converter/cdi_abort.cdi.s -o out
./"$verifier" out

if [ "$?" != 1 ]; then
    echo ERROR: Verifier failed to catch invalid control flow
    exit 1
fi

