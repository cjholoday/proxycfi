#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.fptypes output out *.so
  
verifier="../../../verifier/verify.py"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )" 

# purpose: Test that the verifier verifies functions that are only connected
#          to main with a shared library intermediate

cdi_flags="-g --save-temps -fno-jump-tables"
tools_dir="$SCRIPT_DIR/../../../tools"
gen_sl="$tools_dir/gen_sl.bash"

"$gen_sl" libcaller.so caller.c

cdi-gcc $cdi_flags main.c -L. libcaller.so -o out \
    -Wl,-rpath="$SCRIPT_DIR" 

if [ "$?" != 0 ]; then
    echo ERROR: Compilation failed!
    exit 1
fi

"$verifier" -i out
if [ "$?" == 0 ]; then
    echo ERROR: Verification failed to catch indirect jump!
    exit 1
fi
