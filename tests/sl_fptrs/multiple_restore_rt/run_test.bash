#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.out *.fptypes output out

verify="../../../verifier/verify.py"

# Multiple libraries can define __restore_rt for returning from signals. Test
# that CDI code can handle multiple __restore_rt definitions

cdi_flags="-g --save-temps -fno-jump-tables"
cdi-gcc $cdi_flags -pthread sig.c -o out

if [ "$?" != 0 ]; then
    echo ERROR: Compilation failed!
    exit 1
fi

# Verify that the executable is CDI compliant
"$verify" -i out
if [ "$?" != 0 ]; then
    echo ERROR: Verification failed
    exit 1
fi

# Check that the output is correct
./out > output
diff output correct_output
if [ "$?" != 0 ]; then
    echo ERROR: Incorrect output!
    exit 1
fi
