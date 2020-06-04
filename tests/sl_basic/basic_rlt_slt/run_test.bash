#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.out *.fptypes output out *.so

# remove versioned shared libraries, symlinks and all
rm -f *.so *.so.[0-9]*  *.so.[0-9]*.[0-9]*

# purpose: test that --cdi-test causes unsafe movement

verify="../../../verifier/verify.py"

cdi-gcc --cdi-make-sl=libcalc.so calc.c
cdi-gcc --cdi-use-sl=libcalc.so main.c formulas.c -o out

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

