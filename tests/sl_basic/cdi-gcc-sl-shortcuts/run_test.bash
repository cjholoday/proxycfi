#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.out *.fptypes output out *.so

verify="../../../verifier/verify.py"

cdi-gcc --cdi-make-sl=libhello.so hello.c
cdi-gcc --cdi-use-sl=libhello.so main.c -o out

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
