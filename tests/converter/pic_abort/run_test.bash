#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.out *.fptypes output out

verify="../../../verifier/verify.py"


gcc -S -fpic hello.c 
gcc -c -fpic hello.c "../../../converter/cdi_abort.cdi.s"
gcc -shared -o libhello.so hello.o cdi_abort.cdi.o

gcc -L"$(pwd)" -Wl,-rpath="$(pwd)" -o out main.c -lhello

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
