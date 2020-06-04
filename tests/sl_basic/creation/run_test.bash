#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.out *.fptypes output out *.so

# remove versioned shared libraries, symlinks and all
rm -f *.so *.so.[0-9]*  *.so.[0-9]*.[0-9]*

verify="../../../verifier/verify.py"

gcc -c -fpic hello.c
gcc -shared -Wl,-soname,libhello.so.6 -o libhello.so.6.0.0 hello.o

ln -s libhello.so.6.0.0 libhello.so
ln -s libhello.so.6.0.0 libhello.so.6 

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
