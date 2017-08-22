#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.out *.fptypes output out

# remove versioned shared libraries, symlinks and all
rm -f *.so *.so.[0-9]*  *.so.[0-9]*.[0-9]*

verify="../../../verifier/verify.py"

cdi-gcc --make-sl=lib1.so.1.0.0 sl1.c
if [ "$?" != 0 ]; then
    echo ERROR: Compilation failed!
    exit 1
fi

cdi-gcc --make-sl=lib2.so.2.0.0 --use-sl=lib1.so sl2.c
if [ "$?" != 0 ]; then
    echo ERROR: Compilation failed!
    exit 1
fi

cdi-gcc --make-sl=lib3.so.3.0.0 --use-sl=lib1.so sl3.c
if [ "$?" != 0 ]; then
    echo ERROR: Compilation failed!
    exit 1
fi

cdi-gcc --use-sl=lib1.so.1,lib2.so,lib3.so main.c -o out
if [ "$?" != 0 ]; then
    echo ERROR: Compilation failed!
    exit 1
fi

# Check that the output is correct
./out > output
diff output correct_output
if [ "$?" != 0 ]; then
    echo ERROR: Incorrect output!
    exit 1
fi
