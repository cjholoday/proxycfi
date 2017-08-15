#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.out *.fptypes output out *.so

verify="../../../verifier/verify.py"

cdi-gcc --make-sl=lib1.so sl1.c
if [ "$?" != 0 ]; then
    echo ERROR: Compilation failed!
    exit 1
fi

cdi-gcc --make-sl=lib2.so --use-sl=lib1.so sl2.c
if [ "$?" != 0 ]; then
    echo ERROR: Compilation failed!
    exit 1
fi

cdi-gcc --make-sl=lib3.so --use-sl=lib1.so sl3.c
if [ "$?" != 0 ]; then
    echo ERROR: Compilation failed!
    exit 1
fi

cdi-gcc --use-sl=lib1.so,lib2.so,lib3.so main.c -o out
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
