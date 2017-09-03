#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.out *.fptypes output out

# remove versioned shared libraries, symlinks and all
rm -f *.so *.so.[0-9]*  *.so.[0-9]*.[0-9]*

verify="../../../verifier/verify.py"

cdi-gcc --make-sl=libadd.so.1.0.0 add.c
if [ "$?" != 0 ]; then
    echo ERROR: Compilation failed!
    exit 1
fi

cdi-gcc --make-sl=libdo_add.so.2.0.0 --use-sl=libadd.so do_add.c
if [ "$?" != 0 ]; then
    echo ERROR: Compilation failed!
    exit 1
fi

cdi-gcc --use-sl=libadd.so.1,libdo_add.so main.c -o out
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
