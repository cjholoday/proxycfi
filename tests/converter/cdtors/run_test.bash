#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.out *.fptypes output out
rm -f *.so *.so.[0-9]*  *.so.[0-9]*.[0-9]*

cdi-gcc *.c -o out

# Check that the output is correct
./out > output
diff output correct_output
if [ "$?" != 0 ]; then
    echo "ERROR: Incorrect output! (non-sl)"
    exit 1
fi

rm out

# now compile the ctors and dtors into a shared library 
cdi-gcc --make-sl=libcdtors.so.1.0.0 cdtors.c
cdi-gcc --use-sl=libcdtors.so main.c -o out

./out > output
diff output correct_output
if [ "$?" != 0 ]; then
    echo "ERROR: Incorrect output! (sl)"
    exit 1
fi
