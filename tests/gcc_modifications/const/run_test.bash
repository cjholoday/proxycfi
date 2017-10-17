#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.out *.fptypes output out

# purpose: test that --cdi-test causes unsafe movement

verify="../../../verifier/verify.py"

cdi-gcc --cdi-converter-no-mystery-types main.c -o out --cdi-spec

if [ "$?" != 0 ]; then
    echo ERROR: Compilation failed
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

diff main.c.ftypes main.c.ftypes.correct
if [ "$?" != 0 ]; then
    echo ERROR: Incorrect ftypes file
    exit 1
fi

diff main.c.fptypes main.c.fptypes.correct
if [ "$?" != 0 ]; then
    echo ERROR: Incorrect fptypes file
    exit 1
fi
