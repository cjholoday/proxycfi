#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.out *.fptypes output out

# purpose: test that --cdi-test causes unsafe movement
# cases covered:
#       single return from a function
#       multiple returns from a function
#       multiple returns in a recursive function
#       Multiple source files

cdi_flags="-g --save-temps -fno-jump-tables"
cdi-gcc setjmp.c -o out

# Verify that the executable is CDI compliant
"$VERIFY" -ir out
check "verification failed" || exit 1

# Check that the output is correct
./out > output
diff output correct_output
check "incorrect output" || exit 1
