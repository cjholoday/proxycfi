#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.fptypes output out

# purpose: test duplicated symbols appearing in ld spec

cdi_flags="-g --save-temps -fno-jump-tables"
ld_spec=$(cdi-gcc $cdi_flags main.c libprint.a -o out \
    -Wl,--cdi-options="--spec" | tail -1 | sed 's/--cdi-options=--spec//g')

echo $ld_spec
ld_spec_with_dups="$ld_spec -L. -lprint libprint.a -l print"

/usr/local/cdi/cdi-ld $ld_spec_with_dups

if [ "$?" != 0 ]; then
    echo ERROR: Compilation failed!
    exit 1
fi

./out > output

if [ "$?" != 0 ]; then
    echo ERROR: Running the executable for the test failed!
    exit 1
fi

diff output correct_output

if [ "$?" != 0 ]; then
    echo ERROR: Incorrect output!
    exit 1
fi
