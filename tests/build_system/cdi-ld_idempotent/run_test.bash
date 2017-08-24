#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.fptypes output out

# purpose: test that cdi-ld.py can be run with the same spec multiple times
#          in a row without error. This guarrantee helps with debugging

ld_spec=$(cdi-gcc $cdi_flags main.c libcall_print.a libprint.a -o out \
    -Wl,--cdi-options="--spec"  | tail -1 | sed 's/--cdi-options=--spec//g')

cdi-gcc call_print.c -c
ar rcs libcall_print.a call_print.o

cdi-gcc print.c -c
ar rcs libprint.a print.o


cdi-gcc main.c libcall_print.a libprint.a -o out


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


rm out
/usr/local/cdi/cdi-ld $ld_spec

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


# Now test idempotence when exiting with error. In particular test the case where
# cdi-ld.py exits with error while attempting to generate the non-CDI version

bad_ld_spec="$ld_spec --non-existent-option"

/usr/local/cdi/cdi-ld $bad_ld_spec

if [ "$?" = 0 ]; then
    echo ERROR: cdi-ld succeeded when it should fail
    exit 1
fi
echo "(This error is intended)"

/usr/local/cdi/cdi-ld $ld_spec

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
