#!/bin/bash

# purpose: test that cdi-ld.py can be run with the same spec multiple times
#          in a row without error. This guarrantee helps with debugging

cdi-gcc call_print.c -c
ar rcs libcall_print.a call_print.o

cdi-gcc print.c -c
ar rcs libprint.a print.o

ld_spec=$(cdi-gcc main.c libcall_print.a libprint.a -o out \
    --cdi-spec | tail -1 | sed 's/--cdi-spec//g')

cdi-gcc main.c libcall_print.a libprint.a -o out
check "compilation failed" || exit 1

./out > output
check "./out exited with error" || exit 1

diff output correct_output
check "incorrect output" || exit 1

rm out

# check idempotence when the program exits without error
/usr/local/cdi/cdi-ld $ld_spec
check "compilation failed" || exit 1

./out > output
check "./out exited with error" || exit 1

diff output correct_output
check "incorrect output" || exit 1


# Now test idempotence when exiting with error. In particular test the case where
# cdi-ld.py exits with error while attempting to generate the non-CDI version
bad_ld_spec="$ld_spec --non-existent-option"

/usr/local/cdi/cdi-ld $bad_ld_spec
echeck "cdi-ld succeeded with non-existent option" || exit 1
echo "(This error is intended)"

/usr/local/cdi/cdi-ld $ld_spec
check "cdi-ld failed" || exit 1

./out > output
check "./out exited with error" || exit 1

diff output correct_output
check "incorrect output" || exit 1
