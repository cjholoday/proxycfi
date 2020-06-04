#!/bin/bash

# purpose: test duplicated symbols appearing in ld spec

cdi-gcc print.c -c
ar rcs libprint.a print.o

ld_spec=$(cdi-gcc main.c libprint.a -o out \
    --cdi-spec | tail -1 | sed 's/--cdi-spec//g')

echo $ld_spec
ld_spec_with_dups="$ld_spec -L. -lprint libprint.a -l print"

set -f
"$CDI_LD" $ld_spec_with_dups
check "compilation failed" || exit 1
set +f

./out > output
check "./out exited with error"

diff output correct_output
check "incorrect output" || exit 1
