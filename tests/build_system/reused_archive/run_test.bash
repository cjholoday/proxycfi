#!/bin/bash

cdi-gcc print.c -c
check "compilation failed" || exit 1

ar rcs libprint.a print.o

cdi-gcc main.c libprint.a -o out
check "(1) compilation failed" || exit 1

./out > output
check "(1) ./out exited with error" || exit 1

diff output correct_output1
check "(1) incorrect output" || exit 1

# now reuse it
cdi-gcc $cdi_flags main_extended.c libprint.a -o out
check "(2) compilation failed"

./out > output
check "(2) ./out exited with error" || exit 1

diff output correct_output2
check "(2) incorrect output" || exit 1
