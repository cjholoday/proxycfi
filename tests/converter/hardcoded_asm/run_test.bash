#!/bin/bash

# Test that memcpy and memset work. They play funnily with the converter

mv add.s add.s.dont_clean || true
clean
mv add.s.dont_clean add.s

cdi-gcc main.c add.s -o out --cdi-converter-verbose --cdi-converter-no-mystery-types --cdi-converter-no-fp-punt
check "failed to compile" || exit 1

# Check that the output is correct
./out > output
check "./out exited with error" || exit 1

diff output correct_output
check "incorrect output" || exit 1

"$VERIFY" -i out
check "verification failed" || exit 1
