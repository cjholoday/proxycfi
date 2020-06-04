#!/bin/bash

# Test that memcpy and memset work. They play funnily with the converter

clean

cdi-gcc mem.c -o out --cdi-converter-verbose --cdi-musl-static
check "failed to compile" || exit 1

# Check that the output is correct
./out > output
check "./out exited with error" || exit 1

diff output correct_output
check "incorrect output" || exit 1

"$VERIFY" -i out
check "verification failed" || exit 1