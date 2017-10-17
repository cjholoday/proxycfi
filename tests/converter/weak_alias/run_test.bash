#!/bin/bash

clean

cdi-gcc main.c -o out
check "compilation failed" || exit 1

# Check that the output is correct
./out > output
diff output correct_output
check "incorrect output" || exit 1
