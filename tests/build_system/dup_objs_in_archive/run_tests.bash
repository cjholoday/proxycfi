#!/bin/bash

clean

rm -f print.a

cdi-gcc print1.c -c -o print.o
check "print1.c failed to compile" || exit 1
ar rc print.a print.o

cdi-gcc print2.c -c -o print.o
check "print2.c failed to compile" || exit 1
ar q print.a print.o

cdi-gcc main.c print.a -o out --cdi-verbose
check "main.c compilation with print.a failed" || exit 1

./out > output
check "./out exited with error" || exit 1

diff output correct_output
check "output does not match correct_output" || exit 1
