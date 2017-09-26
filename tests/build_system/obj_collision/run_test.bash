#!/bin/bash

# purpose: test the case where object files within two archives have the same
#          name but different contents

rm print.c

cp print1.c print.c
cdi-gcc print.c -c 
ar rcs libprint1.a print.o

cp print2.c print.c
cdi-gcc print.c -c 
ar rcs libprint2.a print.o

cdi-gcc main.c -L. -lprint1 -lprint2 -o out
check "compilation failed" || exit 1

./out > output
check "./out exited with error" || exit 1

diff output correct_output
check "incorrect output" || exit 1
