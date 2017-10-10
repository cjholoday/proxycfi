#!/bin/bash

clean

cdi-gcc --make-sl=libadd.so.1.0.0 add.c
check "compilation of libadd.so failed" || exit 1

cdi-gcc --make-sl=libdo_add.so.2.0.0 --use-sl=libadd.so do_add.c
check "compilation of libdo_add.so failed" || exit 1

cdi-gcc --use-sl=libadd.so.1,libdo_add.so main.c -o out
check "compilation of main.c failed" || exit 1

# Check that the output is correct
./out > output
check "./out exited with error" || exit 1

diff output correct_output
check "incorrect output" || exit 1
