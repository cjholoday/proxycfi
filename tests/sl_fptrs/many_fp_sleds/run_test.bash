#!/bin/bash

clean

cdi-gcc --cdi-make-sl=libtargetful1.so.1.0.0 targetful1.c
check "compilation of libtargetful1.so failed" || exit 1

cdi-gcc --cdi-make-sl=libtargetful2.so.1.0.0 targetful2.c
check "compilation of libtargetful2.so failed" || exit 1

cdi-gcc --cdi-use-sl=libtargetful1.so,libtargetful2.so main.c -o out
check "compilation of main.c failed" || exit 1

./out > output
check "./out exited with error" || exit 1

diff output correct_output
check "incorrect output" || exit 1
