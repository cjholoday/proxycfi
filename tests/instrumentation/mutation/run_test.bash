#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.fptypes output out

diff_trace="../../../instrumentation/diff_trace.py"
addr_translate="../../../instrumentation/addr_translation.py"

gcc *.c ../../../instrumentation/instrumentation.c \
    -finstrument-functions -g -o out

if [ "$?" != 0 ]; then
    echo ERROR: Compilation failed!
    exit 1
fi

./out > output
"$addr_translate" out trace_table.out > funct_names.out

if [ "$?" == 1 ]; then
    echo ERROR: Traces are different
    exit 1
fi

diff funct_names.out funct_names.corr
"$diff_trace" out trace.out funct_names.out trace.corr funct_names.corr 
if [ "$?" == 1 ]; then
    echo ERROR: Traces are different
    exit 1
fi



