#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.fptypes output out

diff_trace="../../../instrumentation/diff_trace.py"
addr_translate="../../../instrumentation/addr_translation.py"

gcc main.c ../../../instrumentation/instrumentation.c \
    -finstrument-functions -g -o out

# purpose: test that instrumentation is generated and that the trace diff'er
# can handle a small, simple program

if [ "$?" != 0 ]; then
    echo ERROR: Compilation failed!
    exit 1
fi

./out > output

if [ "$?" != 0 ]; then
    echo ERROR: Running the executable for the test failed!
    exit 1
fi

"$addr_translate" out trace_table.out > funct_table.out
diff funct_table.out funct_table.corr

if [ "$?" != 0 ]; then
    echo ERROR: The tracing is incorrect
    exit 1
fi

diff trace.out trace.corr

if [ "$?" != 0 ]; then
    echo ERROR: The tracing is incorrect
    exit 1
fi

cp trace_table.out trace_table.temp.out
"$diff_trace" out trace.out funct_table.out trace.corr funct_table.corr

if [ "$?" != 0 ]; then
    echo ERROR: The tracing is incorrect
    exit 1
fi



