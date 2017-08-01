#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.fptypes output out

diff_trace="../../../instrumentation/diff_trace.py"
addr_translate="../../../instrumentation/addr_translation.py"

gcc main.c ../../../instrumentation/instrumentation.c \
    -finstrument-functions -g -o out

# purpose: check that the trace diff'er notices that there are too many returns

if [ "$?" != 0 ]; then
    echo ERROR: Compilation failed!
    exit 1
fi

./out > output

if [ "$?" != 0 ]; then
    echo ERROR: Running the executable for the test failed!
    exit 1
fi

# add another return
printf '0\n' >> trace.out

"$addr_translate" out trace_table.out > funct_table.out

cp trace_table.out funct_table.temp.out
cp trace.out trace.temp.out
"$diff_trace" out trace.out trace_table.out trace.temp.out funct_table.temp.out \
    2> /dev/null

if [ "$?" == 0 ]; then
    echo "ERROR: 'too many returns' error not caught"
    exit 1
fi



