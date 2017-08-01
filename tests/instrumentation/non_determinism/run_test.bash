#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.fptypes output out

diff_trace="../../../instrumentation/diff_trace.py"
addr_translate="../../../instrumentation/addr_translation.py"

gcc main.c ../../../instrumentation/instrumentation.c \
    -finstrument-functions -g -o out

# purpose: check that non-determinism defeats instrumentation diff'ing

if [ "$?" != 0 ]; then
    echo ERROR: Compilation failed!
    exit 1
fi

./out > output
"$addr_translate" out trace_table.out > funct_table1.out
mv trace.out trace1.out


# ensure both runs do not get the same random seed
sleep 2 

./out > output
"$addr_translate" out trace_table.out > funct_table2.out
mv trace.out trace2.out

"$diff_trace" out trace1.out funct_table.out trace2.out funct_table2.out 2> /dev/null
if [ "$?" == 0 ]; then
    echo ERROR: The tracing is identical when it shouldn\'t be!
    exit 1
fi



