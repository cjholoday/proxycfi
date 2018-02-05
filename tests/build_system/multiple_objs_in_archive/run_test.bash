#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.fptypes output out *.a

verify="../../../verifier/verify.py"
addr_translate="../../../instrumentation/addr_translation.py"
diff_trace="../../../instrumentation/diff_trace.py"

cdi_flags="-g --save-temps -fno-jump-tables"

cdi-gcc $cdi_flags basic_opers.c formulas.c -c -finstrument-functions
ar rcs libcalculator.a basic_opers.o formulas.o
cdi-gcc $cdi_flags compute.c libcalculator.a -o out 


if [ "$?" != 0 ]; then
    echo ERROR: Compilation failed!
    exit 1
fi

"$verify" -i out

if [ "$?" != 0 ]; then
    echo ERROR: Verification failed!
    exit 1
fi

./out > output

if [ "$?" != 0 ]; then
    echo ERROR: Running the executable for the test failed!
    exit 1
fi

diff output correct_output

if [ "$?" != 0 ]; then
    echo ERROR: Incorrect output!
    exit 1
fi

#cdi-gcc $cdi_flags compute.c libcalculator.a -o out -finstrument-functions \
#    ../../../instrumentation/instrumentation.c
#./out > output
#"$addr_translate" out trace_table.out > funct_table1.out
#mv trace.out trace1.out
#
#cdi-gcc $cdi_flags compute.c libcalculator.a -o out -finstrument-functions \
#    ../../../instrumentation/instrumentation.c \
#    -Wl,--cdi-options="--abandon-cdi"
#./out > output
#"$addr_translate" out trace_table.out > funct_table2.out
#mv trace.out trace2.out
#
#"$diff_trace" out trace1.out funct_table1.out trace2.out funct_table2.out
#if [ "$?" != 0 ]; then
#    echo ERROR: The traces differ!
#    exit 1
#fi
