#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.out *.fptypes output out

# purpose: test that --cdi-test causes unsafe movement

verify="../../../verifier/verify.py"
diff_trace="../../../instrumentation/diff_trace.py"
addr_translate="../../../instrumentation/addr_translation.py"

# cases covered:
#       single return from a function
#       multiple returns from a function
#       multiple returns in a recursive function
#       Multiple source files

cdi_flags="-g --save-temps -fno-jump-tables"
cdi-gcc $cdi_flags main.c formulas.c calc.c -o out

# Verify that the executable is CDI compliant
"$verify" -ir out
if [ "$?" != 0 ]; then
    echo ERROR: Verification failed
    exit 1
fi

# Check that the output is correct
./out > output
diff output correct_output
if [ "$?" != 0 ]; then
    echo ERROR: Incorrect output!
    exit 1
fi

# instrumentation in this way is not supported by musl
# disable instrumentation
if [ 0 && "$CDI_MUSL_STATIC" != 1 ] && [ "$CDI_DISABLE_INSTRUMENTATION" != 1 ]; then

    # Get non-CDI trace
    gcc $cdi_flags -finstrument-functions main.c formulas.c calc.c -o out \
        ../../../instrumentation/instrumentation.c
    ./out > output
    "$addr_translate" out trace_table.out > funct_table2.out
    mv trace.out trace2.out

    # Get CDI trace
    cdi-gcc $cdi_flags -finstrument-functions main.c formulas.c calc.c -o out \
        ../../../instrumentation/instrumentation.c
    ./out > output
    "$addr_translate" out trace_table.out > funct_table1.out
    mv trace.out trace1.out


    # Check that the traces are identical
    "$diff_trace" out trace1.out funct_table1.out trace2.out funct_table2.out
    if [ "$?" != 0 ]; then
        echo ERROR: The CDI trace is different than the non-CDI trace!
        exit 1
    fi
fi
