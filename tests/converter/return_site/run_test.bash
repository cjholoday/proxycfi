#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.out *.fptypes output out

# purpose: test that --cdi-test causes unsafe movement
# cases covered:
#       single return from a function
#       multiple returns from a function
#       multiple returns in a recursive function
#       Multiple source files

cdi_flags="-g --save-temps -fno-jump-tables"
cdi-gcc $cdi_flags main.c formulas.c calc.c -o out

# Verify that the executable is CDI compliant
"$VERIFY" -ir out
check "verification failed" || exit 1

# Check that the output is correct
./out > output
diff output correct_output
check "incorrect output" || exit 1

# instrumentation in this way is not supported by musl
if [ "$CDI_MUSL_STATIC" != 1 ] && [ "$CDI_DISABLE_INSTRUMENTATION" != 1 ]; then
    # Get non-CDI trace
    gcc $cdi_flags -finstrument-functions main.c formulas.c calc.c -o out \
        ../../../instrumentation/instrumentation.c
    ./out > output
    "$ADDR_TRANSLATE" out trace_table.out > funct_table2.out
    mv trace.out trace2.out

    # Get CDI trace
    cdi-gcc $cdi_flags -finstrument-functions main.c formulas.c calc.c -o out \
        ../../../instrumentation/instrumentation.c
    ./out > output
    "$ADDR_TRANSLATE" out trace_table.out > funct_table1.out
    mv trace.out trace1.out

    # Check that the traces are identical
    "$DIFF_TRACE" out trace1.out funct_table1.out trace2.out funct_table2.out
    check "the cdi trace is different than the non-cdi trace" || exit 1
fi
