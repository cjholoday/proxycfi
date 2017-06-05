#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd "$SCRIPT_DIR"

test_dirs=$(find . -maxdepth 1 -type d -not -name .)

for test_dir in $test_dirs; do
    # skip this test if there is no way to run it
    if [ ! -f "$test_dir/run_test.bash" ]; then 
        continue
    fi

    cd "$test_dir"
    pretty_test_dir="'${test_dir:2}'"

    padding="................................................."
    printf "running test ${pretty_test_dir}${padding:0:-${#pretty_test_dir}}"

    ./run_test.bash > log.txt 2>&1
    if [ "$?" != 0 ]; then
        printf "FAILED: run ./run_test.bash for more info\n"
    else
        printf "passed\n"
    fi
    cd ..
done
