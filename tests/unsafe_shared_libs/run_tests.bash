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
    echo "running test '${test_dir:2}'"
    ./run_test.bash > log.txt 2>&1
    if [ "$?" != 0 ]; then
        cat log.txt
        echo "-----------------------------------------------------"
        echo "error: test '${test_dir:2}' failed. See the output above."
    fi
    cd ..
done
