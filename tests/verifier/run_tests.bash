#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd "$SCRIPT_DIR"
for test_dir in $(ls | grep -v run_tests.bash); do
    echo "running test '$test_dir'..."
    cd "$test_dir"
    ./run_test.bash > log.txt 2>&1
    if [ "$?" != 0 ]; then
        cat log.txt
        echo "-----------------------------------------------------"
        echo "error: test '$test_dir' failed. See the output above."
    fi
    cd ..
done
