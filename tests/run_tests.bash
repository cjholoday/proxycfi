#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"                  
. "$SCRIPT_DIR/test_env.bash"

test_suite="$1"
if [ ! -z "$test_suite" ]; then
    # we were called to run all tests in $test_suite

    cd "$test_suite"
    test_dirs=$(find . -maxdepth 1 -type d -not -name .)

    for test_dir in $test_dirs; do
        # skip this test if there is no way to run it
        if [ ! -f "$test_dir/run_test.bash" ]; then 
            continue
        fi

        cd "$test_dir"
        clean

        pretty_test_dir="'${test_dir:2}'"

        padding="................................................."
        printf "running test ${pretty_test_dir}${padding:0:-${#pretty_test_dir}}"

        bash run_test.bash > log.txt 2>&1
        if [ "$?" != 0 ]; then
            printf "FAILED: run ./run_test.bash for more info\n"
        else
            printf "passed\n"
        fi
        cd ..
    done
else
    # we were called to run all tests in ALL test suites

    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"                  
    cd "$SCRIPT_DIR"

    test_categories=$(find . -maxdepth 1 -type d -not -name .)

    for category in $test_categories; do
        echo "==================================================="
        echo "Running '${category:2}' tests"
        echo "==================================================="

        cd "$category"
        ./run_tests.bash
        cd ..
    done
fi
