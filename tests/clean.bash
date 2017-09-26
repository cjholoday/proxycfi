#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"                  
. "$SCRIPT_DIR/test_env.bash"
cd "$SCRIPT_DIR"

test_categories=$(find . -maxdepth 1 -type d -not -name .)

for category in $test_categories; do
    cd "$category"

    tests=$(find . -maxdepth 1 -type d -not -name .)
    for cdi_test in $tests; do
        cd "$cdi_test"
        clean
        cd ..
    done
    cd ..
done
