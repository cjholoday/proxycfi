#!/bin/bash

# Run ALL cdi tests

# test categories e.g. build_system, converter, verifier, ...
test_categories=$(find . -maxdepth 1 -type d -not -name .)

for category in $test_categories; do
    echo "==================================================="
    echo "Running '${category:2}' tests"
    echo "==================================================="

    cd "$category"
    ./run_tests.bash
    cd ..
done

