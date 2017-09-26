#!/bin/bash
#
# Exports bash variables and functions that are useful for testing CDI
# This script must be sourced before running individual tests


SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

export ROOT="$(readlink -f "$SCRIPT_DIR/..")"
export TESTS="$ROOT/tests"

export VERIFY="$ROOT/verifier/verify.py"
export DIFF_TRACE="$ROOT/instrumentation/diff_trace.py"
export ADDR_TRANSLATE="$ROOT/instrumentation/addr_translation.py"

export CDI_LD="/usr/local/cdi/cdi-ld"
export CDI_AS="/usr/local/cdi/cdi-as"

# prints out the first argument as the error message
function check {
    if [ "$?" != "0" ]; then
        echo "failed check: $1"
        exit 1
    fi
}

function echeck {
    if [ "$?" == "0" ]; then
        echo "failed echeck: $1"
        exit 1
    fi
}

function clean {
    # allow the clean script to be overrided
    if [ -f clean.bash ]; then
        bash clean.bash
    else
        rm -f *.o *.s *.json *.i *.ftypes *.out *.fptypes output out *.a *.json

        # remove versioned shared libraries, symlinks and all                           
        rm -f *.so *.so.[0-9]* *.so.[0-9]*.[0-9]*  
    fi
}

export -f check
export -f echeck
export -f clean
