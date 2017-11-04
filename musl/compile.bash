#!/bin/bash

export CDI_MUSL_STATIC=0

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"                  

# sanity check on cwd
if [ "$(basename "$SCRIPT_DIR")" != musl ]; then
    echo "setup.bash must be run in the directory in which it's found" >&2
    exit 1
fi

cd build
make 2> ../e | tee ../m && make install

