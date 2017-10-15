#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"                  

# sanity check on cwd
if [ "$(basename "$SCRIPT_DIR")" != musl ]; then
    echo "setup.bash must be run in the directory in which it's found" >&2
    exit 1
fi

rm -rf build
rm -rf dest
mkdir build
mkdir dest

cd build
make distclean 2> /dev/null
export REALGCC="cdi-gcc"
../musl/configure --prefix="$(pwd)/../dest/" CC=cdi-gcc CFLAGS="-O0"

