#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"                  

# sanity check on cwd
if [ "$(basename "$SCRIPT_DIR")" != musl ]; then
    echo "setup.bash must be run in the directory in which it's found" >&2
    exit 1
fi

compile_type="$1"
if [ "$compile_type" == "static" ]; then
    compile_type="--disable-shared"
elif [ "$compile_type" == "dynamic" ]; then
    compile_type=""
else
    echo "usage: ./setup.bash [static/dynamic]" >&2
    echo "    static:  do not use shared libraries" >&2
    echo "    dynamic: compile with shared libraries" >&2
    exit 1
fi


rm -rf build
rm -rf dest
mkdir build
mkdir dest

cd build
make distclean 2> /dev/null

export REALGCC="cdi-gcc"
../musl/configure --prefix="$(pwd)/../dest/" "$compile_type" CC=cdi-gcc CFLAGS="-O0"

