#!/bin/bash

cwd=$(pwd)
cwd_base=$(basename "$cwd")
destination="$cwd/../${cwd_base}-dest"

CC="$1"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cdi_flags="-g --save-temps -fno-jump-tables"
instrumenter="$SCRIPT_DIR/../instrumentation/instrumentation.o"

"$CC" $cdi_flags "$SCRIPT_DIR/../instrumentation/instrumentation.c" -c \
    -o "$instrumenter"

make distclean
if [ -f "configure" ]; then
    ./configure CC="$CC" \
        CFLAGS="$cdi_flags -Wl,$instrumenter -finstrument-functions"
elif [ -f "config" ]; then 
    ./config CC="$CC" \
        CFLAGS="$cdi_flags -Wl,$instrumenter -finstrument-functions"
else
    echo "error: no 'configure' or 'config' file present"
    exit 1
fi

if [ "$?" != 0 ]; then
    exit 1
fi

make 2> e | tee m
if [ "$?" != 0 ]; then
    exit 1
fi

make install DESTDIR="$destination"
if [ "$?" != 0 ]; then
    exit 1
fi
