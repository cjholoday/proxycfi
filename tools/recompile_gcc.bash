#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

"$SCRIPT_DIR"/set_wrappers_vanilla.bash

cd "$SCRIPT_DIR"/../cdi-gcc/build 
make 2> errlog2.txt | tee makelog2.txt
make install

"$SCRIPT_DIR"/set_wrappers_cdi.bash


