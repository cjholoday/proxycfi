#!/bin/bash

rm -f *.o *.s *.json *.i *.ftypes *.fptypes output out

cdi_flags="-g --save-temps -fno-jump-tables"
cdi-gcc $cdi_flags main.c -o out -lssl -lcrypto

# This test requires that:
#
# 1. openssl is installed
# 2. libcrypto.so and libssl.so have been compiled with -g 
#    --> you'll have to compile from source yourself
#    --> make sure you include versioning by using -Wl,--version-script=[file]
#    --> when the compilation is finished put the two shared libraries in 
#        /usr/local/cdi/lib if they are fully CDI or in /usr/local/cdi/ulib if
#        they are simply compiled with debug symbols
#    --> The version script should contain: 
#
#   OPENSSL_1.0.0 {                                                                    
#       global:                                                                        
#         *;                                                                         
#   };      
#
#    --> Configure with something like this: 
#        ./config -g --shared -fno-omit-frame-pointer --openssldir=/usr/local/cdi/openssl --prefix=/usr/local/cdi --version-script=openssl.ld




if [ "$?" != 0 ]; then
    echo ERROR: Compilation failed!
    exit 1
fi

./out > output

if [ "$?" != 0 ]; then
    echo ERROR: Running the executable for the test failed!
    exit 1
fi

diff output correct_output

if [ "$?" != 0 ]; then
    echo ERROR: Incorrect output!
    exit 1
fi
