#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

sudo rm /usr/local/cdi/cdi-as
sudo rm /usr/local/cdi/cdi-ld
sudo ln -sf "$SCRIPT_DIR/../gcc_wrappers/cdi-as.py" /usr/local/cdi/cdi-as     
sudo ln -sf "$SCRIPT_DIR/../gcc_wrappers/cdi-ld.py" /usr/local/cdi/cdi-ld     

