#!/bin/bash

cd /usr/local/                                                                 
sudo mkdir -p cdi && cd $_                                                     
sudo rm -f cdi-as cdi-ld                                                       
sudo ln -s $(which as) cdi-as                                                  
sudo ln -s $(which ld) cdi-ld   
