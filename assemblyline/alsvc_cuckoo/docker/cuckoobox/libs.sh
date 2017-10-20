#!/usr/bin/env bash

mkdir -p libs/

# Collect inetsim
wget -O libs/inetsim_1.2.6-1_all.deb http://www.inetsim.org/debian/binary/inetsim_1.2.6-1_all.deb

echo "Collecting volatility..."
# These are the libraries that need to exist in the 'libs' folder within this directory
# volatility-2.4.1.tar.gz
mkdir -p libs/volatility
git clone https://github.com/volatilityfoundation/volatility.git libs/volatility
cd libs/volatility
git checkout 2.5
tar -zcf ../volatility-2.5.tar.gz *
cd ../
rm -rf volatility
