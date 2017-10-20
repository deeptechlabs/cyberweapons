#!/bin/bash 

YARA_TGZ=$1
TMP=/tmp

if [ ! -e "$YARA_TGZ" ]; then
    echo "Yara package does not exist: $YARA_TGZ"
    exit 1
fi

Exit() {
    echo "$2" >&2
    exit $1
}


(
tar -xvzf $YARA_TGZ -C $TMP  &&
cd ${TMP}/yara-3.4.0 &&
./bootstrap.sh &&
./configure --prefix /usr/local && 
make && 
sudo make install 
echo "Complete native build."
) || Exit 1 "Error install native yara engine"


# The python bindings (from the core tarball extracted above).
(
cd ${TMP}/yara-3.4.0/yara-python &&
python setup.py build &&
sudo python setup.py install &&
echo "Completed python binding installation."
) || Exit 1 "Error install yara python bindings."

# Ensure the yara libs are found in LD_LIBRARY_PATH
sudo ldconfig
