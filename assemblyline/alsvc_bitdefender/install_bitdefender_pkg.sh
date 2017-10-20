#!/bin/bash

BDRUN=$1

Exit() {
    echo "$2"
    exit $1
}

DPKG_OUT=`dpkg -l | grep "ii  bitdefender"`

if [ "${DPKG_OUT}" != "" ];
then
    Exit 0 "BitDefender already installed"
fi

[ -e "$BDRUN" ] || Exit 1 "BitDefender Installer not found: ${BDRUN}"

chmod +x ${BDRUN}
rm -rf /tmp/bdinstall/ 2> /dev/null
yes n | sh ${BDRUN} --target /tmp/bdinstall/ --uninstall
sudo dpkg -i /tmp/bdinstall/bitdefender-scanner_7.6-4_amd64.deb
rm -rf /tmp/bdinstall/
