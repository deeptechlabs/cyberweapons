# Setup Kaspersky Icap Server
This will install Kaspersky for Proxy on either a VM or a baremetal box.

**Prerequisites:**

* You have to install the Ubuntu base OS before. See [Install Ubuntu Server](documentation.html?fname=install_ubuntu_server.md)
* You have a copy of the latest Kaspersky for Proxy debian installer in your home folder (Doc was built with version: 5.5-86_i386)
* You have a valid licence file in your home folder

## Install pre-requisite packages

    sudo apt-get install libc6-i386 unzip

## Lauch the installer

    cd
    sudo dpkg -i kav4proxy_5.5-86_i386.deb

    #Note: You need to specify the path to your valid licence file during install

## Edit the configuration
    sudo nano /etc/opt/kaspersky/kav4proxy.conf

    #Edit the following field to those values:
    ListenAddress=0.0.0.0:1344
    SendAVScanResult=true

## Update to latest DAT

    sudo /opt/kaspersky/kav4proxy/bin/kav4proxy-keepup2date