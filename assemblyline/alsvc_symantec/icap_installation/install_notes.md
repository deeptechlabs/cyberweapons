# Setup Symantec Icap Server
This will install Symantec Protection Engine CS on either a VM or a baremetal box.

**Prerequisites:**

* You have to install the Centos 7 Minimal OS before
* You have a copy of the latest Symantec Protection Engine CS zip installer in your home folder (Doc was built with version: 7.8.0.141)
* You have a valid licence file in your home folder

## Install pre-requisite packages

    yum install net-tools nano NetworkManager-tui unzip sharutils glibc initscripts libuuid.i686

## Extract the installer

    cd
    unzip Symantec_Protection_Engine_CS_7.8.0.141_Linux_IN.zip

## Run the installer

    cd ~/Symantec_Protection_Engine/Symantec_Protection_Engine/RedHat
    ./SymantecProtectionEngine.sh

## Add the licence file

    cp ~/<YOUR LICENCE FILE> /opt/Symantec/Licenses/
    /etc/init.d/symcscan restart
