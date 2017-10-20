# Setup FSecure Icap Server
This will install FSecure GateKeeper server on either a VM or a baremetal box.

**Prerequisites:**

* You have to install the Ubuntu base OS before. See [Install Ubuntu Server](documentation.html?fname=install_ubuntu_server.md)
* You have a copy of the latest FSecure GateKeeper tar.gz installer in your home folder (Doc was built with version: 5.40.73)
* You have a valid licence code

## Install pre-requisite packages

    sudo apt-get install build-essential libc6-i386 lib32stdc++6 wget

## Extract the source

    tar zxvf fsigk-5.40.73-rtm.tar.gz && rm fsigk-5.40.73-rtm.tar.gz && rm fsigk-5.40.73-0.i386.rpm
    tar zxvf fsigk-5.40.73.tar.gz && rm fsigk-5.40.73.tar.gz

## Edit the configuration

    nano ~/fsigk-5.40.73/conf/fsigk.ini

    #Edit the following field to those values:
    fsasd_service=no

    orspservice_service=no
    fsicapd_service=yes
    fsigkwebui_service=no

    spam_cloudscan=no

    orsp_url_check=no
    orsp_file_check=no
    license=<YOUR LICENCE KEY>

    bind_addr=0.0.0.0

    block_riskware=yes

    enable_email_services=no

## Launch the installer

    cd ~/fsigk-5.40.73/
    sudo make install

## Update to latest DAT

    cd /tmp
    wget http://download.f-secure.com/latest/fsdbupdate9.run
    chmod +x fsdbupdate9.run
    sudo service fsigk_fsaua stop
    sudo FSAUA_DATADIR="/opt/f-secure/fsigk/fsaua/data/" ./fsdbupdate9.run -- noinit
    sudo service fsigk_fsaua start