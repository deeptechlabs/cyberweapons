# This is the procedure to install the NSRL Database in postgresql

This guide was done for NSRL 2.54 but can be adapted for any release DVD iso.

## Download NSRL

    cd
    wget http://www.nsrl.nist.gov/RDS/rds_2.54/RDS_254.iso

## Extract NSRL from ISO

    cd
    mkdir /tmp/NSRL_ISO
    sudo mount -o loop RDS_254.iso /tmp/NSRL_ISO

    mkdir -p ~/NSRL/254
    cp /tmp/NSRL_ISO/* ~/NSRL/254
    sudo umount /tmp/NSRL_ISO

    cd ~/NSRL/254
    unzip NSRLFile.txt.zip && rm NSRLFile.txt.zip
    rm ERRATA.TXT NSRLFile.txt.hash read_me.txt

## Install PostgreSQL

    cd /opt/al/pkg/al_services/alsvc_nsrl/db
    ssh ./install-postgres.sh

    sudo nano /etc/postgresql/9.3/main/postgresql.conf
    # Change the following
    listen_addresses = '*'
    max_connections = 1024
    shared_buffers = 8GB
    work_mem = 16MB

    sudo nano /etc/postgresql/9.3/main/pg_hba.conf
    local   nsrl    <USER>   password
    host    nsrl    <USER>   <NETWORK CIDR> password

## Create NSRL DB

    cd /opt/al/pkg/al_services/alsvc_nsrl/db
    sudo -u postgres create-nsrl.sh <USER> <PASSWORD>

## Load the NSRL DB

    cd /opt/al/pkg/al_services/alsvc_nsrl/db
    sudo -u postgres ./load-nsrl.sh ~/NSRL/254