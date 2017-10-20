# This is the procedure to install the CFMD Database in mysql

## Install Mysql

    sudo apt-get install mysql-server

    sudo nano /etc/mysql/my.cnf
    # Change the following
    bind-address = 0.0.0.0
    max-connections = 4096

    sudo service mysql restart

## Create and load CFMD DB

    cd /opt/al/pkg/al_services/alsvc_cfmd/db
    ./cfmd_import.sh <PATH TO CFMD DATA>

