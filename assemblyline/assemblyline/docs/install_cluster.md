# Assemblyline cluster installation

Unless otherwise noted perform these steps in the order listed.

## Pre-requisites

* All boxes have a fresh ubuntu 14.04.x server install. (See [Install notes](install_ubuntu_server.md))

## On All Boxes
We recommend using clusterssh when performing operations on multiple computers to ensure they are all configured the same way.

### Setup Environment

    sudo apt-get update
    sudo apt-get -y install git ssh

    cat >> ~/.bashrc <<EOF
    export PYTHONPATH=/opt/al/pkg
    source /etc/default/al
    EOF

    source ~/.bashrc

    sudo mkdir -p ${PYTHONPATH} &&
    sudo chown -R `whoami`:`groups | awk '{print $1}'` ${PYTHONPATH}/.. &&
    cd ${PYTHONPATH}

## CORE Server Pre-Install

### Clone/create main repos

    cd $PYTHONPATH
    git clone https://bitbucket.org/cse-assemblyline/assemblyline.git -b prod_3.2
    
### Create cluster deployment
**IMPORTANT**
While running the following command, you will be asked a series of questions concerning your infrastructure.
You will need to know the following things before you run the script:

* Name of your deployment
* Acronym for your organization
* Production cluster or not
* Password you want to give the admin user
* Fully qualified domain name for your web interface
* Core server IP
* IPs and amount of RAM on all of the riak nodes
* IPs of all the worker nodes
* If the workers are baremetal boxes or VMs (we recommand baremetal)
* If you plan on having a log server, the server IP and the amount of RAM 

Once you have all that info you can create your deployment.

    /opt/al/pkg/assemblyline/deployment/create_deployment.py

    # Answer the questions from deployment script
    # NOTE:
    #    Answer to "Which deployment type would you like?" has to be: 3
    #    Answer to "Where would you like us to create your deployment?" has to be: /opt/al/pkg

### Initialise a repo for your al_private

    cd ${PYTHONPATH}/al_private
    git init
    git add -A
    git config user.email "core@al.private"
    git config user.name "Core server"
    git commit -a -m "Initial commit for al_private"

**NOTE**: You can use a real email and user for your private repo and add a remote to push it to your git

### Clone all other repos

    ./assemblyline/al/run/setup_dev_environment.py al_private.seeds.deployment.seed

### Create temporary git server

    mkdir ${PYTHONPATH}/../git && cd ${PYTHONPATH}/../git
    git clone --bare ../pkg/assemblyline/ assemblyline && (cd assemblyline && git update-server-info)
    git clone --bare ../pkg/al_ui/ al_ui && (cd al_ui && git update-server-info)
    git clone --bare ../pkg/al_private/ al_private && (cd al_private && git update-server-info)
    for svc in ../pkg/al_services/*; do [ -d $svc ] && git clone --bare $svc al_services/`echo $svc | sed -e 's|../pkg/al_services/||g'` && (cd al_services/`echo $svc | sed -e 's|../pkg/al_services/||g'` && git update-server-info) done;
    cd ${PYTHONPATH}/.. && sudo python -m SimpleHTTPServer 80

    # Note: Leave web server running in a window (you will return to this window later).

## Riak Nodes (using cluster SSH)

### Set AL_SEED to an appropriate value and update .bashrc
**NOTE**: Set AL_CORE_IP to the IP of your CORE node

    cat >> ~/.bashrc <<EOF
    export AL_SEED=al_private.seeds.deployment.seed
    export AL_CORE_IP=
    EOF

    source ~/.bashrc

### Clone assemblyline repo

    cd $PYTHONPATH
    git clone http://${AL_CORE_IP}/git/al_private
    git clone http://${AL_CORE_IP}/git/assemblyline

### Run install script

    /opt/al/pkg/assemblyline/al/install/install_riak.py
    sudo reboot

    # Login and run the script again.
    /opt/al/pkg/assemblyline/al/install/install_riak.py

## Returning to CORE Server

### Stop temporary git HTTP server
    # Switch back to the window containing the running SimpleHTTPServer.
    ^C
    rm -rf git

### Run install script with install seed

    export AL_SEED=al_private.seeds.deployment.seed
    /opt/al/pkg/assemblyline/al/install/install_core.py

## Log Server (Optional)
If a log server is specified in your seed, should should install it now.

### Update .bashrc
**NOTE**: Set AL_CORE_IP to the IP of your CORE node

    cat >> ~/.bashrc <<EOF
    export AL_CORE_IP=
    EOF

    source ~/.bashrc

### Clone repos

    cd ${PYTHONPATH}
    git clone http://${AL_CORE_IP}/git/al_private
    git clone http://${AL_CORE_IP}/git/assemblyline

### Run install script with install seed

    export AL_SEED=al_private.seeds.deployment.seed
    /opt/al/pkg/assemblyline/al/install/install_logserver.py

## Workers (using cluster SSH)

### Update .bashrc
**NOTE**: Set AL_CORE_IP to the IP of your CORE node

    cat >> ~/.bashrc <<EOF
    export AL_CORE_IP=
    EOF

    source ~/.bashrc

### Clone repos

    cd ${PYTHONPATH}
    git clone http://${AL_CORE_IP}/git/al_private
    git clone http://${AL_CORE_IP}/git/assemblyline

### Run install script with install seed

    export AL_SEED=al_private.seeds.deployment.seed
    /opt/al/pkg/assemblyline/al/install/install_worker.py

