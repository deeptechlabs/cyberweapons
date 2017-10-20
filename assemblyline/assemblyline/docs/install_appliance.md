# Assemblyline appliance installation instruction
This will install Assemblyline on a bare-metal machine. All actions need to be performed from the machine you're installing.

**Prerequisites:**

* Installation of base Ubuntu 14.04.x image. See [Install Ubuntu Server](install_ubuntu_server.md)

## Install bootstrap and source

### Install GIT and SSH

    sudo apt-get update
    sudo apt-get -y install git ssh

### Update .bashrc

    cat >> ~/.bashrc <<EOF
    export PYTHONPATH=/opt/al/pkg
    source /etc/default/al
    EOF

    source ~/.bashrc

### Create repository directory

    sudo mkdir -p ${PYTHONPATH} &&
    sudo chown -R `whoami`:`groups | awk '{print $1}'` ${PYTHONPATH}/.. &&
    cd ${PYTHONPATH}

### Clone/create main repos

    cd $PYTHONPATH
    git clone https://bitbucket.org/cse-assemblyline/assemblyline.git -b prod_3.2
    
### Create Appliance Deployment

    /opt/al/pkg/assemblyline/deployment/create_deployment.py

    # Answer the questions from deployment script
    # NOTE:
    #    Answer to "Which deployment type would you like?" has to be: 2
    #    Answer to "Where would you like us to create your deployment?" has to be: /opt/al/pkg
    #    You don't really need to save the al_private to your git repo.

## Install Riak

### Run install script

    export AL_SEED=al_private.seeds.deployment.seed
    /opt/al/pkg/assemblyline/al/install/install_riak.py
    sudo reboot

    export AL_SEED=al_private.seeds.deployment.seed
    /opt/al/pkg/assemblyline/al/install/install_riak.py
    unset AL_SEED

## Install Core

### Run install script

    /opt/al/pkg/assemblyline/al/install/install_core.py

## Install Worker

### Run install script

    /opt/al/pkg/assemblyline/al/install/install_worker.py

