# Assemblyline Development VM installation instruction
This will install Assemblyline in a self contained virtual machine. All actions need to be performed from inside the virtual machine you're installing.

*NOTE: Development VM installation disables Assemblyline virtual machine service support.*

**Prerequisites:**

* Installation of base Ubuntu 14.04.x image. See [Install Ubuntu Server](install_ubuntu_server.md)
* Your machine should have a minimum of 8GB RAM and 20GB of disk space(less is possible through SOLR/Riak configs)
* You are on a network connected to the internet and can download files from Amazon S3

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

    # The source command will generate an error, but it will disappear once the install is complete.

### Create repository directory

    sudo mkdir -p ${PYTHONPATH} &&
    sudo chown -R `whoami`:`groups | awk '{print $1}'` ${PYTHONPATH}/.. &&
    cd ${PYTHONPATH}

### Clone/create main repos

    cd $PYTHONPATH
    git clone https://bitbucket.org/cse-assemblyline/assemblyline.git -b prod_3.2

### Create Dev VM Deployment

    /opt/al/pkg/assemblyline/deployment/create_deployment.py

    # Answer the questions from deployment script
    # NOTE:
    #    Answer to "Which deployment type would you like?" has to be: 1
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

## Tweaks (optional but recommended)

This tweak enables you to code on your desktop and sync your code to the VM via SSH or PyCharm's remote deployment interface rather than the git repository. The tweak will prevent the VM from pulling the code when the hostagent is restarted.

#### Sinkhole bitbucket.org:

    sudo su -c 'echo "127.0.0.1    bitbucket.org" >> /etc/hosts'
