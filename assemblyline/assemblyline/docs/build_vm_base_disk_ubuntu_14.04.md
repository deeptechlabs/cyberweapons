# Creating the Ubuntu 14.04 base VM disk
This will install the bootstrap code for an assemblyline base VM image. All actions need to be performed on the VM being installed.

**Prerequisites:**

* Installation of the base Ubuntu OS. See [Install Ubuntu Server](install_ubuntu_server.md)
* You have saved your al_private directory to your personal user account on bitbucket

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

### Create the repository directory

    sudo mkdir -p ${PYTHONPATH} &&
    sudo chown -R `whoami`:`groups | awk '{print $1}'` ${PYTHONPATH}/.. &&
    cd ${PYTHONPATH}

### Clone/create main repos

    export BB_USER=<your bitbucket user>

    cd $PYTHONPATH
    git clone https://bitbucket.org/cse-assemblyline/assemblyline.git -b prod_3.2
    git clone https://bitbucket.org/${BB_USER}/al_private.git -b prod_3.2

### Install bootstrap code
    
    export AL_SEED=al_private.seeds.deployment.seed
    /opt/al/pkg/assemblyline/al/install/install_linuxvm_bootstrap.py 
    
### Create a shrunken copy of the disk image.

From the Unix command line:

    mv base-ubuntu1404x64srv.001.qcow2 base-ubuntu1404x64srv.001.qcow2.original
    qemu-img convert -O qcow2 -f qcow2 base-ubuntu1404x64srv.001.qcow2.original base-ubuntu1404x64srv.001.qcow2
    sudo chown `whoami` base-ubuntu1404x64srv.001.qcow2

### Upload the new base disk to the disk store:

    Now you need to upload you disk (base-ubuntu1404x64srv.001.qcow2) to the location specified in your seed's in `filestore.support_urls` + `vm/disks`.

