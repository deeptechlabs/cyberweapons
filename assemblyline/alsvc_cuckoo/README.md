# CUCKOO SERVICE
This ASSEMBLYLINE service provides the ability to perform live dynamic analysis on submitted files via the Open Source project [Cuckoo Sandbox](https://cuckoosandbox.org).

**NOTE**: This service **requires extensive additional installation** before being functional. It is **not** preinstalled during a default installation.

## CUCKOO OVERVIEW

Cuckoo Sandbox supports instrumenting Windows, Linux, Macintosh, and
Android virtual machines; and can also launch files that may cause unintended execution, like PDF's. The Cuckoo 
Sandbox monitors execution, filesystem, and network activity that occurs when a file is opened. This service summarizes 
these results for the ASSEMBLYLINE UI and provides a links to the full result set. Files that are unpacked and saved to 
disk are fed back into ASSEMBLYLINE.

## DEPLOYMENT INSTRUCTIONS

Prior to provisioning a Cuckoo service, please read and understand this document. Failure to do so may result in a 
large volume of error messages in your hostagent log file. 

### CONFIGURATIONS

The Cuckoo service provides a number of sane default configurations. However, if the administrator plans on running
multiple virtual machines simultaneously the ram usage options should be increased as needed. The submission parameter 
`routing` affects whether submissions can talk to the internet or not. 

| Name | Default | Description |
|:---:|:---:|---|
|ramdisk_size|2048M|This is the size of the ramdisk that Cuckoo will use to store VM snapshots and the running virtual machine image. If it's not large enough analysis will fail, see the Troubleshooting section for more information.|
|ram_limit|3072m|This is the maximum amount of ram usable by the Cuckoobox docker container. It doesn't include memory used by inetsim or the Cuckoo service. It should be at least 1G greater than the ramdisk.|
|routing| inetsim, gateway |This submission parameter indicates which routing options users can use. Inetsim is an internet simulator, and gateway routes traffic onto the internet. If either of these are disabled they will no longer be usable by users.|

### DOCKER COMPONENTS

#### Registry

Refer to the following website for registry deployment options.

    https://docs.docker.com/registry/deploying/

To simply start up a local registry, run the following command. This is most useful in an appliance or dev-vm 
deployment.

    sudo docker run -d -p 127.0.0.1:5000:5000 --name registry registry:2

Make sure to configure this registry in the ASSEMBLYLINE seed.

    seed['installation']['docker']['private_registry'] = 'localhost:5000'

In a cluster deployment you will want to set up an authentication proxy with a docker registry on your support server. 
Below are instructions for an Nginx based proxy for domain support.example.com listening on port 8443.

First generate a new pki key, note that docker requires the CN to be the domain of the support server.

    mkdir certs
    openssl req -newkey rsa:4096 -nodes -sha256 \
    -subj '/CN=support.example.com/O=../C=..'
    -keyout certs/support.example.com.key -x509 \
    -days 365 -out certs/support.example.com.cert
    
    cp certs/support.example.com.cert /usr/local/share/ca-certificates/support.example.com.crt
    update-ca-certificates
    
    mkdir /etc/docker/certs.d/support.example.com:8443
    cp certs/support.example.com.cert /usr/local/share/ca-certificates/support.example.com.cert
    cp certs/support.example.com.key /usr/local/share/ca-certificates/support.example.com.key
    chown -R root:root /etc/docker/certs.d/support.example.com:8443
    chmod -R go-rwx /etc/docker/certs.d/support.example.com:8443
    ln -s /etc/docker/certs.d/support.example.com:8443 /etc/docker/certs.d/support.example.com_8443

Note that the final link is created to avoid issues surrounding colons in a filename. Next create some users and 
passwords. I generate passwords with `dd if=/dev/urandom bs=33 count=1 2> /dev/null| base64` but in the example below 
password is used as a password for brevity.

    mkdir auth
    docker run --rm --entrypoint htpasswd registry:2 -Bbn admin password >> auth/htpasswd
    docker run --rm --entrypoint htpasswd registry:2 -Bbn user password >> auth/htpasswd
    cp auth/htpasswd /etc/nginx/docker.htpasswd

You will need to save the following nginx configuration file in /etc/nginx/sites-enabled/docker-proxy

    upstream docker-registry {
      server 127.0.0.1:8443;
    }
    
    server {
      listen                          10.80.30.10:8443 ssl;
      server_name                     support.example.com;
      ssl_certificate                 /etc/docker/certs.d/support.example.com_8443/ca.cert;
      ssl_certificate_key             /etc/docker/certs.d/support.example.com_8443/ca.key;
    
      ssl_protocols TLSv1.1 TLSv1.2;
      ssl_ciphers 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';
      ssl_prefer_server_ciphers on;
      ssl_session_cache shared:SSL:10m;
    
      client_max_body_size            0;
      chunked_transfer_encoding       on;
    
      proxy_set_header Host           $http_host;
      proxy_set_header X-Real-IP      $remote_addr;
      proxy_set_header Authorization  "";
    
      location /v2/ {
        auth_basic                    "Docker Registry";
        auth_basic_user_file          /etc/nginx/docker.htpasswd;
        error_log                     /var/log/nginx/docker.log;
    
        proxy_buffering off;
        proxy_pass                          https://docker-registry;
        proxy_read_timeout                  900;
        proxy_set_header  X-Real-IP         $remote_addr; # pass on real client's IP
        proxy_set_header  X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header  X-Forwarded-Proto $scheme;
    
        set $check 'U';
    
        if ($remote_user = "admin") {
          set $check "";
        }
        if ($request_method !~* "^(GET|HEAD)$") {
          set $check "${check}A";
        }
        if ($check = "UA") {
          # not admin and not GET/HEAD
          return 403;
        }
      }
      location / {
        return 403;
      }
    }

After restarting Nginx, launch the docker registry with the following command.

    docker run -d -p 127.0.0.1:8443:5000 --restart=always --name registry \
     -v /etc/docker/certs.d/support.example.com_8443:/certs:ro \
     -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/ca.cert \
     -e REGISTRY_HTTP_TLS_KEY=/certs/ca.key registry:2

You will need to add the following lines to your seed. 

    seed['installation']['docker']['private_registry'] = 'support.example.com:8443'
    seed['installation']['docker']['private_registry_key'] = """
        Contents of /usr/local/share/ca-certificates/support.example.com.cert
    """
    seed['installation']['docker']['private_registry_auth'] = "user:password".encode('base64').strip()

And you will need to re-run the Cuckoo installer.py to install the certificates and credentials on each worker.

#### Build Docker Image

The following commands assume a local registry. Change localhost as needed for a remote registry. If a remote registry 
is configured on all workers, the following commands will only need to be run once.

    cd /opt/al/pkg/al_services/alsvc_cuckoo/docker/cuckoobox
    sudo apt-get install python-dev libffi-dev libfuzzy-dev
    sudo -u al bash libs.sh
    sudo docker build -t localhost:5000/cuckoo/cuckoobox .
    sudo docker push localhost:5000/cuckoo/cuckoobox

If the `docker build` stages result in network errors, add `--network host` to the build commands.

### Routes

By default Cuckoo ships with two routes for network traffic. The internet simulator "inetsim", and "gateway," a direct 
connection to the internet via the ASSEMBLYLINE worker's gateway. Either of these can be disabled in the Cuckoo service 
configurations.

### EPHEMERAL VIRTUAL MACHINE

#### Build Base Virtual Machine

This step will very slightly depending on whatever operating system you choose. These are examples for Windows 7 and 
Ubuntu. Cuckoo expects all virtual machine data and metadata to exist under /opt/al/var/support/vm/disks/cuckoo/ 
which can be modified via the ASSEMBLYLINE configurations.

Before continuing, make sure the following libraries are installed:

    sudo apt-get install libguestfs-tools python-guestfs

##### Ubuntu 14.04

    sudo -u al mkdir -p /opt/al/var/support/vm/disks/cuckoo/Ubuntu1404/
    sudo -u al qemu-img create -f qcow2 /opt/al/var/support/vm/disks/cuckoo/Ubuntu1404/Ub14disk.qcow2 20G
    sudo virt-install --connect qemu:///system --virt-type kvm --name Ubuntu1404 --ram 1024             \
        --disk path=/opt/al/var/support/vm/disks/cuckoo/Ubuntu1404/Ub14disk.qcow2,size=20,format=qcow2  \
        --vnc --cdrom /path/to/install/CD.iso  --network network=default,mac=00:01:02:16:32:63          \
        --os-variant ubuntutrusty
        
Once the operating system has been installed, perform the following setup.

* Set NOPASSWD on the user accounts sudoers entry
* Set the user account to automatically login
* Copy agent.py from the cuckoo repository to the main users home directory in the virtual machine
* Set `sudo ~/agent.py` and `bash /bootstrap.sh` to run on login
    * This step will depend on window manager, but the command `gnome-session-manager` works for gnome
* Install the following packages on the virtual machine: systemtap, gcc, linux-headers-$(uname -r)
* Copy `data/strace.stp` onto the virtual machine
* Run `sudo stap -k 4 -r $(uname -r) strace.stp -m stap_ -v`
* Place stap_.ko into /root/.cuckoo/
* Uninstall the following packages which cause extraneous network noise:
    * software-center
    * update-notifier
    * oneconf
    * update-manager
    * update-manager-core
    * ubuntu-release-upgrader-core
    * whoopsie
    * ntpdate
    * cups-daemon
    * avahi-autoipd
    * avahi-daemon
    * avahi-utils
    * account-plugin-salut
    * libnss-mdns
    * telepathy-salut
* Delete `/etc/network/if-up.d/ntpdate`
* Add `net.ipv6.conf.all.disable_ipv6 = 1` to /etc/sysctl.conf
* Edit `/etc/init/procps.conf`, changing the "start on" line to `start on runlevel [0123456]`

When done, shutdown the virtual machine. Remove the CD drive configuration from the virtual machine. The virtual 
machine will fail if it contains any references to the install medium.

    sudo virsh edit Ubuntu1404

Create a snapshot of the virtual machine.

    sudo virsh snapshot-create Ubuntu1404

Verify that there is a "current" snapshot with the following command, it should result in a lot of XML.

    sudo virsh snapshot-current Ubuntu1404

Then continue from the "Prepare the snapshot for Cuckoo" section.

##### Windows 7

    sudo -u al mkdir -p /opt/al/var/support/vm/disks/cuckoo/Win7SP1x86/
    sudo -u al qemu-img create -f qcow2 /opt/al/var/support/vm/disks/cuckoo/Win7SP1x86/Win7disk.qcow2 20G
    sudo virt-install --connect qemu:///system --virt-type kvm --name Win7SP1x86 --ram 1024             \
        --disk path=/opt/al/var/support/vm/disks/cuckoo/Win7SP1x86/Win7disk.qcow2,size=20,format=qcow2  \
        --vnc --cdrom /path/to/install/CD.iso  --network network=default,mac=00:01:02:16:32:64          \
        --os-variant win7 --video cirrus

Once the operating system has been installed, perform the following setup.

* Install Python 2.7
* Optional: Install PIL (Python Image Library) if periodic screenshots are desired
* Disable Windows Update, Windows Firewall, and UAC(User Access Control)
* set python.exe and pythonw.exe to "Run as Administrator"
* Optional: Install Java, .Net, and other runtime libraries
* Copy agent.py from the cuckoo repository to the users startup folder
* Rename the extension from .py to .pyw
* Make sure no password is required to get to a desktop from boot
* Create a RunOnce key for c:\bootstrap.bat

When done, shutdown the virtual machine. Windows may choose to hibernate instead of shutting down, make sure the
guest has completely shut down. Remove the CD drive configuration from the virtual machine. The virtual machine will
fail if it contains any references to the install medium.

    sudo virsh edit Win7SP1x86

Create a snapshot of the virtual machine.

    sudo virsh snapshot-create Win7SP1x86

Verify that there is a "current" snapshot with the following command, it should result in a lot of XML.

    sudo virsh snapshot-current Win7SP1x86

##### Windows 10

Windows 10 is not *Officially* supported.

##### Android

Android is not *Officially* supported.

#### Prepare the snapshot for Cuckoo

The prepare_vm command line will also differ depending on OS, and IP space. A sample for Windows 7 is provided 
below.

    source /etc/default/al
    cd /opt/al/pkg/al_services/alsvc_cuckoo/vm
    sudo -u al PYTHONPATH=$PYTHONPATH ./prepare_vm.py --domain Win7SP1x86 --platform windows \
        --hostname PREPTEST --tags "pe32,default" --force --base Win7SP1x86  --name inetsim_Win7SP1x86 \
        --guest_profile Win7SP1x86 --template win7 --ordinal 10 --route inetsim
    
The parameters for prepare_vm.py are:

* domain
    * The same as the virt-install --name argument
* platform
    * The "Cuckoo platform." Either "windows" or "linux" 
* hostname
    * A new hostname for the prepared VM 
* tags
    * Comma separated list of tags which map to partial or full tags in common/constraints.py
    * Cuckoo will favour more specific tags
    * One VM may include the tag "default" to function as a default.
* force
    * Overwrite domain name if needed.
* base
    * Subdirectory of /opt/al/var/support/vm/disks/cuckoo/ containing the disk.
* name
    * Name of the new domain to create.
* guest_profile
    * The volatility profile
    * A list of all possible guest profiles is available on the [Volatility website.](https://github.com/volatilityfoundation/volatility/wiki/Volatility%20Usage#selecting-a-profile)
* template
    * The prepare_vm template, valid values are "win7", "win10", or "linux"
* ordinal
    * A number between 1 and 32000, each prepared virtual machine needs a unique ordinal
    * This number is turned into an IP address, so any collision between deployed virtual machines may cause undefined 
  errors
* route
    * Either gateway or inetsim
    * If gateway is chosen, all traffic from the virtual machine will be routed over the internet
    * If inetsim is chosen, all traffic from the virtual machine will be routed to an inetsim instance 

#### Deploy all snapshots to Cuckoo

Once you've prepared all the virtual machine, there should be a number of .tar.gz files containing virtual machine
metadata. The prepare_cuckoo.py overwrites the current cuckoo configuration, so it's recommended to keep these files
handy in case you want to deploy new virtual machines in future. The prepare_cuckoo.py script will automatically
retrieve Cuckoo service configurations including metadata paths and enabled routes. If you change these configurations 
you will also need to run prepare_cuckoo.py again.

    source /etc/default/al
    cd /opt/al/pkg/al_services/alsvc_cuckoo/vm
    sudo -u al PYTHONPATH=$PYTHONPATH ./prepare_cuckoo.py *.tar.gz
    
This is all that's needed for ASSEMBLYLINE deployments on single node appliances. To deploy ASSEMBLYLINE in a cluster, 
Move all the files in /opt/al/var/support/vm/disks/cuckoo/ to the vm/disks/cuckoo folder on the support server.

### DEBUGGING

If you've deployed ASSEMBLYLINE in a cluster configuration and the Cuckoo service can't start up, check the logs for 
transport errors. It is possible that there is a mismatch between the FTP root of the support host and Cuckoo's service 
configurations. The REMOTE_DISK_ROOT should be relative to the support hosts FTP root directory.

If you need to enter a running cuckoobox docker container while ASSEMBLYLINE is running, use the following command.

    sudo docker exec -ti `sudo docker ps | grep cuckoobox | cut -d ' ' -f 1` bash

To change the service configurations, use supervisorctl.

    supervisorctl -s unix:///tmp/supervisor.sock

You will find log files in /tmp and /opt/sandbox/bootstrap.log

If analysis sometimes succeeds and sometimes fails, make sure the tmpfs filesystem isn't filling up.

If you find that the Cuckoobox container exists immediately after being launched, this may be an out-of-memory issue on 
the ram mount inside the container. This directory is limited to 2 gigabytes by default, but can be modified in the 
ASSEMBLYLINE configurations. It must be large enough to store the snapshot image for all virtual machines with enough 
room left over for any given virtual machine to run a malware sample.
