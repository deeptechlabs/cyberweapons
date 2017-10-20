# Creating the Windows 7 Base Disk

### Prerequisites

1. You have KVM and virtmanager installed on your Linux workstation.
2. You have an ISO for windows 7 enterprise SP1
3. You have saved your al_private directory to your personal user account on bitbucket

### Create the (initially empty) base disk image:

    qemu-img create -f qcow2 -o preallocation=metadata base-win7sp1x64.001.qcow2 40G

### Use Virt-Manager GUI to create and install the operating system

    virt-manager

Inside virt-manager do the following:

    Right Click localhost (QEMU)
      New
        Name: Windows7SP1x64Base
        Choose how you would like to install the operating system:
            select Import existing disk
        Forward

        Provide the existing storage path:
          Browse and select the .qcow image you create above.

        Choose an operating system type and version:
          OS Type: Windows
          Version: Microsoft Windows 7
        Forward

        Choose Memory and CPU (This can be changed later)
          Memory (RAM): 2048
          CPUs: 2
        Forward

        Ready to begin installation of Windows7SP1x64Base:
          Check 'Customize configuration before install'
        Finish

      Configuration Tweaks
        Select 'Disk 1'
          Expand 'Advanced Options'
          Change Storage format to 'qcow2'
          Click Apply

        Click Add Hardware
          Select Storage
          Click 'Select managed or other existing storage'
          Click Browse
          Click Browse Local
            Select the en_windows_7_xxx.iso you downloaded in the first step.
          Select Device type 'IDE CDROM'
          Finish

        Select Boot Options
          Select CDROM as first boot choice
          Click Apply

      Click Begin Installation

This should save the VM configuration and boot the VM into the Windows installation.

### Install OS

    Type a user name: 'user'
    Type a computer name: 'WIN7SP1X64VM'
    Type a password: ROOT_PASS
    Retype your password: ROOT_PASS
    Type a password hint: ROOT_PASS_HINT

    'Ask me later'

    Time zone: 'Eastern Time (US & Canada)'

    'Work network'


On first boot:

    Right-click on desktop -> Screen resolution
    Select Resolution '1280 x 1024'
    Advanced settings -> Monitor
      Select Colors 'High Color (16 bit)'

    Start -> Control Panel
    System and Security
      Action Center -> Change User Account Control setting
        Select Never notify
      Click OK
      Click Yes

      Action Center
        Change Action Center settings
          Problem reporting settings
            Select Never check for solutions
            Click OK
          Uncheck all messages
          Click OK
        Click Control Panel Home

      Windows Firewall
        Turn Windows Firewall on or off
          Home or work (private) network
            Select Turn off Windows Firewall
          Public network location settings
            Select Turn off Windows Firewall
        Click OK
      Click Control Panel Home

    Hardware and Sound
      Choose a power plan
        Expand Show additional plans
          Select High Performance
          Click Change plan settings
            Select Turn off the display 'Never'
            Click Save changes
          Click Control Panel Home

    Start -> Right click Computer -> Properties
    System protection
      Select 'Local Disk (C:) (System)'
      Click Configure
        Select Turn off system protection
    Remote settings
      Uncheck Allow Remote Assistance
      Click Apply
    Advanced system settings
      Performance
        Click Settings
          Select Adjust for best performance
          Click OK
      Startup and Recovery
        Click Settings
          Select Time to display list of operating systems '5 seconds'
          Select Write debugging information '(none)'

    Start -> Click Computer
    Right Click C:\
      Properties
        Uncheck 'Allow files on this drive to have contents indexed in addition to file properites'
        Click Apply
        Select Apply changes to drive C:\ subfolders and files
        Click Continue
        For any Attribute erros say Ignore All
        Click OK

### Install basic tools

Download packages (found in creationtools.zip provided by the developers)

* 7z457-x64
* ActivePython-2.7.8.10-win32-x86
* Git-1.9.4.exe
* gvim74
* Sysinternals Suite
* Virtio.zip

Install downloaded packages:

    Run and install 7zip installer (Defaults)
    Active Pythoin installer (Defaults)
    Git installer (Disable windows explorer integration)
      Uncheck 'Windows Explorer integration'
      Click Next
      Click Next
      Select 'Use Git from the Windows Command Prompt'
      Click Next
      Leave the default 'Checkout Windows-style, commit Unix-style line endings'
      Click Next

    Install GVim:
      Select create .bat files for command line use

    Unzip SysinternalsSuite to C:\SysinternalsSuite\

    Unzip the virtio.zip to c:\drivers\

    Delete temporary files and unneeded desktop shortcuts

    Empty Recycle Bin

    Shutdown

### Setup VirtIO drivers

We need to temporarily attach a virtio disk to the virtual machine to kick Windows into installing the virtio drivers.

    Add Hardware
      Storage
        Select "Create a disk image on the computer's hard drive"
        Enter 1.0 GB
        Select Device type 'Virtio disk'
        Select Storage format 'qcow2'
        Click Finish

    Click NIC:nn:nn:nn
      Select Device model 'virtio'
      Click Apply

Boot the VM and log in

    Install Drivers
      Start -> Control Panel -> System and Security -> Device Manager
        SCSI Controller -> Update Driver Software -> Browse My Computer
           C:\Drivers\Virtio
           Click OK
           Click Next
           Check 'Always trust software from Red Hat'
           Click Install

        Ethernet Controller -> Update Driver Software -> Browse my Computer
          C:\Drivers\Virtio
          Click OK
          Click Next
          Click Close

### Finalise and install Assemblyline

    Edit Registry
        HKLM\SYSTEM\CurrentControlSet\Control\Windows\ErrorMode (change from 0 to 2)
        HKLM\SYSTEM\CurrentControlSet\Control\Windows\ShellErrorMode (change from 1 to 2)
        HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\DontShowUI (add DWORD 1)

    Enable Autologon
      Start
        C:\SysinternalsSuite\autologon
          Enter the password ROOT_PASS
          Click Enable
          Click OK

    NTFS Disable Last Access Updates, Install and Test Basic Assemblyline, defrag, ...
      Start -> All Programs -> Accessories -> Command Prompt
        Type
          fsutil behvaior set DisableLastAccess 1
          cd \

          mkdir opt
          cd opt
          mkdir al
          cd al
          mkdir pkg
          cd pkg

          set BB_USER=<your_bb_user>

          git clone https://bitbucket.org/cse-assemblyline/assemblyline.git -b prod_3.2
          git clone https://bitbucket.org/%BB_USER%/al_private.git -b prod_3.2

          set AL_SEED=al_private.seeds.deployment.seed
          set PYTHONPATH=\opt\al\pkg

          python /opt/al/pkg/assemblyline/al/install/install_windowsvm.py

          defrag C: /U /V /X
          C:\SysinternalsSuite\sdelete.exe -z
          defrag C: /U /V /X

    Add startup script
      From the start menu choose:
        Run
      Type:
        shell:startup
      Copy /opt/al/pkg/assemblyline/al/run/vmbootstrap/runhostagentforever.vbs into the window that popped up

    Setup system wide environment variables
     Windows -> File Explorer
       Right click This PC -> Properties
         Advanced system settings
           Environment Variables
             System variables
               New...
                 name=PYTHONPATH
                 value=C:\opt\al\pkg
               New...
                 name=AL_DATASTORE
                 value=datastore.al

    Shutdown

### Remove temporary disk

Now that the virtio drivers are installed. We can switch our IDE Disk to VirtIO for better performance.

    In virt-manager Click 'Disk 1'
       Select advanced options:
           Change Disk bus to 'Virtio'
    Boot

### Create a shrunken copy of the disk image.

From the Unix command line:

    mv base-win7sp1x64.001.qcow2 base-win7sp1x64.001.qcow2.original
    qemu-img convert -O qcow2 -f qcow2 base-win7sp1x64.001.qcow2.original base-win7sp1x64.001.qcow2
    sudo chown `whoami` base-win7sp1x64.001.qcow2

### Upload the new base disk to the disk store:

    Now you need to upload you disk (base-win7sp1x64.001.qcow2) to the location specified in your seed's in `filestore.support_urls` + `vm/disks`.


