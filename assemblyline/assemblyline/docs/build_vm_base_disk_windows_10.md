# Creating the Windows 10 Base Disk

### Prerequisites

1. You have KVM and virtmanager installed on your Linux workstation.
2. You have an ISO for Windows 10 enterprise
3. You have saved your al_private directory to your personal user account on bitbucket

### Create the (initially empty) base disk image:

    qemu-img create -f qcow2 -o preallocation=metadata base-win10x64.001.qcow2 40G

### Use Virt-Manager GUI to create and install the operating system

    virt-manager

Inside virt-manager do the following:

    Right Click localhost (QEMU)
      New
        Name: Windows10x64Base
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

        Ready to begin installation of Windows10x64Base:
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
    Type a password: ROOT_PASS
    Retype your password: ROOT_PASS
    Type a password hint: ROOT_PASS_HINT

On first boot:

    Right-click on desktop -> Display settings
      Advanced display settings
        Select Resolution '1280 x 1024'

    Windows -> Search the web and Windows
      Type: 'Control Panel'

        Security and Maintenance
          Change User Account Control settings
            Select "Never notify"
          Change Windows Smart Screen settings
            Select "Don't do anything"
          Change Security and Maintenance settings
            Uncheck all messages
          Click OK

        Windows Firewall
          Turn Windows Firewall on or off
            Home or work (private) network
              Select Turn off Windows Firewall
            Public network location settings
              Select Turn off Windows Firewall
          Click OK

        Windows Defender
          Settings
            Turn Off
              Real-time protection
              Cloud-based protection
              Sample Submission
            Click on the Windows Update tab
              Advanced Options
                Select "Notify to schedule restart"
                Tick "Defer Upgrade"
                Choose how updates are delivered
                  Turn off

        Power Options
          Show Additional plans
            Select "High Performance"

    Windows -> File Explorer
      Right click Local Disk (C:)
        Properties
          Uncheck 'Allow files on this drive to have contents indexed ...'
          Click Apply
          Select Apply changes to drive C:\ subfolders and files
          Click OK
          Click Continue
          For any Attribute erros say Ignore All

      Right click This PC -> Properties
        Advanced system settings
          Performance
            Click Settings
              Select Adjust for best performance
              Click OK
          Startup and Recovery
            Click Settings
              Select Time to display list of operating systems '5 seconds'
              Select Write debugging information '(none)'

### Install basic tools

Download packages (found in creationtools.zip provided by the developers)

* 7z457-x64
* ActivePython-2.7.8.10-win32-x86
* Git-1.9.4.exe
* gvim74
* Sysinternals Suite
* virtio-win-0.1.126.iso

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

    Insert VirtIO drvier CD
      Click on IDE CDROM 1
        Click Disconnect
        Click Connect
        Click Browse
          Select 'virtio-win-0.1.126.iso'
          Click OK
        Click Boot Options
          Uncheck CDROM
          Click Apply

    Boot the VM and log in
      Windows -> Search the web and Windows
        Type: 'Control Panel'
          Device Manager
            SCSI Controller -> Update Driver Software -> Browse My Computer
              D:\
              Click Next
              Check 'Always trust software from Red Hat'
              Click Install

            Ethernet Controller -> Update Driver Software -> Browse my Computer
              D:\
              Click Next
              Click Close

            PCI Device -> Update Driver Software -> Browse my Computer
              D:\
              Click Next
              Click Close

### Finalise and install Assemblyline

    Edit Registry
      Windows -> Search the web and Windows
        Type: 'regedit'
          HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Disabled (add DWORD 1)
          HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\DontShowUI (add DWORD 1)
          HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware (change from 0 to 1)
          HKLM\SYSTEM\CurrentControlSet\Control\Windows\ErrorMode (change from 0 to 2)
          HKLM\SYSTEM\CurrentControlSet\Control\Windows\ShellErrorMode (change from 1 to 2)

    Enable Autologon
      Windows -> Search the web and Windows
        Type: 'netplwiz'
          Uncheck "Users must enter a user name and password..."
          Click 'OK'
          Enter ROOT_PASS
          Confirm ROOT_PASS
          Click OK
          
    NTFS Disable Last Access Updates, Install and Test Basic Assemblyline, defrag, ...
      Windows -> Search the web and Windows
        Type: 'cmd'
        Right click the Command Prompt Desktop App
          Click "Run as Administrator"
        In command prompt, Type
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
      In the search bar type:
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

    mv base-win10x64.001.qcow2 base-win10x64.001.qcow2.original
    qemu-img convert -O qcow2 -f qcow2 base-win10x64.001.qcow2.original base-win10x64.001.qcow2
    sudo chown `whoami` base-win10x64.001.qcow2

### Upload the new base disk to the disk store:

    Now you need to upload you disk (base-win10x64.001.qcow2) to the location specified in your seed's in `filestore.support_urls` + `vm/disks`.


