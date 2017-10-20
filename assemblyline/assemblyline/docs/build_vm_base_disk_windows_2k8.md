# Creating the Windows 2008 Base Disk

### Prerequisites

1. You have KVM and virtmanager installed on your Linux workstation.
2. You have an ISO for windows 2k8 r2 SP1
3. You have saved your al_private directory to your personal user account on bitbucket

### Create the (initially empty) base disk image:

    qemu-img create -f qcow2 -o preallocation=metadata base-win2k8r2x64.001.qcow2 40G


### Use Virt-Manager GUI to create and install the operating system

    virt-manager

Inside virt-manager do the following:

    Right Click localhost (QEMU)
      New
        Name: Windows2008Base
        Choose how you would like to install the operating system:
            select Import existing disk
      Forward

      Provide the existing storage path:
        Browse and select the .qcow image you create above.

      Choose an operating system type and version:
        OS Type: Windows
        Version: Microsoft Windows Server 2008
      Forward

      Choose Memory and CPU (This can be changed later)
         Memory (RAM): 2048
         CPUs: 2
      Forward

      Ready to Begin Panel:
        check 'customize configuration before install'
        Finish

      Configuration Tweaks
      Select 'Disk 1'
        Expand 'Advanced Options'
        Change Storage forma to 'qcow2'
        Click Apply

       Click Add Hardware
         Select Storage
         Click 'Select managed or other existing storage.'
         Click Browse
           Select the end_windows_server_2008_r2_xxx.iso you downloaded in the first step.
           Device Type: 'IDE CDROM'
         Finish

      Select Boot Options
        Select CDROM as first boot choice
        Click Apply

      Click Begin Installation


This should save the VM configuration and boot the VM into the windows installation.
  

### Install OS

Start the VM and proceed with the Windows Installation. For the Windows installation you can you select the defaults. For operating system choose: Windows Server 2008 R2 Standard (Full Installation) and
the rest should be intuitive / default based. The system will reboot once and complete the install.

For the initial password use TEMP_ROOT_PASS. We'll tweak password complexity policy later and make it ROOT_PASS.

On first boot make the following OS tweaks:

    Server Manager console :
      Do not show me this console at logon.


    Initial Configuration Tasks:
    Control Panael -> System and Securtiy
       Change computer name:
           Control Panael -> System -> Computer Name:  WIN2008R2x64

       Action Center:
         Security -> User Account Control
             UAC will notify when programs try to make changes to the computer: off (never notify)
         Maintenance
            - Check for solutions to report problems: Never check for solutions


         Maintenance:
          Check for solutions to problem reports
              settings -> Never check for solutions


       Windows Firewall:
          Turn windows firwall on or off
            Turn off for all locations

       Windows Update
          Let me choose my settings
          Never install updates

       Power Options:
         Switch from balanced to 'High Performance' Plan:
         Click change plans settings
             turn off display: never

       System
         Advanced System Settings
           Advanced
             Performance:
               Visual Effects:
                  Performance: Adjust for best performance
           Startup and Recovery
              Time to display list of operating systems: 5 seconds
              System Failure:
                 Write debugging information:
                     (none)

    Administrative Tools:
    Local Security Policy
     Account Policy
        Password Policy
           Maxmimum passowrd age: 0 (forver)
           Password must meet complexity requirements: disabled

    Control Panel -> Appearance -> Display
      Adjust resolution:
        1280x1024

    Services:
      Disable Microsoft Software Shadow Copy

    Disable Index on the C drive:
      Open Explorer
      Right Click C:\
        Properties
        Uncheck 'Allow files on this drive to have contents indexed in addition to file properites'
        Click Apply
        Select Apply changes to drive C:\ subfolders and files
        For any Attribute erros say Ignore All

Change password to ROOT_PASS.

### Install Basic Tools

Download the following: (found in creationtools.zip provided by the developers)

* 7z457-x64
* ActivePython-2.7.8.10-win32-x86
* Git-1.9.4.exe
* sysinternals suite
* virtio.zip

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
      select create .bat files for command line use

    Unzip SysinternalsSuite..zip and copy to C:\SysinternalsSuite\

    Unzip the virtio.zip drivers to c:\drivers\

    Delete temporary files and unneeded desktop shortcuts

    Empty Recycle Bin

    Shutdown

### Setup VirtIO drivers

We need to temporarily attach a virtio disk to the virtual machine to kick Windows into installing the virtio drivers.

    Add Hardware
      Storage
        Create a disk image on the computers hard driver:
        1GB
        Device Type: Virtio Disk
        Storage Format :qcow2

        Click NIC:nn:nn:nn
          Select Device model 'virtio'
          Click Apply

Delete temporary files and unneeded desktop shortcuts

Empty Recycle Bin

Boot the machine, then:

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

Now that the virtio drivers are installed, we can switch our IDE Disk to VirtIO for better performance.

    In virt-manager Click 'Disk 1'
       Select advanced options:
           Change Disk bus to 'Virtio'
    Boot

### Create a shrunken copy of the disk image.

From the Unix command line:

    mv base-win2k8r2x64.001.qcow2 base-win2k8r2x64.001.qcow2.original
    qemu-img convert -O qcow2 -f qcow2 base-win2k8r2x64.001.qcow2.original base-win2k8r2x64.001.qcow2
    sudo chown `whoami` base-win2k8r2x64.001.qcow2

### Upload the new base disk to the disk store:

    Now you need to upload you disk (base-win2k8r2x64.001.qcow2) to the location specified in your seed's in `filestore.support_urls` + `vm/disks`.

