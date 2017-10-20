#!/usr/bin/env python

from assemblyline.al.install import SiteInstaller
from assemblyline.al.install.stages import cmd_service_all

alsi = SiteInstaller()

alsi.milestone("Stoping components")
cmd_service_all(alsi, 'stop')

alsi.milestone("Installing pip configuration files")
alsi.install_persistent_pip_conf()

alsi.milestone("Creating AL user")
from assemblyline.al.install.stages import install_00_init
install_00_init.install(alsi)

alsi.milestone("Installing Bootstrap")
from assemblyline.al.install.stages import install_20_bootstrap
install_20_bootstrap.install(alsi)

alsi.milestone("Fix default AL exports for VM based systems")
alsi.sudo_sed_inline("/etc/default/al",
                    ["s/{installer_host}/datastore.al/".format(installer_host=alsi.config['core']['nodes'][0])])

alsi.milestone("Installing Core Dependancies")
from assemblyline.al.install.stages import install_30_core_deps
install_30_core_deps.install(alsi)

alsi.milestone("Installing Hostagent")
from assemblyline.al.install.stages import install_70_hostagent
install_70_hostagent.install(alsi, install_kvm=False, register_host=False)

alsi.milestone("Patch hostagent to use the bootstrap mode")
alsi.sudo_install_file("assemblyline/al/run/vmbootstrap/hostagent-withbootstrap.conf", "/etc/init/hostagent.conf")

alsi.milestone("Installing Supplementary Packages")
from assemblyline.al.install.stages import install_90_supplementary
install_90_supplementary.install(alsi)

alsi.milestone("Cleaning up")
from assemblyline.al.install.stages import install_90_cleanup
install_90_cleanup.install(alsi)

alsi.milestone("Stopping components")
cmd_service_all(alsi, 'stop')

alsi.milestone("Completed.")
