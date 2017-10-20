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

alsi.milestone("Setup and clone git repos")
alsi.setup_git_repos()

alsi.milestone("Reload configuration")
alsi.reload_config()

alsi.milestone("Installing Bootstrap")
from assemblyline.al.install.stages import install_20_bootstrap
install_20_bootstrap.install(alsi)

alsi.milestone("Installing Core Dependancies")
from assemblyline.al.install.stages import install_30_core_deps
install_30_core_deps.install(alsi)

alsi.milestone("Patching /etc/hosts to route datastore.al to localhost")
from assemblyline.al.install.stages import install_40_patch_hosts
install_40_patch_hosts.install(alsi)

alsi.milestone("Installing Harddrive monitor")
from assemblyline.al.install.stages import install_40_harddrive_monitor
install_40_harddrive_monitor.install(alsi)

alsi.milestone("Installing System Metrics Collector")
from assemblyline.al.install.stages import install_60_system_metrics
install_60_system_metrics.install(alsi)

alsi.milestone("Installing Haproxy")
from assemblyline.al.install.stages import install_60_haproxy
install_60_haproxy.install(alsi, include_worker_extensions=True)

alsi.milestone("Installing Hostagent")
from assemblyline.al.install.stages import install_70_hostagent
install_70_hostagent.install(alsi)

alsi.milestone("Installing Controller")
from assemblyline.al.install.stages import install_70_controller
install_70_controller.install(alsi)

alsi.milestone("Installing Service Dependencies")
from assemblyline.al.install.stages import install_80_services
install_80_services.install(alsi, register=False)

alsi.milestone("Installing Supplementary Packages")
from assemblyline.al.install.stages import install_90_supplementary
install_90_supplementary.install(alsi)

alsi.milestone("Cleaning up")
from assemblyline.al.install.stages import install_90_cleanup
install_90_cleanup.install(alsi)

alsi.milestone("Starting components")
cmd_service_all(alsi, 'stop')
cmd_service_all(alsi, 'start')

alsi.milestone("Completed.")
