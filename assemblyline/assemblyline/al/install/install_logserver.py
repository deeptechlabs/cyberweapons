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

alsi.milestone("Installing Common Dependencies")
from assemblyline.al.install.stages import install_30_core_deps
install_30_core_deps.install(alsi)

alsi.milestone("Patching /etc/hosts to route datastore.al to localhost")
from assemblyline.al.install.stages import install_40_patch_hosts
install_40_patch_hosts.install(alsi)

alsi.milestone("Installing Harddrive monitor")
from assemblyline.al.install.stages import install_40_harddrive_monitor
install_40_harddrive_monitor.install(alsi)

alsi.milestone("Installing Log Server Components")
from assemblyline.al.install.stages import install_60_logserver
install_60_logserver.install(alsi)

alsi.milestone("Installing System Metrics collector")
from assemblyline.al.install.stages import install_60_system_metrics
install_60_system_metrics.install(alsi)

alsi.milestone("Installing Supplementary Packages")
from assemblyline.al.install.stages import install_90_supplementary
install_90_supplementary.install(alsi)

alsi.milestone("Cleaning up")
from assemblyline.al.install.stages import install_90_cleanup
install_90_cleanup.install(alsi)

alsi.milestone("Completed.")
