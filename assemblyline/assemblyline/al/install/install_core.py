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

alsi.milestone("Installing FTP Component")
from assemblyline.al.install.stages import install_10_ftp
install_10_ftp.install(alsi)

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

alsi.milestone("Executing any preinstall hooks for core.")
alsi.execute_core_preinstall_hook()

alsi.milestone("Installing Redis")
from assemblyline.al.install.stages import install_50_redis
install_50_redis.install(alsi)

alsi.milestone("Installing System Metrics Collector")
from assemblyline.al.install.stages import install_60_system_metrics
install_60_system_metrics.install(alsi)

alsi.milestone("Installing UI and REST API")
from assemblyline.al.install.stages import install_60_webui
install_60_webui.install(alsi)

alsi.milestone("Installing Alerter")
from assemblyline.al.install.stages import install_60_alerter
install_60_alerter.install(alsi)

alsi.milestone("Installing Alert Actions")
from assemblyline.al.install.stages import install_60_alert_actions
install_60_alert_actions.install(alsi)

alsi.milestone("Installing Workflow Filters")
from assemblyline.al.install.stages import install_60_workflow_filter
install_60_workflow_filter.install(alsi)

alsi.milestone("Installing Expiry service")
from assemblyline.al.install.stages import install_60_expiry
install_60_expiry.install(alsi)

alsi.milestone("Installing Haproxy")
from assemblyline.al.install.stages import install_60_haproxy
install_60_haproxy.install(alsi)

alsi.milestone("Installing Journalist")
from assemblyline.al.install.stages import install_60_journalist
install_60_journalist.install(alsi)

alsi.milestone("Installing Heuristic Statistics")
from assemblyline.al.install.stages import install_70_heuristic_statistics
install_70_heuristic_statistics.install(alsi)

alsi.milestone("Installing Signature Statistics")
from assemblyline.al.install.stages import install_70_signature_statistics
install_70_signature_statistics.install(alsi)

alsi.milestone("Installing Dispatcher")
from assemblyline.al.install.stages import install_70_dispatcher
install_70_dispatcher.install(alsi)

alsi.milestone("Installing Middleman")
from assemblyline.al.install.stages import install_70_middleman
install_70_middleman.install(alsi)

alsi.milestone("Installing Plumber")
from assemblyline.al.install.stages import install_70_plumber
install_70_plumber.install(alsi)

alsi.milestone("Installing Metrics Daemon")
from assemblyline.al.install.stages import install_70_metricsd
install_70_metricsd.install(alsi)

alsi.milestone("Installing Quota Sniper")
from assemblyline.al.install.stages import install_70_quota_sniper
install_70_quota_sniper.install(alsi)

alsi.milestone("Registering services from the master list.")
from assemblyline.al.install.stages import install_70_register_services
install_70_register_services.install(alsi)

alsi.milestone("Registering core server to the machine list.")
from assemblyline.al.install.stages import install_70_register_core
install_70_register_core.install(alsi)

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
