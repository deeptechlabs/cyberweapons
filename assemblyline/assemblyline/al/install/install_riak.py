#!/usr/bin/env python

import os
import sys

from assemblyline.al.install import SiteInstaller
from assemblyline.al.install.stages import install_20_bootstrap
from assemblyline.al.install.stages import install_30_core_deps

STATUS_FILE = os.path.expanduser('/opt/al/.install_status')
STATUS_INITIAL_COMPLETE = 'INITIAL_COMPLETE'


def check_resource_requirements(seed):
    import psutil
    solr_heap_min_gb = seed['datastore']['riak']['solr']['heap_min_gb']
    solr_heap_max_gb = seed['datastore']['riak']['solr']['heap_max_gb']
    if solr_heap_min_gb > solr_heap_max_gb:
        return False, "solr_heap_min_gb > solr_heap_max_gb (%s > %s)" % (solr_heap_min_gb, solr_heap_max_gb)

    phymem_gb = psutil.phymem_usage().total * 1.0 / (1024 * 1024 * 1024)
    if solr_heap_max_gb > (phymem_gb / 2.0):
        return False, "solr_heap_max_gb > physical_mem/2 (heap:%s phy:%s)" % (solr_heap_max_gb, phymem_gb)

    return True, ''


def is_postboot():
    if 'postboot' in sys.argv:
        return True
    if os.path.exists(STATUS_FILE):
        with open(STATUS_FILE, 'r') as statusf:
            status_word = statusf.read()
            if status_word.strip() == STATUS_INITIAL_COMPLETE:
                return True
    return False


def write_statusfile(status_word):
    with open(STATUS_FILE, 'w') as sf:
        sf.write(status_word)


def postboot_install(alsi):
    our_ip = alsi.get_ipaddress()
    our_hostname = alsi.get_hostname()
    if our_ip not in alsi.config['datastore']['riak']['nodes'] and \
            our_hostname not in alsi.config['datastore']['riak']['nodes']:
        raise Exception("Our IP or HOSTNAME: %s was not found as a riak node in seed." % our_ip)

    requirements_met, msg = check_resource_requirements(alsi.config)
    if not requirements_met:
        raise Exception("RIAK resource requirements are not met: %s" % msg)

    alsi.milestone("Installing Riak (POSTBOOT)")
    from assemblyline.al.install.stages import install_50_riak_postboot
    install_50_riak_postboot.install(alsi)

    alsi.milestone("Installing System Metrics Collector")
    from assemblyline.al.install.stages import install_60_system_metrics
    install_60_system_metrics.install(alsi)

    alsi.milestone("Installing Supplementary Packages")
    from assemblyline.al.install.stages import install_90_supplementary
    install_90_supplementary.install(alsi)

    alsi.milestone("Cleaning up")
    from assemblyline.al.install.stages import install_90_cleanup
    install_90_cleanup.install(alsi)
    alsi.milestone("Completed.")


def initial_install(alsi):
    alsi.milestone("Installing pip configuration files")
    alsi.install_persistent_pip_conf()

    alsi.milestone("Creating AL user")
    from assemblyline.al.install.stages import install_00_init
    install_00_init.install(alsi)

    alsi.milestone("Installing Bootstrap")
    install_20_bootstrap.install(alsi)

    alsi.milestone("Installing Common Dependencies")
    install_30_core_deps.install(alsi)

    alsi.milestone("Installing Harddrive monitor")
    from assemblyline.al.install.stages import install_40_harddrive_monitor
    install_40_harddrive_monitor.install(alsi)

    our_ip = alsi.get_ipaddress()
    our_hostname = alsi.get_hostname()
    if our_ip not in alsi.config['datastore']['riak']['nodes'] and \
            our_hostname not in alsi.config['datastore']['riak']['nodes']:
        raise Exception("Our IP or HOSTNAME: %s was not found as a riak node in seed." % our_ip)

    requirements_met, msg = check_resource_requirements(alsi.config)
    if not requirements_met:
        raise Exception("RIAK resource requirements are not met: %s" % msg)

    alsi.milestone("Installing Riak (PreBoot)")
    from assemblyline.al.install.stages import install_40_riak
    install_40_riak.install(alsi)

    # Write the status word out to disk so we'll we have completed the initial install.
    write_statusfile(STATUS_INITIAL_COMPLETE)
    alsi.milestone("You must reboot before proceeding!!!!!!!")


if __name__ == '__main__':
    try:
        os.environ['AL_SEED_STATIC'] = os.environ['AL_SEED']
    except IndexError:
        raise Exception("AL_SEED environment variable is not set!")

    installer = SiteInstaller()

    if is_postboot():
        postboot_install(installer)
        exit(0)
    else:
        initial_install(installer)
        exit(0)
