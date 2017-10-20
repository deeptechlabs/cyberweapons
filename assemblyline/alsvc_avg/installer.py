#!/usr/bin/env python

import os
import subprocess


def install(alsi):
    alsi.sudo_install_file(
        'assemblyline/al/install/etc/sysctl.d/60-al-largeshm.conf',
        '/etc/sysctl.d/60-al-large-shm.conf')

    alsi.runcmd('sudo service procps start')

    deb = 'avg2013flx-r3115-a6155.i386.deb'
    remote_path = os.path.join('avg/' + deb)
    local_path = os.path.join('/tmp/', deb)
    alsi.sudo_apt_install(['lib32z1',])
    alsi.pip_install('python-dateutil')
    alsi.fetch_package(remote_path, local_path)
    alsi.runcmd('sudo dpkg -i ' + local_path)

    alsi.sudo_sed_inline('/opt/avg/av/cfg/scand.ini', ['s/Severity=INFO/Severity=None/g',])
    alsi.sudo_sed_inline('/opt/avg/av/cfg/tcpd.ini', ['s/Severity=INFO/Severity=None/g',])
    alsi.sudo_sed_inline('/opt/avg/av/cfg/wd.ini', ['s/Severity=INFO/Severity=None/g',])

    alsi.runcmd('sudo avgcfgctl -w Default.setup.features.antispam=false')
    alsi.runcmd('sudo avgcfgctl -w Default.setup.features.oad=false')
    alsi.runcmd('sudo avgcfgctl -w Default.setup.features.scheduler=false')
    alsi.runcmd('sudo avgcfgctl -w Default.setup.features.tcpd=false')

    alsi.append_line_if_doesnt_exist("/etc/sudoers", "al ALL=NOPASSWD: /usr/bin/avgupdate")

    alsi.sudo_install_file(
            'al_services/alsvc_avg/avg-cleaneventdb.cron',
            '/etc/cron.d/avg-cleaneventdb')

    update_dir = "/tmp/avgupd_dir"
    remote_update_file = 'av_updates/avg/avg_update.cart'
    alsi.fetch_package(remote_update_file, os.path.join(update_dir, 'avg_update.cart'))
    subprocess.call("cd {update_dir} && cart -d -f avg_update.cart".format(update_dir=update_dir),
                    shell=True)
    ret = subprocess.call("sudo /usr/bin/avgupdate --source=folder "
                          "--path={update_dir}".format(update_dir=update_dir), shell=True)
    if ret not in [0, 2]:
        alsi.warning("'avgupdate' command failed with status: %s" % ret)

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
