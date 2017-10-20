#!/usr/bin/env python

import os


def install(alsi):
    bd_run = "BitDefender-Antivirus-Scanner-7.6-4.linux-gcc4x.amd64.deb.run"
    remote_path = 'bitdefender/' + bd_run
    local_path = '/tmp/' + bd_run
    alsi.fetch_package(remote_path, local_path)

    sh_installer = os.path.join(
      alsi.alroot, 'pkg/al_services/alsvc_bitdefender/install_bitdefender_pkg.sh')

    alsi.runcmd(" ".join(['sudo', sh_installer, local_path]), piped_stdio=False)

    alsi.sudo_sed_inline("/opt/BitDefender-scanner/etc/bdscan.conf",
                         ["s/^LicenseAccepted\s=\s.*/LicenseAccepted = True/g"])

    try:
        licence_key = alsi.config['services']['master_list']['BitDefender']['config']['LICENCE_KEY']
    except KeyError:
        licence_key = None

    if licence_key:
        alsi.sudo_sed_inline("/opt/BitDefender-scanner/etc/bdscan.conf",
                             ["s/^Key\s=\s.*/Key = {lic}/g".format(lic=licence_key)])

    bd_path = os.path.join(alsi.alroot, 'pkg', 'al_services', 'alsvc_bitdefender')
    online_updater_path = os.path.join(bd_path, 'online_updater.sh')
    offline_updater_path = os.path.join(bd_path, 'offline_updater.sh')

    alsi.append_line_if_doesnt_exist("/etc/sudoers", "al ALL=NOPASSWD: %s" % online_updater_path)
    alsi.append_line_if_doesnt_exist("/etc/sudoers", "al ALL=NOPASSWD: %s" % offline_updater_path)

    remote_dat_name = 'cumulative.zip'
    alsi.fetch_package(os.path.join('av_updates/bitdefender', remote_dat_name),
                       os.path.join('/tmp/bdupd_dir/', remote_dat_name))

    alsi.runcmd('sudo %s' % offline_updater_path)


if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
