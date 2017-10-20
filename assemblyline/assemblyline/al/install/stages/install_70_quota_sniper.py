#!/usr/bin/env python

import os


def install(alsi=None):
    if not alsi:
        from assemblyline.al.install import SiteInstaller
        alsi = SiteInstaller()

    alsi.sudo_install_file('assemblyline/al/install/etc/init/quota_sniper.conf',
                          '/etc/init/quota_sniper.conf')

    if not os.path.exists('/etc/init.d/quota_sniper'):
        alsi.runcmd('sudo ln -s /lib/init/upstart-job /etc/init.d/quota_sniper')

if __name__ == '__main__':
    install()
