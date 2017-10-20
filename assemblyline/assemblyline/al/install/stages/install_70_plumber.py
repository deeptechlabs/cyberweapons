#!/usr/bin/env python

import os


def install(alsi=None):
    if not alsi:
        from assemblyline.al.install import SiteInstaller
        alsi = SiteInstaller()

    alsi.sudo_install_file('assemblyline/al/install/etc/init/plumber.conf', '/etc/init/plumber.conf')

    if not os.path.exists('/etc/init.d/plumber'):
        alsi.runcmd('sudo ln -s /lib/init/upstart-job /etc/init.d/plumber')

if __name__ == '__main__':
    install()
