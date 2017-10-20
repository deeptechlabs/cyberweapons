#!/usr/bin/env python

import os


def install(alsi=None):
    if not alsi:
        from assemblyline.al.install import SiteInstaller
        alsi = SiteInstaller()

    alsi.pip_install_all([
        "elasticsearch==2.3.0"
    ])

    alsi.sudo_install_file('assemblyline/al/install/etc/init/metricsd.conf', '/etc/init/metricsd.conf')

    if not os.path.exists('/etc/init.d/metricsd'):
        alsi.runcmd('sudo ln -s /lib/init/upstart-job /etc/init.d/metricsd')

if __name__ == '__main__':
    install()
