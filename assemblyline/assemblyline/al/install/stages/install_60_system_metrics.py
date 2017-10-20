#!/usr/bin/env python

import os


def install(alsi):
    logserver = alsi.config['logging']['logserver'].get('node', None)

    if not logserver:
        alsi.milestone('No logserver enabled. SKipping')
        return

    alsi.pip_install_all([
        "psutil==2.1.1",
        "elasticsearch==2.3.0"
    ])

    alsi.sudo_install_file('assemblyline/al/install/etc/init/system_metrics.conf', '/etc/init/system_metrics.conf')

    if not os.path.exists('/etc/init.d/system_metrics'):
        alsi.runcmd('sudo ln -s /lib/init/upstart-job /etc/init.d/system_metrics')

    alsi.runcmd('sudo service system_metrics start')

    alsi.milestone("System Metrics Collector install complete")


if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    installer = SiteInstaller()
    install(installer)
