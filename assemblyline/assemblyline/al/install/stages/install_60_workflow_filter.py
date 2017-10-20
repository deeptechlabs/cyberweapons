#!/usr/bin/env python
import os


def install(alsi):
    alsi.sudo_install_file('assemblyline/al/install/etc/init/workflow_filter.conf',
                          '/etc/init/workflow_filter.conf')

    if not os.path.exists('/etc/init.d/workflow_filter'):
        alsi.runcmd('sudo ln -s /lib/init/upstart-job /etc/init.d/workflow_filter')

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    installer = SiteInstaller()
    install(installer)
