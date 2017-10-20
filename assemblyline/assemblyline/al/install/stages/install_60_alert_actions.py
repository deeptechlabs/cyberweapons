#!/usr/bin/env python
import os


def install(alsi):
    alsi.sudo_install_file('assemblyline/al/install/etc/init/alert_actions.conf',
                          '/etc/init/alert_actions.conf')

    if not os.path.exists('/etc/init.d/alert_actions'):
        alsi.runcmd('sudo ln -s /lib/init/upstart-job /etc/init.d/alert_actions')

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    installer = SiteInstaller()
    install(installer)
