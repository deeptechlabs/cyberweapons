#!/usr/bin/env python

import os


def install(alsi=None):

    if not alsi:
        from assemblyline.al.install import SiteInstaller
        alsi = SiteInstaller()

    # Upstart Install.
    alsi.sudo_install_file('assemblyline/al/install/etc/init/dispatcher_instance.conf',
                          '/etc/init/dispatcher_instance.conf')

    alsi.sudo_install_file('assemblyline/al/install/etc/init/dispatchers.conf', '/etc/init/dispatchers.conf')

    if not os.path.exists('/etc/init.d/dispatchers'):
        alsi.runcmd('sudo ln -s /lib/init/upstart-job /etc/init.d/dispatchers')


if __name__ == '__main__':
    install()
