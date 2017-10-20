#!/usr/bin/env python
import os


def install(alsi):

    alsi.sudo_install_file('assemblyline/al/install/etc/init/expiry.conf', '/etc/init/expiry.conf')

    alsi.sudo_install_file('assemblyline/al/install/etc/init/expiry_workers.conf', '/etc/init/expiry_workers.conf')

    alsi.sudo_install_file('assemblyline/al/install/etc/init/expiry_worker_instance.conf',
                          '/etc/init/expiry_worker_instance.conf')

    if not os.path.exists('/etc/init.d/expiry'):
        alsi.runcmd('sudo ln -s /lib/init/upstart-job /etc/init.d/expiry')

    if not os.path.exists('/etc/init.d/expiry_workers'):
        alsi.runcmd('sudo ln -s /lib/init/upstart-job /etc/init.d/expiry_workers')

    alsi.milestone("expiry install complete")


if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    installer = SiteInstaller()
    install(installer)
