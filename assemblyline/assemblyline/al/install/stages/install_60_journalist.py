#!/usr/bin/env python
import os

def install(alsi):

    alsi.sudo_install_file(
        'assemblyline/al/install/etc/init/journalist.conf',
        '/etc/init/journalist.conf'
    )

    if not os.path.exists('/etc/init.d/journalist'):
        alsi.runcmd('sudo ln -s /lib/init/upstart-job /etc/init.d/journalist')

    alsi.milestone("journalist install complete")


if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    installer = SiteInstaller()
    install(installer)
