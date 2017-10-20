#!/usr/bin/env python
import os


def install(alsi):
    alsi.sudo_apt_install(['postgresql-client', 'libpq-dev'])
    alsi.pip_install('psycopg2')

    alsi.sudo_install_file('assemblyline/al/install/etc/init/alerter.conf', '/etc/init/alerter.conf')
    alsi.sudo_install_file('assemblyline/al/install/etc/init/alerter_instance.conf', '/etc/init/alerter_instance.conf')

    if not os.path.exists('/etc/init.d/alerter'):
        alsi.runcmd('sudo ln -s /lib/init/upstart-job /etc/init.d/alerter')

    alsi.milestone("alerter install complete")


if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    installer = SiteInstaller()
    install(installer)
