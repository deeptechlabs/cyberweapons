#!/usr/bin/env python

import os


def install(alsi=None):
    if not alsi:
        from assemblyline.al.install import SiteInstaller
        alsi = SiteInstaller()

    alsi.sudo_install_file('assemblyline/al/install/etc/init/controller.conf',
                          '/etc/init/controller.conf')

    if not os.path.exists('/etc/init.d/controller'):
        alsi.runcmd('sudo ln -s /lib/init/upstart-job /etc/init.d/controller')

    tmpl_path = os.path.join(alsi.alroot, 'pkg', 'assemblyline/al/install/etc/sudoers.d/controller.tmpl')
    tmpl = open(tmpl_path).read()
    alsi.append_line_if_doesnt_exist("/etc/sudoers", tmpl.replace('__USER__', alsi.config['system']['user']))

if __name__ == '__main__':
    install()
