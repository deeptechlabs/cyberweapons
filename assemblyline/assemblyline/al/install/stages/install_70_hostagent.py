#!/usr/bin/env python

import os
import sys


def _install_kvm_libvirt(alsi):
    alsi.sudo_apt_install(['cpu-checker'])
    rc, _, _ = alsi.runcmd('kvm-ok', raise_on_error=False)
    if not rc == 0:
        alsi.fatal("You are attempting to install hostagent with virtual machine support however "
                   "your BIOS does not have VX extensions enabled. Enable VT-x in bios or run again with novirt option")
        exit(1)

    alsi.sudo_apt_install(['kvm', 'libvirt-bin', 'virt-manager', 'pkg-config', 'libvirt-dev', 'libxml2-dev',
                          'libxslt1-dev', 'python-spice-client-gtk', 'libvirt-bin', 'python-lxml', 'python-libvirt'])

    # Remove apparmor which can be a nighmare with libvirt. I believe the
    # problems have been fixed in latest ubuntu package releases but leaving
    # for now.
    alsi.remove_apparmor()
    alsi.sudo_sed_inline('/etc/libvirt/qemu.conf', [
        's/#security_driver = "selinux"/security_driver = "none"/',
    ])

    sys_user = alsi.config['system']['user']
    alsi.runcmd("sudo usermod -G libvirtd -a {user}".format(user=sys_user))

    script = os.path.join(alsi.alroot, 'pkg', 'assemblyline', 'al', 'install', 'helpers', 'update_libvirt_dns_ip.py')
    alsi.runcmd('sudo su -c "{script} {datastore_ip}" {user}'.format(script=script,
                                                                     datastore_ip=alsi.get_ipaddress(),
                                                                     user=sys_user))

    alsi.runcmd('sudo service libvirt-bin restart')


def install(alsi=None, install_kvm=True, register_host=True):
    if not alsi:
        from assemblyline.al.install import SiteInstaller
        alsi = SiteInstaller()

    if not alsi.config['workers']['install_kvm'] or (len(sys.argv) == 2 and sys.argv[1] == 'novirt'):
        install_kvm = False

    if install_kvm:
        _install_kvm_libvirt(alsi)

    alsi.pip_install_all(['apscheduler>=2.1.0,<3.0'])

    alsi.sudo_install_file('assemblyline/al/install/etc/init/hostagent.conf', '/etc/init/hostagent.conf')

    if not os.path.exists('/etc/init.d/hostagent'):
        alsi.runcmd('sudo ln -s /lib/init/upstart-job /etc/init.d/hostagent')

    if register_host:
        # register ourselves
        register_this_host()


def register_this_host():
    from assemblyline.al.core.agents import HostAgent
    agent = HostAgent()
    agent.register_host()


if __name__ == '__main__':
    install()
