#!/usr/bin/env python

from assemblyline.al.install import SiteInstaller


def install(alsi=None):
    alsi = alsi or SiteInstaller()

    alsi.milestone("Installing pureftp and default AL FTP config.")
    alsi.sudo_apt_install(['pure-ftpd'])

    user = alsi.config['filestore']['ftp_user']
    sys_user = alsi.config['system']['user']
    password = alsi.config['filestore']['ftp_password']
    root = alsi.config['filestore']['ftp_root']
    ip_restriction = alsi.config['filestore'].get('ftp_ip_restriction', None)

    if ip_restriction:
        alsi.runcmd("( echo '{password}' ; echo '{password}') | "
                   "sudo pure-pw useradd {user} -r {ip_restriction} "
                   "-u {sys_user} -g adm -d {root}".format(user=user,
                                                           sys_user=sys_user,
                                                           password=password,
                                                           ip_restriction=ip_restriction,
                                                           root=root),
                   raise_on_error=False)
    else:
        alsi.runcmd("( echo '{password}' ; echo '{password}') | "
                   "sudo pure-pw useradd {user} -u {sys_user} -g adm -d {root}".format(user=user,
                                                                                       sys_user=sys_user,
                                                                                       password=password,
                                                                                       root=root),
                   raise_on_error=False)

    alsi.runcmd("sudo pure-pw mkdb", raise_on_error=False)
    alsi.runcmd("sudo ln -s /etc/pure-ftpd/conf/PureDB /etc/pure-ftpd/auth/50PureDB", raise_on_error=False)

    alsi.sudo_install_file('assemblyline/al/install/etc/pure-ftpd/conf/MaxClientsNumber',
                          '/etc/pure-ftpd/conf/MaxClientsNumber')
    alsi.runcmd('sudo service pure-ftpd restart')

if __name__ == '__main__':
    install()
