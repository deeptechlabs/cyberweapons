#!/usr/bin/env python


def install(alsi):
    alsi.sudo_apt_install([
        'p7zip-full', 
        'p7zip-rar',
        'libarchive-dev',
        'unace-nonfree'
    ])

    alsi.pip_install_all([
        'python-libarchive==3.1.2-1',
        'tnefparse',
        'olefile'
    ])

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
