#!/usr/bin/env python


def install(alsi):

    alsi.pip_install_all([
        'bencode',
        'humanfriendly',
        'hurry.filesize',
    ])

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
