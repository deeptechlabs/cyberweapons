#!/usr/bin/env python


def install(alsi):
    alsi.sudo_apt_install([
        'upx-ucl',
    ])

    alsi.milestone("Unpacker install complete.")

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
