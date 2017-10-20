#!/usr/bin/env python


def install(alsi):

    alsi.install_yara_3()

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())

