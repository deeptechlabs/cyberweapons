#!/usr/bin/env python

import os

def install(alsi):
    alsi.sudo_apt_install('libmysqlclient-dev')
    alsi.pip_install('MySQL-python==1.2.5')

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    alsi = SiteInstaller()
    install(alsi)


