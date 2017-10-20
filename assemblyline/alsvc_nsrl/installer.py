#!/usr/bin/env python

import os

def install(alsi):
    alsi.sudo_apt_install('libpq-dev')
    alsi.pip_install('psycopg2')

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    alsi = SiteInstaller()
    install(alsi)


