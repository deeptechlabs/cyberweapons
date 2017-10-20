#!/usr/bin/env python


def install(alsi):
    alsi.sudo_apt_install([
        'python-pyrex', 
        'swig',
        'libemu-dev',
        'libnspr4-dev',
        'pkg-config',
    ])

    alsi.pip_install('nose')
    alsi.pip_install('python-spidermonkey')

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
