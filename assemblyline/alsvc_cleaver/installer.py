#!/usr/bin/env python


def install(alsi):
    alsi.pip_install_all([
        'hachoir-core==1.3.3',
        'hachoir-parser==1.3.4',
        'hachoir-metadata==1.3.3'
        ])

    alsi.info("Cleaver dependencies installed.")

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
