#!/usr/bin/env python

def install(alsi):
    alsi.milestone('MetaPeek Complete.')

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
