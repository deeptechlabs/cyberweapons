#!/usr/bin/env python

def install(alsi):
    # No deps.
    alsi.milestone('FSecure Complete.')

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
