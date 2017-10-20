#!/usr/bin/env python


# noinspection PyUnusedLocal
def install(alsi):
    pass

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    cur_alsi = SiteInstaller()
    install(cur_alsi)
