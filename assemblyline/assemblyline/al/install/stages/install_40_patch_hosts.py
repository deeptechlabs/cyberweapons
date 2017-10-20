#!/usr/bin/env python


def install(alsi=None):
    alsi.append_line_if_doesnt_exist("/etc/hosts", "127.0.0.1    datastore.al")
    alsi.info("Patched /etc/hosts to add datastore.al.")

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    installer = SiteInstaller()
    install(installer)
