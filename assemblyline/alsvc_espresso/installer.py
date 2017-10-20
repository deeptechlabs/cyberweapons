#!/usr/bin/env python
import os


def install(alsi):
    remote_cfr = 'cfr/cfr.jar'
    local_cfr = os.path.join(alsi.alroot, 'support/cfr/cfr.jar')
    alsi.fetch_package(remote_cfr, local_cfr)

    alsi.install_oracle_java8()
    alsi.milestone("Espresso install complete.")

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
