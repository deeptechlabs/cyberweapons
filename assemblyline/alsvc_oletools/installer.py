#!/usr/bin/env python

import os


def install(alsi):
    alsi.milestone('Starting Oletools install..')
    ole_tgz = 'oletools-0.45.tar.gz'
    local_path = os.path.join('/tmp', ole_tgz)
    remote_path = 'oletools/' + ole_tgz
    alsi.fetch_package(remote_path, local_path)
    alsi.runcmd('sudo -H pip install ' + local_path, piped_stdio=False)
    alsi.milestone('Completed Oletools install.')

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
