#!/usr/bin/env python

import os


def install(alsi):

    alsi.milestone('Starting Swiffer install..')

    alsi.pip_install("Pillow==2.3.0")

    support_dir = os.path.join(alsi.alroot, 'support/swiffer')
    local_rabcdasm_tgz = os.path.join(alsi.install_temp, 'rabcdasm.tar.gz')
    alsi.fetch_package('swiffer/rabcdasm.tar.gz', local_rabcdasm_tgz)
    if not os.path.exists(support_dir):
        os.makedirs(support_dir)
    alsi.runcmd('tar xvzf {tarfile} -C {support_dir}'.format(tarfile=local_rabcdasm_tgz, support_dir=support_dir))

    pyswf = "pyswf-master-custom-patched.tgz"
    remote_path = 'python/pip/' + pyswf
    local_path = os.path.join('/tmp/', pyswf)
    alsi.fetch_package(remote_path, local_path)
    alsi.runcmd('sudo -H pip install ' + local_path, piped_stdio=False)

    alsi.milestone('Completed Swiffer install.')


if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
