#!/usr/bin/env python

import os
import subprocess


def install(alsi):
    from al_services.alsvc_mcafee.mcafee_lib import McAfeeScanner

    mcafee_tgz = 'vscl-l64-604-e.tar.gz'
    remote_path = 'mcafee/' + mcafee_tgz
    install_dir = os.path.join(alsi.alroot, 'support/mcafee')
    if not os.path.exists(install_dir):
        os.makedirs(install_dir)
    local_path = os.path.join('/tmp', mcafee_tgz)
    alsi.fetch_package(remote_path, local_path)
    alsi.runcmd(' '.join(['tar -xvzf', local_path, '-C', install_dir]))

    avupdate_dir = os.path.join(alsi.alroot, "var", "avdat")
    mcafee_update_dir = os.path.join(avupdate_dir, "mcafee")
    if not os.path.exists(mcafee_update_dir):
        os.makedirs(mcafee_update_dir)

    remote_av_file = 'avvdat-latest.zip'
    remote_av_path = 'av_updates/mcafee/' + remote_av_file
    local_av_path = os.path.join('/tmp', remote_av_file)
    alsi.fetch_package(remote_av_path, local_av_path)

    subprocess.call(['unzip', '-o', local_av_path, '-d', mcafee_update_dir])
    scanner = McAfeeScanner(os.path.join(install_dir, 'uvscan'), mcafee_update_dir)
    scanner.decompress_avdefinitions()

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
