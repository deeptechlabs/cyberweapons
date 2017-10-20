#!/usr/bin/env python

import os
import zipfile

def install(alsi):
    support_dir = os.path.join(alsi.alroot, 'support')
    if not os.path.exists(support_dir):
        os.makedirs(support_dir)

    alsi.install_pefile()
    local_sigcheck_zip = os.path.join(support_dir, 'sigcheck.zip')
    alsi.fetch_package("sigcheck/sigcheck.zip", local_sigcheck_zip)
    with zipfile.ZipFile(local_sigcheck_zip) as zf:
        zf.extractall(path=support_dir)

    # TODO: Update certificate catalogue ??
    
if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
