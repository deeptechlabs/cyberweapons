#!/usr/bin/env python

import os
import json


def install(alsi):
    support_dir = os.path.join(alsi.alroot, "support")
    alsi.runcmd("mkdir -p %s" % support_dir, raise_on_error=False)
    binja_license_dir = os.path.join(alsi.alroot, ".binaryninja")
    alsi.runcmd("mkdir -p %s" % binja_license_dir, raise_on_error=False)

    binja_pkg = "binja/binja.tar.gz"
    binja_license = os.path.join(alsi.alroot, ".binaryninja", "license.dat")

    alsi.fetch_package(binja_pkg, os.path.join("/tmp", "binja", binja_pkg))
    alsi.runcmd("cd %s && tar -xzf %s" % (os.path.join("/tmp", "binja"), binja_pkg))
    alsi.runcmd("cp -R /tmp/binja/binaryninja %s" % support_dir)
    # Talk to Jordan about license usage; get quote for machine processing
    b_license = alsi.config['services']['master_list']['Binja']['config']['license']

    if b_license:
        with open(binja_license, "wb") as fp:
            json.dump(b_license, fp, indent=4, separators=(',', ': '))

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
