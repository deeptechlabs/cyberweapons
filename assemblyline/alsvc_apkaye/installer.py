#!/usr/bin/env python

import os


def install(alsi):
    alsi.sudo_apt_install(["libc6-i386", "lib32z1", "lib32gcc1", "unzip"])

    apkaye_support_dir = os.path.join(alsi.alroot, "support", "apkaye")
    alsi.runcmd("sudo mkdir -p %s" % apkaye_support_dir, raise_on_error=False)

    apktool_pkg = "apktool_2.0.3.jar"
    remote_path = 'apkaye/' + apktool_pkg
    local_path = os.path.join("/tmp", "apkaye", apktool_pkg)
    alsi.fetch_package(remote_path, local_path)
    alsi.runcmd("sudo cp %s %s" % (local_path, apkaye_support_dir))

    d2j_pkg = "dex-tools-2.0.zip"
    remote_path = 'apkaye/' + d2j_pkg
    local_path = os.path.join("/tmp", "apkaye", d2j_pkg)
    alsi.fetch_package(remote_path, local_path)
    alsi.runcmd("cd %s && unzip -o dex-tools-2.0.zip" % os.path.join("/tmp", "apkaye"))
    alsi.runcmd("sudo cp -R /tmp/apkaye/dex2jar-2.0 %s" % apkaye_support_dir)
    alsi.runcmd("sudo chmod +x %s/*.sh" % os.path.join(apkaye_support_dir, 'dex2jar-2.0'))

    aapt_pkg = "aapt.tgz"
    remote_path = 'apkaye/' + aapt_pkg
    local_path = os.path.join("/tmp", "apkaye", aapt_pkg)
    alsi.fetch_package(remote_path, local_path)
    alsi.runcmd("cd %s && tar zxf aapt.tgz" % os.path.join("/tmp", "apkaye"))
    alsi.runcmd("sudo cp -R /tmp/apkaye/aapt %s" % apkaye_support_dir)

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    installer = SiteInstaller()
    install(installer)
