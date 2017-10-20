#!/usr/bin/env python

import os


def install(alsi):
    alsi.install_yara_3()
    alsi.install_pefile()

    # Add config decoder rules to deployment
    yara_import_script = os.path.join(alsi.alroot, "pkg", "assemblyline", "al", "run", "yara_importer.py")
    rule_file = os.path.join(alsi.alroot, "pkg", "al_services", "alsvc_configdecoder",
                             "rules", "config_decoder_sigs.yar")
    alsi.runcmd("{script} -f -s {rules}".format(script=yara_import_script, rules=rule_file))

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
