#!/usr/bin/env python

def install(alsi):

    default_rules = "/opt/al/pkg/al_services/alsvc_tagcheck/sample_sigset.csv"
    alsi.runcmd("python /opt/al/pkg/al_services/alsvc_tagcheck/tsig.py {}" .format(default_rules))

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
