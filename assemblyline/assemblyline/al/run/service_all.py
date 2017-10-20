#!/usr/bin/env python

import sys
from assemblyline.al.install import SiteInstaller
from assemblyline.al.install.stages import cmd_service_all

VALID_COMMANDS = ['start', 'stop', 'restart', 'status']


def exec_on_all(cmd):
    alsi = SiteInstaller()
    cmd_service_all(alsi, cmd, al_svc_only=True)

if __name__ == '__main__':
    if len(sys.argv) == 2:
        command = sys.argv[1]
        if command not in VALID_COMMANDS:
            exit("You can only execute %s commands." % ", ".join(VALID_COMMANDS))
        exec_on_all(command)
    else:
        print "Usage: service_all COMMAND"
        exit(1)
