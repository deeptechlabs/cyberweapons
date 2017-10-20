#!/usr/bin/env python
from __future__ import absolute_import

import sys

from assemblyline.al.common import log
from assemblyline.al.core.agents import HostAgent


def usage():
    print 'Usage: %s [--sysprep|--register|--updateandexit]]' % sys.argv[0]


def main():
    log.init_logging('hostagent')
    agent = HostAgent()
    if len(sys.argv) > 1:
        if len(sys.argv) == 2:
            if (sys.argv[1] == '--sysprep') or sys.argv[1] == '--updateandexit':
                result = agent.sysprep()
                print 'SysPrep: %s' % str(result)
                exit(0)
            elif sys.argv[1] == '--register':
                result = agent.register_host()
                print "Registration Result: %s" % str(result)
                exit(0)
            else:
                usage()
                exit(1)
        else:
            usage()
            exit(1)

    agent.serve_forever()


if __name__ == '__main__':
    main()
