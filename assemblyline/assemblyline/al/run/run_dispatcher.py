#!/usr/bin/env python

import getopt
import sys

from assemblyline.al.common import forge
from assemblyline.al.common import log
from assemblyline.al.core.dispatch import Dispatcher
from assemblyline.al.core.servicing import ServiceProxyManager


def main(shard):
    log.init_logging('dispatcher')

    ds = forge.get_datastore()

    service_proxies = ServiceProxyManager(ds.list_service_keys())
    dispatcher = Dispatcher(service_proxies, shard=shard, debug=False)
    dispatcher.start()

if __name__ == '__main__':
    s = '0'

    opts, args = getopt.getopt(sys.argv[1:], 's:', ['shard='])
    for opt, arg in opts:
        if opt in ('-s', '--shard'):
            s = arg

    main(s)
