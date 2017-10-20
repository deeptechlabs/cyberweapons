#!/usr/bin/env python

import json
import sys

from assemblyline.al.common import queue

q = queue.CommsQueue('SsMetrics')

name_filter = None
if len(sys.argv) > 1:
    name_filter = sys.argv[1]

try:
    while True:
        for msg in q.listen():
            if not msg or msg.get('type', None) != 'message':
                continue
            data = json.loads(msg['data'])
            if name_filter and data.get('name', '') != name_filter:
                continue
            print data
except KeyboardInterrupt:
    print 'Exiting'
q.close()


