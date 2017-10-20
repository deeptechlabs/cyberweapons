#!/usr/bin/env python

import logging
import json

from pprint import pformat

from assemblyline.al.common.queue import CommsQueue

logging.getLogger()

def main():

    q = CommsQueue('status')
    try:
        while True:
            for msg in q.listen():
                print msg
                if not msg or msg.get('type', None) != 'message':
                    continue
                data = json.loads(msg['data'])
                print pformat(data)
    except KeyboardInterrupt:
        print 'Exiting'
    q.close()

if __name__ == '__main__':
    main()

