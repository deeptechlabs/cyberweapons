#!/usr/bin/env python

import json
import logging
import signal
import sys

from assemblyline.al.common import forge
from assemblyline.al.common import log
from assemblyline.al.common import queue

config = forge.get_config()
log.init_logging('ingest-bridge')

PRODUCTION_DB = config.core.ingest_bridge.db
PRODUCTION_HOST = config.core.ingest_bridge.host
PRODUCTION_PORT = config.core.ingest_bridge.port

SEND_EVERY = int(config.core.ingest_bridge.send_every)

logger = logging.getLogger('assemblyline.ingest_bridge')
running = True


# noinspection PyUnusedLocal
def interrupt(unused1, unused2):  # pylint:disable=W0613
    global running  # pylint:disable=W0603
    logger.info("Caught signal. Coming down...")
    running = False

signal.signal(signal.SIGINT, interrupt)
signal.signal(signal.SIGTERM, interrupt)


def main():
    trafficq = queue.CommsQueue('traffic',
                                host=PRODUCTION_HOST,
                                port=PRODUCTION_PORT,
                                db=PRODUCTION_DB)

    ingestq = queue.MultiQueue(host=config.core.redis.persistent.host,
                               port=config.core.redis.persistent.port,
                               db=config.core.redis.persistent.db)

    count = 0
    while running:
        # noinspection PyBroadException
        try:
            msg = next(trafficq.listen())
            if not msg or msg.get('type', 'unknown') != 'message':
                continue

            data = msg.get('data', None)
            if not data:
                continue 

            data = json.loads(data)
            if count % SEND_EVERY == 0:
                queue_name = forge.determine_ingest_queue(data['sha256'])
                ingestq.push(queue_name, data)

        except:  # pylint: disable=W0702
            logger.exception('Unhandled exception:')

        count += 1

if __name__ == '__main__':
    if config.core.redis.persistent.host == PRODUCTION_HOST:
        logger.error("Queue host is production host. Cowardly refusing to run.")
        sys.exit(1)

    main()
