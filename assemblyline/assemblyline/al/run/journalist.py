#!/usr/bin/env python

import logging
import os
import signal

from assemblyline.al.common import forge
from assemblyline.al.common import log
from assemblyline.al.common import queue

config = forge.get_config()

log.init_logging('journalist')

directory = config.core.expiry.journal.directory
emptyresult_queue = queue.NamedQueue(
    "ds-emptyresult",
    db=config.core.redis.persistent.db,
    host=config.core.redis.persistent.host,
    port=config.core.redis.persistent.port,
)   
logger = logging.getLogger('assemblyline.journalist')
max_open_files = 8
path_and_filehandle = []
path_to_filehandle = {}
previous = []
running = True


# noinspection PyUnusedLocal
def interrupt(unused1, unused2):  # pylint:disable=W0613
    global running  # pylint:disable=W0603
    logger.info("Caught signal. Coming down...")
    running = False

signal.signal(signal.SIGINT, interrupt)
signal.signal(signal.SIGTERM, interrupt)


def get_filehandle(path):
    fh = path_to_filehandle.get(path, None)
    if fh:
        return fh

    # Make sure directory exists.
    dirname = os.path.dirname(path)
    if not os.path.exists(dirname):
        os.makedirs(dirname)

    path_to_filehandle[path] = fh = open(path, 'ab')

    path_and_filehandle.append((fh, path))
    if len(path_and_filehandle) > max_open_files:
        pfh, ppath = path_and_filehandle.pop(0)

        if path_to_filehandle.get(ppath, None) == pfh:
            path_to_filehandle.pop(ppath)

        logger.info("Closing file %s", ppath)
        pfh.close()

    return fh


def main():
    while running:
        # noinspection PyBroadException
        try:
            msg = emptyresult_queue.pop()
            if not msg:
                continue

            riak_key, created = msg.split("\t")

            path = os.path.join(directory, created[:10]) + '.emptyresult'
            fh = get_filehandle(path)

            fh.write(riak_key + "\n")
            fh.flush()

        except:  # pylint: disable=W0702
            logger.exception('Unhandled exception:')


if __name__ == '__main__':
    main()

