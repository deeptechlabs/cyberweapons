#!/usr/bin/env python

import logging
import time

from assemblyline.al.common import forge
from assemblyline.al.common import log
from assemblyline.al.common.task import Task
from assemblyline.al.service.list_queue_sizes import get_service_queue_lengths

log.init_logging('plumber')
logger = logging.getLogger('assemblyline.plumber')

dispatch_queue = forge.get_dispatch_queue()
store = forge.get_datastore()
config = forge.get_config()
service_queue = {}
threshold = {}


def get_queue(n):
    q = service_queue.get(n, None)
    if not q:
        service_queue[n] = q = forge.get_service_queue(n)

    return q

for service in store.list_services():
    # noinspection PyBroadException
    try:
        name = service.get('name')
        params = service.get('config', {})
        value = params.get('PLUMBER_MAX_QUEUE_SIZE', None)
        if value is not None:
            threshold[name] = value
    except:  # pylint:disable=W0702
        logger.exception('Problem getting service config:')

logger.info("Monitoring the following service queues: %s", threshold)

while True:
    queue_lengths = get_service_queue_lengths()

    over = {
        k: v for k, v in queue_lengths.iteritems() if v > (threshold.get(k, 0) or v)
    }

    for name, size in over.iteritems():
        excess = size - threshold.get(name, size)
        if excess <= 0:
            continue

        for msg in get_queue(name).unpush(excess):
            # noinspection PyBroadException
            try:
                t = Task(msg)

                t.watermark(name, '')
                t.nonrecoverable_failure('Service busy.')
                t.cache_key = store.save_error(name, None, None, t)

                dispatch_queue.send_raw(t.as_dispatcher_response())
                logger.info("%s is too busy to process %s.", name, t.srl)
            except:  # pylint:disable=W0702
                logger.exception('Problem sending response:')

    time.sleep(config.system.update_interval)
