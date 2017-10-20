#!/usr/bin/env python
"""
Alerter

Alerter is responsible for monitoring the alert queue and creating alerts.
"""
import logging
import signal

from assemblyline.common import net
from assemblyline.common.isotime import now
from assemblyline.al.common import forge
from assemblyline.al.common import log

config = forge.get_config()
log.init_logging("alerter")

from assemblyline.al.common import counter
from assemblyline.al.common import queue

persistent_settings = {
    'db': config.core.redis.persistent.db,
    'host': config.core.redis.persistent.host,
    'port': config.core.redis.persistent.port,
}

alertq_name = 'm-alert'
commandq_name = 'a-command'
create_alert = forge.get_create_alert()
datastore = forge.get_datastore()
exit_msgs = ['server closed the connection unexpectedly']
interval = 3 * 60 * 60
logger = logging.getLogger('assemblyline.alerter')
max_consecutive_errors = 100
max_retries = 10
running = True

alertq = queue.NamedQueue(alertq_name, **persistent_settings)
commandq = queue.NamedQueue(commandq_name, **persistent_settings)

# Publish counters to the metrics sink.
counts = counter.AutoExportingCounters(
    name='alerter',
    host=net.get_hostip(),
    export_interval_secs=5,
    channel=forge.get_metrics_sink(),
    auto_log=True,
    auto_flush=True)
counts.start()


# noinspection PyUnusedLocal
def interrupt(unused1, unused2):  # pylint:disable=W0613
    global running  # pylint:disable=W0603
    logger.info("Caught signal. Coming down...")
    running = False

signal.signal(signal.SIGINT, interrupt)
signal.signal(signal.SIGTERM, interrupt)


def process_alerts():
    global running  # pylint: disable=W0603

    consecutive_errors = 0

    end_t = now(interval)
    while running:
        if now() > end_t:
            logger.info("Finished interval (%ds). Restarting...", interval)
            running = False
            break

        event = queue.select(alertq, commandq, timeout=1)
        if not event:
            continue

        q_name = event[0]
        message = event[1]
        if q_name == alertq_name:
            counts.increment('alert.received')
            try:
                create_alert(counts, datastore, logger, message)
                consecutive_errors = 0
            except Exception as ex:  # pylint: disable=W0703
                consecutive_errors += 1
                retries = message['retries'] = message.get('retries', 0) + 1
                if retries > max_retries:
                    logger.exception('Max retries exceeded for: %s',
                                     str(message))
                else:
                    alertq.push(message)
                    if 'Submission not finalized' not in str(ex):
                        logger.exception('Unhandled exception processing: %s',
                                         str(message))

                for x in exit_msgs:
                    if x in str(ex):
                        consecutive_errors = max_consecutive_errors + 1
                        break

            if consecutive_errors > max_consecutive_errors:
                break


logger.info('Starting...')
# noinspection PyBroadException
try:
    process_alerts()
except:  # pylint:disable=W0702
    logger.exception('Unhandled exception while processing alerts:')

logger.info('Stopping...')
counts.stop()
