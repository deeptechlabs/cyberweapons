#!/usr/bin/env python

# Run a standalone AL service.
#
# Usage: python ./run_service_live <servicename>

import logging
import sys
import time
from assemblyline.common.importing import class_by_name

from assemblyline.al.common import forge, log
from assemblyline.al.common.queue import CommsQueue
from assemblyline.al.common.message import Message, MT_SVCHEARTBEAT
from assemblyline.al.common.importing import service_by_name
from assemblyline.al.service.service_driver import ServiceDriver

logger = logging.getLogger('assemblyline.run_service')
NUM_WORKERS = 1

config = forge.get_config()


def send_minimal_heartbeat(service_name, num_workers):
    """Send just enough heartbeat that the dispatcher knows we are up."""
    logger.info('Sending heartbeat.')
    heartbeat = {
        'services': { 
            'details': {
                service_name: {'num_workers': num_workers}
            }
        }
    }
    msg = Message(to='*', mtype=MT_SVCHEARTBEAT, sender='runservice_live', body=heartbeat)
    CommsQueue('status').publish(msg.as_dict())


def get_valid_service_list():
    valid_services = [s['name'] for s in forge.get_datastore().list_services()]
    valid_services.sort()
    return 'Valid services:\n\t%s' % '\n\t'.join(valid_services)


def usage():
    print 'Usage: %s <service>' % sys.argv[0]
    print get_valid_service_list()


def main():
    log.init_logging('run_service')

    if len(sys.argv) != 2:
        usage()
        exit(1)

    name = sys.argv[1]

    try:
        svc_class = class_by_name(name) if '.' in name else service_by_name(name)
    except:
        print 'Could not load service "%s".\n%s' % (name, get_valid_service_list())
        raise

    logger.info('Running service in stand-alone mode. CTRL-C to exit.')
    # noinspection PyBroadException
    try:
        cfg = forge.get_datastore().get_service(svc_class.SERVICE_NAME).get("config", {})
    except:  # pylint: disable=W0702
        cfg = {}
    service_driver = ServiceDriver(svc_class, cfg, 86400, NUM_WORKERS)
    service_driver.start()

    try:
        while True:
            send_minimal_heartbeat(svc_class.SERVICE_NAME, NUM_WORKERS)
            time.sleep(config.system.update_interval)
    except KeyboardInterrupt:
        print 'Exiting.'
    finally:
        service_driver.stop_hard()


if __name__ == '__main__':
    main()
