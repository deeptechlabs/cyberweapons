#!/usr/bin/env python
import logging

from assemblyline.al.common import forge

ds = None

log = logging.getLogger('assemblyline.al.service')


def get_service_queue_length(service_name):
    # noinspection PyBroadException
    try:
        svc_queue = forge.get_service_queue(service_name.split(".")[-1])
        return svc_queue.length()
    except:
        return -1


def get_service_queue_lengths():
    global ds  # pylint: disable=W0603
    if not ds:
        ds = forge.get_datastore()

    # Default is to return all services in a dict of class_name: queue_size.
    queue_lengths = {}
    services = ds.list_services()
    for svc in services:
        # noinspection PyBroadException
        try:
            if not svc:
                continue
            classpath = svc.get('classpath', "al_services.%s.%s" % (svc['repo'], svc['class_name']))
            queue_lengths[svc['name']] = get_service_queue_length(classpath)
        except Exception:  # pylint: disable=W0703
            log.exception('while getting queue length for %s', svc['name'])

    return queue_lengths

if __name__ == '__main__':
    import pprint
    pprint.pprint(get_service_queue_lengths())
