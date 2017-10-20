#!/usr/bin/env python

import logging
import os

from assemblyline.common.isotime import now_as_iso, epoch_to_iso, iso_to_epoch
from assemblyline.al.common import forge
from assemblyline.al.common import log
from assemblyline.al.common import queue

config = forge.get_config()
datastore = forge.get_datastore()

log.init_logging('idx_to_journal')

directory = config.core.expiry.journal.directory
emptyresult_queue = queue.NamedQueue(
    "ds-emptyresult",
    db=config.core.redis.persistent.db,
    host=config.core.redis.persistent.host,
    port=config.core.redis.persistent.port,
)
logger = logging.getLogger('assemblyline.idx_to_journal')
max_open_files = 1
path_and_filehandle = []
path_to_filehandle = {}
previous = []


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


# noinspection PyBroadException
def main():
    for day in range(31):
        today = now_as_iso(24 * 60 * 60 * day)
        query = "__expiry_ts__:[%s TO %s+1DAY]" % (today, today)
        minutes_params = (
            ("rows", "0"),
            ("facet", "on"),
            ("facet.date", "__expiry_ts__"),
            ("facet.date.start", today),
            ("facet.date.end", today + "+1DAY"),
            ("facet.date.gap", "+1MINUTE"),
            ("facet.mincount", "1"),
        )
        res_minutes = datastore.direct_search("emptyresult", query, args=minutes_params)
        minutes = res_minutes.get("facet_counts", {}).get("facet_dates", {}).get("__expiry_ts__", {})
        for minute, minute_count in minutes.iteritems():
            if minute in ['end', 'gap', 'start']:
                continue

            if minute_count > 0:
                for x in datastore.stream_search('emptyresult', "__expiry_ts__:[%s TO %s+1MINUTE]" % (minute, minute)):
                    try:
                        created = epoch_to_iso(iso_to_epoch(today) - (15 * 24 * 60 * 60))
                        riak_key = x['_yz_rk']

                        path = os.path.join(directory, created[:10]) + '.index'
                        fh = get_filehandle(path)

                        fh.write(riak_key + "\n")
                        fh.flush()

                    except:  # pylint: disable=W0702
                        logger.exception('Unhandled exception:')

if __name__ == '__main__':
    main()
