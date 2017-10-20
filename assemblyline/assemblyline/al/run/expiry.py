#!/usr/bin/env python

import logging
import os
import time

from threading import Thread

from assemblyline.common.isotime import now_as_iso, now, iso_to_epoch
from assemblyline.al.common import forge, log as al_log, queue
from assemblyline.al.core.datastore import SearchException

DATABASE_NUM = 4
QUERY = "__expiry_ts__:[* TO NOW-12HOUR]"  # Delay expiry by 12 hours so we expire peak data during offpeak hours
SLEEP_TIME = 5
MAX_QUEUE_LENGTH = 100000

config = forge.get_config()
al_log.init_logging('expiry')
log = logging.getLogger('assemblyline.expiry')


def load_expired(datastore, name, delete_queue):
    # Keep track of the last 60 minutes we've processed and don't reprocess them until they are out of the ignored
    # window to let time for the index to be commited to memory
    max_rows = 500
    max_depth = 5000
    ignored_window = []
    max_window_size = 60

    hosts = datastore.hosts
    host_id = 0

    log.debug("Expiry will cycle through the following hosts: %s" % ", ".join(hosts))
    first_run = True
    while True:
        cur_host = hosts[host_id % len(hosts)]
        log.debug("Running queries through node: %s" % cur_host)
        try:
            if delete_queue.length() == 0:
                params = (
                    ("rows", "0"),
                    ("facet", "on"),
                    ("facet.date", "__expiry_ts__"),
                    ("facet.date.start", "NOW/DAY-1MONTH"),
                    ("facet.date.end", "NOW/DAY+1DAY"),
                    ("facet.date.gap", "+1DAY"),
                    ("facet.mincount", "1")
                )

                res_overview = datastore.direct_search(name, QUERY, args=params, _hosts_=[cur_host])

                days = res_overview.get("facet_counts", {}).get("facet_dates", {}).get("__expiry_ts__", {})
                for day, count in days.iteritems():
                    if day in ['end', 'gap', 'start']:
                        continue

                    # We will rewrite keys that are older then two days that we've seen in more then one run
                    #     The index is most likely out of sync for these keys....
                    rewrite = False
                    if not day.startswith(now_as_iso()[:10]) and \
                            not day.startswith(now_as_iso(-86400)[:10]) and \
                            not first_run:
                        rewrite = True

                    if count > 0:
                        minutes_params = (
                            ("fq", "__expiry_ts__:[%s TO %s+1DAY]" % (day, day)),
                            ("rows", "0"),
                            ("facet", "on"),
                            ("facet.date", "__expiry_ts__"),
                            ("facet.date.start", day),
                            ("facet.date.end", day + "+1DAY"),
                            ("facet.date.gap", "+1MINUTE"),
                            ("facet.mincount", "1"),
                        )
                        res_minutes = datastore.direct_search(name, QUERY, args=minutes_params, _hosts_=[cur_host])

                        minutes = res_minutes.get("facet_counts", {}).get("facet_dates", {}).get("__expiry_ts__", {})
                        for minute, minute_count in minutes.iteritems():
                            if minute in ['end', 'gap', 'start'] or minute in ignored_window:
                                continue

                            ignored_window.append(minute)
                            if len(ignored_window) > max_window_size:
                                ignored_window.pop(0)

                            if minute_count > 0:
                                for r in range(0, minute_count, max_rows)[:max_depth / max_rows]:
                                    data_params = (
                                        ("fl", "_yz_rk"),
                                        ("rows", str(max_rows)),
                                        ("start", str(r))
                                    )
                                    res = datastore.direct_search(name,
                                                                  "__expiry_ts__:[%s TO %s+1MINUTE]" % (minute, minute),
                                                                  args=data_params, _hosts_=[cur_host])
                                    delete_queue.push(*[(x['_yz_rk'], rewrite, day)
                                                        for x in res.get("response", {}).get("docs", [])])

                                while delete_queue.length() > MAX_QUEUE_LENGTH:
                                    time.sleep(SLEEP_TIME)

                first_run = False
        except SearchException:
            # We've hit a search exception, reset and retry...
            ignored_window = []
            first_run = True

        host_id += 1
        time.sleep(SLEEP_TIME)


def load_journal(name, delete_queue):
    working_dir = config.core.expiry.journal.directory
    expiry_ttl = config.core.expiry.journal.ttl * 24 * 60 * 60
    log.debug("Expiry will load journal in %s for %s bucket." % (working_dir, name))
    while True:
        try:
            for listed_file in os.listdir(working_dir):
                journal_file = os.path.join(working_dir, listed_file)
                if os.path.isfile(journal_file):
                    if journal_file.endswith(name):
                        cur_time = now()
                        day = "%sT00:00:00Z" % listed_file.split(".")[0]
                        file_time = iso_to_epoch(day)
                        if file_time + expiry_ttl <= cur_time:
                            with open(journal_file) as to_delete_journal:
                                count = 0
                                for line in to_delete_journal:
                                    if count % 1000 == 0:
                                        while delete_queue.length() > MAX_QUEUE_LENGTH:
                                            time.sleep(SLEEP_TIME)

                                    line = line.strip()
                                    if line:
                                        delete_queue.push(line)

                                    count += 1

                            os.unlink(journal_file)
        except OSError:
            pass

        time.sleep(SLEEP_TIME)


def track_status(queues):
    while True:
        log.info("%6i A | %6i E | %6i F | %6i R | %6i S | %6i FS | %6i ER" % (queues['alert'].length(),
                                                                              queues['error'].length(),
                                                                              queues['file'].length(),
                                                                              queues['result'].length(),
                                                                              queues['submission'].length(),
                                                                              queues['filescore'].length(),
                                                                              queues['emptyresult'].length()))
        time.sleep(SLEEP_TIME)


def main(bucket_list, journal_queues):
    ds = forge.get_datastore()
    queues = {x: queue.NamedQueue('d-%s' % x, db=DATABASE_NUM) for x in set(journal_queues).union(set(bucket_list))}

    Thread(target=track_status, name="queues_status", args=(queues,)).start()

    log.info("Ready!")
    loader_threads = {x: Thread(target=load_expired,
                                name="loader_%s" % x,
                                args=(ds, x, queues[x])) for x in bucket_list}

    loader_threads.update({'journal_%s' % x: Thread(target=load_journal,
                                                    name="journal_loader_%s" % x,
                                                    args=(x, queues[x])) for x in journal_queues})

    for thread in loader_threads.itervalues():
        thread.start()

    for thread in loader_threads.itervalues():
        thread.join()


if __name__ == '__main__':
    log.info("AL Expiry cleanup starting...")

    buckets = ["submission", "file", "alert", "result", "error", "filescore"]
    journal_queues = []
    if config.core.expiry.get('journal', None):
        journal_queues.append('emptyresult')
    main(buckets, journal_queues)
