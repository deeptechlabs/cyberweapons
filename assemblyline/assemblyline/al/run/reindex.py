#!/usr/bin/env python

import time
import threading
import subprocess
import os
import logging
import sys

from assemblyline.al.common import forge, log as al_log, queue
config = forge.get_config()

# Run config
DATABASE_NUM = 3
RETRY_PRINT_THRESHOLD = 1000
PROCESSES_COUNT = 50
COUNT_INCREMENT = 1000
LOW_THRESHOLD = 10000
HIGH_THRESHOLD = 50000
DEBUG = False
DO_SYS_BUCKETS = True

# Logger
al_log.init_logging('reindex')
log = logging.getLogger('assemblyline.reindex')

# Globals
ds = forge.get_datastore()
reindex_queue = queue.NamedQueue('r-index', db=DATABASE_NUM)
done_queue = queue.NamedQueue("r-done", db=DATABASE_NUM)
bucket_error = []

bucket_map = {
    "node": ds.nodes,
    "profile": ds.profiles,
    "signature": ds.signatures,
    "user": ds.users,
    "alert": ds.alerts,
    "file": ds.files,
    "result": ds.results,
    "error": ds.errors,
    "submission": ds.submissions,
    "filescore": ds.filescores
}


def cleanup_queues():
    # TODO: restart from last place instead of cleaning up and restart from start...
    log.info("Cleaning up reindex and done queues...")
    reindex_queue.delete()
    for _ in xrange(PROCESSES_COUNT):
        reindex_queue.push({"is_done": True})
    time.sleep(5)
    reindex_queue.delete()
    done_queue.delete()


# noinspection PyProtectedMember,PyBroadException
def process_bucket(b_name, bucket):
    try:
        count = 0
        for key in ds._stream_bucket_debug_keys(bucket):
            reindex_queue.push({"bucket_name": b_name, "key": key})

            count += 1
            if count % COUNT_INCREMENT == 0:
                if reindex_queue.length() > HIGH_THRESHOLD:
                    retry = 0
                    while reindex_queue.length() > LOW_THRESHOLD:
                        if retry % RETRY_PRINT_THRESHOLD == 0:
                            log.info("Re-Index queue reached max threshold (%s). Waiting for queue size to "
                                     "reach %s before sending more keys... [%s]" % (HIGH_THRESHOLD,
                                                                                    LOW_THRESHOLD,
                                                                                    reindex_queue.length()))
                        time.sleep(0.1)
                        retry += 1
    except:
        log.error("Error occurred while processing bucket %s." % b_name)
        bucket_error.append(b_name)


def done_thread():
    global bucket_error
    map_count = {}
    t_count = 0
    e_count = 0
    t0 = time.time()
    t_last = t0
    done_count = 0
    while True:
        _, data = queue.select(done_queue)
        if data.get("is_done", False):
            done_count += 1
        else:
            if data.get('success', False):
                t_count += 1

                bucket_name = data['bucket_name']

                if bucket_name not in map_count:
                    map_count[bucket_name] = 0

                map_count[bucket_name] += 1

                if t_count % COUNT_INCREMENT == 0:
                    new_t = time.time()
                    log.info("%s (%s at %s keys/sec) Q:%s ==> %s" % (t_count,
                                                                     new_t-t_last,
                                                                     int(COUNT_INCREMENT/(new_t-t_last)),
                                                                     reindex_queue.length(),
                                                                     map_count))
                    t_last = new_t
            else:
                e_count += 1

        if done_count == PROCESSES_COUNT:
            break

    summary = ""
    summary += "Re-Index DONE! (%s keys re-indexed - %s errors - %s secs)\n" % (t_count, e_count, time.time()-t0)
    summary += "\n############################################\n"
    summary += "########## RE-INDEX SUMMARY ################\n"
    summary += "############################################\n\n"

    for k, v in map_count.iteritems():
        summary += "\t%15s: %s\n" % (k.upper(), v)
    if len(bucket_error) > 0:
        summary += "\nThese buckets failed to index completely: %s\n" % bucket_error
    log.info(summary)


if __name__ == "__main__":
    p_list = []
    try:
        args = sys.argv[1:]
        buckets = []
        for a in args:
            if a in bucket_map:
                buckets.append(a)

        if len(buckets) == 0:
            log.info("You need to specify buckets to re-index. reindex.py BUCKET1 BUCKET2 ... BUCKETN")
            exit()

        log.info("Full data re-indexer is starting on buckets: %s" % ", ".join(buckets))

        # Cleanup the queues before starting the workers
        cleanup_queues()

        # Start reindex workers
        log.info("Spawning %s Re-Indexer workers..." % PROCESSES_COUNT)
        DEVNULL = open(os.devnull, 'w')
        for _ in xrange(PROCESSES_COUNT):
            run_dir = os.path.abspath(__file__).replace("reindex.py", "")
            p = subprocess.Popen([os.path.join(run_dir, "invoke.sh"),
                                  os.path.join(run_dir, 'reindex_worker.py')],
                                 stderr=DEVNULL,
                                 stdout=DEVNULL)
            p_list.append(p)
        log.info("All Re-Indexer workers started!")

        # Start done thread
        t = threading.Thread(target=done_thread, name="Done thread")
        t.start()

        # Process data buckets
        log.info("Processing buckets...")
        for name in buckets:
            log.info("Processing bucket: %s" % name)
            process_bucket(name, bucket_map[name])

        # Push kill message to all workers
        log.info("All queues done. Sending kill command to workers and waiting for them to finish...")
        for _ in xrange(PROCESSES_COUNT):
            reindex_queue.push({"is_done": True})

        # Wait for workers to finish
        t.join()
    finally:
        log.info("Re-Indexer terminated.")
