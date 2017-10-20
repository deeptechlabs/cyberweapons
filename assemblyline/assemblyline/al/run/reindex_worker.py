#!/usr/bin/env python

from assemblyline.al.common import forge, queue
from assemblyline.al.common import log

import logging
import os

config = forge.get_config()
config.logging.log_to_console = False
config.logging.log_to_syslog = False
config.logging.log_to_file = True

pid = str(os.getpid())
log.init_logging('reindex_worker.%s' % pid)
logger = logging.getLogger('assemblyline.reindex_worker')


# Run config
DATABASE_NUM = 3

# Globals
ds = forge.get_datastore()
reindex_queue = queue.NamedQueue('r-index', db=DATABASE_NUM)
done_queue = queue.NamedQueue("r-done", db=DATABASE_NUM)


def do_reindex(bucket_name, key):
    try:
        data = ds._get_bucket_item(ds.get_bucket(bucket_name), key)
        data = ds.sanitize(bucket_name, data, key)
        ds._save_bucket_item(ds.get_bucket(bucket_name), key, data)
    except:
        done_queue.push({"is_done": False, "success": False, "bucket_name": bucket_name, "key": key})

    done_queue.push({"is_done": False, "success": True, "bucket_name": bucket_name, "key": key})


if __name__ == "__main__":
    print "\n** Re-Index worker starting! **\n"
    while True:
        _, data = queue.select(reindex_queue)
        if isinstance(data, list):
            data = data[0]
        if data.get('is_done', False):
            break
        else:
            do_reindex(data['bucket_name'], data['key'])

    done_queue.push({"is_done": True})
