#!/usr/bin/env python

import logging

from assemblyline.al.common import forge
from assemblyline.al.common import log as al_log
from assemblyline.al.common import queue
config = forge.get_config()

DATABASE_NUM = 4

al_log.init_logging('expiry_worker')
log = logging.getLogger('assemblyline.expiry_worker')


# noinspection PyBroadException
def main():
    ds = forge.get_datastore()
    fs = forge.get_filestore()
    submission_queue = queue.NamedQueue('d-submission', db=DATABASE_NUM)
    result_queue = queue.NamedQueue('d-result', db=DATABASE_NUM)
    file_queue = queue.NamedQueue('d-file', db=DATABASE_NUM)
    error_queue = queue.NamedQueue('d-error', db=DATABASE_NUM)
    dynamic_queue = queue.NamedQueue('d-dynamic', db=DATABASE_NUM)
    alert_queue = queue.NamedQueue('d-alert', db=DATABASE_NUM)
    filescore_queue = queue.NamedQueue('d-filescore', db=DATABASE_NUM)
    emptyresult_queue = queue.NamedQueue('d-emptyresult', db=DATABASE_NUM)

    log.info("Ready!")
    queues = [submission_queue, result_queue, file_queue, error_queue, dynamic_queue, alert_queue, filescore_queue,
              emptyresult_queue]
    while True:
        queue_name, key = queue.select(*queues)

        try:
            rewrite = False
            expiry = None
            if isinstance(key, tuple) or isinstance(key, list):
                key, rewrite, expiry = key

            if rewrite:
                # noinspection PyProtectedMember
                ds._save_bucket_item(ds.get_bucket(queue_name[2:]), key, {"__expiry_ts__": expiry})

            if queue_name == "d-submission":
                ds.delete_submission(key)
                log.debug("Submission %s (DELETED)" % key)
            elif queue_name == "d-result":
                ds.delete_result(key)
                log.debug("Result %s (DELETED)" % key)
            elif queue_name == "d-error":
                ds.delete_error(key)
                log.debug("Error %s (DELETED)" % key)
            elif queue_name == "d-file":
                ds.delete_file(key)
                if config.core.expiry.delete_storage and fs.exists(key, location='far'):
                    fs.delete(key, location='far')
                log.debug("File %s (DELETED)" % key)
            elif queue_name == "d-alert":
                ds.delete_alert(key)
                log.debug("Alert %s (DELETED)" % key)
            elif queue_name == "d-filescore":
                ds.delete_filescore(key)
                log.debug("FileScore %s (DELETED)" % key)
            elif queue_name == "d-emptyresult":
                ds.delete_result(key)
                log.debug("EmptyResult %s (DELETED)" % key)
            else:
                log.warning("Unknown message: %s (%s)" % (key, queue_name))
        except:
            log.exception("Failed deleting key %s from bucket %s:", key, queue_name)

        queues = queues[1:] + queues[0:1]

if __name__ == '__main__':
    log.info("Expiry worker starting...")
    main()
