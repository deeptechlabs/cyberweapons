#!/usr/bin/env python

import logging

from assemblyline.al.common import forge
from assemblyline.al.common import log
from assemblyline.al.common import queue

config = forge.get_config()

persistent_settings = {
    'db': config.core.redis.persistent.db,
    'host': config.core.redis.persistent.host,
    'port': config.core.redis.persistent.port,
}

ingestq = queue.NamedQueue('m-ingest-test', **persistent_settings)

def resubmit(metadata):
    ingestq.push(metadata)

def main():
    log.init_logging('test')
    logger = logging.getLogger('assemblyline.test')

    store = forge.get_datastore()

    sids = []
    for x in store.stream_search('submission', 'times.completed:[2015-01-30T00:00:00.000Z TO 2015-01-30T00:59:59.999Z]'):
        sid = x['submission.sid']
        sids.append(sid)

    count = 0
    submissions = store.get_submissions(sids)
    for submission in submissions:
        if submission.get('state', '') != 'completed':
            continue
        if len(submission['files']) != 1:
            continue
        _, srl = submission['files'][0]
        fileinfo = store.get_file(srl)
        if not fileinfo:
            continue
        submission = submission.get('submission', {})
        if not submission:
            continue
        metadata = submission.get('metadata', {})
        if not metadata:
            continue
        metadata['ignore_submission_cache'] = True
        metadata['ignore_cache'] = False
        metadata['md5'] = fileinfo['md5']
        metadata['sha1'] = fileinfo['sha1']
        metadata['sha256'] = fileinfo['sha256']
        metadata['size'] = fileinfo['size']
        resubmit(metadata)
        count += 1
        if count >= 1000:
            break
            
    logger.info('Resubmitted %d submissions for testing', count)

if __name__ == '__main__':
    main()
