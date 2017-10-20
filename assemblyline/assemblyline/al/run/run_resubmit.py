#!/usr/bin/env python

import getopt
import logging
import redis
import sys

from assemblyline.al.common import forge
from assemblyline.al.common import log

config = forge.get_config()

def resubmit(submission):
    del submission['times']
    forge.get_dispatch_queue().send_raw(submission)

def main(shard):
    log.init_logging('dispatcher')
    logger = logging.getLogger('assemblyline.dispatch')

    r = redis.StrictRedis(config.core.redis.nonpersistent.host,
                          config.core.redis.nonpersistent.port,
                          config.core.redis.nonpersistent.db)

    r.delete('ingest-queue-' + shard)

    store = forge.get_datastore()
    store.commit_index('submission')

    query = 'state:submitted AND times.submitted:[NOW-1DAY TO *]'
    sids = []
    for x in store.stream_search('submission', query):
        sid = x['submission.sid']
        if str(forge.determine_dispatcher(sid)) == shard:
            sids.append(sid)

    count = 0
    submissions = store.get_submissions(sids)
    for submission in submissions:
        if submission.get('state', '') != 'submitted':
            sid = submission.get('sid', '')
            if sid:
                store.save_submission(sid, submission)
            continue
        submission['request'] = {}
        for path, srl in submission['files']:
            submission['fileinfo'] = store.get_file(srl)
            submission['request']['path'] = path
            submission['request']['srl'] = srl
            resubmit(submission)
        count += 1
            
    logger.info('Resubmitted %d submissions to dispatcher %s.', count, shard)

if __name__ == '__main__':
    s = '0'

    opts, args = getopt.getopt(sys.argv[1:], 's:', ['shard='])
    for opt, arg in opts:
        if opt in ('-s', '--shard'):
            s = arg

    main(s)
