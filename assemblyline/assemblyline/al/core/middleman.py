#!/usr/bin/env python
"""
Middleman

Middleman is responsible for monitoring for incoming submission requests,
sending submissions, waiting for submissions to complete, sending a message
to a notification queue as specified by the submission and, based on the
score received, possibly sending a message to indicate that an alert should
be created.
"""

# This file has comments prefixed with a 'df' which are used to extract a
# dataflow diagram. These comments take one of the six forms shown below:
#
# rule <name> <regex> => <replacement> [#]
# text <literal text> [#]
# line <name> [#]
# node <name> [#]
# pull <name> [#]
# push <name> [#]
#
# Rule lines cause the replacement to be stored with a given name.
# Text lines insert the text verbatim. Line lines apply the rule with
# the given name to the current line. Head and pull/push lines are
# similar except that the text extracted from a node line is retained
# and matched with all following pull/push lines until the next node
# line. All dataflow directives are terminated by a newline but they
# can also be terminated by a hash character so that they can share a
# line with pylint, or other, directives.
#
# To produce a dataflow diagram find the dataflow script (most likely
# under al/run/admin) and (with Graphviz installed) run:
#
#   dataflow.py < middleman.py | dot -Tsvg > dataflow.svg
#
# df rule add ^\W*(\w+)\.add.* => \1
# df rule calls ^\W*(?:if )?(\w+).* => \1
# df rule def ^def (\w+).* => \1
# df rule delete ^\W*(\w+)\.delete.* => \1
# df rule hash ^(\w+) = .*  => \1 [label=\1,shape=polygon,sides=4,skew=.4]
# df rule ifcalls ^\W*if (\w+).* => \1
# df rule pop ^.* (\w+)\.pop.* => \1
# df rule push ^\W*(\w+)\.push.* => \1
# df rule queue ^(\w+) = .* => \1 [label=\1,shape=plaintext]
# df rule thread ^.*range.(\w+).*target=(\w+).* => \2 [label="\2 x\1"]
#
# df text digraph dataflow {
# df text node [shape=box]
# df text rankdir=TB
# df text ranksep="1"
# df text { rank=source; "ingestq"; "completeq"; }
# df text { rank=sink; "alertq"; "trafficq"; }

import getopt
import logging
import redis
import signal
import sys
import time

import riak

from collections import namedtuple
from math import tanh
from random import random
from assemblyline.common import net
from threading import RLock, Thread

from assemblyline.common.charset import dotdump, safe_str
from assemblyline.common.exceptions import get_stacktrace_info
from assemblyline.common.isotime import iso_to_epoch, now, now_as_iso
from assemblyline.common.net import get_hostip, get_hostname, get_mac_address
from assemblyline.al.common import forge
from assemblyline.al.common import counter
from assemblyline.al.common import log
from assemblyline.al.common import message
from assemblyline.al.common import queue
from assemblyline.al.common.notice import Notice, overrides
from assemblyline.al.common.remote_datatypes import Hash
from assemblyline.al.common.task import Task, get_submission_overrides
from assemblyline.al.core.datastore import create_filescore_key
from assemblyline.al.core.filestore import FileStoreException, CorruptedFileStoreException


class ScanLock(object):
    SCAN_LOCK_LOCK = RLock()
    SCAN_LOCK = {}

    def __init__(self, scan_key):
        self.scan_key = scan_key

    def __enter__(self):
        with self.SCAN_LOCK_LOCK:
            l = self.SCAN_LOCK.get(self.scan_key, None)
            if not l:
                self.SCAN_LOCK[self.scan_key] = l = [0, RLock()]
            l[0] += 1
        l[1].acquire()

    def __exit__(self, unused1, unused2, unused3):
        with self.SCAN_LOCK_LOCK:
            l = self.SCAN_LOCK[self.scan_key]
            l[0] -= 1
            if l[0] == 0:
                del self.SCAN_LOCK[self.scan_key]
        l[1].release()


Timeout = namedtuple('Timeout', ['time', 'scan_key'])


Classification = forge.get_classification()
config = forge.get_config()
constants = forge.get_constants()

log.init_logging("middleman")
logger = logging.getLogger('assemblyline.middleman')

persistent = {
    'db': config.core.redis.persistent.db,
    'host': config.core.redis.persistent.host,
    'port': config.core.redis.persistent.port,
}

shards = 1
try:
    shards = int(config.core.middleman.shards)
except AttributeError:
    logger.warning("No shards setting. Defaulting to %d.", shards)

shard = '0'
opts, _ = getopt.getopt(sys.argv[1:], 's:', ['shard='])
for opt, arg in opts:
    if opt in ('-s', '--shard'):
        shard = arg

# Globals
alertq = queue.NamedQueue('m-alert', **persistent)  # df line queue
cache = {}
cache_lock = RLock()
chunk_size = 1000
completeq_name = 'm-complete-' + shard
date_fmt = '%Y-%m-%dT%H:%M:%SZ'
default_prefix = config.core.middleman.default_prefix
dup_prefix = 'w-' + shard + '-'
dupq = queue.MultiQueue(**persistent)  # df line queue
expire_after_seconds = config.core.middleman.expire_after
get_whitelist_verdict = forge.get_get_whitelist_verdict()
hostinfo = {
    'ip:': get_hostip(),
    'mac_address': get_mac_address(),
    'host': get_hostname(),
}
ingestq_name = 'm-ingest-' + shard
is_low_priority = forge.get_is_low_priority()
max_priority = config.submissions.max.priority
max_retries = 10
max_time = 2 * 24 * 60 * 60  # Wait 2 days for responses.
max_waiting = int(config.core.dispatcher.max.inflight) / (2 * shards)
min_priority = 1
priority_value = constants.PRIORITIES
retry_delay = 180
retryq = queue.NamedQueue('m-retry-' + shard, **persistent)  # df line queue
running = True
sampling = False
selected_initial = [
    'Antivirus', 'Extraction', 'Filtering', 'Networking', 'Static Analysis'
]
stale_after_seconds = config.core.middleman.stale_after
start_time = now()
submissionq = queue.NamedQueue('m-submission-' + shard, **persistent)  # df line queue
timeouts = []
timeouts_lock = RLock()
whitelist = forge.get_whitelist()
whitelisted = {}
whitelisted_lock = RLock()

dropper_threads = 1
try:
    dropper_threads = int(config.core.middleman.dropper_threads)
except AttributeError:
    logger.warning(
        "No dropper_threads setting. Defaulting to %d.",
        dropper_threads
    )

incomplete_expire_after_seconds = 3600
try:
    incomplete_expire_after_seconds = \
        config.core.middleman.incomplete_expire_after
except AttributeError:
    logger.warning(
        "No incomplete_stale_after setting. Defaulting to %d.",
        incomplete_expire_after_seconds
    )

incomplete_stale_after_seconds = 1800
try:
    incomplete_stale_after_seconds = \
        config.core.middleman.incomplete_stale_after
except AttributeError:
    logger.warning(
        "No incomplete_stale_after setting. Defaulting to %d.",
        incomplete_stale_after_seconds
    )

ingester_threads = 1
try:
    ingester_threads = int(config.core.middleman.ingester_threads)
except AttributeError:
    logger.warning(
        "No ingester_threads setting. Defaulting to %d.",
        ingester_threads
    )

submitter_threads = 1
try:
    submitter_threads = int(config.core.middleman.submitter_threads)
except AttributeError:
    logger.warning(
        "No submitter_threads setting. Defaulting to %d.",
        submitter_threads
    )

defaults = {
    'classification': config.core.middleman.classification,
    'completed_queue': completeq_name,
    'deep_scan': False,
    'ignore_cache': False,
    'ignore_filtering': False,
    'ignore_tag': False,
    'max_extracted': config.core.middleman.max_extracted,
    'max_supplementary': config.core.middleman.max_supplementary,
    'params': {},
}

# When a unique queue for a priority group has passed a threshold value, we
# start sampling, gradually increasing the probability that a newly ingested
# entry will be dropped.
sample_threshold = {
    'low': config.core.middleman.get('sampling_at', {}).get('low', 10000000),
    'medium': config.core.middleman.get('sampling_at', {}).get('medium', 2000000),
    'high': config.core.middleman.get('sampling_at', {}).get('high', 1000000),
    'critical': config.core.middleman.get('sampling_at', {}).get('critical', 500000),
}

priority_range = {}

prev = 'low'
start = 0
for lvl in ('medium', 'high', 'critical', 'user'):
    end = priority_value.get(lvl, max_priority + 1)
    priority_range[prev] = (start, end - 1)
    prev = lvl
    start = end

threshold_value = {
    'critical': 500,
    'high': 100,
}

# Input. An external process creates a record when any submission completes.
completeq = queue.NamedQueue(completeq_name)  # df line queue

# Output. Dropped entries are placed on this queue.
dropq = queue.NamedQueue('m-drop-' + shard, **persistent)  # df line queue

# Input. An external process places submission requests on this queue.
ingestq = queue.NamedQueue(ingestq_name, **persistent)  # df line queue

# Output. Notifications are placed on a notification queue.
notificationq = {}

# Input/Output. Unique requests are placed in and processed from this queue.
uniqueq = queue.PriorityQueue('m-unique-' + shard, **persistent)  # df line queue

# State. The submissions in progress are stored in Redis in order to
# persist this state and recover in case we crash.
scanning = Hash('m-scanning-' + shard, **persistent)  # df line hash

# Status.
statusq = queue.CommsQueue('status')

# Traffic.
# df text trafficq [label=trafficq,shape=plaintext]
trafficq = queue.LocalQueue()


def exit_and_log(original):
    # noinspection PyBroadException
    def wrapper(*args, **kwargs):
        global running  # pylint: disable=W0603
        try:
            return original(*args, **kwargs)
        except:  # pylint: disable=W0702
            logger.exception("Exiting:")
            running = False

    wrapper.__name__ = original.__name__
    wrapper.__doc__ = original.__doc__
    wrapper.__dict__.update(original.__dict__)

    return wrapper


def _add(key, psid, sid, score, errors, t):
    cache[key] = {
        'errors': errors,
        'psid': psid,
        'score': score,
        'sid': sid,
        'time': t,
    }


def add(key, psid, sid, score, errors, t):
    with cache_lock:
        _add(key, psid, sid, score, errors, t)


def check(datastore, notice):
    key = stamp_filescore_key(notice)

    with cache_lock:
        result = cache.get(key, None)

    counter_name = 'ingest.cache_hit_local'
    if result:
        logger.info('Local cache hit')
    else:
        counter_name = 'ingest.cache_hit'

        result = datastore.get_filescore(key)
        if result:
            logger.info('Remote cache hit')
        else:
            ingester_counts.increment('ingest.cache_miss')
            return None, False, None, key

        add(key, result.get('psid', None), result['sid'], result['score'],
            result.get('errors', 0), result['time'])

    current_time = now()
    delta = current_time - result.get('time', current_time)
    errors = result.get('errors', 0)

    if expired(delta, errors):
        ingester_counts.increment('ingest.cache_expired')
        with cache_lock:
            cache.pop(key, None)
            datastore.delete_filescore(key)
        return None, False, None, key 
    elif stale(delta, errors):
        ingester_counts.increment('ingest.cache_stale')
        return None, False, result['score'], key

    ingester_counts.increment(counter_name)

    return result.get('psid', None), result['sid'], result['score'], key


# Invoked when notified that a submission has completed.
# noinspection PyBroadException
def completed(task):  # df node def
    sha256 = task.root_sha256

    psid = task.psid
    score = task.score
    sid = task.sid

    scan_key = task.scan_key

    with ScanLock(scan_key):
        # Remove the entry from the hash of submissions in progress.
        raw = scanning.pop(scan_key)  # df pull pop
        if not raw:
            logger.warning("Untracked submission (score=%d) for: %s %s",
                           int(score), sha256, str(task.metadata))

            # Not a result we care about. We are notified for every
            # submission that completes. Some submissions will not be ours.
            if task.metadata:
                stype = None
                try:
                    stype = task.metadata.get('type', None)
                except:  # pylint: disable=W0702
                    logger.exception("Malformed metadata: %s:", sid)

                if not stype:
                    return scan_key
            
                if (task.description or '').startswith(default_prefix):
                    raw = {
                        'metadata': task.metadata,
                        'overrides': get_submission_overrides(task, overrides),
                        'sha256': sha256,
                        'type': stype,
                    }

                    finalize(psid, sid, score, Notice(raw))
            return scan_key

        errors = task.raw.get('error_count', 0)
        file_count = task.raw.get('file_count', 0)
        ingester_counts.increment('ingest.submissions_completed')
        ingester_counts.increment('ingest.files_completed', file_count)
        ingester_counts.increment('ingest.bytes_completed', int(task.size or 0))

        notice = Notice(raw)
 
        with cache_lock:
            _add(scan_key, psid, sid, score, errors, now())

        finalize(psid, sid, score, notice)  # df push calls

        def exhaust():
            while True:
                res = dupq.pop(  # df pull pop
                    dup_prefix + scan_key, blocking=False
                )
                if res is None:
                    break
                yield res

        # You may be tempted to remove the assignment to dups and use the
        # value directly in the for loop below. That would be a mistake.
        # The function finalize may push on the duplicate queue which we
        # are pulling off and so condensing those two lines creates a
        # potential infinite loop.
        dups = [dup for dup in exhaust()]
        for dup in dups:
            finalize(psid, sid, score, Notice(dup))

    return scan_key


def stamp_filescore_key(notice, sha256=None):
    if not sha256:
        sha256 = notice.get('sha256')
    key_data = notice.parse(
        description=': '.join((default_prefix, sha256 or '')), **defaults
    )
    selected = notice.get('selected')

    key = notice.get('scan_key', None)
    if not key:
        key = create_filescore_key(sha256, key_data, selected)
        notice.set('scan_key', key)

    return key


def determine_resubmit_selected(selected, resubmit_to):
    resubmit_selected = None

    selected = set(selected)
    resubmit_to = set(resubmit_to)

    if not selected.issuperset(resubmit_to):
        resubmit_selected = sorted(selected.union(resubmit_to))

    return resubmit_selected


def drop(notice):  # df node def
    priority = notice.get('priority')

    dropped = False
    if priority <= min_priority:
        dropped = True
    else:
        for level in ('low', 'medium', 'critical', 'high'):
            rng = priority_range[level]
            if rng[0] <= priority <= rng[1]:
                dropped = must_drop(uniqueq.count(*rng),
                                    sample_threshold[level])
                break

    if notice.get('never_drop', False) or not dropped:
        return False

    notice.set('failure', 'Skipped')
    dropq.push(notice.raw)  # df push push

    ingester_counts.increment('ingest.skipped')

    return True


def drop_chance(length, maximum):
    return tanh(float(length - maximum) / maximum * 2.0)


@exit_and_log
def dropper():  # df node def
    datastore = forge.get_datastore()

    while running:
        raw = dropq.pop(timeout=1)  # df pull pop
        if not raw:
            continue

        notice = Notice(raw)

        send_notification(notice)

        c12n = notice.get('classification', config.core.middleman.classification)
        expiry = now_as_iso(86400)
        sha256 = notice.get('sha256')

        datastore.save_or_freshen_file(sha256, {'sha256': sha256}, expiry, c12n)

    datastore.close()


def expired(delta, errors):
    if errors:
        return delta >= incomplete_expire_after_seconds
    else:
        return delta >= expire_after_seconds


def finalize(psid, sid, score, notice):  # df node def
    logger.debug("Finalizing (score=%d) %s", score, notice.get('sha256'))
    if psid:
        notice.set('psid', psid)
    notice.set('sid', sid)
    notice.set('al_score', score)

    selected = notice.get('selected', [])
    resubmit_to = notice.get('resubmit_to', [])

    resubmit_selected = determine_resubmit_selected(selected, resubmit_to)
    will_resubmit = resubmit_selected and should_resubmit(score)
    if will_resubmit:
        notice.set('psid', None)

    if is_alert(notice, score):
        alertq.push(notice.raw)  # df push push

    send_notification(notice)

    if will_resubmit:
        notice.set('psid', sid)
        notice.set('resubmit_to', [])
        notice.set('scan_key', None)
        notice.set('sid', None)
        notice.set('selected', resubmit_selected)
        priority = notice.get('priority', 0)

        uniqueq.push(priority, notice.raw)  # df push push


def ingest(datastore, user_groups, raw):  # df node def
    notice = Notice(raw)

    ignore_size = notice.get('ignore_size', False)
    never_drop = notice.get('never_drop', False)
    sha256 = notice.get('sha256')
    size = notice.get('size', 0)

    # Make sure we have a submitter ...
    user = notice.get('submitter', None)
    if user is None:
        user = config.submissions.user
        notice.set('submitter', user)

    # ... and groups.
    groups = notice.get('groups', None)
    if groups is None:
        groups = user_groups.get(user, None)
        if groups is None:
            ruser = datastore.get_user(user)
            if not ruser:
                return
            groups = ruser.get('groups', [])
            user_groups[user] = groups
        notice.set('groups', groups)

    selected = notice.get('selected', None)
    if not selected:
        selected = selected_initial
        notice.set('selected', selected)
        notice.set('resubmit_to', ['Dynamic Analysis'])

    resubmit_to = notice.get('resubmit_to', None)
    if resubmit_to is None:
        notice.set('resubmit_to', [])

    ingester_counts.increment('ingest.bytes_ingested', int(size))
    ingester_counts.increment('ingest.submissions_ingested')

    if not sha256:
        send_notification(
            notice, failure="Invalid sha256", logfunc=logger.warning
        )
        return

    c12n = notice.get('classification', '')
    if not Classification.is_valid(c12n):
        send_notification(
            notice, failure="Invalid classification %s" % c12n,
            logfunc=logger.warning
        )
        return

    metadata = notice.get('metadata', {})
    if isinstance(metadata, dict):
        to_delete = []
        for k, v in metadata.iteritems():
            size = sys.getsizeof(v, -1)
            if isinstance(v, basestring):
                size = len(v)
            if size > config.core.middleman.max_value_size:
                to_delete.append(k)
            elif size < 0:
                to_delete.append(k)
        if to_delete:
            logger.info('Removing %s from %s', to_delete, notice.raw)
            for k in to_delete:
                metadata.pop(k, None)

    if size > config.submissions.max.size and not ignore_size and not never_drop:
        notice.set(
            'failure', "File too large (%d > %d)" % (size, config.submissions.max.size)
        )
        dropq.push(notice.raw)  # df push push
        ingester_counts.increment('ingest.skipped')
        return

    pprevious, previous, score = None, False, None
    if not notice.get('ignore_cache', False):
        pprevious, previous, score, _ = check(datastore, notice)

    # Assign priority.
    low_priority = is_low_priority(notice)

    priority = notice.get('priority')
    if priority is None:
        priority = priority_value['medium']

        if score is not None:
            priority = priority_value['low']
            for level in ('critical', 'high'):
                if score >= threshold_value[level]:
                    priority = priority_value[level]
                    break
        elif low_priority:
            priority = priority_value['low']

    # Reduce the priority by an order of magnitude for very old files.
    current_time = now()
    if priority and \
            expired(current_time - seconds(notice.get('ts', current_time)), 0):
        priority = (priority / 10) or 1

    notice.set('priority', priority)

    # Do this after priority has been assigned.
    # (So we don't end up dropping the resubmission).
    if previous:
        ingester_counts.increment('ingest.duplicates')
        finalize(pprevious, previous, score, notice)  # df push calls
        return

    if drop(notice):  # df push calls
        return

    if is_whitelisted(notice):  # df push calls
        return

    uniqueq.push(priority, notice.raw)  # df push push


@exit_and_log
def ingester():  # df node def # pylint:disable=R0912
    datastore = forge.get_datastore()
    user_groups = {}

    # Move from ingest to unique and waiting queues.
    # While there are entries in the ingest queue we consume chunk_size
    # entries at a time and move unique entries to uniqueq / queued and
    # duplicates to their own queues / waiting.
    while running:
        while True:
            result = completeq.pop(blocking=False)  # df pull pop
            if not result:
                break

            completed(Task(result))  # df push calls

        entry = ingestq.pop(timeout=1)  # df pull pop
        if not entry:
            continue

        trafficq.push(entry)  # df push push

        sha256 = entry.get('sha256', '')
        if not sha256 or len(sha256) != 64:
            logger.error("Invalid sha256: %s", entry)
            continue

        entry['md5'] = entry.get('md5', '').lower()
        entry['sha1'] = entry.get('sha1', '').lower()
        entry['sha256'] = sha256.lower()

        ingest(datastore, user_groups, entry)  # df push calls

    datastore.close()


# noinspection PyBroadException
def init():
    datastore = forge.get_datastore()
    datastore.commit_index('submission')

    sids = [
        x['submission.sid'] for x in datastore.stream_search(
            'submission',
            'state:submitted AND times.submitted:[NOW-1DAY TO *] '
            'AND submission.metadata.type:* '
            'AND NOT submission.description:Resubmit*'
        )
    ]

    submissions = {}
    submitted = {}
    for submission in datastore.get_submissions(sids):
        task = Task(submission)

        if not task.original_selected or not task.root_sha256 or not task.scan_key:
            continue

        if forge.determine_ingest_queue(task.root_sha256) != ingestq_name:
            continue

        scan_key = task.scan_key
        submissions[task.sid] = submission
        submitted[scan_key] = task.sid

    # Outstanding is the set of things Riak believes are being scanned.
    outstanding = set(submitted.keys())

    # Keys is the set of things middleman believes are being scanned.
    keys = set(scanning.keys())

    # Inflight is the set of submissions middleman and Riak agree are inflight.
    inflight = outstanding.intersection(keys)

    # Missing is the set of submissions middleman thinks are in flight but
    # according to Riak are not incomplete.
    missing = keys.difference(inflight)

    # Process the set of submissions Riak believes are incomplete but
    # middleman doesn't know about.
    for scan_key in outstanding.difference(inflight):
        sid = submitted.get(scan_key, None)

        if not sid:
            logger.info("Init: No sid found for incomplete")
            continue

        if not task.original_selected or not task.root_sha256 or not task.scan_key:
            logger.info("Init: Not root_sha256 or original_selected")
            continue

        submission = submissions[sid]

        task = Task(submission)

        if not task.metadata:
            logger.info(
                "Init: Incomplete submission is not one of ours: %s", sid
            )

        stype = None
        try:
            stype = task.metadata.get('type', None)
        except:  # pylint: disable=W0702
            logger.exception(
                "Init: Incomplete submission has malformed metadata: %s", sid
            )
            
        if not stype:
            logger.info("Init: Incomplete submission missing type: %s", sid)

        raw = {
            'metadata': task.metadata,
            'overrides': get_submission_overrides(task, overrides),
            'sha256': task.root_sha256,
            'type': stype,
        }
        raw['overrides']['selected'] = task.original_selected

        reinsert(datastore, " (incomplete)", Notice(raw), logger)

    r = redis.StrictRedis(persistent['host'],
                          persistent['port'],
                          persistent['db'])

    # Duplicates is the set of sha256s where a duplicate queue exists.
    duplicates = [
        x.replace(dup_prefix, '', 1) for x in r.keys(dup_prefix + '*')
    ]

    # Process the set of duplicates where no scanning or riak entry exists.
    for scan_key in set(duplicates).difference(outstanding.union(keys)):
        raw = dupq.pop(dup_prefix + scan_key, blocking=False)
        if not raw:
            logger.warning("Init: Couldn't pop off dup queue (%s)", scan_key)
            dupq.delete(dup_prefix + scan_key)
            continue

        reinsert(datastore, " (missed duplicate)", Notice(raw), logger)

    while True:
        res = completeq.pop(blocking=False)
        if not res:
            break

        scan_key = completed(Task(res))
        try:
            missing.remove(scan_key)
        except:  # pylint: disable=W0702
            pass

    # Process the set of submissions middleman thinks are in flight but
    # according to Riak are not incomplete.
    for scan_key in missing:
        raw = scanning.pop(scan_key)
        if raw:
            reinsert(datastore, '', Notice(raw), logger, retry_all=False)

    # Set up time outs for all inflight submissions.
    expiry_time = now(max_time)
    for scan_key in inflight:
        # No need to lock. We're the only thing running at this point.
        timeouts.append(Timeout(scan_key, expiry_time))

    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)

    datastore.close()


# noinspection PyUnusedLocal
def interrupt(unused1, unused2):  # pylint:disable=W0613
    global running  # pylint:disable=W0603
    logger.info("Caught signal. Coming down...")
    running = False


def is_alert(notice, score):
    generate_alert = notice.get('generate_alert', True)
    if not generate_alert:
        return False

    if score < threshold_value['critical']:
        return False

    return True


def is_whitelisted(notice):  # df node def
    reason, hit = get_whitelist_verdict(whitelist, notice)
    hit = {x: dotdump(safe_str(y)) for x, y in hit.iteritems()}

    sha256 = notice.get('sha256')

    if not reason:
        with whitelisted_lock:
            reason = whitelisted.get(sha256, None)
            if reason:
                hit = 'cached'

    if reason:
        if hit != 'cached':
            with whitelisted_lock:
                whitelisted[sha256] = reason

        notice.set(
            'failure',
            "Whitelisting due to reason %s (%s)" % (dotdump(safe_str(reason)), hit)
        )
        dropq.push(notice.raw)  # df push push

        ingester_counts.increment('ingest.whitelisted')
        whitelister_counts.increment('whitelist.' + reason)

    return reason


@exit_and_log
def maintain_inflight():  # df node def
    while running:
        # If we are scanning less than the max_waiting, submit more.
        length = scanning.length() + submissionq.length()
        if length < 0:
            time.sleep(1)
            continue

        num = max_waiting - length
        if num <= 0:
            time.sleep(1)
            continue

        entries = uniqueq.pop(num)  # df pull pop
        if not entries:
            time.sleep(1)
            continue

        for raw in entries:
            # Remove the key event_timestamp if it exists.
            raw.pop('event_timestamp', None)

            submissionq.push(raw)  # df push push


###############################################################################
#
# To calculate the probability of dropping an incoming submission we compare
# the number returned by random() which will be in the range [0,1) and the
# number returned by tanh() which will be in the range (-1,1).
#
# If length is less than maximum the number returned by tanh will be negative
# and so drop will always return False since the value returned by random()
# cannot be less than 0.
#
# If length is greater than maximum, drop will return False with a probability
# that increases as the distance between maximum and length increases:
#
#     Length           Chance of Dropping
#
#     <= maximum       0
#     1.5 * maximum    0.76
#     2 * maximum      0.96
#     3 * maximum      0.999
#
###############################################################################
def must_drop(length, maximum):
    return random() < drop_chance(length, maximum)


@exit_and_log
def process_retries():  # df node def
    while running:
        raw = retryq.pop(timeout=1)  # df pull pop
        if not raw:
            continue

        retry_at = raw['retry_at']
        delay = retry_at - now()

        if delay >= 0.125:
            retryq.unpop(raw)
            time.sleep(min(delay, 1))
            continue

        ingestq.push(raw)  # df push push


# noinspection PyBroadException
@exit_and_log
def process_timeouts():  # df node def
    global timeouts  # pylint:disable=W0603

    with timeouts_lock:
        current_time = now()
        index = 0

        for t in timeouts:
            if t.time >= current_time:
                break

            index += 1

            try:
                timed_out(t.scan_key)  # df push calls
            except:  # pylint: disable=W0702
                logger.exception("Problem timing out %s:", t.scan_key)

        timeouts = timeouts[index:]


def reinsert(datastore, msg, notice, out, retry_all=True):
    sha256 = notice.get('sha256')
    if not sha256:
        logger.error("Invalid sha256: %s", notice.raw)

    if forge.determine_ingest_queue(sha256) != ingestq_name:
        return

    pprevious, previous, score = None, False, None
    if not notice.get('ignore_cache', False):
        pprevious, previous, score, _ = check(datastore, notice)

    if previous:
        out.info("Init: Found%s: %s", msg, notice.get('sha256'))
        finalize(pprevious, previous, score, notice)
    elif retry_all or not score:
        logger.info("Init: Retrying%s: %s", msg, notice.get('sha256'))
        ingestq.push(notice.raw)
    else:
        logger.info("Init: Stale%s: %s", msg, notice.get('sha256'))


def retry(raw, scan_key, sha256, ex):  # df node def
    current_time = now()

    notice = Notice(raw)
    retries = notice.get('retries', 0) + 1

    if retries > max_retries:
        trace = ''
        if ex and type(ex) != FileStoreException:
            trace = ': ' + get_stacktrace_info(ex)
        logger.error('Max retries exceeded for %s%s', sha256, trace)
        dupq.delete(dup_prefix + scan_key)
    elif expired(current_time - seconds(notice.get('ts', current_time)), 0):
        logger.info('No point retrying expired submission for %s', sha256)
        dupq.delete(dup_prefix + scan_key)  # df pull delete
    else:
        logger.info('Requeuing %s (%s)', sha256, ex or 'unknown')
        notice.set('retries', retries)
        notice.set('retry_at', now(retry_delay))

        retryq.push(notice.raw)  # df push push


def return_exception(func, *args, **kwargs):
    try:
        func(*args, **kwargs)
        return None
    except Exception as ex:  # pylint: disable=W0703
        return ex


# noinspection PyBroadException
def seconds(t, default=0):
    try:
        try:
            return float(t)
        except ValueError:
            return iso_to_epoch(t)
    except:  # pylint:disable=W0702
        return default


def send_heartbeat():
    t = now()

    up_hours = (t - start_time) / (60.0 * 60.0)

    queues = {}
    drop_p = {}

    for level in ('low', 'medium', 'critical', 'high'):
        queues[level] = uniqueq.count(*priority_range[level])
        threshold = sample_threshold[level]
        drop_p[level] = 1 - max(0, drop_chance(queues[level], threshold))

    heartbeat = {
        'hostinfo': hostinfo,
        'inflight': scanning.length(),
        'ingest': ingestq.length(),
        'ingesting': drop_p, 
        'queues': queues,
        'shard': shard,
        'up_hours': up_hours,
        'waiting': submissionq.length(),

        'ingest.bytes_completed': 0,
        'ingest.bytes_ingested': 0,
        'ingest.duplicates': 0,
        'ingest.files_completed': 0,
        'ingest.skipped': 0,
        'ingest.submissions_completed': 0,
        'ingest.submissions_ingested': 0,
        'ingest.timed_out': 0,
        'ingest.whitelisted': 0,
    }

    # Send ingester stats.
    exported = ingester_counts.export()

    # Add ingester stats to our heartbeat.
    heartbeat.update(exported)

    # Send our heartbeat.
    raw = message.Message(to="*", sender='middleman',
                          mtype=message.MT_INGESTHEARTBEAT,
                          body=heartbeat).as_dict()
    statusq.publish(raw)

    # Send whitelister stats.
    whitelister_counts.export()


@exit_and_log
def send_heartbeats():
    while running:
        send_heartbeat()
        time.sleep(1)


def send_notification(notice, failure=None, logfunc=logger.info):
    if failure:
        notice.set('failure', failure)

    failure = notice.get('failure', None)
    if failure:
        logfunc("%s: %s", failure, str(notice.raw))

    queue_name = notice.get('notification_queue', False)
    if not queue_name:
        return

    score = notice.get('al_score', 0)
    threshold = notice.get('notification_threshold', None)
    if threshold and score < int(threshold):
        return

    q = notificationq.get(queue_name, None)
    if not q:
        notificationq[queue_name] = q = \
            queue.NamedQueue(queue_name, **persistent)
    q.push(notice.raw)


@exit_and_log
def send_traffic():
    real_trafficq = queue.CommsQueue('traffic')

    while running:
        msg = trafficq.pop(timeout=1)
        if not msg:
            continue

        real_trafficq.publish(msg)


def should_resubmit(score):

    # Resubmit:
    #
    # 100%     with a score above 400.
    # 10%      with a score of 301 to 400.
    # 1%       with a score of 201 to 300.
    # 0.1%     with a score of 101 to 200.
    # 0.01%    with a score of 1 to 100.
    # 0.001%   with a score of 0.
    # 0%       with a score below 0.

    if score < 0:
        return False

    if score > 400:
        return True

    resubmit_probability = 1.0 / 10 ** ((500 - score) / 100)
    
    return random() < resubmit_probability


def stale(delta, errors):
    if errors:
        return delta >= incomplete_stale_after_seconds
    else:
        return delta >= stale_after_seconds


def submit(client, notice):
    priority = notice.get('priority')
    sha256 = notice.get('sha256')

    hdr = notice.parse(
        description=': '.join((default_prefix, sha256 or '')), **defaults
    )

    user = hdr.pop('submitter')
    hdr.pop('priority', None)

    path = notice.get('filename', None) or sha256
    client.submit(sha256, path, priority, user, **hdr)
    with timeouts_lock:
        timeouts.append(Timeout(now(max_time), notice.get('scan_key')))


# noinspection PyBroadException
@exit_and_log
def submitter():  # df node def
    client = forge.get_submission_service()
    datastore = forge.get_datastore()

    while running:
        try:
            raw = submissionq.pop(timeout=1)  # df pull pop
            if not raw:
                continue

            # noinspection PyBroadException
            try:
                sha256 = raw['sha256']
            except Exception:  # pylint: disable=W0703
                logger.exception("Malformed entry on submission queue:")
                continue

            if not sha256:
                logger.error("Malformed entry on submission queue: %s", raw)
                continue

            notice = Notice(raw)
            if drop(notice):  # df push calls
                continue

            if is_whitelisted(notice):  # df push calls
                continue

            pprevious, previous, score = None, False, None
            if not notice.get('ignore_cache', False):
                pprevious, previous, score, scan_key = check(datastore, notice)

            if previous:
                if not notice.get('resubmit_to', []) and not pprevious:
                    logger.warning("No psid for what looks like a resubmission of %s: %s", sha256, scan_key)
                finalize(pprevious, previous, score, notice)  # df push calls
                continue

            with ScanLock(scan_key):
                if scanning.exists(scan_key):
                    logger.debug('Duplicate %s', sha256)
                    ingester_counts.increment('ingest.duplicates')
                    dupq.push(dup_prefix + scan_key, notice.raw)  # df push push
                    continue

                scanning.add(scan_key, notice.raw)  # df push add

            ex = return_exception(submit, client, notice)
            if not ex:
                continue

            ingester_counts.increment('ingest.error')

            should_retry = True
            tex = type(ex)
            if tex == FileStoreException:
                ex = tex("Problem with file: %s" % sha256)
            elif tex == CorruptedFileStoreException:
                logger.error("Submission failed due to corrupted filestore: %s" % ex.message)
                should_retry = False
            else:
                trace = get_stacktrace_info(ex)
                logger.error("Submission failed: %s", trace)

            raw = scanning.pop(scan_key)
            if not raw:
                logger.error('No scanning entry for for %s', sha256)
                continue

            if not should_retry:
                continue

            retry(raw, scan_key, sha256, ex)

            if tex == riak.RiakError:
                raise ex  # pylint: disable=E0702

        except Exception:  # pylint:disable=W0703
            logger.exception("Unexpected error") 


# Invoked when a timeout fires. (Timeouts always fire).
def timed_out(scan_key):  # df node def
    actual_timeout = False

    with ScanLock(scan_key):
        # Remove the entry from the hash of submissions in progress.
        entry = scanning.pop(scan_key)  # df pull pop
        if entry:
            actual_timeout = True
            logger.error("Submission timed out for %s: %s", scan_key, str(entry))

        dup = dupq.pop(dup_prefix + scan_key, blocking=False)  # df pull pop
        if dup:
            actual_timeout = True

        while dup:
            logger.error("Submission timed out for %s: %s", scan_key, str(dup))
            dup = dupq.pop(dup_prefix + scan_key, blocking=False)

    if actual_timeout:
        ingester_counts.increment('ingest.timed_out')

ingester_counts = counter.AutoExportingCounters(
    name='ingester',
    host=net.get_hostip(),
    auto_flush=True,
    auto_log=False,
    export_interval_secs=config.system.update_interval,
    channel=forge.get_metrics_sink())

whitelister_counts = counter.AutoExportingCounters(
    name='whitelister',
    host=net.get_hostip(),
    auto_flush=True,
    auto_log=False,
    export_interval_secs=config.system.update_interval,
    channel=forge.get_metrics_sink())

init()

Thread(target=maintain_inflight, name="maintain_inflight").start()
Thread(target=process_retries, name="process_retries").start()
Thread(target=send_heartbeats, name="send_heartbeats").start()
Thread(target=send_traffic, name="send_traffic").start()

# pylint: disable=C0321
for i in range(dropper_threads):
    Thread(target=dropper, name="dropper_%s" % i).start()  # df line thread
# noinspection PyRedeclaration
for i in range(ingester_threads):
    Thread(target=ingester, name="ingester_%s" % i).start()  # df line thread
# noinspection PyRedeclaration
for i in range(submitter_threads):
    Thread(target=submitter, name="submitter_%s" % i).start()  # df line thread

while running:
    process_timeouts()
    time.sleep(60)

# df text }
