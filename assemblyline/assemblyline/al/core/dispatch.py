#!/usr/bin/env python

import logging
import os
import psutil
import riak
import signal
import socket
import threading
import time

from collections import namedtuple
from copy import deepcopy
from pprint import pformat
from assemblyline.common import net

from assemblyline.common.exceptions import get_stacktrace_info
from assemblyline.common.isotime import now_as_iso
from assemblyline.common.net import get_hostip, get_hostname, get_mac_address
from assemblyline.al.common import forge
from assemblyline.al.common import counter
from assemblyline.al.common import message
from assemblyline.al.common.queue import CommsQueue, DispatchQueue, LocalQueue, NamedQueue, reply_queue_name
from assemblyline.al.common.remote_datatypes import ExpiringSet, Hash, ExpiringHash
from assemblyline.al.common.task import Task
from assemblyline.al.core.datastore import compress_riak_key
config = forge.get_config()

persistent = {
    'db': config.core.redis.persistent.db,
    'host': config.core.redis.persistent.host,
    'port': config.core.redis.persistent.port,
}

Classification = forge.get_classification()
DONE = len(config.services.stages) + 1

counts = None # Created when dispatcher starts.
log = logging.getLogger('assemblyline.dispatch')

class DispatchException(Exception):
    pass

Entry = namedtuple('Entry', ['dispatcher', 'task', 'retries', 'parents',
     'completed_children', 'extracted_children', 'outstanding_children',
     'acknowledged_services', 'completed_services', 'dispatched_services',
     'outstanding_services'])
Timeout = namedtuple('Timeout', ['sid', 'srl', 'data', 'time'])

def eligible_parent(service_manager, task):
    if not isinstance(task.eligible_parents, list) or not task.service_name:
        return True

    eligible_parents = service_manager.expand_categories(task.eligible_parents)
    if task.service_name in eligible_parents:
        return True

    return False

def CreateEntry(dispatcher, task, now):
    parent = None
    psrl = task.psrl
    sid = task.sid
    srl = task.srl

    if not psrl:
        if task.quota_item and task.submitter:
            log.info(
                "Submission %s counts toward quota for %s",
                sid, task.submitter
            )
            Hash('submissions-' + task.submitter, **persistent).add(
                sid, now_as_iso()
            )
    else:
        # This task has a parent. 
        try:
            parent = dispatcher.entries[sid][psrl]
            parent_task = parent.task

            # Child inherits parent's selected (and skipped) services
            # + any specifically added by the child.
            task.selected = (task.selected or []) + \
                (parent_task.selected or []) + (parent_task.skipped or [])

            if eligible_parent(dispatcher.service_manager, task):
                # Child inherits parent's excluded services 
                # + any specifically excluded by the child.
                task.excluded = (task.excluded or []) + \
                    (parent_task.excluded or [])
            else:
                task.excluded = task.selected
        except KeyError:
            # Couldn't find parent. It might have been filtered out.
            dispatcher.debug("Couldn't find parent (%s) of %s/%s",
                             psrl, sid, srl)
            return None

    # Create acked, completed, dispatched and outstanding service structures.
    a, c, d, o = dispatcher.service_manager.determine_services(task, now)

    # Make sure the initial score is set to 0.
    task.score = 0
    task.max_score = 0

    # Tuples are immutable so we have to store the entry's stage on the task.
    task.stage = 0
    entry = Entry(dispatcher, task, {}, [], {}, {}, {}, a, c, d, o)
    if parent:
        # Set up parent/child links.
        entry.parents.append(parent)
        if not srl in parent.outstanding_children and \
            not srl in parent.completed_children:
            parent.outstanding_children[srl] = entry

    return entry

def RemoveEntry(dispatcher, entry, sid, srl, now):
    # The only way for a task to be complete is for all its children
    # to be complete. This means we can remove a completed task because
    # there are, by definition, no outstanding children.
    entries = dispatcher.entries
    files = entries.get(sid, {})

    if files.pop(srl, None):
        dispatcher.completed[sid][srl] = entry.task.classification

    parents = entry.parents

    if parents:
        dispatcher.debug("Child completed: %s/%s", sid, srl)

        # Move to completed_children on parent(s) and update parent(s).
        for p in parents:
            o = p.outstanding_children.pop(srl, None)
            if o:
                p.completed_children[srl] = o
            UpdateEntry(p, now)
    else:
        dispatcher.debug("Parent completed: %s/%s", sid, srl)

        task = entry.task

        sid = task.sid

        dispatcher.storage_queue.push({
            'type': 'complete',
            'expiry': task.__expiry_ts__,
            'filescore_key': task.scan_key,
            'now': now,
            'psid': task.psid,
            'score': int(dispatcher.score.get(sid, None) or 0),
            'sid': sid,
        })

        # If there are outstanding srls, return.
        if len(files):
            return

        if task.quota_item and task.submitter:
            log.info(
                "Submission %s no longer counts toward quota for %s",
                sid, task.submitter
            )
            Hash('submissions-' + task.submitter, **persistent).pop(sid)

        # If there are no outstanding srls, remove this sid as well.
        entries.pop(sid)

        # Update the scan object.
        c12ns = dispatcher.completed.pop(sid).values()
        classification = Classification.UNRESTRICTED
        for c12n in c12ns:
            classification = Classification.max_classification(
                classification, c12n
            )

        results = dispatcher.results.pop(sid, [])
        errors = dispatcher.errors.pop(sid, [])

        raw = None
        if task.completed_queue:
            raw = deepcopy(task.raw)
            raw.update({
                'errors': errors,
                'results': results,
                'error_count': len(set([x[:64] for x in errors])),
                'file_count': len(set([x[:64] for x in errors + results])),
            })

        dispatcher.storage_queue.push({
            'type': 'finalize',
            'classification': classification,
            'completed_queue': task.completed_queue,
            'errors': errors,
            'results': results,
            'score': int(dispatcher.score.pop(sid, None) or 0),
            'sid': sid,
            'watchers': dispatcher.watchers.pop(sid, {}),
            'raw': raw,
        })

    return


def UpdateEntry(entry, now):
    dispatcher = entry.dispatcher
    task = entry.task
    sid = task.sid
    srl = task.srl
    stage = task.stage
    acknowledged_services = entry.acknowledged_services
    dispatched_services = entry.dispatched_services
    outstanding_services = entry.outstanding_services

    # Move to the next stage if task's current stage is complete.
    while not stage or stage != DONE \
        and not acknowledged_services[stage] \
        and not dispatched_services[stage] \
        and not outstanding_services[stage]:
        stage += 1
    task.stage = stage

    # Check if any and all children are complete for this task.
    if stage == DONE:
        counts.increment('dispatch.files_completed')

        ExpiringSet(task.get_tag_set_name()).delete()
        ExpiringHash(task.get_submission_tags_name()).delete()

        if entry.outstanding_children or entry.extracted_children:
            return False

        # TODO: Insert sanity checks.

        # This file is done.
        if dispatcher.score[sid] is None or task.score > dispatcher.score[sid]:
            dispatcher.score[sid] = task.score
        else:
            task.score = dispatcher.score[sid]

#        raw = None
#        if task.completed_queue and not task.psrl:
#            results = dispatcher.results.get(sid, [])
#            errors = dispatcher.errors.get(sid, [])
#            raw = task.raw
#            raw.update({
#                'errors': errors,
#                'results': results,
#                'error_count': len(set([x[:64] for x in errors])),
#                'file_count': len(set([x[:64] for x in errors + results])),
#            })
#            NamedQueue(task.completed_queue).push(raw)

        RemoveEntry(dispatcher, entry, sid, srl, now)

        return True

    # This task is not done if there are dispatched services.
    if dispatched_services[stage]:
        return False

    # Dispatch.
    dispatched_services[stage] = to_dispatch = outstanding_services[stage] 
    entry.outstanding_services[stage] = {}
    entry.dispatcher.debug("%s is now stage %d", task.srl, stage)
    for service in to_dispatch.itervalues():
        entry.dispatcher.debug("Dispatching %s to: %s", task.srl, service.name)
        entry.dispatcher.dispatch(service, entry, now)

    return False

q = DispatchQueue()

class Dispatcher(object):
    # Instead of having a dynamic dict, __slots__ defines a static structure.
    # Access to member variables defined in this way is more efficient (but
    # as a side effect we lose the ability to add members dynamically).
    __slots__ = ('ack_timeout', 'child_timeout', 'completed', 'control_queue',
                 'debug', 'drain', 'entries', 'errors', 'high', 'ingest_queue',
                 'last_check', 'lock', 'pop', 'queue_size', 'response_queue',
                 'results', 'running', 'score', 'service_manager',
                 'service_timeout', 'shard', 'storage_queue',
                 'watchers', 'hostinfo')
    def __init__(self, service_manager, #pylint: disable=R0913
                 control_queue=None, debug=False,
                 high=config.core.dispatcher.max.inflight/config.core.dispatcher.shards,
                 pop=forge.get_dispatch_queue().pop,
                 shard='0'):
        if debug:
            self.debug = log.info
        else:
            self.debug = lambda *msg: None

        self.hostinfo = { 
            'ip:': get_hostip(), 
            'mac_address': get_mac_address(), 
            'host': get_hostname(),
        }

        self.ack_timeout = {}
        self.child_timeout = {}
        self.completed = {}
        self.control_queue = control_queue or \
            forge.get_control_queue('control-queue-' + shard)
        self.drain = False
        self.entries = {}
        self.errors = {}
        self.high = high
        self.ingest_queue = 'ingest-queue-' + shard
        self.last_check = 0
        self.lock = threading.Lock()
        self.pop = pop
        self.queue_size = {}
        # Reponse queues are named: <hostname>-<pid>-<seconds>-<shard>.
        self.response_queue = '-'.join((socket.gethostname(), str(os.getpid()),
                                        str(int(time.time())), shard))
        self.results = {}
        self.running = False
        self.score = {}
        self.service_manager = service_manager
        self.service_timeout = {}
        self.shard = shard
        self.storage_queue = LocalQueue()
        self.watchers = {}

        log.info('Dispatcher started. Dispatching to services:{0}'.format(
            [s for s in service_manager.services]))

    def _service_info(self):
        list_result = {}
        now = time.time()
        for service in self.service_manager.services.itervalues():
            is_up = not self._service_is_down(service, now)
            list_result[service.name] = {
                'is_up': is_up,
                'accepts': service.accepts,
                'details': service.metadata
            }
        return list_result

    def _service_is_down(self, service, now):
        last = service.metadata['last_heartbeat_at']
        return now - last > config.system.update_interval * 6

    def acknowledged(self, task, now=None):
        if not now:
            now = time.time()
        entries = self.entries
        sender = task.service_name
        sid = task.sid
        srl = task.srl

        # Make sure the entry exists.
        submission = entries.get(sid, None)
        if not submission:
            return

        entry = submission.get(srl, None)
        if not entry:
            return

        # Mark this service as acknowledged.
        stage = self.service_manager.stage_by_name(sender)
        service_entry = entry.dispatched_services[stage].pop(sender, None)
        if not service_entry:
            return

        entry.acknowledged_services[stage][sender] = service_entry

        seconds = task.seconds

        # Add the timeout to the end of its respective list.
        service_timeout = self.service_timeout
        lst = service_timeout.get(seconds, [])
        lst.append(Timeout(sid, srl, sender, now + float(seconds)))
        service_timeout[seconds] = lst

    def check_timeouts(self, now=None):
        if not now:
            now = time.time()
        # Make sure the right amount of time has elapsed since our last check.
        if now - self.last_check < config.system.update_interval:
            return

        self.last_check = now
        with self.lock:
            try:
                self.process_timeouts('acknowledged_services', now,
                                      'Ack timeout', self.ack_timeout)
                self.process_timeouts('completed_services', now,
                                      'Service timeout',
                                      self.service_timeout)
                timeouts = self.child_timeout
                for k, v in timeouts.iteritems():
                    start = 0
                    timeouts[k] = []
                    for t in v:
                        # Timeouts are added to the end of their list so
                        # when we reach the first non-timed out timeout,
                        # we are done.
                        if t.time >= now:
                            break

                        # Timeouts remain active (so that we don't have
                        # to scan for them when removing tasks that have
                        # completed. So it is possible for a timeout to
                        # refer to an id that no longer exists.
                        submission = self.entries.get(t.sid, None)
                        if submission:
                            entry = submission.get(t.srl, None)
                            if entry:
                                if entry.extracted_children.pop(t.data, None):
                                    log.info('Child %s of parent %s timed out',
                                             t.data, t.srl)
                                UpdateEntry(entry, now)

                        start += 1

                    # Remove processed timeouts.
                    timeouts[k] = v[start:] + timeouts[k]
            except Exception as ex: #pylint: disable=W0703
                trace = get_stacktrace_info(ex)
                log.error('Problem processing timeouts: %s', trace)

    def dispatch(self, service, entry, now):
        task = entry.task
        sid = task.sid
        srl = task.srl
        name = service.name

        queue_size = self.queue_size[name] = self.queue_size.get(name, 0) + 1
        entry.retries[name] = entry.retries.get(name, -1) + 1

        if task.profile:
            if entry.retries[name]:
                log.info('%s Graph: "%s" -> "%s/%s" [label=%d];',
                         sid, srl, srl, name, entry.retries[name])
            else:
                log.info('%s Graph: "%s" -> "%s/%s";',
                         sid, srl, srl, name)
                log.info('%s Graph: "%s/%s" [label=%s];',
                         sid, srl, name, name)

        file_count = len(self.entries[sid]) + len(self.completed[sid])

        # Warning: Please do not change the text of the error messages below.
        msg = None
        if self._service_is_down(service, now):
            msg = 'Service down.'
        elif entry.retries[name] > config.core.dispatcher.max.retries:
            msg = 'Max retries exceeded.'
        elif entry.retries[name] >= 1:
            log.debug("Retry sending %s/%s to %s", sid, srl, name)
        elif task.depth > config.core.dispatcher.max.depth:
            msg = 'Max depth exceeded.'
        elif file_count > config.core.dispatcher.max.files:
            msg = 'Max files exceeded.'

        if msg:
            log.debug(' '.join((msg, "Not sending %s/%s to %s." % \
                         (sid, srl, name))))
            response = Task(deepcopy(task.raw))
            response.watermark(name, '')
            response.nonrecoverable_failure(msg)
            self.storage_queue.push({
                'type': 'error',
                'name': name,
                'response': response,
            })
            return False

        if service.skip(task):
            response = Task(deepcopy(task.raw))
            response.watermark(name, '')
            response.success()
            q.send_raw(response.as_dispatcher_response())
            return False

        # Setup an ack timeout.
        seconds = min(service.timeout * (queue_size + 5), 7200)

        task.ack_timeout = seconds
        task.sent = now

        service.proxy.execute(task.priority, task.as_service_request(name))

        # Add the timeout to the end of its respective list.
        ack_timeout = self.ack_timeout
        lst = ack_timeout.get(seconds, [])
        lst.append(Timeout(sid, srl, name, now + seconds))
        ack_timeout[seconds] = lst

        return True

    def heartbeat(self):
        while not self.drain:
            with self.lock:
                heartbeat = {
                    'shard': self.shard,
                    'entries': len(self.entries),
                    'errors': len(self.errors),
                    'results': len(self.results),
                    'resources': {
                        "cpu_usage.percent": psutil.cpu_percent(),
                        "mem_usage.percent": psutil.phymem_usage().percent,
                        "disk_usage.percent": psutil.disk_usage('/').percent,
                        "disk_usage.free": psutil.disk_usage('/').free,
                    },
                    'services': self._service_info(),
                    'queues': {
                        'max_inflight': self.high,
                        'control': self.control_queue.length(),
                        'ingest': q.length(self.ingest_queue),
                        'response': q.length(self.response_queue),
                    },
                }

                heartbeat['hostinfo'] = self.hostinfo
                msg = message.Message(to="*", sender='dispatcher', 
                    mtype=message.MT_DISPHEARTBEAT, body=heartbeat) 
                CommsQueue('status').publish(msg.as_dict())

            time.sleep(1)

    def interrupt(self, unused1, unused2): #pylint: disable=W0613
        if self.drain:
            log.info('Forced shutdown.')
            self.running = False
            return

        log.info('Shutting down gracefully...')
        # Rename control queue to 'control-<hostname>-<pid>-<seconds>-<shard>'.
        self.control_queue = \
            forge.get_control_queue('control-' + self.response_queue)
        self.drain = True

    def poll(self, n):
        """Poll for n responses/resubmissions and (max - n) submissions"""
        # Process control messages.
        msg = self.control_queue.pop(blocking=False)
        while msg:
            with self.lock:
                self.process(msg)
            msg = self.control_queue.pop(blocking=False)
        # Grab n responses/resubmissions from our queue.
        submissions = self.pop(self.response_queue, self.high)
        # Grab (max - n) new submissions from our ingest queue.
        n = self.high - n
        if not self.drain and n > 0:
            submissions += self.pop(self.ingest_queue, n)
        # Process the responses/resubmissions and submissions.
        # ... "for decisions and revisions which a minute will reverse" ;-)
        n = len(submissions)
        for submission in submissions:
            with self.lock:
                self.process(submission)
        return n

    def process(self, msg):
        func = None
        task = Task.wrap(msg)

        if not msg:
            log.warning("Got 'None' msg")
            return

        try:
            func = self.__getattribute__(task.state)
        except AttributeError:
            log.warning('Unknown message type: %s', task.state)

        try:
            func(task)
        except Exception as ex: #pylint: disable=W0703
            trace = get_stacktrace_info(ex)
            log.error('Problem processing %s: %s', pformat(task.raw), trace)

    def process_timeouts(self, name, now, msg, timeouts):
        services = self.service_manager.services

        # Timeouts are stored in lists according to the timeout seconds.
        for k, v in timeouts.items():
            start = 0
            timeouts[k] = []
            for t in v:
                # Timeouts are added to the end of their list so when we
                # reach the first non-timed out timeout, we are done.
                if t.time >= now:
                    break

                # Timeouts remain active (so that we don't have to scan
                # for them when removing tasks that have completed. So it
                # is possible for a timeout to refer to an id that no
                # longer exists.
                if self.redispatch(name, t.sid, t.srl,
                                   services[t.data], msg, now):
                    timeouts[k].append(Timeout(t.sid, t.srl, t.data, now + k))

                start += 1

            # Remove processed timeouts.
            timeouts[k] = v[start:] + timeouts[k]

    def redispatch(self, name, sid, srl, service, reason, now):
        entry = None
        try:
            entry = self.entries[sid][srl]
        except KeyError:
            return False

        try:
            stage = self.service_manager.stage_by_name(service.name)
            d = getattr(entry, name)[stage]
            c = entry.completed_services[stage]
            if service.name in c or d and service.name in d:
                return False
            log.info("%s for %s: %s/%s", reason, service.name, sid, srl)
            self.dispatch(service, entry, now)
            return True
        except Exception as ex: #pylint: disable=W0703
            trace = get_stacktrace_info(ex)
            log.error("Couldn't redispatch to %s for %s/%s: %s",
                      service.name, sid, srl, trace)
            response = Task(deepcopy(entry.task.raw))
            response.watermark(service.name, '')
            response.nonrecoverable_failure(trace)
            self.storage_queue.push({
                'type': 'error',
                'name': service.name,
                'response': response,
            })
            return False

    def serviced(self, task, now=None):
        if not now:
            now = time.time()
        entries = self.entries
        sender = task.service_name
        sid = task.sid
        srl = task.srl
        services = self.service_manager.services
        stage = self.service_manager.stage_by_name(sender)
        status = task.status or ''

        # Make sure the entry exists.
        submission = entries.get(sid, None)
        if not submission:
            log.debug("Couldn't find sid for: %s", task.raw)
            return

        entry = submission.get(srl, None)
        if not entry:
            log.debug("Couldn't find srl for: %s", task.raw)
            return

        # Move this service from dispatched to completed.
        asvc = entry.acknowledged_services[stage].get(sender, None)
        dsvc = entry.dispatched_services[stage].get(sender, None)
        svc = asvc or dsvc
        if not svc:
            log.debug("Service already completed for: %s", task.raw)
            return

        queue_size = self.queue_size.get(sender, 0)
        if queue_size:
            self.queue_size[sender] = queue_size - 1

        if task.profile:
            log.info('%s Graph: "%s/%s" -> "%s/%s/%s";',
                     sid, srl, sender, srl, sender, status)
            log.info('%s Graph: "%s/%s/%s" [label="%s"];',
                     sid, srl, sender, status, status)

        if task.dispatch_queue != self.response_queue:
            raise Exception("Queue is %s. Should be %s." % \
                            (task.dispatch_queue, self.response_queue))

        # Send the cache_key to any watchers ...
        cache_key = task.cache_key
        if cache_key:
            msg = {'status': status[:4], 'cache_key': cache_key}
            for w in self.watchers.get(sid, {}).itervalues():
                w.push(msg)
        # ... and append it to this submission's list of cache_keys.
        if status[:4] == 'FAIL':
            log.debug("Service %s failed (%s): %s",
                      sender, status, task.message)
            if status == 'FAIL_RECOVERABLE':
                if self.redispatch('completed_services', sid, srl,
                                   services[sender],
                                   'Recoverable failure', now):
                    return
            if cache_key:
                self.errors[sid].append(cache_key)
                # We don't send error keys to services. If we want to:
                #compressed = compress_riak_key(cache_key, srl)
                #entry.task.errors = (entry.task.errors or []) + [compressed]
        else:
            score = int(task.score or 0)
            entry.task.score += score
            if not entry.task.max_score or score > entry.task.max_score:
                entry.task.max_score = score
            self.debug("%s (%d) completed %s", sender, score, srl)
            if cache_key:
                self.results[sid].append(cache_key)
                compressed = compress_riak_key(cache_key, srl)
                entry.task.results = (entry.task.results or []) + [compressed]

        entry.completed_services[stage][sender] = svc
        self.service_manager.update_last_result_at(sender, now)

        entry.acknowledged_services[stage].pop(sender, None)
        entry.dispatched_services[stage].pop(sender, None)

        # If the service said to drop this entry clear all services.
        if not task.ignore_filtering and task.filter == 'drop':
            self.debug("%s (%s) said to DROP %s", sender, stage, srl)
            entry.task.filter = 'drop'
            for i, s in enumerate(entry.dispatched_services):
                if i > stage and s:
                    s.clear()
            for i, s in enumerate(entry.outstanding_services):
                if i > stage and s:
                    s.clear()

        if status[:4] != 'FAIL':
            # Record any children we should be seeing if we haven't.
            for child in task.extracted or []:
                if child[1] and \
                    not child[1] in entry.outstanding_children and \
                    not child[1] in entry.completed_children and \
                    not child[1] in self.completed[sid] and \
                    not child[1] in entries[sid]:
                    entry.extracted_children[child[1]] = True

                    # Setup a child timeout.
                    seconds = config.core.dispatcher.timeouts.child

                    # Add the timeout to the end of its respective list.
                    child_timeout = self.child_timeout
                    lst = child_timeout.get(seconds, [])
                    lst.append(Timeout(sid, srl, child[1], now + seconds))
                    child_timeout[seconds] = lst

        UpdateEntry(entry, now)

    def start(self):
        global counts # pylint: disable=W0603

        # Publish counters to the metrics sink.
        counts = counter.AutoExportingCounters(
            name='dispatcher-%s' % self.shard,
            host=net.get_hostip(),
            auto_flush=True,
            auto_log=False,
            export_interval_secs=config.system.update_interval,
            channel=forge.get_metrics_sink(),
            counter_type='dispatcher')
        counts.start()

        self.service_manager.start()

        # This starts a thread that polls for messages with an exponential
        # backoff, if no messages are found, to a maximum of one second.
        minimum = -6
        maximum = 0
        self.running = True

        threading.Thread(target=self.heartbeat).start()
        for _ in range(8):
            threading.Thread(target=self.writer).start()

        signal.signal(signal.SIGINT, self.interrupt)

        time.sleep(2 * int(config.system.update_interval))

        exp = minimum
        while self.running:
            if self.poll(len(self.entries)):
                exp = minimum
                continue
            if self.drain and not self.entries:
                break
            time.sleep(2**exp)
            exp = exp + 1 if exp < maximum else exp
            self.check_timeouts()

        counts.stop()

    def submitted(self, task, now=None):
        if not now:
            now = time.time()
        entries = self.entries
        psrl = task.psrl
        sid = task.sid
        srl = task.srl

        if task.is_initial():
            self.debug("Parent submitted: %s/%s", sid, srl)
            task.depth = 0
            # Stamp the task with the current time.
            task.received = now
        else:
            if task.dispatch_queue != self.response_queue:
                raise Exception("Queue is %s. Should be %s." % \
                                (task.dispatch_queue, self.response_queue))
            try:
                # If we learned about the child in the parent's response,
                # remove it from the list of extracted children (it will
                # now be in outstanding).
                entries[sid][psrl].extracted_children.pop(srl, None)
            except: #pylint: disable=W0702
                pass

            self.debug("Child of %s/%s submitted: %s", sid, psrl, srl)
            task.depth += 1
            if task.profile:
                log.info('%s Graph: "%s/%s" -> "%s";',
                         sid, psrl, task.submitter, srl)

        # Stamp this dispatcher's queue on the task to make sure
        # responses and resubmissions will come to this dispatcher.
        task.dispatch_queue = self.response_queue

        # If this is the initial (root) submission save the scan object.
        if not sid in entries:
            if psrl:
                # This is a child but we don't know about the parent.
                log.debug("Parent (%s) does not exist for sid/srl: %s/%s",
                          psrl, sid, srl)
                return

            entries[sid] = {}
            self.completed[sid] = {}
            self.errors[sid] = []
            self.results[sid] = []
            self.score[sid] = None
        submission = entries[sid]

        if srl in submission or srl in self.completed.get(sid, {}):
            return

        entry = CreateEntry(self, task, now)
        if entry is None:
            return

        if task.profile:
            log.info('%s Graph: "%s" [label="%s"]', sid, srl,
                     ''.join((srl[:4], '...', srl[-4:])))

        submission[srl] = entry
        UpdateEntry(entry, now)

        # It is possible to combine a submit and watch message.
        if task.watch_queue:
            self.watch(task)

    def watch(self, task):
        queue = task.watch_queue
        sid = task.sid

        # Make sure this submission exists.
        watchers = self.watchers.get(sid, {})

        # Bail if we have a watcher with the same name for this sid.
        if queue in watchers:
            return

        ttl = 0
        try:
            ttl = config.core.dispatcher.timeouts.watch_queue
        except: # pylint: disable=W0702
            pass

        w = NamedQueue(queue, ttl=ttl)

        errors = self.errors.get(sid, None)
        results = self.results.get(sid, None)
        if results is None and errors is None:
            # TODO: Should we send UNKNOWN.
            w.push({'status': 'STOP'})
            return

        watchers[queue] = w
        self.watchers[sid] = watchers

        # Send all cache keys to the newly created queue.
        # Afterward they will be sent as they are received.
        w.push({'status': 'START'})
        if results:
            w.push(*[{'status': 'OK', 'cache_key': c} for c in results])
        if errors:
            w.push(*[{'status': 'FAIL', 'cache_key': c} for c in errors])

    def writer(self):
        queue = {}
        store = forge.get_datastore()

        while self.running:
            try:
                msg = self.storage_queue.pop(timeout=1)
                if not msg:
                    if self.drain:
                        break
                    continue

                response = None

                if msg['type'] == 'complete':
                    key = msg['filescore_key']
                    if key:
                        store.save_filescore(
                            key, msg['expiry'], {
                                'psid': msg['psid'],
                                'sid': msg['sid'],
                                'score': msg['score'],
                                'time': msg['now'],
                            }
                        )

                elif msg['type'] == 'error': 
                    name, response = msg['name'], msg['response']
                    response.cache_key = \
                        store.save_error(name, None, None, response)
                    q.send_raw(response.as_dispatcher_response())

                elif msg['type'] == 'finalize':
                    store.finalize_submission(
                        msg['sid'], msg['classification'],
                        msg['errors'], msg['results'], msg['score']
                    ) 

                    completed_queue = msg['completed_queue']
                    if completed_queue:
                        cq = queue.get(completed_queue, None)
                        if not cq:
                            cq = NamedQueue(completed_queue)
                            queue[completed_queue] = cq
                        cq.push(msg['raw'])

                    # Send complete message to any watchers.
                    for w in msg['watchers'].itervalues():
                        w.push({'status': 'STOP'})

                else:
                    log.warning("Unhandled message type: %s",
                                msg.get('type', '<unknown>'))
            except riak.RiakError:
                msg['retries'] = retries = msg.get('retries', 0) + 1
                if retries > 5:
                    log.exception("Max retries exceeded")
                    continue
                self.storage_queue.push(msg)
                log.exception("Problem doing %s", msg.get('type', 'unknown'))
            except Exception: # pylint:disable=W0702
                log.exception('Problem in writer')
                # TODO: Should we sleep for a bit here to avoid flailing?

        store.close()

    def explain_state(self, task):
        log.info('Got explain_state message.')

        nq = NamedQueue(task.watch_queue)

        submission = self.entries.get(task.sid, None)
        if submission:
            has_timeout = False
            for v in self.ack_timeout.itervalues():
                for t in v:
                    if t.sid == task.sid:
                        has_timeout = True

            for v in self.service_timeout.itervalues():
                for t in v:
                    if t.sid == task.sid:
                        has_timeout = True

            if not has_timeout:
                nq.push({
                    'srl': 0,
                    'message': 'No timeouts for this submission!',
                    'depth': 0,
                })
            for entry in submission.itervalues():
                if not entry.task.psrl:
                    explain(entry, nq)
        nq.push(False)

    def get_system_time(self, task):
        nq = NamedQueue(task.watch_queue)
        nq.push({'time': time.time()})

    def list_service_info(self, task):
        NamedQueue(task.watch_queue).push(self._service_info())

    def outstanding_services(self, task):
        nq = NamedQueue(task.watch_queue)
        outstanding = {}
        submission = self.entries.get(task.sid, None)
        if submission:
            for entry in submission.itervalues():
                get_outstanding_services(entry, outstanding)
        nq.push(outstanding)

    def outstanding_submissions(self, task):
        nq = NamedQueue(task.watch_queue)
        nq.push({'sids': self.entries.keys()})

def get_outstanding_services(entry, outstanding):
    o = entry.outstanding_services
    d = entry.dispatched_services
    a = entry.acknowledged_services

    stage = entry.task.stage
    if stage == DONE:
        return

    for name in o[stage].keys() + d[stage].keys() + a[stage].keys():
        outstanding[name] = outstanding.get(name, 0) + 1

    for child in entry.outstanding_children.itervalues():
        get_outstanding_services(child, outstanding)

def explain(entry, nq, depth=0):
    outstanding_services = entry.outstanding_services
    dispatched_services = entry.dispatched_services
    acknowledged_services = entry.acknowledged_services

    stage = entry.task.stage
    if stage != DONE:
        nq.push({
            'srl': entry.task.srl,
            'message': 'Stage: ' + str(stage),
            'depth': depth,
        })
        if outstanding_services[stage]:
            nq.push({
                'srl': entry.task.srl,
                'message': 'Undispatched: ' + \
                    ','.join([x for x in outstanding_services[stage]]),
                'depth': depth,
            })
        elif dispatched_services[stage]:
            nq.push({
                'srl': entry.task.srl,
                'message': 'Awaiting acks for: ' + \
                    ','.join([x for x in dispatched_services[stage]]),
                'depth': depth,
            })
        elif acknowledged_services[stage]:
            nq.push({
                'srl': entry.task.srl,
                'message': 'Awaiting results for: ' + \
                    ','.join([x for x in acknowledged_services[stage]]),
                'depth': depth,
            })

    for csrl in entry.extracted_children:
        child = entry.dispatcher.entries[entry.task.sid].get(csrl, None)
        if not child:
            nq.push({
                'srl': entry.task.srl,
                'message': 'Extracted child %s not found' % csrl,
                'depth': depth,
            })
        else:
            nq.push({
                'srl': entry.task.srl,
                'message': 'Extracted child: ',
                'depth': depth,
            })
            explain(child, nq, depth+1)

    for child in entry.outstanding_children.itervalues():
        nq.push({
            'srl': entry.task.srl,
            'message': 'Outstanding child: ',
            'depth': depth,
        })
        explain(child, nq, depth+1)


class DispatchClient(object):
    @classmethod
    def _send_control_queue_call(cls, shard, state, **kw):
        name = reply_queue_name(state)
        kw.update({
            'state': state,
            'watch_queue': name,
        })
        t = Task({}, **kw)
        forge.get_control_queue('control-queue-' + str(shard)).push(t.raw)
        nq = NamedQueue(name)
        return nq.pop(timeout=5)

    @classmethod
    def get_system_time(cls, shard='0'):
        result = cls._send_control_queue_call(shard, 'get_system_time')
        return result.get('time', None) if result else None

    @classmethod
    def list_service_info(cls, shard='0'):
        result = cls._send_control_queue_call(shard, 'list_service_info')
        #return result.get('services', None) if result else None
        return result

    @classmethod
    def get_outstanding_services(cls, sid):
        shard = forge.determine_dispatcher(sid)
        result = cls._send_control_queue_call(shard, 'outstanding_services', sid=sid)
        return result

    @classmethod
    def list_outstanding(cls, shard='0'):
        result = cls._send_control_queue_call(shard, 'outstanding_submissions')
        return result.get('sids', None) if result else None

