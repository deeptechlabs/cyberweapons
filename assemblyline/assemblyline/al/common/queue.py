#!/usr/bin/env python

import json
import time
import uuid

from Queue import Empty, Queue

from assemblyline.common.exceptions import get_stacktrace_info
from assemblyline.common.isotime import now_as_iso
from assemblyline.al.common import forge
from assemblyline.al.common.task import Task
from assemblyline.al.common.remote_datatypes import get_client, log, redis, retry_call


def reply_queue_name(suffix=None):
    components = [now_as_iso(), str(uuid.uuid4())]
    if suffix:
        components.append(str(suffix))
    return '.'.join(components)


class CommsQueue(object):
    def __init__(self, names, host=None, port=None, db=None, private=False):
        self.c = get_client(host, port, db, private)
        self.p = retry_call(self.c.pubsub)
        if not isinstance(names, list):
            names = [names]
        self.names = names
        self._connected = False

    def _connect(self):
        if not self._connected:
            retry_call(self.p.subscribe, self.names)
            self._connected = True

    def close(self):
        retry_call(self.p.close)
        
    def listen(self):
        while True:
            self._connect()
            try:
                i = self.p.listen()
                v = next(i)
                if isinstance(v, dict) and v.get('type', '') != 'subscribe':
                    yield(v)
            except redis.ConnectionError as ex:
                trace = get_stacktrace_info(ex)
                log.warning('Redis connection error (1): %s', trace)
                self._connected = False
        
    def publish(self, message):
        for name in self.names:
            retry_call(self.c.publish, name, json.dumps(message))


class LocalQueue(Queue):
    # To set a timeout call with timeout=<seconds>.
    def pop(self, blocking=True, **kw):
        try:
            result = self.get(block=blocking, **kw)
        except Empty:
            result = None
        return result

    def push(self, *messages):
        for message in messages:
            self.put(message)


class MultiQueue(object):
    def __init__(self, host=None, port=None, db=None, private=False):
        self.c = get_client(host, port, db, private)

    def delete(self, name):
        retry_call(self.c.delete, name)

    def pop(self, name, blocking=True, timeout=0):
        if blocking:
            if not timeout:
                response = retry_call(self.c.blpop, name, timeout)
            else:
                try:
                    response = self.c.blpop(name, timeout)
                except redis.ConnectionError as ex:
                    trace = get_stacktrace_info(ex)
                    log.warning('Redis connection error (2): %s', trace)
                    time.sleep(timeout)
                    response = None
        else:
            response = retry_call(self.c.lpop, name)

        if not response:
            return response

        if blocking:
            return json.loads(response[1])
        else:
            return json.loads(response)

    def push(self, name, *messages):
        for message in messages:
            retry_call(self.c.rpush, name, json.dumps(message))

    def length(self, name):
        return retry_call(self.c.llen, name)


class NamedQueue(object):
    def __init__(
        self, name, host=None, port=None, db=None, private=False, ttl=0
    ):
        self.c = get_client(host, port, db, private)
        self.name = name
        self.ttl = ttl

    def delete(self):
        retry_call(self.c.delete, self.name)

    def length(self):
        return retry_call(self.c.llen, self.name)

    def peek_next(self):
        response = retry_call(self.c.lrange, self.name, 0, 0)

        if not response:
            return None
        else:
            return json.loads(response[0])

    def pop(self, blocking=True, timeout=0):
        if blocking:
            if not timeout:
                response = retry_call(self.c.blpop, self.name, timeout)
            else:
                try:
                    response = self.c.blpop(self.name, timeout)
                except redis.ConnectionError as ex:
                    trace = get_stacktrace_info(ex)
                    log.info('Redis connection error (3): %s', trace)
                    time.sleep(timeout)
                    response = None
        else:
            response = retry_call(self.c.lpop, self.name)

        if not response:
            return response

        if blocking:
            return json.loads(response[1])
        else:
            return json.loads(response)

    def push(self, *messages):
        for message in messages:
            retry_call(self.c.rpush, self.name, json.dumps(message))
        if self.ttl:
            retry_call(self.c.expire, self.name, self.ttl)

    def unpop(self, *messages):
        """Put all messages passed back at the head of the FIFO queue."""
        for message in messages:
            retry_call(self.c.lpush, self.name, json.dumps(message))
        if self.ttl:
            retry_call(self.c.expire, self.name, self.ttl)


def select(*queues, **kw):
    timeout = kw.get('timeout', 0)
    if len(queues) < 1:
        raise TypeError('At least one queue must be specified')
    if any([type(q) != NamedQueue for q in queues]):
        raise TypeError('Only NamedQueues supported')

    c = queues[0].c
    # TODO: Can we compare two StrictRedis instances for equality?
    #       (Queues are back to having their own StrictRedis instance).
    # if any([q.c != c for q in queues[1:]]):
    #    raise ValueError('All queues must share a client')

    if not timeout:
        response = retry_call(c.blpop, [q.name for q in queues], timeout)
    else:
        try:
            response = c.blpop([q.name for q in queues], timeout)
        except redis.ConnectionError as ex:
            trace = get_stacktrace_info(ex)
            log.warning('Redis connection error (4): %s', trace)
            time.sleep(timeout)
            response = None

    if not response:
        return response

    return response[0], json.loads(response[1])

# ARGV[1]: <queue name>, ARGV[2]: <max items to pop minus one>.
pq_pop_script = """
local result = redis.call('zrange', ARGV[1], 0, ARGV[2])
if result then redis.call('zremrangebyrank', ARGV[1], 0, ARGV[2]) end
return result
"""

# ARGV[1]: <queue name>, ARGV[2]: <priority>, ARGV[3]: <vip>,
# ARGV[4]: <item (string) to push>.
pq_push_script = """
local seq = string.format('%020d', redis.call('incr', 'global-sequence'))
local vip = string.format('%1d', ARGV[3])
redis.call('zadd', ARGV[1], 0 - ARGV[2], vip..seq..ARGV[4])
"""

# ARGV[1]: <queue name>, ARGV[2]: <max items to unpush>.
pq_unpush_script = """
local result = redis.call('zrange', ARGV[1], 0 - ARGV[2], 0 - 1)
if result then redis.call('zremrangebyrank', ARGV[1], 0 - ARGV[2], 0 - 1) end
return result
"""


# noinspection PyBroadException
def decode(data):
    try:
        return json.loads(data)
    except:  # pylint: disable=W0702
        log.warning("Invalid data on queue: %s", str(data))
        return None


class PriorityQueue(object):
    def __init__(self, name, host=None, port=None, db=None, private=False):
        self.c = get_client(host, port, db, private)
        self.r = self.c.register_script(pq_pop_script)
        self.s = self.c.register_script(pq_push_script)
        self.t = self.c.register_script(pq_unpush_script)
        self.name = name

    def count(self, lowest, highest):
        return retry_call(self.c.zcount, self.name, -highest, -lowest)

    def delete(self):
        retry_call(self.c.delete, self.name)

    def length(self):
        return retry_call(self.c.zcard, self.name)

    def pop(self, num=1):
        num -= 1
        if num < 0:
            return []
        try:
            return [decode(s[21:]) for s in retry_call(self.r, args=[self.name, num])]
        except redis.ConnectionError as ex:
            trace = get_stacktrace_info(ex)
            log.warning('Redis connection error (5): %s', trace)
            return []

    def push(self, priority, data, vip=None):
        vip = 0 if vip else 9
        retry_call(self.s, args=[self.name, priority, vip, json.dumps(data)])

    def unpush(self, num=1):
        if num < 0:
            return []
        try:
            return [json.loads(s[21:])
                    for s in retry_call(self.t, args=[self.name, num])]
        except redis.ConnectionError as ex:
            trace = get_stacktrace_info(ex)
            log.warning('Redis connection error (6): %s', trace)
            return []


class DispatchQueue(object):
    def __init__(self, host=None, port=None, db=None):
        config = forge.get_config()
        self.host = host or config.core.redis.nonpersistent.host
        self.port = port or config.core.redis.nonpersistent.port
        self.db = db or config.core.redis.nonpersistent.db
        self.q = {}

    def _get_queue(self, n):
        q = self.q.get(n, None)
        if not q:
            self.q[n] = q = PriorityQueue(n, self.host, self.port, self.db)
        return q

    def length(self, name):
        return self._get_queue(name).length()

    def pop(self, name, num=1):
        return self._get_queue(name).pop(num)

    def send(self, task, shards=None, queue_name=None):
        if queue_name is None:
            queue_name = {}

        if not shards:
            config = forge.get_config()
            shards = config.core.dispatcher.shards

        if not task.dispatch_queue:
            n = forge.determine_dispatcher(task.sid, shards)
            name = queue_name.get(n, None)
            if not name:
                queue_name[n] = name = 'ingest-queue-' + str(n)
            task.dispatch_queue = name
        if not task.priority:
            task.priority = 0
        self._get_queue(task.dispatch_queue).push(task.priority, task.raw)

    def send_raw(self, raw, shards=None):
        if not shards:
            config = forge.get_config()
            shards = config.core.dispatcher.shards

        task = Task(raw)
        self.send(task, shards)

    def submit(self, task, shards=None):
        if not shards:
            config = forge.get_config()
            shards = config.core.dispatcher.shards
        task.dispatch_queue = None
        self.send(task, shards)
