import json
import logging
import redis
import time

from distutils.version import StrictVersion
from random import shuffle
from uuid import uuid4

from assemblyline.common import isotime
from assemblyline.al.common import forge

# Add a version warning if redis python client is < 2.10.0. Older versions
# have a connection bug that can manifest with the dispatcher.
if StrictVersion(redis.__version__) <= StrictVersion('2.10.0'):
    import warnings
    warnings.warn("%s works best with redis > 2.10.0. You're running"
                  " redis %s. You should upgrade." %
                  (__name__, redis.__version__))

log = logging.getLogger('assemblyline.queue')
pool = {}


def retry_call(func, *args, **kw):
    maximum = 2
    exponent = -7

    while True:
        try:
            return func(*args, **kw)
        except redis.ConnectionError:
            log.exception('Reconnect')
            time.sleep(2 ** exponent)
            exponent = exponent + 1 if exponent < maximum else exponent


def get_client(host, port, db, private):
    if not host or not port or not db:
        config = forge.get_config()
        host = host or config.core.redis.nonpersistent.host
        port = int(port or config.core.redis.nonpersistent.port)
        db = int(db or config.core.redis.nonpersistent.db)

    if private:
        return redis.StrictRedis(host=host, port=port, db=db)
    else:
        return redis.StrictRedis(connection_pool=get_pool(host, port, db))


def get_pool(host, port, db):
    key = (host, port, db)

    connection_pool = pool.get(key, None)
    if not connection_pool:
        connection_pool = \
            redis.BlockingConnectionPool(
                host=host,
                port=port,
                db=db,
                max_connections=200
            )
        pool[key] = connection_pool

    return connection_pool


class Counters(object):
    def __init__(self, prefix="counter", host=None, port=None, db=None, track_counters=False):
        self.c = get_client(host, port, db, False)
        self.prefix = prefix
        if track_counters:
            self.tracker = Hash("c-tracker-%s" % prefix, host=host, port=port, db=db)
        else:
            self.tracker = None

    def inc(self, name, value=1, track_id=None):
        if self.tracker:
            self.tracker.add(track_id, isotime.now_as_local())
        return retry_call(self.c.incr, "%s-%s" % (self.prefix, name), value)

    def dec(self, name, value=1, track_id=None):
        if self.tracker:
            self.tracker.pop(str(track_id))
        return retry_call(self.c.decr, "%s-%s" % (self.prefix, name), value)

    def get_queues_sizes(self):
        out = {}
        for queue in retry_call(self.c.keys, "%s-*" % self.prefix):
            queue_size = int(retry_call(self.c.get, queue))
            if queue_size != 0:
                out[queue] = queue_size

        return out

    def get_queues(self):
        return retry_call(self.c.keys, "%s-*" % self.prefix)

    # noinspection PyBroadException
    def ready(self):
        try:
            self.c.ping()
        except Exception:  # pylint: disable=W0702
            return False

        return True

    def reset_queues(self):
        self.c.delete("c-tracker-%s" % self.prefix)
        for queue in retry_call(self.c.keys, "%s-*" % self.prefix):
            retry_call(self.c.set, queue, "0")


e_enter_script = """
local release_name = ARGV[1]
local waiting_queue = ARGV[2]
local window_holder = ARGV[3]
local timeout = ARGV[4]
if redis.call('setnx', window_holder, release_name) == 1 then
    redis.call('expire', window_holder, timeout)
    return true
end
redis.pcall('rpush', waiting_queue, release_name)
return false
"""

e_exit_script = """
local release_name = ARGV[1]
local waiting_queue = ARGV[2]
local window_holder = ARGV[3]
if redis.call('get', window_holder) ~= release_name then
    return
end
redis.call('del', window_holder)
local waiting_release_names = redis.call('lrange', waiting_queue, 0, -1)
redis.call('del', waiting_queue)
return waiting_release_names
"""


# noinspection PyProtectedMember pylint: disable=W0212
class ExclusionWindow(object):
    def __init__(self, name, seconds, host=None, port=None, db=None):
        uuid = uuid4().get_hex()
        self.c = get_client(host, port, db, False)
        self.release_name = '-'.join(('ew', str(seconds), name, uuid))
        self.waiting_queue = '-'.join(('ew', str(seconds), name, 'waiting'))
        self.window_holder = '-'.join(('ew', str(seconds), name, 'holder'))
        self.seconds = seconds
        self._aquire = self.c.register_script(e_enter_script)
        self._release = self.c.register_script(e_exit_script)

    def __enter__(self):
        while not retry_call(self._aquire, args=[
            self.release_name, self.waiting_queue, self.window_holder,
            self.seconds,
        ]):
            retry_call(self.c.blpop, self.release_name, self.seconds)

    def __exit__(self, unused1, unused2, unused3):
        queue_names = retry_call(self._release, args=[
            self.release_name, self.waiting_queue, self.window_holder
        ])
        if not queue_names:
            return
        shuffle(queue_names)
        for queue_name in queue_names:
            retry_call(self.c.rpush, queue_name, True)


# noinspection PyProtectedMember pylint: disable=W0212
class ExpiringSet(object):
    def __init__(self, name, ttl=86400, host=None, port=None, db=None):
        self.c = get_client(host, port, db, False)
        self.name = name
        self.ttl = ttl

    def add(self, *values):
        rval = retry_call(self.c.sadd, self.name,
                          *[json.dumps(v) for v in values])
        retry_call(self.c.expire, self.name, self.ttl)
        return rval

    def length(self):
        return retry_call(self.c.scard, self.name)

    def members(self):
        return [json.loads(s) for s in retry_call(self.c.smembers, self.name)]

    def delete(self):
        retry_call(self.c.delete, self.name)


h_pop_script = """
local result = redis.call('hget', ARGV[1], ARGV[2])
if result then redis.call('hdel', ARGV[1], ARGV[2]) end
return result
"""


# noinspection PyProtectedMember pylint: disable=W0212
class Hash(object):
    def __init__(self, name, host=None, port=None, db=None):
        self.c = get_client(host, port, db, False)
        self.name = name
        self._pop = self.c.register_script(h_pop_script)

    def add(self, key, value):
        return retry_call(self.c.hsetnx, self.name, key, json.dumps(value))

    def exists(self, key):
        return retry_call(self.c.hexists, self.name, key)

    def get(self, key):
        return retry_call(self.c.hget, self.name, key)

    def keys(self):
        return retry_call(self.c.hkeys, self.name)

    def length(self):
        return retry_call(self.c.hlen, self.name)

    def items(self):
        items = retry_call(self.c.hgetall, self.name)
        if not isinstance(items, dict):
            return {}
        for k in items.keys():
            items[k] = json.loads(items[k])
        return items

    def pop(self, key):
        item = retry_call(self._pop, args=[self.name, key])
        if not item:
            return item
        return json.loads(item)

    def set(self, key, value):
        return retry_call(self.c.hset, self.name, key, json.dumps(value))

    def delete(self):
        retry_call(self.c.delete, self.name)


# noinspection PyProtectedMember pylint: disable=W0212
class ExpiringHash(Hash):
    def __init__(self, name, ttl=86400, host=None, port=None, db=None):
        super(ExpiringHash, self).__init__(name, host, port, db)
        self.ttl = ttl

    def add(self, key, value):
        rval = super(ExpiringHash, self).add(key, value)
        retry_call(self.c.expire, self.name, self.ttl)
        return rval

    def set(self, key, value):
        rval = super(ExpiringHash, self).set(key, value)
        retry_call(self.c.expire, self.name, self.ttl)
        return rval
