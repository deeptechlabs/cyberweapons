import json

from assemblyline.al.common import forge, queue
config = forge.get_config()

h_pop_script = """
local result = redis.call('hget', ARGV[1], ARGV[2])
if result then redis.call('hdel', ARGV[1], ARGV[2]) end
return result
"""

# noinspection PyProtectedMember pylint: disable=W0212
class Hash(object):
    def __init__(self, name,
                 host=config.core.redis.nonpersistent.host,
                 port=config.core.redis.nonpersistent.port,
                 db=config.core.redis.nonpersistent.db):
        self.c = queue.get_client(host, port, db, False)
        self.name = name
        self._pop = self.c.register_script(h_pop_script)

    def add(self, key, value):
        return queue._retry_call(self.c.hsetnx, self.name, key, json.dumps(value))

    def exists(self, key):
        return queue._retry_call(self.c.hexists, self.name, key)

    def keys(self):
        return queue._retry_call(self.c.hkeys, self.name)

    def length(self):
        return queue._retry_call(self.c.hlen, self.name)

    def pop(self, key):
        item = queue._retry_call(self._pop, args=[self.name, key])
        if not item:
            return item
        return json.loads(item)

    def delete(self):
        queue._retry_call(self.c.delete, self.name)

