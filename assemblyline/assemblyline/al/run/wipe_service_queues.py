#!/usr/bin/env python

# merge this.
import redis

from assemblyline.al.common import forge
config = forge.get_config()

def main():
    r = redis.StrictRedis(config.core.redis.nonpersistent.host,
                          config.core.redis.nonpersistent.port,
                          config.core.redis.nonpersistent.db)

    for key in r.keys('Service-*'):
        r.delete(key)

    for key in r.keys('*/tags'):
        r.delete(key)

if __name__ == '__main__':
    main()
