#!/usr/bin/env python

from assemblyline.al.common import forge
from assemblyline.al.common.remote_datatypes import Counters

config = forge.get_config()

counter = Counters(prefix="quota",
                   host=config.core.redis.nonpersistent.host,
                   port=config.core.redis.nonpersistent.port,
                   db=config.core.redis.nonpersistent.db)

if counter.ready():
    counter.reset_queues()