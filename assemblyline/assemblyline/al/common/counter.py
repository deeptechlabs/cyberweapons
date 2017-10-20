import collections
import copy
import logging
import pprint
import threading

log = logging.getLogger('assemblyline.counters')

class Counters(collections.Counter):
    pass

class AutoExportingCounters(object):

    def __init__(self,
                 name,
                 host,
                 export_interval_secs,
                 channel,
                 auto_log=True,
                 auto_flush=False,
                 counter_type=None):
        self.channel = channel
        self.export_interval = export_interval_secs
        self.counts = Counters()
        self.name = name
        self.host = host
        self.type = counter_type or name
        self.counts['type'] = counter_type or name
        self.counts['name'] = name
        self.counts['host'] = host
        self.auto_log = auto_log
        self.auto_flush = auto_flush
        self.lock = threading.Lock()
        self.scheduler = None
        assert self.channel
        assert(self.export_interval > 0)

    def start(self):
        import apscheduler
        import apscheduler.scheduler
        self.scheduler = apscheduler.scheduler.Scheduler()
        self.scheduler.add_interval_job(self.export,
                seconds=self.export_interval)
        self.scheduler.start()

    def stop(self):
        if self.scheduler:
            self.scheduler.shutdown()
            self.scheduler = None

    def export(self):
        try:
            # To avoid blocking increments on the redis operation 
            # we only hold the long to do a copy.
            with self.lock:
                thread_copy = copy.deepcopy(self.counts)
                if self.auto_flush:
                    self.counts = Counters()
                    self.counts['type'] = self.type
                    self.counts['name'] = self.name
                    self.counts['host'] = self.host

            self.channel.publish(thread_copy)
            if self.auto_log:
                log.info("%s", pprint.pformat(thread_copy))

            return thread_copy
        except:
            log.exception("Exporting counters")

    def set(self, name, value):
        try:
            with self.lock:
                self.counts[name] = value
        except: # Don't let increment fail anything.
            log.exception("Setting counter")

    def increment(self, name, increment_by=1):
        try:
            with self.lock:
                self.counts[name] += increment_by
        except: # Don't let increment fail anything.
            log.exception("Incrementing counter")


