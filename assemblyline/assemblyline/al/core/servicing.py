
import json
import logging
import platform
import re
import threading
import time

from collections import namedtuple
from assemblyline.common.importing import class_by_path
from assemblyline.al.common import forge
from assemblyline.al.common.message import Message, MT_SVCHEARTBEAT
from assemblyline.al.common.queue import CommsQueue
from assemblyline.al.service.service_driver import ServiceDriver

config = forge.get_config()
log = logging.getLogger('assemblyline.svc.mgr')

DONE = len(config.services.stages) + 1
NAME = dict([(x + 1, config.services.stages[x]) for x in xrange(len(config.services.stages))])
ORDER = dict([(config.services.stages[x], x + 1) for x in xrange(len(config.services.stages))])

ServiceEntry = namedtuple(
    'ServiceEntry', [
        'name',
        'accepts',
        'category',
        'proxy',
        'rejects',
        'skip',
        'stage',
        'timeout',
        'metadata'])

LocalServiceEntry = namedtuple(
    'LocalServiceEntry', [
        'name',
        'type',
        'handle'])


def service_list(parsed):
    # determine list of live services from a parsed heartbeat
    live = []
    try:
        services = parsed['services']
        if not services:
            return []
        service_details = services['details']
        live = [name for name, stats in service_details.items() if stats.get('num_workers', 0) > 0]
    except (KeyError, TypeError) as e:
        log.warn('ignoring service_list exception: %s', str(e))
    return live


def skip_all(_):
    return True


class ServiceManager(object):
    """ Top Level Service Configuration Bootstrap

    Each host has a 'host-profile' in the datastore keyed by its mac address.
    Example excerpt from host-profile:
      {u'auto-AL-WORKER-01':
          {u'services':
              {u'McAfee': {u'service_overrides': {}, u'workers': 4},
               u'NSRL': {u'service_overrides': {}, u'workers': 1},
               ...
       }}}

    The 'services' block of the host-profile is the 'services_profile'.
    The services_profile is used to initialize the ServiceManager.

    The ServiceManager will walk the services_profile and for each service
    allocation in that map it will fetch the detailed service entry from
    riak. It will apply any overrides to the standard config and use that
    to initialize a ServiceDriver for that type of service.
    """

    def __init__(self, services_profile, config_overrides=None):
        self.config_overrides = config_overrides
        self.services_profile = services_profile
        self._lock = threading.Lock()
        self.services = []
        self.datastore = None
        self._started = False

    def get_stats(self):
        """ Return a dictionary of statistics. """
        with self._lock:
            stats = {}
            for service_driver in self.services:
                name = service_driver.handle.get_name()
                if name in stats:
                    log.error("Duplicate entry for %s. Num Drivers; %s",
                              service_driver.handle.get_name(),
                              len(self.services))
                stats[name] = service_driver.handle.get_stats()
            return stats

    def drain(self):
        return self.shutdown()

    def undrain(self):
        return self.start()

    def start(self):
        """ Start all configured services.

        If a service is misconfigured or will not start, it is skipped.
        """
        with self._lock:
            return self._start()

    # noinspection PyBroadException
    def _start(self):
        if self._started:
            log.error("Double start detected in ServiceManager.")

        self.datastore = forge.get_datastore()
        for service_name, service_alloc in self.services_profile.iteritems():
            service_entry = self.datastore.get_service(service_name)
            if not service_entry:
                log.error("No datastore entry found for %s. Skipping",
                          service_name)
                continue

            if service_entry.get('type', 'service') != 'service':
                log.error("Skipping non service %s.", service_name)
                continue

            if not service_entry.get('enabled', False):
                log.warn("Skipping disabled service: %s.", service_name)
                continue

            this_platform = platform.system()
            supported = service_entry.get('supported_platforms', [])
            if this_platform not in supported:
                log.error("%s will not run on this platform (%s). Skipping.",
                          service_name, this_platform)
                continue

            num_workers = service_alloc.get('workers')
            if not num_workers:
                log.error("No workers specified. Not launching: %s.",
                          service_name)
                continue

            if num_workers <= 0 or num_workers > 1000:
                log.error("Worker count is not sane. Skipping. %s (%s)",
                          service_name, num_workers)
                continue

            # Grab the configuration specific to the service.
            service_classpath = service_entry.get('classpath')
            if not service_classpath:
                log.error("Service entry has no classpath. Skipping")
                continue

            try:
                service_cls = class_by_path(service_classpath)
            except:  # pylint:disable=W0702
                log.exception('Could not instantiate service with classpath: %s. Skipping', service_classpath)
                continue

            service_params = service_entry.get('config')
            if service_params is None:
                log.error('No service params found in service entry for %s. Skipping', service_name)
                continue

            # Apply any service config overrides in our profile to the service params.
            service_config_overrides = service_alloc.get('service_overrides')
            if service_config_overrides:
                log.info('Applying service param overrides: %s', service_config_overrides)
                service_params.update(service_config_overrides)

            service_timeout = service_entry.get('timeout')
            if service_timeout is None:
                log.info('Service entry has no timeout. Using class default %s', service_cls.SERVICE_TIMEOUT)
                service_timeout = service_cls.SERVICE_TIMEOUT

            try:
                service_driver = ServiceDriver(service_cls, service_params, 
                                               service_timeout=service_timeout, num_workers=num_workers,
                                               config_overrides=self.config_overrides)
            except:  # pylint:disable=W0702
                log.exception("Failed to instantiate service driver for : %s. Skipping", service_classpath)
                continue

            service_type = service_entry.get('stage', 'CORE')

            service_entry = \
                LocalServiceEntry(service_name, service_type, service_driver)

            self.services.append(service_entry)

            service_driver.start()
            self._started = True

    # noinspection PyUnusedLocal
    def shutdown(self):
        with self._lock:
            self._shutdown()

    def _shutdown(self, skip_soft_stop=False):
        # First stop the supervisor thread so it doesn't try sending heartbeats
        # etc via shutdown. Then issue a soft stop to all drivers so they can all begin
        # a controlled shutdown in parallel. Then issue the hard stops which
        # will give the services a fixed amount of time to shutdown before it terminates
        # them forcefully.
        log.info("service manager shutting down")
        for service_driver in self.services:
            service_driver.handle.stop_supervisor()

        if not skip_soft_stop:
            for service_driver in self.services:
                service_driver.handle.stop_soft()

        for service_driver in self.services:
            service_driver.handle.stop_hard()

        self.datastore.close()
        self._started = False
        self.services = []


class ServiceProxy(object):
    """ ServiceProxy is a remote proxy / stub for a given service."""

    def __init__(self, service_name):
        self.service_queue = forge.get_service_queue(service_name)

    def execute(self, priority, srequest):
        """Issue a remote call to the configured service."""
        return self.service_queue.push(priority, srequest)


class ServiceProxyManager(object):
    """ ServiceProxyManager is primarily used by the Dispatcher to
    manage the remove stubs / proxies for all services."""

    def __init__(self, full_service_list):
        self.service_list = full_service_list
        self.lock = threading.Lock()
        self.datastore = forge.get_datastore()

        self._init_categories_and_services()

    def _determine_services(self, task, _):  # pylint:disable=W0613
        ignore_tag = task.ignore_tag
        tag = task.tag or 'unknown'
        acknowledged, outstanding, completed, dispatched = (
            [{} if NAME.get(y, False) else None for y in range(DONE + 1)] for _ in range(4))
        excluded = self.expand_categories(task.excluded)
        if not task.selected:
            selected = [s for s in self.services.keys()]
        else:
            selected = self.expand_categories(task.selected)
        for k, v in self.services.items():
            if v.category == config.services.system_category:
                selected.append(k)
        services = list(set(selected).difference(excluded))
        selected = []
        skipped = []
        task.excluded = list(excluded)
        for name in services:
            try:
                service = self.services[name]
                if ignore_tag or re.match(service.accepts, tag) and not re.match(service.rejects, tag):
                    outstanding[service.stage][name] = service
                    selected.append(name)
                else:
                    skipped.append(name)
            except KeyError:
                # TODO: This should probably result in an error record.
                skipped.append(name)
        # Change sets back to lists so that they are serializable.
        task.selected = selected
        task.skipped = skipped

        return acknowledged, completed, dispatched, outstanding

    def determine_services(self, task, now):
        with self.lock:
            return self._determine_services(task, now)

    def expand_categories(self, services):
        """Expands the names of service categories found in the list of services.
        Parameters:
        group : str or list
            The name of a group/service or,
            a list of groups/services that need to be expanded.
        """
        if services is None:
            return []

        # If we received a string instead of a list,
        # make a list from the string and operate on that.
        if not isinstance(services, list):
            services = [services]
        else:
            services = services[:]

        found_services = set()
        seen_categories = set()
        for item in services:
            # If the name of this item is the same as the name
            # given to a group of services...
            if item in self.categories:
                # ... And we haven't seen the name of this group yet...
                if item not in seen_categories:
                    # Add all of the items in this group to the list of
                    # things that we need to evaluate, and mark this
                    # group as having been seen.
                    services.extend(self.categories[item])
                    seen_categories.update(item)
                continue

            # This is the name of a service -
            # add it to the set of actual service names.
            found_services.update([item])

        return list(found_services)

    def init_categories_and_services(self):
        with self.lock:
            self._init_categories_and_services()

    def stage_by_name(self, name):
        return self.services[name].stage

    def start(self):
        def listen_loop():
            # TODO: This should resume if there is a connection failure/problem.
            try:
                status = CommsQueue('status')
                for msg in status.listen():
                    if msg['type'] != 'message':
                        continue

                    msg = Message.parse(json.loads(msg['data']))
                    if msg.mtype != MT_SVCHEARTBEAT:
                        continue

                    t = time.time()
                    for k in service_list(msg.body):
                        with self.lock:
                            service = self.services.get(k, None)
                            if not service:
                                service = self._add_service(k)
                            if service:
                                service.metadata['last_heartbeat_at'] = t

            except Exception:
                log.exception('In listen_loop')
                raise

        thread = threading.Thread(target=listen_loop)
        thread.daemon = True
        thread.start()

    def update_last_result_at(self, name, t):
        with self.lock:
            service = self.services.get(name, None)
            if service:
                service.metadata['last_result_at'] = t

    # noinspection PyBroadException
    def _add_service(self, service_name):
        service_entry = self.datastore.get_service(service_name)
        log.info('Pulled from riak: %s: %s', service_name, service_entry)

        if not service_entry:
            log.warn("Could not find service '%s' in the datastore.", service_name)
            return None

        if not service_entry.get('enabled', False):
            log.info("Skipping disabled service: %s.", service_name)
            return None

        accepts = service_entry.get('accepts', '.*')
        class_name = service_entry.get('classpath', None)
        rejects = service_entry.get('rejects', 'empty')
        short_name = service_entry.get('name', None) or service_name
        timeout = service_entry.get('timeout', config.services.timeouts.default)

        category = service_entry.get('category', None)
        stage = ORDER[service_entry.get('stage', 'CORE')]

        if category:
            l = self.categories.get(category, [])
            if short_name not in l:
                l.append(short_name)
                self.categories[category] = l
        if not class_name:
            raise KeyError("No 'classpath' found for service '%s'!", service_name)

        try:
            cls = class_by_path(class_name)
            skip = cls.skip
        except:  # pylint:disable=W0702
            log.exception("Could not get service's skip method:%s.", class_name)
            skip = skip_all

        proxy = self._create_proxy(class_name.split('.')[-1])
        entry = ServiceEntry(service_name, accepts, category, proxy,
                             rejects, skip, stage, timeout,
                             {'last_heartbeat_at': 0, 'last_result_at': 0})
        if service_name in self.services:
            raise KeyError('Duplicate service entry: {}'.format(service_name))
        self.services[service_name] = entry

        return entry

    @staticmethod
    def _create_proxy(service_name):
        return ServiceProxy(service_name)

    def _init_categories_and_services(self):
        self.categories = {}  # pylint:disable=W0201
        self.services = {}  # pylint:disable=W0201

        for service_name in self.service_list:
            self._add_service(service_name)
