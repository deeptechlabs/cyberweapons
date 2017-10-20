#!/usr/bin/env python

from __future__ import absolute_import
import copy

import logging
import os
import pprint
import psutil
import shutil
import tempfile
import threading
import time
import signal
import subprocess
import uuid

from assemblyline.common import isotime
from assemblyline.common.exceptions import get_stacktrace_info
from assemblyline.common import net
from assemblyline.common import sysinfo
from assemblyline.al.common.importing import service_by_name
from assemblyline.al.common.provisioning import ServiceAllocation, VmAllocation
from assemblyline.al.service.list_queue_sizes import get_service_queue_length, get_service_queue_lengths
from assemblyline.al.common import forge
from assemblyline.al.common.message import Message, MT_SVCHEARTBEAT
from assemblyline.al.common.message import send_rpc, reply_to_rpc
from assemblyline.al.common.queue import CommsQueue, NamedQueue, LocalQueue, reply_queue_name
from assemblyline.al.common.task import Task
from assemblyline.al.core.servicing import ServiceManager
config = forge.get_config()


class RemoteShutdownInterrupt(Exception):
    pass


class UnsupportedRequestError(Exception):
    pass


class ProvisioningError(Exception):
    pass


DEFAULT_REGISTRATION = {
    'ip': '',
    'hostname': '',
    'mac_address': '',
    'enabled': True,
    'profile': '',
    'is_vm': False,
    'hosts_override': {},
    'vm_host': '',
    'source_rev': ''
}
VM_MAC_PREFIX = '5254'
DATABASE_NUM = 3


# noinspection PyBroadException
def worker_cleanup(mac, logger=None):
    """
    Cleanup is responsible for performing resource cleanup for workers in the event that they're killed
    (and with flex manager, this happens more frequently).
    :param mac: the mac address of the host to cleanup
    :param logger: optional logger
    """
    try:
        if logger:
            logger.info('Worker resource cleanup starting.')
        persistent_settings = {
            'db': config.core.redis.persistent.db,
            'host': config.core.redis.persistent.host,
            'port': config.core.redis.persistent.port,
        }
        queue_name = "cleanup-%s" % mac
        cleanupq = NamedQueue(queue_name, **persistent_settings)

        def exhaust():
            while True:
                res = cleanupq.pop(blocking=False)
                if res is None:
                    break
                yield res

        ops = [op for op in exhaust()]
        for op in ops:
            # Execute the cleanup operation
            if isinstance(op, dict):
                op_type = op.get('type')
                op_args = op.get('args')
                if op_type == 'shell' and op_args is not None:
                    if logger:
                        logger.info('Executing cleanup command: %s', str(op_args))
                    subprocess.Popen(args=op_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if logger:
            logger.info("Worker resource cleanup complete.")
    except:
        if logger:
            logger.exception("Worker resource cleanup failed: ")


class AgentRequest(Message):
    """ Convenience for HostAgent specific Message's."""

    PING = 'ping'
    DRAIN = 'drain'
    UNDRAIN = 'undrain'
    SHUTDOWN = 'shutdown'

    VM_LIST = 'vm_list'
    VM_START = 'vm_start'
    VM_STOP = 'vm_stop'
    VM_STOP_ALL = 'vm_stop_all'
    VM_GET_REVERT_TIMES = 'vm_get_revert_times'
    VM_RESTART = 'vm_restart'
    VM_REFRESH_ALL = 'vm_refreshall'
    VM_REFRESH_FLEET = 'vm_refreshfleet'
    VM_REFRESH_INSTANCE = 'vm_refreshinstance'

    START_SERVICES = 'start_services'
    STOP_SERVICES = 'stop_services'

    VALID_REQUESTS = [SHUTDOWN, START_SERVICES, STOP_SERVICES, PING]

    # noinspection PyUnusedLocal
    def __init__(self, to, mtype, body, sender=None, reply_to=None):
        super(AgentRequest, self).__init__(to, mtype, sender, reply_to=None, body=body)

    @classmethod
    def parse(cls, raw):
        return Message.parse(raw)

    @classmethod
    def is_agent_request(cls, msg):
        return msg.mtype in cls.VALID_REQUESTS


class FlexManager(object):

    # Regardless of CPU/RAM requirements we limit
    # the number of worker instances to this.
    MAX_WORKERS = 50

    # Maximum number of times to requery the datastore on error
    DATASTORE_RETRY_LIMIT = 8

    # Maximum and minimum ticks spent on the same main service
    MAX_TICKS = 144
    MIN_TICKS = 12

    # Ticks lenght in seconds
    SECONDS_PER_TICKS = 5

    # Start/Stop Flexing threshold
    START_FLEX = max(100, config.core.dispatcher.max.inflight * 5 / 100)
    STOP_FLEX = 25

    # noinspection PyGlobalUndefined,PyUnresolvedReferences
    def __init__(self):
        # Delay these imports so most nodes don't import them.
        global Scheduler
        from apscheduler.scheduler import Scheduler

        self.bottleneck_queue_sizes = {}
        self.cores = None
        self.datastore = forge.get_datastore()
        self.flex_profile = None
        self.flex_scheduler = None
        self.log = logging.getLogger('assemblyline.flex')
        self.mac = net.get_mac_for_ip(net.get_hostip())
        self.main_bottleneck = ''
        self.needs_cleanup = True
        self.previous_queue_sizes = {}
        self.safe_start_dict = {}
        self.safeq = NamedQueue('safe-start-%s' % self.mac)
        self.service_manager = None
        self.ram_mb = None
        self.tick_count = 0
        self.vm_manager = None

    # noinspection PyUnresolvedReferences
    def start(self):

        self.cores = psutil.NUM_CPUS
        self.flex_scheduler = Scheduler()
        self.ram_mb = int(psutil.TOTAL_PHYMEM / (1024 * 1024))

        assert(self.cores > 0)
        assert(self.ram_mb > 256)
        assert((self.MAX_TICKS > 6) and (self.MAX_TICKS < 10000))

        self.log.info('Blacklisted for Flex: %s', " ".join(config.services.flex_blacklist))

        self.flex_scheduler.add_interval_job(self._check_flexing_status,
                                             seconds=self.SECONDS_PER_TICKS, kwargs={})
        self._find_new_bottlenecks()

        self.flex_scheduler.start()

    def heartbeat(self):
        heartbeat = {}

        if self.vm_manager:
            vm_hb = self.vm_manager.get_stats()
            if vm_hb:
                heartbeat['vmm'] = vm_hb

        if self.service_manager:
            details = self.service_manager.get_stats()
            if details:
                heartbeat['services'] = {'status': 'up', 'details': details}
            else:
                heartbeat['services'] = None
        else:
            heartbeat['services'] = None

        return heartbeat

    def shutdown(self):
        self.log.info('shutting down flex manager.')
        self.flex_scheduler.shutdown()
        if self.service_manager:
            self.service_manager.shutdown()
            self.service_manager = None
        if self.vm_manager:
            self.vm_manager.shutdown()
            self.vm_manager = None
        self.datastore.close()

    def _check_flexing_status(self):
        self.tick_count += 1

        if self.tick_count > self.MAX_TICKS:
            self.log.info("flexnode has been running for max period. respawning.")
            self._find_new_bottlenecks()
            return

        if self.main_bottleneck:
            service_queue_lengths = {x: get_service_queue_length(x) for x in self.bottleneck_queue_sizes.keys()}
            if service_queue_lengths[self.main_bottleneck] < self.STOP_FLEX:
                self.log.info("flexnode main bottleneck (%s) has shrunk under minimum threshold, "
                              "looking for new bottlenecks..." % self.main_bottleneck)
                for srv, queue_size in self.bottleneck_queue_sizes.iteritems():
                    self.log.info("    %s: %d --> %d" % (srv, queue_size, service_queue_lengths[srv]))
                self._find_new_bottlenecks()
                return

            self.log.info("flexnode bottleneck progress:")
            for srv, queue_size in self.bottleneck_queue_sizes.iteritems():
                self.log.info("    %s: %d --> %d" % (srv, queue_size, service_queue_lengths[srv]))

        else:
            self.log.info("flexnode has no services up, checking for new job...")
            self._find_new_bottlenecks()

    def _wait_for_safe_start(self):

        # If safe_start is enabled, we wait until the service has initialized (or timed out) before
        # respawning a new blitz.
        if not self.bottleneck_queue_sizes or not self.flex_profile or not self.safe_start_dict:
            # Nothing to wait on..
            self.log.info("Safe-start has nothing to wait for.")
            return

        for srv in [k for k, v in self.safe_start_dict.iteritems() if v]:
            self.log.info("Waiting on safe-start for service: %s", srv)

            # Before shutting down a service, make sure all of our spawned instances have come up
            worker_count = int(self.flex_profile.get("services", {}).get(srv, {}).get('workers', None) or 0)
            # Maximum 2 minute wait
            max_wait = 120
            while worker_count > 0 and max_wait > 0:
                start = time.time()
                if self.safeq.pop(timeout=max_wait) is not None:
                    worker_count -= 1
                end = time.time()
                max_wait -= int(end - start)

            if worker_count > 0:
                self.log.warning("Service %s is being stopped, but safe_start timed out!")

            self.log.info("Safe-start completed successfully for service: %s", srv)

    # precondition: holding scheduler_thread_lock
    def _find_new_bottlenecks(self):
        self.log.info("Finding new bottlenecks...")
        if self.needs_cleanup:
            self.tick_count = 0
            self._wait_for_safe_start()
            if self.service_manager:
                self.service_manager.shutdown()
                self.service_manager = None

            if self.vm_manager:
                self.vm_manager.shutdown()
                self.vm_manager = None

            # Cleanup queue should also be handled here
            worker_cleanup(self.mac, self.log)

            # Delete any lingering safe-start queue entries (timeout/restart)
            self.safeq.delete()
            self.needs_cleanup = False

        flexable_services, self.flex_profile, self.safe_start_dict = self._create_profile_for_cur_bottleneck()

        if flexable_services:
            self.bottleneck_queue_sizes = {k: v for k, v in flexable_services}
            self.main_bottleneck = flexable_services[0][0]
            self.log.info("Starting Transient ServiceManager with profile: %s. TTL:%d secs.",
                          str(self.flex_profile), self.MAX_TICKS * self.SECONDS_PER_TICKS)

            self.service_manager = ServiceManager(self.flex_profile.get('services'))
            self.service_manager.start()

            if config.workers.install_kvm:
                from assemblyline.al.common.vm import VmManager
                self.vm_manager = VmManager(self.flex_profile.get('virtual_machines'))
                self.vm_manager.sysprep()
                self.vm_manager.start()
            self.needs_cleanup = True
        else:
            self.main_bottleneck = ''
            self.bottleneck_queue_sizes = {}

    def _determine_busiest_services(self):
        queue_lengths = get_service_queue_lengths()

        for blacklisted_service in config.services.flex_blacklist:
            if blacklisted_service in queue_lengths:
                try:
                    queue_lengths.pop(blacklisted_service)
                except KeyError:
                    pass

        flexable_services = sorted([(k, v) for k, v in queue_lengths.iteritems() if v >= self.START_FLEX],
                                   key=lambda x: x[1], reverse=True)

        return flexable_services

    # noinspection PyBroadException
    def _load_profile_data(self):
        # Occasionally we encounter missing profile data, which usually works when a retry occurs.
        retries = self.DATASTORE_RETRY_LIMIT
        while retries > 0:
            try:
                profile_map = self.datastore.get_all_profiles()
                service_map = {x['name']: x for x in self.datastore.list_services()}
                vm_list = self.datastore.list_virtualmachines()
                return profile_map, service_map, vm_list
            except:
                self.log.exception("Error retrieving profile data:")
                time.sleep(.5)
                retries -= 1
        raise ProvisioningError("Unable to retrieve profile data.")

    def _load_allocation_for_service(self, service_to_load):
        vm_to_alloc = None
        profile_map, service_map, vm_list = self._load_profile_data()
        for vm in vm_list:
            vm['srv_list'] = {
                vm['name']: vm['num_workers']
            }

            if service_to_load in vm['srv_list'] and vm['name'] == service_to_load:
                vm_to_alloc = copy.copy(vm)
                break
            else:
                self.log.info('This is not the vm we are looking for: %s with %s' % (vm['name'], vm['srv_list']))

        if vm_to_alloc:
            cpu_usage = 0
            for service in vm_to_alloc['srv_list']:
                cpu_usage += service_map.get(service, {}).get('cpu_cores', 1) * vm_to_alloc['srv_list'][service]

            return VmAllocation(service_to_load, cpu_usage, vm_to_alloc['ram'], vm_to_alloc['srv_list'])
        else:
            try:
                return ServiceAllocation(service_to_load,
                                         service_map[service_to_load].get('cpu_cores', 1),
                                         service_map[service_to_load].get('ram_mb', 1024),
                                         service_to_load)
            except KeyError:
                return None

    def _create_profile_for_cur_bottleneck(self):
        profile = {'services': {}, 'system_overrides': {}, 'virtual_machines': {}}
        safe_start_dict = {}
        resources = {}
        ratio = {}
        allocation = {}

        temp_flexable_services = self._determine_busiest_services()

        if not temp_flexable_services:
            self.log.info("There are no service that meet the minimum requirement for flexing...")
            return temp_flexable_services, profile, safe_start_dict

        flexable_services = [(k, v) for k, v in temp_flexable_services if k in self.previous_queue_sizes]

        if not flexable_services:
            self.previous_queue_sizes = {k: v for k, v in temp_flexable_services}
            return flexable_services, profile, safe_start_dict
        else:
            self.previous_queue_sizes = {}

        self.log.info("The following services are candidates for current flex node:")
        for srv, queue_size in flexable_services:
            self.log.info("    %s: %d" % (srv, queue_size))
            res = self._load_allocation_for_service(srv)
            if not res:
                raise ProvisioningError("No automatic provisioning profile for %s", srv)

            resources[srv] = res
            ratio[srv] = queue_size * 1.0 / flexable_services[0][1]
            allocation[srv] = 0

        # Allocate services
        available_ram = self.ram_mb - 256
        available_cpu = self.cores - 0.1
        failed_list = []
        main_service, main_queue_size = flexable_services[0]
        main_resources = resources[main_service]
        something_changed = True

        while something_changed:
            something_changed = False
            # Can I allocated the main service ?
            if main_resources.cores <= available_cpu and main_resources.ram_mb <= available_ram and \
                    allocation[main_service] < self.MAX_WORKERS:
                available_cpu -= main_resources.cores
                available_ram -= main_resources.ram_mb
                allocation[main_service] += 1
                something_changed = True
            else:
                if main_service not in failed_list:
                    failed_list.append(main_service)
                    something_changed = True

            for srv, queue_size in flexable_services[1:]:
                # is it time to allocate this service
                if (int(ratio[srv] * allocation[main_service]) != allocation[srv] or main_service in failed_list) and \
                        srv not in failed_list:
                    res = resources[srv]
                    if res.cores <= available_cpu and res.ram_mb <= available_ram and \
                            allocation[srv] < self.MAX_WORKERS:
                        available_cpu -= res.cores
                        available_ram -= res.ram_mb
                        allocation[srv] += 1
                        something_changed = True
                    else:
                        failed_list.append(srv)
                        something_changed = True

        self.log.info("Machine has %s cores and %sMB ram. The flex manager will provision %s cores and %sMB ram." %
                      (self.cores, self.ram_mb, self.cores-available_cpu, self.ram_mb-available_ram))

        for srv, _ in flexable_services:
            for x in range(0, allocation[srv]):
                resources[srv].update_profile_for_allocation(profile)

                # Get the name of the optional startup guard queue (used to prevent restart during initialization)
                safe_start_dict[srv] = service_by_name(srv).SERVICE_SAFE_START

        return flexable_services, profile, safe_start_dict


class HostAgent(object):

    def __init__(self):
        self.ip = net.get_hostip()
        self.mac = net.get_mac_for_ip(self.ip)
        self.store = forge.get_datastore()
        self.log = logging.getLogger('assemblyline.agent')
        self.log.info('Starting HostAgent: MAC[%s] STORE[%s]' % (self.mac, self.store))

        # This hosts registration from riak (Hosts tab in UI).
        self.registration = None
        self.service_manager = None
        self.vm_manager = None
        self.flex_manager = None
        self.lock = None
        self.consumer_thread = None
        self._should_run = False
        self.host_profile = {}
        self.executor_thread = None

        # Chores are actions that we run periodically and which we coallesce
        # when the same chore is requested multiple times in the same tick.
        # Jobs are executed as they are received.
        self.jobs = LocalQueue()
        self.last_heartbeat = 0
        self.rpc_handlers = {
            AgentRequest.PING: self.ping,
            AgentRequest.DRAIN: self.drain,
            AgentRequest.UNDRAIN: self.undrain,
            AgentRequest.SHUTDOWN: self.shutdown,
            AgentRequest.VM_LIST: self.list_vms,
            AgentRequest.VM_START: self.start_vm,
            AgentRequest.VM_STOP: self.stop_vm,
            AgentRequest.VM_STOP_ALL: self.stop_all_vms,
            AgentRequest.VM_RESTART: self.restart_vm,
            AgentRequest.VM_REFRESH_ALL: self.refresh_vm_all,
            AgentRequest.VM_REFRESH_FLEET: self.refresh_vm_fleet,
            AgentRequest.VM_GET_REVERT_TIMES: self.vm_get_revert_times,
            AgentRequest.START_SERVICES: self.start_services,
            AgentRequest.STOP_SERVICES: self.stop_services,
        }

        self._should_run = True

        # Fetch and update or host registration information in riak.
        # self._init_registration() defer registration until later

    # noinspection PyUnresolvedReferences
    def register_host(self):
        if self.is_a_vm():
            return "This is a VM, no need to register."

        existing_reg = self.store.get_node(self.mac)
        if existing_reg:
            return "already registered: %s" % pprint.pformat(existing_reg)
        reg = DEFAULT_REGISTRATION.copy()
        reg['hostname'] = net.get_hostname()
        reg['ip'] = self.ip
        reg['mac_address'] = self.mac
        reg['machine_info'] = sysinfo.get_machine_info()
        reg['last_checkin'] = isotime.now_as_iso()
        reg['platform'] = sysinfo.get_platform()
        reg['profile'] = config.workers.default_profile
        reg['created'] = time.asctime()
        if 'roles' not in reg:
            reg['roles'] = []
        if "controller" not in reg["roles"]:
            reg['roles'].append("controller")
        if "hostagent" not in reg["roles"]:
            reg['roles'].append("hostagent")
        self.store.save_node(self.mac, reg)
        return 'Registered %s with %s' % (self.mac, pprint.pformat(reg))

    def _init_queues(self):
        self.rpcqueue = NamedQueue(self.mac)

    def is_a_vm(self):
        if self.mac.startswith(VM_MAC_PREFIX) and config.workers.install_kvm:
            return True
        return False

    # noinspection PyUnresolvedReferences
    def _init_registration(self):
        if self.is_a_vm():
            nq = NamedQueue('vm-%s' % self.mac, db=DATABASE_NUM)
            reg = nq.pop()
            nq.push(reg)

            self.log.info('Updating our registration.')
            reg['hostname'] = net.get_hostname()
            reg['ip'] = self.ip
            reg['machine_info'] = sysinfo.get_machine_info()
            reg['last_checkin'] = isotime.now_as_iso()
            reg['platform'] = sysinfo.get_platform()
            reg['updated'] = time.asctime()
            reg['system_name'] = config.system.name
            if 'roles' not in reg:
                reg['roles'] = []
            if "hostagent" not in reg["roles"]:
                reg['roles'].append("hostagent")

        else:
            reg = self.store.get_node(self.mac)

            if not reg:
                self.log.info('This appears to be our first run on this host. Registering ourselves.')
                reg = DEFAULT_REGISTRATION.copy()
                reg['hostname'] = net.get_hostname()
                reg['ip'] = self.ip
                reg['mac_address'] = self.mac
                reg['machine_info'] = sysinfo.get_machine_info()
                reg['last_checkin'] = isotime.now_as_iso()
                reg['platform'] = sysinfo.get_platform()
                reg['profile'] = 'idle'
                reg['created'] = time.asctime()
                if 'roles' not in reg:
                    reg['roles'] = []
                if "controller" not in reg["roles"]:
                    reg['roles'].append("controller")
                if "hostagent" not in reg["roles"]:
                    reg['roles'].append("hostagent")
                self.store.save_node(self.mac, reg)
            else:
                # Just do an update of the extra info in registration.
                self.log.info('Updating our registration.')
                reg['hostname'] = net.get_hostname()
                reg['ip'] = self.ip
                if not reg.get('profile', None):
                    reg['profile'] = config.workers.default_profile
                reg['machine_info'] = sysinfo.get_machine_info()
                reg['last_checkin'] = isotime.now_as_iso()
                reg['platform'] = sysinfo.get_platform()
                reg['updated'] = time.asctime()
                reg['system_name'] = config.system.name
                if 'roles' not in reg:
                    reg['roles'] = []
                if "controller" not in reg["roles"] and not reg.get('is_vm', False):
                    reg['roles'].append("controller")
                if "hostagent" not in reg["roles"]:
                    reg['roles'].append("hostagent")
                self.store.save_node(self.mac, reg)

        self.registration = reg

        msgs = forge.apply_overrides(reg.get('config_overrides', None))
        if msgs:
            self.log.info("Using %s.", " and ".join(msgs))

        self.log.info('Our registration: %s', pprint.pformat(self.registration))

    def _wait_for_networking(self, timeout):
        uid = uuid.uuid4().get_hex()
        for each_second in xrange(timeout):
            try:
                q = NamedQueue('hostagent-redischeck-%s' % uid)
                q.push('can i reach you')
                q.pop(timeout=1, blocking=False)
                return True
            except Exception as e:
                self.log.info('waiting for redis reachability. %s ', str(e))
        return False

    def _check_time_drift(self):
        dispatcher = '0'
        name = reply_queue_name('cli_get_time')
        t = Task({}, **{
            'state': 'get_system_time',
            'watch_queue': name,
        })
        forge.get_control_queue('control-queue-' + dispatcher).push(t.raw)
        nq = NamedQueue(name)
        r = nq.pop(timeout=5)
        if r is None or 'time' not in r:
            self.log.warn('timed out trying to determine dispatchers clock.')
            return

        clock_difference = abs(r['time'] - time.time())
        if clock_difference > 600:
            self.log.info('Dispatchers clock %s away from ours. Clocks are not set correctly',
                          clock_difference)
        else:
            self.log.debug('Clock drift from dispatcher: %s.', clock_difference)

    # noinspection PyBroadException
    def _clear_tempdir(self):
        # Clear our temporary folder of any files left from previous executions.
        try:
            altemp_dir = os.path.join(tempfile.gettempdir(), 'al')
            shutil.rmtree(altemp_dir, ignore_errors=True)
        except:
            self.log.exception('while clearing temporary directory during sysprep')

    def sysprep(self):
        """Basic prep and return."""
        self._init_registration()
        self._init_queues()
        self.log.info('performing sysprep')
        self._clear_tempdir()
        self._wait_for_networking(20)
        self._check_time_drift()

        if not self.registration:
            raise ProvisioningError('Host registration not found.')

        if not self.registration.get('enabled', None):
            raise ProvisioningError('Host explicitly disabled.')

        profile_name = self.registration.get('profile', None)
        if not profile_name:
            raise ProvisioningError('Host has no assigned profile.')

        if 'profile_definition' not in self.registration:

            self.host_profile = self.store.get_profile(profile_name)
            if not self.host_profile:
                raise ProvisioningError('Host profile does not appear to exist in datastore: %s.', profile_name)

            self.log.info('Our profile: %s', pprint.pformat(self.host_profile))

        else:
            self.host_profile = self.registration.get('profile_definition', {})

        self.log.info('Our profile: %s', pprint.pformat(self.host_profile))
        vm_config = self.host_profile.get('virtual_machines', {})
        if vm_config and not profile_name.startswith('flex'):
            from assemblyline.al.common.vm import VmManager
            self.vm_manager = VmManager(vm_config)
            self.vm_manager.sysprep()

        # if we are are running within a VM. patch hosts files.
        if self.is_a_vm():
            nq = NamedQueue('vm-%s' % self.mac, db=DATABASE_NUM)
            nq.push(self.registration)

    # noinspection PyUnusedLocal
    def undrain(self, msg):
        self.store = forge.get_datastore()
        if self.service_manager:
            self.service_manager.undrain()
        if self.vm_manager:
            self.vm_manager.undrain()
        return True

    # noinspection PyUnusedLocal
    def drain(self, msg):
        if self.service_manager:
            self.service_manager.drain()
        if self.vm_manager:
            self.vm_manager.drain()
        if self.store:
            self.store.close()
        return True

    # noinspection PyUnusedLocal
    def list_vms(self, _msg):
        return self.vm_manager.list_vms()

    # noinspection PyUnusedLocal
    def stop_all_vms(self, _msg):
        return self.vm_manager.stop_all()

    def start_vm(self, msg):
        instance_name = msg.body.get('name', None)
        return self.vm_manager.start_vm(instance_name)

    def stop_vm(self, msg):
        instance_name = msg.body.get('name', None)
        return self.vm_manager.stop_vm(instance_name)

    def restart_vm(self, msg):
        instance_name = msg.body.get('name', None)
        return self.vm_manager.restart_vm(instance_name)

    def refresh_vm_fleet(self, msg):
        fleet_name = msg.body.get('name', None)
        return self.vm_manager.refresh_fleet(fleet_name)

    # noinspection PyUnusedLocal
    def vm_get_revert_times(self, _msg):
        return self.vm_manager.get_revert_times()

    # noinspection PyUnusedLocal
    def refresh_vm_all(self, _msg):
        return self.vm_manager.refresh_all()

    @staticmethod
    def _handle_unknown_request(msg):
        raise Exception('Unknown message type: %s', msg.mtype)

    def start_services(self, _):
        self._start_services()
        return 'started'

    # noinspection PyUnusedLocal
    def stop_services(self, msg):
        self._stop_services()
        return 'stopped'

    @staticmethod
    def _handle_exception(msg, e):
        return 'Exception while processing msg %s: %s' % (msg.mtype, str(e))

    def _handle_request(self, msg):
        self.log.info('Processing RPC: %s', msg.mtype)
        handler = self.rpc_handlers.get(msg.mtype, self._handle_unknown_request)
        return handler(msg)

    # noinspection PyBroadException
    def _rpc_executor_thread_main(self):
        self.send_heartbeat()
        while self._should_run:
            try:
                self.log.debug('Checking for RPCs on %s. Waiting: %s',
                               self.rpcqueue.name, self.jobs.qsize())
                raw = self.rpcqueue.pop(timeout=1, blocking=True)
                if not raw:
                    continue

                # RPCs are in assemblyline.al.common.Message format.
                msg = None
                error = None
                try:
                    msg = AgentRequest.parse(raw)
                except Exception as e:
                    self.log.exception('While processing rpc: %s', raw)
                    error = str(e)

                # TODO should we just block instead of using job queue ?
                if msg:
                    self.jobs.push(msg)
                else:
                    reply_to_rpc(raw, response_body=error, succeeded=False)
            except KeyboardInterrupt:
                self._should_run = False
                self.log.error('Thread got CTL-C in consumer thread.')
                return
            except Exception:
                self.log.exception('Unhandled Exception in consumer thread.')
                time.sleep(2)
                continue

    def _complete_chores_if_due(self):
        now = time.time()
        since_last_heartbeat = now - self.last_heartbeat
        if abs(since_last_heartbeat) >= config.system.update_interval:
            self.send_heartbeat()
            self.last_heartbeat = now

    # noinspection PyUnusedLocal
    def ping(self, _msg):
        self.log.info('PING')
        return 'PONG'

    def heartbeat(self):
        heartbeat = {
            'mac': self.mac,
            'time': isotime.now_as_iso(),
            'registration': self.registration,
            'resources': {
                'cpu_usage.percent': psutil.cpu_percent(),
                'mem_usage.percent': psutil.phymem_usage().percent,
                'disk_usage.percent': psutil.disk_usage('/').percent,
                'disk_usage.free': psutil.disk_usage('/').free
            }
        }

        profile = self.registration.get('profile', None)
        if profile:
            heartbeat['profile'] = profile

        heartbeat['profile_definition'] = self.host_profile

        vm_host_mac = self.registration.get('vm_host_mac', None)
        if vm_host_mac:
            heartbeat['vm_host_mac'] = vm_host_mac

        if self.vm_manager:
            heartbeat['vmm'] = self.vm_manager.get_stats()
        else:
            heartbeat['vmm'] = None

        if self.service_manager:
            heartbeat['services'] = {'status': 'up', 'details': self.service_manager.get_stats()}
        else:
            heartbeat['services'] = None

        if self.flex_manager:
            heartbeat.update(self.flex_manager.heartbeat())

        return heartbeat

    def send_heartbeat(self):
        self.log.debug(r'heartbeat.')
        heartbeat = self.heartbeat()
        msg = Message(to='*', mtype=MT_SVCHEARTBEAT, sender=self.mac, body=heartbeat)
        CommsQueue('status').publish(msg.as_dict())

    @staticmethod
    def shutdown(msg):
        raise RemoteShutdownInterrupt(str(msg))

    # noinspection PyBroadException
    def start_components(self):
        if not self.registration:
            raise ProvisioningError('Host registration not found.')

        if not self.registration.get('enabled', None):
            raise ProvisioningError('Host explicitly disabled.')

        profile_name = self.registration.get('profile', None)
        if not profile_name:
            raise ProvisioningError('Host has no assigned profile.')

        if 'profile_definition' not in self.registration:
            self.host_profile = self.store.get_profile(profile_name)
            if not self.host_profile:
                raise ProvisioningError('Host profile definition not found for %s.', profile_name)
            self.log.info('Our profile: %s', pprint.pformat(self.host_profile))

            # Prior to startup, remove any safe-start queues associated with our mac address.
            NamedQueue('safe-start-%s' % self.mac).delete()

            if profile_name.startswith('flex'):
                self.log.info('We have been provisioned as a flex node. Starting FlexManager.')
                self.flex_manager = FlexManager()
                self.flex_manager.start()
                return
        else:
            self.host_profile = self.registration.get('profile_definition', {})

        services_config = self.host_profile.get('services', None)
        if services_config:
            config_overrides = self.registration.get('config_overrides', {})
            self.service_manager = ServiceManager(services_config, config_overrides)
            self.service_manager.start()
        else:
            self.log.info('No services provisioned for this host.')

        vm_config = self.host_profile.get('virtual_machines', {})
        if vm_config:
            from assemblyline.al.common.vm import VmManager
            self.vm_manager = VmManager(vm_config)
            self.vm_manager.start()
        else:
            self.log.info('No virtual machines provisioned for this host.')
            try:
                from assemblyline.al.common.vm import VmManager
                # Attempt to launch VmManager to cleanup any old VMs that may be left over
                # from a previously configured profile on this node.
                self.vm_manager = VmManager()
                self.vm_manager.start()
                self.vm_manager.shutdown()
            except:
                pass

    def _stop_services(self):
        if self.service_manager:
            self.log.info('Stopping ServiceManager')
            self.service_manager.shutdown()
            self.service_manager = None

    def _start_services(self):
        if self.service_manager:
            # already running
            return

        services_config = self.host_profile.get('services', None)
        if services_config:
            config_overrides = self.registration.get('config_overrides', {})
            self.service_manager = ServiceManager(services_config, config_overrides)
            self.service_manager.start()
        else:
            self.log.info('No services provisioned for this host.')

    def stop_components(self):
        if self.service_manager:
            self._stop_services()

        if self.vm_manager:
            self.log.info('Stopping VmManager.')
            self.vm_manager.shutdown()
            self.vm_manager = None

        if self.flex_manager:
            self.log.info('Stopping Flex Manager.')
            self.flex_manager.shutdown()
            self.flex_manager = None

    def run(self):
        # Clean up any leftover resources from workers
        worker_cleanup(self.mac, self.log)
        # Start up the core components (service and vmm managers)
        # and then kick of the rpc receiver.
        self._init_registration()
        self._init_queues()
        self.start_components()
        self.executor_thread = threading.Thread(target=self._rpc_executor_thread_main, name='agent_rpc_consumer')
        self.executor_thread.start()

        while self._should_run:
            self._complete_chores_if_due()
            job = self.jobs.pop(timeout=0.5)
            if not job:
                continue

            succeeded = True
            try:
                result = self._handle_request(job)
            except RemoteShutdownInterrupt:
                reply_to_rpc(job, response_body='Host Agent Shutting down.', succeeded=True)
                raise
            except Exception as e:  # pylint:disable=W0703
                succeeded = False
                result = 'Error while completing job: %s' % str(e)
                self.log.exception('while completing job')

            reply_to_rpc(job, response_body=result, succeeded=succeeded)

        self.log.info('_should_run is false. exiting.')
        return

    def stop(self):
        self.log.info('Stopping: MAC[%s] STORE[%s]' % (self.mac, self.store))
        self._should_run = False
        self.stop_components()
        if self.consumer_thread:
            self.consumer_thread.join(5)

        if self.store:
            self.store.close()

        worker_cleanup(self.mac, self.log)

    # noinspection PyUnusedLocal
    def _stop_signal_handler(self, signal_num, interrupted_frame):
        self.log.info("Shutting down due to signal.")
        self.stop()

    def serve_forever(self):
        try:
            # Listen for our shutdown signal
            signal.signal(signal.SIGINT, self._stop_signal_handler)
            # Inject a message onto the agents queue.
            self.run()
        except KeyboardInterrupt:
            self.log.info('Shutting down due to KeyboardInterrupt.')
            self.stop()
        except RemoteShutdownInterrupt as ri:
            msg = 'Shutting down due to remote command: %s' % ri
            self.log.info(msg)
            self.stop()
        except Exception as ex:
            msg = 'Shutting down due to unhandled exception: %s' % get_stacktrace_info(ex)
            self.log.error(msg)
            self.stop()


class AgentClient(object):

    def __init__(self, async=False, sender=None):
        """ If sender is not specified the local MAC is used """
        self.sender = sender or net.get_mac_for_ip(net.get_hostip())
        self.async = async

    def _send_agent_rpc(self, mac, command, args=None):
        result = send_rpc(AgentRequest(
            to=mac, mtype=command, body=args,
            sender=self.sender), async=self.async)

        if not self.async:
            if result:
                return result.body
            return 'timeout'
        else:
            return result


class VmmAgentClient(AgentClient):

    def __init__(self, async=False, sender=None):
        super(VmmAgentClient, self).__init__(async, sender)

    def list_vms(self, mac):
        return self._send_agent_rpc(mac, AgentRequest.VM_LIST)

    def get_revert_times(self, mac):
        return self._send_agent_rpc(mac, AgentRequest.VM_GET_REVERT_TIMES)

    def stop_all_vms(self, mac):
        return self._send_agent_rpc(mac, AgentRequest.VM_STOP_ALL)

    def start_vm(self, mac, vmname):
        return self._send_agent_rpc(mac, AgentRequest.VM_START, args={'name': vmname})

    def refresh_all(self, mac):
        return self._send_agent_rpc(mac, AgentRequest.VM_REFRESH_ALL)

    def refresh_fleet(self, mac, fleet):
        return self._send_agent_rpc(mac, AgentRequest.VM_REFRESH_FLEET, args={'name': fleet})

    def stop_vm(self, mac, vmname):
        return self._send_agent_rpc(mac, AgentRequest.VM_STOP, args={'name': vmname})

    def restart_vm(self, mac, vmname):
        return self._send_agent_rpc(mac, AgentRequest.VM_RESTART, args={'name': vmname})


class ServiceAgentClient(AgentClient):

    def __init__(self, sender=None, async=False):
        super(ServiceAgentClient, self).__init__(async, sender)

    # noinspection PyUnusedLocal
    def shutdown(self, mac, async=False):
        return self._send_agent_rpc(mac, AgentRequest.SHUTDOWN)

    # noinspection PyUnusedLocal
    def drain(self, mac, async=False):
        return self._send_agent_rpc(mac, AgentRequest.DRAIN)

    # noinspection PyUnusedLocal
    def undrain(self, mac, async=False):
        return self._send_agent_rpc(mac, AgentRequest.UNDRAIN)

    # noinspection PyUnusedLocal
    def ping(self, mac, async=False):
        return self._send_agent_rpc(mac, AgentRequest.PING)

    # noinspection PyUnusedLocal
    def startservices(self, mac, async=False):
        return self._send_agent_rpc(mac, AgentRequest.START_SERVICES)

    # noinspection PyUnusedLocal
    def stopservices(self, mac, async=False):
        return self._send_agent_rpc(mac, AgentRequest.STOP_SERVICES)
