import apscheduler
import apscheduler.scheduler
import datetime
import hashlib
import libvirt
import logging
import lxml
import lxml.etree
import os
import pprint
import subprocess
import time
import threading
import uuid

from assemblyline.common import net
from assemblyline.common.exceptions import ConfigException
from assemblyline.al.core.agents import ServiceAgentClient
from assemblyline.al.common import forge, queue
from assemblyline.al.common.hosts import DEFAULT_REGISTRATION
from random import randint

config = forge.get_config()

TEMPLATE_XP = 'winxp'
TEMPLATE_2K8 = 'win2k8'
TEMPLATE_PRECISE = 'ubuntuprecise'
SPECIFIC_TEMPLATES = [TEMPLATE_XP, TEMPLATE_2K8, TEMPLATE_PRECISE]
DATABASE_NUM = 3

VM_DISK_PATH_PREFIX = 'vm/disks/'

log = logging.getLogger('assemblyline.vmm')


class State(object):
    INIT = 'init'
    STARTING = 'starting'
    RUNNING = 'running'
    DRAINING = 'drain'
    DRAINED = 'drain'


def get_backing_file(disk_filename):
    img_info = subprocess.check_output(['qemu-img', 'info', disk_filename])
    for line in img_info.splitlines():
        if line.startswith('backing file'):
            tokens = line.split()
            return os.path.basename(tokens[2])


def get_mac_for_serviceinstance(servicename, seperator=':'):
    """ servicename is of form Name.Instance """
    hostip = net.get_hostip()
    hostbyte = int(hostip.split('.')[-1])
    name, instance = servicename.split('.')
    md5hex = hashlib.md5(name).hexdigest()
    service_byte1 = int(md5hex[:2], 16)
    service_byte2 = int(md5hex[2:4], 16)
    mac = [0x52, 0x54, hostbyte, service_byte1, service_byte2, int(instance)]
    return seperator.join("%02x" % x for x in mac).upper()


def update_hosts_file(qcow_path, hostname, ip):
    # Launch guest fs wrapper of the drive.
    import guestfs

    log.info('patching disk to direct %s to %s', hostname, ip)
    g = guestfs.GuestFS(python_return_dict=True)
    g.add_drive(filename=qcow_path, format='qcow2')
    g.launch()

    # Get a list of paritions that contain an operating system.
    # We should really only ever see one OS parition with our drives.
    # If there is more than one, fail early.
    os_partitions = g.inspect_os()
    if len(os_partitions) != 1:
        raise Exception("More than 1 OS partition detected")

    # Mount the os parition in guestfs
    rootpart = os_partitions[0]
    g.mount(rootpart, '/')

    linux_path = '/etc/hosts'
    win_path = '/Windows/System32/drivers/etc/hosts'
    winxp_path = '/WINDOWS/system32/drivers/etc/hosts'

    if g.exists(linux_path):
        linesep = '\n'
        hosts_filepath = linux_path
    elif g.exists(win_path):
        linesep = '\r\n'
        hosts_filepath = win_path
    elif g.exists(winxp_path):
        linesep = '\r\n'
        hosts_filepath = winxp_path
    else:
        raise Exception("Could not find a hosts file on this disk.")

    # Read the hosts file. This raises RuntimeError if it does not exist.
    orig_hosts_content = g.read_file(hosts_filepath)
    logging.debug('original hosts:\n%s', orig_hosts_content)

    host_found = False
    lines = orig_hosts_content.splitlines()
    # search for an existing entry for this hostname.
    for i in range(0, len(lines)):
        if not lines[i]:
            continue
        this_hostname = lines[i].split()[-1]
        if this_hostname == hostname:
            # existing entry for this host. overwrite in place with updated ip.
            host_found = True
            lines[i] = '%s %s' % (ip, hostname)

    if not host_found:
        # there was no existing entry for this host. append a new entry for it.
        lines.append('%s %s' % (ip, hostname))

    new_hosts_content = linesep.join(lines)
    logging.debug('writing:\n%s', new_hosts_content)
    g.write_file(hosts_filepath, new_hosts_content, 0)
    g.close()


def vm_tuple_to_str(name, instance):
    return name + "." + str(instance)


def vm_str_to_tuple(name):
    return name.split('.')


def get_mac_from_xml(xml):
    domain_root = lxml.etree.fromstring(xml)
    mac_node = domain_root.find('.//devices/interface[@type="network"]/mac')
    return mac_node.attrib['address']


def build_xml_for_machine(os_type, vmtype, name, num_cpu, memory_mb, backing_disk, mac_address=None, vm_uuid=None):

    if vmtype not in SPECIFIC_TEMPLATES:
        template_path = os.path.join(os.path.dirname(__file__), './vmxml/', "default_%s.xml" % os_type)
    else:
        template_path = os.path.join(os.path.dirname(__file__), './vmxml/', "%s.xml" % vmtype)

    template_xmlstring = open(template_path, 'r').read()

    domain_root = lxml.etree.fromstring(template_xmlstring)
    domain_root.find('name').text = name
    domain_root.find('uuid').text = vm_uuid or str(uuid.uuid4())
    domain_root.find('memory').text = str(memory_mb)
    domain_root.find('vcpu').text = str(num_cpu)

    disk_source = domain_root.find('.//devices/disk/source')
    disk_source.attrib['file'] = backing_disk

    mac_node = domain_root.find('.//devices/interface[@type="network"]/mac')
    mac_node.attrib['address'] = mac_address

    return lxml.etree.tostring(domain_root)


def get_vmcfg_for_localhost():
    ip = net.get_hostip()
    mac = net.get_mac_for_ip(ip)
    store = forge.get_datastore()
    host_registration = store.get_node(mac)
    if not host_registration:
        raise ConfigException('Could not find host registration fr %s' % mac)

    profile_name = host_registration.get('profile', None)
    if not profile_name:
        raise ConfigException('Could not find profile for host: %s' % mac)

    host_profile = store.get_profile(profile_name)
    if not host_profile:
        raise ConfigException('Could not fetch host profile %s' % profile_name)

    vm_config = host_profile.get('virtual_machines', None)
    if not vm_config:
        raise ConfigException('Could not find virtual machine section in %s' % profile_name)
    store.client.close()
    return vm_config


class VmManager(object):

    def __init__(self, vmcfg=None):
        self.disk_root = config.workers.virtualmachines.disk_root
        if not os.path.exists(self.disk_root):
            os.makedirs(self.disk_root)
        self.vmm = None
        self.cfg = vmcfg
        if vmcfg is None:
            self.cfg = get_vmcfg_for_localhost()
        self.vmrevert_scheduler = None
        self.host_ip = net.get_hostip()
        self.host_mac = net.get_mac_for_ip(self.host_ip)
        self.log = logging.getLogger('assemblyline.vmm')
        self.vm_profiles = {}
        self.vmm_lock = threading.Lock()
        self._state = State.INIT
        self._hostagent_client = ServiceAgentClient(async=True)
        self.store = forge.get_datastore()
        self.vm_configs = {}

    def _local_path_for_disk_url(self, url):
        return os.path.join(self.disk_root, os.path.basename(url))

    def list_required_disks(self):
        """Does not need to be started."""
        required = []
        for vm_name in self.cfg.keys():
            vm_profile = self.store.get_virtualmachine(vm_name)
            disk_url = vm_profile.get('virtual_disk_url')
            if not disk_url:
                self.log.error("No disk_url for vm profile: %s", vm_name)
                continue
            disk_filename = disk_url.rpartition('/')[-1]
            if not disk_filename:
                self.log.error("Could not determine filename for url: %s", disk_url)
                continue

            local_disk_path = self._local_path_for_disk_url(disk_url)
            if not local_disk_path:
                self.log.error("Could not determine local path for url: %s", disk_url)
                continue

            if os.path.getsize(local_disk_path) == 0:
                self.log.info("Removing empty disk before download: %s", local_disk_path)
                os.remove(local_disk_path)

            if os.path.exists(local_disk_path):
                self.log.info("Disk already exists. Skipping %s", local_disk_path)
                continue

            required.append(disk_filename)
        return required

    def sysprep(self):
        self.prep_disks()

    def _fetch_disk(self, disk_url):
        transport = forge.get_support_filestore()
        local_disk_path = self._local_path_for_disk_url(disk_url)
        if not local_disk_path:
            raise Exception("Could not determine local path for url: %s" % disk_url)

        if os.path.exists(local_disk_path):
            self.log.info("Disk already exists. Skipping %s", local_disk_path)
            return local_disk_path

        self.log.warn("DOWNLOADING LARGE DISK (%s). THIS MAY TAKE A WHILE", local_disk_path)
        try:
            transport.download(os.path.join(VM_DISK_PATH_PREFIX, disk_url), local_disk_path)
        except Exception, e:  # pylint: disable=W0703
            self.log.error("Could not download disk: %s (%s)", disk_url, str(e))
            # noinspection PyBroadException
            try:
                os.unlink(local_disk_path)
            except:
                pass

        return local_disk_path

    def prep_disks(self):

        for vm_name in self.cfg.keys():
            vm_profile = self.store.get_virtualmachine(vm_name)
            if not vm_profile:
                raise Exception("No profile found for %s" % vm_name)

            disk_url = os.path.basename(vm_profile.get('virtual_disk_url'))
            if not disk_url:
                self.log.error("No disk_url for vm profile: %s", vm_name)
                continue
            disk_filename = disk_url.rpartition('/')[-1]
            if not disk_filename:
                self.log.error("Could not determine filename for url: %s", disk_url)
                continue

            # Fetch up to 4 disks deep... we could go full recursive but lets
            # keep it simple and enforce a sane ancestry.
            local_disk_path = self._fetch_disk(disk_url)
            parent = get_backing_file(local_disk_path)
            if parent:
                parent_path = self._fetch_disk(parent)
                gparent = get_backing_file(parent_path)
                if gparent:
                    gparent_path = self._fetch_disk(gparent)
                    ggparent = get_backing_file(gparent_path)
                    if ggparent:
                        ggparent_path = self._fetch_disk(ggparent)
                        gggparent = get_backing_file(ggparent_path)
                        if gggparent and not os.path.exists(gggparent):
                            raise Exception("Not fetching g.g.g.grandparent for disk: {}. Cleanup your disks.")

    def drain(self):
        self.log.info("VmManager drain (%s:%s).", self.host_ip, self.host_mac)
        return self.shutdown()

    def undrain(self):
        self.log.info("VmManager undrain (%s:%s).", self.host_ip, self.host_mac)
        return self.start()

    def start(self):
        self._state = State.STARTING
        self.log.info("VmManager starting on (%s:%s).", self.host_ip, self.host_mac)
        with self.vmm_lock:
            self.vmm = libvirt.open(None)
            self.vmrevert_scheduler = apscheduler.scheduler.Scheduler()
            self.store = forge.get_datastore()

            # clean any state that might be left from previous run.
            self._destroy_all()

            # install and start vms
            self._reconcile_config()
            self.log.info("Starting all instances.")
            self._start_all()
            self._schedule_automatic_reverts()
            self._state = State.RUNNING

    def shutdown(self):
        self._state = State.DRAINING
        with self.vmm_lock:
            if self.vmrevert_scheduler:
                self.vmrevert_scheduler.shutdown()
                self.vmrevert_scheduler = None
            self._shutdown_all()
            self._destroy_all()
            if self.vmm:
                self.vmm.close()
                self.vmm = None
            self.log.info("Closing vmm connection")
        self._state = State.DRAINED
        self.store.client.close()
        self.store = None

    def _get_msg_args_by_name(self, msg, arglist):
        if not msg or not msg.get('body', None):
            raise Exception("Invalid msg")
        argdict = msg.get('body')
        try:
            params = [argdict[x] for x in arglist]
        except KeyError:
            self.log.error("Missing one or more params for %s", msg.mtype)
            raise
        return params

    def _get_instances_for_fleet(self, fleet):
        instances = set()
        vmconfig = self.cfg.get(fleet, None)
        if not vmconfig:
            self.log.warn("Missing profile for virtual machine: %s. Skipping.", fleet)
            return instances
        num_instances = vmconfig.get('num_instances')
        for i in range(1, num_instances + 1):
            instance_name = vm_tuple_to_str(fleet, i)
            instances.add(instance_name)
        return instances

    def get_stats(self):
        vm_info = {}
        with self.vmm_lock:
            if not self.vmm:
                return None

            for vm in self.vmm.listAllDomains():
                vm_details = {'mac_address': get_mac_from_xml(vm.XMLDesc()).replace(':', '').upper()}
                # This is relatively expensive way of getting the mac
                # but it is the 'truest' source. Use this approach for now.
                vm_info[vm.name()] = vm_details
            return vm_info

    def pre_registration(self, name, mac, service, num_workers):
        self.log.info('preregistering VM: %s mac:%s service:%s host:%s.' % (name, mac, service, self.host_mac))
        reg = DEFAULT_REGISTRATION.copy()
        reg['hostname'] = name
        reg['mac_address'] = mac
        reg['is_vm'] = True
        reg['vm_host'] = self.host_ip
        reg['vm_host_mac'] = self.host_mac
        reg['profile'] = service
        reg['profile_definition'] = {
            'services': {
                service: {
                    'workers': num_workers,
                    'service_overrides': {}
                }
            }
        }
        reg['roles'] = ["hostagent"]
        if config.workers.virtualmachines.use_parent_as_datastore or config.workers.virtualmachines.use_parent_as_queue:
            reg['config_overrides'] = {'parent_ip': self.host_ip}

        vm_queue = queue.NamedQueue('vm-%s' % mac, db=DATABASE_NUM)
        vm_queue.delete()
        vm_queue.push(reg)

    @classmethod
    def virt_install(cls, os_type, template, name, vcpus, ram, disk, mac):
        fname = '/tmp/' + name + '.xml'
        try:
            machine_xml = build_xml_for_machine(os_type, template, name, vcpus, ram, disk, mac)
            open(fname, 'w').write(machine_xml)
            install_result = subprocess.check_output(['virsh', 'define', fname], stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as se:
            log.error("Install Failed: %s", se.output)
            return

        # noinspection PyBroadException
        try:
            os.unlink(fname)
        except:  # pylint:disable=W0702
            pass

        log.info("Install Result: %s", install_result.strip())

    def _install_missing(self, missing):
        for name in missing:
            self.log.info('Installing VM: %s', name)
            vprof = self.vm_profiles[name]
            cpu = vprof['vcpus']
            ram = vprof['ram']
            os_type = vprof['os_type']
            variant = vprof['os_variant']
            disk = os.path.join(self.disk_root, vprof.get('virtual_disk_url', "").rpartition('/')[-1])
            if not os.path.isfile(disk):
                raise ConfigException('Missing disk for this vm (%s). Run vm_disk --sync.' % disk)
            mac = get_mac_for_serviceinstance(name)
            # noinspection PyBroadException
            try:
                self.virt_install(os_type, variant, name, cpu, ram, disk, mac)
                reg_mac = mac.replace(':', '').upper()
                self.pre_registration(name, reg_mac, vprof['name'], vprof['num_workers'])
            except:
                self.log.exception("While installing VM: %s", name)

    def _get_instances_for_fleets(self):
        instances = set()
        for fleet in self.cfg.iterkeys():
            instances.update(self._get_instances_for_fleet(fleet))
        return instances

    def _start_all(self):
        for vm in self.vmm.listAllDomains():
            if not vm.isActive():
                vm.create()

    def _destroy_all(self):
        self.log.info("Destroying any old instances.")
        for vm in self.vmm.listAllDomains():
            if vm.isActive():
                vm.destroy()
            vm.undefine()

    def _shutdown_all(self):
        if self.vmm:
            for vm in self.vmm.listAllDomains():
                if vm.isActive():
                    mac = self._get_mac_for_instance(vm.name())
                    self.log.info("Not sending drain to VM: %s at %s", vm.name(), mac)

            time.sleep(2)
            for vm in self.vmm.listAllDomains():
                try:
                    self.log.info("Sending acpi shutdown to VM: %s", vm.name())
                    vm.shutdown()
                except Exception as lve:
                    if 'domain is not running' not in lve.message:
                        self.log.exception('while shutting down a vm')

    def _stop_all(self):
        stopped = []
        already_stopped = []
        for vm in self.vmm.listAllDomains():
            name = vm.name
            if vm.isActive():
                stopped.append(name)
                vm.destroy()
            else:
                already_stopped.append(name)
        return {'stopped': stopped, 'already_stopped': already_stopped}

    def _reconcile_config(self):
        self.log.info("reconciling")
        expected = set()

        # Determine which VMs we should be running.
        configured_vms = self.cfg
        for name, cfg in configured_vms.iteritems():
            vmprofile = self.store.get_virtualmachine(name)
            if not vmprofile:
                self.log.warn("Missing profile for virtual machine: %s. Skipping.", name)
                continue
            num_instances = cfg['num_instances']
            for i in range(1, num_instances + 1):
                instance_name = vm_tuple_to_str(name, i)
                expected.add(instance_name)
                self.vm_profiles[instance_name] = vmprofile

        # Destroy and VMs which are no longer configured for this host.
        for vm in self.vmm.listAllDomains():
            if vm.name() not in expected:
                if vm.isActive():
                    vm.destroy()
                vm.undefine()

        # Install VMs.
        pretty_cfg = pprint.pformat(self.cfg)
        self.log.info('Pretty Config: %s', pretty_cfg)
        self._install_missing(expected)

    def _schedule_automatic_reverts(self):
        for fleet in self.cfg.iterkeys():
            cfg = self.store.get_virtualmachine(fleet)
            revert_secs = cfg.get('revert_every', 0)
            if not revert_secs:
                self.log.warn('no autorevert schedule for %s (%s)', fleet, revert_secs)
                continue
            if revert_secs < 600:
                self.log.error('ignoring overly agressive revert schedule for %s (%s)', fleet, revert_secs)
                revert_secs = 600
            # apply a random jitter to the restart interval so there is less change all fleets across
            # the cluster revert at the same time.
            jitter = randint(0, 300)
            self.log.debug('Adding revert for %s every %s seconds', fleet, revert_secs)
            self.vmrevert_scheduler.add_interval_job(
                self._respawn_fleet,
                seconds=revert_secs + jitter,
                kwargs={'fleet': fleet})

        self.vmrevert_scheduler.start()

    def get_revert_times(self):
        upcoming = {}
        revert_jobs = self.vmrevert_scheduler.get_jobs()
        now = datetime.datetime.now()
        for job in revert_jobs:
            fleet_name = job.kwargs.get('fleet')
            tdelta = job.next_run_time - now
            seconds_until_revert = int(tdelta.total_seconds())
            upcoming[fleet_name] = seconds_until_revert
        return upcoming

    def _reconcile_config_fleet(self, fleet):
        self.log.info("reconciling")
        expected = set()
        self.vm_configs = {}

        # Determine which VMs we should be running.
        configured_vms = get_vmcfg_for_localhost()
        if fleet not in configured_vms:
            return "deleted"

        cfg = configured_vms[fleet]
        vmprofile = self.store.get_virtualmachine(fleet)
        if not vmprofile:
            self.log.warn("Missing profile for virtual machine: %s. Skipping.", fleet)
            return
        num_instances = cfg['num_instances']
        for i in range(1, num_instances + 1):
            instance_name = vm_tuple_to_str(fleet, i)
            self.log.info('Adding %s', instance_name)
            expected.add(instance_name)
            self.vm_configs[instance_name] = vmprofile

        # Destroy and VMs in this fleet (to be refreshed)
        for vm in self.vmm.listAllDomains():
            if vm.name() in expected:
                if vm.isActive():
                    vm.destroy()
                vm.undefine()

        # Install VMs.
        self._install_missing(expected)

    def _respawn_fleet(self, fleet):
        with self.vmm_lock:
            self.log.info('autoreverting: %s', fleet)
            self.refresh_fleet(fleet)

    def _get_mac_for_instance(self, vmname, format_for_al=True):
        vm = self.vmm.lookupByName(vmname)
        vm_xml = vm.XMLDesc()
        mac = get_mac_from_xml(vm_xml)
        if format_for_al:
            mac = mac.replace(':', '').upper()
        return mac

    def stop_all(self):
        return self._stop_all()

    def list_vms(self):
        return [vm.name() for vm in self.vmm.listAllDomains()]

    def refresh_all(self):
        self._reconcile_config()
        self._start_all()

    def refresh_fleet(self, fleet):
        self._reconcile_config_fleet(fleet)
        self._start_all()

    def restart_vm(self, instance_name):
        self.stop_vm(instance_name)
        self.start_vm(instance_name)
        return {'vm_name': instance_name,
                'vm_mac': self._get_mac_for_instance(instance_name)}

    def start_vm(self, instance_name):
        vm = self.vmm.lookupByName(instance_name)
        if not vm.isActive():
            vm.create()  # create is 'start' in libvirt speak.
        return {'vm_name': instance_name,
                'vm_mac': self._get_mac_for_instance(instance_name)}

    def stop_vm(self, instance_name):
        vm = self.vmm.lookupByName(instance_name)
        mac = self._get_mac_for_instance(instance_name)
        if vm.isActive():
            vm.destroy()
        return {'vm_name': instance_name,
                'vm_mac': mac}
