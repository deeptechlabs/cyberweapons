#!/usr/bin/env python 
import sys
import libvirt
import logging
import lxml
import lxml.etree
import os
import subprocess

from assemblyline.al.common import forge
config = forge.get_config(static_seed=os.environ.get("VMEDIT_SEED", None))
from assemblyline.al.common import vm

QCOW2_EXT = 'qcow2'
LOCAL_VMDISK_ROOT = '/opt/al/var/masterdisks/'

log = logging.getLogger('assemblyline.al.vme')


class VmEditor(object):

    def __init__(self, vmname, cfg=None):
        self.ds = forge.get_datastore()
        self.vm_name = vmname + '.001'
        if cfg:
            self.vm_cfg = cfg.workers.virtualmachines.master_list.get(vmname, {}).get('cfg', None)
        else:
            self.vm_cfg = self.ds.get_virtualmachine(vmname)
        if not self.vm_cfg:
            raise Exception("Could not find VM %s in the seed" % vmname)
        self.vmm = libvirt.open(None)

    def install_launch_canary(self):
        # if currently running. close and wipe.
        # fetch disk and base disk. increment disk number by 1.
        # install vm without the qemu disk patch
        # launch
        # ... user configures
        # ...
        log.info("Destroying any existing instances of %s", self.vm_name)
        self._destroy_existing()
        log.info("Fetching an installing VM for %s", self.vm_name)
        self._fetch_install_canary()

    @staticmethod
    def __mutable_virt_install(os_type, template, vm_name, vcpus, ram, disk, mac):
        machine_xml = vm.build_xml_for_machine(os_type, template, vm_name, vcpus, ram, disk, mac)
        machine_root = lxml.etree.fromstring(machine_xml)
        # remove the qemu -snapshot option (so changes are permanent)
        qemu = machine_root.find('qemu:commandline', namespaces=machine_root.nsmap)
        qemu.getparent().remove(qemu)
        fname = '/tmp/' + vm_name + '.xml'
        open(fname, 'w').write(lxml.etree.tostring(machine_root))
        install_result = subprocess.check_output(['virsh', 'define', fname], stderr=subprocess.STDOUT)
        log.info("Install Result: %s", install_result.strip())

    def __fetch_disk(self):
        current_disk = self.vm_cfg['virtual_disk_url']
        diskpath_elems = current_disk.split('.')
        if len(diskpath_elems) < 3:
            raise Exception('Invalid disk url: %s. Expected "name.version.qcow2"' % current_disk)

        suffix = diskpath_elems[-1]
        version = diskpath_elems[-2]
        if not suffix == QCOW2_EXT:
            raise Exception('Invalid disk suffix: %s. Expected %s' % (suffix, QCOW2_EXT))
        
        try:
            version_i = int(version)
            next_version_i = version_i + 1
            if next_version_i > 999:
                raise ValueError('Too large')
        except ValueError:
            raise Exception('Invalid disk version. Expect 3 character decimal number. Found: %s' % version)

        newdisk_elems = diskpath_elems[0:-2]
        newdisk_elems.append('%03d' % next_version_i)
        newdisk_elems.append(QCOW2_EXT)
        new_disk = '.'.join(newdisk_elems)

        transport = forge.get_support_filestore()
        local_disk_path = os.path.join(LOCAL_VMDISK_ROOT, new_disk)
        remote_disk_path = os.path.join(vm.VM_DISK_PATH_PREFIX, current_disk)
        if os.path.exists(local_disk_path):
            log.warn('Removing existing disk: %s.', current_disk)
            os.unlink(local_disk_path)

        log.info('Copying %s -> %s for installation.', current_disk, new_disk)
        transport.download(remote_disk_path, local_disk_path)
        if os.path.getsize(local_disk_path) < 1024 * 1024:
            raise Exception('Impossibly small disk downloaded. Aborting. %s' % local_disk_path)

        backing_disk = vm.get_backing_file(local_disk_path)
        while backing_disk:
            local_backing_disk = os.path.join(LOCAL_VMDISK_ROOT, backing_disk)
            if not os.path.exists(local_backing_disk):
                remote_path = os.path.join(vm.VM_DISK_PATH_PREFIX, backing_disk)
                transport.download(remote_path, local_backing_disk)
                if os.path.getsize(local_backing_disk) < 1024 * 1024:
                    raise Exception('Impossibly small backing disk downloaded: %s' % local_backing_disk)
            backing_disk = vm.get_backing_file(local_backing_disk)

        return local_disk_path

    def _fetch_install_canary(self):
        vm_name = self.vm_name
        local_disk_path = self.__fetch_disk()
        cpus = self.vm_cfg['vcpus']
        ram = self.vm_cfg['ram']
        os_type = self.vm_cfg['os_type']
        variant = self.vm_cfg['os_variant']
        mac = vm.get_mac_for_serviceinstance(vm_name)
        self.__mutable_virt_install(os_type, variant, vm_name, cpus, ram, local_disk_path, mac)

    def _destroy_existing(self):
        try:
            cur_vm = self.vmm.lookupByName(self.vm_name)
            if cur_vm.isActive():
                cur_vm.destroy()
            cur_vm.undefine()
        except libvirt.libvirtError as lve:
            if 'Domain not found' in lve.get_error_message():
                # nothing to destroy
                return
            else: 
                raise


if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

    if len(sys.argv) < 2:
        print "You must specify a VM to pull the disk for...\n\nvmedit VM_NAME\n"
        exit(1)
    vme = VmEditor(sys.argv[1], config)
    vme.install_launch_canary()
