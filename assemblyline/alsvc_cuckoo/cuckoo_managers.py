import json
import logging
import os
from os.path import join
import subprocess

from assemblyline.common.docker import DockerException, DockerManager
from assemblyline.al.common import forge

config = forge.get_config()


class CuckooContainerManager(DockerManager):
    def __init__(self, cfg, vmm):
        super(CuckooContainerManager, self).__init__('cuckoo', 'assemblyline.al.service.cuckoo.cm')

        ctx = {
            'image': cfg['cuckoo_image'],
            'privileged': True,
            'detatch': True,
            'caps': ['ALL'],
            'ram': cfg['ram_limit'],
            'volumes': [
                    (vmm.local_meta_root, "/opt/vm_meta", "ro"),
                    (vmm.local_vm_root, "/var/lib/libvirt/images", "ro")
                ],
            'commandline': [os.path.split(cfg['vm_meta'])[1], cfg['ramdisk_size']]
        }
        self.name = self.add_container(ctx)
        self.tag_map = self.parse_vm_meta(vmm.vm_meta)

    @staticmethod
    def parse_vm_meta(vm_meta):
        tag_set = {}
        for vm in vm_meta:
            if vm['route'] not in tag_set:
                tag_set[vm['route']] = {}
            vm_tags = vm['tags'].split(",")
            for tag in vm_tags:
                tag = tag
                if tag in tag_set[vm['route']]:
                    raise DockerException("Tag collision between %s and %s (tag: %s)." % (
                        vm['name'],
                        tag_set[vm['route']][tag],
                        tag
                        )
                    )
                tag_set[vm['route']][tag] = vm['name']
        return tag_set


class CuckooVmManager(object):
    def fetch_disk(self, disk_base, disk_url, recursion=4):
        if recursion == 0:
            raise DockerException("Disk fetch recursing too far for %s. Cleanup your disks." % disk_url)

        if not os.path.exists(join(config.workers.virtualmachines.disk_root, disk_base)):
            os.makedirs(join(config.workers.virtualmachines.disk_root, disk_base))

        local_disk_path = join(self.local_vm_root, disk_base, os.path.basename(disk_url))
        remote_disk_path = join(self.remote_root, disk_base, disk_url)

        if not os.path.exists(local_disk_path):
            self.log.warn("DOWNLOADING LARGE DISK (%s -> %s). THIS MAY TAKE A WHILE", remote_disk_path, local_disk_path)
            try:
                self.transport.download(remote_disk_path, local_disk_path)
            except:
                self.log.error("Could not download disk: %s", disk_url)
                os.unlink(local_disk_path)
                raise

        parent = self._get_backing_file(local_disk_path)
        if parent:
            self.fetch_disk(disk_base, parent, recursion-1)

    def download_xml(self, vm):
        local_meta_dir = self.local_meta_root
        if not os.path.exists(local_meta_dir):
            os.makedirs(local_meta_dir)

        self._fetch_meta(join(vm['name'], vm['xml']), local_meta_dir)
        self._fetch_meta(join(vm['name'], vm['snapshot_xml']), local_meta_dir)

    def __init__(self, cfg):
        self.log = logging.getLogger('assemblyline.svc.cuckoo.vmm')
        self.transport = forge.get_support_filestore()

        self.local_vm_root = join(config.workers.virtualmachines.disk_root, cfg['LOCAL_DISK_ROOT'])
        self.local_meta_root = join(config.system.root, cfg['LOCAL_VM_META_ROOT'])
        self.remote_root = cfg['REMOTE_DISK_ROOT']
        self.vm_meta_path = join(self.local_meta_root, cfg['vm_meta'])

        # Download Metadata
        self._fetch_meta(cfg['vm_meta'], self.local_meta_root)

        with open(self.vm_meta_path, 'r') as fh:
            self.vm_meta = json.load(fh)

        for vm in self.vm_meta:
            # Download VMs
            self.fetch_disk(vm['base'], vm['disk'])

            # Download VM XML
            self.download_xml(vm)

    def _fetch_meta(self, fname, local_path):
        remote_path = join(self.remote_root, fname)
        local_path = join(local_path, fname)
        try:
            self.transport.download(remote_path, local_path)
        except:
            self.log.exception("Unable to download metadata file %s:", remote_path)
            raise

        return local_path

    @staticmethod
    def _get_backing_file(disk_filename):
        img_info = subprocess.check_output(['qemu-img', 'info', disk_filename])
        for line in img_info.splitlines():
            if line.startswith('backing file'):
                tokens = line.split()
                return os.path.basename(tokens[2])
