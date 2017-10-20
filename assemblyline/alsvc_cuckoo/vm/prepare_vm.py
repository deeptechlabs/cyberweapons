#!/usr/bin/python

import argparse
import guestfs
import jinja2
import libvirt
import logging
import lxml
import lxml.etree
import os
import shlex
import subprocess
import tempfile
import time
import uuid
import json
import traceback
from assemblyline.al.common import forge

# VM Preparation -- a poor man's vmcloak ;)
#
# Instead of instrumenting a full windows install, this script assumes that you have a
# working VM that will execute a RunOnce on C:\bootstrap.bat (we will handle the file upload).
#
# 1.    Our bootstrap file is uploaded to C:\bootstrap.bat, using the configuration options specified
# 2.    The vm is booted, bootstrapped, and then shut down.
# 3.    The vm is booted, a snapshot is taken, and then shut down.
# 4.    Configuration is generated (disk xml, snapshot xml, metadata)
# 5.    Done!
#
# Yes, vmcloak looks great, but would require some modification for Windows 7 and libvirt,
# so this will have to do for now.


class PrepareVM:
    class VMPrepException(Exception):
        pass

    def _run_cmd(self, command, raise_on_error=True):
        self.log.info("Running shell command: %s", command)
        arg_list = shlex.split(command)
        proc = subprocess.Popen(arg_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        if stderr and raise_on_error:
            raise self.VMPrepException(stderr)
        return stdout

    def _upload_file(self, contents, guest_disk_path, guest_disk_format, dest_filename):
        self.log.info("Uploading file -- disk: %s -- path: %s", guest_disk_path, dest_filename)
        dest_filepath = "/"
        dest_filename = dest_filename

        g = guestfs.GuestFS(python_return_dict=True)
        g.add_drive(filename=guest_disk_path, format=guest_disk_format)
        g.launch()
        # Get a list of partitions that contain an operating system.
        # We should really only ever see one OS partition with our drives.
        # If there is more than one, fail early.
        os_partitions = g.inspect_os()
        if len(os_partitions) != 1:
            raise self.VMPrepException("More than one OS partition detected.. This isn't supported!")

        # Mount the os partition in guestfs
        rootpart = os_partitions[0]
        g.mount(rootpart, dest_filepath)
        with tempfile.NamedTemporaryFile() as out_file:
            out_file.write(contents)
            out_file.flush()
            g.upload(out_file.name, dest_filename)
        g.sync()
        g.umount_all()

    def _purge_domain(self, domain):
        self.log.info("Purging snapshot, domain definition and disk images for %s", domain)
        dom = self.lv.lookupByName(domain)
        # Get the disk
        dom_root = lxml.etree.fromstring(dom.XMLDesc())
        dom_disk = dom_root.find("./devices/disk/source").attrib['file']
        if dom.state()[0] not in [libvirt.VIR_DOMAIN_SHUTDOWN, libvirt.VIR_DOMAIN_SHUTOFF]:
            try:
                dom.destroy()
            except libvirt.libvirtError:
                self.log.error("Unable to destroy inactive domain. Manually power off and retry.")
                raise

        # Remove snapshots first
        for snapshot in dom.listAllSnapshots():
            snapshot_del_cmd = "virsh snapshot-delete %s %s" % (domain, snapshot.getName())
            self._run_cmd(snapshot_del_cmd)

        # Undefine the domain
        dom.undefine()

        # Delete the disk
        disk_del_cmd = "virsh vol-delete --pool default %s" % dom_disk
        self._run_cmd(disk_del_cmd, raise_on_error=False)
        if os.path.exists(dom_disk):
            os.remove(dom_disk)

        self.log.info("Domain %s has been purged", domain)

    def parse_args(self):
        USAGE = "Snapshot Creator (for container-based malware analysis)"
        VERSION = "0.1"

        # Command-line arguments for the whole deployment.
        parser = argparse.ArgumentParser(usage=USAGE, version=VERSION)
        parser.add_argument('--domain', action='store', help="Existing libvirt domain to prepare",
                            dest='domain', required=True)
        parser.add_argument('--platform', action='store', help="Guest OS platform (windows,linux)",
                            dest='platform', required=True)
        parser.add_argument('--name', action='store', help="Output snapshot name",
                            default="snapshot", dest='snapshot_name', required=True)
        parser.add_argument('--hostname', action='store', help="Guest hostname",
                            dest='hostname', required=True)
        parser.add_argument('--tags', action='store', help="Comma-separated list of tags describing the vm",
                            dest='tags', required=True)
        parser.add_argument('--force', action='store_true',
                            help="Force creation of the new domain (will delete existing domain)",
                            dest='force', required=False)
        parser.add_argument('--base', action='store', help="VM Base (lowest layer) i.e. Win7SP1x86",
                            dest='base', required=True)
        parser.add_argument('--guest_profile', action='store', help="Volatility guest profile, i.e. Win7SP1x86",
                            dest='guest_profile', required=True)
        parser.add_argument('--template', action='store',
                            help="Bootstrap template, either win7 or linux (or unsupported win10)",
                            dest='template', required=True)
        parser.add_argument('--ordinal', action='store',
                            help="A unique number between 1 and 32000",
                            dest='ordinal', required=True)
        parser.add_argument('--route', action='store',
                            help="One of the following values: inetsim, gateway",
                            dest='route', required=True)

        args = parser.parse_args()

        # Validate ordinal
        args.ordinal = int(args.ordinal)
        if 1 > args.ordinal or 32000 < args.ordinal:
            self.log.error("Ordinal out of range")
            exit(7)

        # Validate route, inetsim is built in
        enabled_routes = ['inetsim']

        for param in forge.get_datastore().get_service(self.SERVICE_NAME)['submission_params']:
            if param['name'] == "routing":
                enabled_routes = param['list']

        if not isinstance(enabled_routes, list):
            self.log.error("No routing submission_parameter.")
            exit(7)

        if args.route not in enabled_routes:
            self.log.error("Invalid route, must be one of %s", ", ".join(enabled_routes))
            exit(7)

        ip_net = "10.%i.%i.%%i" % (args.ordinal / 256, args.ordinal % 256)

        args.vm_ip = ip_net % 100
        args.vm_gateway = ip_net % 1
        args.vm_fakenet = ip_net % 10
        args.netmask = "255.255.255.0"
        args.vm_network = ip_net % 0
        args.dns = "8.8.8.8"
        self.args = args

    def __init__(self):
        self.args = None
        self.log = logging.getLogger()
        self.log.setLevel(logging.DEBUG)
        sh = logging.StreamHandler()
        fmt = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        sh.setFormatter(fmt)
        self.log.addHandler(sh)
        self.SERVICE_NAME = "Cuckoo"

        if os.geteuid() != 0:
            self.log.error("root privileges required to run this script..")
            exit(-1)

        if "__file__" in globals():
            self.SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
        else:
            self.SCRIPT_DIR = os.getcwd()
        self.TEMPLATE_BASE = os.path.join(self.SCRIPT_DIR, 'templates')

        self.lv = None
        last_exception = None
        for i in xrange(3):
            try:
                self.lv = libvirt.open(None)
                if self.lv is not None:
                    break
            except:
                last_exception = traceback.format_exc()
            time.sleep(3)

        if self.lv is None:
            raise self.VMPrepException("Unable to acquire libvirt connection.. this is fatal:\n%s" % last_exception)

    def render_bootstrap_files(self, template, context):
        template_path = os.path.join(self.TEMPLATE_BASE, "bootstrap_%s_template.json" % template)
        if not os.path.exists(template_path):
            raise IOError("No such template path %s" % template_path)

        _t = json.load(open(template_path))
        timeout = int(_t.get("timeout", 60))
        files_out = {}
        for fname, v in _t.get("files", {}).iteritems():
            if "contents" in v:
                contents = v['contents']
                contents = "%s\n" % "\n".join(contents)
            if v.get("render", False):
                contents = jinja2.Environment().from_string(contents).render(context)
            files_out[fname] = contents

        return timeout, files_out

    def render_vm_meta(self, context):
        meta_path = os.path.join(self.TEMPLATE_BASE, "meta_template.jinja2")
        with open(meta_path) as fh:
            tm = jinja2.Environment().from_string(fh.read())
            return tm.render(context)

    def validate_domain(self, domain, snapshot_name, force):
        dom = self.lv.lookupByName(domain)
        # Make sure the domain we're going to snapshot exists
        if not dom:
            raise self.VMPrepException("Domain %s was not found.." % domain)

        # Make sure the domain we're creating doesn't exist, or delete it if force=True
        if snapshot_name in self.lv.listDefinedDomains():
            if force is True:
                self._purge_domain(snapshot_name)
            else:
                raise self.VMPrepException("The specified snapshot domain name already exists: %s. If you want to "
                                           "destroy this domain, the corresponding snapshots and the disk image, "
                                           "re-run this script with the --force flag" % snapshot_name)
        else:
            self.log.debug("Snapshot %s not in domain list %s" % (snapshot_name, self.lv.listDefinedDomains()))
        return dom

    def prepare_vm(self):
        if self.args is None:
            self.log.error("prepare_vm arguments not set")
            exit(7)
        self.log.info("VMPREP initiated for snapshot: %s -- domain: %s", self.args.snapshot_name, self.args.domain)
        self.log.info("VM Data: ip:%s, gateway:%s, netmask:%s, hostname:%s, dns:%s, platform:%s, tags:%s",
                      self.args.vm_ip, self.args.vm_gateway, self.args.netmask, self.args.hostname, self.args.dns,
                      self.args.platform, self.args.tags)

        dom = self.validate_domain(self.args.domain, self.args.snapshot_name, self.args.force)

        domain_root = lxml.etree.fromstring(dom.XMLDesc())
        backing_disk = domain_root.find("./devices/disk/source").attrib['file']
        disk_driver = domain_root.find("./devices/disk/driver").attrib['type']

        if backing_disk is None:
            raise self.VMPrepException("Unable to find any disks.. cannot use a domain with no disk!")

        # Extend the disk
        snapshot_dir = os.path.split(backing_disk)[0]
        snapshot_disk_name = "%s.%s" % (self.args.snapshot_name, disk_driver)
        snapshot_disk = os.path.join(snapshot_dir, snapshot_disk_name)
        qemu_cmd = 'qemu-img create -b %s -f %s %s' % (backing_disk, disk_driver, snapshot_disk)
        self._run_cmd(qemu_cmd)

        # Upload the bootstrap file
        bootstrap_context = {
            "ip":       self.args.vm_ip,
            "gateway":  self.args.vm_gateway,
            "netmask":  self.args.netmask,
            "hostname": self.args.hostname,
            "dns_ip":   self.args.dns,
        }

        timeout, file_list = self.render_bootstrap_files(self.args.template, bootstrap_context)

        for fname, contents in file_list.iteritems():
            self._upload_file(contents, snapshot_disk, disk_driver, fname)

        # Create the snapshot disk's xml file from the base disk's xml, then use it to define a new domain.
        disk_name = domain_root.find("./name")
        disk_uuid = domain_root.find("./uuid")
        disk_root = domain_root.find("./devices/disk/source")
        disk_name.text = self.args.snapshot_name
        disk_uuid.text = str(uuid.uuid4())
        disk_root.attrib['file'] = snapshot_disk
        snapshot_xml = lxml.etree.tostring(domain_root)
        snapshot_domain = self.lv.defineXML(snapshot_xml)
        snapshot_xml_filename = "%s.xml" % self.args.snapshot_name

        # Boot the new domain, and wait until it powers off (then we know bootstrapping completed)
        self.log.info("Bootstrapping snapshot domain: %s (%d second timeout)", self.args.snapshot_name, timeout)
        snapshot_domain.create()
        waited = 0
        max_wait = timeout
        while snapshot_domain.state()[0] != libvirt.VIR_DOMAIN_SHUTOFF:
            time.sleep(2)
            waited += 2
            if waited >= max_wait:
                raise self.VMPrepException("Domain %s did not shut down within timeout. "
                                           "Bootstrapping failed." % self.args.snapshot_name)

        # Reboot the bootstrapped domain and take a snapshot
        self.log.info("Rebooting domain %s to take snapshot.. (approximately %d seconds)", self.args.snapshot_name, timeout)
        time.sleep(5)
        snapshot_domain.create()
        time.sleep(timeout)
        # Using virsh here is just plain easier than creating snapshot xml..
        self._run_cmd("virsh snapshot-create %s" % self.args.snapshot_name)
        snapshot_snap_xml = snapshot_domain.snapshotCurrent().getXMLDesc()
        snapshot_snap_xml_filename = "%s_snapshot.xml" % self.args.snapshot_name

        # Poweroff the snapshot domain
        snapshot_domain.destroy()

        # Populate the snapshot metadata
        metadata_context = {
            "name":     self.args.snapshot_name,
            "base":     self.args.base,
            "disk":     snapshot_disk_name,
            "xml":      snapshot_xml_filename,
            "snapshot_xml": snapshot_snap_xml_filename,
            "ip":       self.args.vm_ip,
            "netmask":  self.args.netmask,
            "network":  self.args.vm_network,
            "fakenet":  self.args.vm_fakenet,
            "gateway":  self.args.vm_gateway,
            "tags":     self.args.tags,
            "platform": self.args.platform,
            "guest_profile": self.args.guest_profile,
            "route":    self.args.route
        }

        metadata = self.render_vm_meta(metadata_context)
        self.log.info("Metadata template: %s", metadata)

        # Dump the files needed to import this domain as-is somewhere else:
        meta_dir = os.path.join(self.SCRIPT_DIR, self.args.snapshot_name)
        if not os.path.exists(meta_dir):
            os.mkdir(meta_dir)
        if not os.path.isdir(meta_dir):
            tmp_dir = tempfile.mkdtemp(suffix=meta_dir)
            self.log.warning("Can't write metadata to %s, writing to %s instead", meta_dir, tmp_dir)
            meta_dir = tmp_dir
        snap_domain_xml_path = os.path.join(meta_dir, "%s.xml" % self.args.snapshot_name)
        with open(snap_domain_xml_path, 'w') as fh:
            fh.write(snapshot_xml)
        snap_domain_snapshot_xml_path = os.path.join(meta_dir, "%s_snapshot.xml" % self.args.snapshot_name)
        with open(snap_domain_snapshot_xml_path, 'w') as fh:
            fh.write(snapshot_snap_xml)
        snap_metadata_path = os.path.join(meta_dir, "%s_meta.json" % self.args.snapshot_name)
        with open(snap_metadata_path, 'w') as fh:
            fh.write(metadata)

        # Tar up the directory..
        self._run_cmd("tar -C %s -zcvf %s.tar.gz %s" % (self.SCRIPT_DIR, self.args.snapshot_name,
                                                        self.args.snapshot_name))
        self.log.info("Successfully prepared domain %s for sandbox.." % self.args.snapshot_name)

if __name__ == "__main__":
    pv = PrepareVM()
    pv.parse_args()
    pv.prepare_vm()
