#!/usr/bin/python
import json
import os
import sys
import tarfile
import lxml.etree
import uuid

from assemblyline.al.common import forge
from assemblyline.al.common.importing import service_by_name


class CuckooPrepException(Exception):
    pass


def mod_json_meta(json_file, prepend):
    vm_name = "_".join([prepend, json_file['name']])
    out_xml_name = "_".join([prepend, json_file['xml']])
    out_snap_name = "_".join([prepend, json_file['snapshot_xml']])
    json_file = dict(json_file)
    json_file['name'] = vm_name
    json_file['snapshot_xml'] = out_snap_name
    json_file['xml'] = out_xml_name
    return vm_name, out_xml_name, out_snap_name, json_file


def trymkdir(path):
    if not os.path.exists(path):
        os.makedirs(path)


# noinspection PyUnresolvedReferences
def mod_xml_meta(xml_file, path, new_value):
    dom_root = lxml.etree.fromstring(xml_file)
    node = dom_root.find(path)
    if node is None:
        return xml_file

    if new_value is None:
        node.getparent().remove(node)
    else:
        node.text = new_value
    return lxml.etree.tostring(dom_root)


def install_vm_meta(directory, tarball, prefixes):
    vm_name = os.path.basename(tarball).split(".", 1)[0]

    tar = tarfile.open(tarball)
    try:
        json_file = tar.extractfile(tar.getmember(os.path.join(vm_name, "%s_meta.json" % vm_name)))
    except KeyError:
        print "Error, no json file."
        sys.exit(7)
    if json_file is None:
        print "Error, json file is not actually a file."
        sys.exit(7)

    json_file = json.load(json_file)
    trymkdir(os.path.join(directory, json_file['base']))

    for prefix in prefixes:
        new_vm_name, xml_name, snap_name, new_json_file = mod_json_meta(json_file, prefix)
        trymkdir(os.path.join(directory, new_vm_name))
        json_name = os.path.join(directory, new_vm_name, "%s_meta.json" % new_vm_name)
        xml_name = os.path.join(directory, new_vm_name, xml_name)
        snap_name = os.path.join(directory, new_vm_name, snap_name)
        with open(json_name, "w") as fh:
            json.dump(new_json_file, fh)

        guid = str(uuid.uuid4())
        with open(xml_name, "w") as fh:
            xml_file = tar.extractfile(tar.getmember(os.path.join(vm_name, json_file['xml']))).read()
            xml_file = mod_xml_meta(xml_file, "./name", new_vm_name)
            xml_file = mod_xml_meta(xml_file, "./uuid", guid)
            xml_file = mod_xml_meta(xml_file, "domain/seclabel", None)
            fh.write(xml_file)

        with open(snap_name, "w") as fh:
            xml_file = tar.extractfile(tar.getmember(os.path.join(vm_name, json_file['snapshot_xml']))).read()
            xml_file = mod_xml_meta(xml_file, "domain/name", new_vm_name)
            xml_file = mod_xml_meta(xml_file, "domain/uuid", guid)
            xml_file = mod_xml_meta(xml_file, "domain/seclabel", None)
            fh.write(xml_file)

        yield new_json_file

    tar.close()


# noinspection PyBroadException
def main():
    if len(sys.argv) == 1:
        print "Usage: %s <One or more prepared VM tarballs>"
        sys.exit(7)

    try:
        svc_class = service_by_name("Cuckoo")
    except:
        print 'Could not load service "%s".\n' \
              'Valid options:\n%s' % ("Cuckoo", [s['name'] for s in forge.get_datastore().list_services()])
        sys.exit(7)

    cfg = forge.get_datastore().get_service(svc_class.SERVICE_NAME).get("config", {})
    config = forge.get_config()

    local_meta_root = os.path.join(config.system.root, cfg['REMOTE_DISK_ROOT'])
    vm_meta_path = os.path.join(local_meta_root, cfg['vm_meta'])

    out_config = vm_meta_path
    out_directory = os.path.dirname(out_config)
    vm_list = sys.argv[1:]

    cuckoo_config = []
    for vm in vm_list:
        for js in install_vm_meta(out_directory, vm, ['']):
            cuckoo_config.append(js)

    with open(out_config, "w") as fh:
        json.dump(
            cuckoo_config,
            fh,
            sort_keys=True,
            indent=4,
            separators=(',', ': ')
        )

    print "Wrote %i Definitions to %s!" % (len(cuckoo_config), out_config)

if __name__ == "__main__":
    main()
