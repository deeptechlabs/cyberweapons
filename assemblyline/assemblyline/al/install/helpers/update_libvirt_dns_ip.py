#!/usr/bin/env python

import libvirt
import lxml
import lxml.etree
import sys


def redirect_datastore_al_in_libvirtdns(datastore_ip):
    try:
        vmm = libvirt.open(None)
        default_vnet = vmm.networkLookupByName('default')
        vnet_xml = lxml.etree.fromstring(default_vnet.XMLDesc())
        if vnet_xml.find('dns') is not None:
            print "Dns already configured"
            return 0

        cmd = libvirt.VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST
        flags = libvirt.VIR_NETWORK_UPDATE_AFFECT_CONFIG
        section = libvirt.VIR_NETWORK_SECTION_DNS_HOST
        datastore_xml = '<host ip="{datastore_ip}"><hostname>datastore.al' \
                        '</hostname></host>'.format(datastore_ip=datastore_ip)
        default_vnet.update(cmd, section, -1, datastore_xml, flags)
    except Exception as e: 
        print(str(e))
        return -1
    return 0

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "Usage: %s <datastore_ip>" % sys.argv[0]
        exit(1)

    d_ip = sys.argv[1]
    exit(redirect_datastore_al_in_libvirtdns(d_ip))
