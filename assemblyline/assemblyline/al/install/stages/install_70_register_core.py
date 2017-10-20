#!/usr/bin/env python
from assemblyline.common import net, sysinfo
from assemblyline.al.common.hosts import DEFAULT_CORE_REGISTRATION


def install(alsi=None):
    from assemblyline.al.common import forge
    ds = forge.get_datastore()

    ip = net.get_hostip()
    mac = net.get_mac_for_ip(ip)

    existing_reg = ds.get_node(mac)
    if existing_reg:
        alsi.info("Registration already exist. Skipping...")
        return
    reg = DEFAULT_CORE_REGISTRATION.copy()
    reg['hostname'] = net.get_hostname()
    reg['ip'] = ip
    reg['mac_address'] = mac
    reg['machine_info'] = sysinfo.get_machine_info()
    reg['platform'] = sysinfo.get_platform()
    if 'roles' not in reg:
        reg['roles'] = []
    if "dispatcher" not in reg["roles"]:
        reg['roles'].append("dispatcher")
    if "middleman" not in reg["roles"]:
        reg['roles'].append("middleman")
    ds.save_node(mac, reg)
    alsi.info("Core server registered!")


if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    installer = SiteInstaller()
    install(installer)
