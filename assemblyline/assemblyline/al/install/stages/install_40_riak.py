#!/usr/bin/env python

import os

RIAK_DEB = 'riak_2.1.4-1_amd64.deb'


def patch_riak_conf(alsi):
    our_ip = None  # Set this value if alsi is picking the wrong NIC
    if not our_ip:
        our_ip = alsi.get_ipaddress()

    riakcfg = alsi.config['datastore']['riak']

    ring_size = riakcfg['ring_size']
    if ring_size < 8 or ring_size > 1024:
        raise Exception("Riak ring_size is not sane: %s" % ring_size)

    # Riak Solr options
    solr_heap_min_gb = riakcfg['solr']['heap_min_gb']
    solr_heap_max_gb = riakcfg['solr']['heap_max_gb']
    solr_gc_options = riakcfg['solr']['gc']

    alsi.sudo_sed_inline('/etc/riak/riak.conf', [
        "s/riak@127.0.0.1/riak@%s/g" % our_ip,
        "s/127.0.0.1/0.0.0.0/g",
        "s/search = off/search = on/g",
        "s/## ring_size = 64/ring_size = %s/g" % ring_size,
        "s/anti_entropy = active/anti_entropy = passive/g",
        "s/-Xms1g -Xmx1g -XX:+UseStringCache -XX:+UseCompressedOops/-Xms%sg -Xmx%sg -XX:+UseCompressedOops "
        "-Dcom.sun.management.jmxremote.rmi.port=8986 -XX:+UseStringCache %s/g" %
        (solr_heap_min_gb, solr_heap_max_gb, solr_gc_options),
        "s/riak_control = off/riak_control = on/g",
        "s/storage_backend = bitcask/storage_backend = leveldb/g",
        "s/leveldb.maximum_memory.percent = 70/leveldb.maximum_memory.percent = 50/g",
        "s/object.size.maximum = 50MB/object.size.maximum = 5MB/g",
        "s/object.size.warning_threshold = 5MB/object.size.warning_threshold = 500KB/g"
    ])

    alsi.append_line_if_doesnt_exist('/etc/riak/riak.conf', 'background_manager = on')
    alsi.append_line_if_doesnt_exist('/etc/riak/riak.conf', 'anti_entropy.use_background_manager = on')
    alsi.append_line_if_doesnt_exist('/etc/riak/riak.conf', 'handoff.use_background_manager = on')
    alsi.append_line_if_doesnt_exist('/etc/riak/riak.conf', 'max_concurrent_requests = 85000')
    alsi.append_line_if_doesnt_exist('/etc/riak/riak.conf', 'handoff.ip = 0.0.0.0')


def install(alsi=None):
    riakcfg = alsi.config['datastore']['riak']

    # Riak Solr options
    solr_heap_min_gb = riakcfg['solr']['heap_min_gb']
    solr_heap_max_gb = riakcfg['solr']['heap_max_gb']
    for ramsize in [solr_heap_min_gb, solr_heap_max_gb]:
        if not isinstance(ramsize, int) or not ramsize > 0 or not ramsize < 32:
            raise Exception("Invalid SOLR heap config. Should be between 0 and 31. Aborting. ")

    ring_size = riakcfg['ring_size']
    if ring_size < 8 or ring_size > 1024:
        raise Exception("Riak ring_size is not sane: %s" % ring_size)

    our_ip = None  # Set this value if alsi is picking the wrong NIC
    our_hostname = alsi.get_hostname()
    if not our_ip:
        our_ip = alsi.get_ipaddress()

    nodes = riakcfg['nodes']
    if our_ip.strip() not in nodes and our_hostname not in nodes:
        print "IP %s not found in riak[nodes] configuration. Aborting.: %s" % (our_ip, nodes)
        exit(1)

    alsi.info("Installing Ubuntu packages from apt.")
    alsi.sudo_apt_install([
        'build-essential',
        'curl',
        'ethtool',
        'fop',
        'git',
        'libffi-dev',
        'libncurses5-dev', 
        'libpam0g-dev',
        'libssl-dev',
        'openssl',
        'unixodbc-dev',
        'xsltproc',
    ])

    alsi.install_oracle_java8()

    pkg_path = 'riak/' + RIAK_DEB 
    local_path = os.path.join(alsi.install_temp, RIAK_DEB)
    alsi.fetch_package(pkg_path, local_path)
    alsi.runcmd('sudo dpkg -i -E ' + local_path)
    os.remove(local_path)

    patch_riak_conf(alsi)

    alsi.sudo_install_file(
        'assemblyline/al/install/etc/default/riak',
        '/etc/default/riak')

    alsi.sudo_install_file(
        'assemblyline/al/install/etc/limits.d/al-riak.conf',
        '/etc/security/limits.d/al-riak.conf')

    # add pam_limits to pam.d so the ulimits are honored at boot time for services
    for pamfile in ['/etc/pam.d/common-session', '/etc/pam.d/common-session-noninteractive']:
        alsi.append_line_if_doesnt_exist(pamfile, "session required  pam_limits.so")

    tweaks = riakcfg['tweaks']
    if tweaks['net']:
        alsi.sudo_install_file(
            'assemblyline/al/install/etc/sysctl.d/10-alriak-net.conf',
            '/etc/sysctl.d/10-alriak-net.conf')

    if tweaks['disableswap']:
        alsi.sudo_install_file(
            'assemblyline/al/install/etc/sysctl.d/10-alriak-noswap.conf',
            '/etc/sysctl.d/10-alriak-noswap.conf')

    if tweaks['10gnic']:
        alsi.sudo_install_file(
            'assemblyline/al/install/etc/sysctl.d/10-alriak-10gnic.conf',
            '/etc/sysctl.d/10-alriak-10gnic.conf')

    if tweaks['noop_scheduler']:
        alsi.sudo_sed_inline("/etc/rc.local", ['s/^exit 0//g'])
        block_devices = [x for x in os.listdir("/sys/block")
                         if "loop" not in x and
                         "ram" not in x and
                         "dm-" not in x and
                         "vda" not in x]
        for bd in block_devices:
            alsi.append_line_if_doesnt_exist("/etc/rc.local",
                                             "echo noop > /sys/block/%s/queue/scheduler 2> /dev/null || true" % bd)
            alsi.append_line_if_doesnt_exist("/etc/rc.local",
                                             "echo 1024 > /sys/block/%s/queue/nr_requests 2> /dev/null  || true" % bd)
        alsi.append_line_if_doesnt_exist("/etc/rc.local", "exit 0")

    if tweaks['fs']:
        alsi.runcmd("sudo tune2fs -o journal_data_writeback `mount | head -n 1 | cut -d ' ' -f 1`")

        mount_options = "errors=remount-ro,nobarrier,noatime,data=writeback"
        if not alsi.grep_quiet('/etc/fstab', mount_options):
            alsi.sudo_sed_inline('/etc/fstab', ["s/errors=remount-ro/%s/g" % mount_options])


if __name__ == '__main__':
    
    from assemblyline.al.install import SiteInstaller
    installer = SiteInstaller()
    install(installer)
