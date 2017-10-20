#!/usr/bin/env python

import os
import pprint

from assemblyline.common.importing import module_attribute_by_name


def install(alsi, include_worker_extensions=False):
    if not alsi.config['system']['use_proxy']:
        alsi.info("Proxy disabled in the seed. Skipping...")
        return

    import jinja2
    alsi.sudo_apt_install(['haproxy',])

    # build list of riak nodes to include in the haproxy configuration
    nodes = []
    count = 1
    for riak_ip in alsi.config['datastore']['riak']['nodes']:
        nodes.append({'hostname': 'riak-' + str(count), 'ip': riak_ip})
        count += 1

    tmpl_path = os.path.join(alsi.alroot, 'pkg', 'assemblyline/al/install/etc/haproxy/haproxy.cfg.core.tmpl')

    alsi.info("Updating HAProxy configuration for nodes: " + pprint.pformat(nodes))
    haproxy_cfg_tmpl = jinja2.Template(open(tmpl_path, 'r').read())

    # we might need to pass alsi.config to the template in future if we have
    # more advanced haproxy settings
    redis_ip = alsi.config['core']['nodes'][0]
    worker_ext = ''
    if include_worker_extensions:
        haproxy_ext = alsi.config['workers'].get('haproxy_extensions', None)
        if haproxy_ext:
            worker_ext = module_attribute_by_name(haproxy_ext)

    include_redis = False
    if alsi.get_ipaddress() != redis_ip:
        include_redis = alsi.config['workers'].get('proxy_redis', True)
    concrete_cfg = haproxy_cfg_tmpl.render(nodes=nodes,
                                           include_redis=include_redis,
                                           redis_ip=redis_ip,
                                           worker_extensions=worker_ext,
                                           datastore_port=alsi.config['datastore']['port'],
                                           datastore_stream_port=alsi.config['datastore']['stream_port'],
                                           datastore_solr_port=alsi.config['datastore']['solr_port'])

    with open('/tmp/haproxy.cfg', 'w') as f:
        f.write(concrete_cfg)

    alsi.runcmd("sudo cp /tmp/haproxy.cfg /etc/haproxy/haproxy.cfg")

    alsi.sudo_sed_inline('/etc/default/haproxy', ['s/ENABLED=0/ENABLED=1/'])
    alsi.runcmd('sudo service haproxy restart')

    alsi.info("HAProxy installation and configuration complete!")


if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    installer = SiteInstaller()
    install(installer)
