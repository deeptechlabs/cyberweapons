#!/usr/bin/env python

from assemblyline.al.install.seeds.assemblyline_common import seed

# ----------------- Just edit IPs, users and passwords in this section -----------------
IP_CORE = '192.168.0.1'
IP_LOGGER = "192.168.0.2"

IP_WORKERS = [
    "192.168.0.20",
    "192.168.0.21",
    "192.168.0.22",
    "192.168.0.23",
    "192.168.0.24",
    "192.168.0.25",
    "192.168.0.26",
    "192.168.0.27",
    "192.168.0.28",
    "192.168.0.29"
]

IP_RIAK_NODES = [
    "192.168.0.10",
    "192.168.0.11",
    "192.168.0.12",
    "192.168.0.13",
    "192.168.0.14"
]


SYS_USER = 'al'
FTP_PASS = 'ftp_password'
FTP_USER = 'ftp_user'
LOGGER_PASS = "logger_password"
# ----------------- End of section -----------------

# Start with the default seed and update for AL
seed['core']['nodes'] = [IP_CORE]
seed['core']['redis']['nonpersistent']['host'] = IP_CORE
seed['core']['redis']['persistent']['host'] = IP_CORE

seed['datastore']['riak']['nodes'] = IP_RIAK_NODES

seed['filestore']['ftp_password'] = FTP_PASS
seed['filestore']['ftp_user'] = FTP_USER
seed['filestore']['support_urls'] = [
    'ftp://{user}:{password}@{core}/opt/al/var/support'.format(core=IP_CORE, user=FTP_USER, password=FTP_PASS)
]
seed['filestore']['urls'] = [
    'ftp://{user}:{password}@{core}/opt/al/var/storage'.format(core=IP_CORE, user=FTP_USER, password=FTP_PASS)
]

seed['logging']['log_to_syslog'] = True
seed['logging']['logserver']['kibana']['host'] = IP_LOGGER
seed['logging']['logserver']['kibana']['password'] = LOGGER_PASS
seed['logging']['logserver']['node'] = IP_LOGGER
seed['logging']['syslog_ip'] = IP_LOGGER

seed['submissions']['url'] = "https://%s:443" % IP_CORE

seed['system']['name'] = 'production'
seed['system']['internal_repository'] = {
    'url': 'http://{core}/git/'.format(core=IP_CORE),
    'branch': 'prod_3.2'
}
seed['system']['user'] = SYS_USER

seed['workers']['nodes'] = IP_WORKERS
seed['workers']['virtualmachines']['use_parent_as_queue'] = True
seed['workers']['virtualmachines']['use_parent_as_datastore'] = True


if __name__ == '__main__':
    import sys

    if "json" in sys.argv:
        import json
        print json.dumps(seed)
    else:
        import pprint
        pprint.pprint(seed)
