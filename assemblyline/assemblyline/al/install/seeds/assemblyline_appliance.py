#!/usr/bin/env python

from assemblyline.al.install.seeds.assemblyline_common import seed
from assemblyline.al.install import SiteInstaller

appliance_ip = SiteInstaller.get_ipaddress(silent=True)

SYS_PASS = 'changeme'
SYS_USER = 'al'
FTP_PASS = 'Ch@ang3thisPassword'
FTP_USER = 'alftp'

# Start with the default seed and update for AL
seed['core']['alerter']['shards'] = 1
seed['core']['dispatcher']['shards'] = 1
seed['core']['expiry']['delete_storage'] = False
seed['core']['middleman']['shards'] = 1
seed['core']['nodes'] = [appliance_ip]
seed['core']['redis']['persistent']['host'] = appliance_ip
seed['core']['redis']['nonpersistent']['host'] = appliance_ip

seed['datastore']['port'] = 9087
seed['datastore']['stream_port'] = 9098
seed['datastore']['solr_port'] = 9093

seed['datastore']['riak']['solr']['heap_max_gb'] = 2
seed['datastore']['riak']['nodes'] = [appliance_ip]
seed['datastore']['riak']['ring_size'] = 32
seed['datastore']['riak']['nvals'] = {'low': 1, 'med': 1, 'high': 1}

seed['filestore']['ftp_password'] = FTP_PASS
seed['filestore']['ftp_user'] = FTP_USER
seed['filestore']['support_urls'] = [
    'ftp://{user}:{password}@{server}/opt/al/var/support'.format(user=FTP_USER, password=FTP_PASS, server=appliance_ip)
]
seed['filestore']['urls'] = [
    'ftp://{user}:{password}@{server}/opt/al/var/storage'.format(user=FTP_USER, password=FTP_PASS, server=appliance_ip)
]

seed['submissions']['url'] = "https://%s:443" % appliance_ip

seed['system']['password'] = SYS_PASS
seed['system']['internal_repository'] = {
    'url': 'http://{appliance_ip}/git/'.format(appliance_ip=appliance_ip),
    'branch': 'prod_3.2'
}
seed['system']['user'] = SYS_USER

seed['workers']['nodes'] = [appliance_ip]
seed['workers']['proxy_redis'] = False
seed['workers']['virtualmachines']['use_parent_as_queue'] = True
seed['workers']['virtualmachines']['use_parent_as_datastore'] = True

seed['ui']['uwsgi']['max_workers'] = 16
seed['ui']['uwsgi']['start_workers'] = 1
seed['ui']['uwsgi']['threads'] = 1

if __name__ == '__main__':
    import sys

    if "json" in sys.argv:
        import json
        print json.dumps(seed)
    else:
        import pprint
        pprint.pprint(seed)
