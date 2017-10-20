#!/usr/bin/env python

import glob
import os
import psutil
import riak
import subprocess
import time

from assemblyline.common.isotime import now_as_iso
from assemblyline.al.common.security import get_password_hash

MASTER_UP_KEY = 'master.up'
MASTER_COMPLETE_KEY = 'master.complete'
INSTALLSTATE_BUCKET = 'install.state'
TRANSFERS_COMPLETE_KEY = 'transfers.complete'


def install(alsi):
    alsi.runcmd('sudo service riak start')
    riak_nodes = sorted(alsi.config['datastore']['riak']['nodes'])

    our_ip = alsi.get_ipaddress()
    our_hostname = alsi.get_hostname()

    # By convention if we are the first node in the sorted list. We are the 'temporary master'
    # Otherwise we just need to join the existing (already provisioned node)
    master_ip = riak_nodes[0].strip()
    slaves = [node.strip() for node in riak_nodes[1:]]
    if our_ip == master_ip or our_hostname == master_ip:
        install_master(alsi, our_ip, slaves)
    else:
        install_slave(alsi, master_ip, our_ip)


# noinspection PyUnresolvedReferences
def _increase_jetty_concurrency(alsi):
    if alsi.config['datastore']['riak']['tweaks']['jetty']:
        # riak changes the name of the yokozuna directory with each release.
        # glob and change all jetty.xml for all versions.
        jetty_xmls = glob.glob('/usr/lib/riak/lib/yokozuna-*/priv/solr/etc/jetty.xml')
        # concurrency should be twice the number of cpus.
        # we keep it in the range of 8 to 64 in case psutil gives us a bad result.
        concurrency = min(psutil.NUM_CPUS * 2, 64)
        concurrency = max(concurrency, 8)
        for jetty_xml in jetty_xmls:
            alsi.info('patching ' + jetty_xml)
            alsi.sudo_sed_inline(jetty_xml, [
                's/"minThreads">10/"minThreads">{}/'.format(concurrency),
                's/<!-- <Set name="acceptors">16<\/Set> -->/<Set name="acceptors">{}<\/Set>/'.format(concurrency)
            ])


def _install_tunedconfigs(alsi):
    if alsi.config['datastore']['riak']['tweaks']['tuned_solr_configs']:
        for bucketname in ['submission', 'result', 'filescore', 'file', 'error', 'alert']:
            tuned_config = os.path.join(alsi.alroot,
                                        "pkg/assemblyline/al/install/etc/riak/tunedconfig/solrconfig.xml." + bucketname)
            if not os.path.exists(tuned_config):
                raise Exception("Tuned config not found: %s. Aborting." % tuned_config)
            existing_config = '/var/lib/riak/yz/%s/conf/solrconfig.xml' % bucketname
            if not os.path.exists(existing_config):
                raise Exception("Existing solr config not found for %s" % existing_config)
            alsi.runcmd('sudo install -m 664 -b -o riak -g riak %s %s' % (tuned_config, existing_config))


def _ensure_transfer_completion(alsi, master_ip):
    while True:
        p = subprocess.Popen(['sudo', 'riak-admin', 'transfers'], 
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (output, err) = p.communicate()
        if 'No transfers active' in output:
            break 

        alsi.info("riak transfers still in progress. waiting for it to settle...")
        time.sleep(10)

    alsi.milestone("Updating master installstate in riak (transfers).")

    client = riak.RiakClient(protocol='pbc', nodes=[{'host': master_ip}])
    # noinspection PyUnresolvedReferences
    client.resolver = riak.resolver.last_written_resolver
    b = client.bucket(INSTALLSTATE_BUCKET)
    completion_value = b.new(key=TRANSFERS_COMPLETE_KEY, data=time.asctime())
    completion_value.store()
    alsi.milestone("Intra-cluster data transfers are complete.")


def _mark_master_up(alsi, master_ip):
    alsi.milestone("Updating master with 'up' status in riak.")

    client = riak.RiakClient(protocol='pbc', nodes=[{'host': master_ip}])
    # noinspection PyUnresolvedReferences
    client.resolver = riak.resolver.last_written_resolver
    b = client.bucket(INSTALLSTATE_BUCKET)
    completion_value = b.new(key=MASTER_UP_KEY, data=time.asctime())
    completion_value.store()


def _restart_riak(alsi):
    alsi.milestone("Restarting riak node")
    alsi.runcmd('sudo service riak restart')
    alsi.info('Riak node restarted.')


def install_master(alsi, master_ip, slaves):
    alsi.info("We are master")
    _mark_master_up(alsi, master_ip)
    _block_for_all_slaves(alsi, master_ip, slaves)
    _commit_riak_plan(alsi)
    _install_master_datamodel(alsi, master_ip)
    _install_tunedconfigs(alsi)
    _increase_jetty_concurrency(alsi)
    _restart_riak(alsi)
    alsi.milestone("Done.")


def install_slave(alsi, master_ip, our_ip):
    # Wait until the master node has complete his install and is alive before proceeding.
    alsi.milestone("Waiting for master to come alive.")
    _block_for_master_up(alsi, master_ip)
    alsi.milestone("Master is alive. We are a slave node. Joining master. slave:%s master:%s" % (master_ip, our_ip))
    alsi.runcmd('sudo riak-admin cluster join riak@{master}'.format(master=master_ip))

    alsi.milestone("Updating install state in riak for ourselves (%s)" % our_ip)
    client = riak.RiakClient(protocol='pbc', nodes=[{'host': master_ip}])
    # noinspection PyUnresolvedReferences
    client.resolver = riak.resolver.last_written_resolver

    b = client.bucket(INSTALLSTATE_BUCKET)
    completion_value = b.new(key=our_ip, data=time.asctime())
    completion_value.store()

    _block_for_master_completion(alsi, master_ip)
    _install_tunedconfigs(alsi)
    _increase_jetty_concurrency(alsi)
    _restart_riak(alsi)
    alsi.milestone("Done.")


def _block_for_master_completion(alsi, riak_ip):
    return _block_for_key_existence(alsi, riak_ip,
                                    INSTALLSTATE_BUCKET,
                                    MASTER_COMPLETE_KEY)


def _block_for_master_up(alsi, riak_ip):
    return _block_for_key_existence(alsi, riak_ip,
                                    INSTALLSTATE_BUCKET,
                                    MASTER_UP_KEY)

    
def _block_for_slave_completion(alsi, master_ip, slave_ip):
    return _block_for_key_existence(alsi, master_ip,
                                    INSTALLSTATE_BUCKET, slave_ip)


# noinspection PyBroadException
def _block_for_key_existence(alsi, master_ip, bucket, key):
    while True:
        try:
            client = riak.RiakClient(protocol='pbc', nodes=[{'host': master_ip}])
            # noinspection PyUnresolvedReferences
            client.resolver = riak.resolver.last_written_resolver
            if not client.is_alive():
                alsi.info("Riak not yet alive.")
                raise Exception("Master not yet alive.")

            b = client.bucket(bucket)
            value = b.get(key)
            if not value.exists:
                alsi.info("Status not yet in riak.")
                raise Exception('Not yet complete.')

            return
        except:
            alsi.info("Waiting 10 seconds for reconnect.")
            time.sleep(3)


def _commit_riak_plan(alsi):
    alsi.runcmd('sudo riak-admin cluster plan')
    alsi.runcmd('sudo riak-admin cluster commit')


def _block_for_all_slaves(alsi, master_ip, slaves):
    pending = list(slaves)
    while pending:
        slave = pending[0]
        _block_for_slave_completion(alsi, master_ip, slave)
        alsi.milestone("slave %s has joined." % slave)
        pending.remove(slave)
    alsi.milestone("All slaves have joined. Ready to proceed.")


def _install_master_datamodel(alsi, master_ip):
    nvals = alsi.config['datastore']['riak']['nvals']
    nval_med = nvals['med']
    nval_high = nvals['high']

    indexed_buckets = (
        'alert',
        'error',
        'file',
        'filescore',
        'node',
        'profile',
        'result',
        'signature',
        'submission',
        'user',
        'workflow'
    )

    schema_src_root = os.path.join(alsi.alroot, 'pkg/assemblyline/al/install/etc/riak/schema')

    # Copy schemas to a temporary location for the install.
    schema_dst_root = alsi.install_temp
    if not os.path.exists(schema_dst_root):
        os.makedirs(schema_dst_root)

    for bucket in indexed_buckets:
        src = os.path.join(schema_src_root, bucket + '.xml')
        dst = os.path.join(schema_dst_root, bucket + '.xml')
        alsi.runcmd('cp -f {src} {dst}'.format(src=src, dst=dst))
              
    alsi.runcmd('sudo riak-admin bucket-type create '
                'data \'{"props": {"allow_mult": false, "dvv_enabled": false, "last_write_wins": true}}\'',
                raise_on_error=False)
    alsi.runcmd('sudo riak-admin bucket-type activate data',
                raise_on_error=False)

    client = riak.RiakClient(protocol='pbc', nodes=[{'host': master_ip}])
    # noinspection PyUnresolvedReferences
    client.resolver = riak.resolver.last_written_resolver

    # execute any optional riak preinstall hook
    alsi.execute_riak_preinstall_hook()

    for bucket in indexed_buckets:
        alsi.info('Creating schema for: ' + bucket)
        schema_file = os.path.join(schema_dst_root, bucket + '.xml')
        schema_contents = open(schema_file, 'r').read()
        client.create_search_schema(schema=bucket, content=schema_contents)

    buckets = (
        {'name': 'alert', 'nval': nval_med, 'index': 'alert'},
        {'name': 'blob', 'nval': nval_high},
        {'name': 'emptyresult', 'nval': nval_med},
        {'name': 'error', 'nval': nval_med, 'index': 'error'},
        {'name': 'file', 'nval': nval_med, 'index': 'file'},
        {'name': 'filescore', 'nval': nval_med, 'index': 'filescore'},
        {'name': 'node', 'nval': nval_high, 'index': 'node'},
        {'name': 'profile', 'nval': nval_high, 'index': 'profile'},
        {'name': 'result', 'nval': nval_med, 'index': 'result'},
        {'name': 'signature', 'nval': nval_high, 'index': 'signature'},
        {'name': 'submission', 'nval': nval_med, 'index': 'submission'},
        {'name': 'user', 'nval': nval_high, 'index': 'user'},
        {'name': 'workflow', 'nval': nval_high, 'index': 'workflow'}
    )

    for bucket_data in buckets:
        if 'index' in bucket_data:
            alsi.info('Creating index for: ' + bucket_data['name'])
            client.create_search_index(bucket_data['index'], bucket_data['name'], bucket_data['nval'])

    for bucket_data in buckets:
        alsi.info('Setting bucket props for: ' + bucket_data['name'])
        bucket = client.bucket(bucket_data['name'], bucket_type="data")
        props = {
            'dvv_enabled': False,
            'last_write_wins': True,
            'allow_mult': False,
            'n_val': bucket_data['nval']
        }
        if 'index' in bucket_data:
            props["search_index"] = bucket_data['index']

        client.set_bucket_props(bucket=bucket, props=props)

    _add_initial_riak_users(alsi, client)

    alsi.milestone("Saving our seed configuration to riak at: %s" % master_ip)
    from assemblyline.al.common import config_riak

    branch_override = os.environ.get('AL_BRANCH', None)
    if branch_override:
        alsi.info("Patching repo internal repo to use branch '{branch}'".format(branch=branch_override))
        alsi.config['system']['internal_repository']['branch'] = branch_override

    config_riak.SEED_RIAK_NODE = master_ip
    config_riak.save_seed(alsi.config, 'original_seed')
    config_riak.save_seed(alsi.config, 'previous_seed')
    config_riak.save_seed(alsi.config, 'seed')
    if alsi.seed_module:
        config_riak.save_seed(alsi.seed_module, 'seed_module')

    # Add the initial default profile
    default_profile_name = alsi.config['workers']['default_profile']
    alsi.milestone("Saving a default profile to riak: " + default_profile_name)
    default_profile = {'services': {}, 'system_overrides': {}, 'virtual_machines': {}}
    profiles = client.bucket('profile', bucket_type='data')
    p = profiles.new(key=default_profile_name, data=default_profile)
    p.store()
    
    alsi.milestone("Updating master installstate in riak.")
    b = client.bucket(INSTALLSTATE_BUCKET)
    completion_value = b.new(key=MASTER_COMPLETE_KEY, data=time.asctime())
    completion_value.store()
    alsi.milestone("Data model install is complete.")


def _add_initial_riak_users(alsi, client):
    htpass_users = alsi.config['auth'].get('internal', {}).get('users', [])
    # add the service api user as well
    if htpass_users:
        users = client.bucket("user", bucket_type="data")
        for user in htpass_users.itervalues():
            alsi.milestone('Creating user in riak:' + user['uname'])
            u = users.new(
                key=user['uname'],
                data={
                    "api_quota": user.get('api_quota', 10),
                    "agrees_with_tos": user.get('agrees_with_tos', now_as_iso()),
                    "dn": user.get('dn', None),
                    "uname": user['uname'],
                    "name": user.get('name', user['uname']),
                    "avatar": user.get('avatar', None),
                    "groups": user.get('groups', ["DEFAULT_GROUP"]),
                    "is_admin": user.get('is_admin', False),
                    "is_active": user.get('is_active', True),
                    "classification": user['classification'],
                    "password": get_password_hash(user.get('password', None))
                },
                content_type='application/json')
            u.store()


if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    installer = SiteInstaller()
    install(installer)
