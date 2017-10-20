#!/usr/bin/env python
import importlib
import logging
import os
import platform
import riak
import subprocess
import time

SEED_RIAK_NODE = os.environ.get('AL_DATASTORE', '') or 'datastore.al'
SEED_BUCKET = os.environ.get('AL_SEED_BUCKET', '') or 'blob'
SEED_KEY = os.environ.get('AL_SEED_KEY', '') or 'seed'
AL_ROOT = os.environ.get('AL_ROOT', '') or '/opt/al/'
AL_PYTHONPATH = os.path.join(AL_ROOT, 'pkg')
COMPLETION_FILE = os.path.join(AL_ROOT, 'var/bootstrap.complete')


def run_hooks_if_necessary(bstrap_cfg):
    hooks = bstrap_cfg.get('installation', {}).get('hooks', {}).get('bootstrap', [])
    if not hooks:
        return

    import sys
    sys.path.append(AL_PYTHONPATH)

    for runhook in hooks:
        hook_module = importlib.import_module(runhook)
        if not hasattr(hook_module, 'execute'):
            logging.warn('hook: %s has no execute', hook_module)
            return

        from assemblyline.al.install import SiteInstaller
        alsi = SiteInstaller(bstrap_cfg)
        hook_cb = getattr(hook_module, 'execute')
        hook_cb(alsi)


def hostagent_bootstrap_stage1():
    # At this point we should have any source repos checked out
    print 'running bootstrap stage 1'
    riakclient = _get_riak_client()
    bstrap_cfg = riakclient.bucket(SEED_BUCKET, bucket_type='data').get(SEED_KEY).data
    if not bstrap_cfg:
        raise Exception("No bootstrap config found at %s::%s::%s" % (
            SEED_RIAK_NODE, SEED_BUCKET, SEED_KEY))

    al_user = bstrap_cfg['system']['user']
    al_root = bstrap_cfg['system']['root']
    run_hooks_if_necessary(bstrap_cfg)

    if 'Windows' in platform.system():
        return

    # persist the primary bootstrap variables to disk for future use
    if not os.path.exists('/opt/al/tmp'):
        os.makedirs('/opt/al/tmp')
    bootstrap_tmp = '/opt/al/tmp/bootstrap.al'

    default_rc = (
        'PYTHONPATH={pythonpath}\n'
        'AL_DATASTORE=datastore.al\n'
        'AL_ROOT={alroot}\n'
        'AL_USER={aluser}\n').format(pythonpath=os.path.join(al_root, 'pkg'), alroot=al_root, aluser=al_user)

    with open(bootstrap_tmp, 'w') as f:
        f.write(default_rc)

    subprocess.Popen('chown -R {aluser}:adm /opt/al/tmp'.format(aluser=al_user), shell=True).wait()
    subprocess.Popen('cp /opt/al/tmp/bootstrap.al /etc/default/al', shell=True).wait()
    subprocess.Popen('chmod o+r /etc/default/al', shell=True).wait()


def _get_riak_client():
    retry_delay = 5
    retries_left = 10
    while retries_left > 0:
        # noinspection PyBroadException
        try:
            riakc = riak.RiakClient(nodes=[{'host': SEED_RIAK_NODE}])
            riakc.ping()
            return riakc
        except:  # pylint:disable-msg=W0702
            logging.exception('Instantiating riak client to %s. Retrying in %s seconds.', SEED_RIAK_NODE, retry_delay)
            time.sleep(retry_delay)
            retries_left -= 1

    raise Exception('Max retries exceeded. Aborting (letting init restart us)')


def completion_file_exists():
    return os.path.exists(COMPLETION_FILE)


def write_completion_file():
    print 'writing completion file to ' + COMPLETION_FILE
    completion_dir = os.path.dirname(COMPLETION_FILE)
    if not os.path.exists(completion_dir):
        os.makedirs(completion_dir)
    with open(COMPLETION_FILE, 'w') as f:
        f.write('complete')


if __name__ == '__main__':
    import sys
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)

    if completion_file_exists():
        print "completion file found. skipping bootstrap."
        exit(0)

    hostagent_bootstrap_stage1()

    write_completion_file()
