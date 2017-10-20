#!/usr/bin/env python

import logging
import os
import platform
import posixpath
import riak
import shutil
import stat
import subprocess
import time

from random import choice

os.path.sep = posixpath.sep
os.path.join = posixpath.join
os.path.split = posixpath.split
os.sep = posixpath.sep

# Allow the caller (typically init) to override these if needed
SEED_RIAK_NODE = os.environ.get('AL_DATASTORE', '') or 'datastore.al'
SEED_BUCKET = os.environ.get('AL_SEED_BUCKET', '') or 'blob'
SEED_KEY = os.environ.get('AL_SEED_KEY', '') or 'seed'
AL_ROOT = os.environ.get('AL_ROOT', '') or '/opt/al/'
AL_USER = os.environ.get('AL_USER', '') or 'user'

COMPLETION_FILE = os.path.join(AL_ROOT, 'var/bootstrap.complete')


# noinspection PyUnusedLocal
def onerror(func, path, exc_info):
    if not os.access(path, os.W_OK):
        os.chmod(path, stat.S_IWUSR)
        func(path)
    else:
        raise


# noinspection PyBroadException
def hostagent_bootstrap_stage0():
    riakclient = _get_riak_client()
    bstrap_cfg = riakclient.bucket(SEED_BUCKET, bucket_type='data').get(SEED_KEY).data
    if not bstrap_cfg:
        logging.error("No bootstrap config found at %s::%s::%s", SEED_RIAK_NODE, SEED_BUCKET, SEED_KEY)
        exit(1)

    repo_cfg = bstrap_cfg['system']['internal_repository']
    if len(repo_cfg) == 0:
        raise Exception('No git repositories specified in bootstrap configuration.')

    repo_list = []
    installed_repos = os.listdir(os.path.join(AL_ROOT, 'pkg'))
    for item in installed_repos:
        if item == "al_services":
            continue

        if os.path.isdir(os.path.join(AL_ROOT, 'pkg', item)):
            repo_list.append(item)

    installed_services = os.listdir(os.path.join(AL_ROOT, 'pkg', 'al_services'))
    for item in installed_services:
        if os.path.isdir(os.path.join(AL_ROOT, 'pkg', 'al_services', item)):
            repo_list.append("al_services/%s" % item)

    if 'assemblyline' not in repo_list:
        raise Exception("No bootstrap information for assemblyline repo.")

    done = False
    while not done:
        repo_name = None
        try:
            for repo_name in repo_list:
                try:
                    _git_clone(os.path.join(AL_ROOT, 'pkg', repo_name), repo_cfg['url'] + repo_name,
                               os.environ.get("AL_BRANCH", repo_cfg.get('branch', 'prod_3.2')))
                except:
                    # If cloning fails and system user password is enabled, we will try to SSH copy the source instead.
                    if bstrap_cfg['system']['password']:
                        logging.info("Could not clone '%s' but SSH access is enabled. Revert to SSH copy." % repo_name)

                        remote_repo_path = os.path.join(bstrap_cfg['system']['root'], 'pkg')
                        local_repo_path = os.path.join(AL_ROOT, 'pkg')
                        _code_sync(bstrap_cfg['core']['nodes'][0],
                                   bstrap_cfg['system']['user'],
                                   bstrap_cfg['system']['password'],
                                   remote_repo_path,
                                   local_repo_path,
                                   repo_name)
                    else:
                        raise
            done = True
        except:
            retry_in = choice(range(10))
            logging.error("Failed code cloning for repo: %s\nRetrying in %s seconds." % (repo_name, retry_in))
            time.sleep(retry_in)

    # That's it. Typically init will call the stage 1 bootstrap (which we should have just checked out)
    logging.info('stage 0 complete.')
    exit(0)


def _code_sync(host, user, passwd, remote_path, local_path, repo_name):
    import pysftp

    from stat import S_ISDIR, S_ISREG

    # Monkey patching walktree so it does not fail on symlinks
    def walktree(self, remotepath, fcallback, dcallback, ucallback,
                 recurse=True):
        self._sftp_connect()
        dcallback(remotepath)
        for entry in self.listdir(remotepath):
            pathname = posixpath.join(remotepath, entry)
            # noinspection PyBroadException
            try:
                mode = self._sftp.stat(pathname).st_mode
            except:
                continue
            if S_ISDIR(mode):
                # It's a directory, call the dcallback function
                dcallback(pathname)
                if recurse:
                    # now, recurse into it
                    self.walktree(pathname, fcallback, dcallback, ucallback)
            elif S_ISREG(mode):
                # It's a file, call the fcallback function
                fcallback(pathname)
            else:
                # Unknown file type
                ucallback(pathname)
    pysftp.Connection.walktree = walktree

    cnopts = pysftp.CnOpts()
    cnopts.hostkeys = None
    with pysftp.Connection(host, username=user, password=passwd, cnopts=cnopts) as conn:
        with conn.cd(remote_path):
            conn.get_r(repo_name, local_path)


def _git_clone(local_dir, repo_url, branch): 
    if os.path.exists(local_dir):
        logging.info("Removing directory: %s" % local_dir)
        shutil.rmtree(local_dir, onerror=onerror)

    git_cmdline = 'git clone -b {branch} {url} {dir}'.format(user=AL_USER, branch=branch, url=repo_url, dir=local_dir)
    if 'Windows' in platform.system():
        git_cmdline = 'git clone -b {branch} {url} {dir}'.format(user=AL_USER,
                                                                 branch=branch,
                                                                 url=repo_url,
                                                                 dir=local_dir)

    p = subprocess.Popen(git_cmdline, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    out, err = p.communicate()
    if p.returncode != 0:
        raise Exception('Git clone may have failed. ExitCode: %s.\nstderr:%s\nstdout:%s' % (p.returncode, out, err))
    logging.info('Git clone successful for %s:\n%s', repo_url, out)


# noinspection PyBroadException
def _get_riak_client():
    retry_delay = 5
    retries_left = 10
    while retries_left > 0:
        try:
            riakc = riak.RiakClient(nodes=[{'host': SEED_RIAK_NODE}])
            riakc.ping()
            return riakc
        except:  # pylint:disable=W0702
            logging.exception('Instantiating riak client to %s. Retrying in %s seconds.', SEED_RIAK_NODE, retry_delay)
            time.sleep(retry_delay)
            retries_left -= 1

    raise Exception('Max retries exceeded. Aborting (letting init restart us)')
 

if __name__ == '__main__':
    import sys
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    if os.path.exists(COMPLETION_FILE):
        logging.info('completion file exists. skipping bootstrap.')
        exit(0)
    hostagent_bootstrap_stage0()
