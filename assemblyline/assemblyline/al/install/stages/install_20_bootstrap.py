#!/usr/bin/env python

from assemblyline.al.install import SiteInstaller

import tempfile
import os


def install(alsi):
    alsi.check_log_prerequisites()
    alsi.install_persistent_pip_conf()

    alsi.info("Installing just enough to bootstrap.")
    alsi.sudo_apt_install([
        'git',
        'python-pip',
    ])
    alsi.pip_refresh()

    alsi.info("Installing more Ubuntu apt packages.")
    alsi.sudo_apt_install([
        'build-essential',
        'cython',
        'libffi-dev',
        'libssl-dev',
        'libxml2-dev',
        'libxslt1-dev',
        'pkg-config',
        'python-dev',
        'unzip',
    ])

    alsi.info("Installing Python packages using pip.")
    alsi.pip_install_all([
        'chardet>=2.2,<3.0',
        'hiredis>=0.1.4,<0.2',
        'psutil>=2.0,<3.0',
        'python-magic>=0.4.6',
        'setproctitle>=1.1,<=2.0',
        'redis>=2.10,<3.0',
        'netifaces>=0.10',
        'apscheduler>=2.1.2,<3.0',
    ])

    alsi.pip_upgrade_all(['pip==6.0.8', 'requests==2.6.0'])
    alsi.pip_refresh()

    # ssdeep is slow and error prone so we install it seperate from the rest.
    alsi.info("Installing ssdeep. This can take a while....")
    alsi.pip_install('ssdeep==2.9-0.3')

    # Install python-riak. The riak pip package does not appear
    # to install its deps correctly. So we include them here explicitly.
    alsi.pip_install_all([
        'cffi',
        'enum34',
        'pyasn1'
    ])
    alsi.pip_install_all([
        'boto3==1.4.4',
        'botocore==1.5.62',
        'setuptools==24.0.2',
        'cryptography==2.0.3',
        'riak-pb',
        'pyOpenSSL',
        'six==1.9.0',
        'pycparser',
        'riak>=2.2',
        'paramiko==2.0.1',
        'pysftp==0.2.9'
    ])

    # Install /etc/default/al
    if not os.path.exists("/etc/default/al"):
        defaults_tmp = tempfile.NamedTemporaryFile(delete=False)

        pypath = 'export PYTHONPATH=' + alsi.alroot + '/pkg\n'
        os.environ['PYTHONPATH'] = alsi.alroot + '/pkg'
        defaults_tmp.write(pypath)

        ssdatastore = 'export AL_DATASTORE=' + alsi.config['core']['nodes'][0] + '\n'
        os.environ['AL_DATASTORE'] = alsi.config['core']['nodes'][0]
        defaults_tmp.write(ssdatastore)

        alroot = 'export AL_ROOT=' + alsi.alroot + '\n'
        os.environ['AL_ROOT'] = alsi.alroot
        defaults_tmp.write(alroot)

        aluser = 'export AL_USER=' + alsi.config['system']['user'] + '\n'
        os.environ['AL_USER'] = alsi.config['system']['user']
        defaults_tmp.write(aluser)

        forced_branch = os.environ.get("AL_BRANCH", None)
        if forced_branch:
            defaults_tmp.write('export AL_BRANCH=' + forced_branch + '\n')

        defaults_tmp.close()
        alsi.runcmd('sudo cp {tmpfile} /etc/default/al'.format(
            tmpfile=defaults_tmp.name))
        alsi.runcmd('sudo chmod 644 /etc/default/al')
    
if __name__ == '__main__':
    installer = SiteInstaller()
    install(installer)
