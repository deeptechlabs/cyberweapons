#!/usr/bin/env python

import os

# Check and install SiteInstaller dependancies
try:
    # noinspection PyUnresolvedReferences
    import pip
    if pip.__version__ != "8.1.2":
        raise ImportError("Upgrade PIP")

    # noinspection PyUnresolvedReferences
    import requests
    if requests.__version__ != "2.10.0":
        raise ImportError("Upgrade request")
except ImportError:
    from assemblyline.common.importing import module_attribute_by_name
    from assemblyline.al.install import PipInstaller

    seed = os.environ.get('AL_SEED', None)
    if seed:
        temp_config = module_attribute_by_name(seed)

        pip_installer = PipInstaller(pypi_index_url=temp_config['installation']['pip_index_url'])
        pip_installer.upgrade_all(['requests==2.10.0'])
        # noinspection PyBroadException
        try:
            pip_installer.upgrade_all(['pip==8.1.2'])
        except:
            pass

    else:
        print "Cannot pip installer without the AL_SEED variable set"
        exit(1)

# Start SiteInstaller
from assemblyline.al.install import SiteInstaller

alsi = SiteInstaller()

support_dir = os.path.join(alsi.alroot, 'support')
if not os.path.exists(support_dir):
    os.makedirs(support_dir)

# Install boostrap packages
try:
    # noinspection PyUnresolvedReferences
    import Crypto
except ImportError:
    pycrypto = 'pycrypto-2.6.win32-py2.7.exe'
    local_path = os.path.join(support_dir, pycrypto)
    alsi.fetch_package(r'python/pywin/' + pycrypto, local_path)
    alsi.runcmd(local_path)

# Install boostrap packages
try:
    # noinspection PyUnresolvedReferences
    import psutil
except ImportError:
    psutil_pkg = 'psutil-2.1.0.win32-py2.7.exe'
    local_path = os.path.join(support_dir, psutil_pkg)
    alsi.fetch_package(r'python/pywin/' + psutil_pkg, local_path)
    alsi.runcmd(local_path)


alsi.pip_install_all([
    'chardet>=2.2,<3.0',
    'redis>=2.10,<3.0',
    'netifaces>=0.10',
    'apscheduler>=2.1.2,<3.0',
])

alsi.pip_install_all([
    'cffi==1.4.1',
    'enum34',
    'pyasn1',
    'google-apputils'
])

alsi.pip_install_all([
    'boto3==1.4.4',
    'botocore==1.5.62',
    'setuptools==24.0.2',
    'cryptography',
    'riak-pb',
    'pyOpenSSL',
    'six==1.9.0',
    'pycparser',
    'riak>=2.2',
    'paramiko==2.0.1',
    'pysftp==0.2.9'
])

# Install core deps pip packages
alsi.pip_install_all([
    'easydict',
    'pytz',
    'versiontools',
    'ansicolors==1.0.2',
    'chardet==2.2.1',
    'requests>=2.0',
    'redis>=2.10',
    'apscheduler>=2.1.2,<3.0',
    'pyinstaller',
    'retrying',
    'setuptools-git',
    'enum34',
    'pyasn1',
    'riak',
])

alsi.info("Download and install CaRT")
cart_pkg = 'cart-1.0.8.tar.gz'
remote_path = 'python/cart/' + cart_pkg
local_path = '/tmp/' + cart_pkg
alsi.fetch_package(remote_path, local_path)
alsi.pip_install(local_path)

# Install assemblyline_client deps
alsi.pip_install_all([
    'socketio-client==0.5.6',
    'requests[security]',
    'pycrypto==2.6.1'
])

alsi.info("Download and install assemblyline_client")
al_pkg = 'assemblyline_client-3.2.0.tar.gz'
remote_path = 'python/assemblyline_client/' + al_pkg
local_path = '/tmp/' + al_pkg
alsi.fetch_package(remote_path, local_path)
alsi.pip_install(local_path)

alsi.milestone("Completed. Proceed to installing services for this VM.")
