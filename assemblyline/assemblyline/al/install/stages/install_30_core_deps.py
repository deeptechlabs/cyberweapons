#!/usr/bin/env python

import os
from assemblyline.al.install.stages import instant_import
google = None


def install(alsi=None):
    global google  # pylint: disable=W0603
    al_root = alsi.config['system']['root']
    if not os.path.exists(al_root):
        os.makedirs(al_root)

    alsi.info("Installing core Ubuntu packages using apt.")
    alsi.sudo_apt_install([
        'build-essential',
        'cython',
        'libffi-dev',
        'libssl-dev',
        'pkg-config', 
        'ntp',
        'python-dev', 
        'python-lxml',
        'python-pip', 
        'p7zip-full',
        'unzip',
    ])

    # Install python pip packages. 
    alsi.info("Installing Python pip packages.")
    alsi.pip_install_all([
        'easydict',
        'pytz',
        'jinja2',
        'versiontools',
        'ansicolors==1.0.2',
        'chardet==2.2.1',
        'requests>=2.0',
        'hiredis<=0.1.4',
        'psutil==2.1.1',
        'python-magic==0.4.6',
        'ssdeep==2.9-0.3',
        'setproctitle==1.1.8',
        'redis>=2.10',
        'netifaces>=0.10',
        'apscheduler>=2.1.2,<3.0',
        'pyinstaller',
        'pycrypto',
        'retrying',
        'setuptools-git',
        'cffi',
        'enum34',
        'pyasn1',
        'riak',
        'passlib==1.6.5',
        'bcrypt==3.1.0'
    ])
    alsi.milestone("Importing protobuf library using instant_import monkey patch...")
    google = instant_import('protobuf', 'google')

    # use the new six library
    import six
    reload(six)

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

    alsi.info("Dowload and install assemblyline_client")
    assemblyline_client_pkg = 'assemblyline_client-3.2.0.tar.gz'
    remote_path = 'python/assemblyline_client/' + assemblyline_client_pkg
    local_path = '/tmp/' + assemblyline_client_pkg
    alsi.fetch_package(remote_path, local_path)
    alsi.pip_install(local_path)

    alsi.sudo_install_file(
        'assemblyline/al/install/etc/cron/al-sweepstorage',
        '/etc/cron.d/al-sweepstorage')

    alsi.info("Completed core deps installation.")


# DEFERRED:
# Removed libxml2-dev, libxslt1-dev and libvirt-dev until I know we need them this early.
if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    installer = SiteInstaller()
    install(installer)
