#!/usr/bin/env python

import requests
import os

# noinspection PyBroadException
try:
    # noinspection PyUnresolvedReferences
    requests.packages.urllib3.disable_warnings()
except:
    pass


def install(alsi):
    from copy import deepcopy
    from assemblyline.al.common import forge
    from assemblyline.common.user_defaults import ACCOUNT_DEFAULT, SETTINGS_DEFAULT

    mm_user = alsi.config['core']['middleman']['user']
    ds = forge.get_datastore()
    mm_user_data = ds.get_user(mm_user)
    if not mm_user_data:
        mm_user_data = deepcopy(ACCOUNT_DEFAULT)
        mm_user_data['api_quota'] = 256
        mm_user_data['classification'] = alsi.config['core']['middleman']['classification']
        mm_user_data['groups'] = ["MIDDLEMAN"]
        mm_user_data['name'] = mm_user
        mm_user_data['uname'] = mm_user
        ds.save_user(mm_user, mm_user_data)

        mm_options = deepcopy(SETTINGS_DEFAULT)
        mm_options['classification'] = alsi.config['core']['middleman']['classification']
        ds.save_user(mm_user + "_options", mm_options)

    alsi.sudo_install_file('assemblyline/al/install/etc/init/middleman_instance.conf',
                          '/etc/init/middleman_instance.conf')

    alsi.sudo_install_file('assemblyline/al/install/etc/init/middleman.conf',
                          '/etc/init/middleman.conf')

    if not os.path.exists('/etc/init.d/middleman'):
        alsi.runcmd('sudo ln -s /lib/init/upstart-job /etc/init.d/middleman')

    alsi.milestone("middleman install complete")


if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    installer = SiteInstaller()
    install(installer)
