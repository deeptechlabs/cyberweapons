#!/usr/bin/env python

import os
import shutil


def install(alsi=None):

    if not alsi:
        from assemblyline.al.install import SiteInstaller
        alsi = SiteInstaller()

    alsi.sudo_install_file(
        'assemblyline/al/install/etc/sysctl.d/10-dispatcher-overcommitmem.conf',
        '/etc/sysctl.d/10-dispatcher-overcommitmem.conf')
    alsi.runcmd('sudo sysctl vm.overcommit_memory=1')

    alsi.sudo_apt_install(['redis-server'])

    alsi.sudo_sed_inline('/etc/redis/redis.conf',
                        ['s/bind 127.0.0.1/bind 0.0.0.0/g',
                         's/timeout 0/timeout 30/g',
                         's/save 900 1/#save 900 1/g',
                         's/save 300 10/#save 300 10/g',
                         's/save 60 10000/save ""/g'])

    redis_cfg_tmp = '/tmp/redis.conf'
    if os.path.exists(redis_cfg_tmp):
        os.unlink(redis_cfg_tmp)
    shutil.copyfile('/etc/redis/redis.conf', redis_cfg_tmp)

    alsi.sudo_sed_inline(redis_cfg_tmp, [
        's/redis-server.pid/redis-persist.pid/g',
        's/port 6379/port 6380/g',
        's/redis-server.log/redis-persist.log/g',
        's/# syslog-ident redis/syslog-ident redis-persist/g',
        's|/var/lib/redis|/var/lib/redis-persist|g',
        's/appendonly no/appendonly yes/g',
        's/auto-aof-rewrite-percentage 100/auto-aof-rewrite-percentage 0/g'])

    alsi.sudo_sed_inline('/etc/default/redis-server', ['s/# ULIMIT=/ULIMIT=/g'])

    alsi.sudo_install_file(redis_cfg_tmp, '/etc/redis-persist/redis.conf')

    redis_init_tmp = '/tmp/init_redis.conf'
    if os.path.exists(redis_init_tmp):
        os.unlink(redis_init_tmp)
    shutil.copyfile('/etc/init.d/redis-server', redis_init_tmp)

    alsi.sudo_sed_inline(redis_init_tmp, [r's/redis\/redis.conf/redis-persist\/redis.conf/g',
                                         's/redis-server.pid/redis-persist.pid/g'])
    alsi.sudo_install_file(redis_init_tmp, '/etc/init.d/redis-persist')

    alsi.runcmd('sudo mkdir /var/lib/redis-persist', raise_on_error=False)
    alsi.runcmd('sudo chown redis:redis /var/lib/redis-persist')
    alsi.runcmd('sudo update-rc.d redis-persist defaults')

    persistent_settings = alsi.config['core']['redis']['persistent']
    db = persistent_settings['db']
    port = persistent_settings['port']

    tmpl_path = os.path.join(
            alsi.alroot, 'pkg',
            'assemblyline/al/install/etc/cron/al-redis_maintenance.tmpl')

    tmpl = open(tmpl_path).read()
    cfg = tmpl.replace('___DB___', str(db)).replace('___PORT___', str(port))
    with open('/tmp/al-redis_maintenance', 'w') as f:
        f.write(cfg)

    alsi.sudo_install_file('/tmp/al-redis_maintenance', '/etc/cron.d/al-redis_maintenance')

if __name__ == '__main__':
    install()
