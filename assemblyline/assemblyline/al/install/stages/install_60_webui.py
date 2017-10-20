#!/usr/bin/env python


import os


def install(alsi):
    import psutil
    import jinja2

    alsi.execute_ui_preinstall_hook()

    alsi.sudo_apt_install([
        'apache2-utils',
        'fcgiwrap',
        'freetds-dev',
        'libldap2-dev',
        'libsasl2-dev',
        'nginx',
        'libpq-dev',
        'libmysqlclient-dev',
        'postgresql-client',
    ])

    # UI Dependencies.
    alsi.pip_install_all([
        'wsaccel==0.6.2',
        'Flask==0.10.1',
        'uWSGI==2.0.5.1',
        'Flask-SocketIO==0.3.8',
        'gevent==1.0.1',
        'gevent-websocket==0.9.3',
        'gevent-socketio==0.3.6',
        'gunicorn==18.0',
        'python-ldap==2.4.15',
        'markdown',
        'setuptools_git',
        'pymssql',
        'psycopg2',
        'MySQL-python',
        'requests_toolbelt==0.3.1',
        'pyqrcode==1.2.1',
        'python_u2flib_server==5.0.0'
    ])

    www_dir = os.path.join(alsi.alroot, 'var/www')
    uwsgi_log_dir = os.path.join(alsi.alroot, 'var/log/uwsgi')
    gunicorn_log_dir = os.path.join(alsi.alroot, 'var/log/gunicorn')
    uwsgi_ini_dir = os.path.join(alsi.alroot, '/opt/al/etc/uwsgi/vassals')
    for d in [www_dir, uwsgi_log_dir, gunicorn_log_dir, uwsgi_ini_dir]:
        if not os.path.exists(d):
            os.makedirs(d)

    uwsgi_ini_path = os.path.join(alsi.alroot, 'pkg/assemblyline/al/install/etc/uwsgi/alui_uwsgi.ini')
    with open(uwsgi_ini_path, 'rb') as f:
        uwsgi_ini = f.read()

    uwsgi_ini = uwsgi_ini.format(
            start_workers=alsi.config['ui']['uwsgi']['start_workers'],
            max_workers=alsi.config['ui']['uwsgi']['max_workers'],
            max_requests_per_worker=alsi.config['ui']['uwsgi']['max_requests_per_worker'],
            threads=alsi.config['ui']['uwsgi']['threads']
        )
    with open('/tmp/alui_uwsgi.ini', 'wb') as f:
        f.write(uwsgi_ini)

    uwsgi_ini_dst_path = os.path.join(uwsgi_ini_dir, 'alui_uwsgi.ini')
    alsi.runcmd('sudo cp /tmp/alui_uwsgi.ini %s' % uwsgi_ini_dst_path)

    alsi.sudo_install_file(
            'assemblyline/al/install/etc/logrotate.d/uwsgi',
            '/etc/logrotate.d/uwsgi')
    alsi.runcmd('sudo chmod 644 /etc/logrotate.d/uwsgi')

    # nginx configuration
    tmpl_path = os.path.join(alsi.alroot,
                             'pkg/assemblyline/al/install/etc/nginx/conf.d/alui_nginx_http.conf.tmpl')
    http_templ = jinja2.Template(open(tmpl_path, 'r').read())
    concrete_cfg = http_templ.render(seed=alsi.config)
    with open('/tmp/alui_nginx_http.conf', 'w') as f:
        f.write(concrete_cfg)
    alsi.runcmd('sudo cp /tmp/alui_nginx_http.conf /etc/nginx/conf.d/alui_nginx_http.conf')

    ssl_config = alsi.config['ui']['ssl']
    if ssl_config['enabled']:
        if not os.path.exists('/etc/ssl/al_certs'):
            alsi.runcmd('sudo mkdir -p /etc/ssl/al_certs')
        alsi.runcmd('sudo chmod 755 /etc/ssl/al_certs')

        tmpl_path = os.path.join(alsi.alroot, 'pkg/assemblyline/al/install/etc/nginx/conf.d/alui_nginx_https.conf.tmpl')
        http_templ = jinja2.Template(open(tmpl_path, 'r').read())
        concrete_cfg = http_templ.render(seed=alsi.config)
        with open('/tmp/alui_nginx_https.conf', 'w') as f:
            f.write(concrete_cfg)
        alsi.runcmd('sudo cp /tmp/alui_nginx_https.conf /etc/nginx/conf.d/alui_nginx_https.conf')

        ssl_crt = ssl_config['certs'].get('crt', None)
        ssl_key = ssl_config['certs'].get('key', None)
        if ssl_crt and ssl_key:
            if not os.path.exists('/etc/ssl/al_certs/al.crt'):
                alsi.runcmd('sudo cp %s /etc/ssl/al_certs/al.crt' % os.path.join(alsi.alroot, 'pkg', ssl_crt))
            if not os.path.exists('/etc/ssl/al_certs/al.key'):
                alsi.runcmd('sudo cp %s /etc/ssl/al_certs/al.key' % os.path.join(alsi.alroot, 'pkg', ssl_key))
        elif ssl_config['certs']['autogen']:
            create_install_selfsigned_certs(alsi)

        ssl_ca = ssl_config['certs'].get('ca', None)
        if ssl_ca:
            if not os.path.exists('/etc/ssl/al_certs/ca.crt'):
                alsi.runcmd('sudo cp %s /etc/ssl/al_certs/ca.crt' % os.path.join(alsi.alroot, 'pkg', ssl_ca))

                # Make ca certs valid throughout the whole system
                # (this prevents nginx to sometimes throw a bad cert error)
                alsi.runcmd('sudo cp %s /usr/local/share/ca-certificates/al_ca.crt'
                            % os.path.join(alsi.alroot, 'pkg', ssl_ca))
                alsi.runcmd('sudo update-ca-certificates')

            ssl_crl = ssl_config['certs'].get('crl', None)
            if ssl_crl:
                if not os.path.exists('/etc/ssl/al_certs/crl.crt'):
                    alsi.runcmd('sudo cp %s /etc/ssl/al_certs/crl.crt' % os.path.join(alsi.alroot, 'pkg', ssl_crl))

        ssl_trusted = ssl_config['certs'].get('tc', None)
        if ssl_trusted:
            if not os.path.exists('/etc/ssl/al_certs/tc.crt'):
                alsi.runcmd('sudo cp %s /etc/ssl/al_certs/tc.crt' % os.path.join(alsi.alroot, 'pkg', ssl_trusted))

        alsi.runcmd('sudo chmod 600 /etc/ssl/al_certs')

    alsi.sudo_install_file(
        'assemblyline/al/install/etc/init/uwsgi.conf',
        '/etc/init/uwsgi.conf')

    alsi.sudo_install_file(
        'assemblyline/al/install/etc/init/gunicorn.conf',
        '/etc/init/gunicorn.conf')

    if not os.path.exists('/etc/init.d/uwsgi'):
        alsi.runcmd('sudo ln -s /lib/init/upstart-job /etc/init.d/uwsgi')

    if not os.path.exists('/etc/init.d/gunicorn'):
        alsi.runcmd('sudo ln -s /lib/init/upstart-job /etc/init.d/gunicorn')

    alsi.install_yara_3()

    nginx_processes = max(1, int(psutil.cpu_count() / 3))
    alsi.sudo_sed_inline('/etc/nginx/nginx.conf', [
        's/worker_connections 768/worker_connections 1024/g',
        's/worker_processes 4/worker_processes %s/g' % str(nginx_processes),
    ])

    if os.path.exists('/etc/nginx/sites-enabled/default'):
        alsi.runcmd('sudo rm /etc/nginx/sites-enabled/default')

    alsi.append_line_if_doesnt_exist('/etc/security/limits.conf', "*                soft    nofile          16384")
    alsi.append_line_if_doesnt_exist('/etc/security/limits.conf', "*                hard    nofile          16384")


def create_install_selfsigned_certs(alsi):
    # for now we hardcode the path locations

    if os.path.exists('/etc/ssl/al_certs/al.crt'):
        # skip if we see a cert
        alsi.info("skipping certificate install. a certificate exists.")
        return

    if not os.path.exists('/etc/ssl/al_certs'):
        alsi.runcmd('sudo mkdir -p /etc/ssl/al_certs')

    cert_location = '/etc/ssl/al_certs/al.crt'
    key_location = '/etc/ssl/al_certs/al.key'

    fqdn = alsi.config['ui']['fqdn']

    ssl_opts = [
        '-subj /CN=%s/' % fqdn,
        '-x509',
        '-batch',
        '-nodes',
        '-days 3650',
        '-newkey rsa:%s' % alsi.config['ui'].get('rsa_key_size', 2048),
        '-keyout ' + key_location,
        '-out ' + cert_location,
    ]
    alsi.runcmd('sudo openssl req ' + ' '.join(ssl_opts))
    if not os.path.exists('/etc/ssl/al_certs/ca.crt'):
        alsi.runcmd('sudo cp  /etc/ssl/al_certs/al.crt /etc/ssl/al_certs/ca.crt')

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    installer = SiteInstaller()
    install(installer)
