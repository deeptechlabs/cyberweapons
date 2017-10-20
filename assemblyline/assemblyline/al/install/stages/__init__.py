
import os


def instant_import(module_name, import_dir=None):
    import pip
    import imp

    if not import_dir:
        import_dir = module_name
    for x in pip.get_installed_distributions():
        if x.key == module_name:
            return imp.load_module(import_dir, None, x.location + '/' + import_dir, ('', '', 5))

    raise ImportError("Could not find module '{module}'.".format(module=module_name))


def cmd_service_all(alsi, cmd, al_svc_only=False):
    service_deps = [
        'pure-ftpd',
        'redis-persist',
        'redis-server',
        'nginx',
        'elasticsearch',
        'logstash',
        'filebeat',
        'kibana'
    ]
    al_services = [
        'gunicorn',
        'uwsgi',
        'alert_actions',
        'workflow_filter',
        'alerter',
        'controller',
        'dispatchers',
        'expiry',
        'expiry_workers',
        'hostagent',
        'ingest_bridge',
        'journalist',
        'metricsd',
        'middleman',
        'plumber',
        'quota_sniper',
        'system_metrics',
    ]

    if al_svc_only:
        services = al_services
    else:
        services = service_deps
        services.extend(al_services)

    if cmd == 'stop':
        services = services[::-1]

    alsi.info("Running {cmd} command on all services".format(cmd=cmd))
    for service in services:
        if os.path.exists('/etc/init/{service}.conf'.format(service=service)) or \
                os.path.exists('/etc/init.d/{service}'.format(service=service)):
            alsi.runcmd("sudo service {service} {cmd}".format(service=service, cmd=cmd), raise_on_error=False)
    alsi.info("{cmd} execution completed.".format(cmd=cmd))
