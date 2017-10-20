#!/usr/bin/env python

import importlib
from assemblyline.al.service import register_service


# noinspection PyBroadException
def install(alsi=None, register=False):
    # shortly we will allow node specific service list override. 
    # for now they always get default.
    services_to_install = [k for k, v in alsi.config['services']['master_list'].iteritems() if v['install_by_default']]
    default_profile = alsi.config['workers']['default_profile']
    alsi.info("Preparing to Install: %s", services_to_install)

    for service in services_to_install:
        svc_detail = alsi.config['services']['master_list'][service]
        classpath = svc_detail.get('classpath', "al_services.%s.%s" % (svc_detail['repo'], svc_detail['class_name']))
        config_overrides = svc_detail.get('config', {})
        service_directory = classpath.rpartition('.')[0]
        installer_path = '.'.join([service_directory, 'installer'])
        alsi.milestone("Installing %s using %s" % (service, installer_path))
        try:
            m = importlib.import_module(installer_path)
            install_svc = getattr(m, 'install')
            install_svc(alsi)

            if register:
                service_key = register_service.register(classpath, config_overrides=config_overrides,
                                                        enabled=svc_detail.get('enabled', True))['name']
                # If successful register service and add to default profile.
                if svc_detail['enabled']:
                    alsi.milestone("adding to profile %s" % default_profile)
                    register_service.add_to_profile(
                        alsi.config['workers']['default_profile'],
                        service_key)
        except:
            alsi.error("Failed to install service %s." % service)
            alsi.log.exception('While installing service %s', service)


if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    installer = SiteInstaller()
    install(installer)
