#!/usr/bin/env python
from assemblyline.al.common.config_riak import load_seed, save_seed
from assemblyline.al.service import register_service


def install(alsi=None):
    # shortly we will allow node specific service list override. 
    # for now they always get default.
    services_to_register = alsi.config['services']['master_list']
    default_profile = alsi.config['workers']['default_profile'],
    alsi.info("Preparing to Register: %s", ",".join(services_to_register.keys()))

    for service, svc_detail in services_to_register.iteritems():
        svc_detail = alsi.config['services']['master_list'][service]
        classpath = svc_detail.get('classpath', "al_services.%s.%s" % (svc_detail['repo'], svc_detail['class_name']))
        config_overrides = svc_detail.get('config', {})

        # noinspection PyBroadException
        try:
            register_service.register(classpath, config_overrides=config_overrides,
                                      enabled=svc_detail.get('enabled', True))
            if svc_detail['enabled'] and svc_detail['install_by_default']:
                alsi.milestone("Adding '%s' to profile '%s'" % (service, default_profile))
                register_service.add_to_profile(alsi.config['workers']['default_profile'], service)
        except:
            alsi.fatal("Failed to register service %s." % service)
            alsi.log.exception('While registering service %s', service)

    seed = load_seed()
    save_seed(seed, "original_seed")
    save_seed(seed, "previous_seed")

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    installer = SiteInstaller()
    install(installer)
