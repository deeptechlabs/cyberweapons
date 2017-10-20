#!/usr/bin/env python

import getopt
import logging
import sys
from pprint import pprint
from assemblyline.common.importing import class_by_name
from assemblyline.al.common import forge
from assemblyline.al.common.importing import service_by_name


def cmdline_register_service():
    opts, args = getopt.getopt(sys.argv[1:], 'eln', ['existing', 'list', 'noexec'])
    store_config = True
    reregister_existing = False
    for opt, arg in opts:
        if opt in ('-e', '--existing'):
            reregister_existing = True
        if opt in ('-l', '--list'):
            # TODO get this from the seed
            sys.exit(0)
        if opt in ('-n', '--noexec'):
            store_config = False

    if not store_config and reregister_existing:
        print >> sys.stderr, sys.argv[0], 'cannot use -n and -e simultanously'
        sys.exit(1)

    if not reregister_existing and len(args) != 1:
        print >> sys.stderr, sys.argv[0], '[-s] <fully-qualified class name>'
        sys.exit(1)

    if reregister_existing and len(args) != 0:
        print >> sys.stderr, sys.argv[0], '[-e]'
        sys.exit(1)

    if reregister_existing:
        reregister_services(store_config=store_config)
    else:
        register(args[0], store_config=store_config)


def store_service_config(name, store_config=True, config_overrides=None, enabled=True):
    cls = class_by_name(name) if '.' in name else service_by_name(name)
    if not hasattr(cls, "get_default_config"):
        raise Exception(name + " is not an AL service. Make sure the class path you've entered is valid.")
    cfg = cls.get_default_config()
    cfg['enabled'] = enabled

    if '.' in name:
        cfg['classpath'] = name

    if config_overrides:
        for cfg_key, cfg_value in config_overrides.iteritems():
            if cfg_key not in cfg['config'] and cfg_key != 'PLUMBER_MAX_QUEUE_SIZE':
                raise Exception("Config override %s is not a valid configuration option for %s" % (cfg_key, name))
            cfg['config'][cfg_key] = cfg_value
    if store_config:
        srv_config = forge.get_datastore().get_service(cfg['name'])
        if srv_config:
            srv_config.update(cfg)
        else:
            srv_config = cfg

        forge.get_datastore().save_service(cfg['name'], srv_config)
        return srv_config
    return cfg


def add_to_profile(profile_name, service_key):
    ds = forge.get_datastore()
    profile = ds.get_profile(profile_name)
    if not profile:
        raise Exception("Could not find profile: %s")
    profile['services'][service_key] = {'service_overrides': {}, 'workers': 1}
    ds.save_profile(profile_name, profile)


def reregister_services(store_config=True, config_overrides=None):
    failed = []
    passed = []
    services = forge.get_datastore().list_services()
    for svc in services:
        class_name = svc.get('classpath', "al_services.%s.%s" % (svc['repo'], svc['class_name']))

        pprint(class_name)
        try:
            store_service_config(class_name, store_config, config_overrides)
            passed.append(class_name)
        except ImportError as ie:
            failed.append((class_name, ie))
            logging.error('Existing service cannot be imported for inspection: %s. Skipping.', class_name)
    logging.info("Succeeded: \n\t%s", "\n\t".join(passed))
    logging.info("Failed:")
    for (c, e) in failed:
        logging.info("\t%s - %s", c, e)


def register(name, store_config=True, config_overrides=None, enabled=True):
    logging.info("Storing %s", name)
    return store_service_config(name, store_config, config_overrides, enabled=enabled)


if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    cmdline_register_service()
