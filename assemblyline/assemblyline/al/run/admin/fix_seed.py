#!/usr/bin/env python
"""
This script takes a seed path as parameter and save the seed into
the original_seed key in the blob bucket.
"""

import os
import sys

seed_path = ""
# noinspection PyBroadException
try:
    seed_path = sys.argv[1]
    os.environ['AL_SEED_STATIC'] = seed_path
except:
    print "fix_seed <seed_path>"
    exit(1)

if __name__ == "__main__":
    import logging

    from assemblyline.al.core.datastore import RiakStore
    from assemblyline.common.importing import module_attribute_by_name
    from assemblyline.al.service import register_service

    log = logging.getLogger('assemblyline.datastore')
    log.setLevel(logging.WARNING)

    # noinspection PyBroadException
    seed = module_attribute_by_name(seed_path)
    services_to_register = seed['services']['master_list']

    for service, svc_detail in services_to_register.iteritems():
        classpath = svc_detail.get('classpath', "al_services.%s.%s" % (svc_detail['repo'], svc_detail['class_name']))
        config_overrides = svc_detail.get('config', {})

        seed['services']['master_list'][service].update(register_service.register(classpath,
                                                                                  config_overrides=config_overrides,
                                                                                  store_config=False,
                                                                                  enabled=svc_detail.get('enabled',
                                                                                                         True)))

    ds = RiakStore(hosts=seed['datastore']['hosts'])
    print "Seed {seed} loaded and datastore connected to {hosts}".format(seed=seed_path,
                                                                         hosts="|".join(seed['datastore']['hosts']))

    # noinspection PyBroadException
    try:
        target = sys.argv[2]
    except:
        target = raw_input("Where to save to? [seed]: ")
        if not target:
            target = "seed"

    ds.save_blob(target, seed)
    print "Seed '%s' saved to '%s'" % (seed_path, target)
