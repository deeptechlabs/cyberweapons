#!/usr/bin/env python

from assemblyline.al.install.seeds.assemblyline_appliance import seed

seed['installation']['external_packages'] = {
    'assemblyline': {
        'transport': 'local',
        'args': {'base': '/opt/al/var/installdeps/assemblyline/'}
    }
}


if __name__ == '__main__':
    import sys

    if "json" in sys.argv:
        import json
        print json.dumps(seed)
    else:
        import pprint
        pprint.pprint(seed)
