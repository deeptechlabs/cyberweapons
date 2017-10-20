#!/usr/bin/env python

from assemblyline.al.install.seeds.assemblyline_appliance import seed

seed['services']['master_list']['Cuckoo']['install_by_default'] = False

seed['monitoring']['harddrive'] = False
seed['workers']['install_kvm'] = False

if __name__ == '__main__':
    import sys

    if "json" in sys.argv:
        import json
        print json.dumps(seed)
    else:
        import pprint
        pprint.pprint(seed)
