#!/usr/bin/python

import csv
import sys
import pprint
import hashlib
import json

from assemblyline.al.common import forge
ds = forge.get_datastore()


def get_signatures(backup=True, path='sigs'):
    sigs = ds.get_blob('tagcheck_signatures')
    if backup:
        backup_fname = '%s_%s.json' % (path, str(hashlib.md5(str(sigs)).hexdigest()))
        with open(backup_fname, 'w') as fh:
            fh.write(json.dumps(sigs))
            print "Signatures backed up to %s" % backup_fname
    return sigs


def store_signatures(csv_path):
    with open(csv_path, 'r') as fh:
        reader = csv.reader(fh)
        sigblob = {}
        for row in reader:
            key = row[0]
            if key in sigblob:
                print "Skipping duplicate signature %s.." % key
                continue
            sigblob[key] = {
                "classification": row[1],
                "status": row[2],
                "score": row[3],
                "threat_actor": row[4],
                "implant_family": row[5],
                "comment": row[6],
                "values": [s for s in row[7].split(";")],
                "callback": row[8],
            }

    print "This is what we're about to write to riak: "
    pprint.pprint(sigblob)
    ds.save_blob('tagcheck_signatures', sigblob)
    print "Signatures written to riak."

if __name__ == "__main__":
    get_signatures()
    store_signatures(sys.argv[1])



