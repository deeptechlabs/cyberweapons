#!/usr/bin/env python

import sys

from assemblyline.al.common import forge
config = forge.get_config()

VERBOSE = False
QUIET = True

if __name__ == "__main__":
    # Initializing datastore
    if len(sys.argv) < 3:
        print "usage: reader.py <lookback_hours> <datastore_ip_1> ... <datastore_ip_n>"
        exit(1)
    try:
        lookback_hours = int(sys.argv[1])
    except ValueError:
        print "usage: reader.py <lookback_hours> <datastore_ip_1> ... <datastore_ip_n>"
        exit(1)

    ds_ip = sys.argv[2:]

    config.datastore.solr_port = 8093
    config.datastore.stream_port = 8098
    config.datastore.port = 8087
    config.datastore.hosts = ds_ip

    from assemblyline.al.core import datastore
    ds = datastore.RiakStore()

    # Creating fake submissions
    while True:
        result = ds.direct_search("submission", "times.submitted:[NOW-1HOUR+5MINUTE TO NOW]",
                                  [("sort", "times.submitted ASC"), ("rows", "5"), ("fl", "submission.sid")])

        sids = [x['submission.sid'] for x in result.get('response', {}).get('docs', [])]

        for sid in sids:
            if not QUIET:
                if VERBOSE:
                    print "GET submission:", sid
                else:
                    print "S",
            submission = ds.get_submission(sid)
            if not submission:
                continue
            file_srls = [x[0] for x in submission['files']]
            res_keys = {}
            for key in submission['results']:
                srl = key[:64]
                keys = res_keys.get(srl, [])
                keys.append(key)
                res_keys[srl] = keys

            for srl in file_srls:
                if not QUIET:
                    if VERBOSE:
                        print "\tGET file:", srl
                    else:
                        print "F",
                if not ds.get_file(srl):
                    if not QUIET:
                        if VERBOSE:
                            print "\t\tERROR"
                        else:
                            print "-E-",

                for key in res_keys[srl]:
                    if not QUIET:
                        if VERBOSE:
                            print "\t\tGET result:", key
                        else:
                            print "R",

                    if not ds.get_result(key):
                        if not QUIET:
                            if VERBOSE:
                                print "\t\t\tERROR"
                            else:
                                print "-E-",

            if not QUIET:
                print ""
