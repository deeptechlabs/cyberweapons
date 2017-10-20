#!/usr/bin/env python
import sys
import time

from assemblyline.al.common import forge
config = forge.get_config()

if __name__ == "__main__":
    valid_buckets = ['submission', 'file', 'result']
    # Initializing datastore
    if len(sys.argv) in [1, 2]:
        print "usage: expiry.py <bucket> <datastore_ip_1> ... <datastore_ip_n>"
        exit(1)
    bucket = sys.argv[1]
    if bucket not in valid_buckets:
        print "usage: expiry.py <bucket> <datastore_ip_1> ... <datastore_ip_n>"
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
        for item in ds.stream_search(bucket, "__expiry_ts__:[* TO NOW]"):
            if bucket == "submission":
                ds.delete_submission(item['_yz_rk'])
            elif bucket == "file":
                ds.delete_file(item['_yz_rk'])
            elif bucket == "result":
                ds.delete_result(item['_yz_rk'])

        time.sleep(1)
