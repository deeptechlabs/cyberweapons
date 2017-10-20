#!/usr/bin/env python
# This script can be run on the core server to upgrade the riak cluster to support workflows

import riak

client = riak.RiakClient(protocol='pbc', nodes=[{'host': 'localhost'}])
client.resolver = riak.resolver.last_written_resolver

with open('/opt/al/pkg/assemblyline/al/install/etc/riak/schema/workflow.xml') as wf_handle:
    workflow_schema = wf_handle.read()

client.create_search_schema(schema='workflow', content=workflow_schema)
client.create_search_index('workflow', 'workflow', 3)

bucket = client.bucket('workflow', bucket_type="data")
props = {
    'dvv_enabled': False,
    'last_write_wins': True,
    'allow_mult': False,
    'n_val': 3,
    'search_index': 'workflow'
}
client.set_bucket_props(bucket=bucket, props=props)
