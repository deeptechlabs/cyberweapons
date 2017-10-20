#!/bin/sh

{ python | grep -F 'SHARDS:' | sed -e 's/SHARDS: //g'; } <<EOF
from assemblyline.al.common import forge
config = forge.get_config()
print 'SHARDS:', ' '.join([str(n) for n in range(0, $1)])
EOF

