#!/bin/sh

{ python | grep -F 'DELETERS:' | sed -e 's/DELETERS: //g'; } <<EOF
from assemblyline.al.common import forge
config = forge.get_config()
print 'DELETERS:', ' '.join([str(n) for n in range(0, config.core.expiry.workers)])
EOF

