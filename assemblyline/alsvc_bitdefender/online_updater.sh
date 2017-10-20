#!/usr/bin/env bash

touch /opt/BitDefender-scanner/var/lib/scan/bdcore.so.linux-x86_64
bdscan --update
rm /opt/BitDefender-scanner/var/lib/scan/bdcore.so
ln -s /opt/BitDefender-scanner/var/lib/scan/bdcore.so.linux-x86_64 /opt/BitDefender-scanner/var/lib/scan/bdcore.so