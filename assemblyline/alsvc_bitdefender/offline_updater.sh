#!/usr/bin/env bash

unzip -o /tmp/bdupd_dir/cumulative.zip -d /opt/BitDefender-scanner/var/lib/scan
rm /opt/BitDefender-scanner/var/lib/scan/bdcore.so
ln -s /opt/BitDefender-scanner/var/lib/scan/bdcore.so.linux-x86_64 /opt/BitDefender-scanner/var/lib/scan/bdcore.so