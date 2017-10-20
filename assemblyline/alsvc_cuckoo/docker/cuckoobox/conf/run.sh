#!/usr/bin/env bash

pkill "^inetsim_*"

rm /run/inetsim.pid
find /var/log/inetsim/ -type f -delete
find /var/lib/inetsim/ -name "*.mbox" -delete

iptables -F
iptables-restore /home/sandbox/conf/rules.v4

/usr/bin/inetsim
