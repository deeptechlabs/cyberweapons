#!/usr/bin/env python

# ./generate_LCID.py < LCID > LCID.py

import os
import pprint

def generate_LCID(f):
    lcid = {}
    for line in f:
        tpl = line.split("|")
        if len(tpl) == 3:
            lcid[int(tpl[2])] = unicode(tpl[0], 'utf-8')
    return lcid

if __name__ == '__main__':
    print "LCID = \\"
    pprint.pprint(generate_LCID(os.sys.stdin))

