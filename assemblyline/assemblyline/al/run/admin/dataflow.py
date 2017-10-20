#!/usr/bin/env python

import re
import sys

head = ''
rules = {}

while True:
    line = sys.stdin.readline()
    if not line:
        break

    line = line.strip()

    match = re.match(r'.*# df (.*?)(?: #[^#]*)?$', line)

    if not match:
        continue

    directive = match.groups()[0]

    command = directive.split(' ', 1)

    if command[0] == 'text':
        print command[1]
    elif command[0] == 'rule':
        name, args = command[1].split(' ', 1)
        rule = args.split(' => ')
        rules[name] = [rule[0].strip(), rule[1].strip()]
    elif command[0] == 'line':
        rule = rules[command[1]]
        print re.sub(rule[0], rule[1], line)
    elif command[0] == 'node':
        rule = rules[command[1]]
        head = re.sub(rule[0], rule[1], line)
    elif command[0] == 'pull':
        rule = rules[command[1]]
        print "%s -> %s [label=%s]" % (
            re.sub(rule[0], rule[1], line), head, command[1]
        )
    elif command[0] == 'push':
        rule = rules[command[1]]
        print "%s -> %s [label=%s]" % (
            head, re.sub(rule[0], rule[1], line), command[1]
        )

#print rules

