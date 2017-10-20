import socket
import uuid

from assemblyline.common.net_static import TLDS_ALPHA_BY_DOMAIN


def is_valid_domain(domain):
    if "@" in domain:
        return False

    if "." in domain:
        tld = domain.split(".")[-1]
        return tld.upper() in TLDS_ALPHA_BY_DOMAIN

    return False


def is_valid_ip(ip):
    parts = ip.split(".")
    if len(parts) == 4:
        for p in parts:
            try:
                if 0 <= int(p) <= 255:
                    continue
            except ValueError:
                return False

        return True

    return False


def is_valid_email(email):
    parts = email.split("@")
    if len(parts) == 2:
        if is_valid_domain(parts[1]):
            return True

    return False


def get_hostname():
    return socket.gethostname()


def get_mac_address():
    return "".join(["{0:02x}".format((uuid.getnode() >> i) & 0xff) for i in range(0, 8 * 6, 8)][::-1]).upper()


# noinspection PyUnboundLocalVariable
def get_mac_for_ip(ip):
    import netifaces as nif
    for i in nif.interfaces():
        addrs = nif.ifaddresses(i)
        try:
            if_mac = addrs[nif.AF_LINK][0]['addr']
            if_ip = addrs[nif.AF_INET][0]['addr']
        except (IndexError, KeyError):
            if_mac = if_ip = None

        if if_ip == ip:
            return if_mac.replace(':', '').upper()

    # If we couldn't match on IP just use the old uuid based approach.
    return get_mac_address()


def get_random_mac(seperator=':'):
    from random import randint
    oui = [0x52, 0x54, 0x00]
    mac = oui + [randint(0, 0xff), randint(0, 0xff), randint(0, 0xff)]
    return seperator.join("%02x" % x for x in mac).upper()


# noinspection PyBroadException,PyUnresolvedReferences,PyUnboundLocalVariable
def get_hostip():
    import netifaces as nif
    # fetch the nic serving up the default gateway
    if_default = nif.gateways().get('default')
    (ip, nic) = if_default.get(nif.AF_INET)
    # Fetch the IP of that nic
    try:
        ip = nif.ifaddresses(nic).get(nif.AF_INET)[0].get('addr')
    except:
        import sys
        import subprocess

        subnet = ip.split(".")[0]
        if sys.platform.startswith('win'):
            proc = subprocess.Popen('ipconfig', stdout=subprocess.PIPE)
            output = proc.stdout.read()
            for line in output.split('\n'):
                if "IP Address" in line and ": %s" % subnet in line:
                    ip = line.split(": ")[1].replace('\r', '')
                    break

        else:
            proc = subprocess.Popen('ifconfig', stdout=subprocess.PIPE)
            output = proc.stdout.read()

            for line in output.split('\n'):
                if "addr:%s" % subnet in line:
                    ip = line.split("addr:")[1].split(" ")[0]
                    break

    return ip
