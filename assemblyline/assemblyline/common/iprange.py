from math import log
from socket import inet_aton
from struct import pack, unpack


# If you are tempted to extend this module to add support for IPv6 (or some
# similar invasive change) take a look at using PySubnetTree and extending it
# to allow arbitrary ranges instead.

def _convert(ip):
    return unpack('!I', inet_aton(ip))[0]


def _next(lower, upper):
    size = 2
    while lower + size - 1 <= upper and _valid(lower, lower + size - 1):
        size *= 2

    return size / 2


def _valid(lower, upper):
    return lower & (upper - lower) == 0


# noinspection PyPep8Naming
class _dict(dict):
    pass


def ip_to_int(ip):
    if type(ip) == int:
        return ip
    return _convert(ip)


# noinspection PyTypeChecker
class RangeTable(object):
    """Efficient storage of IPv4 ranges and lookup of IPv4 addresses."""

    def __init__(self):
        self.clear()
        self._trie = _dict()

    def _add_cidr(self, lower, upper, value):
        if not _valid(lower, upper):
            # The public add_range method should ensure this never happens.
            raise Exception("invalid range: %d-%d" % (lower, upper))

        size = upper - lower
        points = 3 - int(log(size + 1, 256))

        lower = self._to_path(lower)
        upper = self._to_path(upper)

        for x in range(lower[points], upper[points] + 1):
            self._add_path(lower[:points] + (x,), value)

    def _add_path(self, path, value):
        trie = self._trie
        for point in path[:-1]:
            d = trie.get(point, _dict())
            if not isinstance(d, _dict):
                prev = d
                d = _dict()
                d.update({x: prev for x in range(0, 256)})
            trie[point] = d
            trie = d
        trie[path[-1]] = value

    def _add_range(self, lower, upper, value):
        while lower <= upper:
            size = _next(lower, upper)
            self._add_cidr(lower, lower + size - 1, value)
            lower += size

    def _follow_path(self, path):
        entry = self._trie
        while isinstance(entry, _dict):
            entry = entry.get(path[0], None)
            path = path[1:]
        return entry

    @staticmethod
    def _to_path(integer):
        return unpack('B' * 4, pack('!I', integer))

    def __getitem__(self, key):
        return self._follow_path(self._to_path(ip_to_int(key)))

    def __setitem__(self, key, value):
        if type(key) == int:
            self._add_cidr(key, key, value)
            return

        span = key.split('-', 1)
        if len(span) == 1:
            span = key.split('/', 1)
        if len(span) == 1:
            span.append(span[0])

        span[0] = _convert(span[0].strip())
        if span[1].find('.') == -1:
            mask = 2 ** (32 - int(span[1])) - 1
            span[0] -= span[0] & mask
            span[1] = span[0] | mask
        else:
            span[1] = _convert(span[1].strip())

        self._add_range(span[0], span[1], value)

    def add_range(self, lower, upper, value):
        lower = ip_to_int(lower)
        upper = ip_to_int(upper)

        self._add_range(lower, upper, value)

        while lower <= upper:
            size = _next(lower, upper)
            self._add_cidr(lower, lower + size - 1, value)
            lower += size

    def clear(self):
        self._trie = _dict()  # pylint:disable=W0201

    def dump(self):
        from pprint import pformat
        return pformat(self._trie)


PRIVATE_NETWORKS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]

RESERVED_NETWORKS = [
    "0.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "240.0.0.0/4",
    "224.0.0.0/4",
    "255.255.255.255/32",
]

_private_ips = RangeTable()
for cidr in PRIVATE_NETWORKS:
    _private_ips[cidr] = True

_reserved_ips = RangeTable()
for cidr in RESERVED_NETWORKS:
    _reserved_ips[cidr] = True


def is_ip_private(ip):
    return _private_ips[ip] or False


def is_ip_reserved(ip):
    return _private_ips[ip] or _reserved_ips[ip] or False


if __name__ == '__main__':
    r = RangeTable()
    r['0.0.0.0/24'] = 'blah'

    print r['0.0.0.0']
    print r['0.0.0.1']
    print r['0.0.1.1']

    print r[0]
    print r[1]
    print r[1000]

    r['0.0.0.1-0.0.0.2'] = {'message': 'not blah'}
    r['0.0.0.200 - 0.0.1.2'] = 'testing'
    r['127.0.0.1/8'] = 'loopback'  # Notice we handle the incorrect CIDR.

    print r['0.0.0.0']
    print r['0.0.0.1']
    print r['0.0.1.1']

    print r.dump()
