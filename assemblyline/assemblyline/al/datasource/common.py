import re
HASH_RE = r'^[0-9a-fA-F]{32,64}$'
HASH_PATTERN = re.compile(HASH_RE)


class DatasourceException(Exception):
    pass


def hash_type(value):
    if HASH_PATTERN.match(value):
        return {
            32: "md5", 40: "sha1", 64: "sha256"
        }.get(len(value), "invalid")
    else:
        return "invalid"

# noinspection PyUnusedLocal
class Datasource(object):
    @staticmethod
    def hash_type(value):
        return hash_type(value)

    # Subclasses should implement the following methods.
    def __init__(self, log, **kw):  # pylint: disable=W0613
        self.log = log

    def parse(self, result, **kw):  # pylint: disable=W0613
        pass

    def query(self, value, **kw):  # pylint: disable=W0613
        pass


# noinspection PyMethodMayBeStatic,PyUnusedLocal
class Null(object):
    def __init__(self, e=None):
        self.e = e

    def parse(self, result, **kw):  # pylint: disable=W0613
        return []

    def query(self, value, **kw):  # pylint: disable=W0613
        if self.e:
            raise self.e  # pylint: disable=E0702

        return []
