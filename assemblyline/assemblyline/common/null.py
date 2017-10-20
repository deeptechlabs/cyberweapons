class CountryCodeMap(object):
    def __getitem__(self, ip):
        return '??'


# noinspection PyUnusedLocal
def compute_notice_field(_notice, _name):
    return None, False


# noinspection PyUnusedLocal
def create_alert(_counter, _datastore, _logger, _message):
    pass


def decode_file(_, fileinfo):
    return None, None, fileinfo


# noinspection PyUnusedLocal
def encode_file(data, file_format, name, password=None):  # pylint: disable=W0613
    error = {}

    if file_format != 'raw':
        error['code'] = 500
        error['text'] = "Invalid file format specified."

    return data, error


def is_low_priority(_):
    return False

whitelist = []
