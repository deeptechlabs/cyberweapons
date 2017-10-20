""" Mock Transports for use in testing and performan analysis."""

class FetchOnceMockTransport(object):
    """ A mock transport that will fetch the file specified at instantiation
        time and return that payload for all subsequent calls to get(). """

    def __init__(self, transport, replay_file):
        self.file_payload = transport.get(replay_file)

    def get(self, _unused_file):
        """ Return the fetch mock/replay payload. """
        return self.file_payload
