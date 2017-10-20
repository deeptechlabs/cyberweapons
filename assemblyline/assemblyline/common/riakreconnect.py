import time


class RiakReconnect(object):
    RECONNECT_MSGS = ["insufficient_vnodes",
                      "Unknown message code: ",
                      "all_nodes_down",
                      "Socket returned short packet",
                      "Not enough nodes are up to service this request.",
                      "connected host has failed to respond",
                      "target machine actively refused it",
                      "timeout",
                      "Connection refused",
                      "Truncated message",
                      "Truncated string",
                      "Unexpected end-group tag",
                      "unknown msg code",
                      "key must be a string, instead got None",
                      "Tag had invalid wire type",
                      "returned zero bytes unexpectedly",
                      "unexpected message code:",
                      "Client is closed.",
                      "established connection was aborted",
                      "existing connection was forcibly closed",
                      "Error processing incoming message:"]
    MAX_RETRY_BACKOFF = 10

    def __init__(self, reconnect_func, log=None):
        self._reconnect_func = reconnect_func
        self.log = log

    def __call__(self, original):
        def wrapper(*args, **kw):
            s = args[0]
            retries = 0
            while True:
                try:
                    return original(*args, **kw)
                except OverflowError:
                    self._reconnect_func(s)
                    retries += 1
                except Exception, e:  # pylint: disable=W0703
                    re_raise = True
                    for x in self.RECONNECT_MSGS:
                        msg = str(e)
                        if x in msg:
                            if retries < self.MAX_RETRY_BACKOFF:
                                time.sleep(retries)
                            else:
                                time.sleep(self.MAX_RETRY_BACKOFF)
                            if self.log and retries % 10 == 0:
                                self.log.debug("Reconnecting to riak: %s", msg)
                            self._reconnect_func(s)
                            re_raise = False
                            break

                    if re_raise:
                        raise
                    else:
                        retries += 1

        # Make this a well-behaved decorator.
        wrapper.__name__ = original.__name__
        wrapper.__doc__ = original.__doc__
        wrapper.__dict__.update(original.__dict__)

        return wrapper
