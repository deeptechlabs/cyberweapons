import threading
import time

from collections import OrderedDict


class TimeExpiredCache(object):
    """
    TimeExpiredCache is a thread safe caching object that will store any amount of items for
    a period of X seconds at maximum.

    A thread inside the cache is fired every "expiry_rate" seconds and will remove all items that
    meet their timeouts.

    If you add the same item twice, the second time you add the item it will be ignored or can
    raise an exception if specified. This will not freshen the timeout for the specified item.
    """

    def __init__(self, timeout, expiry_rate=5, raise_on_error=False):
        self.lock = threading.Lock()
        self.timeout = timeout
        self.expiry_rate = expiry_rate
        self.raise_on_error = raise_on_error
        self.cache = {}
        self.timeout_list = []
        timeout_thread = threading.Thread(target=self._process_timeouts, name="_process_timeouts")
        timeout_thread.setDaemon(True)
        timeout_thread.start()

    def __len__(self):
        with self.lock:
            return len(self.cache)

    def __str__(self):
        with self.lock:
            return 'TimeExpiredCache(%s): %s' % (self.timeout, str(self.cache.keys()))

    def _process_timeouts(self):
        while True:
            time.sleep(self.expiry_rate)
            current_time = time.time()
            index = 0

            with self.lock:
                for t, k in self.timeout_list:
                    if t >= current_time:
                        break

                    index += 1

                    self.cache.pop(k, None)

                self.timeout_list = self.timeout_list[index:]

    def add(self, key, data):
        with self.lock:
            if key in self.cache:
                if self.raise_on_error:
                    raise KeyError("%s already in cache" % key)
                else:
                    return

            self.cache[key] = data
            self.timeout_list.append((time.time() + self.timeout, key))

    def get(self, key, default=None):
        with self.lock:
            return self.cache.get(key, default)

    def keys(self):
        with self.lock:
            return self.cache.keys()


class SizeExpiredCache(object):
    """
    SizeExpiredCache is a thread safe caching object that will store only X number of item for
    caching at maximum.

    If more items are added, the oldest item is removed.

    If you add the same item twice, the second time you add the item it will be ignored or can
    raise an exception if specified. This will not freshen the item position in the cache.
    """

    def __init__(self, max_item_count, raise_on_error=False):
        self.lock = threading.Lock()
        self.max_item_count = max_item_count
        self.cache = OrderedDict()
        self.raise_on_error = raise_on_error

    def __len__(self):
        with self.lock:
            return len(self.cache)

    def __str__(self):
        with self.lock:
            return 'SizeExpiredCache(%s/%s): %s' % (len(self.cache), self.max_item_count, str(self.cache.keys()))

    def add(self, key, data):
        with self.lock:
            if key in self.cache:
                if self.raise_on_error:
                    raise KeyError("%s already in cache" % key)
                else:
                    return

            self.cache[key] = data
            if len(self.cache) > self.max_item_count:
                self.cache.popitem(False)

    def get(self, key, default=None):
        with self.lock:
            return self.cache.get(key, default)

    def keys(self):
        with self.lock:
            return self.cache.keys()


# Test caches...
if __name__ == "__main__":
    print "Testing TimeExpiredCache ..."
    tc = TimeExpiredCache(5, 1)
    tc.add(1, 1)
    time.sleep(1)
    tc.add(2, 2)
    while len(tc) > 0:
        print tc, "get(1) =>", tc.get(1)
        time.sleep(1)
    else:
        print tc, tc.get(1)

    print "\nTesting SizeExpiredCache..."
    sc = SizeExpiredCache(5)
    for x in range(10):
        sc.add(x, x)
        print sc, "get(%s) =>" % x, sc.get(x)
