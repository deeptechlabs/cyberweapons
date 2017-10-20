import time
import uuid

print 'waiting for networking...'

from assemblyline.al.common.queue import NamedQueue

time.sleep(2)


# TODO Rewrite this entirely
def wait_for_networking(timeout):
    uid = uuid.uuid4().get_hex()
    for _each_second in xrange(timeout):
        try:
            q = NamedQueue('hostagent-redischeck-%s' % uid)
            q.push('can i reach you')
            q.pop(timeout=1, blocking=False)
            return True
        except Exception as e:
            print('waiting for redis reachability. %s ' % str(e))
    return False

wait_for_networking(10)
