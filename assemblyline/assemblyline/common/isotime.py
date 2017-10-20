from datetime import datetime
from time import time

EPOCH = datetime.utcfromtimestamp(0)
ISO_FMT = '%Y-%m-%dT%H:%M:%S'
LOCAL_FMT = '%Y-%m-%d %H:%M:%S'

# DO NOT REMOVE!!! THIS IS MAGIC!
# strptime Thread safe fix... yeah ...
datetime.strptime("2000", "%Y")
# END OF MAGIC


def _epoch_to_ms(t):
    # noinspection PyBroadException
    try:
        return str(t - int(t))[1:]
    except:  # pylint:disable=W0702
        return ''


def _timestamp_to_ms(ts):
    # noinspection PyBroadException
    try:
        start = ts.find('.')
        end = ts.find('Z')
        if end == -1:
            end = len(ts)

        return float(ts[start:end])
    except:  # pylint:disable=W0702
        return 0.0


def epoch_to_iso(t):
    s = datetime.utcfromtimestamp(t).isoformat()
    return ''.join((s, 'Z'))


def epoch_to_local(t):
    s = datetime.fromtimestamp(t).strftime(LOCAL_FMT)
    return ''.join((s, _epoch_to_ms(t)))[:26]


def iso_to_epoch(ts, hp=False):
    if not ts:
        return 0
    dt = datetime.strptime(ts[:19], ISO_FMT)
    if hp:
        return long(((dt - EPOCH).total_seconds() + _timestamp_to_ms(ts)) * 1000000)
    else:
        return (dt - EPOCH).total_seconds() + _timestamp_to_ms(ts)


def iso_to_local(ts):
    return epoch_to_local(iso_to_epoch(ts))


def local_to_epoch(ts, hp=False):
    epoch = iso_to_epoch("%sZ" % ts.replace(" ", "T"))
    if hp:
        return long((epoch + (utc_offset_from_local(epoch) * 3600)) * 1000000)
    else:
        return epoch + (utc_offset_from_local(epoch) * 3600)


def local_to_iso(ts):
    return epoch_to_iso(local_to_epoch(ts))


def now(offset=0.0):
    return time() + offset


def now_as_iso(offset=0.0):
    return epoch_to_iso(now(offset))


def now_as_local(offset=0.0):
    return epoch_to_local(now(offset))


def utc_offset_from_local(cur_time=None):
    if not cur_time:
        cur_time = time()
    return int(cur_time - iso_to_epoch("%sZ" % epoch_to_local(cur_time).replace(" ", "T"))) / 3600

if __name__ == "__main__":
    my_time = time()
    print "\nCurrent Epoch:", my_time
    print "Now as Epoch:", now(), "\n"

    print "Now as ISO:", now_as_iso()
    print "Now as Local:", now_as_local(), "\n"

    temp_time = time()
    print "Testing conversion functions with time:", temp_time
    print "\tLocal -> ISO:", abs(iso_to_epoch(local_to_iso(epoch_to_local(temp_time))) - temp_time) < 0.000001
    print "\tISO -> Local:", abs(local_to_epoch(iso_to_local(epoch_to_iso(temp_time))) - temp_time) < 0.000001, "\n"

    print "Testing functions with time:", my_time
    print "\tISO functions:", my_time == iso_to_epoch(epoch_to_iso(my_time))
    print "\tLocal functions:", abs(my_time - local_to_epoch(epoch_to_local(my_time))) < 0.000001
    print "\tUTC offset from local:", utc_offset_from_local(my_time), "\n"

    my_time = local_to_epoch("2015-01-01 00:00:00")
    print "Testing functions with time (NOT daylight savings time):", my_time
    print "\tISO functions:", my_time == iso_to_epoch(epoch_to_iso(my_time))
    print "\tLocal functions:", abs(my_time - local_to_epoch(epoch_to_local(my_time))) < 0.000001
    print "\tUTC offset from local:", utc_offset_from_local(my_time), "\n"

    my_time = local_to_epoch("2015-05-05 00:00:00")
    print "Testing functions with time (Daylight savings time):", my_time
    print "\tISO functions:", my_time == iso_to_epoch(epoch_to_iso(my_time))
    print "\tLocal functions:", abs(my_time - local_to_epoch(epoch_to_local(my_time))) < 0.000001
    print "\tUTC offset from local:", utc_offset_from_local(my_time)
