
hostname = 'unknownhost'
# noinspection PyBroadException
try:
    from assemblyline.common.net import get_hostname
    hostname = get_hostname()
except:  # pylint:disable=W0702
    pass

ip = 'x.x.x.x'
# noinspection PyBroadException
try:
    from assemblyline.common.net import get_hostip
    ip = get_hostip()
except:  # pylint:disable=W0702
    pass

AL_SYSLOG_FORMAT = ip + ' AL %(levelname)8s %(process)5d %(name)20s | %(message)s'
AL_LOG_FORMAT = '%(asctime)-16s %(levelname)8s ' + hostname + ' %(process)d %(name)30s | %(message)s'
