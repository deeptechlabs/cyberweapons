# noinspection PyBroadException
def try_setproctitle(name):
    try:
        from setproctitle import setproctitle  # @UnresolvedImport
        setproctitle(name)
    except:  # pylint:disable-msg=W0702
        pass
