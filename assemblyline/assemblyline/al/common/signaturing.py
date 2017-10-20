import re

_operators = {
    'in': lambda args: lambda x: x in args,
    'not in': lambda args: lambda x: x not in args,
    'regexp': lambda args: re.compile(*args).match,
}


# noinspection PyBroadException
def _call(cache, data, func, key):
    try:
        value = cache.get(key, None)
        if not value:
            cache[key] = value = data.get(key)
        if not callable(func):
            func = _transform(func)
        return {key: value} if func(value) else {}
    except:  # pylint: disable=W0702
        return {}


def _match(cache, data, sig):
    summary = {}
    results = [
        _call(cache, data, f, k) for k, f in sig['conditions'].iteritems()
    ]
    if all(results):
        [summary.update(r) for r in results]  # pylint: disable=W0106
    return summary


def _matches(data, sigs):
    cache = {}
    unknown = 0
    for sig in sigs:
        result = _match(cache, data, sig)
        if result:
            name = sig.get('name', None)
            if not name:
                unknown += 1
                name = "unknown%d" % unknown
            yield((name, result))
    return


def optimize(signatures):
    for sig in signatures:
        conditions = sig.get('conditions')
        for k, v in conditions.iteritems():
            conditions[k] = _transform(v)


def _transform(condition):
    if isinstance(condition, basestring):
        args = [condition]
        func = 'regexp'
    else:
        args = list(condition[1:])
        func = condition[0]

    return _operators[func](args)


def drop(whitelist, data):
    return next(_matches(data, whitelist), ("", {}))


# noinspection PyUnusedLocal
def check(_data):
    # Returns a float between -1 and 1 where
    # -1 KNOWN MALICIOUS
    #  0 UNKNOWN
    #  1 KNOWN GOOD
    pass
