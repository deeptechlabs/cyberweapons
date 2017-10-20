
class NamedConstants(object):

    def __init__(self, name, string_value_list):
        self._name = name
        self._value_map = dict(string_value_list)
        self._reverse_map = dict([(s[1], s[0]) for s in string_value_list])

        # we also import the list as attributes so things like
        # tab completion and introspection still work.
        for s, v in self._value_map.iteritems():
            setattr(self, s, v)

    def name_for_value(self, v):
        return self._reverse_map[v]

    def contains_value(self, v):
        return v in self._reverse_map

    def __getitem__(self, s):
        return self._value_map[s]

    def __getattr__(self, s):
        # We implement our own getattr mainly to provide the better exception.
        return self._value_map[s]


class StringTable(object):

    def __init__(self, name, string_value_list):
        self._name = name
        self._value_map = dict(string_value_list)
        self._reverse_map = dict([(s[1], s[0]) for s in string_value_list])

        # we also import the list as attributes so things like
        # tab completion and introspection still work.
        for s in self._value_map.keys():
            setattr(self, s, s)

    def name_for_value(self, v):
        return self._reverse_map[v]

    def contains_string(self, s):
        return s in self._reverse_map

    def contains_value(self, v):
        return v in self._value_map

    def __getitem__(self, s):
        if s in self._value_map:
            return s
        raise AttributeError("Invalid value for %s (%s)" % (self._name, s))

    def __getattr__(self, s):
        # We implement our own getattr mainly to provide the better exception.
        if s in self._value_map:
            return s
        raise AttributeError("Invalid value for %s (%s)" % (self._name, s))
