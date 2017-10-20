from assemblyline.common.importing import class_by_name
from assemblyline.al.common import forge

Classification = forge.get_classification()


class InvalidClassificationException(Exception):
    pass


class Heuristic(object):
    def __init__(self, hid, name, filetype, description, classification=Classification.UNRESTRICTED):
        self.id = hid
        self.name = name
        self.filetype = filetype
        self.description = description
        self.classification = classification
        if not Classification.is_valid(classification):
            raise InvalidClassificationException()

    def __repr__(self):
        return "Heuristic('{id}', '{name}', '{filetype}', " \
               "'{description}', '{classification}')".format(id=self.id, name=self.name,
                                                             filetype=self.filetype, description=self.description,
                                                             classification=self.classification)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "filetype": self.filetype,
            "description": self.description.strip(),
            "classification": self.classification
        }


def get_heuristics_form_class(cls):
    out = []
    try:
        for c_cls in list(cls.__mro__)[:-1][::-1]:
            out.extend([v for v in c_cls.__dict__.itervalues() if isinstance(v, Heuristic) and v not in out])
    except AttributeError:
        pass

    return sorted(out, key=lambda k: k.id)


def list_all_heuristics(srv_list):
    out = []
    for srv in srv_list:
        cls_path = srv.get('classpath', None)
        if cls_path:
            try:
                cls = class_by_name(cls_path)
            except ImportError:
                continue
            out.extend(cls.list_heuristics())
    return out, {x['id']: x for x in out}
