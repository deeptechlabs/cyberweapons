from assemblyline.common.charset import safe_str
from assemblyline.common.isotime import epoch_to_iso
from assemblyline.al.common import forge
from assemblyline.al.common import task
from assemblyline.al.common.forge import get_constants, get_config

constants = get_constants()
config = get_config()


class NoticeException(Exception):
    pass


alert = [
    'sid',
]

aliases = config.core.alerter.metadata_aliases
meta_fields = {
    "al_score": "number",
    "filename": "text",
    "size": "number",
    "ts": "date"
}
meta_fields.update(config.core.alerter.metadata_fields)
metadata = meta_fields.keys()

overrides = task.submission_overrides + [
    'completed_queue',
    'description',
    'generate_alert',
    'groups',
    'notification_queue',
    'notification_threshold',
    'psid',
    'resubmit_to',
    'scan_key',
    'selected',
    'submitter',
]

root = {
    'failure': False,
    'initial_key': False,
    'never_drop': False,
    'priority': False,
    'resubmit_key': False,
    'retries': False,
    'retry_at': False,
    'sha256': False,
    'type': False,
}


# noinspection PyBroadException
def ensure_bool(v):
    try:
        return bool(v)
    except:  # pylint: disable=W0702
        return False


# noinspection PyBroadException
def ensure_int(v):
    try:
        return int(v)
    except:  # pylint: disable=W0702
        return 0


def ensure_iso(v):
    try:
        return epoch_to_iso(float(v))
    except (TypeError, ValueError):
        return v


def ensure_safe_list(v):
    if type(v) != list:
        # We assume a pipe ('|') separated string if v is not a list.
        v = safe_str(v).split('|')
    return [safe_str(x) for x in v if x]


def identity(v):
    return v

translation = {
    k: {
        'bool': ensure_bool,
        'date': ensure_iso,
        'list': ensure_safe_list,
        'number': ensure_int,
        'text': safe_str,
    }.get(v, identity) for k, v in meta_fields.iteritems()
}


class Notice(object):
    parent = root.copy()

    # noinspection PyTypeChecker
    def __init__(self, raw=None):
        self.compute_notice_field = forge.get_compute_notice_field()
        self.raw = raw or {}
        self.__class__ = {
            'FLAT': FlatNotice,
        }.get(self.raw.get('type', 'FLAT'), StructuredNotice)

    def __contains__(self, name):
        return self._contains(name)

    def _contains(self, name):
        alias = aliases.get(name, False)

        # The alias (if any) must exist in the same container.
        container = self._container(name)
        if container is None:
            return False

        return name in container or (alias and alias in container)

    def _container(self, name):
        has_parent = self.parent.get(name, None)

        raw = self.raw
        if has_parent is None or raw is None:
            return None

        container = raw
        if has_parent:
            container = raw.get(has_parent, None)
            if container is None:
                container = {}
                raw[has_parent] = container

        return container

    def _get(self, name, default):
        alias = aliases.get(name, None)

        # The alias (if any) must exist in the same container.
        container = self._container(name)
        if container is None:
            raise KeyError(name)

        if not alias or name in container:
            return container.get(name, default)

        return container.get(alias, default)

    def update_alert(self, additional_fields, alert_data):
        alert_data.update({
            k: self.get(k) for k in set(additional_fields + alert_data.keys()) if k in self and self.get(k)
        })
        return alert_data

    def get(self, name, default=None):
        value, computed = self.compute_notice_field(self, name)
        if not computed:
            value = self._get(name, default)
        return translation.get(name, identity)(value)

    def has_key(self, name):
        return self._contains(name)

    def metadata(self):
        try:
            return self.get("metadata", {})
        except KeyError:
            return {}

    def parse(self, **defaults):
        hdr = {
            k: self.get(k, defaults.get(k, None)) for k in overrides if k in self or k in defaults
        }
        hdr['metadata'] = self.metadata()

        return hdr

    def set(self, name, value):
        alias = aliases.get(name, None)

        # The alias (if any) must exist in the same container.
        container = self._container(name)
        if container is None:
            raise KeyError(name)

        if not alias or name in container:
            container[name] = value
            return

        container[alias] = value


class FlatNotice(Notice):
    parent = root.copy()

    parent.update({k: False for k in alert})
    parent.update({k: False for k in metadata})
    parent.update({k: False for k in aliases.itervalues()})
    parent.update({k: False for k in overrides})

    def metadata(self):
        return {k: self.get(k) for k in metadata if k in self}


class StructuredNotice(Notice):
    parent = root.copy()

    parent.update({
        'alert': False,
        'metadata': False,
        'overrides': False,
    })

    parent.update({k: 'alert' for k in alert})
    parent.update({k: 'metadata' for k in metadata})
    parent.update({k: 'metadata' for k in aliases.itervalues()})
    parent.update({k: 'overrides' for k in overrides})

    def metadata(self):
        return self.get('metadata', {})

    def parse(self, **defaults):
        hdr = {}
        hdr.update(defaults)
        hdr.update(self.get('overrides', {}))

        meta = self.metadata()
        if meta:
            hdr['metadata'] = meta

        return hdr
