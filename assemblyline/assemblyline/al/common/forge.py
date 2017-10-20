import importlib

from easydict import EasyDict

from assemblyline.common.importing import module_attribute_by_name
from assemblyline.al.common.config_riak import get_config


def _dynamic_import(path):
    if not path:
        ImportError("Error importing '%s'" % path or '')
    return module_attribute_by_name(path)


def apply_overrides(overrides):
    config = get_config()
    msgs = []
    if not overrides:
        return msgs

    parent_ip = overrides.get('parent_ip', None)
    if parent_ip and config.workers.virtualmachines.use_parent_as_datastore:
        config.datastore.hosts = [parent_ip]
        msgs.append("parent (%s) as datastore" % parent_ip)
    if parent_ip and config.workers.virtualmachines.use_parent_as_queue:
        config.core.redis.nonpersistent.host = parent_ip
        msgs.append("parent (%s) as queue" % parent_ip)

    return msgs


# noinspection PyShadowingNames
def determine_dispatcher(sid, shards=None):
    if not shards:
        shards = get_config().core.dispatcher.shards
    n = reduce(lambda x, y: x ^ y, [int(y, 16) for y in sid[-12:]])
    return n % shards


# noinspection PyShadowingNames
def determine_ingest_queue(sha256, shards=None):
    if not shards:
        shards = get_config().core.middleman.shards
    n = reduce(lambda x, y: x ^ y, [int(y, 16) for y in sha256[:4]])
    return 'm-ingest-' + str(n % shards)


def get_classification():
    config = get_config()
    classification = _dynamic_import(config.system.classification.engine)
    return classification(config.system.classification.definition)


def get_constants():
    config = get_config()
    return importlib.import_module(config.system.constants)


def get_compute_notice_field():
    config = get_config()
    return _dynamic_import(config.core.bulk.compute_notice_field)


def get_create_alert():
    config = get_config()
    return _dynamic_import(config.core.alerter.create_alert)


def get_control_queue(name):
    from assemblyline.al.common.queue import NamedQueue
    return NamedQueue(name)


def get_country_code_map():
    config = get_config()
    return _dynamic_import(config.system.country_code_map)()


def get_datastore():
    from assemblyline.al.core.datastore import RiakStore
    return RiakStore()


def get_decode_file():
    config = get_config()
    return _dynamic_import(config.submissions.decode_file)


def get_dispatch_queue():
    from assemblyline.al.common.queue import DispatchQueue
    return DispatchQueue()


def get_dn_parser():
    config = get_config()
    try:
        return _dynamic_import(config.auth.dn_parser)
    except: # pylint: disable=W0702
        return None


def get_filestore():
    from assemblyline.al.core.filestore import FileStore
    config = get_config()
    return FileStore(*config.filestore.urls)


def get_is_low_priority():
    config = get_config()
    return _dynamic_import(config.core.bulk.is_low_priority)


def get_get_whitelist_verdict():
    config = get_config()
    return _dynamic_import(config.core.bulk.get_whitelist_verdict)


def get_metrics_sink():
    from assemblyline.al.common.queue import CommsQueue
    return CommsQueue('SsMetrics')


def get_service_queue(service_name):
    from assemblyline.al.common.queue import PriorityQueue
    return PriorityQueue(name='Service-%s' % service_name)


def get_site_specific_apikey_handler():
    config = get_config()
    return _dynamic_import(config.auth.get('apikey_handler', 'al_ui.site_specific.validate_apikey'))


def get_site_specific_dn_handler():
    config = get_config()
    return _dynamic_import(config.auth.get('dn_handler', 'al_ui.site_specific.validate_dn'))


def get_site_specific_userpass_handler():
    config = get_config()
    return _dynamic_import(config.auth.get('userpass_handler', 'al_ui.site_specific.validate_userpass'))


def get_submit_client(datastore=None):
    from assemblyline.al.core.submission import SubmissionClient
    return SubmissionClient(datastore=datastore)


def get_submission_service():
    from assemblyline.al.core.submission import SubmissionService
    return SubmissionService()


def get_support_filestore():
    from assemblyline.al.core.filestore import FileStore
    config = get_config()
    return FileStore(*config.filestore.support_urls)


def get_ui_context():
    config = get_config()
    return EasyDict(_dynamic_import(config.ui.context))


def get_whitelist():
    config = get_config()
    return _dynamic_import(config.core.bulk.whitelist)


def get_yara_importer():
    config = get_config()
    return _dynamic_import(config.system.yara.importer)


def get_yara_parser():
    config = get_config()
    return _dynamic_import(config.system.yara.parser)
