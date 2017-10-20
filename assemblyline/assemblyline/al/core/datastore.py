import logging

import re
import threading

import requests
import time

from copy import copy
from hashlib import md5
from random import choice
from urllib2 import quote, unquote
from riak import RiakError
from assemblyline.common.charset import safe_str
from assemblyline.common.chunk import chunked_list

from assemblyline.common.concurrency import execute_concurrently
from assemblyline.common.isotime import epoch_to_iso, iso_to_epoch, now_as_iso
from assemblyline.common.riakreconnect import RiakReconnect
from assemblyline.al.common import forge
from assemblyline.al.common.error_template import get_error_template_from_key, is_template_error
from assemblyline.al.common.queue import NamedQueue
from assemblyline.al.common.task import Task, get_submission_overrides

# noinspection PyBroadException
try:
    # noinspection PyUnresolvedReferences
    requests.packages.urllib3.disable_warnings()
except:  # pylint: disable=W0702
    pass

config = forge.get_config()

try:
    import simplejson as json
except ImportError:
    import json

APPLICATION_JSON = 'application/json'
EXTRA_SEARCH_FIELD = '__text__'
DATASTORE_STREAM_PORT = config.datastore.stream_port
DATASTORE_SOLR_PORT = config.datastore.solr_port
RIAK_PROTOCOL_USED = 'pbc'  # either http or pbc

USE_EMPTY_BUCKET = True

Classification = forge.get_classification()

emptyresult_queue = NamedQueue(
    "ds-emptyresult",
    db=config.core.redis.persistent.db,
    host=config.core.redis.persistent.host,
    port=config.core.redis.persistent.port,
)
field_sanitizer = re.compile("^[a-z][a-z0-9_\-.]+$")
log = logging.getLogger('assemblyline.datastore')
riak = None


def compress_riak_key(uncompressed, srl):
    return uncompressed.replace(srl, '')


def create_filescore_key(sha256, getter, selected=None):
    # One up this if the cache is ever messed up and we
    # need to quickly invalidate all old cache entries.
    version = 0

    d = get_submission_overrides(getter)
    d['sha256'] = sha256
    if selected:
        d['selected'] = [str(x) for x in selected]

    s = ', '.join(["%s: %s" % (k, d[k]) for k in sorted(d.iterkeys())])

    return 'v'.join([str(md5(s).hexdigest()), str(version)])


def is_emptyresult(raw):
    if not USE_EMPTY_BUCKET:
        return False

    result = raw.get('result', None)
    response = raw.get('response', None)

    if not result or not response:
        return False

    extracted = response.get('extracted', [])
    supplementary = response.get('supplementary', [])

    score = result.get('score', 0)
    sections = result.get('sections', [])
    tags = result.get('tags', [])

    if score == 0 and len(sections) == 0 and len(tags) == 0 and len(extracted) == 0 and len(supplementary) == 0:
        return True

    return False


# noinspection PyBroadException
def make_empty_result(key, fileinfo=None):
    if not fileinfo:
        fileinfo = {}

    try:
        fields = key.split('.')

        return {
            '__access_grp1__': fileinfo.get('__access_grp1__', []),
            '__access_grp2__': fileinfo.get('__access_grp2__', []),
            '__access_lvl__': fileinfo.get('__access_lvl__', 0),
            '__access_req__': fileinfo.get('__access_req__', []),
            '__expiry_ts__': fileinfo.get('__expiry_ts__', ''),
            'classification': fileinfo.get('classification', ''),
            'created': fileinfo.get('seen_last', ''),
            'response': {
                'extracted': [],
                'message': '',
                'milestones': {
                    'service_completed': 0.0,
                    'service_started': 0.0
                },
                'service_name': fields[1],
                'service_version': fields[2][1:].replace('_', '.'),
                'supplementary': []
            },
            'result': {
                'classification': Classification.UNRESTRICTED,
                'context': None,
                'default_usage': None,
                'score': 0,
                'sections': [],
                'tags': [],
                'tags_score': 0,
                'truncated': False
            },
            'srl': fields[0]
        }
    except:
        log.exception("Problem making empty result:")

    return None


# noinspection PyUnusedLocal
def sanitize_null(data, key=None):
    return data


# noinspection PyUnusedLocal
def sanitize_alert(data, key=None):
    reporting_ts = iso_to_epoch(data.get('reporting_ts', now_as_iso()))
    data['__expiry_ts__'] = epoch_to_iso(reporting_ts + (365 * 24 * 60 * 60))
    return data


def sanitize_profile(data, key=None):
    items = [json.dumps(data), key]
    data[EXTRA_SEARCH_FIELD] = ", ".join(items)
    return data


# noinspection PyUnusedLocal
def sanitize_signature(data, key=None):
    # noinspection PyBroadException
    try:
        data[EXTRA_SEARCH_FIELD] = " ".join(data['meta'].keys())
    except:  # pylint:disable=W0702
        pass
    return data


# noinspection PyUnusedLocal
def sanitize_submission(data, key=None):
    t = Task(data)

    for field in ['received', 'skipped', 'watch_queue']:
        t.remove(field)
    metadata = t.metadata
    if metadata:
        if not isinstance(metadata, dict):
            t.remove('metadata')
        else:
            t.metadata = {
                k: v for k, v in metadata.iteritems()
                if field_sanitizer.match(k) and k.find('.') == -1
                }
    if t.priority:
        t.priority = int(t.priority)
    return data


def uncompress_riak_key(compressed, srl):
    return srl + compressed if compressed.startswith('.') else compressed


class DataStoreException(Exception):
    pass


class SearchRetryException(Exception):
    pass


class SearchException(Exception):
    pass


class SearchDepthException(Exception):
    pass


# noinspection PyBroadException
class DataStoreBase(object):
    """ ResultStore interface. 
        Service results will be stored via a ResultStore interface.
        The interface will also provide for cache lookups.
    """

    # Errors.
    @staticmethod
    def pre_save_error(task, srl, error):
        error['created'] = now_as_iso()
        error['srl'] = srl
        classification = task.classification
        parts = Classification.get_access_control_parts(classification)
        error.update(parts)

    # Profiles.
    # noinspection PyUnusedLocal
    @staticmethod
    def pre_save_profile(key, profile):
        profile = sanitize_profile(profile, key)

    # Signatures.
    @staticmethod
    def pre_save_signature(signature):
        signature = sanitize_signature(signature)
        classification = signature.get('meta', {}).get('classification', None)
        if not classification:
            classification = Classification.UNRESTRICTED
        classification = Classification.normalize_classification(classification)
        signature['meta']['classification'] = classification
        parts = Classification.get_access_control_parts(classification)
        signature.update(parts)

    # Signatures.
    @staticmethod
    def pre_save_workflow(wf_id, workflow):
        cur_wf_id = workflow.get('id', wf_id)

        if cur_wf_id != wf_id:
            raise DataStoreException("You cannot change the ID of a workflow")

        workflow['id'] = cur_wf_id
        classification = workflow.get('classification', None)
        if not classification:
            classification = Classification.UNRESTRICTED
        classification = Classification.normalize_classification(classification)
        workflow['classification'] = classification
        parts = Classification.get_access_control_parts(classification)
        workflow.update(parts)

    # Files.
    def get_file(self, srl):
        raise NotImplementedError()

    def save_file(self, srl, fileinfo):
        raise NotImplementedError()

    # Results.
    def lookup_result(self, service_name, version, conf_key, srl):
        raise NotImplementedError()

    @staticmethod
    def pre_save_result(task_classification, srl, result):
        result['created'] = result.get('created', now_as_iso())
        result['srl'] = srl
        classification = result.get('result', {}).get('classification', None)
        if not classification:
            classification = Classification.UNRESTRICTED
        classification = Classification.max_classification(
            classification,
            task_classification
        )
        parts = Classification.get_access_control_parts(classification)
        result['classification'] = classification
        result.update(parts)

    @staticmethod
    def sanitize(bucket, data, key=None):
        return {
            'alert': sanitize_alert,
            'profile': sanitize_profile,
            'signature': sanitize_signature,
            'submission': sanitize_submission,
        }.get(bucket, sanitize_null)(data, key=key)

    def save_result(self, service_name, version, conf_key, srl, c12n, result):
        raise NotImplementedError()

    @staticmethod
    def service_name_from_key(key):
        try:
            return key.split('.')[1]
        except:  # pylint: disable=W0702
            return ''

    @staticmethod
    def srl_from_key(key):
        try:
            return key.split('.')[0]
        except:  # pylint: disable=W0702
            return ''

    # Submissions.
    def create_submission(self, sid, submission, files):
        # The 'files' parameter should be a list of (path, sha256/srl) tuples.
        submission['files'] = files
        Task(submission).submitted = now_as_iso()
        self.save_submission(sid, submission)

    def finalize_submission(self, sid, classification, errors, results, score):
        submission = self.get_submission(sid)
        if not submission:
            log.warn(
                'Updating non-existent submission: %s - %s - %s',
                sid, errors, results
            )
            return
        submission['original_classification'] = submission['classification']
        submission['classification'] = classification
        submission['error_count'] = len(errors)
        submission['errors'] = errors
        submission['file_count'] = len(set([x[:64] for x in errors + results]))
        submission['results'] = results
        t = Task(submission, max_score=score)
        t.state = 'completed'
        t.completed = now_as_iso()
        for field in [
            'completed_queue', 'generate_alert',
            'notification_queue', 'notification_threshold', 'max_extracted',
            'max_supplementary', 'root_sha256', 'profile',
        ]:
            t.remove(field)
        self.save_submission(sid, submission)

    def get_submission(self, sid):
        raise NotImplementedError()

    @staticmethod
    def pre_save_submission(submission):
        submission = sanitize_submission(submission)
        t = Task(submission)
        t.classification = Classification.normalize_classification(t.classification)
        parts = Classification.get_access_control_parts(t.classification)
        submission.update(parts)

    def save_submission(self, sid, submission):
        raise NotImplementedError()

    def update_submission(self, current, **kwargs):
        sid = current.sid
        submission = self.get_submission(sid)
        if not submission:
            log.warn('Updating non existant submission: %s', sid)
            return
        t = Task(submission, **kwargs)
        t.dispatch_queue = current.dispatch_queue

        self.save_submission(sid, t.raw)


# noinspection PyBroadException
class RiakStore(DataStoreBase):
    """ Riak implementation of the ResultStore interface."""
    READ_TIMEOUT_MILLISECS = 30000
    MIN_KEY_LEN = 5
    ALLOW_MULTIGET = True
    MAX_SEARCH_DEPTH = 5000
    MAX_ROW_SIZE = 500
    MAX_RETRY = 5
    INDEXED_BUCKET_LIST = [
        "alert",
        "error",
        "file",
        "result",
        "signature",
        "submission",
        "workflow"]
    ADMIN_INDEXED_BUCKET_LIST = [
        "filescore",
        "node",
        "profile",
        "user"]
    CURRENT_QUERY_PLAN = {}
    HTTP_SESSION_POOL = {}

    # noinspection PyUnresolvedReferences
    def __init__(self, hosts=None, port=None, protocol_used=RIAK_PROTOCOL_USED):
        global riak
        if riak is None:
            import riak

        super(RiakStore, self).__init__()
        self.hosts = hosts or config.datastore.hosts
        self.port = port or config.datastore.port

        # Init Client
        self.riak_nodes = [{'host': n, 'pb_port': self.port, 'http_port': DATASTORE_STREAM_PORT} for n in self.hosts]
        self.client = riak.RiakClient(protocol=protocol_used, nodes=self.riak_nodes)
        log.debug('riakclient opened...')

        # Set default encoders
        self.client.set_encoder('application/json', utf8safe_encoder)
        self.client.set_encoder('text/json', utf8safe_encoder)

        # Set default resolver
        self.client.resolver = riak.resolver.last_written_resolver

        # Initialize buckets
        self._alerts = self._create_monkey_bucket("alert")
        self._blobs = self._create_monkey_bucket("blob")
        self._emptyresults = self._create_monkey_bucket("emptyresult")
        self._errors = self._create_monkey_bucket("error")
        self._files = self._create_monkey_bucket("file")
        self._filescores = self._create_monkey_bucket("filescore")
        self._nodes = self._create_monkey_bucket("node")
        self._profiles = self._create_monkey_bucket("profile")
        self._results = self._create_monkey_bucket("result")
        self._signatures = self._create_monkey_bucket("signature")
        self._submissions = self._create_monkey_bucket("submission")
        self._users = self._create_monkey_bucket("user")
        self._workflows = self._create_monkey_bucket("workflow")

        self.protocol_used = protocol_used

    ################################################################
    # Control Functions
    ########
    # noinspection PyTypeChecker
    def _create_monkey_bucket(self, bucket_name):
        #     Very cautious.
        # Much wow.
        #          Such magic.

        def bind(func, obj):
            return func.__get__(obj, obj.__class__)

        def new_monkey_search(monkey_bucket_name):
            def monkey_search(datastore, query, **kwargs):
                params = {
                    '__access_control__': kwargs.pop('filter', None),
                    'df': kwargs.pop('df', "text"),
                    'args': []
                }

                for k, v in kwargs.iteritems():
                    params['args'].append((k, str(v)))

                resp = datastore.direct_search(monkey_bucket_name, query, **params).get('response', {})
                resp['num_found'] = resp.pop("numFound", 0)
                return resp

            return monkey_search

        monkey_bucket = self.client.bucket(bucket_name, bucket_type="data")
        monkey_bucket.search = bind(new_monkey_search(bucket_name), self)
        return monkey_bucket

    def close(self):
        if self.client:
            log.debug('riakclient closed...')
            self.client.close()
            self.client = None

    def get_bucket(self, name):
        bucket_map = {
            "alert": self.alerts,
            "blob": self.blobs,
            "emptyresult": self.emptyresults,
            "error": self.errors,
            "file": self.files,
            "filescore": self.filescores,
            "node": self.nodes,
            "profile": self.profiles,
            "result": self.results,
            "signature": self.signatures,
            "submission": self.submissions,
            "user": self.users,
            "workflow": self.workflows
        }

        if name in bucket_map:
            return bucket_map[name]
        return None

    def terminate_session(self, session, host, port):
        session_key = "%s_%s" % (host, port)
        log.debug("Closing HTTP session for %s..." % session_key)
        try:
            session.close()
        except:
            pass

        try:
            del self.HTTP_SESSION_POOL[session_key]
        except:
            pass

    def get_or_create_session(self, host_list, port):
        host = choice(host_list)
        session_key = "%s_%s" % (host, port)
        session = self.HTTP_SESSION_POOL.get(session_key, None)
        if not session:
            log.debug("Creating new HTTP session for %s..." % session_key)
            session = requests.Session()
            self.HTTP_SESSION_POOL[session_key] = session

        return session, host, port

    def wake_up_riak(self):
        global riak
        if riak is None:
            import riak

        try:
            if not self.client.ping():
                self.client.close()
                self.client = None
                self.client = riak.RiakClient(protocol=self.protocol_used, nodes=self.riak_nodes)
        except:
            pass

    def __str__(self):
        return '{0} - {1}:{2}'.format(
            self.__class__.__name__,
            self.hosts,
            self.port)

    @staticmethod
    def _clean_extra_index(data):
        try:
            del data[EXTRA_SEARCH_FIELD]
        except:  # pylint:disable=W0702
            pass
        return data

    @RiakReconnect(wake_up_riak, log)
    def _delete_bucket_item(self, bucket, key):
        return bucket.delete(key)

    @RiakReconnect(wake_up_riak, log)
    def _get_bucket_item(self, bucket, key, strict=False):
        return self._clean_extra_index(self._get_data(bucket.get(key), strict=strict))

    @RiakReconnect(wake_up_riak, log)
    def _get_bucket_items(self, bucket, key_list, strict=False):
        temp_keys = copy(key_list)
        if RiakStore.ALLOW_MULTIGET:
            done = False
            retry = 0
            ret = []
            while not done:
                for bucket_item in bucket.multiget(temp_keys):
                    if not isinstance(bucket_item, tuple):
                        try:
                            item_data = self._get_data(bucket_item, strict=strict)
                        except DataStoreException:
                            continue
                        if item_data is not None:
                            ret.append(self._clean_extra_index(item_data))
                        temp_keys.remove(bucket_item.key)

                if len(temp_keys) == 0:
                    done = True
                else:
                    retry += 1

                if retry >= RiakStore.MAX_RETRY:
                    raise DataStoreException("%s is missing data for the following keys: %s" % (bucket.name.upper(),
                                                                                                temp_keys))

            return ret
        else:
            return [self._clean_extra_index(self._get_data(bucket.get(x), strict=strict)) for x in key_list]

    @RiakReconnect(wake_up_riak, log)
    def _get_bucket_items_dict(self, bucket, key_list, strict=False):
        temp_keys = copy(key_list)
        if RiakStore.ALLOW_MULTIGET:
            done = False
            retry = 0
            ret = {}
            while not done:
                for bucket_item in bucket.multiget(temp_keys):
                    if not isinstance(bucket_item, tuple):
                        try:
                            item_data = self._get_data(bucket_item, strict=strict)
                        except DataStoreException:
                            continue
                        if item_data is not None:
                            ret[bucket_item.key] = self._clean_extra_index(item_data)
                        temp_keys.remove(bucket_item.key)

                if len(temp_keys) == 0:
                    done = True
                else:
                    retry += 1

                if retry >= RiakStore.MAX_RETRY:
                    raise DataStoreException("%s is missing data for the following keys: %s" % (bucket.name.upper(),
                                                                                                temp_keys))

            return ret
        else:
            return {x: self._clean_extra_index(self._get_data(bucket.get(x), strict=strict)) for x in key_list}

    @staticmethod
    def _get_data(item, strict=False):
        if strict and not item.exists:
            raise DataStoreException("Key '{key}' does not exist in bucket {bucket}.".format(key=item.key,
                                                                                             bucket=item.bucket.name))
        if item.encoded_data == 'None':
            return None
        try:
            return item.data
        except Exception:
            if item.bucket.name != 'blob':
                log.exception("[bucket:'%s', key:'%s'] Using riak_object.encoded_data instead of riak_object.data. "
                              "Someone inserted a non JSON data object into riak." % (item.bucket.name, item.key))
            return item.encoded_data

    def _get_riak_key(self, service_name, version, conf_key, srl):
        l = [srl, service_name.replace('.', '_')]
        if version:
            l.append('v' + version.replace('.', '_'))
        if conf_key:
            l.append('c' + conf_key.replace('.', '_'))
        key = '.'.join(l)
        if len(key) < self.MIN_KEY_LEN:
            raise DataStoreException('Invalid riak key: %s', key)
        return key

    @RiakReconnect(wake_up_riak, log)
    def _list_bucket_keys(self, bucket, access_control=None):
        out = []

        for item in self.stream_search(bucket.name, "*", fl="_yz_rk", access_control=access_control):
            out.append(item['_yz_rk'])

        return list(set(out))

    @staticmethod
    def _stream_bucket_debug_keys(bucket):
        for keys in bucket.stream_index("$bucket", ""):
            for key in keys:
                yield key

    @RiakReconnect(wake_up_riak, log)
    def _list_bucket_debug_keys(self, bucket):
        out = []
        for keys in bucket.stream_index("$bucket", ""):
            out.extend(keys)

        return out

    @RiakReconnect(wake_up_riak, log)
    def _save_bucket_item(self, bucket, key, data):
        if " " in key:
            raise DataStoreException("Your are not allowed to use space in the key. [%s]" % key)
        item = bucket.new(key=key, data=data, content_type=APPLICATION_JSON)
        item.store()

    @RiakReconnect(wake_up_riak, log)
    def _search_bucket(self, bucket, query="*:*", start=0, rows=100, sort="_yz_rk asc", fl="*", access_control=""):
        if "score" not in fl:
            fl += ",score"

        if start + rows > self.MAX_SEARCH_DEPTH:
            raise SearchDepthException(
                "Cannot search deeper then %s items. Use stream searching instead..." % self.MAX_SEARCH_DEPTH)
        if rows > self.MAX_ROW_SIZE:
            raise SearchDepthException("Page size cannot be bigger than %s." % self.MAX_ROW_SIZE)

        if isinstance(query, unicode):
            query = query.encode("utf-8")

        if not sort:
            results = bucket.search(query, df="text", fl=fl, start=start, rows=rows, filter=access_control)
        else:
            results = bucket.search(query, df="text", fl=fl, start=start, rows=rows, filter=access_control, sort=sort)
        return {"items": RiakStore.search_result_to_list_dict(results),
                "total": results['num_found'], 'offset': start, "count": rows}

    @RiakReconnect(wake_up_riak, log)
    def _wipe_bucket(self, bucket):
        for keys in bucket.stream_index("$bucket", ""):
            for key in keys:
                bucket.delete(key)

    ################################################################
    # Properties
    ########
    @property
    def alerts(self):
        return self._alerts

    @property
    def blobs(self):
        return self._blobs

    @property
    def emptyresults(self):
        return self._emptyresults

    @property
    def errors(self):
        return self._errors

    @property
    def files(self):
        return self._files

    @property
    def filescores(self):
        return self._filescores

    @property
    def nodes(self):
        return self._nodes

    @property
    def profiles(self):
        return self._profiles

    @property
    def results(self):
        return self._results

    @property
    def signatures(self):
        return self._signatures

    @property
    def submissions(self):
        return self._submissions

    @property
    def users(self):
        return self._users

    @property
    def workflows(self):
        return self._workflows

    ################################################################
    # Static Functions
    ########
    @staticmethod
    def valid_solr_param(k, v):
        msg = "Invalid parameter (%s=%s). Should be between %d and %d"

        if k in ["q", "df", "wt"]:
            return False
        if k.endswith('facet.offset') or k.endswith('group.offset'):
            return False
        if k.endswith('facet.limit') and not 1 <= int(v) <= 1000:
            raise SearchException(msg % (k, v, 1, 1000))
        if k.endswith('group.limit') and not 1 <= int(v) <= 10:
            raise SearchException(msg % (k, v, 1, 10))
        if k == 'rows' and not 0 <= int(v) <= 500:
            raise SearchException(msg % (k, v, 0, 500))

        return True

    def advanced_search(self, bucket, query, args, df="text", wt="json", save_qp=False, __access_control__=None,
                        _hosts_=config.datastore.hosts, _port_=DATASTORE_STREAM_PORT):

        if bucket not in RiakStore.INDEXED_BUCKET_LIST and bucket not in RiakStore.ADMIN_INDEXED_BUCKET_LIST:
            raise SearchException("Bucket %s does not exists." % bucket)

        host_list = copy(_hosts_)

        try:
            query = quote(query)
        except:
            raise SearchException("Unable to URL quote query: %s" % safe_str(query))

        while True:
            if len(host_list) == 0:
                host_list = copy(_hosts_)
            session, host, port = self.get_or_create_session(host_list, _port_)
            try:
                kw = "&".join(["%s=%s" % (k, quote(safe_str(v))) for k, v in args if self.valid_solr_param(k, v)])
                url = "http://%s:%s/search/query/%s/?q=%s&df=%s&wt=%s" % (
                    host, port, bucket, query, df, wt)

                if __access_control__:
                    url += "&fq=%s" % __access_control__

                if kw:
                    url += "&" + kw

                res = session.get(url)
                if res.ok:
                    solr_out = res.json()

                    # Cleanup potential leak of information about our cluster
                    qp_fields = {}
                    params = [k for k in solr_out.get("responseHeader", {}).get("params", {}).keys()]
                    for k in params:
                        if ":%s" % DATASTORE_SOLR_PORT in k or ":8093" in k or k == "shards":
                            if save_qp:
                                qp_fields[k] = solr_out["responseHeader"]["params"][k]
                            del solr_out["responseHeader"]["params"][k]

                    if save_qp:
                        self.CURRENT_QUERY_PLAN[bucket] = "&%s" % "&".join(["%s=%s" % (k, v)
                                                                            for k, v in qp_fields.iteritems()])

                    return solr_out
                else:
                    try:
                        solr_error = res.json()
                        message = solr_error["error"]["msg"]
                        if "IOException" in message or "Server refused" in message:
                            raise SearchRetryException()
                        else:
                            if "neither indexed nor has doc values: " in message:
                                # Cleanup potential leak of information about our cluster
                                qp_fields = {}
                                params = [k for k in solr_error.get("responseHeader", {}).get("params", {}).keys()]
                                for k in params:
                                    if ":%s" % DATASTORE_SOLR_PORT in k or ":8093" in k or k == "shards":
                                        if save_qp:
                                            qp_fields[k] = solr_error["responseHeader"]["params"][k]
                                        del solr_error["responseHeader"]["params"][k]

                                if save_qp:
                                    self.CURRENT_QUERY_PLAN[bucket] = "&%s" % "&".join(["%s=%s" % (k, v)
                                                                                        for k, v in
                                                                                        qp_fields.iteritems()])
                                return solr_error
                            else:
                                raise SearchException(message)
                    except SearchException:
                        raise
                    except:
                        if res.status_code == 404:
                            raise SearchException("Bucket %s does not exists." % bucket)
                        elif res.status_code == 500:
                            raise SearchRetryException()
                        else:
                            raise SearchException("bucket: %s, query: %s, args: %s\n%s" %
                                                  (bucket, query, args, res.content))
            except requests.ConnectionError:
                host_list.remove(host)
            except SearchRetryException:
                host_list.remove(host)
            finally:
                if save_qp:
                    self.terminate_session(session, host, port)

    @staticmethod
    def _commit_now(bucket, host):
        url = "http://{host}:{port}/internal_solr/{bucket}/update/?commit=true" \
              "&softCommit=true&wt=json".format(host=host,
                                                port=DATASTORE_SOLR_PORT,
                                                bucket=bucket)

        res = requests.get(url)
        if res.ok:
            solr_out = res.json()
            return solr_out
        else:
            return None

    def commit_index(self, bucket, hosts=config.datastore.riak.nodes):
        log.warning("SOLR was forced into committing data for bucket %s." % bucket)

        plan = []
        for host in hosts:
            plan.append((self._commit_now, (bucket, host), host))

        res = execute_concurrently(plan)
        for val in res.itervalues():
            if not val:
                return False

        return True

    def direct_search(self, bucket, query, args=(), df="text", wt="json", __access_control__=None,
                      _hosts_=config.datastore.hosts, _port_=DATASTORE_SOLR_PORT):
        if bucket not in self.CURRENT_QUERY_PLAN or not self.CURRENT_QUERY_PLAN[bucket]:
            log.debug("There is no coverage plan for bucket '%s'. Re-dispatching to advanced_search and saving the "
                      "coverage plan..." % bucket)
            riak_out = self.advanced_search(bucket, query, args, df=df, wt=wt, save_qp=True,
                                            __access_control__=__access_control__, _hosts_=_hosts_)
            log.debug("Coverage plan for '%s' saved as: %s" % (bucket, self.CURRENT_QUERY_PLAN[bucket]))
            riak_out['provider'] = "RIAK"
            return riak_out

        if bucket not in RiakStore.INDEXED_BUCKET_LIST and bucket not in RiakStore.ADMIN_INDEXED_BUCKET_LIST:
            raise SearchException("Bucket %s does not exists." % bucket)

        host_list = copy(_hosts_)

        try:
            query = quote(query)
        except:
            raise SearchException("Unable to URL quote query: %s" % safe_str(query))

        if len(host_list) == 0:
            host_list = copy(_hosts_)
        session, host, port = self.get_or_create_session(host_list, _port_)
        try:
            kw = "&".join(["%s=%s" % (k, quote(safe_str(v))) for k, v in args if self.valid_solr_param(k, v)])
            url = "http://%s:%s/internal_solr/%s/select/?q=%s&df=%s&wt=%s" % (
                host, port, bucket, query, df, wt)

            if __access_control__:
                url += "&fq=%s" % __access_control__

            if kw:
                url += "&" + kw

            url += self.CURRENT_QUERY_PLAN[bucket]

            res = session.get(url)
            if res.ok:
                solr_out = res.json()

                # Cleanup potential leak of information about our cluster
                params = [k for k in solr_out.get("responseHeader", {}).get("params", {}).keys()]
                for k in params:
                    if ":%s" % DATASTORE_SOLR_PORT in k or ":8093" in k or k == "shards":
                        del solr_out["responseHeader"]["params"][k]

                solr_out['provider'] = "SOLR"
                return solr_out
            else:
                try:
                    solr_error = res.json()
                    message = solr_error["error"]["msg"]
                    if "IOException" in message or "Server refused" in message:
                        raise SearchRetryException()
                    else:
                        if "neither indexed nor has doc values: " in message:
                            # Cleanup potential leak of information about our cluster
                            params = [k for k in solr_error.get("responseHeader", {}).get("params", {}).keys()]
                            for k in params:
                                if ":%s" % DATASTORE_SOLR_PORT in k or ":8093" in k or k == "shards":
                                    del solr_error["responseHeader"]["params"][k]
                            return solr_error
                        else:
                            raise SearchException(message)
                except SearchException:
                    raise
                except:
                    if res.status_code == 404:
                        raise SearchException("Bucket %s does not exists." % bucket)
                    elif res.status_code == 500:
                        raise SearchRetryException()
                    else:
                        raise SearchException("bucket: %s, query: %s, args: %s\n%s" %
                                              (bucket, query, args, res.content))
        except requests.ConnectionError:
            riak_out = self.advanced_search(bucket, unquote(query), args, df=df, wt=wt, save_qp=True,
                                            __access_control__=__access_control__, _hosts_=_hosts_)
            riak_out['provider'] = "RIAK"
            return riak_out
        except SearchRetryException:
            riak_out = self.advanced_search(bucket, unquote(query), args, df=df, wt=wt, save_qp=True,
                                            __access_control__=__access_control__, _hosts_=_hosts_)
            riak_out['provider'] = "RIAK"
            return riak_out

    def generate_field_list(self, get_full_list, specific_bucket=None, hosts=config.datastore.hosts,
                            port=DATASTORE_SOLR_PORT):
        host_list = copy(hosts)

        if specific_bucket and (specific_bucket in RiakStore.INDEXED_BUCKET_LIST or
                                specific_bucket in RiakStore.ADMIN_INDEXED_BUCKET_LIST):
            bucket_list = [specific_bucket]
        elif not specific_bucket:
            bucket_list = copy(RiakStore.INDEXED_BUCKET_LIST)
            if get_full_list:
                bucket_list += RiakStore.ADMIN_INDEXED_BUCKET_LIST
        else:
            bucket_list = []

        output = {}
        for bucket_name in bucket_list:
            while True:
                if len(host_list) == 0:
                    host_list = copy(hosts)
                session, host, port = self.get_or_create_session(host_list, port)
                try:
                    url = "http://%s:%s/internal_solr/%s/admin/luke/?wt=json" % (host, port, bucket_name)
                    res = session.get(url)
                    if res.ok:
                        bucket_data = {}
                        j = res.json()

                        fields = j.get("fields", {})
                        for k, v in fields.iteritems():
                            if k.startswith("_") or "//" in k:
                                continue
                            if not field_sanitizer.match(k):
                                continue

                            bucket_data[k] = {
                                "indexed": v.get("schema", "").startswith("I"),
                                "stored": v.get("schema", "")[:3].endswith("S"),
                                "list": v.get("schema", "")[:5].endswith("M"),
                                "type": v.get("type", "")
                            }

                        output[bucket_name] = bucket_data
                        break
                    else:
                        try:
                            j = res.json()
                            message = j["error"]["msg"]
                            if "IOException" in message or "Server refused" in message:
                                raise SearchRetryException()
                            else:
                                raise SearchException(message)
                        except SearchException:
                            raise
                        except:
                            if res.status_code == 404:
                                break
                            elif res.status_code == 500:
                                raise SearchRetryException()
                            else:
                                raise SearchException(res.content)
                except requests.ConnectionError:
                    host_list.remove(host)
                except SearchRetryException:
                    host_list.remove(host)

        return output

    def page_search(self, bucket, query, df="text", sort="_yz_id asc", fl=None, item_buffer_size=500, cursor='*',
                    access_control=None):

        if item_buffer_size > 500 or item_buffer_size < 50:
            raise SearchException("Variable item_buffer_size must be between 50 and 500.")

        if query in ["*", "*:*"] and fl != "_yz_rk":
            raise SearchException("You did not specified a query, you just asked for everything... Play nice.")

        args = [("sort", sort),
                ("cursorMark", cursor),
                ("rows", str(item_buffer_size))]

        if fl:
            args.append(("fl", fl))

        j = self.direct_search(bucket, query, args, df=df, __access_control__=access_control)

        cursor = j["nextCursorMark"]

        return {"cursor": cursor,
                "items": j["response"]["docs"],
                "total": j["response"]["numFound"],
                "done": len(j["response"]["docs"]) < item_buffer_size}

    def stats_search(self, bucket, query, stats_fields, df="text", hosts=config.datastore.hosts,
                     port=DATASTORE_STREAM_PORT):
        host_list = copy(hosts)

        if query in ["*", "*:*"]:
            raise SearchException("You did not specified a query, you just asked for everything... Play nice.")

        if not stats_fields:
            raise SearchException("You did not specify a field for stats.")

        stats_query = ""
        for field in stats_fields:
            stats_query += "stats.field=%s" % field

        try:
            query = quote(query)
        except:
            raise SearchException("Unable to URL quote query: %s" % safe_str(query))

        while True:
            if len(host_list) == 0:
                host_list = copy(hosts)
            session, host, port = self.get_or_create_session(host_list, port)
            try:
                url = "http://%s:%s/search/query/%s?q=%s&stats=true&%s&rows=0&df=%s&wt=json" % (
                    host, port, bucket, query, stats_query, df)
                res = session.get(url)
                if res.ok:
                    j = res.json()
                    return j["stats"]["stats_fields"]
                else:
                    try:
                        j = res.json()
                        message = j["error"]["msg"]
                        if "IOException" in message or "Server refused" in message:
                            raise SearchRetryException()
                        else:
                            raise SearchException(message)
                    except SearchException:
                        raise
                    except:
                        if res.status_code == 404:
                            raise SearchException("Bucket %s does not exists." % bucket)
                        elif res.status_code == 500:
                            raise SearchRetryException()
                        else:
                            raise SearchException(res.content)
            except requests.ConnectionError:
                host_list.remove(host)
            except SearchRetryException:
                host_list.remove(host)

    @staticmethod
    def result_keys_to_dict(input_dict):
        output_dict = {}
        for k, v in input_dict.iteritems():
            items = k.split(".")
            parent = output_dict
            for i in items:
                if i not in parent:
                    if items.index(i) == (len(items) - 1):
                        parent[i] = v

                        break
                    else:
                        parent[i] = {}
                parent = parent[i]

        # Cleanup data
        for x in ["_yz_rb", "_yz_rt", "_yz_id", "score"]:
            try:
                del output_dict[x]
            except:
                pass

        return output_dict

    @staticmethod
    def search_result_to_list_dict(res):
        out = []

        docs = res.get('response', {}).get("docs", res.get("docs", []))
        for i in docs:
            out.append(RiakStore.result_keys_to_dict(i))

        return out

    def stream_search(self, bucket, query, df="text", sort="_yz_id asc", fl=None, item_buffer_size=200,
                      access_control=None, fq=None):

        def _auto_fill(_self, _page_size, _items, _lock, _bucket, _query, _args, _df, _access_control):
            _max_yield_cache = 50000

            done = False
            _args = list(_args)
            while not done:
                skip = False
                with lock:
                    if len(_items) > _max_yield_cache:
                        skip = True

                if skip:
                    time.sleep(0.01)
                    continue

                j = _self.direct_search(_bucket, _query, _args, df=_df, __access_control__=_access_control)

                # Replace cursorMark.
                _args = _args[:-1]
                _args.append(('cursorMark', j.get('nextCursorMark', '*')))

                with _lock:
                    _items.extend(j['response']['docs'])

                done = _page_size - len(j['response']['docs'])

        if item_buffer_size > 500 or item_buffer_size < 50:
            raise SearchException("Variable item_buffer_size must be between 50 and 500.")

        if query in ["*", "*:*"] and fl != "_yz_rk":
            raise SearchException("You did not specified a query, you just asked for everything... Play nice.")

        args = [("sort", sort),
                ("rows", str(item_buffer_size))]

        if fl:
            args.append(("fl", fl))

        if fq:
            if isinstance(fq, list):
                for item in fq:
                    args.append(("fq", item))
            else:
                args.append(("fq", fq))
        args.append(('cursorMark', '*'))

        yield_done = False
        items = []
        lock = threading.Lock()
        sf_t = threading.Thread(target=_auto_fill,
                                args=[self, item_buffer_size, items, lock, bucket, query, args, df, access_control],
                                name="stream_search_%s" % md5(bucket + safe_str(query)).hexdigest()[:7])
        sf_t.setDaemon(True)
        sf_t.start()
        while not yield_done:
            try:
                with lock:
                    item = items.pop(0)

                yield item
            except IndexError:
                if not sf_t.is_alive() and len(items) == 0:
                    yield_done = True
                time.sleep(0.01)

    ################################################################
    # Helper Functions
    ########
    @RiakReconnect(wake_up_riak, log)
    def get_file_list_from_keys(self, keys):
        if len(keys) == 0:
            return {}
        keys = [x for x in list(keys) if not x.endswith(".e")]
        items = self._get_bucket_items_dict(self.results, keys)

        out = {}
        for key, item in items.iteritems():
            extracted = item.get('response', {}).get('extracted', [])
            if len(extracted) == 0:
                continue
            if key[:64] not in out:
                out[key[:64]] = []
            out[key[:64]].extend([dict(zip(("name", "srl", "desc"), i)) for i in extracted])

        return out

    @RiakReconnect(wake_up_riak, log)
    def get_files_scores_from_keys(self, keys):
        if len(keys) == 0:
            return {}
        keys = [x for x in list(keys) if not x.endswith(".e")]
        items = self._get_bucket_items_dict(self.results, keys)

        scores = {x[:64]: 0 for x in keys}
        for key, item in items.iteritems():
            score = int(item.get("result", {}).get("score", 0))
            scores[key[:64]] += score

        return scores

    @RiakReconnect(wake_up_riak, log)
    def get_tag_list_from_keys(self, keys):
        if len(keys) == 0:
            return []
        keys = [x for x in list(keys) if not x.endswith(".e")]
        items = self._get_bucket_items_dict(self.results, keys, strict=True)

        out = []
        for key, item in items.iteritems():
            tags = item.get('result', {}).get('tags', [])
            [tag.update({"key": key}) for tag in tags]  # pylint:disable=W0106
            out.extend(tags)

        return out

    @RiakReconnect(wake_up_riak, log)
    def list_file_active_keys(self, srl, access_control=None):
        query = "_yz_rk:%s*" % srl
        if isinstance(query, unicode):
            query = query.encode("utf-8")

        item_list = [x for x in self.stream_search("result", query, access_control=access_control)]

        item_list.sort(key=lambda k: k["created"], reverse=True)

        active_found = []
        active_keys = []
        alternates = []
        for item in item_list:
            item = self.result_keys_to_dict(item)
            if item['response']['service_name'] not in active_found:
                active_keys.append(item['_yz_rk'])
                active_found.append(item['response']['service_name'])
            else:
                alternates.append(item)

        return active_keys, alternates

    @RiakReconnect(wake_up_riak, log)
    def list_file_childrens(self, srl, access_control=None):
        output = []
        query = "_yz_rk:%s* AND response.extracted:*" % srl

        if isinstance(query, unicode):
            query = query.encode("utf-8")

        args = [
            ("fl", "_yz_rk"),
            ("rows", "100"),
            ("sort", "created desc"),
            ("group", "on"),
            ("group.field", "response.service_name"),
            ("group.main", "true")
        ]
        response = self.direct_search("result", query, args, __access_control__=access_control)
        result_res = [x['_yz_rk'] for x in self.search_result_to_list_dict(response)]

        processed_srl = []
        for r in self._get_bucket_items(self.results, result_res):
            for extracted in r['response']['extracted']:
                name, srl = extracted[:2]
                if srl not in processed_srl:
                    processed_srl.append(srl)
                    output.append({'srl': srl, 'name': name})

        return output

    @RiakReconnect(wake_up_riak, log)
    def get_file_submission_meta(self, srl, access_control=None):
        output = {}

        query = "files:%s OR results:%s" % (srl, srl)
        if isinstance(query, unicode):
            query = query.encode("utf-8")

        args = [
            ("fl", "_yz_rk"),
            ("rows", "0"),
            ("facet", "on"),
            ("facet.mincount", "1")
        ]
        args.extend([("facet.field", x) for x in config.statistics.submission_meta_fields])

        response = self.direct_search("submission", query, args, __access_control__=access_control)

        for k, v in response.get("facet_counts", {}).get("facet_fields", {}).iteritems():
            output[k.split(".")[-1]] = chunked_list(v, 2)

        return output

    @RiakReconnect(wake_up_riak, log)
    def list_file_error_keys(self, srl, access_control=None):
        query = "_yz_rk:%s*" % srl
        if isinstance(query, unicode):
            query = query.encode("utf-8")

        return list(set([x["_yz_rk"] for x in self.stream_search("error", query, fl="_yz_rk",
                                                                 access_control=access_control)]))

    @RiakReconnect(wake_up_riak, log)
    def list_file_parents(self, srl, access_control=None):
        query = "response.extracted:%s" % srl
        if isinstance(query, unicode):
            query = query.encode("utf-8")

        processed_srl = []
        output = []
        args = [
            ("fl", "_yz_rk"),
            ("rows", "100"),
            ("sort", "created desc")
        ]
        response = self.direct_search("result", query, args, __access_control__=access_control)
        for p in self.search_result_to_list_dict(response):
            key = p["_yz_rk"]
            sha256 = key[:64]
            if sha256 not in processed_srl:
                output.append(key)
                processed_srl.append(sha256)

            if len(processed_srl) >= 10:
                break

        return output

    @RiakReconnect(wake_up_riak, log)
    def list_file_related_submissions_keys(self, srl, access_control=None):
        query = "files:%s OR results:%s" % (srl, srl)
        if isinstance(query, unicode):
            query = query.encode("utf-8")

        return list(set([x["_yz_rk"] for x in self.stream_search("submission", query, fl="_yz_rk",
                                                                 access_control=access_control)]))

    @RiakReconnect(wake_up_riak, log)
    def list_file_result_keys(self, srl, access_control=None):
        query = "_yz_rk:%s*" % srl
        if isinstance(query, unicode):
            query = query.encode("utf-8")

        return list(set([x["_yz_rk"] for x in self.stream_search("result", query, fl="_yz_rk",
                                                                 access_control=access_control)] +
                        [x["_yz_rk"] for x in self.stream_search("emptyresult", query, fl="_yz_rk",
                                                                 access_control=access_control)]))

    @RiakReconnect(wake_up_riak, log)
    def search_all(self, query, start=0, rows=100, access_control=""):
        plan = [(self.search_result, (query, start, rows, access_control), "results"),
                (self.search_file, (query, start, rows, access_control), "files"),
                (self.search_submission, (query, start, rows, access_control), "submissions"),
                (self.search_signature, (query, start, rows, access_control), "signatures"),
                (self.search_alert, (query, start, rows, access_control), "alerts")]

        res = execute_concurrently(plan, calculate_timers=True)

        for exception in res.get("_exception_", {}).itervalues():
            raise exception

        return res

    ################################################################
    # Alerts Functions
    ########
    def delete_alert(self, alert_key):
        self._delete_bucket_item(self.alerts, alert_key)

    def get_alert(self, alert_key):
        return self._get_bucket_item(self.alerts, alert_key)

    def get_alerts(self, key_list):
        return self._get_bucket_items(self.alerts, key_list)

    def get_alert_statistics(self, query="*:*", start=0, rows=100, access_control="", fq_list=None, start_time=None,
                             time_slice="4DAY", field_list=None):
        output = {}

        if isinstance(query, unicode):
            query = query.encode("utf-8")

        if start + rows > self.MAX_SEARCH_DEPTH:
            raise SearchDepthException(
                "Cannot search deeper then %s items. Use stream searching instead..." % self.MAX_SEARCH_DEPTH)
        if rows > self.MAX_ROW_SIZE:
            raise SearchDepthException("Page size cannot be bigger than %s." % self.MAX_ROW_SIZE)

        args = [
            ("rows", "0"),
            ("facet", "on"),
            ("facet.mincount", "1")
        ]

        if time_slice:
            if start_time:
                args.append(("fq", "reporting_ts:[%s-%s TO %s]" % (start_time, time_slice, start_time)))
            else:
                args.append(("fq", "reporting_ts:[NOW-%s TO NOW]" % time_slice))
        else:
            if start_time:
                args.append(("fq", "reporting_ts:[* TO %s]" % start_time))

        if fq_list is not None:
            for fq in fq_list:
                args.append(("fq", fq))

        fields = field_list or config.statistics.alert_statistics_fields
        facet_field_list = [("facet.field", x) for x in fields]

        plan = []

        for item in facet_field_list:
            temp_args = copy(args)
            temp_args.append(item)
            plan.append((self.direct_search, ("alert", query, temp_args, "text", "json", access_control), item[1]))

        results = execute_concurrently(plan, calculate_timers=True)

        for plan_key, response in results.iteritems():
            if plan_key.startswith("_"):
                output[plan_key] = response
            else:
                for k, v in response.get("facet_counts", {}).get("facet_fields", {}).iteritems():
                    output[k.split(".")[-1]] = [[safe_str(x[0]), x[1]] for x in chunked_list(v, 2)]

        return output

    def list_alert_keys(self):
        return self._list_bucket_keys(self.alerts)

    def list_alert_debug_keys(self):
        return self._list_bucket_debug_keys(self.alerts)

    def list_alerts(self, query="*:*", start=0, rows=100, access_control="", fq_list=None, start_time=None,
                    time_slice="4DAY"):
        if isinstance(query, unicode):
            query = query.encode("utf-8")

        if start + rows > self.MAX_SEARCH_DEPTH:
            raise SearchDepthException(
                "Cannot search deeper then %s items. Use stream searching instead..." % self.MAX_SEARCH_DEPTH)
        if rows > self.MAX_ROW_SIZE:
            raise SearchDepthException("Page size cannot be bigger than %s." % self.MAX_ROW_SIZE)

        args = [
            ("rows", str(rows)),
            ("sort", "reporting_ts desc"),
            ("start", str(start)),
            ("fl", "_yz_rk")
        ]

        if time_slice:
            if start_time:
                args.append(("fq", "reporting_ts:[%s-%s TO %s]" % (start_time, time_slice, start_time)))
            else:
                args.append(("fq", "reporting_ts:[NOW-%s TO NOW]" % time_slice))
        else:
            if start_time:
                args.append(("fq", "reporting_ts:[* TO %s]" % start_time))

        if fq_list is not None:
            for fq in fq_list:
                args.append(("fq", fq))

        response = self.direct_search("alert", query, args, __access_control__=access_control)
        items = [x["_yz_rk"] for x in response.get('response', {}).get('docs', {})]

        return {
            "items": sorted(self.get_alerts(items), key=lambda k: k['reporting_ts'],
                            reverse=True),
            "total": response.get('response', {}).get('numFound', 0), 'offset': start, "count": rows}

    def list_grouped_alerts(self, query="*:*", field='md5', start=0, rows=100, start_time=None, time_slice="4DAY",
                            access_control="", fq_list=None, time_offset=0):
        if start + rows > self.MAX_SEARCH_DEPTH:
            raise SearchDepthException(
                "Cannot search deeper then %s items. Use stream searching instead..." % self.MAX_SEARCH_DEPTH)
        if rows > self.MAX_ROW_SIZE:
            raise SearchDepthException("Page size cannot be bigger than %s." % self.MAX_ROW_SIZE)

        if isinstance(query, unicode):
            query = query.encode("utf-8")

        args = [
            ("group", "on"),
            ("group.field", field),
            ("rows", str(rows)),
            ("group.sort", "reporting_ts desc"),
            ("sort", "reporting_ts desc"),
            ("start", str(start)),
            ("fl", "_yz_rk,md5"),
            ("fq", field + ":*")
        ]

        if not start_time:
            start_time = now_as_iso(time_offset)
        if time_slice:
            args.append(("fq", "reporting_ts:[%s-%s TO %s]" % (start_time, time_slice, start_time)))
        else:
            args.append(("fq", "reporting_ts:[* TO %s]" % start_time))

        if fq_list is not None:
            for fq in fq_list:
                args.append(("fq", fq))

        response = self.direct_search("alert", query, args, __access_control__=access_control)
        groups = response.get('grouped', {}).get(field, {}).get('groups', {})
        num_found = response.get('grouped', {}).get(field, {}).get('matches', 0)

        alert_keys = []
        md5_list = []
        hint_list = []
        group_count = {}
        for item in groups:
            group_count[item.get('groupValue', None)] = item.get('doclist', {}).get('numFound', 0)
            data = item.get('doclist', {}).get('docs', [{}])[0]
            alert_keys.append(data['_yz_rk'])
            if field in ['md5', 'sha1', 'sha256']:
                md5_list.append(data['md5'])

        alerts = sorted(self.get_alerts(alert_keys), key=lambda k: k['reporting_ts'], reverse=True)

        if md5_list:
            hint_args = [
                ("group", "on"),
                ("group.field", "md5"),
                ("rows", str(rows)),
                ("fl", "md5"),
                ("fq", "owner:*")
            ]

            hint_resp = self.direct_search("alert",
                                           " OR ".join(['md5:"%s"' % v for v in md5_list]),
                                           hint_args,
                                           __access_control__=access_control)
            hint_groups = hint_resp.get('grouped', {}).get(field, {}).get('groups', {})
            for item in hint_groups:
                hint_list.append(item.get('doclist', {}).get('docs', [{}])[0]["md5"])

        counted_total = 0
        for a in alerts:
            count = group_count.get(a.get(field, None), 0)
            a['group_count'] = count
            if a['md5'] in hint_list and not a.get('owner', None):
                a['hint_owner'] = True
            counted_total += count

        return {"items": alerts,
                "total": num_found,
                'offset': start,
                "count": rows,
                "start_time": start_time,
                "counted_total": counted_total}

    def save_alert(self, alert_key, scan_info):
        scan_info = sanitize_alert(scan_info)
        classification = Classification.normalize_classification(scan_info['classification'])
        scan_info['classification'] = classification
        parts = Classification.get_access_control_parts(classification)
        scan_info.update(parts)
        return self._save_bucket_item(self.alerts, alert_key, scan_info)

    def search_alert(self, query="*:*", start=0, rows=100, access_control="", sort="ts desc"):
        res = self._search_bucket(self.alerts, query, start, rows, sort, access_control=access_control)
        res['bucket'] = "alert"
        return res

    def wipe_alerts(self):
        for key in self.alerts.get_keys():
            self._delete_bucket_item(self.alerts, key)
            print 'Wiped: {0}'.format(key)

    ################################################################
    # Blob Functions
    ########
    def delete_blob(self, blob_key):
        self._delete_bucket_item(self.blobs, blob_key)

    def get_blob(self, blob_key):
        return self._get_bucket_item(self.blobs, blob_key)

    def get_blobs(self, key_list):
        return self._get_bucket_items(self.blobs, key_list)

    def list_blob_debug_keys(self):
        return self._list_bucket_debug_keys(self.blobs)

    def save_blob(self, blob_key, blob):
        return self._save_bucket_item(self.blobs, blob_key, blob)

    def wipe_blobs(self):
        for key in self.blobs.get_keys():
            self._delete_bucket_item(self.blobs, key)
            print 'Wiped: {0}'.format(key)

    ################################################################
    # Error Functions
    ########
    def delete_error(self, key):
        self._delete_bucket_item(self.errors, key)

    def get_error(self, key):
        return get_error_template_from_key(key) or self._get_bucket_item(self.errors, key)

    def get_errors(self, key_list):
        key_list = list(set(key_list))
        out = []
        new_key_list = []

        for key in key_list:
            data = get_error_template_from_key(key)
            if data:
                out.append(data)
            else:
                new_key_list.append(key)

        out.extend(self._get_bucket_items(self.errors, new_key_list))
        return out

    def get_errors_dict(self, key_list):
        key_list = list(set(key_list))
        out = {}
        new_key_list = []

        for key in key_list:
            data = get_error_template_from_key(key)
            if data:
                out[key] = data
            else:
                new_key_list.append(key)

        out.update(self._get_bucket_items_dict(self.errors, new_key_list))
        return out

    def list_error_keys(self):
        return self._list_bucket_keys(self.errors)

    def list_error_debug_keys(self):
        return self._list_bucket_debug_keys(self.errors)

    @RiakReconnect(wake_up_riak, log)
    def list_errors(self, query="*:*", start=0, rows=100, access_control=""):
        if isinstance(query, unicode):
            query = query.encode("utf-8")

        if start + rows > self.MAX_SEARCH_DEPTH:
            raise SearchDepthException(
                "Cannot search deeper then %s items. Use stream searching instead..." % self.MAX_SEARCH_DEPTH)
        if rows > self.MAX_ROW_SIZE:
            raise SearchDepthException("Page size cannot be bigger than %s." % self.MAX_ROW_SIZE)

        results = self.errors.search(query, df="text", start=start,
                                     rows=rows, sort="created desc", filter=access_control)
        data = self.get_errors_dict([x["_yz_rk"] for x in results['docs']])
        [v.update({"key": k}) for k, v in data.iteritems()]

        return {
            "items": sorted(data.values(), key=lambda y: y['created'], reverse=True),
            "total": results['num_found'], 'offset': start, "count": rows
        }

    def save_error(self, service_name, version, conf_key, task):
        srl = task.srl
        error = task.as_service_result()
        riak_key = self._get_riak_key(service_name, version, conf_key, srl)
        message = error.get('response', {}).get('message', '')
        riak_key += '.e' + md5(message).hexdigest()

        if not is_template_error(riak_key):
            self.pre_save_error(task, srl, error)
            self._save_bucket_item(self.errors, riak_key, error)
        return riak_key

    def search_error(self, query="*:*", start=0, rows=100, sort="_yz_rk asc", access_control=""):
        return self._search_bucket(self.errors, query, start, rows, sort, access_control=access_control)

    def wipe_errors(self):
        for key in self.errors.get_keys():
            self._delete_bucket_item(self.errors, key)
            print 'Wiped: {0}'.format(key)

    ################################################################
    # File Functions
    ########
    def delete_file(self, key, transport=None):
        self._delete_bucket_item(self.files, key)
        if transport:
            transport.delete(key)

    def get_file(self, key):
        return self._get_bucket_item(self.files, key)

    def get_file_from_hash(self, file_hash):
        items = self.direct_search("file", file_hash).get('response', {}).get("docs", [])

        if len(items) == 0:
            return None
        elif len(items) > 1:
            raise DataStoreException("Found the same hash more then once. Cannot choose which one to return!")

        sha256 = items[0].get("sha256", 0)
        return self.get_file(sha256)

    def get_files(self, key_list):
        return self._get_bucket_items(self.files, key_list)

    def get_files_dict(self, key_list):
        return self._get_bucket_items_dict(self.files, key_list)

    def list_file_keys(self):
        return self._list_bucket_keys(self.files)

    def list_file_debug_keys(self):
        return self._list_bucket_debug_keys(self.files)

    def save_or_freshen_file(self, srl, fileinfo, expiry, classification):
        current_fileinfo = self.get_file(srl) or {}

        # Remove control fields from file info and update current file info
        for x in ['classification', '__expiry_ts__', 'seen_count', 'seen_first', 'seen_last']:
            fileinfo.pop(x, None)
        current_fileinfo.update(fileinfo)

        # Update expiry time
        riak_expiry = current_fileinfo.get('__expiry_ts__', expiry)
        iso_expiry = epoch_to_iso(max(iso_to_epoch(riak_expiry), iso_to_epoch(expiry)))
        current_fileinfo['__expiry_ts__'] = iso_expiry

        # Update seen counters
        iso_now = now_as_iso()
        seen_count = current_fileinfo.get('seen_count', 0) + 1
        seen_first = current_fileinfo.get('seen_first', iso_now)
        current_fileinfo['seen_count'] = seen_count
        current_fileinfo['seen_last'] = iso_now
        current_fileinfo['seen_first'] = seen_first

        # Update Classification
        classification = Classification.min_classification(
            current_fileinfo.get('classification', classification),
            classification
        )
        current_fileinfo['classification'] = classification
        parts = Classification.get_access_control_parts(classification)
        current_fileinfo.update(parts)

        self.save_file(srl, current_fileinfo)

    def save_file(self, srl, fileinfo):
        self._save_bucket_item(self.files, srl, fileinfo)

    @RiakReconnect(wake_up_riak, log)
    def search_file(self, query, start=0, rows=100, access_control="", sort="seen_last desc"):
        output_res = {"items": [], "total": 0, "offset": start, "count": rows, 'bucket': "file"}
        if isinstance(query, unicode):
            query = query.encode("utf-8")

        if start + rows > self.MAX_SEARCH_DEPTH:
            raise SearchDepthException(
                "Cannot search deeper then %s items. Use stream searching instead..." % self.MAX_SEARCH_DEPTH)
        if rows > self.MAX_ROW_SIZE:
            raise SearchDepthException("Page size cannot be bigger than %s." % self.MAX_ROW_SIZE)

        file_res = self.files.search(query, df="text", start=start,
                                     rows=rows, sort=sort, filter=access_control)

        if file_res["num_found"]:
            output_res["total"] = file_res["num_found"]

            for x in file_res['docs']:
                output_res['items'].append(RiakStore.result_keys_to_dict(x))

        return output_res

    def wipe_files(self):
        for key in self.files.get_keys():
            self._delete_bucket_item(self.files, key)
            print 'Wiped: {0}'.format(key)

    ################################################################
    # File Scores Functions
    ########
    def delete_filescore(self, key):
        self._delete_bucket_item(self.filescores, key)

    def get_filescore(self, key):
        return self._get_bucket_item(self.filescores, key)

    def get_filescores(self, key_list):
        return self._get_bucket_items(self.filescores, key_list)

    def list_filescore_keys(self):
        return self._list_bucket_keys(self.filescores)

    def list_filescore_debug_keys(self):
        return self._list_bucket_debug_keys(self.filescores)

    def save_filescore(self, key, expiry, filescore):
        current_filescore = self.get_filescore(key) or {}
        current_expiry = current_filescore.get('__expiry_ts__', expiry)
        if iso_to_epoch(current_expiry) > iso_to_epoch(expiry):
            return
        filescore['__expiry_ts__'] = expiry
        return self._save_bucket_item(self.filescores, key, filescore)

    def search_filescore(self, query="*:*", start=0,
                         rows=100, sort="_yz_rk asc"):
        return self._search_bucket(self.filescores, query, start, rows, sort)

    def wipe_filescores(self):
        for key in self.filescores.get_keys():
            self._delete_bucket_item(self.filescores, key)
            print 'Wiped: {0}'.format(key)

    ################################################################
    # Nodes Functions
    ########
    def delete_node(self, mac_address):
        self._delete_bucket_item(self.nodes, mac_address)

    def get_node(self, mac_address):
        return self._get_bucket_item(self.nodes, mac_address)

    def get_nodes(self, key_list):
        return [n for n in self._get_bucket_items(self.nodes, key_list) if n is not None]

    def list_node_keys(self):
        return self._list_bucket_keys(self.nodes)

    def list_node_debug_keys(self):
        return self._list_bucket_debug_keys(self.nodes)

    def wipe_vm_nodes_by_parent_mac(self, parent_mac):
        nodes_to_wipe = self.get_vm_nodes_by_parent_mac(parent_mac)
        for node_key in nodes_to_wipe:
            self._delete_bucket_item(self.nodes, node_key)
        return nodes_to_wipe

    def get_vm_nodes_by_parent_mac(self, parent_mac):
        vm_nodes = []
        for key in self.list_node_keys():
            node_entry = self._get_bucket_item(self.nodes, key)
            if node_entry and 'is_vm' in node_entry and node_entry['is_vm']:
                if node_entry.get('vm_host_mac', None) == parent_mac:
                    vm_nodes.append(key)
        return vm_nodes

    def save_node(self, mac_address, registration):
        return self._save_bucket_item(self.nodes, mac_address, registration)

    def search_node(self, query="*:*", start=0, rows=100, sort="_yz_rk asc"):
        return self._search_bucket(self.nodes, query, start, rows, sort)

    def wipe_vm_nodes(self):
        for key in self.list_node_keys():
            node_entry = self._get_bucket_item(self.nodes, key)
            if node_entry and 'is_vm' in node_entry and node_entry['is_vm']:
                self._delete_bucket_item(self.nodes, key)
                print 'Deleted: {0}'.format(key)

    def wipe_nodes(self):
        for key in self.nodes.get_keys():
            self._delete_bucket_item(self.nodes, key)
            print 'Wiped: {0}'.format(key)

    ################################################################
    # Profiles Functions
    ########
    def delete_profile(self, key):
        self._delete_bucket_item(self.profiles, key)

    def get_profile(self, key):
        return self._get_bucket_item(self.profiles, key)

    @RiakReconnect(wake_up_riak, log)
    def get_all_profiles(self):
        query = "_yz_rk:*"

        return self._get_bucket_items_dict(self.profiles,
                                           [x['_yz_rk'] for x in self.stream_search("profile", query)])

    def get_profiles(self, key_list):
        return self._get_bucket_items(self.profiles, key_list)

    def get_profiles_dict(self, key_list):
        return self._get_bucket_items_dict(self.profiles, key_list)

    @RiakReconnect(wake_up_riak, log)
    def list_all_profiles(self):
        query = "_yz_rk:*"
        profiles = self._get_bucket_items_dict(self.profiles,
                                               [x['_yz_rk'] for x in self.stream_search("profile", query)])
        p_list = []
        for name, p in profiles.iteritems():
            p['name'] = name
            p_list.append(p)

        return sorted(p_list, key=lambda k: k['name'])

    @RiakReconnect(wake_up_riak, log)
    def list_profiles(self, query="*", start=0, rows=100):
        out = []

        if isinstance(query, unicode):
            query = query.encode("utf-8")

        if start + rows > self.MAX_SEARCH_DEPTH:
            raise SearchDepthException(
                "Cannot search deeper then %s items. Use stream searching instead..." % self.MAX_SEARCH_DEPTH)
        if rows > self.MAX_ROW_SIZE:
            raise SearchDepthException("Page size cannot be bigger than %s." % self.MAX_ROW_SIZE)

        results = self.profiles.search(query, df="_yz_rk", start=start,
                                       rows=rows, sort="_yz_rk asc")
        used_profiles = list(set([x['profile'] for x in self.stream_search("node", "profile:*", fl="profile")]))
        default_profiles = list(set([x['name']
                                     for x in self.list_virtualmachines()
                                     if x.get('name', None) is not None]))

        res_keys = [x['_yz_rk'] for x in results['docs']]
        res = self.get_profiles_dict(res_keys)

        count = results['num_found']

        for key in res_keys:
            try:
                val = res[key]
                item = {
                    "name": key,
                    "num_service": 0,
                    "num_vm": 0,
                    "num_worker": 0,
                    "used": key in used_profiles,
                    "vm_default": key in default_profiles
                }
                if 'services' in val:
                    item["num_service"] = len(val['services'])
                    for _, srv in val['services'].iteritems():
                        item['num_worker'] += srv.get('workers', 0)
                if 'virtual_machines' in val:
                    for _, v in val['virtual_machines'].iteritems():
                        item["num_vm"] += v.get('num_instances', 0)

                out.append(item)
            except:  # pylint:disable=W0702
                count -= 1

        return {
            "items": sorted(out, key=lambda k: k['name']),
            "total": count,
            'offset': start,
            "count": rows
        }

    def list_profile_keys(self):
        return self._list_bucket_keys(self.profiles)

    def list_profile_debug_keys(self):
        return self._list_bucket_debug_keys(self.profiles)

    def save_profile(self, name, profile):
        self.pre_save_profile(name, profile)
        return self._save_bucket_item(self.profiles, name, profile)

    def search_profile(self, query="*:*", start=0,
                       rows=100, sort="_yz_rk asc"):
        return self._search_bucket(self.profiles, query, start, rows, sort)

    def wipe_profiles(self):
        for key in self.profiles.get_keys():
            self._delete_bucket_item(self.profiles, key)
            print 'Wiped: {0}'.format(key)

    ################################################################
    # Result Functions
    ########
    def delete_result(self, key):
        if key.endswith('.e'):
            self._delete_bucket_item(self.emptyresults, key)
        else:
            self._delete_bucket_item(self.results, key)

    def freshen_result(self, service_name, version, conf_key, srl,
                       result, expiry, classification):
        if is_emptyresult(result):
            riak_key = self._get_riak_key(service_name, version, conf_key, srl)
            return riak_key + '.e'

        previous_classification = result.get(
            'classification', Classification.UNRESTRICTED)

        classification = Classification.min_classification(
            classification or Classification.UNRESTRICTED,
            previous_classification
        )

        result_classification = result.get('result', {}).get(
            'classification', Classification.UNRESTRICTED)

        classification = Classification.max_classification(
            classification, result_classification
        )

        previous_expiry = iso_to_epoch(result.get('__expiry_ts__', expiry))
        expiry = max(previous_expiry, iso_to_epoch(expiry))

        if classification == previous_classification and expiry < previous_expiry + 86400:
            return

        result['__expiry_ts__'] = epoch_to_iso(expiry)

        return self.save_result(service_name, version, conf_key, srl,
                                classification, result)

    def get_result(self, key):
        if key.endswith('.e'):
            return make_empty_result(
                key, self._get_bucket_item(self.files, key[:64])
            )
        else:
            return self._get_bucket_item(self.results, key)

    def get_results(self, key_list):
        empty_key_list = [e for e in key_list if e.endswith('.e')]
        result_key_list = [e for e in key_list if not e.endswith('.e')]

        empties = []
        if empty_key_list:
            sha256s = list(set([x[:64] for x in empty_key_list]))
            fileinfo = self._get_bucket_items_dict(self.files, sha256s)

            empties = [
                make_empty_result(x, fileinfo[x[:64]]) for x in empty_key_list
                ]

        results = self._get_bucket_items(self.results, result_key_list)

        return sorted(empties + results, key=lambda k: k['created'],
                      reverse=True)

    def get_results_dict(self, key_list):
        empty_key_list = [e for e in key_list if e.endswith('.e')]
        result_key_list = [e for e in key_list if not e.endswith('.e')]

        d = {}
        if empty_key_list:
            sha256s = list(set([x[:64] for x in empty_key_list]))
            fileinfo = self._get_bucket_items_dict(self.files, sha256s)

            d = {
                x: make_empty_result(x, fileinfo[x[:64]])
                for x in empty_key_list
                }

        d.update(self._get_bucket_items_dict(self.results, result_key_list))

        return d

    def list_emptyresult_debug_keys(self):
        return self._list_bucket_debug_keys(self.emptyresults)

    def list_result_keys(self):
        return self._list_bucket_keys(self.emptyresults) + self._list_bucket_keys(self.results)

    def list_result_debug_keys(self):
        return self._list_bucket_debug_keys(self.results)

    @RiakReconnect(wake_up_riak, log)
    def lookup_result(self, service_name, version, conf_key, srl):
        riak_key = self._get_riak_key(service_name, version, conf_key, srl)
        log.debug('LOOKUP key: %s', riak_key)

        riak_obj = self.results.get(
            riak_key, timeout=self.READ_TIMEOUT_MILLISECS
        )
        if riak_obj and riak_obj.data:
            return riak_key, riak_obj.data

        riak_key += '.e'
        riak_obj = self.emptyresults.get(
            riak_key, timeout=self.READ_TIMEOUT_MILLISECS
        )

        if riak_obj and riak_obj.data:
            return riak_key, make_empty_result(riak_key)

        return None, None

    def save_result(self, service_name, version, conf_key, srl, c12n, result):
        riak_key = self._get_riak_key(service_name, version, conf_key, srl)
        log.debug('STORING key: %s value: %s', riak_key, result)
        self.pre_save_result(c12n, srl, result)
        if is_emptyresult(result):
            riak_key += '.e'
            self._save_bucket_item(
                self.emptyresults, riak_key, {
                    '__expiry_ts__': result['__expiry_ts__']
                }
            )
            emptyresult_queue.push("\t".join((riak_key, result['created'])))
        else:
            self._save_bucket_item(self.results, riak_key, result)

        return riak_key

    @RiakReconnect(wake_up_riak, log)
    def search_result(self, query, start=0, rows=100, access_control="", sort="created desc"):
        output_res = {
            "items": [],
            "total": 0,
            "offset": start,
            "count": rows,
            "bucket": "result"
        }
        if isinstance(query, unicode):
            query = query.encode("utf-8")

        if start + rows > self.MAX_SEARCH_DEPTH:
            raise SearchDepthException(
                "Cannot search deeper then %s items. Use stream searching instead..." % self.MAX_SEARCH_DEPTH)
        if rows > self.MAX_ROW_SIZE:
            raise SearchDepthException("Page size cannot be bigger than %s." % self.MAX_ROW_SIZE)

        result_res = self.results.search(query, df="text", start=start,
                                         rows=rows, sort=sort, filter=access_control)

        if result_res["num_found"]:
            output_res["total"] = result_res["num_found"]

            for x in result_res['docs']:
                output_res['items'].append(RiakStore.result_keys_to_dict(x))

        return output_res

    def wipe_emptyresults(self):
        for key in self.emptyresults.get_keys():
            self._delete_bucket_item(self.emptyresults, key)
            print 'Wiped: {0}'.format(key)

    def wipe_results(self):
        for key in self.results.get_keys():
            self._delete_bucket_item(self.results, key)
            print 'Wiped: {0}'.format(key)

    ################################################################
    # Service Functions
    ########
    def delete_service(self, service):
        seed = self.get_blob('seed')
        if seed:
            try:
                del seed['services']['master_list'][service]
                self.save_blob('seed', seed)
            except KeyError:
                pass

    def get_service(self, name):
        seed = self.get_blob('seed')
        return seed.get('services', {}).get('master_list', {}).get(name, None)

    def get_services(self, key_list):
        seed = self.get_blob('seed')
        return [seed.get('services', {}).get('master_list', {}).get(name, None) for name in key_list]

    def list_services(self):
        seed = self.get_blob('seed')
        return sorted([seed['services']['master_list'][name]
                       for name in seed.get('services', {}).get('master_list', {}).keys()],
                      key=lambda k: k.get('name', ''))

    def list_service_keys(self):
        seed = self.get_blob('seed')
        return sorted(seed.get('services', {}).get('master_list', {}).keys())

    def save_service(self, name, service):
        seed = self.get_blob('seed')
        seed['services']['master_list'][name] = service
        self.save_blob('seed', seed)

    ################################################################
    # Signature Functions
    ########
    def update_signatures_last_modified(self):
        # Save this in a human-readable format.
        self.save_blob("signatures_last_modified", now_as_iso())

    def get_signatures_last_modified(self):
        # Return as epoch time to make it easy to compare.
        iso = self.get_blob("signatures_last_modified")
        if not iso:
            return '1970-01-01T00:00:00.000000Z'
        return iso

    def delete_signature(self, key):
        self._delete_bucket_item(self.signatures, key)
        self.update_signatures_last_modified()

    def get_signature(self, key):
        return self._get_bucket_item(self.signatures, key)

    def get_signatures(self, key_list):
        return self._get_bucket_items(self.signatures, key_list)

    def get_next_rev_for_name(self, org, name):
        query = "meta.id:%s_* AND name:%s" % (org, name)
        results = self.signatures.search(query, start=0, rows=1,
                                         sort="_yz_rk desc")["docs"]
        if len(results) == 0:
            return None, None
        else:
            try:
                return results[0]["meta.id"], int(results[0]["meta.rule_version"]) + 1
            except:  # pylint:disable=W0702
                return None, None

    def get_last_signature_id(self, org):
        query = "meta.id:%s_0*" % org
        results = self.signatures.search(query, start=0, rows=1,
                                         sort="_yz_rk desc")["docs"]
        if len(results) == 0:
            return 0
        else:
            try:
                return int(results[0]["meta.id"].split("_")[1])
            except:  # pylint:disable=W0702
                return 0

    def get_last_rev_for_id(self, sid):
        query = "meta.id:%s" % sid
        if isinstance(query, unicode):
            query = query.encode("utf-8")
        results = self.signatures.search(query, start=0, rows=1,
                                         sort="_yz_rk desc")["docs"]
        if len(results) == 0:
            return 0
        else:
            try:
                return int(results[0]["meta.rule_version"])
            except:  # pylint:disable=W0702
                return 0

    def list_signature_keys(self):
        return self._list_bucket_keys(self.signatures)

    def list_signature_debug_keys(self):
        return self._list_bucket_debug_keys(self.signatures)

    @RiakReconnect(wake_up_riak, log)
    def list_signatures(self, query="meta.id:*", start=0, rows=100, access_control=""):
        if isinstance(query, unicode):
            query = query.encode("utf-8")

        if start + rows > self.MAX_SEARCH_DEPTH:
            raise SearchDepthException(
                "Cannot search deeper then %s items. Use stream searching instead..." % self.MAX_SEARCH_DEPTH)
        if rows > self.MAX_ROW_SIZE:
            raise SearchDepthException("Page size cannot be bigger than %s." % self.MAX_ROW_SIZE)

        results = self.signatures.search(query, df="text", start=start,
                                         rows=rows, sort="_yz_rk asc", filter=access_control)
        return {
            "items": RiakStore.search_result_to_list_dict(results),
            "total": results['num_found'],
            "offset": start,
            "count": rows,
        }

    def save_signature(self, sid, signature):
        self.pre_save_signature(signature)
        self._save_bucket_item(self.signatures, sid, signature)
        self.update_signatures_last_modified()

    def list_filtered_signature_keys(self, query="*", access_control=None):
        if isinstance(query, unicode):
            query = query.encode("utf-8")

        return list(set([x["_yz_rk"] for x in self.stream_search("signature", query, fl="_yz_rk",
                                                                 access_control=access_control)]))

    def search_signature(self, query="*", start=0, rows=100, access_control="", sort="_yz_rk asc"):
        output_res = {
            "items": [],
            "total": 0,
            "offset": start,
            "count": rows,
            "bucket": "signature"
        }
        if isinstance(query, unicode):
            query = query.encode("utf-8")

        if start + rows > self.MAX_SEARCH_DEPTH:
            raise SearchDepthException(
                "Cannot search deeper then %s items. Use stream searching instead..." % self.MAX_SEARCH_DEPTH)
        if rows > self.MAX_ROW_SIZE:
            raise SearchDepthException("Page size cannot be bigger than %s." % self.MAX_ROW_SIZE)

        signature_res = self.signatures.search(query, df="text", start=start,
                                               rows=rows, sort=sort, filter=access_control)

        if signature_res["num_found"]:
            output_res["total"] = signature_res["num_found"]

            for x in signature_res['docs']:
                item = RiakStore.result_keys_to_dict(x)
                output_res['items'].append(item)

        return output_res

    def wipe_signatures(self):
        for key in self.signatures.get_keys():
            self._delete_bucket_item(self.signatures, key)
            print 'Wiped: {0}'.format(key)
        self.update_signatures_last_modified()

    ################################################################
    # Submission Functions
    ########
    SUMMARY_TAGS = ["NET_IP", "NET_DOMAIN_NAME", "NET_FULL_URI", "AV_VIRUS_NAME", "IMPLANT_NAME", "IMPLANT_FAMILY",
                    "TECHNIQUE_OBFUSCATION", "THREAT_ACTOR", "FILE_CONFIG", "FILE_OBFUSCATION", "EXPLOIT_NAME",
                    "FILE_SUMMARY"]

    # noinspection PyUnresolvedReferences
    def create_summary(self, submission, user):
        output = {"map": {}, "tags": {}}
        tags = self._get_bucket_item(self.submissions, submission['submission']['sid'] + "_summary")
        if not tags:
            tags = {"tags": self.get_tag_list_from_keys(submission.get("results", [])),
                    '__expiry_ts__': submission['__expiry_ts__']}
            try:
                self._save_bucket_item(self.submissions, submission['submission']['sid'] + "_summary", tags)
            except RiakError:
                pass

        for t in tags.get("tags", []):
            if t["type"] not in self.SUMMARY_TAGS or t['value'] == "" \
                    or not Classification.is_accessible(user['classification'], t['classification']):
                continue

            srl = t["key"][:64]
            tag_key = t['type'] + "__" + t['value']

            # File map
            if tag_key not in output['map']:
                output['map'][tag_key] = []

            if srl not in output['map'][tag_key]:
                output['map'][tag_key].append(srl)

            # Tag map
            if srl not in output['map']:
                output['map'][srl] = []

            if srl not in output['map'][srl]:
                output['map'][srl].append(tag_key)

            # Tags
            if t['type'] not in output['tags']:
                output['tags'][t['type']] = {t['value']: {'classification': t['classification'],
                                                          'usage': t['usage'],
                                                          'context': t['context']}}
            else:
                if t['value'] not in output['tags'][t['type']]:
                    output['tags'][t['type']][t['value']] = {'classification': t['classification'],
                                                             'usage': t['usage'],
                                                             'context': t['context']}

        for t_type in output['tags']:
            output['tags'][t_type] = [
                {'value': k, 'classification': Classification.max_classification(v['classification'],
                                                                                 submission['classification']),
                 'context': v['context'],
                 'usage': v['usage']}
                for k, v in output['tags'][t_type].iteritems()
                ]

        return output

    @staticmethod
    def _is_valid_tree(tree, num_files, max_score):
        def _count_children(sub_tree, cur_files, cur_score):
            temp_score = cur_score
            for k, v in sub_tree.iteritems():
                if v['score'] > temp_score:
                    temp_score = v['score']
                cur_files.append(k)
                cur_files, temp_score = _count_children(v.get("children", {}), cur_files, temp_score)
            return cur_files, temp_score

        files, tree_score = _count_children(tree, [], 0)
        files = list(set(files))

        if len(files) < num_files:
            return False

        if tree_score != max_score:
            return False

        return True

    def create_file_tree(self, submission):
        results = submission.get('results', [])
        num_files = len(list(set([x[:64] for x in results])))
        max_score = submission.get('submission', {}).get('max_score', 0)

        cached_tree = self._get_bucket_item(self.submissions, submission['submission']['sid'] + "_tree")
        if cached_tree:
            del cached_tree['__expiry_ts__']
            if self._is_valid_tree(cached_tree, num_files, max_score):
                return cached_tree

        tree = {}

        plan = [
            (self.get_file_list_from_keys, (results,), "files"),
            (self.get_files_scores_from_keys, (results,), "scores")
        ]

        res = execute_concurrently(plan)

        files = res.get("files", {})
        scores = res.get("scores", {})
        tree_cache = []

        def recurse_tree(child_p, placeholder, parents_p, lvl=0):
            if lvl == config.core.dispatcher.max.depth + 1:
                # Enforce depth protection while building the tree
                return

            if child_p['srl'] in placeholder:
                placeholder[child_p['srl']]['name'].append(child_p['name'])
            else:
                children_list = {}
                truncated = False
                child_list = files.get(child_p['srl'], [])
                for new_child in child_list:
                    if new_child['srl'] in tree_cache:
                        truncated = True
                        continue
                    tree_cache.append(child['srl'])

                    if new_child['srl'] not in parents_p:
                        recurse_tree(new_child, children_list,
                                     parents_p + [child_p['srl']], lvl+1)

                placeholder[child_p['srl']] = {
                    "name": [child_p['name']],
                    "children": children_list,
                    "truncated": truncated,
                    "score": scores.get(child_p['srl'], 0),
                }

        for name, srl in submission['files']:
            if srl in tree:
                tree[srl]['name'].append(name)
            else:
                parents = [srl]
                children = {}
                c_list = files.get(srl, [])
                for child in c_list:
                    tree_cache.append(child['srl'])
                    recurse_tree(child, children, parents)

                tree[srl] = {
                    "name": [name],
                    "children": children,
                    "truncated": False,
                    "score": scores.get(srl, 0),
                }

        tree['__expiry_ts__'] = submission['__expiry_ts__']
        try:
            self._save_bucket_item(self.submissions, submission['submission']['sid'] + "_tree", tree)
        except RiakError:
            pass
        del tree['__expiry_ts__']

        return tree

    def delete_submission(self, key):
        self._delete_bucket_item(self.submissions, key)

    def delete_submission_tree(self, key, cleanup=True, transport=None):
        submission = self.get_submission(key)
        errors = submission.get("errors", [])
        results = submission.get("results", [])
        files = []
        fix_classification_files = []

        temp_files = [x[:64] for x in errors]
        temp_files.extend([x[:64] for x in results])
        temp_files = list(set(temp_files))
        for temp in temp_files:
            query = "errors:%s OR results:%s" % (temp, temp)
            if self.search_submission(query, rows=0)["total"] < 2:
                files.append(temp)
            else:
                fix_classification_files.append(temp)
        errors = [x for x in errors if x[:64] in files]
        results = [x for x in results if x[:64] in files]

        # Delete childs
        for e in errors:
            self.delete_error(e)
        for r in results:
            self.delete_result(r)
        for f in files:
            self.delete_file(f, transport=transport)
        if fix_classification_files and cleanup:
            # Fix classification for the files that remain in the system
            for f in fix_classification_files:
                cur_file = self.get_file(f)
                if cur_file:
                    classifications = []
                    # Find possible submissions that uses that file and the min classification for those submissions
                    for item in self.stream_search("submission", "files:%s OR results:%s OR errors:%s" % (f, f, f),
                                                   fl="classification,_yz_rk"):
                        if item['_yz_rk'] != key:
                            classifications.append(item['classification'])
                    classifications = list(set(classifications))
                    if len(classifications) > 0:
                        new_file_class = classifications[0]
                    else:
                        new_file_class = Classification.UNRESTRICTED

                    for c in classifications:
                        new_file_class = Classification.min_classification(new_file_class, c)

                    # Find the results for that classification and alter them if the new classification does not match
                    for item in self.stream_search("result", "_yz_rk:%s*" % f, fl="classification,_yz_rk"):
                        new_class = Classification.max_classification(
                            item.get('classification', Classification.UNRESTRICTED), new_file_class)
                        if item.get('classification', Classification.UNRESTRICTED) != new_class:
                            cur_res = self.get_result(item['_yz_rk'])
                            if cur_res:
                                cur_res['classification'] = new_class
                                parts = Classification.get_access_control_parts(new_class)
                                cur_res.update(parts)

                                self._save_bucket_item(self.results, item['_yz_rk'], cur_res)

                    # Alter the file classification if the new classification does not match
                    if cur_file['classification'] != new_file_class:
                        cur_file['classification'] = new_file_class
                        parts = Classification.get_access_control_parts(new_file_class)
                        cur_file.update(parts)

                        self._save_bucket_item(self.files, f, cur_file)

        self._delete_bucket_item(self.submissions, key)
        self._delete_bucket_item(self.submissions, key + "_tree")
        self._delete_bucket_item(self.submissions, key + "_summary")

    def get_submission(self, key):
        return self._get_bucket_item(self.submissions, key)

    def get_submissions(self, key_list):
        return self._get_bucket_items(self.submissions, key_list)

    def list_submission_keys(self):
        return self._list_bucket_keys(self.submissions)

    def list_submission_debug_keys(self):
        return self._list_bucket_debug_keys(self.submissions)

    @RiakReconnect(wake_up_riak, log)
    def list_submissions(self, username="*", start=0, rows=100, qfilter="*", access_control=""):
        if username == "*":
            query = qfilter
        else:
            query = "submission.submitter:%s AND %s" % (username, qfilter)

        if start + rows > self.MAX_SEARCH_DEPTH:
            raise SearchDepthException(
                "Cannot search deeper then %s items. Use stream searching instead..." % self.MAX_SEARCH_DEPTH)
        if rows > self.MAX_ROW_SIZE:
            raise SearchDepthException("Page size cannot be bigger than %s." % self.MAX_ROW_SIZE)

        if isinstance(query, unicode):
            query = query.encode("utf-8")

        results = self.submissions.search(query, df="text",
                                          start=start, rows=rows,
                                          sort="times.submitted desc", filter=access_control)
        return {
            "items": RiakStore.search_result_to_list_dict(results),
            "total": results['num_found'],
            "offset": start,
            "count": rows,
        }

    @RiakReconnect(wake_up_riak, log)
    def list_submissions_group(self, group="*", start=0, rows=100, qfilter="*", access_control=""):
        if group == "*":
            query = qfilter
        else:
            query = "submission.groups:%s AND %s" % (group, qfilter)

        if isinstance(query, unicode):
            query = query.encode("utf-8")

        if start + rows > self.MAX_SEARCH_DEPTH:
            raise SearchDepthException(
                "Cannot search deeper then %s items. Use stream searching instead..." % self.MAX_SEARCH_DEPTH)
        if rows > self.MAX_ROW_SIZE:
            raise SearchDepthException("Page size cannot be bigger than %s." % self.MAX_ROW_SIZE)

        results = self.submissions.search(query, df="text",
                                          start=start, rows=rows,
                                          sort="times.submitted desc", filter=access_control)
        return {
            "items": RiakStore.search_result_to_list_dict(results),
            "total": results['num_found'],
            "offset": start,
            "count": rows,
        }

    def save_submission(self, sid, submission):
        if submission is None:
            log.warn('Trying to save an empty submission: %s', sid)
            return
        self.pre_save_submission(submission)
        self._save_bucket_item(self.submissions, sid, submission)

    @RiakReconnect(wake_up_riak, log)
    def search_submission(self, query, start=0, rows=100, access_control="", fl="*", sort="times.submitted desc"):
        if "score" not in fl:
            fl += ",score"
        output_res = {
            "items": [],
            "total": 0,
            "offset": start,
            "count": rows,
            "bucket": "submission"
        }
        if isinstance(query, unicode):
            query = query.encode("utf-8")

        if start + rows > self.MAX_SEARCH_DEPTH:
            raise SearchDepthException(
                "Cannot search deeper then %s items. Use stream searching instead..." % self.MAX_SEARCH_DEPTH)
        if rows > self.MAX_ROW_SIZE:
            raise SearchDepthException("Page size cannot be bigger than %s." % self.MAX_ROW_SIZE)

        submission_res = self.submissions.search(query, df="text", fl=fl,
                                                 start=start, rows=rows,
                                                 sort=sort, filter=access_control)

        if submission_res["num_found"]:
            output_res["total"] = submission_res["num_found"]

            for x in submission_res['docs']:
                item = RiakStore.result_keys_to_dict(x)
                output_res['items'].append(item)

        return output_res

    def wipe_submissions(self):
        for key in self.submissions.get_keys():
            self._delete_bucket_item(self.submissions, key)
            print 'Wiped: {0}'.format(key)

    ################################################################
    # User Functions
    ########
    def delete_user(self, key):
        self._delete_bucket_item(self.users, key)

    def get_user_account(self, user):
        return self._get_bucket_item(self.users, user)

    def get_user_avatar(self, user):
        return self._get_bucket_item(self.users, "%s_avatar" % user)

    def get_user_favorites(self, user):
        return self._get_bucket_item(self.users, "%s_favorites" % user)

    def get_user_options(self, user):
        return self._get_bucket_item(self.users, "%s_options" % user)

    def get_user(self, systemname):
        return self._get_bucket_item(self.users, systemname)

    def get_users(self, key_list):
        return self._get_bucket_items(self.users, key_list)

    @RiakReconnect(wake_up_riak, log)
    def list_users(self, start=0, rows=100, query=None):
        if not query:
            query = "uname:*"
        else:
            query = "uname:* AND %s" % query

        if isinstance(query, unicode):
            query = query.encode("utf-8")

        if start + rows > self.MAX_SEARCH_DEPTH:
            raise SearchDepthException(
                "Cannot search deeper then %s items. Use stream searching instead..." % self.MAX_SEARCH_DEPTH)
        if rows > self.MAX_ROW_SIZE:
            raise SearchDepthException("Page size cannot be bigger than %s." % self.MAX_ROW_SIZE)

        results = self.users.search(query, df="text", start=start,
                                    rows=rows, sort="uname asc")
        return {
            "items": RiakStore.search_result_to_list_dict(results),
            "total": results['num_found'],
            "offset": start,
            "count": rows,
        }

    def list_user_keys(self):
        return self._list_bucket_keys(self.users)

    def list_user_debug_keys(self):
        return self._list_bucket_debug_keys(self.users)

    def save_user(self, key, value):
        if value is None:
            return

        if isinstance(value, dict):
            if value.get("avatar", None) is not None:
                if self.set_user_avatar(key, value["avatar"]):
                    value["avatar"] = None
        self._save_bucket_item(self.users, key, value)

    def search_user(self, query="*:*", start=0, rows=100, sort="_yz_rk asc"):
        return self._search_bucket(self.users, query, start, rows, sort)

    def set_user_account(self, user, data):
        try:
            self._save_bucket_item(self.users, user, data)
            return True
        except:  # pylint:disable=W0702
            return False

    def set_user_avatar(self, user, data):
        try:
            # Validate avatar
            if not (data.startswith("data:image") and ";base64," in data[:30]):
                return False

            key = "%s_avatar" % user
            self._save_bucket_item(self.users, key, data)
            return True
        except:  # pylint:disable=W0702
            return False

    def set_user_favorites(self, user, data):
        try:
            key = "%s_favorites" % user
            self._save_bucket_item(self.users, key, data)
            return True
        except:  # pylint:disable=W0702
            return False

    def set_user_options(self, user, data):
        try:
            key = "%s_options" % user
            self._save_bucket_item(self.users, key, data)
            return True
        except:  # pylint:disable=W0702
            return False

    def wipe_users(self):
        for key in self.users.get_keys():
            self._delete_bucket_item(self.users, key)
            print 'Wiped: {0}'.format(key)

    ################################################################
    # VirtualMachine Functions
    ########
    def delete_virtualmachine(self, virtualmachine):
        seed = self.get_blob('seed')
        if seed:
            try:
                del seed['workers']['virtualmachines']['master_list'][virtualmachine]
                self.save_blob('seed', seed)
            except KeyError:
                pass

    def get_virtualmachine(self, name):
        seed = self.get_blob('seed')
        temp_vm = seed.get('workers', {}).get('virtualmachines', {}).get('master_list', {}).get(name, {})
        vm = temp_vm.get('cfg', None)
        if vm:
            vm['num_workers'] = temp_vm.get('num_workers', 1)
        return vm

    def get_virtualmachines(self, key_list):
        seed = self.get_blob('seed')
        out = []
        for name in key_list:
            temp_vm = seed.get('workers', {}).get('virtualmachines', {}).get('master_list', {}).get(name, {})
            vm = temp_vm.get('cfg', None)
            if vm:
                vm['num_workers'] = temp_vm.get('num_workers', 1)
            out.append(vm)
        return

    def list_virtualmachines(self):
        seed = self.get_blob('seed')
        out = []
        for name in seed.get('workers', {}).get('virtualmachines', {}).get('master_list', {}).keys():
            temp_vm = seed.get('workers', {}).get('virtualmachines', {}).get('master_list', {}).get(name, {})
            vm = temp_vm.get('cfg', None)
            if vm:
                vm['num_workers'] = temp_vm.get('num_workers', 1)
            out.append(vm)

        return sorted(out, key=lambda k: k.get('name', ''))

    def list_virtualmachine_keys(self):
        seed = self.get_blob('seed')
        return sorted(seed.get('workers', {}).get('virtualmachines', {}).get('master_list', {}).keys())

    def save_virtualmachine(self, name, virtualmachine):
        seed = self.get_blob('seed')
        if name in seed['workers']['virtualmachines']['master_list']:
            template = seed['workers']['virtualmachines']['master_list'][name]
        else:
            template = {'cfg': {}, "num_workers": 1}
        template['num_workers'] = virtualmachine.get('num_workers', 1)
        virtualmachine.pop('num_workers', None)
        template['cfg'].update(virtualmachine)
        seed['workers']['virtualmachines']['master_list'][name] = template
        self.save_blob('seed', seed)

    ################################################################
    # Workflow Functions
    ########
    def delete_workflow(self, wf):
        self._delete_bucket_item(self.workflows, wf)

    def increment_workflow_counter(self, wf_id, count):
        wf = self.get_workflow(wf_id)
        if not wf:
            return

        if "hit_count" in wf:
            wf['hit_count'] += count
        else:
            wf['hit_count'] = count

        wf['last_seen'] = now_as_iso()
        self.save_workflow(wf_id, wf)

    def get_workflow(self, wf):
        return self._get_bucket_item(self.workflows, wf)

    def get_workflows(self, wf_list):
        return self._get_bucket_items(self.workflows, wf_list)

    @RiakReconnect(wake_up_riak, log)
    def list_workflows(self, start=0, rows=100, query=None, access_control=""):
        if not query:
            query = "*:*"

        if isinstance(query, unicode):
            query = query.encode("utf-8")

        if start + rows > self.MAX_SEARCH_DEPTH:
            raise SearchDepthException(
                "Cannot search deeper then %s items. Use stream searching instead..." % self.MAX_SEARCH_DEPTH)
        if rows > self.MAX_ROW_SIZE:
            raise SearchDepthException("Page size cannot be bigger than %s." % self.MAX_ROW_SIZE)

        results = self.workflows.search(query, df="text", start=start, rows=rows,
                                        sort="name asc", filter=access_control)
        return {
            "items": RiakStore.search_result_to_list_dict(results),
            "total": results['num_found'],
            "offset": start,
            "count": rows,
        }

    def list_workflow_labels(self, access_control=""):
        args = [
            ("rows", "0"),
            ("facet", "on"),
            ("facet.field", "label"),
        ]
        res = self.direct_search('workflow', '*', args=args, __access_control__=access_control)
        labels = res.get('facet_counts', {}).get('facet_fields', {}).get('label', [])

        lbl_out = []
        count = 0
        for lbl in labels:
            if count % 2 == 0:
                lbl_out.append(lbl)
            count += 1

        return lbl_out

    def list_workflow_keys(self):
        return self._list_bucket_keys(self.workflows)

    def list_workflow_debug_keys(self):
        return self._list_bucket_debug_keys(self.workflows)

    def save_workflow(self, wf, wf_data):
        if wf_data is None:
            return

        self.pre_save_workflow(wf, wf_data)
        self._save_bucket_item(self.workflows, wf, wf_data)

    def search_workflow(self, query="*:*", start=0, rows=100, sort="name asc", access_control=""):
        return self._search_bucket(self.workflows, query, start, rows, sort, filter=access_control)

    def wipe_workflows(self):
        for key in self.workflows.get_keys():
            self._delete_bucket_item(self.workflows, key)
            print 'Wiped: {0}'.format(key)


def utf8safe_encoder(obj):
    """
    This fixes riak unicode issues when strings in blob are already UTF-8.
    """
    return json.dumps(obj)
