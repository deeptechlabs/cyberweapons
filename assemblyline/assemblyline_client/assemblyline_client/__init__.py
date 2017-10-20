import json
import logging
import os
import re
import requests
import socketIO_client
import sys
import time
import threading

from base64 import b64encode
from json import dumps
from os.path import basename

__all__ = ['Client', 'ClientError']
__build__ = [3, 2, 0]

try:
    # noinspection PyUnresolvedReferences,PyUnboundLocalVariable
    basestring
except NameError:
    # noinspection PyShadowingBuiltins
    basestring = str  # pylint: disable=W0622

try:
    from urllib2 import quote
except ImportError:
    # noinspection PyUnresolvedReferences
    from urllib.parse import quote  # pylint: disable=E0611,F0401

INVALID_STREAM_SEARCH_PARAMS = ('cursorMark', 'rows', 'sort')
RETRY_FOREVER = 0
SEARCHABLE = ('alert', 'file', 'result', 'signature', 'submission')
SUPPORTED_API = 'v3'


def _bool_to_param_string(b):
    if not isinstance(b, bool):
        return b
    return {True: 'true', False: 'false'}[b]


def _convert(response):
    return response.json()['api_response']


def _join_param(k, v):
    return '='.join((k, quote(str(v)))) 


def _join_kw(kw):
    return '&'.join([
        _join_param(k, v) for k, v in kw.items() if v is not None
    ])


def _join_params(q, l):
    return '&'.join([quote(q)] + [_join_param(*e) for e in l if _param_ok(e)])


# noinspection PyProtectedMember
def _kw(*ex):
    local_frames = sys._getframe().f_back.f_locals  # pylint: disable=W0212
    return {
        k: _bool_to_param_string(v) for k, v in local_frames.items() if k not in ex
    }


# Calculate the API path using the class and method names as shown below:
#
#     /api/v3/<class_name>/<method_name>/[arg1/[arg2/[...]]][?k1=v1[...]]
#
# noinspection PyProtectedMember
def _magic_path(obj, *args, **kw):
    c = obj.__class__.__name__.lower()
    m = sys._getframe().f_back.f_code.co_name  # pylint:disable=W0212

    return _path('/'.join((c, m)), *args, **kw)


def _param_ok(k):
    return k not in ('q', 'df', 'wt')


# Calculate the API path using the prefix as shown:
#
#     /api/v3/<prefix>/[arg1/[arg2/[...]]][?k1=v1[...]]
#
def _path(prefix, *args, **kw):
    path = '/'.join(['api', SUPPORTED_API, prefix] + list(args) + [''])

    params = _join_kw(kw)
    if not params:
        return path

    return '?'.join((path, params))


def _raw(response):
    return response.content


def _stream(output):
    def _do_stream(response):
        f = output
        if isinstance(output, basestring):
            f = open(output, 'wb')
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                f.write(chunk)
        if f != output:
            f.close()
    return _do_stream


def _walk(obj, path, paths):
    if isinstance(obj, int):
        return
    for m in dir(obj):
        mobj = getattr(obj, m)
        if m == '__call__':
            doc = str(mobj.__doc__)
            if doc in (
                'x.__call__(...) <==> x(...)',
                'Call self as a function.'
            ):
                doc = str(obj.__doc__)
            doc = doc.split("\n\n", 1)[0]
            doc = re.sub(r'\s+', ' ', doc.strip())
            if doc != 'For internal use.':
                paths.append(['.'.join(path), doc])
            continue
        elif m.startswith('_') or m.startswith('im_'):
            continue

        _walk(mobj, path + [m], paths)


class Alert(object):
    def __init__(self, connection):
        self._connection = connection
        self.batch = Batch(connection)

    def __call__(self, event_id):
        """\
Return the full alert for the given event_id.

Required:
event_id: Alert key. (string)

Throws a Client exception if the alert does not exist.
"""
        return self._connection.get(_path('alert', event_id))

    def label(self, event_id, *labels):
        """\
Add label(s) to the alert with the given event_id.

Required:
event_id: Alert key. (string)
*labels : One or more labels. (variable argument list of strings).

Throws a Client exception if the alert does not exist.
"""
        return self._connection.get(_magic_path(self, event_id, *labels))

    def ownership(self, event_id):
        """\
Set the ownership of the alert with the given event_id to the current user.

Required:
event_id: Alert key. (string)

Throws a Client exception if the alert does not exist.
"""
        return self._connection.get(_magic_path(self, event_id))

    def priority(self, event_id, priority):
        """\
Set the priority of the alert with the given event_id.

Required:
event_id: Alert key. (string)
priority: Priority. (integer-ish).

Throws a Client exception if the alert does not exist.
"""
        return self._connection.get(_magic_path(self, event_id, priority))

    def status(self, event_id, status):
        """\
Set the status of the alert with the given event_id.

Required:
event_id: Alert key. (string)
status  : Status. (string).

Throws a Client exception if the alert does not exist.
"""
        return self._connection.get(_magic_path(self, event_id, status))


# noinspection PyUnusedLocal
class Batch(object):
    def __init__(self, connection):
        self._connection = connection

    def label(self, q, labels, tc=None, start=None, fq_list=None):  # pylint: disable=W0613
        """\
Add labels to alerts matching the search criteria.

Required:
q       : SOLR query. (string)
labels  : Labels to apply. (list of strings)

Optional:
tc      : Beginning* of time range as SOLR Date Math offset. (string)
start   : End* of time range as SOLR Date. Defaults to 'NOW'. (string)
fq_list : List of filter queries. (list of strings)

*Batch operations can be thought of as working backward from start time.
"""
        kw = _kw('self', 'fq_list', 'labels')
        path = _path('alert/label/batch', *labels, **kw)

        if not fq_list:
            fq_list = []

        return self._connection.get(path, *fq_list)

    def ownership(self, q, tc=None, start=None, fq_list=None):  # pylint: disable=W0613
        """\
Set ownership on alerts matching the search criteria.

Required:
q       : SOLR query. (string)

Optional:
tc      : Beginning* of time range as SOLR Date Math offset. (string)
start   : End* of time range as SOLR Date. Defaults to 'NOW'. (string)
fq_list : List of filter queries. (list of strings)

*Batch operations can be thought of as working backward from start time.
"""
        kw = _kw('self', 'fq_list', 'ownership')
        path = _path('alert/ownership/batch', **kw)

        if not fq_list:
            fq_list = []

        return self._connection.get(path, *fq_list)

    def priority(self, q, priority, tc=None, start=None, fq_list=None):  # pylint: disable=W0613
        """\
Set the priority on alerts matching the search criteria.

Required:
q       : SOLR query. (string)
priority: Priority to apply. (integer-ish)

Optional:
tc      : Beginning* of time range as SOLR Date Math offset. (string)
start   : End* of time range as SOLR Date. Defaults to 'NOW'. (string)
fq_list : List of filter queries. (list of strings)

*Batch operations can be thought of as working backward from start time.
"""
        kw = _kw('self', 'fq_list', 'priority')
        path = _path('alert/priority/batch', priority, **kw)

        if not fq_list:
            fq_list = []

        return self._connection.get(path, *fq_list)

    def status(self, q, status, tc=None, start=None, fq_list=None):  # pylint: disable=W0613
        """\
Set the status on alerts matching the search criteria.

Required:
q       : SOLR query. (string)
status  : Status to apply. (string)

Optional:
tc      : Beginning* of time range as SOLR Date Math offset. (string)
start   : End* of time range as SOLR Date. Defaults to 'NOW'. (string)
fq_list : List of filter queries. (list of strings)

*Batch operations can be thought of as working backward from start time.
"""
        kw = _kw('self', 'fq_list', 'status')
        path = _path('alert/status/batch', status, **kw)

        if not fq_list:
            fq_list = []

        return self._connection.get(path, *fq_list)


class Bundle(object):
    def __init__(self, connection):
        self._connection = connection

    def create(self, sid, output=None):
        """\
Creates a bundle containing the submission results and the associated files

Required:
sid    : Submission ID (string)

Optional:
output  : Path or file handle. (string or file-like object)

If output is not specified the content is returned
"""
        path = _path('bundle/create', sid)

        if output:
            return self._connection.download(path, _stream(output))
        return self._connection.download(path, _raw)

    def import_bundle(self, bundle):
        """\
Import a submission bundle into the system

Required:
bundle      : bundle to import (string, bytes or file_handle)

Returns {'success': True/False } depending if it was imported or not
"""
        if isinstance(bundle, basestring):
            if len(bundle) <= 1024 and os.path.exists(bundle):
                with open(bundle, 'rb') as f:
                    contents = f.read()
            else:
                contents = bundle
        elif "read" in dir(bundle):
            contents = bundle.read()
        else:
            raise TypeError("Invalid bundle")

        return self._connection.post(_path('bundle/import'), data=contents)


class Client(object):
    def __init__(  # pylint: disable=R0913
        self, server, auth=None, cert=None, debug=lambda x: None,
        headers=None, retries=RETRY_FOREVER, silence_requests_warnings=True, apikey=None
    ):
        self._connection = Connection(
            server, auth, cert, debug, headers, retries,
            silence_requests_warnings, apikey
        )

        self.alert = Alert(self._connection)
        self.bundle = Bundle(self._connection)
        self.file = File(self._connection)
        self.hash_search = HashSearch(self._connection)
        self.ingest = Ingest(self._connection)
        self.live = Live(self._connection)
        self.search = Search(self._connection)
        self.service = Service(self._connection)
        self.signature = Signature(self._connection)
        self.socketio = SocketIO(self._connection)
        self.submission = Submission(self._connection)
        self.submit = Submit(self._connection)
        self.user = User(self._connection)

        paths = []
        _walk(self, [''], paths)

        self.__doc__ = 'Client provides the following methods:\n\n' + \
            '\n'.join(['\n'.join(p + ['']) for p in paths])


class ClientError(Exception):
    def __init__(self, message, status_code):
        super(ClientError, self).__init__(message)
        self.status_code = status_code


# noinspection PyPackageRequirements
class Connection(object):
    # noinspection PyUnresolvedReferences
    def __init__(  # pylint: disable=R0913
        self, server, auth, cert, debug, headers, retries,
        silence_requests_warnings, apikey
    ):
        self.auth = auth
        self.apikey = apikey
        if silence_requests_warnings:
            try:
                requests.packages.urllib3.disable_warnings()  # pylint: disable=E1101
            except AttributeError:
                # Difference versions of requests may not have 'packages'.
                try:
                    requests.urllib3.disable_warnings()  # pylint: disable=E1101
                except AttributeError:
                    pass

        self.debug = debug
        self.max_retries = retries
        self.server = server

        session = requests.Session()

        session.headers.update({'content-type': 'application/json'})
        session.verify = False

        if cert:
            session.cert = cert
        if headers:
            session.headers.update(headers)

        self.session = session

        try:
            auth_session_detail = self._authenticate()
        except ClientError as ce:
            if ce.status_code == 404:
                # The 'api/v3/auth/login/' api does not exist, reverting to old authentication method.
                auth_session_detail = {'session_duration': 60}
                session.auth = self.auth
            else:
                raise

        session.timeout = auth_session_detail['session_duration']

        r = self.request(self.session.get, 'api/', _convert)
        s = {SUPPORTED_API}
        if not isinstance(r, list) or not set(r).intersection(s):
            raise ClientError("Supported API (%s) not available" % s, 0)

    def _load_public_encryption_key(self):
        public_key = self.request(self.session.get, "api/v3/auth/init/", _convert)

        if not public_key:
            return None

        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_v1_5

        key = RSA.importKey(public_key)
        return PKCS1_v1_5.new(key)

    def _authenticate(self):
        if self.apikey and len(self.apikey) == 2:
            public_key = self._load_public_encryption_key()
            if public_key:
                key = b64encode(public_key.encrypt(self.apikey[1]))
            else:
                key = self.apikey[1]
            auth = {
                'user': self.apikey[0],
                'apikey': key
            }
        elif self.auth and len(self.auth) == 2:
            public_key = self._load_public_encryption_key()
            if public_key:
                pw = b64encode(public_key.encrypt(self.auth[1]))
            else:
                pw = self.auth[1]
            auth = {
                'user': self.auth[0],
                'password': pw
            }
        else:
            auth = {}
        return self.request(self.session.get, "api/v3/auth/login/", _convert, data=json.dumps(auth))

    def delete(self, path, **kw):
        return self.request(self.session.delete, path, _convert, **kw)

    def download(self, path, process, **kw):
        return self.request(self.session.get, path, process, **kw)

    def get(self, path, **kw):
        return self.request(self.session.get, path, _convert, **kw)

    def post(self, path, **kw):
        return self.request(self.session.post, path, _convert, **kw)

    def request(self, func, path, process, **kw):
        self.debug(path)

        retries = 0
        while self.max_retries < 1 or retries <= self.max_retries:
            if retries:
                time.sleep(min(2, 2 ** (retries - 7)))
            response = func('/'.join((self.server, path)), **kw)
            if 'XSRF-TOKEN' in response.cookies:
                self.session.headers.update({'X-XSRF-TOKEN': response.cookies['XSRF-TOKEN']})
            if response.ok:
                return process(response)
            elif response.status_code == 401:
                try:
                    resp_data = response.json()
                    if resp_data["api_error_message"] == "Authentication required":
                        self._authenticate()
                    else:
                        raise ClientError(response.content, response.status_code)
                except Exception:
                    raise ClientError(response.content, response.status_code)
            elif response.status_code not in (502, 503, 504):
                raise ClientError(response.content, response.status_code)

            retries += 1


# noinspection PyUnusedLocal
class File(object):
    def __init__(self, connection):
        self._connection = connection

    def children(self, srl):
        """\
Return the list of children for the file with the given srl.

Required:
srl     : File key. (string)

Throws a Client exception if the file does not exist.
"""
        return self._connection.get(_magic_path(self, srl))

    # noinspection PyShadowingBuiltins
    def download(self, srl, format=None, output=None, password=None):  # pylint: disable=W0613,W0622
        """\
Download the file with the given srl.

Required:
srl     : File key. (string)

Optional:
format  : Encoding. (string)
output  : Path or file handle. (string or file-like object)
password: For password-protected zips. (string)

If output is not specified the content is returned.

Throws a Client exception if the file does not exist.
"""
        kw = _kw('output', 'self', 'srl')
        path = _magic_path(self, srl, **kw)
        if output:
            return self._connection.download(path, _stream(output))
        return self._connection.download(path, _raw)

    def info(self, srl):
        """\
Return info for the the file with the given srl.

Required:
srl     : File key. (string)

Throws a Client exception if the file does not exist.
"""
        return self._connection.get(_magic_path(self, srl))

    def result(self, srl, service=None):
        """\
Return all the results for the given srl.

Required:
srl     : File key. (string)

Optional:
service : Service name. (string)

If a service is specified, results are limited to that service.

Throws a Client exception if the file does not exist.
"""
        args = [service] if service else []
        return self._connection.get(_magic_path(self, srl, *args))

    def score(self, srl):
        """\
Return the latest score for the given srl.

Required:
srl     : File key. (string)

Throws a Client exception if the file does not exist.
"""
        return self._connection.get(_magic_path(self, srl))


class HashSearch(object):
    def __init__(self, connection):
        self._connection = connection

    def __call__(self, h, db=None):
        """\
Perform a hash search for the given md5, sha1 or sha256.

Required:
h       : Hash - md5, sha1 or sha256. (string)

Optional:
db      : Data sources to query. (list of strings).

Note: Not all hash types are supported by all data sources.
"""
        if db is None:
            db = []

        kw = {}
        if db:
            kw['db'] = '|'.join(db)
        return self._connection.get(_path('hash_search', h, **kw))

    def list_data_sources(self):
        """Return the hash search data sources available."""
        return self._connection.get(_path('hash_search/list_data_sources'))


class Ingest(object):
    def __init__(self, connection):
        self._connection = connection

    def __call__(
        self, path, alert=False, contents=None, metadata=None,
        nq=None, nt=None, params=None, srv_spec=None,
        ingest_type='AL_CLIENT'  # pylint: disable=W0622
    ):
        """\
Submit a file to the ingestion queue.

Required:
path    : Path/name of file. (string)

Optional:
alert   : Create an alert if score above alert threshold. (boolean)
contents: File contents. (string)
metadata: Metadata to include with submission. (dict)
nq      : Notification queue name. (string)
nt      : Notification threshold. (integer-ish)
params  : Additional submission parameters. (dict)
srv_spec: Service-specific parameters. (dict)

If contents are provided, the path is used as metadata only.
"""
        if contents is None:
            with open(path, 'rb') as f:
                contents = f.read()
        request = {
            'binary': b64encode(contents).decode('ascii'),
            'name': basename(path),
            'metadata': {'filename': path},
            'type': ingest_type,
        }

        if alert:
            request['generate_alert'] = alert
        if metadata:
            request['metadata'].update(metadata)
        if nq:
            request['notification_queue'] = nq
        if nt:
            request['notification_threshold'] = str(nt)
        if params:
            request['params'] = params
        if srv_spec:
            request['srv_spec'] = srv_spec

        return self._connection.post(_path('ingest'), data=dumps(request))

    def get_message_list(self, nq):
        """\
Return messages from the given notification queue.

Required:
nq      : Notification queue name. (string)

Throws a Client exception if the watch queue does not exist.
"""
        return self._connection.get(_magic_path(self, nq))


class Live(object):
    def __init__(self, connection):
        self._connection = connection

    def get_message_list(self, wq):
        """\
Return messages from the given watch queue.

Required:
wq      : Watch queue name. (string)

Throws a Client exception if the watch queue does not exist.
"""
        return self._connection.get(_magic_path(self, wq))

    def setup_watch_queue(self, sid):
        """\
Set up a watch queue for the submission with the given sid.

Required:
sid     : Submission ID. (string)

Throws a Client exception if the submission does not exist.
"""
        return self._connection.get(_magic_path(self, sid))


class Search(object):
    def __init__(self, connection):
        self._connection = connection
        self.stream = Stream(connection, self._do_search)

    def _do_search(self, bucket, query, *args, **kwargs):
        if bucket not in SEARCHABLE:
            raise ClientError("Bucket %s is not searchable" % bucket, 0)

        args = [('df', 'text')] + list(args) + list(kwargs.items())
        params = _join_params(query, args)
        path = '?q='.join((_path('search/advanced', bucket), params)) 
        return self._connection.get(path)

    def alert(self, query, *args, **kwargs):
        """\
Search alerts with a SOLR query.

Required:
query   : SOLR query. (string)

SOLR parameters can be passed as key/value tuples or keyword parameters.

Returns all results.
"""
        return self._do_search('alert', query, *args, **kwargs)

    def file(self, query, *args, **kwargs):
        """\
Search files with a SOLR query.

Required:
query   : SOLR query. (string)

SOLR parameters can be passed as key/value tuples or keyword parameters.

Returns all results.
"""
        return self._do_search('file', query, *args, **kwargs)

    def result(self, query, *args, **kwargs):
        """\
Search results with a SOLR query.

Required:
query   : SOLR query. (string)

SOLR parameters can be passed as key/value tuples or keyword parameters.

Returns all results.
"""
        return self._do_search('result', query, *args, **kwargs)

    def signature(self, query, *args, **kwargs):
        """\
Search signatures with a SOLR query.

Required:
query   : SOLR query. (string)

SOLR parameters can be passed as key/value tuples or keyword parameters.

Returns all results.
"""
        return self._do_search('signature', query, *args, **kwargs)

    def submission(self, query, *args, **kwargs):
        """\
Search submissions with a SOLR query.

Required:
query   : SOLR query. (string)

SOLR parameters can be passed as key/value tuples or keyword parameters.

Returns all results.
"""
        return self._do_search('submission', query, *args, **kwargs)


# noinspection PyUnusedLocal
class Service(object):
    def __init__(self, connection):
        self._connection = connection

    def error(self, key):
        """\
Return the error with the given key.

Required:
key     : Error key.

Throws a Client exception if the error does not exist.
"""
        return self._connection.get(_magic_path(self, key))

    def result(self, key):
        """\
Return the result with the given key.

Required:
key     : Result key.

Throws a Client exception if the error does not exist.
"""
        return self._connection.get(_magic_path(self, key))

    def multiple(self, error=None, result=None):
        """\
Get multiple result and error keys at the same time.

Optional:
error   : List of error keys. (list of strings).
result  : List of result keys. (list of strings).
"""
        if result is None:
            result = []  # pylint: disable=W0613
        if error is None:
            error = []  # pylint: disable=W0613
        data = dumps(_kw('self'))
        return self._connection.post(_magic_path(self, 'keys'), data=data)


# noinspection PyUnusedLocal
class Signature(object):
    def __init__(self, connection):
        self._connection = connection

    def __call__(self, sid, rev):
        """\
Return the signature with the given ID and revision.

Required:
sid     : Signature ID. (string)
rev     : Signature revision. (string)

Throws a Client exception if the signature does not exist.
"""
        return self._connection.get(_path('signature', sid, rev))

    def download(self, output=None, query=None, safe=True):  # pylint: disable=W0613
        """\
Download the signatures. Defaults to all if no query is provided.

Optional:
output  : Path or file handle. (string or file-like object)
query   : SOLR query. (string)
safe    : Ensure signatures can be compiled. (boolean)

If output is not specified the content is returned.
"""
        path = _magic_path(self, **_kw('output', 'self'))
        if output:
            return self._connection.download(path, _stream(output))
        return self._connection.download(path, _raw)

    def update_available(self, since=''):
        """\
Check if updated signatures are available.

Optional:
since   : ISO 8601 date (%Y-%m-%dT%H:%M:%S). (string)
"""
        return self._connection.get(_magic_path(self, last_update=since))


# noinspection PyBroadException
class SocketIO(object):
    def __init__(self, connection):
        class TerminateLogHandler(logging.StreamHandler):
            def __init__(self):
                super(TerminateLogHandler, self).__init__(stream=None)
                self._sio = None

            def emit(self, _):
                # noinspection PyBroadException
                try:
                    self._sio.disconnect()
                except Exception:
                    pass

            def set_sio(self, sio):
                self._sio = sio

        try:
            self._port = int(connection.server.rsplit(":", 1)[1])
        except IndexError:
            self._port = None
        except ValueError:
            self._port = None

        if self._port:
            self._server = connection.server.rsplit(":", 1)[0]
        else:
            self._server = connection.server

        self._header = {"Cookie": "session=%s" % connection.session.cookies.get('session', None)}
        self._sio = None
        self._log = logging.getLogger('socketIO_client')
        self._log.setLevel(logging.WARNING)
        self._stop_on_warning = TerminateLogHandler()
        self._log.addHandler(self._stop_on_warning)

    # noinspection PyUnusedLocal
    def _stop_callback(self, data):
        try:
            self._sio.disconnect()
        except Exception:
            pass

    def _error_callback(self, data):
        try:
            self._sio.disconnect()
        except Exception:
            pass

        raise ClientError(data['err_msg'], data['status_code'])

    def listen_on_alerts_created(self, alert_callback):
        """\
Listen to the various alerts created messages in the system and call the callback for each alerts

Required:
    alert_callback : Callback function for when alerts created messages are received

This function wait indefinitely and calls the appropriate callback for each messages returned
"""
        self._sio = socketIO_client.SocketIO(self._server, port=self._port, headers=self._header, verify=False)
        self._stop_on_warning.set_sio(self._sio)

        self._sio.on("AlertCreated", alert_callback)

        self._sio.emit('alert', {"status": "start", "client": "assemblyline_client"})
        self._sio.wait()

    def listen_on_dashboard_messages(self, dispatcher_msg_callback=None,
                                     ingest_msg_callback=None, service_msg_callback=None):
        """\
Listen to the various messages you would find on the UI dashboard.

Required (one of):
    dispatcher_msg_callback :   Callback function when a dispatcher message is received
    ingest_msg_callback :       Callback function when a ingest message is received
    service_msg_callback :      Callback function when a service message is received

This function wait indefinitely and calls the appropriate callback for each messages returned
"""
        if dispatcher_msg_callback is None and ingest_msg_callback is None and service_msg_callback is None:
            raise ClientError("At least one of the callbacks needs to be defined...", 400)

        self._sio = socketIO_client.SocketIO(self._server, port=self._port, headers=self._header, verify=False)
        self._stop_on_warning.set_sio(self._sio)

        if dispatcher_msg_callback:
            self._sio.on("DispHeartbeat", dispatcher_msg_callback)
        if ingest_msg_callback:
            self._sio.on("IngestHeartbeat", ingest_msg_callback)
        if service_msg_callback:
            self._sio.on("SvcHeartbeat", service_msg_callback)

        self._sio.emit('monitor', {"status": "start", "client": "assemblyline_client"})
        self._sio.wait()

    def listen_on_watch_queue(self, wq, result_callback=None, error_callback=None):
        """\
Listen to the various messages of a currently running submission's watch queue

Required:
    wq :              ID of the watch queue to listen for
    result_callback : Callback function when receiveing a result cache key
    error_callback :  Callback function when receiveing a error cache key

This function wait indefinitely and calls the appropriate callback for each messages returned
"""
        if result_callback is None and error_callback is None:
            raise ClientError("At least one of the callbacks needs to be defined...", 400)

        self._sio = socketIO_client.SocketIO(self._server, port=self._port, headers=self._header, verify=False)
        self._stop_on_warning.set_sio(self._sio)

        if result_callback:
            self._sio.on("cachekey", result_callback)
        if error_callback:
            self._sio.on("cachekeyerr", error_callback)

        self._sio.on("stop", self._stop_callback)
        self._sio.on("error", self._error_callback)

        self._sio.emit('listen', {"status": "start", "client": "assemblyline_client", "wq_id": wq, 'from_start': True})
        self._sio.wait()

    def listen_on_submissions_ingested(self, submission_callback):
        """\
Listen to the various submission ingested messages in the system and call the callback for each of them

Required:
    submission_callback : Callback function for when submission ingested messages are received

This function wait indefinitely and calls the appropriate callback for each messages returned
"""
        self._sio = socketIO_client.SocketIO(self._server, port=self._port, headers=self._header, verify=False)
        self._stop_on_warning.set_sio(self._sio)

        self._sio.on("SubmissionIngested", submission_callback)

        self._sio.emit('submission', {"status": "start", "client": "assemblyline_client"})
        self._sio.wait()


class Stream(object):
    def __init__(self, connection, do_search):
        self._connection = connection
        self._do_search = do_search
        self._page_size = 500
        self._max_yield_cache = 50000

    def _auto_fill(self, items, lock, bucket, query, *args, **kwargs):
        done = False
        args = list(args)
        while not done:
            skip = False
            with lock:
                if len(items) > self._max_yield_cache:
                    skip = True

            if skip:
                time.sleep(0.01)
                continue

            j = self._do_search(bucket, query, *args, **kwargs)

            # Replace cursorMark.
            args = args[:-1]
            args.append(('cursorMark', j.get('nextCursorMark', '*')))

            with lock:
                items.extend(j['response']['docs'])

            done = self._page_size - len(j['response']['docs'])

    def _do_stream(self, bucket, query, *args, **kwargs):
        if bucket not in SEARCHABLE:
            raise ClientError("Bucket %s is not searchable" % bucket, 0)

        for arg in list(args) + list(kwargs.items()):
            if arg[0] in INVALID_STREAM_SEARCH_PARAMS:
                raise ClientError(
                    "The following parameters cannot be used with stream search: %s",
                    ", ".join(INVALID_STREAM_SEARCH_PARAMS)
                )

        args = list(args) + [
            ('sort', '_yz_id asc'),
            ('rows', str(self._page_size)),
            ('cursorMark', '*')
        ]

        yield_done = False
        items = []
        lock = threading.Lock()
        sf_t = threading.Thread(target=self._auto_fill, args=[items, lock, bucket, query] + args, kwargs=kwargs)
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

    def alert(self, query, *args, **kwargs):
        """\
Search alerts with a SOLR query.

Required:
query   : SOLR query. (string)

SOLR parameters can be passed as key/value tuples or keyword parameters.

Returns a generator that tranparently and efficiently pages through results.
"""
        return self._do_stream('alert', query, *args, **kwargs)

    def file(self, query, *args, **kwargs):
        """\
Search files with a SOLR query.

Required:
query   : SOLR query. (string)

SOLR parameters can be passed as key/value tuples or keyword parameters.

Returns a generator that tranparently and efficiently pages through results.
"""
        return self._do_stream('file', query, *args, **kwargs)

    def result(self, query, *args, **kwargs):
        """\
Search results with a SOLR query.

Required:
query   : SOLR query. (string)

SOLR parameters can be passed as key/value tuples or keyword parameters.

Returns a generator that tranparently and efficiently pages through results.
"""
        return self._do_stream('result', query, *args, **kwargs)

    def signature(self, query, *args, **kwargs):
        """\
Search signatures with a SOLR query.

Required:
query   : SOLR query. (string)

SOLR parameters can be passed as key/value tuples or keyword parameters.

Returns a generator that tranparently and efficiently pages through results.
"""
        return self._do_stream('signature', query, *args, **kwargs)

    def submission(self, query, *args, **kwargs):
        """\
Search submissions with a SOLR query.

Required:
query   : SOLR query. (string)

SOLR parameters can be passed as key/value tuples or keyword parameters.

Returns a generator that tranparently and efficiently pages through results.
"""
        return self._do_stream('submission', query, *args, **kwargs)


class Submission(object):
    def __init__(self, connection):
        self._connection = connection

    def __call__(self, sid):
        """\
Return the submission record for the given sid.

Required:
sid     : Submission ID. (string)

Throws a Client exception if the submission does not exist.
"""
        return self._connection.get(_path('submission', sid))

    def delete(self, sid):
        """\
Delete the submission and related records for the given sid.

Required:
sid     : Submission ID. (string)

Throws a Client exception if the submission does not exist.
"""
        return self._connection.delete(_path('submission', sid))

    def file(self, sid, srl, results=None, errors=None):
        """\
Return all errors and results for a file as part of a specific submission.

Required:
sid     : Submission ID. (string)
srl     : File key. (string)

Optional:
resuls  : Also include results with the given result keys. (list of strings)
errors  : Also include errors with the given error keys. (list of strings)

Throws a Client exception if the submission and/or file does not exist.
"""
        kw = {}
        if errors:
            kw['extra_error_keys'] = errors
        if results:
            kw['extra_result_keys'] = results

        path = _path('submission', sid, 'file', srl)
        if kw:
            return self._connection.post(path, data=dumps(kw))
        else:
            return self._connection.get(path)

    def full(self, sid):
        """\
Return the full result for the given submission.

Required:
sid     : Submission ID. (string)

Throws a Client exception if the submission does not exist.
"""
        return self._connection.get(_magic_path(self, sid))

    def is_completed(self, sid):
        """\
Check if the submission with the given sid is completed.

Required:
sid     : Submission ID. (string)

Returns True/False.

Throws a Client exception if the submission does not exist.
"""
        return self._connection.get(_magic_path(self, sid))

    def summary(self, sid):
        """\
Return the executive summary for the submission with the given sid.

Required:
sid     : Submission ID. (string)

Throws a Client exception if the submission does not exist.
"""
        return self._connection.get(_magic_path(self, sid))

    def tree(self, sid):
        """\
Return the file hierarchy for the submission with the given sid.

Required:
sid     : Submission ID. (string)

Throws a Client exception if the submission does not exist.
"""
        return self._connection.get(_magic_path(self, sid))


class Submit(object):
    def __init__(self, connection):
        self._connection = connection

    def __call__(self, path, contents=None, params=None):
        """\
Submit a file to be dispatched.

Required:
path    : Path/name of file. (string)

Optional:
contents: File contents. (string)
params  : Additional submission parameters. (dict)

If contents are provided, the path is used as metadata only.
"""
        if contents is None:
            with open(path, 'rb') as f:
                contents = f.read()
        request = {
            'binary': b64encode(contents).decode('ascii'),
            'name': basename(path),
        }

        if params:
            request['params'] = params

        return self._connection.post(_path('submit'), data=dumps(request))

    def checkexists(self, *srls):
        """For internal use."""
        return self._connection.post(_magic_path(self), data=dumps(srls))

    def identify(self, data_block):
        """For internal use."""
        return self._connection.post(_magic_path(self), data=dumps(data_block))

    def presubmit(self, data_block):
        """For internal use."""
        return self._connection.post(_magic_path(self), data=dumps(data_block))

    def start(self, data_block):
        """For internal use."""
        return self._connection.post(_magic_path(self), data=dumps(data_block))


class User(object):
    def __init__(self, connection):
        self._connection = connection

    def __call__(self, username):
        """\
Return the settings for the given username.

Required:
username: User key. (string).

Throws a Client exception if the submission does not exist.
"""
        return self._connection.get(_path('user', username))

    def submission_params(self, username):
        """\
Return the submission parameters for the given username.

Required:
username: User key. (string).

Throws a Client exception if the submission does not exist.
"""
        return self._connection.get(_magic_path(self, username))
