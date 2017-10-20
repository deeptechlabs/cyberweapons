import logging
import os
import pprint
import tempfile

from urlparse import urlparse, parse_qs
from urllib import unquote

from assemblyline.common.exceptions import get_stacktrace_info
from assemblyline.common.net import get_hostip, get_hostname
from assemblyline.al.common import forge
from assemblyline.al.common.transport.local import TransportLocal

config = forge.get_config()


class FileStoreException(Exception):
    pass


class CorruptedFileStoreException(Exception):
    pass


def create_transport(url):
    """
    Transport are being initiated using an URL. They follow the normal url format:
    ftp://user:pass@host.com/path/to/file

    In this example, it will extract the following parameters:
    scheme: ftp
    host: host.com
    user: user
    password: pass

    Certain transports can have extra parameters, those parameters need to be specified in the query part of the url.
    e.g.: sftp://host.com/path/to/file?private_key=/etc/ssl/pkey&private_key_pass=pass&validate_host=true
    scheme: ftp
    host: host.com
    user:
    password:
    private_key: /etc/ssl/pkey
    private_key_pass: pass
    validate_host: True

    NOTE: For transport with extra parameters, only specific extra parameters are allow. This is the list of extra
          parameter allowed:

          ftp: None
          http: pki (string)
          sftp: private_key (string), private_key_pass (string), validate_host (bool)
          file: None
    """

    parsed = urlparse(url)

    base = parsed.path or '/'
    host = parsed.hostname
    if parsed.password:
        password = unquote(parsed.password)
    else:
        password = ''
    user = parsed.username or ''

    scheme = parsed.scheme.lower()
    if (scheme == 'ftp' or scheme == 'sftp' or scheme == 'http') and (host == get_hostname() or host == get_hostip()):
        scheme = 'file'

    if scheme == 'ftp':
        from assemblyline.al.common.transport.ftp import TransportFTP
        base = base.replace(config.filestore.ftp_root, "")
        t = TransportFTP(base=base, host=host, password=password, user=user)
    elif scheme == "sftp":
        from assemblyline.al.common.transport.sftp import TransportSFTP

        def get_extras(parsed_dict):
            valid_str_keys = ['private_key', 'private_key_pass']
            valid_bool_keys = ['validate_host']

            out = {}
            for k, v in parsed_dict.iteritems():
                if k in valid_bool_keys:
                    if v[0].lower() == 'true':
                        out[k] = True
                    elif v[0].lower() == 'true':
                        out[k] = False
                if k in valid_str_keys:
                    out[k] = v[0]

            return out
        extras = get_extras(parse_qs(parsed.query))
        t = TransportSFTP(base=base, host=host, password=password, user=user, **extras)
    elif scheme == 'http':
        from assemblyline.al.common.transport.http import TransportHTTP

        def get_extras(parsed_dict):
            valid_str_keys = ['pki']

            out = {}
            for k, v in parsed_dict.iteritems():
                if k in valid_str_keys:
                    out[k] = v[0]

            return out

        extras = get_extras(parse_qs(parsed.query))
        t = TransportHTTP(base=base, host=host, password=password, user=user, **extras)

    elif scheme == 'file':
        t = TransportLocal(base=base)
    else:
        raise FileStoreException("Unknown transport: %s" % scheme)

    return t


class FileStore(object):
    def __init__(self, *transport_urls):
        self.log = logging.getLogger('assemblyline.transport')
        self.transports = [create_transport(url) for url in transport_urls]
        self.local_transports = [
            t for t in self.transports if isinstance(t, TransportLocal)
        ]

    def __enter__(self):
        return self

    # noinspection PyUnusedLocal
    def __exit__(self, ex_type, exc_val, exc_tb):
        self.close()

    def close(self):
        for t in self.transports:
            try:
                t.close()
            except Exception as ex: #pylint: disable=W0703
                trace = get_stacktrace_info(ex)
                self.log.warning('Transport problem: %s', trace)

    def delete(self, path, location='all'):
        for t in self.slice(location):
            try:
                t.delete(path)
            except Exception as ex: #pylint: disable=W0703
                trace = get_stacktrace_info(ex)
                self.log.info('Transport problem: %s', trace)

    def download(self, src_path, dest_path, location='any'):
        successful = False
        transports = []
        download_errors = []
        for t in self.slice(location):
            try:
                t.download(src_path, dest_path)
                transports.append(t)
                successful = True
                break
            except Exception as ex: #pylint: disable=W0703
                download_errors.append((str(t), get_stacktrace_info(ex)))

        if not successful:
            raise FileStoreException('No transport succeeded:\n%s' % pprint.pformat((download_errors)))
        return transports

    def exists(self, path, location='any'):
        transports = []
        for t in self.slice(location):
            try:
                if t.exists(path):
                    transports.append(t)
                    if location == 'any':
                        break
            except Exception as ex: #pylint: disable=W0703
                trace = get_stacktrace_info(ex)
                self.log.warning('Transport problem: %s', trace)
        return transports

    def get(self, path, location='any'):
        for t in self.slice(location):
            try:
                if t.exists(path):
                    return t.get(path)
            except Exception as ex: #pylint: disable=W0703
                trace = get_stacktrace_info(ex)
                self.log.warning('Transport problem: %s', trace)

    def local_path(self, path):
        if not self.local_transports:
            return None

        for t in self.local_transports:
            if t.exists(path):
                return t.normalize(path)

        temporary_path = tempfile.mktemp(prefix="filestore.local_path")
        try:
            self.download(path, temporary_path)
            self.put(temporary_path, path)
        finally:
            os.remove(temporary_path)

        for t in self.local_transports:
            if t.exists(path):
                return t.normalize(path)

        return None

    def put(self, src_path, dst_path, location='all'):
        transports = []
        for t in self.slice(location):
            if not t.exists(dst_path):
                transports.append(t)
                t.put(src_path, dst_path)
                if not t.exists(dst_path):
                    raise FileStoreException('File transfer failed. Remote file does not '
                                             'exist for %s on %s (%s)' % (dst_path, location, t))
        return transports

    def put_batch(self, local_remote_tuples, location='all'):
        failed_tuples = []
        for (src_path, dst_path) in local_remote_tuples:
            try:
                self.put(src_path, dst_path, location)
            except Exception as ex: #pylint: disable=W0703
                trace = get_stacktrace_info(ex)
                failed_tuples.append((src_path, dst_path, trace))
        return failed_tuples

    def slice(self, location):
        start, end = {
            'all': (0, len(self.transports)),
            'any': (0, len(self.transports)),
            'far': (-1, len(self.transports)),
            'near': (0, 1),
        }[location]
        
        transports = self.transports[start:end]
        assert(len(transports) >= 1)
        return transports

    def __str__(self):
        return ', '.join(str(t) for t in self.transports)
