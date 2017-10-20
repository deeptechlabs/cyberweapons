import logging
import os
import posixpath

from assemblyline.common.exceptions import chainall
from assemblyline.al.common.transport.base import Transport, TransportException, normalize_srl_path


@chainall(TransportException)
class TransportHTTP(Transport):
    """
    HTTP Transport class.
    """
    def __init__(self, base=None, host=None, password=None, user=None, pki=None):
        import requests
        self.log = logging.getLogger('assemblyline.transport.http')
        self.base = base
        self.host = host
        self.password = password
        self.user = user
        self.pki = pki
        if user and password:
            self.auth = (user, password)
        else:
            self.auth = None

        def http_normalize(path):
            if '/' in path or len(path) != 64:
                s = posixpath.join(self.base, path)
            else:
                s = posixpath.join(self.base, normalize_srl_path(path))  
            return "{scheme}://{host}{path}".format(scheme="http", host=host, path=s)

        self.session = requests.Session()

        super(TransportHTTP, self).__init__(normalize=http_normalize)

    def __str__(self):
        return 'http:{}@{}'.format(self.user, self.host)
        
    def close(self):
        if self.session:
            self.session.close()

    def delete(self, path):
        raise TransportException("READ ONLY TRANSPORT: Method not implemented")

    def download(self, src_path, dst_path):
        dir_path = os.path.dirname(dst_path)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
        with open(dst_path, 'wb') as localfile:
            src_path = self.normalize(src_path)
            resp = self.session.get(src_path, auth=self.auth, cert=self.pki)
            if resp.ok:
                for chunk in resp.iter_content(chunk_size=1024):
                    if chunk:
                        localfile.write(chunk)
            else:
                raise TransportException("[%s] %s: %s" % (resp.status_code, resp.reason, src_path))
        
    def exists(self, path):
        path = self.normalize(path)
        resp = self.session.head(path, auth=self.auth, cert=self.pki)
        return resp.ok

    def get(self, path):
        path = self.normalize(path)
        resp = self.session.get(path, auth=self.auth, cert=self.pki)
        if resp.ok:
            return resp.content
        else:
            raise TransportException("[%s] %s: %s" % (resp.status_code, resp.reason, path))

    def makedirs(self, path):
        raise TransportException("READ ONLY TRANSPORT: Method not implemented")

    def put(self, src_path, dst_path):
        raise TransportException("READ ONLY TRANSPORT: Method not implemented")

    def put_batch(self, local_remote_tuples):
        return super(TransportHTTP, self).put_batch(local_remote_tuples)
