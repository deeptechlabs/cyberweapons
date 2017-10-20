import ftplib
import logging
import os
import posixpath
import uuid

from io import BytesIO

from assemblyline.common.exceptions import chainall, get_stacktrace_info
from assemblyline.common.path import splitpath
from assemblyline.al.common.transport.base import Transport, TransportException, normalize_srl_path


def reconnect_retry_on_fail(func):
    def new_func(self, *args, **kwargs):
        try:
            if not self.ftp:
                self.ftp = ftplib.FTP(self.host, self.user, self.password)
                try:
                    self.ftp.voidcmd('site umask 002')
                except: # pylint: disable=W0702
                    pass

            return func(self, *args, **kwargs)
        except: # pylint: disable=W0702
            pass

        # The previous attempt at calling original func failed.
        # Reset the connection and try again (one time).
        try:
            if self.ftp:
                self.ftp.close()   # Just best effort.
        except: # pylint: disable=W0702
            pass

        # The original func will reconnect automatically.
        self.ftp = ftplib.FTP(self.host, self.user, self.password)
        try:
            self.ftp.voidcmd('site umask 002')
        except: # pylint: disable=W0702
            pass
        return func(self, *args, **kwargs)

    new_func.__name__ = func.__name__
    new_func.__doc__ = func.__doc__
    return new_func


@chainall(TransportException)    
class TransportFTP(Transport):
    """
    FTP Transport class.
    """
    def __init__(self, base=None, host=None, password=None, user=None):
        self.log = logging.getLogger('assemblyline.transport.ftp')
        self.base = base
        self.ftp = None
        self.host = host
        self.password = password
        self.user = user

        def ftp_normalize(path):
            # If they've provided an absolute path. Leave it a is.
            s = ''
            if path.startswith('/'):
                s = path
            # Relative paths 
            elif '/' in path or len(path) != 64:
                s = posixpath.join(self.base, path)
            else:
                s = posixpath.join(self.base, normalize_srl_path(path))  
            self.log.debug('ftp normalized: %s -> %s', path, s)
            return s

        super(TransportFTP, self).__init__(normalize=ftp_normalize)

    def __str__(self):
        return 'Ftp:{}@{}'.format(self.user, self.host)
        
    def close(self):
        if self.ftp:
            self.ftp.close()

    @reconnect_retry_on_fail
    def delete(self, path):
        path = self.normalize(path)
        self.ftp.delete(path)

    @reconnect_retry_on_fail
    def download(self, src_path, dst_path):
        dir_path = os.path.dirname(dst_path)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
        with open(dst_path, 'wb') as localfile:
            src_path = self.normalize(src_path)
            self.ftp.retrbinary('RETR ' + src_path, localfile.write)
        
    @reconnect_retry_on_fail
    def exists(self, path):
        path = self.normalize(path)
        self.log.debug('Checking for existence of %s', path)
        size = None
        try:
            size = self.ftp.size(path)
        except ftplib.error_perm as e:
            trace = get_stacktrace_info(e)
            # If the file doesnt exist we get a 550.
            if not e.message.startswith('550'):  # pylint:disable=E1101
                raise
        return size is not None
        
    @reconnect_retry_on_fail
    def get(self, path):
        path = self.normalize(path)
        bio = BytesIO()
        self.ftp.retrbinary('RETR ' + path, bio.write)
        return bio.getvalue()
    
    @reconnect_retry_on_fail
    def makedirs(self, path):
        self.log.debug("making dirs: %s", path)
        subdirs = splitpath(path, '/')
        for i in range(len(subdirs)):
            try:
                d = posixpath.sep + posixpath.join(*subdirs[:i+1])
                self.ftp.mkd(d)
            except: # pylint: disable=W0702
                pass

    @reconnect_retry_on_fail
    def put(self, src_path, dst_path):
        dst_path = self.normalize(dst_path)
        dirname = posixpath.dirname(dst_path)
        filename = posixpath.basename(dst_path)
        tempname = uuid.uuid4().get_hex()
        temppath = posixpath.join(dirname, tempname)
        finalpath = posixpath.join(dirname, filename)
        assert(finalpath == dst_path)
        self.makedirs(dirname)
        with open(src_path, 'rb') as localfile:
            self.log.debug("Storing: %s", temppath)
            self.ftp.storbinary('STOR ' + temppath, localfile)
        self.log.debug("Rename: %s -> %s", temppath, finalpath)
        self.ftp.rename(temppath, finalpath)
        assert(self.exists(dst_path))

    @reconnect_retry_on_fail
    def put_batch(self, local_remote_tuples):
        return super(TransportFTP, self).put_batch(local_remote_tuples)

