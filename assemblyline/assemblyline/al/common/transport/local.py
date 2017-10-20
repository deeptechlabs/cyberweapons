import logging
import os
import shutil
import uuid

from assemblyline.common.exceptions import chainall
from assemblyline.al.common.transport.base import Transport, TransportException, normalize_srl_path


@chainall(TransportException)    
class TransportLocal(Transport):
    """
    Local file system Transport class.
    """
    
    def __init__(self, base=None, normalize=None):
        self.log = logging.getLogger('assemblyline.transport.local')
        self.base = base
        self.host = "localhost"
        
        def local_normalize(path):
            # If they've provided an absolute path. Leave it a is.
            if path.startswith('/'):
                s = path
            # Relative paths 
            elif '/' in path or len(path) != 64:
                s = _join(self.base, path)
            else:
                s = _join(self.base, normalize_srl_path(path))
            self.log.debug('local normalized: %s -> %s', path, s)
            return s

        if not normalize:
            normalize = local_normalize

        super(TransportLocal, self).__init__(normalize=normalize)
    
    def delete(self, path):
        path = self.normalize(path)
        os.unlink(path)  

    def download(self, src_path, dst_path):
        if src_path == dst_path:
            return 

        src_path = self.normalize(src_path)
        dir_path = os.path.dirname(dst_path)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
        shutil.copy(src_path, dst_path)
    
    def exists(self, path):
        path = self.normalize(path)
        return os.path.exists(path)

    # noinspection PyBroadException
    def get(self, path):
        path = self.normalize(path)
        fh = None
        try:
            fh = open(path, "rb")
            return fh.read()
        finally:
            try:
                fh.close()
            except:  # pylint: disable=W0702
                pass
    
    def getmtime(self, path):
        path = self.normalize(path)
        # noinspection PyBroadException
        try:
            return os.path.getmtime(path)
        except:  # pylint: disable=W0702
            return 0
    
    def makedirs(self, path):
        path = self.normalize(path)
        try:
            os.makedirs(path)
        except OSError as e:
            if e.errno == 17:
                pass
            else:
                raise e

    def put(self, src_path, dst_path):
        dst_path = self.normalize(dst_path)
        if src_path == dst_path:
            return

        dirname = os.path.dirname(dst_path)
        filename = os.path.basename(dst_path)
        tempname = uuid.uuid4().get_hex()
        temppath = _join(dirname, tempname)
        finalpath = _join(dirname, filename)
        assert(finalpath == dst_path)
        self.makedirs(dirname)
        shutil.copy(src_path, temppath)
        shutil.move(temppath, finalpath)
        assert(self.exists(dst_path))
    
    def save(self, path, content):
        path = self.normalize(path)

        dirname = os.path.dirname(path)
        filename = os.path.basename(path)

        tempname = uuid.uuid4().get_hex()
        temppath = _join(dirname, tempname)

        finalpath = _join(dirname, filename)
        assert(finalpath == path)

        self.makedirs(dirname)
        fh = None
        try:
            fh = open(temppath, "wb")
            return fh.write(content)
        finally:
            # noinspection PyBroadException
            try:
                fh.close()
            except:  # pylint: disable=W0702
                pass

            try:
                shutil.move(temppath, finalpath)
            except:  # pylint: disable=W0702
                pass
            assert(self.exists(path))
    
    def __str__(self):
        return '{0}:{1}'.format(self.__class__.__name__, self.base)

###############################
# Helper functions.
###############################


def _join(base, path):
    path = path.replace("\\", "/").replace("//", "/")
    if base is None:
        return path
    return os.path.join(base, path.lstrip("/")).replace("\\", "/")
