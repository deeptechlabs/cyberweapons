from assemblyline.common.exceptions import ChainException


def normalize_srl_path(srl):
    if '/' in srl:
        return srl

    return '{0}/{1}/{2}/{3}/{4}'.format(srl[0], srl[1], srl[2], srl[3], srl)


class TransportException(ChainException):
    """
    FileTransport exception base class.
    
    TransportException is a subclass of ChainException so that it can be
    used with the Chain and ChainAll decorators.
    """
    pass


class Transport(object):
    """
    FileTransport base class.
    
    - Subclasses should override all methods.
    - Except as noted, FileTransport methods do not return value and raise
    - TransportException on failure.
    - Methods should only raise TransportExceptions. (The decorators
      Chain and ChainAll can be applied to a function/method and class,
      respectively, to ensure that any exceptions raised are converted to
      TransportExceptions.
    """
    
    def __init__(self, normalize=normalize_srl_path):
        self.normalize = normalize

    def close(self):
        pass
    
    def delete(self, path): # pylint:disable=W0613
        """
        Deletes the file.
        """
        raise TransportException("Not Implemented")
    
    def download(self, src_path, dst_path): # pylint:disable=W0613
        """
        Copies the content of src_path to the (likely) local file dst_path.
        """
        raise TransportException("Not Implemented")
    
    def exists(self, path): # pylint:disable=W0613
        """
        Returns True if the path exists, False otherwise.
        Should work with both files and directories.
        """
        raise TransportException("Not Implemented")
    
    def get(self, path): # pylint:disable=W0613
        """
        Returns the content of the file.
        """
        raise TransportException("Not Implemented")
        
    def makedirs(self, path): # pylint:disable=W0613
        """
        Like os.makedirs the super-mkdir, create the leaf directory path and
        any intermediate path segments.
        """
        raise TransportException("Not Implemented")
    
    def put(self, src_path, dst_path): # pylint:disable=W0613
        """
        Save src to dst, overwriting dst if it already exists.
        """
        raise TransportException("Not Implemented")

    def put_batch(self, local_remote_tuples): # pylint:disable=W0613
        """
        Transfer multiple files specified by list of (local, remote) tuples.
        Transports that can optimize batch file transfers should write a custom put_batch. 
        """
        failed_tuples = []
        for (src_path, dst_path) in local_remote_tuples:
            try:
                self.put(src_path, dst_path)
            except Exception as e: # pylint: disable=W0703
                failed_tuples.append((src_path, dst_path, str(e)))
        return failed_tuples

