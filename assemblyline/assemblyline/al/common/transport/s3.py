import logging
import os
import tempfile

import boto3
import botocore

from assemblyline.common.exceptions import chainall
from assemblyline.al.common.transport.base import Transport, TransportException

# noinspection PyBroadException
try:
    botocore.vendored.requests.packages.urllib3.disable_warnings()
except:
    pass

"""
This class assumes a flat file structure in the S3 bucket.  This is due to the way the AL datastore currently handles
file paths for local/ftp datastores not playing nicely with s3 constraints.
"""


@chainall(TransportException)
class TransportS3(Transport):
    DEFAULT_HOST = "s3.amazonaws.com"

    def __init__(self, base=None, accesskey=None, secretkey=None, aws_region=None, s3_bucket=None,
                 host=None, port=None, use_ssl=None, verify=False):
        self.log = logging.getLogger('assemblyline.transport.local')
        self.base = base
        self.bucket = s3_bucket

        if use_ssl is None:
            self.use_ssl = True
        else:
            self.use_ssl = use_ssl

        if host is None:
            self.host = self.DEFAULT_HOST
        else:
            self.host = host

        if port is None:
            self.port = {True: 443, False: 80}[self.use_ssl]
        else:
            self.port = port

        self.scheme = {True: "https", False: "http"}[self.use_ssl]

        self.endpoint_url = "{scheme}://{host}:{port}".format(scheme=self.scheme, host=self.host, port=self.port)

        self.client = boto3.client(
            "s3",
            aws_access_key_id=accesskey,
            aws_secret_access_key=secretkey,
            endpoint_url=self.endpoint_url,
            region_name=aws_region,
            use_ssl=self.use_ssl,
            verify=verify
        )

        def s3_normalize(path):
            # flatten path to just the basename
            return os.path.basename(path)

        super(TransportS3, self).__init__(normalize=s3_normalize)

    def delete(self, path):
        key = self.normalize(path)
        self.client.delete_object(self.bucket, key)

    def download(self, src_path, dst_path):
        key = self.normalize(src_path)
        dir_path = os.path.dirname(dst_path)
        # create dst_path if it doesn't exist
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
        # download the key from s3
        self.client.download_file(self.bucket, key, dst_path)

    def exists(self, path):
        # checks to see if KEY exists
        key = self.normalize(path)
        self.log.debug('Checking for existence of %s', key)
        size = None
        try:
            self.client.head_object(self.bucket, key)
        except botocore.exceptions.ClientError:
            return False

        return True

    def get(self, path):
        dst_path = tempfile.mktemp(prefix="s3_transport.", suffix=".download")
        self.download(path, dst_path)
        with open(dst_path) as downloaded:
            return downloaded.read()

    def makedirs(self, path):
        # Does not need to do anything as s3 has a flat layout.
        pass

    def upload(self, path):
        key = self.normalize(path)
        # if file exists already, it will be overwritten
        self.client.upload_file(path, self.bucket, key)
