import os
import subprocess

from collections import namedtuple

from assemblyline.al.common.result import Result, ResultSection
from assemblyline.al.common.result import SCORE
from assemblyline.al.service.base import ServiceBase

PACKER_UNKNOWN = 'unknown'
PACKER_UPX = 'upx'

UnpackResult = namedtuple('UnpackResult', ['ok', 'localpath', 'displayname', 'meta'])


class Unpacker(ServiceBase):
    SERVICE_ACCEPTS = 'executable/*'
    SERVICE_CATEGORY = "Static Analysis"
    SERVICE_DESCRIPTION = "This service unpacks UPX packed executables for further analysis."
    SERVICE_ENABLED = True
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_STAGE = 'SECONDARY'
    SERVICE_VERSION = '1'
    SERVICE_CPU_CORES = 0.5
    SERVICE_RAM_MB = 256

    SERVICE_DEFAULT_CONFIG = {
        'UPX_EXE': r'/usr/bin/upx',
    }

    def __init__(self, cfg=None):
        super(Unpacker, self).__init__(cfg)
        self.upx_exe = self.cfg.get('UPX_EXE')
        if not os.path.exists(self.upx_exe):
            raise Exception('UPX executable not found on system: %s', self.upx_exe)

    def execute(self, request):
        request.result = Result()
        uresult = self._unpack(request, ['upx'])
        if uresult.ok and uresult.localpath:
            request.add_extracted(uresult.localpath, 'Unpacked from %s' % request.srl, display_name=uresult.displayname)
            request.result.add_section(ResultSection(SCORE.NULL, "%s successfully unpacked!" %
                                                     (os.path.basename(uresult.displayname)),
                                       self.SERVICE_CLASSIFICATION))

    def _unpack_upx(self, packedfile, outputpath, displayname):
        # Test the file to see if UPX agrees with our identification.
        p = subprocess.Popen(
            (self.upx_exe, '-t', packedfile),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        (stdout, stderr) = p.communicate()

        if '[OK]' in stdout and 'Tested 1 file' in stdout:
            p = subprocess.Popen(
                (self.upx_exe, '-d', '-o', outputpath, packedfile),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            (stdout, stderr) = p.communicate()

            if 'Unpacked 1 file' in stdout:
                # successfully unpacked.
                return UnpackResult(True, outputpath, displayname, {'stdout': stdout[:1024]})
        else:
            self.log.info('UPX extractor said this file was not UPX packed:\n%s\n%s',
                          stdout[:1024], stderr[:1024])
        # UPX unpacking is failure prone due to the number of samples that are identified as UPX
        # but are really some minor variant. For that reason we can't really fail the result
        # every time upx has problems with a file.
        return UnpackResult(True, None, None, None)

    def _unpack(self, request, packer_names):
        for name in packer_names:
            if 'upx' in name.lower():
                packedfile = request.download()
                unpackedfile = packedfile + '.unUPX'
                displayname = os.path.basename(request.path) + '.unUPX'
                return self._unpack_upx(packedfile, unpackedfile, displayname)

        return UnpackResult(True, None, None, None)
