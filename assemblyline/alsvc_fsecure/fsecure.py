""" FSecure AntiVirus Scanning Service.

    This service interfaces with FSecure Internet Gatekeeper 5 via ICAP.
"""

from assemblyline.al.common.av_result import VirusHitTag, VirusHitSection
from assemblyline.al.common.result import Result, SCORE
from assemblyline.al.service.base import ServiceBase
from assemblyline.common import icap


class FSecureIcapClient(icap.IcapClient):
    def __init__(self, host, port):
        super(FSecureIcapClient, self).__init__(host, port)

    def get_service_version(self):
        version = 'unknown'
        scan_result = self.scan_data('cleandata')
        for line in scan_result.splitlines():
            if line.startswith('ISTag:'):
                version = line.split(':')[1].strip('" ')
                break
        return version


class FSecure(ServiceBase):
    SERVICE_CATEGORY = 'Antivirus'
    SERVICE_DESCRIPTION = "This services wraps FSecure ICAP Proxy."
    SERVICE_ENABLED = True
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_DEFAULT_CONFIG = {
        "ICAP_HOST": "localhost",
        "ICAP_PORT": 1344,
    }
    SERVICE_CPU_CORES = 0.3
    SERVICE_RAM_MB = 128

    def __init__(self, cfg=None):
        super(FSecure, self).__init__(cfg)
        self.icap_host = None
        self.icap_port = None
        self.fsecure_version = None
        self.icap = None
        self._av_info = ''

    def execute(self, request):
        payload = request.get()
        icap_result = self.icap.scan_data(payload)
        request.result = self.icap_to_alresult(icap_result)
        request.task.report_service_context(self._av_info)

        # if deepscan request include the ICAP HTTP in debug info.
        if request.task.deep_scan:
            request.task.service_debug_info = icap_result

    def get_tool_version(self):
        return self._av_info

    def icap_to_alresult(self, icap_result):
        infection_type = ''
        infection_name = ''
        result_lines = icap_result.strip().splitlines()
        if not len(result_lines) > 3:
            raise Exception('Invalid result from FSecure ICAP server: %s' % str(icap_result))

        x_scan_result = 'X-FSecure-Scan-Result:'
        x_infection_name = 'X-FSecure-Infection-Name:'
        istag = 'ISTag:'

        for line in result_lines:
            if line.startswith(x_scan_result):
                infection_type = line[len(x_scan_result):].strip()
            elif line.startswith(x_infection_name):
                infection_name = line[len(x_infection_name):].strip().strip('"')
            elif line.startswith(istag):
                version_info = line[len(istag):].strip()
                self._set_av_ver(version_info)

        result = Result()
        if infection_name:
            result.add_section(VirusHitSection(infection_name, SCORE.SURE, detection_type=infection_type))
            result.append_tag(VirusHitTag(infection_name))
            
        return result

    def _set_av_ver(self, dbver):
        self._av_info = 'FSecure Internet Linux 5. [%s]' % dbver.strip('"')

    def start(self):
        self.icap_host = self.cfg.get('ICAP_HOST')
        self.icap_port = int(self.cfg.get('ICAP_PORT'))
        self.icap = FSecureIcapClient(self.icap_host, self.icap_port)
        self._set_av_ver(self.icap.get_service_version())

SAMPLE_HIT = """
ICAP/1.0 200 OK
Server: F-Secure ICAP Server
ISTag: "FSAV-2015-08-18_06"
Connection: keep-alive
Expires: Tue, 18 Aug 2015 21:19:11 GMT
X-FSecure-Scan-Result: infected
X-FSecure-Infection-Name: "Exploit.D-Encrypted.Gen"
X-FSecure-FSAV-Duration: 0.039812
X-FSecure-Transaction-Duration: 0.064285
Encapsulated: res-hdr=0, res-body=73
"""

if __name__ == '__main__':
    import pprint
    import logging
    import sys
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    k = FSecure()
    pprint.pprint(k.icap_to_alresult(SAMPLE_HIT))
    pprint.pprint(k.get_tool_version())
