""" Kaspersky AntiVirus Scanning Service.

    This service interfaces with Kaspersky AntiVirus for Proxy via ICAP.

    If was tested against:
        Kaspersky Antivirus for Proxy v5.5

    Dependencies:
       You must have a Kaspersky AV for Proxy running on the local network.

"""
from assemblyline.al.common.av_result import VirusHitTag, VirusHitSection
from assemblyline.al.common.result import Result, SCORE
from assemblyline.al.service.base import ServiceBase
from assemblyline.common import icap


class KasperskyIcapClient(icap.IcapClient):
    """
    Kaspersky flavoured ICAP Client.

    Implemented against Kaspersky Anti-Virus for Proxy 5.5.
    """

    def __init__(self, host, port):
        super(KasperskyIcapClient, self).__init__(host, port)

    def get_service_version(self):
        version = 'unknown'
        options_result = self.options_respmod()
        for line in options_result.splitlines():
            if line.startswith('Service:'):
                version = line[line.index(':')+1:].strip()
                break
        return version


class KasperskyIcap(ServiceBase):
    SERVICE_CATEGORY = 'Antivirus'
    SERVICE_DESCRIPTION = "This services wraps Kaspersky ICAP Proxy."
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
        super(KasperskyIcap, self).__init__(cfg)
        self.icap_host = None
        self.icap_port = None
        self.kaspersy_version = None
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

    def get_kaspersky_version(self):
        av_info = 'Kaspersky Antivirus for Proxy 5.5'
        defs = self.result_store.get_blob("kaspersky_update_definition")
        if defs:
            return "%s - Defs %s" % (av_info, defs.replace(".zip", "").replace("Updates", ""))
        return av_info

    def get_tool_version(self):
        return self._av_info

    def icap_to_alresult(self, icap_result):
        x_response_info = None
        x_virus_id = None
        result_lines = icap_result.strip().splitlines()
        if not len(result_lines) > 3:
            raise Exception('Invalid result from Kaspersky ICAP server: %s' % str(icap_result))

        xri_key = 'X-Response-Info:'
        xvirus_key = 'X-Virus-ID:'
        for line in result_lines:
            if line.startswith(xri_key):
                x_response_info = line[len(xri_key):].strip()
            elif line.startswith(xvirus_key):
                x_virus_id = line[len(xvirus_key):].strip()

        result = Result()
        # Virus hits should have XRI of 'blocked' and XVIRUS containing the virus information.
        # Virus misses should have XRI of 'passed' and no XVIRUS section
        if x_virus_id:
            if not x_response_info == 'blocked':
                self.log.warn('found virus id but response was: %s', str(x_response_info))
            virus_name = x_virus_id.replace('INFECTED ', '')
            result.add_section(VirusHitSection(virus_name, SCORE.SURE))
            result.append_tag(VirusHitTag(virus_name))
            
        return result

    def start(self):
        self.icap_host = self.cfg.get('ICAP_HOST')
        self.icap_port = int(self.cfg.get('ICAP_PORT'))
        self.icap = KasperskyIcapClient(self.icap_host, self.icap_port)
        self._av_info = self.get_kaspersky_version()
