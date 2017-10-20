import json
import time
import logging


from assemblyline.al.common.result import Result, ResultSection, Classification, SCORE, TEXT_FORMAT
from assemblyline.al.common.av_result import VirusHitTag
from assemblyline.al.service.base import ServiceBase
from assemblyline.common.exceptions import RecoverableError

log = logging.getLogger('assemblyline.svc.common.result')


class VTException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class AvHitSection(ResultSection):
    def __init__(self, av_name, virus_name, score):
        title = '%s identified the file as %s' % (av_name, virus_name)
        super(AvHitSection, self).__init__(
            title_text=title,
            score=score,
            classification=Classification.UNRESTRICTED)


class VirusTotalDynamic(ServiceBase):
    SERVICE_CATEGORY = "External"
    SERVICE_DESCRIPTION = "This service submits files/URLs to VirusTotal for analysis."
    SERVICE_ENABLED = False
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_STAGE = "CORE"
    SERVICE_TIMEOUT = 600
    SERVICE_IS_EXTERNAL = True
    SERVICE_DEFAULT_CONFIG = {
        'private_api': False,
        'API_KEY': '',
        'BASE_URL': 'https://www.virustotal.com/vtapi/v2/'
    }

    def __init__(self, cfg=None):
        super(VirusTotalDynamic, self).__init__(cfg)
        self.api_key = self.cfg.get('API_KEY')
        self.private_api = self.cfg.get('private_api')

    # noinspection PyGlobalUndefined,PyUnresolvedReferences
    def import_service_deps(self):
        global requests
        import requests

    def start(self):
        self.log.debug("VirusTotal service started")

    def execute(self, request):
        filename = request.download()
        response = self.scan_file(request, filename)
        result = self.parse_results(response)
        if self.private_api:
            # Call some private API functions
            pass

        request.result = result

    # noinspection PyUnusedLocal
    def scan_file(self, request, filename):

        # Let's scan the file
        url = self.cfg.get('BASE_URL') + "file/scan"
        try:
            f = open(filename, "rb")
        except:
            print "Could not open file"
            return {}

        files = {"file": f}
        values = {"apikey": self.api_key}
        r = requests.post(url, values, files=files)
        try:
            json_response = r.json()
        except ValueError:
            self.log.warn("Invalid response from VirusTotal, "
                          "HTTP code: %s, "
                          "content length: %i, "
                          "headers: %s" % (r.status_code, len(r.content), repr(r.headers)))
            if len(r.content) == 0:
                raise RecoverableError("VirusTotal didn't return a JSON object, HTTP code %s" % r.status_code)
            raise

        # File has been scanned, if response is successful, let's get the response

        if json_response is not None and json_response.get('response_code') <= 0:
            return json_response

        sha256 = json_response.get('sha256', 0)
        if not sha256:
            return json_response

        # Have to wait for the file scan to be available -- might take a few minutes...
        while True:
            url = self.cfg.get('BASE_URL') + "file/report"
            params = {'apikey': self.api_key, 'resource': sha256}
            r = requests.post(url, params)
            json_response = r.json()
            if 'scans' in json_response or json_response.get('response_code') <= 0:
                break
            # Limit is 4 public API calls per minute, make sure we don't exceed quota
            # time.sleep(20)
            time.sleep(20)

        return json_response

    def parse_results(self, response):
        res = Result()
        response = response.get('results', response)

        if response is not None and response.get('response_code') == 204:
            message = "You exceeded the public API request rate limit (4 requests of any nature per minute)"
            raise VTException(message)
        elif response is not None and response.get('response_code') == 203:
            message = "You tried to perform calls to functions for which you require a Private API key."
            raise VTException(message)
        elif response is not None and response.get('response_code') == 1:
            av_hits = ResultSection(title_text='Anti-Virus Detections')
            url_section = ResultSection(
                SCORE.NULL,
                'Virus total report permalink',
                self.SERVICE_CLASSIFICATION,
                body_format=TEXT_FORMAT.URL,
                body=json.dumps({"url": response.get('permalink')}))
            res.add_section(url_section)

            scans = response.get('scans', response)
            av_hits.add_line('Found %d AV hit(s) from %d scans.' % (response.get('positives'), response.get('total')))
            for majorkey, subdict in sorted(scans.iteritems()):
                if subdict['detected']:
                    virus_name = subdict['result']
                    res.append_tag(VirusHitTag(virus_name, context="scanner:%s" % majorkey))
                    av_hits.add_section(AvHitSection(majorkey, virus_name, SCORE.SURE))
            res.add_result(av_hits)

        return res
