import json


from assemblyline.al.common.result import Result, ResultSection, Classification, SCORE, TEXT_FORMAT
from assemblyline.al.common.av_result import VirusHitTag
from assemblyline.al.service.base import ServiceBase
from assemblyline.common.exceptions import RecoverableError


class AvHitSection(ResultSection):
    def __init__(self, av_name, virus_name, score):
        title = '%s identified the file as %s' % (av_name, virus_name)
        super(AvHitSection, self).__init__(
            title_text=title,
            score=score,
            classification=Classification.UNRESTRICTED)


class VirusTotalStatic(ServiceBase):
    SERVICE_CATEGORY = "External"
    SERVICE_DESCRIPTION = "This service checks the file hash to see if there's an existing VirusTotal report."
    SERVICE_ENABLED = False
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_STAGE = "CORE"
    SERVICE_TIMEOUT = 60
    SERVICE_IS_EXTERNAL = True
    SERVICE_DEFAULT_CONFIG = {
        'API_KEY': '',
        'BASE_URL': 'https://www.virustotal.com/vtapi/v2/'
    }

    def __init__(self, cfg=None):
        super(VirusTotalStatic, self).__init__(cfg)
        self.api_key = self.cfg.get('API_KEY')

    # noinspection PyGlobalUndefined,PyUnresolvedReferences
    def import_service_deps(self):
        global requests
        import requests

    def start(self):
        self.log.debug("VirusTotalStatic service started")

    def execute(self, request):
        response = self.scan_file(request)
        result = self.parse_results(response)
        request.result = result

    def scan_file(self, request):

        # Check to see if the file has been seen before
        url = self.cfg.get('BASE_URL') + "file/report"
        params = {'apikey': self.api_key, 'resource': request.sha256}
        r = requests.post(url, params)
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
        return json_response

    def parse_results(self, response):
        res = Result()
        response = response.get('results', response)

        if response is not None and response.get('response_code') == 1:
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
