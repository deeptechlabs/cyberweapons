"""
Symantec Protection Engine for Cloud Services  - AntiVirus Service.
"""

import os
import random
import socket
import re
import time

from assemblyline.al.common.result import ResultSection
from assemblyline.al.common.av_result import VirusHitSection, VirusHitTag
from assemblyline.al.common.result import Result, SCORE, TAG_TYPE, TAG_SCORE
from assemblyline.al.service.base import ServiceBase
from assemblyline.common import icap

CONTAINER_ERRORS = ["Container size violation - scan incomplete.",
                    "Encrypted container deleted;",
                    "Malformed container violation"]


class SymantecIcapClient(icap.IcapClient):
    """
    Symantec flavoured ICAP Client.

    Implemented against Symantec Protection Engine for Cloud Services.

    INCOMPLETE
    """
    def __init__(self, host, port):
        super(SymantecIcapClient, self).__init__(host, port,
                                                 respmod_service='SYMCScanRespEx-AV',
                                                 action="?action=SCAN")

    def get_service_version(self):
        engine_version = 'unknown'
        definition_version = 'unknown'
        options_result = self.options_respmod()
        for line in options_result.splitlines():
            if line.startswith('Service:'):
                engine_version = line[line.index(':')+1:].strip()
            elif line.startswith('X-Definition-Info'):
                definition_version = line[line.index(':')+1:].strip()
        return engine_version, definition_version


class Symantec(ServiceBase):
    SERVICE_CATEGORY = 'Antivirus'
    SERVICE_DEFAULT_CONFIG = {
        'ICAP_HOST': '127.0.0.1',
        'ICAP_PORT': 1344,
    }
    SERVICE_DESCRIPTION = "This services wraps Symantec's ICAP proxy."
    SERVICE_ENABLED = True
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_SUPPORTED_PLATFORMS = ['Linux', 'Windows', ]
    SERVICE_VERSION = '1'
    SERVICE_CPU_CORES = 0.05
    SERVICE_RAM_MB = 32

    def __init__(self, cfg=None):
        super(Symantec, self).__init__(cfg)
        self.icap_host = self.cfg.get('ICAP_HOST')
        self.icap_port = self.cfg.get('ICAP_PORT')
        self._av_info = ''
        self.icap = None

    def connect_icap(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.connect((self.icap_host, self.icap_port))
        return sock

    def execute(self, request):
        request.result = Result()
        local_filename = request.download()
        with open(local_filename) as f:
            file_content = f.read()
        request.set_service_context(self._av_info)
        max_retry = 2
        done = False
        retry = 0

        while not done:
            # If this is a retry, sleep for a second
            if retry:
                # Sleep between 1 and 3 seconds times the number of retry
                time.sleep(retry * random.randrange(100, 300, 1) / float(100))

            output = self.icap.scan_data(file_content)

            ret = self.parse_results(output, request.result, local_filename)
            if ret in [201, 204]:
                done = True
            elif ret == 500:
                # Symantec often 500's on truncated zips and other formats. It tries to decompress/parse
                # them and can't proceed.
                request.result.add_section(ResultSection(SCORE.NULL, 'Symantec could not scan this file.'))
                done = True
            elif ret == 551:
                if retry == max_retry:
                    raise Exception("[FAILED %s times] Resources unvailable" % max_retry)
                else:
                    self.log.info("Resource unavailable... retrying")
                    retry += 1
            elif ret == 558:
                raise Exception("Could not scan file, Symantec license is expired!")
            elif ret == 100:
                raise Exception("Could not find response from icap service, "
                                "response header %s" % output.partition("\r")[0])
            else:
                raise Exception("Unknown return code from symantec: %s" % ret)
        return

    def get_symantec_version(self):
        engine, vers = self.icap.get_service_version()
        return "Engine: {} DAT: {}".format(engine, vers)

    def get_tool_version(self):
        return self._av_info

    def parse_results(self, result_content, file_res, local_filename):
        absolute_filename = ''
        nvirusfound = 0

        lines = result_content.splitlines()
        i = 0

        while i < len(lines):
            if "204 No Content Necessary" in lines[i]:
                return 204
            elif "500 Internal Server Error" in lines[i]:
                return 500
            elif "551 Resource unavailable" in lines[i]:
                return 551
            elif "558 Aborted" in lines[i]:
                return 558
            elif "X-Violations-Found:" in lines[i]:
                nvirusfound = int(lines[i].split(': ')[1])
            elif nvirusfound:
                i += 1
                virus_name = lines[i].split('|')[0].strip()
                self.set_result_values(local_filename, file_res, virus_name, absolute_filename)
                i += 2
                nvirusfound -= 1

                if not nvirusfound:
                    return 201

            i += 1

        return 100

    @staticmethod
    def set_result_values(local_filename, file_res, virus_name, absolute_filename):
        valid_embedded_filename = ""
        if len(absolute_filename) != len(local_filename):
            embedded_char_index = len(local_filename) + 1
            valid_embedded_filename = absolute_filename[embedded_char_index:]

        score = SCORE.SURE
        if virus_name in CONTAINER_ERRORS:
            score = SCORE.INFO

        if valid_embedded_filename != "":
            if os.path.sep == '\\':
                valid_embedded_filename = valid_embedded_filename.replace('/', '\\')

            res = VirusHitSection(virus_name, score, valid_embedded_filename)
        else:
            res = VirusHitSection(virus_name, score)

        file_res.append_tag(VirusHitTag(virus_name))

        cve_found = re.search("CVE-[0-9]{4}-[0-9]{4}", virus_name)
        if cve_found:
            file_res.add_tag(TAG_TYPE.EXPLOIT_NAME,
                             virus_name[cve_found.start():cve_found.end()],
                             TAG_SCORE.MED, usage='IDENTIFICATION')
            file_res.add_tag(TAG_TYPE.FILE_SUMMARY,
                             virus_name[cve_found.start():cve_found.end()],
                             TAG_SCORE.MED, usage='IDENTIFICATION')

        file_res.add_result(res)

    def start(self):
        self.icap = SymantecIcapClient(self.icap_host, self.icap_port)
        self._av_info = self.get_symantec_version()
