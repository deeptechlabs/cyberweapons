from __future__ import absolute_import

import os
import tempfile

from assemblyline_client import Client

from assemblyline.al.common.result import Result, ResultSection
from assemblyline.al.common.result import SCORE, TAG_TYPE, TAG_WEIGHT
from assemblyline.al.service.base import ServiceBase

from al_services.alsvc_configdecoder import configparser


class ConfigDecoder(ServiceBase):
    SERVICE_CATEGORY = 'Static Analysis'
    SERVICE_DEFAULT_CONFIG = {
        "USE_RIAK_FOR_RULES": True,
        "RULE_PATH": 'config_dec_rules.yar',
        "SIGNATURE_USER": 'user',
        "SIGNATURE_PASS": 'changeme',
        "SIGNATURE_URL": 'https://localhost:443',
        "SIGNATURE_QUERY": 'meta.al_configparser:* AND (meta.al_status:DEPLOYED OR meta.al_status:NOISY)'
    }
    SERVICE_DESCRIPTION = "This service runs implant configuration extraction routines for implants identified " \
                          "by Yara rules."
    SERVICE_ENABLED = True
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'

    SERVICE_CPU_CORES = 0.20
    SERVICE_RAM_MB = 1024

    def __init__(self, cfg=None):
        super(ConfigDecoder, self).__init__(cfg)
        self.config_parsers = []
        self.rules = None
        self.signature_user = self.cfg.get('SIGNATURE_USER')
        self.signature_pass = self.cfg.get('SIGNATURE_PASS')
        self.signature_url = self.cfg.get('SIGNATURE_URL')
        self.signature_query = self.cfg.get(
            'SIGNATURE_QUERY', 'meta.al_configparser:* AND (meta.al_status:DEPLOYED OR meta.al_status:NOISY)'
        )
        self.yara_rulepath = None

    # noinspection PyUnresolvedReferences,PyGlobalUndefined
    def import_service_deps(self):
        global yara
        import yara

    # noinspection PyBroadException
    def init_rules(self):
        try:
            self.log.info("Loading rule file...")
            if not self.cfg.get('USE_RIAK_FOR_RULES', False):
                self.yara_rulepath = self.cfg.get('RULE_PATH')
                self.rules = yara.compile(self.yara_rulepath)
            else:
                sig_client = Client(self.signature_url, auth=(self.signature_user, self.signature_pass))
                al_temp_dir = os.path.join(tempfile.gettempdir(), 'al', self.SERVICE_NAME, str(os.getpid()))
                try:
                    os.makedirs(al_temp_dir)
                except:
                    pass
                self.yara_rulepath = os.path.join(al_temp_dir, 'rules.yar')
                sig_client.signature.download(output=self.yara_rulepath, query=self.signature_query, safe=True)
                self.rules = yara.compile(self.yara_rulepath)
                try:
                    os.remove(self.yara_rulepath)
                except:  # pylint: disable=W0702
                    pass

            self.log.info("Using rule file: %s" % self.yara_rulepath)

        except:  # pylint: disable=W0702
            self.log.exception('Problem initializing yara rules:')

    def load_parsers(self):
        from al_services.alsvc_configdecoder import parsers

        self.config_parsers.extend([
            parsers.DarkComet51Parser(),
            parsers.GenericParser(),
        ])

    def start(self):
        self.load_parsers()
        self.init_rules()

    # noinspection PyBroadException
    def apply_parser(self, config_parser, request, hit, content):
        result = request.result

        # if the config_parser statisfies the prerequisite...
        if config_parser.accept(request, hit, content):
            # Attempt to parse config.
            parsed_configs = []
            try:
                parsed_configs = config_parser.parse(request, hit, content)
            except:  # pylint: disable=W0702
                self.log.exception("Parse failure:")

            failed = set()
            for parsed in parsed_configs:
                try:

                    if type(parsed) == configparser.NullParsedConfig and parsed.name not in failed:
                        failed.add(parsed.name)
                        section = ResultSection(
                            SCORE['LOW'],
                            "Configuration identified for %s but "
                            "was not successfully parsed!" % parsed.name,
                            parsed.classification
                        )
                    else:
                        section = ResultSection(
                            SCORE['SURE'],
                            [
                                parsed.name,
                                " configuration successfully parsed."
                            ],
                            parsed.classification
                        )
                        result.add_tag(
                            TAG_TYPE['FILE_CONFIG'], parsed.name,
                            TAG_WEIGHT['HIGH'],
                            classification=parsed.classification
                        )

                        # Add parsed config to the report.
                        parsed.report(request, section, self)

                    if section:
                        result.add_section(section)
                except:  # pylint: disable=W0702
                    self.log.exception("Parse failure:")

    # noinspection PyBroadException
    def execute(self, request):
        request.result = Result()
        content = request.get()

        # Run yara rules for all parsers.
        all_hits = {}
        matches = self.rules.match(data=content)

        # Reorganise the matches in a dictionary
        for match in matches:
            try:
                name = match.meta.get('al_configparser', None)
                if name:
                    all_hits[name] = all_hits.get(name, []) + [match]
            except:  # pylint: disable=W0702
                self.log.exception('Failed iterating over yara matches:')

        # Go through every config parser.
        for config_parser in self.config_parsers:
            try:
                name = config_parser.__class__.__name__.split('.')[-1]
                hits = all_hits.get(name, [])
                self.apply_parser(config_parser, request, hits, content)
            except:  # pylint: disable=W0702
                self.log.exception("Config parser failed:")
