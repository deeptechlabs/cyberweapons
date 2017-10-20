from __future__ import absolute_import

import os
import shutil
import tempfile
import threading

from hashlib import md5
from time import sleep

from cStringIO import StringIO

from assemblyline.common.exceptions import ConfigException
from assemblyline.common.isotime import now_as_iso
from assemblyline.common.yara.YaraValidator import YaraValidator
from assemblyline.al.common import forge
from assemblyline.al.common.result import Result, ResultSection
from assemblyline.al.common.result import TAG_TYPE, TAG_SCORE, TAG_USAGE, Tag
from assemblyline.al.common.transport.local import TransportLocal
from assemblyline.al.service.base import ServiceBase, UpdaterFrequency

from assemblyline_client import Client

Classification = forge.get_classification()

config = forge.get_config()


class YaraMetadata(object):
    def __init__(self, match):
        meta = match.meta
        self.rule_name = match.rule
        self.rule_id = match.meta.get('id', None)
        self.rule_group = match.meta.get('rule_group', None)
        self.rule_version = match.meta.get('rule_version', 1)
        self.description = match.meta.get('description', None)
        self.classification = match.meta.get('classification',
                                             Classification.UNRESTRICTED)
        self.organisation = meta.get('organisation', None)
        self.summary = meta.get('summary', None)
        self.description = meta.get('description', None)
        self.score_override = meta.get('al_score', None)
        self.poc = meta.get('poc', None)
        self.weight = meta.get('weight', 0)  # legacy rule format
        self.al_status = meta.get('al_status', "DEPLOYED")

        def _safe_split(comma_sep_list):
            return [e for e in comma_sep_list.split(',') if e]

        self.actors = _safe_split(match.meta.get('used_by', ''))
        self.summary = _safe_split(match.meta.get('summary', ''))
        self.exploits = _safe_split(match.meta.get('exploit', ''))

        # parse and populate implant list
        self.implants = []
        for implant in match.meta.get('implant', '').split(','):
            if not implant:
                continue
            tokens = implant.split(':')
            implant_name = tokens[0]
            implant_family = tokens[1] if (len(tokens) == 2) else ''
            self.implants.append((implant_name.strip().upper(),
                                  implant_family.strip().upper()))

        # parse and populate technique info
        self.techniques = []
        for technique in meta.get('technique', '').split(','):
            if not technique:
                continue
            tokens = technique.split(':')
            category = ''
            if len(tokens) == 2:
                category = tokens[0]
                name = tokens[1]
            else:
                name = tokens[0]
            self.techniques.append((category.strip(), name.strip()))

        self.info = []
        for info in meta.get('info', '').split(','):
            if not info:
                continue
            tokens = info.split(':', 1)
            if len(tokens) == 2:
                # category, value
                self.info.append((tokens[0], tokens[1]))
            else:
                self.info.append((None, tokens[0]))


NUM_RULES = 'yara.num_rules'
RULE_HITS = 'yara.total_rule_hits'
USING_RIAK = 'yara.using_riak_for_rules'


class Yara(ServiceBase):
    SERVICE_CATEGORY = 'Static Analysis'
    SERVICE_DESCRIPTION = "This services runs all DEPLOYED and NOISY signatures on submitted files. NOISY rules " \
                          "are reported but do not influence the score. DEPLOYED rules score according to their " \
                          "rule group (implant => 1000 | exploit & tool => 500 | technique => 100 | info => 0)."
    SERVICE_ENABLED = True
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_DEFAULT_CONFIG = {
        "USE_RIAK_FOR_RULES": True,
        "RULE_PATH": 'rules.yar',
        "SIGNATURE_USER": 'user',
        "SIGNATURE_PASS": 'changeme',
        "SIGNATURE_URL": 'https://localhost:443',
        "SIGNATURE_QUERY": 'meta.al_status:DEPLOYED OR meta.al_status:NOISY'
    }
    SERVICE_CPU_CORES = 0.5
    SERVICE_RAM_MB = 256

    YARA_SCORE_MAP = {
        'implant': 1000,
        'tool': 500,
        'exploit': 500,
        'technique': 100,
        'info': 0,
    }

    TYPE = 0
    DESCRIPTION = 1
    TECHNIQUE_DESCRIPTORS = {
        'shellcode': (TAG_TYPE.TECHNIQUE_SHELLCODE, 'Embedded shellcode'),
        'packer': (TAG_TYPE.TECHNIQUE_PACKER, 'Packed PE'),
        'cryptography': (TAG_TYPE.TECHNIQUE_CRYPTO, 'Uses cryptography/compression'),
        'obfuscation': (TAG_TYPE.TECHNIQUE_OBFUSCATION, 'Obfuscated'),
        'keylogger': (TAG_TYPE.TECHNIQUE_KEYLOGGER, 'Keylogging capability'),
        'comms_routine': (TAG_TYPE.TECHNIQUE_COMMS_ROUTINE, 'Does external comms'),
        'persistance': (TAG_TYPE.TECHNIQUE_PERSISTENCE, 'Has persistence'),
    }

    def __init__(self, cfg=None):
        super(Yara, self).__init__(cfg)
        self.last_update = "1970-01-01T00:00:00.000000Z"
        self.rules = None
        self.rules_md5 = None
        self.initialization_lock = threading.RLock()
        self.signature_cache = TransportLocal(
            base=os.path.join(config.system.root, 'var', 'cache', 'signatures')
        )
        self.task = None

        self.rule_path = self.cfg.get('RULE_PATH', 'rules.yar')
        self.signature_user = self.cfg.get('SIGNATURE_USER')
        self.signature_pass = self.cfg.get('SIGNATURE_PASS')
        self.signature_url = self.cfg.get('SIGNATURE_URL', 'https://localhost:443')
        self.signature_query = self.cfg.get('SIGNATURE_QUERY',
                                            'meta.al_status:DEPLOYED OR '
                                            'meta.al_status:NOISY')
        self.use_riak_for_rules = self.cfg.get('USE_RIAK_FOR_RULES', False)
        self.get_yara_externals = {"al_%s" % i: i for i in config.system.yara.externals}
        self.update_client = None

    def _add_resultinfo_for_match(self, result, match):
        almeta = YaraMetadata(match)
        self._normalize_metadata(almeta)

        if not self.task.deep_scan and almeta.al_status == "NOISY":
            almeta.score_override = 0

        # determine an overall score for this match
        score = self.YARA_SCORE_MAP.get(almeta.rule_group, 0)
        if almeta.implants:
            score = max(score, 500)
        if almeta.actors:
            score = max(score, 500)
        if almeta.score_override is not None:
            score = int(almeta.score_override)

        result.append_tag(Tag(TAG_TYPE.FILE_YARA_RULE, match.rule, TAG_SCORE.SURE, classification=almeta.classification,
                              usage=TAG_USAGE.IDENTIFICATION))
        title_elements = [match.rule, ]

        # Implant Tags.
        implant_title_elements = []
        for (implant_name, implant_family) in almeta.implants:
            if implant_name:
                implant_title_elements.append(implant_name)
                result.append_tag(
                    Tag(TAG_TYPE.IMPLANT_NAME, implant_name, TAG_SCORE.SURE, classification=almeta.classification))
            if implant_family:
                implant_title_elements.append(implant_family)
                result.append_tag(
                    Tag(TAG_TYPE.IMPLANT_FAMILY, implant_family, TAG_SCORE.SURE, classification=almeta.classification))
        if implant_title_elements:
            title_elements.append('implant: %s' % ','.join(implant_title_elements))

        # Threat Actor metadata.
        for actor in almeta.actors:
            title_elements.append(actor)
            result.append_tag(Tag(TAG_TYPE.THREAT_ACTOR, actor, TAG_SCORE.SURE, classification=almeta.classification))

        # Exploit / CVE metadata.
        if almeta.exploits:
            title_elements.append(" [Exploits(s): %s] " % ",".join(almeta.exploits))
        for exploit in almeta.exploits:
            result.append_tag(Tag(TAG_TYPE.EXPLOIT_NAME, exploit, TAG_SCORE.SURE, classification=almeta.classification))

        # Include technique descriptions in the section summary.
        summary_elements = set()
        for (category, name) in almeta.techniques:
            descriptor = self.TECHNIQUE_DESCRIPTORS.get(category, None)
            if not descriptor:
                continue
            tech_type, tech_description = descriptor
            result.append_tag(Tag(tech_type, name, TAG_SCORE.MED, classification=almeta.classification))
            summary_elements.add(tech_description)

        for (category, value) in almeta.info:
            if category == 'compiler':
                result.append_tag(
                    Tag(TAG_TYPE.INFO_COMPILER, value, TAG_SCORE.LOW, classification=almeta.classification,
                        usage=TAG_USAGE.IDENTIFICATION))
            elif category == 'libs':
                result.append_tag(Tag(TAG_TYPE.INFO_LIBS, value, TAG_SCORE.LOW, classification=almeta.classification,
                                      usage=TAG_USAGE.IDENTIFICATION))

        if summary_elements:
            title_elements.append(' (Summary: %s)' % ", ".join(summary_elements))
        for element in summary_elements:
            result.append_tag(Tag(TAG_TYPE.FILE_SUMMARY, element, TAG_SCORE.SURE, classification=almeta.classification,
                                  usage=TAG_USAGE.IDENTIFICATION))

        title = " ".join(title_elements)
        section = ResultSection(title_text=title, score=score, classification=almeta.classification)

        if almeta.rule_id and almeta.rule_version and almeta.poc:
            section.add_line('Rule Info : %s r.%s by %s' % (almeta.rule_id, almeta.rule_version, almeta.poc))

        if almeta.description:
            section.add_line('Description: %s' % almeta.description)

        self._add_string_match_data(match, section)

        result.add_section(section)
        result.order_results_by_score()

    def _add_string_match_data(self, match, section):
        strings = match.strings
        string_dict = {}
        for offset, identifier, data in strings:
            if data not in string_dict:
                string_dict[data] = []
            string_dict[data].append((offset, identifier))

        result_dict = {}
        for string_value, string_list in string_dict.iteritems():
            count = len(string_list)
            string_offset_list = []
            ident = ''
            for offset, ident in string_list[:5]:
                string_offset_list.append(str(hex(offset)).replace("L", ""))

            if ident == '$':
                string_name = ""
            else:
                string_name = "%s " % ident[1:]

            string_offset = ", ".join(string_offset_list)
            if len(string_list) > 5:
                string_offset += "..."

            is_wide_char = self._is_wide_char(string_value)
            if is_wide_char:
                string_value = self._get_non_wide_char(string_value)

            string_value = repr(string_value)
            if len(string_value) > 100:
                string_value = "%s..." % string_value[:100]

            wide_str = ""
            if is_wide_char:
                wide_str = " (wide)"

            entry_name = ''.join((string_name, wide_str))
            if string_name:
                result_list = result_dict.get(entry_name, [])
                result_list.append((string_value, string_offset, count))
                result_dict[entry_name] = result_list
                continue

            string_hit = "Found %s string: '%s [@ %s]%s'" % (
                entry_name,
                string_value,
                string_offset,
                ' (' + str(count) + 'x)' if count > 1 else ''
            )
            section.add_line(string_hit)

        for entry_name, result_list in result_dict.iteritems():
            for result in result_list[:5]:
                string_hit = "Found %s string: '%s' [@ %s]%s" % (
                    entry_name,
                    result[0],
                    result[1],
                    ' (' + str(result[2]) + 'x)' if result[2] > 1 else ''
                )
                section.add_line(string_hit)
            more = len(result_list[5:])
            if more:
                section.add_line("Found %s string %d more time%s" % (
                    entry_name, more, 's' if more > 1 else ''))

    def _compile_rules(self, rules_txt):
        tmp_dir = tempfile.mkdtemp(dir='/tmp')
        try:
            # Extract the first line of the rules which should look like this:
            # // Signatures last updated: LAST_UPDATE_IN_ISO_FORMAT
            first_line, clean_data = rules_txt.split('\n', 1)
            prefix = '// Signatures last updated: '

            if first_line.startswith(prefix):
                last_update = first_line.replace(prefix, '')
            else:
                self.log.warning(
                    "Couldn't read last update time from %s", rules_txt[:40]
                )
                last_update = now_as_iso()
                clean_data = rules_txt

            rules_file = os.path.join(tmp_dir, 'rules.yar')
            with open(rules_file, 'w') as f:
                f.write(rules_txt)
            try:
                validate = YaraValidator(externals=self.get_yara_externals, logger=self.log)
                edited = validate.validate_rules(rules_file, datastore=True)
            except Exception as e:
                raise e
            # Grab the final output if Yara Validator found problem rules
            if edited:
                with open(rules_file, 'r') as f:
                    sdata = f.read()
                first_line, clean_data = sdata.split('\n', 1)
                if first_line.startswith(prefix):
                    last_update = first_line.replace(prefix, '')
                else:
                    last_update = now_as_iso()
                    clean_data = sdata

            rules = yara.compile(rules_file, externals=self.get_yara_externals)
            rules_md5 = md5(clean_data).hexdigest()
            return last_update, rules, rules_md5
        except Exception as e:
            raise e
        finally:
            shutil.rmtree(tmp_dir)

    def _extract_result_from_matches(self, matches):
        result = Result(default_usage=TAG_USAGE.CORRELATION)
        for match in matches:
            self._add_resultinfo_for_match(result, match)
        return result

    @staticmethod
    def _get_non_wide_char(string):
        res = []
        for (i, c) in enumerate(string):
            if i % 2 == 0:
                res.append(c)

        return ''.join(res)

    @staticmethod
    def _is_wide_char(string):
        if len(string) >= 2 and len(string) % 2 == 0:
            is_wide_char = True
            for (i, c) in enumerate(string):
                if ((i % 2 == 0 and ord(c) == 0) or
                        (i % 2 == 1 and ord(c) != 0)):
                    is_wide_char = False
                    break
        else:
            is_wide_char = False

        return is_wide_char

    @staticmethod
    def _normalize_metadata(almeta):
        almeta.classification = almeta.classification.upper()

    def _update_rules(self, **_):
        self.log.info("Starting Yara's rule updater...")

        if not self.update_client:
            self.update_client = Client(self.signature_url, auth=(self.signature_user, self.signature_pass))

        if self.signature_cache.exists(self.rule_path):
            api_response = self.update_client.signature.update_available(self.last_update)
            update_available = api_response.get('update_available', False)
            if not update_available:
                self.log.info("No update available. Stopping...")
                return

        self.log.info("Downloading signatures with query: %s (%s)" % (self.signature_query, str(self.last_update)))

        signature_data = StringIO()
        self.update_client.signature.download(output=signature_data, query=self.signature_query, safe=True)

        rules_txt = signature_data.getvalue()
        if not rules_txt:
            errormsg = "No rules to compile:\n%s" % rules_txt
            self.log.error("{}/api/v3/signature/download/?query={} - {}:{}".format(
                self.signature_url, self.signature_query, self.signature_user, self.signature_pass)
            )
            self.log.error(errormsg)
            raise ConfigException(errormsg)

        self.signature_cache.save(self.rule_path, rules_txt)

        last_update, rules, rules_md5 = self._compile_rules(rules_txt)
        if rules:
            with self.initialization_lock:
                self.last_update = last_update
                self.rules = rules
                self.rules_md5 = rules_md5

    def execute(self, request):
        if not self.rules:
            return

        self.task = request.task
        local_filename = request.download()

        yara_externals = {}
        for k, i in self.get_yara_externals.iteritems():
            # Check default request.task fields
            try:
                sval = self.task.get(i)
            except:
                sval = None
            if not sval:
                # Check metadata dictionary
                smeta = self.task.metadata
                if not smeta:
                    sval = smeta.get(i, None)
            if not sval:
                # Check params dictionary
                smeta = self.task.params
                if not smeta:
                    sval = smeta.get(i, None)
            # Create dummy value if item not found
            if not sval:
                sval = i

            yara_externals[k] = sval

        with self.initialization_lock:
            try:
                matches = self.rules.match(local_filename, externals=yara_externals)
                self.counters[RULE_HITS] += len(matches)
                request.result = self._extract_result_from_matches(matches)
            except Exception as e:
                if e.message != "internal error: 30":
                    raise
                else:
                    self.log.warning("Yara internal error 30 detected on submission {}" .format(self.task.sid))
                    section = ResultSection(title_text="Yara scan not completed.")
                    section.add_line("File returned too many matches with current rule set and Yara exited.")
                    result = Result()
                    request.result = result
                    result.add_result(section)

    def get_service_version(self):
        basic_version = super(Yara, self).get_service_version()
        return '{}.r{}'.format(basic_version, self.rules_md5 or "0")

    # noinspection PyGlobalUndefined,PyUnresolvedReferences
    def import_service_deps(self):
        global yara
        import yara

        # noinspection PyUnresolvedReferences,PyBroadException
        try:
            requests.packages.urllib3.disable_warnings()
        except:  # pylint: disable=W0702
            pass

    def start(self):
        force_rule_download = False
        # noinspection PyBroadException
        try:
            # Even if we are using riak for rules we may have a saved copy
            # of the rules. Try to load and compile them first.
            self.signature_cache.makedirs(os.path.dirname(self.rule_path))
            rules_txt = self.signature_cache.get(self.rule_path)
            if rules_txt:
                self.log.info("Yara loaded rules from cached file: %s", self.rule_path)
                self.last_update, self.rules, self.rules_md5 = \
                    self._compile_rules(rules_txt)
            else:
                self.log.info("No cached Yara rules found.")
                force_rule_download = True

        except Exception, e:  # pylint: disable=W0702
            if not self.use_riak_for_rules:
                sleep(30)  # Try and avoid flailing.
                raise
            self.log.warning("Something went wrong while trying to load cached rules: %s" % e.message)
            force_rule_download = True

        if self.use_riak_for_rules:
            self._register_update_callback(self._update_rules, execute_now=force_rule_download,
                                           freq=UpdaterFrequency.MINUTE)

        self.log.info(
            "yara started with service version: %s", self.get_service_version()
        )
