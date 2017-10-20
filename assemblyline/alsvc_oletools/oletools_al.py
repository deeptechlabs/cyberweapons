# wrapper service for py-oletools by Philippe Lagadec - http://www.decalage.info
from textwrap import dedent

from assemblyline.common.charset import safe_str
from assemblyline.common.iprange import is_ip_reserved
from assemblyline.al.common.heuristics import Heuristic
from assemblyline.al.common.result import Result, ResultSection, SCORE, TAG_TYPE, TAG_WEIGHT, TAG_USAGE, TEXT_FORMAT
from assemblyline.al.service.base import ServiceBase
from al_services.alsvc_oletools.stream_parser import Ole10Native, PowerPointDoc
import os
import re
import traceback
import hashlib
from operator import attrgetter
import zipfile
import zlib
import email
import json
import gzip
import unicodedata
import binascii

VBA_Parser = None
VBA_Scanner = None
OleID = None
Indicator = None
olefile = None
olefile2 = None
rtf_iter_objects = None


class Macro(object):
    macro_code = ''
    macro_sha256 = ''
    macro_section = None
    macro_score = 0

    def __init__(self, macro_code, macro_sha256, macro_section, macro_score=0):
        self.macro_code = macro_code
        self.macro_sha256 = macro_sha256
        self.macro_section = macro_section
        self.macro_score = macro_score


class Oletools(ServiceBase):
    AL_Oletools_001 = Heuristic("AL_Oletools_001", "Attached Document Template", "document/office/ole",
                                dedent("""\
                                       /Attached template specified in xml relationships. This can be used
                                       for malicious purposes.
                                       """))
    AL_Oletools_002 = Heuristic("AL_Oletools_002", "Multi-embedded documents", "document/office/ole",
                                dedent("""\
                                       /File contains both old OLE format and new ODF format. This can be
                                        used to obfuscate malicious content.
                                       """))
    AL_Oletools_003 = Heuristic("AL_Oletools_003", "Massive document", "document/office/ole",
                                dedent("""\
                                       /File contains parts which are massive. Could not scan entire document.
                                       """))

    SERVICE_CATEGORY = 'Static Analysis'
    SERVICE_ACCEPTS = 'document/office/.*'
    SERVICE_DESCRIPTION = "This service extracts metadata and network information and reports anomalies in " \
                          "Microsoft OLE and XML documents using the Python library py-oletools."
    SERVICE_ENABLED = True
    SERVICE_VERSION = '3'
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_CPU_CORES = 0.5
    SERVICE_RAM_MB = 1024
    SERVICE_DEFAULT_CONFIG = {
        'MACRO_SCORE_MAX_FILE_SIZE': 5 * 1024**2,
        'MACRO_SCORE_MIN_ALERT': 0.6
    }

    MAX_STRINGDUMP_CHARS = 500
    MAX_STRING_SCORE = SCORE.VHIGH
    MAX_MACRO_SECTIONS = 3
    MIN_MACRO_SECTION_SCORE = SCORE.MED

    # in addition to those from olevba.py
    ADDITIONAL_SUSPICIOUS_KEYWORDS = ('WinHttp', 'WinHttpRequest', 'WinInet', 'Lib "kernel32" Alias')

    def __init__(self, cfg=None):
        super(Oletools, self).__init__(cfg)
        self.request = None
        self.task = None
        self.ole_result = None
        self.scored_macro_uri = False
        self.ip_re = re.compile(
            r'^((?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]).){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))'
        )
        self.domain_re = re.compile('^((?:(?:[a-zA-Z0-9\-]+)\.)+[a-zA-Z]{2,5})')
        self.uri_re = re.compile(r'[a-zA-Z]+:/{1,3}[^/]+/[^\s]+')

        self.word_chains = None
        self.macro_skip_words = None
        self.macro_words_re = re.compile("[a-z]{3,}")
        self.macro_score_max_size = cfg.get('MACRO_SCORE_MAX_FILE_SIZE', None)
        self.macro_score_min_alert = cfg.get('MACRO_SCORE_MIN_ALERT', 0.6)

        self.all_macros = None
        self.all_vba = None
        self.filetypes = ['application',
                          'exec',
                          'image',
                          'text',
                          ]

    # noinspection PyUnresolvedReferences
    def import_service_deps(self):
        from oletools.olevba import VBA_Parser, VBA_Scanner
        from oletools.oleid import OleID, Indicator
        from oletools.thirdparty.olefile import olefile, olefile2
        from oletools.rtfobj import rtf_iter_objects
        import magic
        try:
            from al_services.alsvc_frankenstrings.balbuzard.patterns import PatternMatch
            global PatternMatch
        except ImportError:
            pass
        global VBA_Parser, VBA_Scanner
        global OleID, Indicator, olefile, olefile2, rtf_iter_objects
        global magic

    def start(self):
        self.log.debug("Service started")

        chain_path = os.path.join(os.path.dirname(__file__), "chains.json.gz")
        with gzip.open(chain_path) as fh:
            self.word_chains = json.load(fh)

        for k, v in self.word_chains.items():
            self.word_chains[k] = set(v)

        # Don't reward use of common keywords
        self.macro_skip_words = {'var', 'unescape', 'exec', 'for', 'while', 'array', 'object',
                                 'length', 'len', 'substr', 'substring', 'new', 'unicode', 'name', 'base',
                                 'dim', 'set', 'public', 'end', 'getobject', 'createobject', 'content',
                                 'regexp', 'date', 'false', 'true', 'none', 'break', 'continue', 'ubound',
                                 'none', 'undefined', 'activexobject', 'document', 'attribute', 'shell',
                                 'thisdocument', 'rem', 'string', 'byte', 'integer', 'int', 'function',
                                 'text', 'next', 'private', 'click', 'change', 'createtextfile', 'savetofile',
                                 'responsebody', 'opentextfile', 'resume', 'open', 'environment', 'write', 'close',
                                 'error', 'else', 'number', 'chr', 'sub', 'loop'}

    def get_tool_version(self):
        return self.SERVICE_VERSION

    # CIC: Call If Callable
    @staticmethod
    def cic(expression):
        """
        From 'base64dump.py' by Didier Stevens@https://DidierStevens.com
        """
        if callable(expression):
            return expression()
        else:
            return expression

    # IFF: IF Function
    @classmethod
    def iff(cls, expression, value_true, value_false):
        """
        From 'base64dump.py' by Didier Stevens@https://DidierStevens.com
        """
        if expression:
            return cls.cic(value_true)
        else:
            return cls.cic(value_false)

    # Ascii Dump
    @classmethod
    def ascii_dump(cls, data):
        return ''.join([cls.iff(ord(b) >= 32, b, '.') for b in data])

    def execute(self, request):
        self.task = request.task
        request.result = Result()
        self.ole_result = request.result
        self.request = request
        self.scored_macro_uri = False

        self.all_macros = []
        self.all_vba = []

        path = request.download()
        filename = os.path.basename(path)
        file_contents = request.get()

        try:
            self.check_for_macros(filename, file_contents, request.sha256)
            self.check_xml_strings(path)
            self.rip_mhtml(file_contents)
            self.extract_streams(path, file_contents)
            self.create_macro_sections(request.sha256)
        except Exception as e:
            self.log.error("We have encountered a critical error: {}".format(e))

        score_check = 0
        for section in self.ole_result.sections:
            score_check += self.calculate_nested_scores(section)

        if score_check == 0:
            request.result = Result()

        self.all_macros = None
        self.all_vba = None

    def check_for_indicators(self, filename):
        # noinspection PyBroadException
        try:
            ole_id = OleID(filename)
            indicators = ole_id.check()

            for indicator in indicators:
                # ignore these OleID indicators, they aren't all that useful
                if indicator.id in ("ole_format", "has_suminfo",):
                    continue

                indicator_score = SCORE.LOW  # default to LOW

                if indicator.value is True:
                    if indicator.id in ("word", "excel", "ppt", "visio"):
                        # good to know that the filetypes have been detected, but not a score-able offense
                        indicator_score = SCORE.NULL

                    section = ResultSection(indicator_score, "OleID indicator : " + indicator.name)
                    if indicator.description:
                        section.add_line(indicator.description)
                    self.ole_result.add_section(section)
        except:
            self.log.debug("OleID analysis failed")

    # Returns True if the URI should score
    # noinspection PyUnusedLocal
    def parse_uri(self, check_uri):
        m = self.uri_re.match(check_uri)
        if m is None:
            return False
        else:
            full_uri = m.group(0)

        proto, uri = full_uri.split('://', 1)
        if proto == 'file':
            return False

        scorable = False
        if "http://purl.org/" not in full_uri and \
                "http://xml.org/" not in full_uri and \
                ".openxmlformats.org/" not in full_uri and \
                ".oasis-open.org/" not in full_uri and \
                ".xmlsoap.org/" not in full_uri and \
                ".microsoft.com/" not in full_uri and \
                ".w3.org/" not in full_uri and \
                ".gc.ca/" not in full_uri and \
                ".mil.ca/" not in full_uri:

            self.ole_result.add_tag(TAG_TYPE.NET_FULL_URI,
                                    full_uri,
                                    TAG_WEIGHT.MED,
                                    usage=TAG_USAGE.CORRELATION)
            scorable = True

            domain = self.domain_re.match(uri)
            ip = self.ip_re.match(uri)
            if ip:
                ip_str = ip.group(1)
                if not is_ip_reserved(ip_str):
                    self.ole_result.add_tag(TAG_TYPE.NET_IP,
                                            ip_str,
                                            TAG_WEIGHT.HIGH,
                                            usage=TAG_USAGE.CORRELATION)
            elif domain:
                dom_str = domain.group(1)
                self.ole_result.add_tag(TAG_TYPE.NET_DOMAIN_NAME,
                                        dom_str,
                                        TAG_WEIGHT.HIGH,
                                        usage=TAG_USAGE.CORRELATION)

        return scorable

    def check_xml_strings(self, path):
        xml_target_res = ResultSection(score=SCORE.NULL, title_text="Attached External Template Targets in XML")
        xml_ioc_res = ResultSection(score=SCORE.NULL, title_text="IOCs in XML:")
        xml_b64_res = ResultSection(score=SCORE.NULL, title_text="Base64 in XML:")
        try:
            template_re = re.compile(r'/attachedTemplate"\s+[Tt]arget="((?!file)[^"]+)"\s+[Tt]argetMode="External"')
            uris = []
            zip_uris = []
            b64results = {}
            b64_extracted = set()
            if zipfile.is_zipfile(path):
                try:
                    patterns = PatternMatch()
                except:
                    patterns = None
                z = zipfile.ZipFile(path)
                for f in z.namelist():
                    data = z.open(f).read()
                    if len(data) > 500000:
                        data = data[:500000]
                        xml_ioc_res.report_heuristics(Oletools.AL_Oletools_003)
                        xml_ioc_res.score = min(xml_ioc_res.score, 1)
                    zip_uris.extend(template_re.findall(data))
                    # Use FrankenStrings modules to find other strings of interest
                    # Plain IOCs
                    if patterns:
                        pat_strs = ["http://purl.org", "schemas.microsoft.com", "schemas.openxmlformats.org",
                                    "www.w3.org"]
                        pat_ends = ["themeManager.xml", "MSO.DLL", "stdole2.tlb", "vbaProject.bin", "VBE6.DLL", "VBE7.DLL"]
                        pat_whitelist = ['Management', 'Manager', "microsoft.com"]

                        st_value = patterns.ioc_match(data, bogon_ip=True)
                        if len(st_value) > 0:
                            for ty, val in st_value.iteritems():
                                if val == "":
                                    asc_asc = unicodedata.normalize('NFKC', val).encode('ascii', 'ignore')
                                    if any(x in asc_asc for x in pat_strs) \
                                            or asc_asc.endswith(tuple(pat_ends)) \
                                            or asc_asc in pat_whitelist:
                                        continue
                                    else:
                                        xml_ioc_res.score += 1
                                        xml_ioc_res.add_line("Found %s string: %s in file %s}"
                                                             % (TAG_TYPE[ty].replace("_", " "), asc_asc, f))
                                        xml_ioc_res.add_tag(TAG_TYPE[ty], asc_asc, TAG_WEIGHT.LOW)
                                else:
                                    ulis = list(set(val))
                                    for v in ulis:
                                        if any(x in v for x in pat_strs) \
                                                or v.endswith(tuple(pat_ends)) \
                                                or v in pat_whitelist:
                                            continue
                                        else:
                                            xml_ioc_res.score += 1
                                            xml_ioc_res.add_line("Found %s string: %s in file %s"
                                                                 % (TAG_TYPE[ty].replace("_", " "), v, f))
                                            xml_ioc_res.add_tag(TAG_TYPE[ty], v, TAG_WEIGHT.LOW)

                    # Base64
                    b64_matches = set()
                    for b64_tuple in re.findall('(([\x20]{0,2}[A-Za-z0-9+/]{3,}={0,2}[\r]?[\n]?){6,})',
                                                data):
                        b64 = b64_tuple[0].replace('\n', '').replace('\r', '').replace(' ', '')
                        uniq_char = ''.join(set(b64))
                        if len(uniq_char) > 6:
                            if len(b64) >= 16 and len(b64) % 4 == 0:
                                b64_matches.add(b64)
                        """
                        Using some selected code from 'base64dump.py' by Didier Stevens@https://DidierStevens.com
                        """
                        for b64_string in b64_matches:
                            try:
                                b64_extract = False
                                base64data = binascii.a2b_base64(b64_string)
                                sha256hash = hashlib.sha256(base64data).hexdigest()
                                if sha256hash in b64_extracted:
                                    continue
                                # Search for embedded files of interest
                                if 500 < len(base64data) < 8000000:
                                    m = magic.Magic(mime=True)
                                    ftype = m.from_buffer(base64data)
                                    if 'octet-stream' not in ftype:
                                        for ft in self.filetypes:
                                            if ft in ftype:
                                                b64_file_path = os.path.join(self.working_directory,
                                                                             "{}_b64_decoded"
                                                                             .format(sha256hash[0:10]))
                                                self.request.add_extracted(b64_file_path,
                                                                           "Extracted b64 file during "
                                                                           "OLETools analysis.")
                                                with open(b64_file_path, 'wb') as b64_file:
                                                    b64_file.write(base64data)
                                                    self.log.debug("Submitted dropped file for analysis: {}"
                                                                   .format(b64_file_path))

                                                b64results[sha256hash] = [len(b64_string), b64_string[0:50],
                                                                          "[Possible base64 file contents in {}. "
                                                                          "See extracted files.]" .format(f), "", ""]

                                                b64_extract = True
                                                b64_extracted.add(sha256hash)
                                                break
                                if not b64_extract and len(base64data) > 30:
                                    if all(ord(c) < 128 for c in base64data):
                                        check_utf16 = base64data.decode('utf-16').encode('ascii', 'ignore')
                                        if check_utf16 != "":
                                            asc_b64 = check_utf16
                                        else:
                                            asc_b64 = self.ascii_dump(base64data)
                                        # If data has less then 7 uniq chars then ignore
                                        uniq_char = ''.join(set(asc_b64))
                                        if len(uniq_char) > 6:
                                            if patterns:
                                                st_value = patterns.ioc_match(asc_b64, bogon_ip=True)
                                                if len(st_value) > 0:
                                                    for ty, val in st_value.iteritems():
                                                        if val == "":
                                                            asc_asc = unicodedata.normalize('NFKC', val)\
                                                                .encode('ascii', 'ignore')
                                                            xml_ioc_res.add_tag(TAG_TYPE[ty], asc_asc, TAG_WEIGHT.LOW)
                                                        else:
                                                            ulis = list(set(val))
                                                            for v in ulis:
                                                                xml_ioc_res.add_tag(TAG_TYPE[ty], v, TAG_WEIGHT.LOW)
                                            b64results[sha256hash] = [len(b64_string), b64_string[0:50], asc_b64,
                                                                          base64data, "{}" .format(f)]
                            except:
                                pass

                b64index = 0
                for b64k, b64l in b64results.iteritems():
                    xml_b64_res.score = 100
                    b64index += 1
                    sub_b64_res = (ResultSection(SCORE.NULL, title_text="Result {0} in file {1}"
                                                 .format(b64index, f), parent=xml_b64_res))
                    sub_b64_res.add_line('BASE64 TEXT SIZE: {}'.format(b64l[0]))
                    sub_b64_res.add_line('BASE64 SAMPLE TEXT: {}[........]'.format(b64l[1]))
                    sub_b64_res.add_line('DECODED SHA256: {}'.format(b64k))
                    subb_b64_res = (ResultSection(SCORE.NULL, title_text="DECODED ASCII DUMP:",
                                                  body_format=TEXT_FORMAT.MEMORY_DUMP,
                                                  parent=sub_b64_res))
                    subb_b64_res.add_line('{}'.format(b64l[2]))
                    if b64l[3] != "":
                        if patterns:
                            st_value = patterns.ioc_match(b64l[3], bogon_ip=True)
                            if len(st_value) > 0:
                                xml_b64_res.score += 1
                                for ty, val in st_value.iteritems():
                                    if val == "":
                                        asc_asc = unicodedata.normalize('NFKC', val).encode\
                                            ('ascii', 'ignore')
                                        xml_b64_res.add_tag(TAG_TYPE[ty], asc_asc, TAG_WEIGHT.LOW)
                                    else:
                                        ulis = list(set(val))
                                        for v in ulis:
                                            xml_b64_res.add_tag(TAG_TYPE[ty], v, TAG_WEIGHT.LOW)
                z.close()
                for uri in zip_uris:
                    if self.parse_uri(uri):
                        uris.append(uri)

                uris = list(set(uris))
                # If there are domains or IPs, report them
                if uris:
                    xml_target_res.score = 500
                    xml_target_res.add_lines(uris)
                    xml_target_res.report_heuristics(Oletools.AL_Oletools_001)

        except Exception as e:
            self.log.debug("Failed to analyze XML: {}".format(e))

        if xml_target_res.score > 0:
            self.ole_result.add_section(xml_target_res)
        if xml_ioc_res.score > 0:
            self.ole_result.add_section(xml_ioc_res)
        if xml_b64_res.score > 0:
            self.ole_result.add_section(xml_b64_res)

    # chains.json contains common English trigraphs. We score macros on how common these trigraphs appear in code,
    # skipping over some common keywords. A lower score indicates more randomized text, random variable/function names
    # are common in malicious macros.
    def flag_macro(self, macro_text):
        if self.macro_score_max_size is not None and len(macro_text) > self.macro_score_max_size:
            return False

        macro_text = macro_text.lower()
        score = 0.0

        word_count = 0
        byte_count = 0

        for m_cw in self.macro_words_re.finditer(macro_text):
            cw = m_cw.group(0)
            word_count += 1
            byte_count += len(cw)
            if cw in self.macro_skip_words:
                continue
            prefix = cw[0]
            tc = 0
            for i in xrange(1, len(cw) - 1):
                c = cw[i:i + 2]
                if c in self.word_chains.get(prefix, []):
                    tc += 1
                prefix = cw[i]

            score += tc / float(len(cw) - 2)

        if byte_count < 128 or word_count < 32:
            # these numbers are arbitrary, but if the sample is too short the score is worthless
            return False

        return (score / word_count) < self.macro_score_min_alert

    def create_macro_sections(self, request_hash):
        # noinspection PyBroadException
        try:
            filtered_macros = []
            if len(self.all_macros) > 0:
                # noinspection PyBroadException
                try:
                    # first sort all analyzed macros by their relative score, highest first
                    self.all_macros.sort(key=attrgetter('macro_score'), reverse=True)

                    # then only keep, theoretically, the most interesting ones
                    filtered_macros = self.all_macros[0:min(len(self.all_macros), self.MAX_MACRO_SECTIONS)]
                except:
                    self.log.debug("Sort and filtering of macro scores failed, "
                                   "reverting to full list of extracted macros")
                    filtered_macros = self.all_macros
            else:
                self.ole_result.add_section(ResultSection(SCORE.NULL, "No interesting macros found."))

            for macro in filtered_macros:
                if macro.macro_score >= self.MIN_MACRO_SECTION_SCORE:
                    self.ole_result.add_section(macro.macro_section)

            # Create extracted file for all VBA script.
            if len(self.all_vba) > 0:
                vba_file_path = ""
                all_vba = "\n".join(self.all_vba)
                vba_all_sha256 = hashlib.sha256(all_vba).hexdigest()
                if vba_all_sha256 == request_hash:
                    return

                try:
                    vba_file_path = os.path.join(self.working_directory, vba_all_sha256)
                    with open(vba_file_path, 'w') as fh:
                        fh.write(all_vba)

                    self.request.add_extracted(vba_file_path, "vba_code",
                                               "all_vba_%s.vba" % vba_all_sha256[:7])
                except Exception as e:
                    self.log.error("Error while adding extracted"
                                   " macro: {}: {}".format(vba_file_path, str(e)))
        except Exception as e:
            self.log.debug("OleVBA VBA_Parser.detect_vba_macros failed: {}".format(e))
            section = ResultSection(SCORE.NULL, "OleVBA : Error parsing macros: {}".format(e))
            self.ole_result.add_section(section)

    def check_for_macros(self, filename, file_contents, request_hash):
        # noinspection PyBroadException
        try:
            vba_parser = VBA_Parser(filename=filename, data=file_contents)

            try:
                if vba_parser.detect_vba_macros():
                    self.ole_result.add_tag(TAG_TYPE.TECHNIQUE_MACROS,
                                            "Contains VBA Macro(s)",
                                            weight=TAG_WEIGHT.LOW,
                                            usage=TAG_USAGE.IDENTIFICATION)

                    try:
                        for (subfilename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                            if vba_code.strip() == '':
                                continue
                            vba_code_sha256 = hashlib.sha256(vba_code).hexdigest()
                            if vba_code_sha256 == request_hash:
                                continue

                            self.all_vba.append(vba_code)
                            macro_section = self.macro_section_builder(vba_code)
                            toplevel_score = self.calculate_nested_scores(macro_section)

                            self.all_macros.append(Macro(vba_code, vba_code_sha256, macro_section, toplevel_score))
                    except Exception as e:
                        self.log.debug("OleVBA VBA_Parser.extract_macros failed: {}".format(str(e)))
                        section = ResultSection(SCORE.NULL, "OleVBA : Error extracting macros")
                        self.ole_result.add_section(section)

            except Exception as e:
                self.log.debug("OleVBA VBA_Parser.detect_vba_macros failed: {}".format(e))
                section = ResultSection(SCORE.NULL, "OleVBA : Error parsing macros: {}".format(e))
                self.ole_result.add_section(section)
        except:
            self.log.debug("OleVBA VBA_Parser constructor failed, may not be a supported OLE document")

    def calculate_nested_scores(self, section):
        score = section.score
        if len(section.subsections) > 0:
            for subsection in section.subsections:
                score = score + self.calculate_nested_scores(subsection)
        return score

    def macro_section_builder(self, vba_code):

        vba_code_sha256 = hashlib.sha256(vba_code).hexdigest()
        macro_section = ResultSection(SCORE.NULL, "OleVBA : Macro detected")
        macro_section.add_line("Macro SHA256 : %s" % vba_code_sha256)
        #macro_section.add_line("Resubmitted macro as: macro_%s.vba" % vba_code_sha256[:7])
        macro_section.add_tag(TAG_TYPE.OLE_MACRO_SHA256,
                              vba_code_sha256,
                              weight=TAG_WEIGHT.LOW,
                              usage=TAG_USAGE.CORRELATION)

        dump_title = "Macro contents dump"
        analyzed_code = self.deobfuscator(vba_code)
        req_deob = False
        if analyzed_code != vba_code:
            req_deob = True
            dump_title += " [deobfuscated]"

        if len(analyzed_code) > self.MAX_STRINGDUMP_CHARS:
            dump_title += " - Displaying only the first %s characters." % self.MAX_STRINGDUMP_CHARS
            dump_subsection = ResultSection(SCORE.NULL, dump_title, body_format=TEXT_FORMAT.MEMORY_DUMP)
            dump_subsection.add_line(analyzed_code[0:self.MAX_STRINGDUMP_CHARS])
        else:
            dump_subsection = ResultSection(SCORE.NULL, dump_title, body_format=TEXT_FORMAT.MEMORY_DUMP)
            dump_subsection.add_line(analyzed_code)

        if req_deob:
            dump_subsection.add_tag(TAG_TYPE.TECHNIQUE_OBFUSCATION,
                                    "VBA Macro String Functions",
                                    weight=TAG_WEIGHT.LOW,
                                    usage=TAG_USAGE.IDENTIFICATION)

        score_subsection = self.macro_scorer(analyzed_code)
        if score_subsection:
            macro_section.add_section(score_subsection)
            macro_section.add_section(dump_subsection)

        # Flag macros
        if self.flag_macro(analyzed_code):
            macro_section.add_section(ResultSection(SCORE.HIGH, "Macro may be packed or obfuscated."))

        return macro_section

    # TODO: deobfuscator is very primitive; visual inspection and dynamic analysis will often be most useful
    # TODO: may want to eventually pull this out into a Deobfuscation helper that supports multi-languages
    def deobfuscator(self, text):
        self.log.debug("Deobfuscation running")
        deobf = text
        # noinspection PyBroadException
        try:
            # leading & trailing quotes in each local function are to facilitate the final re.sub in deobfuscator()

            # repeated chr(x + y) calls seen in wild, as per SANS ISC diary from May 8, 2015
            def deobf_chrs_add(m):
                if m.group(0):
                    i = int(m.group(1)) + int(m.group(2))

                    if (i >= 0) and (i <= 255):
                        return "\"%s\"" % chr(i)
                return ''

            deobf = re.sub(r'chr[\$]?\((\d+) \+ (\d+)\)', deobf_chrs_add, deobf, flags=re.IGNORECASE)

            def deobf_unichrs_add(m):
                result = ''
                if m.group(0):
                    result = m.group(0)

                    i = int(m.group(1)) + int(m.group(2))

                    # unichr range is platform dependent, either [0..0xFFFF] or [0..0x10FFFF]
                    if (i >= 0) and ((i <= 0xFFFF) or (i <= 0x10FFFF)):
                        result = "\"%s\"" % unichr(i)
                return result

            deobf = re.sub(r'chrw[\$]?\((\d+) \+ (\d+)\)', deobf_unichrs_add, deobf, flags=re.IGNORECASE)

            # suspect we may see chr(x - y) samples as well
            def deobf_chrs_sub(m):
                if m.group(0):
                    i = int(m.group(1)) - int(m.group(2))

                    if (i >= 0) and (i <= 255):
                        return "\"%s\"" % chr(i)
                return ''

            deobf = re.sub(r'chr[\$]?\((\d+) \- (\d+)\)', deobf_chrs_sub, deobf, flags=re.IGNORECASE)

            def deobf_unichrs_sub(m):
                if m.group(0):
                    i = int(m.group(1)) - int(m.group(2))

                    # unichr range is platform dependent, either [0..0xFFFF] or [0..0x10FFFF]
                    if (i >= 0) and ((i <= 0xFFFF) or (i <= 0x10FFFF)):
                        return "\"%s\"" % unichr(i)
                return ''

            deobf = re.sub(r'chrw[\$]?\((\d+) \- (\d+)\)', deobf_unichrs_sub, deobf, flags=re.IGNORECASE)

            def deobf_chr(m):
                if m.group(1):
                    i = int(m.group(1))

                    if (i >= 0) and (i <= 255):
                        return "\"%s\"" % chr(i)
                return ''

            deobf = re.sub('chr[\$]?\((\d+)\)', deobf_chr, deobf, flags=re.IGNORECASE)

            def deobf_unichr(m):
                if m.group(1):
                    i = int(m.group(1))

                    # unichr range is platform dependent, either [0..0xFFFF] or [0..0x10FFFF]
                    if (i >= 0) and ((i <= 0xFFFF) or (i <= 0x10FFFF)):
                        return "\"%s\"" % unichr(i)
                return ''

            deobf = re.sub('chrw[\$]?\((\d+)\)', deobf_unichr, deobf, flags=re.IGNORECASE)

            # handle simple string concatenations
            deobf = re.sub('" & "', '', deobf)

        except:
            self.log.debug("Deobfuscator regex failure, reverting to original text")
            deobf = text

        return deobf

    #  note: we manually add up the score_section.score value here so that it is usable before the service finishes
    #        otherwise it is not calculated until finalize() is called on the top-level ResultSection
    def macro_scorer(self, text):
        self.log.debug("Macro scorer running")
        score_section = None

        try:
            vba_scanner = VBA_Scanner(text)
            vba_scanner.scan(include_decoded_strings=True)

            for string in self.ADDITIONAL_SUSPICIOUS_KEYWORDS:
                if re.search(string, text, re.IGNORECASE):
                    # play nice with detect_suspicious from olevba.py
                    vba_scanner.suspicious_keywords.append((string, 'May download files from the Internet'))

            stringcount = len(vba_scanner.autoexec_keywords) + len(vba_scanner.suspicious_keywords) + \
                len(vba_scanner.iocs)

            if stringcount > 0:
                score_section = ResultSection(SCORE.NULL, "Interesting macro strings found")

                if len(vba_scanner.autoexec_keywords) > 0:
                    subsection = ResultSection(min(self.MAX_STRING_SCORE,
                                                   SCORE.LOW * len(vba_scanner.autoexec_keywords)),
                                               "Autoexecution strings")

                    for keyword, description in vba_scanner.autoexec_keywords:
                        subsection.add_line(keyword)
                        subsection.add_tag(TAG_TYPE.OLE_MACRO_SUSPICIOUS_STRINGS,
                                           keyword, TAG_WEIGHT.HIGH,
                                           usage=TAG_USAGE.IDENTIFICATION)
                    score_section.add_section(subsection)

                if len(vba_scanner.suspicious_keywords) > 0:
                    subsection = ResultSection(min(self.MAX_STRING_SCORE,
                                                   SCORE.MED * len(vba_scanner.suspicious_keywords)),
                                               "Suspicious strings or functions")

                    for keyword, description in vba_scanner.suspicious_keywords:
                        subsection.add_line(keyword)
                        subsection.add_tag(TAG_TYPE.OLE_MACRO_SUSPICIOUS_STRINGS,
                                           keyword, TAG_WEIGHT.HIGH,
                                           usage=TAG_USAGE.IDENTIFICATION)
                    score_section.add_section(subsection)

                if len(vba_scanner.iocs) > 0:
                    subsection = ResultSection(min(500, SCORE.MED * len(vba_scanner.iocs)),
                                               "Potential host or network IOCs")

                    scored_macro_uri = False
                    for keyword, description in vba_scanner.iocs:
                        # olevba seems to have swapped the keyword for description during iocs extraction
                        # this holds true until at least version 0.27

                        subsection.add_line("{}: {}".format(keyword, description))
                        desc_ip = self.ip_re.match(description)
                        if self.parse_uri(description) is True:
                            scored_macro_uri = True
                        elif desc_ip:
                            ip_str = desc_ip.group(1)
                            if not is_ip_reserved(ip_str):
                                scored_macro_uri = True
                                subsection.add_tag(TAG_TYPE.NET_IP,
                                                   ip_str,
                                                   TAG_WEIGHT.HIGH,
                                                   usage=TAG_USAGE.CORRELATION)
                    score_section.add_section(subsection)
                    if scored_macro_uri and self.scored_macro_uri is False:
                        self.scored_macro_uri = True
                        scored_uri_section = ResultSection(score=500,
                                                           title_text="Found network indicator(s) within macros")
                        self.ole_result.add_section(scored_uri_section)

        except Exception as e:
            self.log.debug("OleVBA VBA_Scanner constructor failed: {}".format(str(e)))

        return score_section

    def rip_mhtml(self, data):
        if self.task.tag != 'document/office/mhtml':
            return

        mime_res = ResultSection(score=500,
                                 title_text="ActiveMime Document(s) in multipart/related")

        mhtml = email.message_from_string(data)
        # find all the attached files:
        for part in mhtml.walk():
            content_type = part.get_content_type()
            if content_type == "application/x-mso":
                part_data = part.get_payload(decode=True)
                if len(part_data) > 0x32 and part_data[:10].lower() == "activemime":
                    try:
                        part_data = zlib.decompress(part_data[0x32:])  # Grab  the zlib-compressed data
                        part_filename = part.get_filename(None) or hashlib.sha256(part_data).hexdigest()
                        part_path = os.path.join(self.working_directory, part_filename)
                        with open(part_path, 'w') as fh:
                            fh.write(part_data)
                        try:
                            mime_res.add_line(part_filename)
                            self.request.add_extracted(part_path, "ActiveMime x-mso from multipart/related.")
                        except Exception as e:
                            self.log.error("Error submitting extracted file: {}".format(e))
                    except Exception as e:
                        self.log.debug("Could not decompress ActiveMime part: {}".format(e))

        if len(mime_res.body) > 0:
            self.ole_result.add_section(mime_res)

    def process_ole10native(self, stream_name, data, streams_section):
        try:
            ole10native = Ole10Native(data)

            ole10_stream_file = os.path.join(self.working_directory,
                                             hashlib.sha256(ole10native.native_data).hexdigest())

            with open(ole10_stream_file, 'w') as fh:
                fh.write(ole10native.native_data)

            stream_desc = "{} ({}):\n\tFilename: {}\n\tData Length: {}".format(
                stream_name, ole10native.label, ole10native.filename, ole10native.native_data_size
            )
            streams_section.add_line(stream_desc)
            self.request.add_extracted(ole10_stream_file, "Embedded OLE Stream", stream_name)

            # handle embedded native macros
            if ole10native.label.endswith(".vbs") or \
                    ole10native.command.endswith(".vbs") or \
                    ole10native.filename.endswith(".vbs"):

                self.ole_result.add_tag(TAG_TYPE.TECHNIQUE_MACROS,
                                        "Contains Embedded VBA Macro(s)",
                                        weight=TAG_WEIGHT.LOW,
                                        usage=TAG_USAGE.IDENTIFICATION)

                self.all_vba.append(ole10native.native_data)
                macro_section = self.macro_section_builder(ole10native.native_data)
                toplevel_score = self.calculate_nested_scores(macro_section)

                self.all_macros.append(Macro(ole10native.native_data,
                                             hashlib.sha256(ole10native.native_data).hexdigest(),
                                             macro_section,
                                             toplevel_score))

            return True
        except Exception as e:
            self.log.debug("Failed to parse Ole10Native stream: {}".format(e))
            return False

    def process_powerpoint_stream(self, data, streams_section):
        try:
            powerpoint = PowerPointDoc(data)
            pp_line = "PowerPoint Document"
            if len(powerpoint.objects) > 0:
                streams_section.add_line(pp_line)
            for obj in powerpoint.objects:
                if obj.rec_type == "ExOleObjStg":
                    if obj.error is not None:
                        streams_section.add_line("\tError parsing ExOleObjStg stream. This is suspicious.")
                        streams_section.score += 50
                        continue

                    ole_hash = hashlib.sha256(obj.raw).hexdigest()
                    ole_obj_filename = os.path.join(self.working_directory,
                                                    "{}.pp_ole".format(ole_hash))
                    with open(ole_obj_filename, 'w') as fh:
                        fh.write(obj.raw)

                    streams_section.add_line(
                        "\tPowerPoint Embedded OLE Storage:\n\t\tSHA-256: {}\n\t\t"
                        "Length: {}\n\t\tCompressed: {}".format(
                            ole_hash, len(obj.raw), obj.compressed)
                    )
                    self.log.debug("Added OLE stream within a PowerPoint Document Stream: {}".format(ole_obj_filename))
                    self.request.add_extracted(ole_obj_filename,
                                               "Embedded OLE Storage within PowerPoint Document Stream",
                                               "ExeOleObjStg_{}".format(ole_hash)
                                               )
            return True
        except Exception as e:
            self.log.error("Failed to parse PowerPoint Document stream: {}".format(e))
            return False

    def process_ole_stream(self, ole, streams_section):
        listdir = ole.listdir()
        streams = []
        for dir_entry in listdir:
            streams.append('/'.join(dir_entry))

        if "\x05HwpSummaryInformation" in streams:
            decompress = True
        else:
            decompress = False

        decompress_macros = []

        for stream in streams:
            self.log.debug("Extracting stream: {}".format(stream))
            data = ole.openstream(stream).getvalue()
            try:

                if "Ole10Native" in stream:
                    if self.process_ole10native(stream, data, streams_section) is True:
                        continue

                elif "PowerPoint Document" in stream:
                    if self.process_powerpoint_stream(data, streams_section) is True:
                        continue

                if decompress:
                    try:
                        data = zlib.decompress(data, -15)
                    except zlib.error:
                        pass

                streams_section.add_line(safe_str(stream))
                # Only write all streams with deep scan.
                stream_name = '{}.ole_stream'.format(hashlib.sha256(data).hexdigest())
                if self.request.deep_scan:
                    stream_path = os.path.join(self.working_directory, stream_name)
                    with open(stream_path, 'w') as fh:
                        fh.write(data)
                    self.request.add_extracted(stream_path, "Embedded OLE Stream.", stream)
                    if decompress and (stream.endswith(".ps") or stream.startswith("Scripts/")):
                        decompress_macros.append(data)

            except Exception as e:
                self.log.error("Error adding extracted stream {}: {}".format(stream, e))
                continue
        if decompress_macros:
            macros = "\n".join(decompress_macros)
            stream_name = '{}.macros'.format(hashlib.sha256(macros).hexdigest())
            stream_path = os.path.join(self.working_directory, stream_name)
            with open(stream_path, 'w') as fh:
                fh.write(macros)

            self.request.add_extracted(stream_path, "Combined macros.", "all_macros.ps")
            return True
        return False

    # noinspection PyBroadException
    def extract_streams(self, file_name, file_contents):
        oles = {}
        try:
            streams_res = ResultSection(score=SCORE.INFO,
                                        title_text="Embedded document stream(s)")

            is_zip = False
            is_ole = False
            # Get the OLEs
            if zipfile.is_zipfile(file_name):
                is_zip = True
                z = zipfile.ZipFile(file_name)
                for f in z.namelist():
                    if f in oles:
                        continue
                    bin_data = z.open(f).read()
                    bin_fname = os.path.join(self.working_directory,
                                             "{}.tmp".format(hashlib.sha256(bin_data).hexdigest()))
                    with open(bin_fname, 'w') as bin_fh:
                        bin_fh.write(bin_data)
                    if olefile.isOleFile(bin_fname):
                        oles[f] = olefile.OleFileIO(bin_fname)
                    elif olefile2.isOleFile(bin_fname):
                        oles[f] = olefile2.OleFileIO(bin_fname)
                z.close()

            if olefile.isOleFile(file_name):
                is_ole = True
                oles[file_name] = olefile.OleFileIO(file_name)

            elif olefile2.isOleFile(file_name):
                is_ole = True
                oles[file_name] = olefile2.OleFileIO(file_name)

            if is_zip and is_ole:
                streams_res.report_heuristics(Oletools.AL_Oletools_002)

            decompressed_macros = False
            for ole_filename in oles.iterkeys():
                try:
                    decompressed_macros |= self.process_ole_stream(oles[ole_filename], streams_res)
                except Exception:
                    continue

            if decompressed_macros:
                streams_res.score = SCORE.HIGH

            for _, offset, rtfobject in rtf_iter_objects(file_contents):
                rtfobject_name = hex(offset) + '.rtfobj'
                extracted_obj = os.path.join(self.working_directory, rtfobject_name)
                with open(extracted_obj, 'wb') as fh:
                    fh.write(rtfobject)
                self.request.add_extracted(extracted_obj,
                                           'Embedded RTF Object at offset %s' % hex(offset),
                                           rtfobject_name)

            if len(streams_res.body) > 0:
                self.ole_result.add_section(streams_res)

        except Exception:
            self.log.debug("Error extracting streams: {}".format(traceback.format_exc(limit=2)))

        finally:
            for fd in oles.itervalues():
                try:
                    fd.close()
                except:
                    pass
