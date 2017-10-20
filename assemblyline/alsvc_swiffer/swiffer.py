import hashlib
import os
import re
import ssdeep
from collections import defaultdict
from textwrap import dedent

from datetime import datetime, timedelta
from subprocess import Popen, PIPE

from assemblyline.al.common.heuristics import Heuristic
from assemblyline.al.common.result import Result, ResultSection, SCORE, TAG_TYPE, TAG_WEIGHT
from assemblyline.al.service.base import ServiceBase

# For now, this is the set we analyze
SWF_TAGS = {
    40: 'NameCharacter',
    41: 'ProductInfo',
    56: 'ExportAssets',
    76: 'SymbolClass',
    82: 'DoABC',
    87: 'DefineBinaryData',
}


# noinspection PyBroadException
class Swiffer(ServiceBase):
    AL_Swiffer_001 = Heuristic("AL_Swiffer_001", "Large String Buffer", "audiovisual/flash",
                               dedent("""\
                                      Checks for printable character buffers larger than 512 bytes.
                                      """))

    AL_Swiffer_002 = Heuristic("AL_Swiffer_002", "Recent Compilation", "audiovisual/flash",
                               dedent("""\
                                      Checks if the SWF was compiled within the last 24 hours.
                                      """))

    AL_Swiffer_003 = Heuristic("AL_Swiffer_003", "Embedded Binary Data", "audiovisual/flash",
                               dedent("""\
                                      Checks if the SWF contains embedded binary data.
                                      """))
    AL_Swiffer_004 = Heuristic("AL_Swiffer_004", "Incomplete Disassembly", "audiovisual/flash",
                               dedent("""\
                                      Attempts disassembly and reports errors which may be indicative
                                      of intentional obfuscation.
                                      """))

    SERVICE_CATEGORY = 'Static Analysis'
    SERVICE_ACCEPTS = 'audiovisual/flash'
    SERVICE_DESCRIPTION = "This service extracts metadata and performs anomaly detection on SWF files."
    SERVICE_ENABLED = True
    SERVICE_VERSION = '1'
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_CPU_CORES = 0.05
    SERVICE_RAM_MB = 128

    SERVICE_DEFAULT_CONFIG = {
        'RABCDASM': r'/opt/al/support/swiffer/rabcdasm/rabcdasm',
    }

    def __init__(self, cfg=None):
        super(Swiffer, self).__init__(cfg)
        self.result = None
        self.request = None
        self.tag_analyzers = {
            'DoABC': self._do_abc,
            'DefineBinaryData': self._define_binary_data,
            'ExportAssets': self._export_assets,
            'NameCharacter': self._namecharacter,
            'ProductInfo': self._productinfo,
            'SymbolClass': self._symbolclass,
        }
        self.swf = None
        self.tag_summary = None
        self.symbols = None
        self.binary_data = None
        self.exported_assets = None
        self.big_buffers = None
        self.rabcdasm = self.cfg.get('RABCDASM')
        self.has_product_info = False
        self.anti_decompilation = False
        self.recent_compile = False
        self.disasm_path = None

    def start(self):
        self.log.debug("Service started")
        if not os.path.isfile(self.rabcdasm):
            self.rabcdasm = None

    def get_tool_version(self):
        return self.SERVICE_VERSION

    # noinspection PyGlobalUndefined,PyUnresolvedReferences
    def import_service_deps(self):
        global SWF, ProductKind, ProductEdition
        from swf.movie import SWF
        from swf.consts import ProductKind, ProductEdition

    def execute(self, request):
        self.request = request
        request.result = Result()
        self.result = self.request.result
        file_path = self.request.download()
        fh = open(file_path, 'rb')
        try:
            self.swf = SWF(fh)
            if self.swf is None:
                raise
        except:
            self.log.exception("Unable to parse srl %s:" % self.request.srl)
            fh.close()
            raise
        self.tag_summary = defaultdict(list)
        self.symbols = {}
        self.binary_data = {}
        self.exported_assets = []
        self.big_buffers = set()
        self.has_product_info = False
        self.anti_decompilation = False
        self.recent_compile = False
        self.disasm_path = None

        header_subsection = ResultSection(score=0, title_text="SWF Header")
        header_subsection.add_line("Version: %d" % self.swf.header.version)
        header_subsection.add_line("FileLength: %d" % self.swf.header.file_length)
        header_subsection.add_line("FrameSize: %s" % self.swf.header.frame_size.__str__())
        header_subsection.add_line("FrameRate: %d" % self.swf.header.frame_rate)
        header_subsection.add_line("FrameCount: %d" % self.swf.header.frame_count)
        self.result.add_section(header_subsection)

        # Parse Tags
        tag_types = []
        for tag in self.swf.tags:
            self.tag_analyzers.get(SWF_TAGS.get(tag.type), self._dummy)(tag)
            tag_types.append(str(tag.type))
        tag_list = ','.join(tag_types)
        tags_ssdeep = ssdeep.hash(tag_list)
        _, hash_one, hash_two = tags_ssdeep.split(':')
        self.result.add_tag(tag_type=TAG_TYPE.SWF_TAGS_SSDEEP, value=hash_one,
                            weight=TAG_WEIGHT.NULL)
        self.result.add_tag(tag_type=TAG_TYPE.SWF_TAGS_SSDEEP, value=hash_two,
                            weight=TAG_WEIGHT.NULL)
        # Script Overview
        if len(self.symbols.keys()) > 0:
            root_symbol = 'unspecified'
            if 0 in self.symbols:
                root_symbol = self.symbols[0]
                self.symbols.pop(0)
            symbol_subsection = ResultSection(score=SCORE.NULL, title_text="Symbol Summary")
            symbol_subsection.add_line('Main Timeline: %s' % root_symbol)
            if len(self.symbols.keys()) > 0:
                symbol_subsection.add_line('Other Symbols:')
                for tag_id, name in self.symbols.iteritems():
                    symbol_subsection.add_line('\tTagId: %s\tName: %s' % (tag_id, name))
            self.result.add_section(symbol_subsection)

        if len(self.binary_data.keys()) > 0:
            self.result.report_heuristic(Swiffer.AL_Swiffer_003)
            binary_subsection = ResultSection(score=SCORE.NULL, title_text="Attached Binary Data")
            for tag_id, tag_data in self.binary_data.iteritems():
                tag_name = self.symbols.get(tag_id, 'unspecified')
                binary_subsection.add_line('\tTagId: %s\tName: %s\tSize: %d' % (tag_id, tag_name, len(tag_data)))
                try:
                    binary_filename = hashlib.sha256(tag_data).hexdigest() + '.attached_binary'
                    binary_path = os.path.join(self.working_directory, binary_filename)
                    with open(binary_path, 'w') as fh:
                        fh.write(tag_data)
                    self.request.add_extracted(binary_path,
                                               "SWF Embedded Binary Data %d" % tag_id,
                                               tag_name)
                except:
                    self.log.exception("Error submitting embedded binary data for swf:")

            self.result.add_section(binary_subsection)

        tags_subsection = ResultSection(score=SCORE.INFO, title_text="Tags of Interest")
        for tag in sorted(self.tag_summary.keys()):
            tags_subsection.add_line(tag)
            summaries = self.tag_summary[tag]
            for summary in summaries:
                summary_line = '\t' + '\t'.join(summary)
                tags_subsection.add_line(summary_line)
            tags_subsection.add_line('')
        if len(tags_subsection.body) > 0:
            self.result.add_section(tags_subsection)

        if len(self.big_buffers) > 0:
            self.result.report_heuristic(Swiffer.AL_Swiffer_001)
            bbs = ResultSection(score=SCORE.HIGH, title_text="Large String Buffers")
            for buf in self.big_buffers:
                bbs.add_line("Found a %d byte string." % len(buf))
                buf_filename = ""
                try:
                    buf_filename = hashlib.sha256(buf).hexdigest() + '.stringbuf'
                    buf_path = os.path.join(self.working_directory, buf_filename)
                    with open(buf_path, 'w') as fh:
                        fh.write(buf)
                    self.request.add_extracted(buf_path, "AVM2 Large String Buffer.")
                except:
                    self.log.exception("Error submitting AVM2 String Buffer %s" % buf_filename)
            self.result.add_section(bbs)

        if not self.has_product_info:
            self.log.debug("Missing product info.")
            no_info = ResultSection(score=SCORE.INFO, title_text="Missing Product Information")
            no_info.add_line("This SWF doesn't specify information about the product that created it.")
            self.result.add_section(no_info)

        if self.anti_decompilation:
            self.result.report_heuristic(Swiffer.AL_Swiffer_004)
            self.log.debug("Anti-disassembly techniques may be present.")
            no_dis = ResultSection(score=SCORE.LOW,title_text="Incomplete Disassembly")
            no_dis.add_line("This SWF may contain intentional corruption or obfuscation to prevent disassembly.")

            self.result.add_section(no_dis)

        if self.recent_compile:
            recent_compile = ResultSection(score=SCORE.LOW, title_text="Recent Compilation")
            recent_compile.add_line("This SWF was compiled within the last 24 hours.")
            self.result.add_section(recent_compile)
            self.result.report_heuristic(Swiffer.AL_Swiffer_002)

        fh.close()

    def analyze_asasm(self, asm):
        # Check for large string buffers
        big_buff_re = r'([A-Za-z0-9+/=]{512,})[^A-Za-z0-9+/=]'
        for buf in re.finditer(big_buff_re, asm):
            self.big_buffers.add(buf.group(1))

        # Check for incomplete decompilation (obfuscation or intentional corruption)
        hexbytes = re.findall(r';\s+0x[A-F0-9]{2}', asm)
        if len(hexbytes) > 10:
            self.anti_decompilation = True

    def analyze_abc(self, a_bytes):
        # Drop the file and disassemble
        abc_path = ""
        try:
            abc_hash = hashlib.sha256(a_bytes).hexdigest()
            abc_filename = abc_hash + '.abc'
            abc_path = os.path.join(self.working_directory, abc_filename)
            disasm_path = os.path.join(self.working_directory, abc_hash)
            with open(abc_path, 'w') as fh:
                fh.write(a_bytes)
            rabcdasm = Popen([self.rabcdasm, abc_path], stdout=PIPE, stderr=PIPE)
            stdout, _ = rabcdasm.communicate()
            # rabcdasm makes a directory from the filename.
            if os.path.isdir(disasm_path):
                for root, dirs, file_names in os.walk(disasm_path):
                    for file_name in file_names:
                        asasm_path = os.path.join(root, file_name)
                        with open(asasm_path, 'r') as fh:
                            self.analyze_asasm(fh.read())
                self.disasm_path = disasm_path
        except:
            self.log.exception("Error disassembling abc file %s:" % abc_path)

    def _do_abc(self, tag):
        self.tag_summary['DoABC'].append(("Name: %s" % tag.abcName, "Length: %d" % len(tag.bytes)))
        if self.rabcdasm:
            self.analyze_abc(tag.bytes)

    def _define_binary_data(self, tag):
        self.binary_data[tag.characterId] = tag.data

    def _export_assets(self, tag):
        if not hasattr(tag, 'exports'):
            return
        for export in tag.exports:
            export_tup = ("Character ID: %s" % export.characterId, "Name: %s" % export.characterName)
            if export_tup not in self.exported_assets:
                self.tag_summary['ExportAssets'].append(export_tup)
                self.exported_assets.append(export_tup)

    def _namecharacter(self, tag):
        self.tag_summary['NameCharacter'].append(("Character ID: %s" % tag.characterId,
                                                  "Name: %s" % tag.characterName))

    def _symbolclass(self, tag):
        for symbol in tag.symbols:
            self.symbols[symbol.tagId] = symbol.name

    def _productinfo(self, tag):
        self.has_product_info = True

        if hasattr(tag, 'compileTime'):
            try:
                compile_time = datetime.fromtimestamp(tag.compileTime / 1000)
                compile_time_str = compile_time.ctime()
                # Flag recent compile time:
                if (datetime.now() - compile_time) < timedelta(hours=24):
                    self.recent_compile = True
            except:
                compile_time_str = "Invalid Compile Time: %s" % repr(tag.compileTime)
        else:
            compile_time_str = 'Missing'

        self.tag_summary['ProductInfo'].append(
            ("Product: %s" % ProductKind.tostring(tag.product),
             "Edition: %s" % ProductEdition.tostring(tag.edition),
             "Version (Major.Minor.Build): %d.%d.%d" % (tag.majorVersion, tag.minorVersion, tag.build),
             "Compile Time: %s" % compile_time_str)
        )

    def _dummy(self, tag):
        pass
