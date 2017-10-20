from __future__ import absolute_import
import __builtin__
import re

from textwrap import dedent

from assemblyline.common.charset import translate_str
from assemblyline.al.common.heuristics import Heuristic
from assemblyline.al.common.result import Result, ResultSection, SCORE
from assemblyline.al.common.result import TAG_TYPE as FC_VALUE_TYPE
from assemblyline.al.common.result import TAG_WEIGHT as TAG_SCORE
from assemblyline.al.service.base import ServiceBase
from al_services.alsvc_cleaver.codepages import CODEPAGE_MAP

# Initialize imports
createParser = None
guessParser = None
OfficeRootEntry = None
FragmentGroup = None
MissingField = None
Int8 = None
RawBytes = None
ParserError = None
HEADER_SIZE = None
CompObj = None
SummaryParser = None
PropertyContent = None
PropertyIndex = None
SummaryFieldSet = None
extractMetadata = None
RootSeekableFieldSet = None
hachoir_log = None
getBacktrace = None
WordDocumentFieldSet = None
StringInputStream = None
hachoir_config = None
DummyObject = None
decode_lnk = None


# Next, we have hijack the hachoir_parser.misc.msoffice.OfficeRootEntry.parseProperty
# function to fix a problem, see the code below.
# noinspection PyPep8Naming,PyCallingNonCallable
def myParseProperty(self, property_index, p_property, name_prefix):
    ole2 = self.ole2
    if not p_property["size"].value:
        return
    if p_property["size"].value >= ole2["header/threshold"].value:
        return
    name = "%s[]" % name_prefix
    first = None
    previous = None
    size = 0
    start = p_property["start"].value
    chain = ole2.getChain(start, True)
    blocksize = ole2.ss_size
    desc_format = "Small blocks %s..%s (%s)"
    while True:
        try:
            block = chain.next()
            contiguous = False
            # buggy line: if not first:
            if first is None:  # <-- fixed line
                first = block
                contiguous = True
            # buggy line: if previous and block == (previous+1):
            if previous is not None and block == (previous + 1):  # <-- fixed line
                contiguous = True
            if contiguous:
                previous = block
                size += blocksize
                continue
        except StopIteration:
            block = None
        self.seekSBlock(first)
        desc = desc_format % (first, previous, previous - first + 1)
        size = min(size, p_property["size"].value * 8)
        if name_prefix in ("summary", "doc_summary"):
            yield SummaryFieldSet(self, name, desc, size=size)
        elif name_prefix == "word_doc":
            yield WordDocumentFieldSet(self, name, desc, size=size)
        elif property_index == 1:
            yield CompObj(self, "comp_obj", desc, size=size)
        else:
            yield RawBytes(self, name, size // 8, desc)
        if block is None:
            break
        first = block
        previous = block
        size = ole2.sector_size


# We have hijack the hachoir_parser.misc.msoffice.FragmentGroup.createInputStream
# function to fix a problem, see the code below.
# noinspection PyPep8Naming,PyCallingNonCallable
def myCreateInputStream(self):
    # FIXME: Use lazy stream creation
    data = []
    for item in self.items:
        # bug here by not checking for None
        if item["rawdata"].value is not None:
            data.append(item["rawdata"].value)
    data = "".join(data)

    # FIXME: Use smarter code to send arguments
    args = {"ole2": self.items[0].root}
    tags = {"class": self.parser, "args": args}
    tags = tags.iteritems()
    return StringInputStream(data, "<fragment group>", tags=tags)


# noinspection PyUnresolvedReferences,PyShadowingNames
def do_delayed_imports():
    global createParser, guessParser, OfficeRootEntry, FragmentGroup, MissingField, Int8, RawBytes, ParserError, \
        HEADER_SIZE, CompObj, SummaryParser, PropertyContent, PropertyIndex, SummaryFieldSet, extractMetadata, \
        RootSeekableFieldSet, hachoir_log, getBacktrace, WordDocumentFieldSet, StringInputStream
    from hachoir_parser.guess import createParser, guessParser
    from hachoir_parser.misc.msoffice import OfficeRootEntry, FragmentGroup
    from hachoir_core.field.field import MissingField
    from hachoir_core.field import Int8, RawBytes
    from hachoir_core.field.basic_field_set import ParserError
    from hachoir_parser.misc.ole2 import HEADER_SIZE
    from hachoir_parser.misc.msoffice_summary import CompObj, SummaryParser, PropertyContent, PropertyIndex, \
        SummaryFieldSet
    from hachoir_metadata import extractMetadata
    from hachoir_core.field.seekable_field_set import RootSeekableFieldSet
    from hachoir_core.log import log as hachoir_log
    from hachoir_core.error import getBacktrace
    from hachoir_parser.misc.word_doc import WordDocumentFieldSet
    from hachoir_core.stream.input import StringInputStream
    import hachoir_parser.version
    import hachoir_core.version
    import hachoir_metadata.version
    import hachoir_core.config as hachoir_config
    from al_services.alsvc_cleaver.parse_lnk import decode_lnk

    FragmentGroup.createInputStream = myCreateInputStream
    OfficeRootEntry.parseProperty = myParseProperty

    PropertyIndex.DOCUMENT_PROPERTY[17] = "NumOfChars"
    # noinspection PyBroadException
    try:
        del PropertyIndex.DOCUMENT_PROPERTY[18]
    except:
        pass
    PropertyIndex.DOCUMENT_PROPERTY[19] = "SharedDoc"
    PropertyIndex.DOCUMENT_PROPERTY[20] = "LinkBase"
    PropertyIndex.DOCUMENT_PROPERTY[21] = "HLinks"
    PropertyIndex.DOCUMENT_PROPERTY[22] = "HyperLinksChanged"
    PropertyIndex.DOCUMENT_PROPERTY[23] = "Version"
    PropertyIndex.DOCUMENT_PROPERTY[24] = "VBASignature"
    PropertyIndex.DOCUMENT_PROPERTY[26] = "ContentType"
    PropertyIndex.DOCUMENT_PROPERTY[27] = "ContentStatus"
    PropertyIndex.DOCUMENT_PROPERTY[28] = "Language"
    PropertyIndex.DOCUMENT_PROPERTY[29] = "DocVersion"

    class DummyObject(Int8):
        # noinspection PyPep8Naming,PyMethodMayBeStatic
        def createValue(self):
            return 66

    for k, v in locals().iteritems():
        globals()[k] = v


#
# hachoirOpenFileHelper() & hachoirCloseFileHelper() are used to workaround defect #33 
# in hachoir that results in file handles being left open
#
realOpenFunction = None
hachoirOpenedFiles = {}


# noinspection PyPep8Naming
def hachoirOpenFileHelper(name, mode='r', buffering=-1):
    global realOpenFunction
    if realOpenFunction is None:
        raise Exception("*** Error: realOpenFunction() was not assigned! ***")
    fd = realOpenFunction(name, mode, buffering)
    hachoirOpenedFiles[name] = fd
    return fd


# noinspection PyPep8Naming
def hachoirCloseFileHelper(name):
    # noinspection PyBroadException
    try:
        fd = hachoirOpenedFiles[name]
        fd.close()
        return
    except:
        pass


#########################################################
#                  Scan Execution Class                 #
#########################################################
# noinspection PyPep8Naming,PyShadowingBuiltins,PyCallingNonCallable,PyTypeChecker
class Cleaver(ServiceBase):
    AL_Cleaver_001 = Heuristic("AL_Cleaver_001", "OLE_SUMMARY_CODEPAGE", ".*",
                               dedent("""\
                                      Identifying the CodePage for the file. Used for identification 
                                      purposes.
                                      """))
    AL_Cleaver_002 = Heuristic("AL_Cleaver_002", "OLE_SUMMARY_LASTPRINTED", ".*", "")
    AL_Cleaver_003 = Heuristic("AL_Cleaver_003", "OLE_SUMMARY_CREATETIME", ".*", "")
    AL_Cleaver_004 = Heuristic("AL_Cleaver_004", "OLE_SUMMARY_LASTSAVEDTIME", ".*", "")
    AL_Cleaver_005 = Heuristic("AL_Cleaver_005", "OLE_SUMMARY_TITLE", ".*", "")
    AL_Cleaver_006 = Heuristic("AL_Cleaver_006", "OLE_SUMMARY_SUBJECT", ".*", "")
    AL_Cleaver_007 = Heuristic("AL_Cleaver_007", "OLE_SUMMARY_AUTHOR", ".*", "")
    AL_Cleaver_008 = Heuristic("AL_Cleaver_008", "OLE_SUMMARY_SUBJECT", ".*", "")
    AL_Cleaver_009 = Heuristic("AL_Cleaver_009", "OLE_SUMMARY_COMMENTS", ".*", "")
    AL_Cleaver_010 = Heuristic("AL_Cleaver_010", "OLE_SUMMARY_LASTSAVEDBY", ".*", "")
    AL_Cleaver_011 = Heuristic("AL_Cleaver_011", "OLE_SUMMARY_MANAGER", ".*", "")
    AL_Cleaver_012 = Heuristic("AL_Cleaver_012", "OLE_SUMMARY_COMPANY", ".*", "")
    AL_Cleaver_013 = Heuristic("AL_Cleaver_013", "Root[0] Does Not Exist", ".*", "")
    AL_Cleaver_014 = Heuristic("AL_Cleaver_014", "CLSID Not Null GUID", ".*",
                               dedent("""\
                                      For a root or storage class ID, checking to see if it isn't an 
                                      NULL GUID
                                          
                                          GUID: 00000000-0000-0000-0000-000000000000
                                      """))
    AL_Cleaver_015 = Heuristic("AL_Cleaver_015", "OLE Creation Time", ".*",
                               dedent("""\
                                      Checking the creation time stamp against the standard 
                                      1601-01-01 00:00:00. If they don't match the time will be noted to 
                                      the user.
                                      """))
    AL_Cleaver_016 = Heuristic("AL_Cleaver_016", "OLE Lastmod Time", ".*",
                               dedent("""\
                                      Checking the lastmod time stamp against the standard 
                                      1601-01-01 00:00:00. If they don't match the time will be noted to 
                                      the user.
                                      """))
    AL_Cleaver_017 = Heuristic("AL_Cleaver_017", "CompObj", ".*",
                               dedent("""\
                                      Check if the name is CompObj and the type of the file is not 
                                      stream type
                                      """))
    AL_Cleaver_018 = Heuristic("AL_Cleaver_018", "Missing Field", ".*",
                               dedent("""\
                                      This is caused when an error is thrown when Hachoir lib could not 
                                      get a field from the file. This file is either corrupted, patched or
                                      exploiting a vulnerability.
                                      """))
    AL_Cleaver_019 = Heuristic("AL_Cleaver_019", "Cannot Find Property of Type", ".*",
                               dedent("""\
                                      This is caused when a parser error is thrown when Hachoir lib could 
                                      not parse a property from the file. This file is either corrupted, 
                                      patched or exploiting a vulnerability.
                                      """))
    AL_Cleaver_020 = Heuristic("AL_Cleaver_020", "Overflowing Field", ".*",
                               dedent("""\
                                      This is caused when a parser error is thrown when Hachoir lib could 
                                      not read a field from the file since it it overflowing. This file is
                                      either corrupted, patched or exploiting a vulnerability
                                      """))
    AL_Cleaver_021 = Heuristic("AL_Cleaver_021", "Could not Access Field", ".*",
                               dedent("""\
                                      This is caused when a parser error is thrown when Hachoir lib could 
                                      not access a field from the file. This file is either corrupted, 
                                      patched or exploiting a vulnerability.
                                      """))
    AL_Cleaver_022 = Heuristic("AL_Cleaver_022", "FAT Chain - Loop", ".*",
                               dedent("""\
                                      This is caused when a parser error is thrown when Hachoir lib found 
                                      a loop when navigating through the file. It should be either BFAT or
                                      SFAT. This file is either corrupted, patched or exploiting a 
                                      vulnerability.
                                      """))
    AL_Cleaver_023 = Heuristic("AL_Cleaver_023", "SFAT Invalid Block Index", ".*",
                               dedent("""\
                                      This is caused when a parser error is thrown when Hachoir lib finds 
                                      an invalid block index in the file. This file is either corrupted, 
                                      patched or exploiting a vulnerability
                                      """))
    AL_Cleaver_024 = Heuristic("AL_Cleaver_024", "OLE2: Invalid endian value", ".*",
                               dedent("""\
                                      The stream endian field is not valid.  This file is either 
                                      corrupted, patched or exploiting a vulnerability
                                      """))
    AL_Cleaver_025 = Heuristic("AL_Cleaver_025", "Failure to Parse Whole File", ".*",
                               dedent("""\
                                      The Hachoir lib wasn't able to parse the whole file for some unknown
                                      reason.
                                      """))

    SERVICE_CATEGORY = 'Static Analysis'
    SERVICE_DESCRIPTION = "This service extracts metadata from files, mostly OLE2 files," \
                          " using python's hachoir library."
    SERVICE_ENABLED = True
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'

    SERVICE_CPU_CORES = 0.25
    SERVICE_RAM_MB = 128

    def __init__(self, cfg=None):
        super(Cleaver, self).__init__(cfg)
        do_delayed_imports()

        self.additional_parsing_fields = {}
        self.ole2parser = None
        self.office_root_entry_parser = None
        self.children = {}
        self.parent = {}
        self.property_dict = {}
        self.current_file_res = None
        self.relative_path = ""
        self.filename = ""
        self.current_section = None
        self.current_codepage = None
        hachoir_log.use_buffer = True
        self.invalid_streams = []
        self.invalid_properties_count = 0
        self.bad_link_re = None

    def start(self):
        self.bad_link_re = re.compile("http[s]?://|powershell|cscript|wscript|mshta|<script")

    def get_parser(self, field_type):
        # from ol2 parser
        if field_type == 'Property':
            return self.parse_property
        elif field_type == 'CustomFragment':
            return self.parse_custom_fragment

        # from msoffice_summary parser
        elif field_type == 'SummaryFieldSet':
            return self.parse_summary_field_set
        elif field_type == 'SummarySection':
            return self.parse_summary_section
        elif field_type == 'PropertyContent':
            return self.parse_property_content
        elif field_type == 'CompObj':
            return self.parse_comp_obj

        elif field_type == 'SummaryParser':
            return self.parse_summary_field_set

    PARSING_MODE_CACHE = 0
    PARSING_MODE_DISPLAY = 1

    GUID_DESC = {
        "GUID v0 (0): 00020803-0000-0000-C000-000000000046": "Microsoft Graph Chart",
        "GUID v0 (0): 00020900-0000-0000-C000-000000000046": "Microsoft Word95",
        "GUID v0 (0): 00020901-0000-0000-C000-000000000046": "Microsoft Word 6.0 - 7.0 Picture",
        "GUID v0 (0): 00020906-0000-0000-C000-000000000046": "Microsoft Word97",
        "GUID v0 (0): 00020907-0000-0000-C000-000000000046": "Microsoft Word",

        "GUID v0 (0): 00020C01-0000-0000-C000-000000000046": "Excel",
        "GUID v0 (0): 00020821-0000-0000-C000-000000000046": "Excel",
        "GUID v0 (0): 00020820-0000-0000-C000-000000000046": "Excel97",
        "GUID v0 (0): 00020810-0000-0000-C000-000000000046": "Excel95",

        "GUID v0 (0): 00021a14-0000-0000-C000-000000000046": "Visio",
        "GUID v0 (0): 0002CE02-0000-0000-C000-000000000046": "Microsoft Equation 3.0",

        "GUID v0 (0): 0003000A-0000-0000-C000-000000000046": "Paintbrush Picture",

        "GUID v0 (0): 0003000C-0000-0000-C000-000000000046": "Package",

        "GUID v0 (0): 000C1082-0000-0000-C000-000000000046": "Transform (MST)",
        "GUID v0 (0): 000C1084-0000-0000-C000-000000000046": "Installer Package (MSI)",

        "GUID v0 (0): 00020D0B-0000-0000-C000-000000000046": "MailMessage",

        "GUID v1 (Timestamp & MAC-48): 29130400-2EED-1069-BF5D-00DD011186B7": "Lotus WordPro",
        "GUID v1 (Timestamp & MAC-48): 46E31370-3F7A-11CE-BED6-00AA00611080": "Microsoft Forms 2.0 MultiPage",
        "GUID v1 (Timestamp & MAC-48): 5512D110-5CC6-11CF-8D67-00AA00BDCE1D": "Microsoft Forms 2.0 HTML SUBMIT",
        "GUID v1 (Timestamp & MAC-48): 5512D11A-5CC6-11CF-8D67-00AA00BDCE1D": "Microsoft Forms 2.0 HTML TEXT",
        "GUID v1 (Timestamp & MAC-48): 5512D11C-5CC6-11CF-8D67-00AA00BDCE1D": "Microsoft Forms 2.0 HTML Hidden",
        "GUID v1 (Timestamp & MAC-48): 64818D10-4F9B-11CF-86EA-00AA00B929E8": "Microsoft PowerPoint Presentation",
        "GUID v1 (Timestamp & MAC-48): 64818D11-4F9B-11CF-86EA-00AA00B929E8": "Microsoft PowerPoint Presentation",
        "GUID v1 (Timestamp & MAC-48): 11943940-36DE-11CF-953E-00C0A84029E9": "Microsoft Photo Editor 3.0 Photo",
        "GUID v1 (Timestamp & MAC-48): D27CDB6E-AE6D-11CF-96B8-444553540000": "Shockwave Flash",
        "GUID v1 (Timestamp & MAC-48): 8BD21D40-EC42-11CE-9E0D-00AA006002F3": "Active X Checkbox",
        "GUID v1 (Timestamp & MAC-48): 8BD21D50-EC42-11CE-9E0D-00AA006002F3": "Active X Radio Button",
        "GUID v1 (Timestamp & MAC-48): B801CA65-A1FC-11D0-85AD-444553540000": "Adobe Acrobat Document",
        "GUID v1 (Timestamp & MAC-48): A25250C4-50C1-11D3-8EA3-0090271BECDD": "WordPerfect Office",
        "GUID v1 (Timestamp & MAC-48): C62A69F0-16DC-11CE-9E98-00AA00574A4F": "Microsoft Forms 2.0 Form"
    }

    def parse_summary_field_set(self, field, res, mode, file_res):
        if mode == self.PARSING_MODE_CACHE:
            # when we get here, we assume it's because we are using the short block,
            # otherwise, this is set somewhere else

            # we first get the offset from the short block but then we
            # need to map it back to the file, which is from root[X].
            # offset = field['start'].value * self.ole2parser.ss_size
            # noinspection PyProtectedMember
            offset = field._getAbsoluteAddress()
            keep_looping = True
            root_index = 0
            address = 0
            while keep_looping:
                current_root = self.ole2parser['root[%d]' % root_index]

                if offset == 0 or current_root.size > offset:
                    address = current_root.address + offset
                    keep_looping = False
                else:
                    offset -= current_root.size
                    root_index += 1
            self.additional_parsing_fields[address] = field

        elif mode == self.PARSING_MODE_DISPLAY:
            self.parse_field_name('section', field, True, res, mode, file_res, field['section_count'].value)

    def parse_summary_section(self, field, res, mode, file_res):
        self.current_codepage = None
        section_index = field.name[field.name.find('[') + 1:field.name.find(']')]
        section_index_field = field['../section_index[%s]/name' % section_index]

        if section_index_field.value == u"\xe0\x85\x9f\xf2\xf9\x4f\x68\x10\xab\x91\x08\x00\x2b\x27\xb3\xd9":
            self.current_section = PropertyIndex.COMPONENT_PROPERTY
        elif section_index_field.value == u"\x02\xd5\xcd\xd5\x9c\x2e\x1b\x10\x93\x97\x08\x00\x2b\x2c\xf9\xae":
            self.current_section = PropertyIndex.DOCUMENT_PROPERTY
        elif section_index_field.value == u"\x05\xd5\xcd\xd5\x9c\x2e\x1b\x10\x93\x97\x08\x00\x2b\x2c\xf9\xae":
            # FMTID_UserDefinedProperties
            self.current_section = None
        else:
            self.current_section = None
            unknown_guid = ""
            for c in section_index_field.value:
                unknown_guid += "%s " % hex(ord(c))

            self.log.warning("Unknown_guid: %s %s/%s", unknown_guid, self.task.sid, self.task.srl)

        self.parse_field_name('property', field, True, res, mode, file_res, field['property_count'].value)

    # noinspection PyUnusedLocal
    def parse_property_content(self, field, res, mode, file_res):
        property_index = field.name[field.name.find('[') + 1:field.name.find(']')]
        property_index_field = field['../property_index[%s]/id' % property_index]

        if self.current_section is not None and property_index_field.value in self.current_section:
            description = self.current_section[property_index_field.value]
        else:
            description = "unknown_property_type: %d" % property_index_field.value

        if description == "CodePage":
            self.current_codepage = field.display

            if field.display in CODEPAGE_MAP:
                code_page_desc = CODEPAGE_MAP[field.display]
            else:
                code_page_desc = "unknown"
                self.log.info("Unknown code page: %s %s/%s", field.display, self.task.sid, self.task.srl)

            res.add_line("%s: %s (%s)" % (description, field.display, code_page_desc))
            file_res.add_tag(FC_VALUE_TYPE['OLE_SUMMARY_CODEPAGE'], field.display, TAG_SCORE['LOW'], 'IDENTIFICATION')
            file_res.report_heuristic(Cleaver.AL_Cleaver_001)

        elif (description in ("LastPrinted", "CreateTime", "LastSavedTime") and len(field.display) > 0 and
                field.display != "1601-01-01 00:00:00" and field.display != 'None' and field.display != 'False'):
            res.add_line("%s: %s" % (description, field.display))

            if description == 'LastPrinted':
                file_res.add_tag(FC_VALUE_TYPE['OLE_SUMMARY_LASTPRINTED'], field.display, TAG_SCORE['MED'])
                file_res.report_heuristic(Cleaver.AL_Cleaver_002)
            elif description == 'CreateTime':
                file_res.add_tag(FC_VALUE_TYPE['OLE_SUMMARY_CREATETIME'], field.display, TAG_SCORE['MED'])
                file_res.report_heuristic(Cleaver.AL_Cleaver_003)
            elif description == 'LastSavedTime':
                file_res.add_tag(FC_VALUE_TYPE['OLE_SUMMARY_LASTSAVEDTIME'], field.display, TAG_SCORE['MED'])
                file_res.report_heuristic(Cleaver.AL_Cleaver_004)
        else:
            value = field.display
            if self.current_codepage is not None:
                try:
                    # 1. go from unicode str to str:
                    str_value = ""
                    for value_char in value:
                        str_value = "%s%c" % (str_value, ord(value_char))

                    # 2. now we can promote to unicode properly:
                    value = unicode(str_value, self.current_codepage)
                except UnicodeEncodeError:
                    value = field.display
                except LookupError:
                    value = field.display
                except OverflowError:
                    value = field.display

            # if the value has an end of string, remove it.
            value = value.strip('\x00')

            res.add_line("%s: '%s'" % (description, value))

            if len(value) > 0 and field.display.count('\0') != len(field.display):
                tag_score = TAG_SCORE.MED
                if description == 'Title':
                    file_res.add_tag(FC_VALUE_TYPE['OLE_SUMMARY_TITLE'], value, tag_score)
                    file_res.report_heuristic(Cleaver.AL_Cleaver_005)
                elif description == 'Subject':
                    file_res.add_tag(FC_VALUE_TYPE['OLE_SUMMARY_SUBJECT'], value, tag_score)
                    file_res.report_heuristic(Cleaver.AL_Cleaver_006)
                elif description == 'Author':
                    file_res.add_tag(FC_VALUE_TYPE['OLE_SUMMARY_AUTHOR'], value, tag_score)
                    file_res.report_heuristic(Cleaver.AL_Cleaver_007)
                elif description == 'Subject':
                    file_res.add_tag(FC_VALUE_TYPE['OLE_SUMMARY_SUBJECT'], value, tag_score)
                    file_res.report_heuristic(Cleaver.AL_Cleaver_008)
                elif description == 'Comments':
                    file_res.add_tag(FC_VALUE_TYPE['OLE_SUMMARY_COMMENTS'], value, tag_score)
                    file_res.report_heuristic(Cleaver.AL_Cleaver_009)
                elif description == 'LastSavedBy':
                    file_res.add_tag(FC_VALUE_TYPE['OLE_SUMMARY_LASTSAVEDBY'], value, tag_score)
                    file_res.report_heuristic(Cleaver.AL_Cleaver_010)
                elif description == 'Manager':
                    file_res.add_tag(FC_VALUE_TYPE['OLE_SUMMARY_MANAGER'], value, tag_score)
                    file_res.report_heuristic(Cleaver.AL_Cleaver_011)
                elif description == 'Company':
                    file_res.add_tag(FC_VALUE_TYPE['OLE_SUMMARY_COMPANY'], value, tag_score)
                    file_res.report_heuristic(Cleaver.AL_Cleaver_012)
        return True

    # noinspection PyUnusedLocal
    @staticmethod
    def parse_comp_obj(field, res, mode, file_res):
        try:
            user_type = field["user_type"]
            user_type_value = user_type.value.encode(user_type.charset)
            char_enc_guessed = translate_str(user_type_value)

            res.add_line("User_type (enc: '%s' / confidence: %f): '%s'"
                         % (char_enc_guessed['encoding'],
                            char_enc_guessed['confidence'],
                            char_enc_guessed['converted']))
            res.add_line("Prog_id: %s" % field["prog_id"].value)
            if field['user_type_unicode'].display != 'None':
                res.add_line("User_type_unicode: %s" % field["user_type_unicode"].display)
            if field['prog_id_unicode'].display != 'None':
                res.add_line("Prog_id_unicode: %s" % field["prog_id_unicode"].display)
            return True
        except MissingField, e:
            pass

    # noinspection PyPep8Naming,PyShadowingBuiltins
    def dump_property(self, field, path, index, res, file_res, isOrphan):
        if field['name'].value != '':
            name = field['name'].display[1:-1]
            type = field['type'].value

            if path[-1:] == '\\':
                abs_name = "%s%s" % (path, name)
            else:
                abs_name = "%s\\%s" % (path, name)

            prop_res = ResultSection(title_text="Property: %s" % abs_name)

            # if type is not: 1- storage, 2- stream an not 5- root, that is weird.
            if type != 1 and type != 2 and type != 5:
                self.invalid_properties_count += 1

            # for properties not storage (which should be seen like a folder)
            if type != 1:
                size = field['size'].value
            else:
                size = 0

            address = 0
            if size > 0:
                if field['size'].value < self.ole2parser['header/threshold'].value and index != '0':
                    # we first get the offset from the short block but then we need
                    # to map it back to the file, which is from root[X].
                    offset = field['start'].value * self.ole2parser.ss_size
                    keep_looping = True
                    root_index = 0
                    while keep_looping:
                        try:
                            current_root = self.ole2parser['root[%d]' % root_index]

                            if offset == 0 or current_root.size > offset:
                                address = current_root.address + offset
                                keep_looping = False
                            else:
                                offset -= current_root.size
                                root_index += 1

                        except MissingField:
                            keep_looping = False
                            address = None
                            if not isOrphan:
                                self.invalid_streams.append(field['name'].display)
                else:
                    address = HEADER_SIZE + field['start'].value * self.ole2parser.sector_size
            else:
                address = 0

            if address >= 0:
                prop_res.add_line("(offset: 0x%X size: 0x%X / %s / %s / id=%s left=%s right=%s child=%s)" % (
                    address // 8, size, field['type'].display, field['decorator'].display, index, field['left'].display,
                    field['right'].display, field['child'].display))
            else:
                prop_res.add_line("(offset: 'Could not map' size: 0x%X / %s / %s / id=%s left=%s right=%s child=%s)" % (
                    size, field['type'].display, field['decorator'].display, index, field['left'].display,
                    field['right'].display, field['child'].display))

            # for root or storage
            if type == 5 or type == 1:
                if field['clsid'].display != "Null GUID: 00000000-0000-0000-0000-000000000000":
                    clsid_desc = self.GUID_DESC.get(field['clsid'].display, "unknown clsid")
                    prop_res.add_line("Clsid: %s (%s)" % (field['clsid'].display, clsid_desc))
                    file_res.add_tag(FC_VALUE_TYPE['OLE_CLSID'], field['clsid'].display, TAG_SCORE['LOW'],
                                     'IDENTIFICATION')
                    file_res.report_heuristic(Cleaver.AL_Cleaver_014)
                if field['creation'].display != "1601-01-01 00:00:00":
                    prop_res.add_line("Creation: %s" % field['creation'].display)
                    file_res.add_tag(FC_VALUE_TYPE['OLE_CREATION_TIME'], field['creation'].display, TAG_SCORE['MED'])
                    file_res.report_heuristic(Cleaver.AL_Cleaver_015)
                if field['lastmod'].display != "1601-01-01 00:00:00":
                    prop_res.add_line("Lastmod: %s" % field['lastmod'].display)
                    file_res.add_tag(FC_VALUE_TYPE['OLE_LASTMOD_TIME'], field['lastmod'].display, TAG_SCORE['MED'])
                    file_res.report_heuristic(Cleaver.AL_Cleaver_016)

            # fixe up a bug:
            if name == '\\1CompObj':
                # noinspection PyBroadException
                try:
                    if type != 2:
                        res_error = ResultSection(SCORE.MED,
                                                  "\\1CompObj type is '%d' and it should be 1 (stream) "
                                                  "... really suspicious." % type)
                        # ScanExecution.current_execution.current_file_res.add_result(res_error)
                        file_res.add_result(res_error)
                        file_res.report_heuristic(Cleaver.AL_Cleaver_017)
                        size = field['size'].value

                    # Apparently, we can get to this point and have office_root_entry_parser set to None.
                    # Not sure what we should do about that but trying to use that member variable seems
                    # like a bad idea...
                    if self.office_root_entry_parser is not None:
                        self.office_root_entry_parser.seekSBlock(field['start'].value)
                        compObj_field = CompObj(self.office_root_entry_parser, "comp_obj", "TEST", size * 8)

                        # cache all the sub-fields....
                        for _ in compObj_field:
                            pass

                        self.parse_field(compObj_field, prop_res, self.PARSING_MODE_DISPLAY, file_res)
                except:
                    pass

            if size > 0 and index != '0':
                field_with_other_parser = self.additional_parsing_fields.get(address, None)

                if field_with_other_parser:
                    # noinspection PyTypeChecker
                    self.parse_field(field_with_other_parser, prop_res, self.PARSING_MODE_DISPLAY, file_res)

            if "\n" in prop_res.body:
                res.add_section(prop_res)

    def dump_siblings(self, index, path, res, file_res, isOrphan):
        if (index != 'unused' and index in self.property_dict and
                self.property_dict[index][1] is False):
            field = self.property_dict[index][0]

            if field['type'].display != 'storage':
                self.property_dict[index][1] = True

            self.dump_siblings(field['left'].display, path, res, file_res, isOrphan)
            if field['type'].display != 'storage':
                self.dump_property(field, path, index, res, file_res, isOrphan)
            self.dump_siblings(field['right'].display, path, res, file_res, isOrphan)

    def dump_dir(self, dir_index, path, file_res, isOrphan):
        # 1. make sure the directory wasn't dumped already
        if dir_index in self.property_dict and self.property_dict[dir_index][1] is False:
            self.property_dict[dir_index][1] = True

            field = self.property_dict[dir_index][0]
            field_name = field['name'].display[1:-1]
            field_full_name = path + field_name

            # 2. create a res with it's name
            res = ResultSection(SCORE.NULL, "OLE2 STORAGE: %s" % field_full_name)

            # 3. Dump the dir property
            self.dump_property(self.property_dict[dir_index][0], path, dir_index, res, file_res, isOrphan)

            # 3. navigate the red-black tree
            self.dump_siblings(field['child'].display, field_full_name, res, file_res, isOrphan)

            if len(res.subsections) > 0:
                file_res.add_result(res)

            # call recursively our children when there is a children
            if dir_index in self.children:
                for sub_dir in self.children[dir_index][1]:
                    self.dump_dir(sub_dir, field_full_name + '\\', file_res, isOrphan)

    def dump_properties(self, file_res):
        # 1. start with id 0 and naviguate the tree from there.
        self.dump_dir('0', '\\', file_res, False)

        # 2. any missing properties, look for dir first?
        while len(self.parent) > 0:
            cur_dir = self.parent.items()[0][0]
            if self.property_dict[cur_dir][1]:
                del self.parent[cur_dir]
            else:
                while cur_dir in self.parent and self.property_dict[self.parent[cur_dir]][1] is False:
                    cur_dir = self.parent[cur_dir]
                self.dump_dir(cur_dir, '\\-ORPHAN-\\', file_res, True)

        for (id, field_struct) in self.property_dict.iteritems():
            if field_struct[1] is False and field_struct[0]['type'].display == 'storage':
                self.dump_dir(id, '\\-ORPHAN-\\', file_res, True)

        if len(self.invalid_streams) > 0:
            res_error = ResultSection(SCORE.MED,
                                      "Trying to access stream content from the short block, but root[0] doesn't "
                                      "even exist.  This file is either corrupted, patched or exploiting a "
                                      "vulnerability.")
            res_error.add_line("Unable to access the following stream(s): '%s'" % "', '".join(self.invalid_streams))
            file_res.add_result(res_error)
            file_res.report_heuristic(Cleaver.AL_Cleaver_013)

        # 3. any missing properties, with no parent?
        orphans = {}
        for (id, field_struct) in self.property_dict.iteritems():
            if field_struct[1] is False and field_struct[0]['name'].value != '':
                orphans[id] = field_struct

        if len(orphans) > 0:
            res = ResultSection(SCORE.NULL, "OLE2 STORAGE: \\-ORPHAN-")
            for (id, field_struct) in orphans.iteritems():
                self.dump_property(field_struct[0], '\\-ORPHAN-', id, res, file_res, True)

            if len(res.subsections) > 0:
                file_res.add_result(res)

    def find_parent(self, parent_index, children_index, recurse_count=0):
        if children_index != 'unused':
            if recurse_count > 10:
                return
            try:
                children_field = self.ole2parser["property[%s]" % children_index]
            except MissingField:
                return

            if children_field['type'].display == 'storage':
                self.children[parent_index][1].append(children_index)
                if children_field not in self.parent:
                    self.parent[children_index] = parent_index

            recurse_count += 1
            self.find_parent(parent_index, children_field['left'].display, recurse_count)
            self.find_parent(parent_index, children_field['right'].display, recurse_count)

    # noinspection PyUnusedLocal
    def parse_property(self, field, res, mode, file_res):
        if mode == self.PARSING_MODE_CACHE:
            property_index = field.name[field.name.find('[') + 1:field.name.find(']')]
            child = field['child'].display

            if child != 'unused':
                self.children[property_index] = [child, []]
                self.find_parent(property_index, child)
            self.property_dict[property_index] = [field, False]

    # noinspection PyProtectedMember
    def parse_custom_fragment(self, field, res, mode, file_res):
        # dest_stream = open('c:\\temp_stream.bin', 'wb')
        # f = FileFromInputStream(field.getSubIStream())
        # dest_stream.write(f.read())
        # dest_stream.close()

        # time to switch parser...
        field_address = field._getAbsoluteAddress()
        stream = field.getSubIStream()
        parser = guessParser(stream)

        # cache all the fields first otherwise I won't be able to access it.
        if isinstance(parser, RootSeekableFieldSet):
            # for field in parser._readFields():
            #    pass
            self.cache_fields(parser, file_res)

        if isinstance(parser, OfficeRootEntry):
            self.office_root_entry_parser = parser

            # 1- list all of the summary
            self.parse_field_name('summary', parser, True, res, mode, file_res)

            # 2- list all doc_summary
            self.parse_field_name('doc_summary', parser, True, res, mode, file_res)

        elif isinstance(parser, SummaryParser):
            self.additional_parsing_fields[field_address] = parser

            # sec_field = parser['section[0]']
            # try:
            #    for f in sec_field:
            #        print f.name
            # except ParserError, e:
            #    pass
            # try:
            #    for f in sec_field:
            #        print f.name
            # except:
            #    pass

    def parse_field(self, field, res, mode, file_res):
        parser_func = self.get_parser(field.getFieldType())
        if parser_func:
            parser_func(field, res, mode, file_res)

    def parse_field_name(self, field_name, field, is_array, res, mode, file_res, num_of_loop=0):
        index = 0
        keep_looping = True
        entry_found = False

        self.cache_fields(field, file_res)
        current_field_name = None
        while keep_looping:
            try:
                while keep_looping:
                    if is_array:
                        index_str = "[%d]" % index
                        index += 1
                    else:
                        index_str = ""
                        keep_looping = False

                    if num_of_loop != 0 and index == num_of_loop:
                        keep_looping = False

                    current_field_name = "%s%s" % (field_name, index_str)
                    # print current_field_name

                    sub_field = field[current_field_name]
                    entry_found = True
                    self.parse_field(sub_field, res, mode, file_res)

            except MissingField, e:
                # print("    missing")
                if num_of_loop == 0 or index >= num_of_loop:
                    # print("    stop looping1")
                    keep_looping = False
                if e.key == current_field_name:
                    pass
                else:
                    raise

            except ParserError:
                if num_of_loop == 0 or index >= num_of_loop:
                    # print("    stop looping2")
                    keep_looping = False

        return entry_found

    def cache_fields(self, field, file_res):
        num_of_attempt = 15
        keep_trying = True
        previous_parser_error = None

        while keep_trying:
            # noinspection PyBroadException
            try:
                if field.is_field_set:
                    for _ in field:
                        pass

            except MissingField, e:
                res = ResultSection(SCORE.MED,
                                    "Hachoir lib COULD NOT get field '%s' from '%s'.  This file is either corrupted, "
                                    "patched or exploiting a vulnerability." % (
                                        e.key, e.field.path))
                # ScanExecution.current_execution.current_file_res.add_result(res)
                file_res.add_result(res)
                file_res.report_heuristic(Cleaver.AL_Cleaver_018)
            except ParserError, e:
                if previous_parser_error is None and previous_parser_error != e.text:
                    previous_parser_error = e.text
                    if e.text.startswith("OLE2: Unable to parse property of type "):
                        res = ResultSection(SCORE.MED,
                                            "Hachoir lib DID NOT successfully parse one of the property [%s].  This "
                                            "file is either corrupted, patched or exploiting a vulnerability." % e.text)
                        # ScanExecution.current_execution.current_file_res.add_result(res)
                        file_res.add_result(res)
                        file_res.report_heuristic(Cleaver.AL_Cleaver_019)
                    elif e.text.startswith('Unable to add ') and e.text.endswith(" is too large"):
                        res = ResultSection(SCORE.MED,
                                            "Hachoir lib determined that a field is overflowing the file [%s].  This "
                                            "file is either corrupted, patched or exploiting a vulnerability." % e.text)
                        # ScanExecution.current_execution.current_file_res.add_result(res)
                        file_res.add_result(res)
                        file_res.report_heuristic(Cleaver.AL_Cleaver_020)
                    elif e.text.endswith(" is too large!"):
                        res = ResultSection(SCORE.MED,
                                            "Hachoir lib COULD NOT access a field [%s].  This file is either corrupted,"
                                            " patched or exploiting a vulnerability." % e.text)
                        # ScanExecution.current_execution.current_file_res.add_result(res)
                        file_res.add_result(res)
                        file_res.report_heuristic(Cleaver.AL_Cleaver_021)
                    elif e.text.startswith("Seek above field set end"):
                        res = ResultSection(SCORE.MED,
                                            "Hachoir lib determined that a field is overflowing the file [%s].  This "
                                            "file is either corrupted, patched or exploiting a vulnerability." % e.text)
                        # ScanExecution.current_execution.current_file_res.add_result(res)
                        file_res.add_result(res)
                        file_res.report_heuristic(Cleaver.AL_Cleaver_020)
                    elif "FAT chain: Found a loop" in e.text:
                        if e.text.startswith('B'):
                            fat = 'BFAT'
                        else:
                            fat = 'SFAT'
                        res = ResultSection(SCORE.MED,
                                            "Hachoir lib found a loop when navigating through the %s [%s].  This file "
                                            "is either corrupted, patched or exploiting a vulnerability." % (
                                                fat, e.text))
                        # ScanExecution.current_execution.current_file_res.add_result(res)
                        file_res.add_result(res)
                        file_res.report_heuristic(Cleaver.AL_Cleaver_022)
                    elif "FAT chain: Invalid block index" in e.text:
                        if e.text.startswith('B'):
                            fat = 'BFAT'
                        else:
                            fat = 'SFAT'
                        res = ResultSection(SCORE.MED,
                                            "Hachoir lib found an invalid block index in the %s [%s].  This file is "
                                            "either corrupted, patched or exploiting a vulnerability." % (
                                                fat, e.text))
                        # ScanExecution.current_execution.current_file_res.add_result(res)
                        file_res.add_result(res)
                        file_res.report_heuristic(Cleaver.AL_Cleaver_023)
                    elif e.text.startswith("OLE2: Invalid endian value"):
                        res = ResultSection(SCORE.MED,
                                            "The stream endian field is not valid [%s].  This file is either "
                                            "corrupted, patched or exploiting a vulnerability." % e.text)
                        # ScanExecution.current_execution.current_file_res.add_result(res)
                        file_res.add_result(res)
                        file_res.report_heuristic(Cleaver.AL_Cleaver_024)
                    else:
                        res = ResultSection(SCORE.LOW,
                                            "Hachoir lib DID NOT successfully parse the entire file ... "
                                            "odd [%s]." % e.text)
                        # ScanExecution.current_execution.current_file_res.add_result(res)
                        file_res.add_result(res)
                        file_res.report_heuristic(Cleaver.AL_Cleaver_025)
                        backtrace = getBacktrace(None)
                        self.log.info("%s/%s\n%s", self.task.sid, self.task.srl, backtrace)

            except:
                res = ResultSection(SCORE.LOW, "Hachoir lib DID NOT successfully parse the entire file ... odd.")
                # ScanExecution.current_execution.current_file_res.add_result(res)
                file_res.add_result(res)
                file_res.report_heuristic(Cleaver.AL_Cleaver_025)
                backtrace = getBacktrace(None)
                self.log.info("%s/%s\n%s", self.task.sid, self.task.srl, backtrace)

            num_of_attempt -= 1
            keep_trying = num_of_attempt > 0

    def dump_invalid_properties(self, file_res):
        if self.invalid_properties_count:
            res = ResultSection(title_text="We've found %s properties with IDs different then "
                                           "1 (storage), 2 (stream) and 5 (root)" % self.invalid_properties_count,
                                score=self.invalid_properties_count)
            file_res.add_result(res)

    # noinspection PyUnusedLocal
    def parse_ole2(self, parser, file_res, file_path):
        self.ole2parser = parser
        # 1- cache all the fields first.
        # for field in parser._readFields():
        #    pass
        self.cache_fields(parser, file_res)

        # 2- load up the more detailed ole2 parser and cache the results.
        root_found = self.parse_field_name('root[0]', parser, False, None, self.PARSING_MODE_CACHE, file_res)

        # 3- cache the summary 
        self.parse_field_name('summary', parser, True, None, self.PARSING_MODE_CACHE, file_res)

        # 4- cache the doc_summary
        self.parse_field_name('doc_summary', parser, True, None, self.PARSING_MODE_CACHE, file_res)

        # 5- cache the properties.
        self.parse_field_name('property', parser, True, None, self.PARSING_MODE_CACHE, file_res)

        # 6- display all the properties (and all of the summary/doc_summary under the respective property)
        self.dump_properties(file_res)

        # 7- display invalid properties
        self.dump_invalid_properties(file_res)

    # noinspection PyAttributeOutsideInit,PyBroadException
    def execute(self, request):
        request.result = Result()
        path = request.download()
        file_res = request.result  # get rid of this
        unicode_filename = unicode(path)
        self.task = request.task

        hachoir_config.quiet = True
        self.additional_parsing_fields = {}
        self.ole2parser = None
        self.office_root_entry_parser = None
        self.children = {}
        self.parent = {}
        self.property_dict = {}
        self.current_file_res = file_res
        self.relative_path = path
        self.filename = request.path
        self.is_metadata = False
        self.metadata_parser_id = None
        self.invalid_streams = []
        self.invalid_properties_count = 0

        if request.tag == "meta/shortcut/windows":
            # Cutout to hamfist lnk up in here
            if self.parse_link(file_res, path, request):
                return

        #
        # Hachoir has a known defect (#33) that results in file handles being left open
        # by createParser().
        #
        # Until this defect is resulved in hachoir the following work around is performed:
        # - override/wrap python's built-in open function with hachoirOpenFileHelper()
        # - hachoirOpenFileHelper() will record the file names and descriptors opened, 
        #   as well as call the original open function
        # - in the "finally" below hachoirCloseFileHelper() is called to close the file handle
        # - in the "finally" built-in open function is returned the original one
        #

        global realOpenFunction
        global hachoirOpenedFiles
        realOpenFunction = __builtin__.open
        hachoirOpenedFiles = {}
        __builtin__.open = hachoirOpenFileHelper

        try:
            parser = createParser(unicode_filename)
            if parser is not None:
                # logger.objects[parser] = logger.objects[parser.stream] = u'root'
                tags = parser.getParserTags()
                parser_id = tags.get('id', 'unknown')

                # if "powerpoint" in (request.task.tag or ""):
                #    self.pps_vba_check(path,file_res)

                if parser_id == 'ole2':
                    # this is just so that we don't bail on the NULL property type and we keep on going.
                    for (key, value) in PropertyContent.TYPE_INFO.iteritems():
                        if value[1] is None:
                            PropertyContent.TYPE_INFO[key] = (value[0], DummyObject)
                    self.parse_ole2(parser, file_res, path)
                elif parser_id != 'exe' and parser_id != 'zip' and parser_id != 'cab' and parser_id != 'tar':
                    # meta data
                    self.is_metadata = True
                    self.metadata_parser_id = parser_id

                    # if compressed flash, use the decompressed version instead,
                    # metadata is not smart enough to do it :-\
                    if parser_id == 'swf' and parser['signature'].display == '"CWS"':
                        try:
                            stream = parser['compressed_data'].getSubIStream()
                            parser = guessParser(stream)
                            res = ResultSection(SCORE.NULL, "METADATA (from parser: CWF)")
                            file_res.add_result(res)
                            res.add_line("Format version: flash version %s" % parser['version'])
                        except:
                            pass
                    else:
                        metadata = extractMetadata(parser, 1)

                        if metadata:
                            text = metadata.exportPlaintext(priority=(9 * 100 + 99), human=True)

                            if text:
                                res = ResultSection(SCORE.NULL, "METADATA (from parser: %s)" % parser_id.upper())
                                file_res.add_result(res)
                                for line in text[1:]:
                                    if line.startswith("- "):
                                        line = line[2:]
                                    res.add_line(line)
        finally:
            #
            # Return the built-in open method to its original state, and 
            # close any files opened by hachoir
            #
            __builtin__.open = realOpenFunction
            hachoirCloseFileHelper(unicode_filename)

    def parse_link(self, file_res, path, request):
        with open(path, "rb") as fh:
            metadata = decode_lnk(fh.read())

        if metadata is None:
            return False

        res = ResultSection(SCORE.INFO, "METADATA (from parser: LNK)")
        extract_vals = ["showCommand", "BasePath", "RELATIVE_PATH", "COMMAND_LINE_ARGUMENTS", "WORKING_DIR", "NetName"]
        for d_type in extract_vals:
            if d_type not in metadata:
                continue
            value = metadata[d_type]
            res.add_line("%s: %s" % (d_type, value))
        bp = metadata.get("BasePath", "").strip()
        rp = metadata.get("RELATIVE_PATH", "").strip()
        nn = metadata.get("NetName", "").strip()
        cla = metadata.get("COMMAND_LINE_ARGUMENTS", "").strip()
        score = TAG_SCORE.NULL
        if bp.lower().endswith("cmd.exe") or rp.lower().endswith("cmd.exe"):
            s = self.bad_link_re.search(cla.lower())
            if s:
                score = TAG_SCORE.HIGH
                res.score = SCORE.HIGH
        file_res.add_tag(tag_type=FC_VALUE_TYPE.FILE_NAME, value=(bp or rp or nn), weight=TAG_SCORE.NULL)
        file_res.add_tag(tag_type=FC_VALUE_TYPE.FILE_PATH_NAME, value="%s %s" % ((rp or bp or nn), cla), weight=score)

        file_res.add_result(res)
        return True
