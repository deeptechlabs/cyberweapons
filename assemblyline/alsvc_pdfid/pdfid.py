
import hashlib
import os

from base64 import b64decode
from textwrap import dedent

from al_services.alsvc_pdfid.ext.ePDFId import PDF_ELEMENT_COMMENT, PDF_ELEMENT_XREF, PDF_ELEMENT_TRAILER, \
    PDF_ELEMENT_STARTXREF, PDF_ELEMENT_INDIRECT_OBJECT, cPDFParser, PDFiD2String, PDF_iD
from assemblyline.al.common.heuristics import Heuristic
from assemblyline.al.common.result import Result, ResultSection, TEXT_FORMAT
from assemblyline.al.common.result import SCORE, TAG_TYPE, TAG_WEIGHT
from assemblyline.al.service.base import ServiceBase


class PDFId(ServiceBase):
    AL_PDFID_001 = Heuristic("AL_PDFID_001", "PDF_Launch", "document/pdf",
                             dedent("""\
                                    /Launch command used
                                    """))
    AL_PDFID_002 = Heuristic("AL_PDFID_002", "After last %%EOF", "document/pdf",
                             dedent("""\
                                    There are byte(s) following the end of the PDF
                                    """))
    AL_PDFID_003 = Heuristic("AL_PDFID_003", "JBIG2Decode", "document/pdf",
                             dedent("""\
                                    looking for /JBIG2Decode. Using the JBIG2 compression
                                    """))
    AL_PDFID_004 = Heuristic("AL_PDFID_004", "AcroForm", "document/pdf",
                             dedent("""\
                                    looking for /AcroForm.  This is an action launched by Forms
                                    """))
    AL_PDFID_005 = Heuristic("AL_PDFID_005", "RichMedia", "document/pdf",
                             dedent("""\
                                    looking for /RichMedia.  This can be use to embed Flash in a PDF
                                    """))
    AL_PDFID_006 = Heuristic("AL_PDFID_006", "PDF Date Modified", "document/pdf",
                             dedent("""\
                                    Date tag is ModDate. Will output the date value.
                                    """))
    AL_PDFID_007 = Heuristic("AL_PDFID_007", "PDF Date Creation", "document/pdf",
                             dedent("""\
                                    Date tag is CreationDate. Will output the date value.
                                    """))
    AL_PDFID_008 = Heuristic("AL_PDFID_008", "PDF Date Last Modified", "document/pdf",
                             dedent("""\
                                    Date tag is LastModified. Will output the date value.
                                    """))
    AL_PDFID_009 = Heuristic("AL_PDFID_009", "PDF Date Source Modified", "document/pdf",
                             dedent("""\
                                    Date tag is SourceModified. Will output the date value.
                                    """))
    AL_PDFID_010 = Heuristic("AL_PDFID_010", "PDF Date PDFX", "document/pdf",
                             dedent("""\
                                    Date tag is pdfx. Will output the date value.
                                    """))
    AL_PDFID_011 = Heuristic("AL_PDFID_011", "Encrypt", "document/pdf",
                             dedent("""\
                                    Found the /Encrypt string in the file. Will need to figure out why.
                                    """))

    SERVICE_ACCEPTS = 'document/pdf'    
    SERVICE_CATEGORY = "Static Analysis"
    SERVICE_DESCRIPTION = "This service extracts metadata from PDFs using Didier Stevens python library PDFId."
    SERVICE_ENABLED = True
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_CPU_CORES = 1
    SERVICE_RAM_MB = 256
    
    def __init__(self, cfg=None):
        super(PDFId, self).__init__(cfg)

    @staticmethod
    def get_switch_count(line):
        if line[-1] == ')':
            switch_count_end_index = line.rfind('(')
        else:
            switch_count_end_index = len(line)

        switch_count_start_index = switch_count_end_index - 1
        while line[switch_count_start_index].isdigit():
            switch_count_start_index -= 1

        return int(line[switch_count_start_index + 1:switch_count_end_index])

    def parse_line(self, line, file_res, res):
        line = line.lstrip()

        if line.startswith('Not a PDF document'):
            res.add_line(line)
            return False
        elif line.startswith('PDF_iD 0.0.11 '):
            return True
        elif(line.startswith('/JBIG2Decode') or line.startswith('/RichMedia') or line.startswith('/Launch') or
                line.startswith('After last %%EOF') or line.startswith('/AcroForm')):
            # 1. switch count:
            switch_count = self.get_switch_count(line)

            # 4. is it using the Launch feature?
            if line.startswith('/Launch') and switch_count > 0:
                file_res.add_tag(TAG_TYPE['EXPLOIT_NAME'], "PDF_Launch", TAG_WEIGHT['MED'])
                file_res.add_section(ResultSection(SCORE['MED'], "/Launch command used ... "
                                                                 "this is very suspicious."))
                file_res.report_heuristic(PDFId.AL_PDFID_001)

            elif line.startswith('After last %%EOF') and switch_count > 0:
                file_res.add_section(ResultSection(SCORE['MED'], "There is %d byte(s) following the end of "
                                                                 "the PDF, this is very suspicious." % switch_count))
                file_res.report_heuristic(PDFId.AL_PDFID_002)

            elif line.startswith('/JBIG2Decode') and switch_count > 0:
                file_res.add_section(ResultSection(SCORE['LOW'], "Using the JBIG2 compression ... potentially "
                                                                 "exploiting the vulnerability?"))
                file_res.report_heuristic(PDFId.AL_PDFID_003)

            elif line.startswith('/AcroForm') and switch_count > 0:
                file_res.add_section(ResultSection(SCORE['LOW'], "Using /AcroForm.  This is an action launched "
                                                                 "by Forms ... suspicious (needs further "
                                                                 "investigation)."))
                file_res.report_heuristic(PDFId.AL_PDFID_004)

            elif line.startswith('/RichMedia') and switch_count > 0:
                file_res.add_section(ResultSection(SCORE['LOW'], "Using /RichMedia.  This can be use to embed "
                                                                 "Flash in a PDF ... suspicious (needs further "
                                                                 "investigation)."))
                file_res.report_heuristic(PDFId.AL_PDFID_005)

        elif line.startswith('D:'):
            sep_index = line.find(' /')
            if sep_index != -1:
                date_tag = line[sep_index + len(' /'):]
                date_value = line[2:sep_index].rstrip()
                txt_tag = ""
                if date_tag == "ModDate":
                    file_res.add_tag(TAG_TYPE['PDF_DATE_MOD'], date_value, TAG_WEIGHT['MED'])
                    file_res.report_heuristic(PDFId.AL_PDFID_006)
                    txt_tag = date_value
                elif date_tag == "CreationDate":
                    file_res.add_tag(TAG_TYPE['PDF_DATE_CREATION'], date_value, TAG_WEIGHT['MED'])
                    file_res.report_heuristic(PDFId.AL_PDFID_007)
                    txt_tag = date_value
                elif date_tag == "LastModified":
                    file_res.add_tag(TAG_TYPE['PDF_DATE_LASTMODIFIED'], date_value, TAG_WEIGHT['MED'])
                    file_res.report_heuristic(PDFId.AL_PDFID_008)
                    txt_tag = date_value
                elif date_tag == "SourceModified":
                    file_res.add_tag(TAG_TYPE['PDF_DATE_SOURCEMODIFIED'], date_value, TAG_WEIGHT['MED'])
                    file_res.report_heuristic(PDFId.AL_PDFID_009)
                    txt_tag = date_value
                elif date_tag == "pdfx":
                    file_res.add_tag(TAG_TYPE['PDF_DATE_PDFX'], date_value, TAG_WEIGHT['MED'])
                    file_res.report_heuristic(PDFId.AL_PDFID_010)
                    txt_tag = date_value

                if txt_tag != "":
                    line = ["D:", txt_tag, " /%s" % date_tag]

        elif line.startswith('/Encrypt') and int(line.split()[1]) > 0:
            file_res.add_section(ResultSection(SCORE['HIGH'], "Using /Encrypt.  ... suspicious "
                                                              "(needs further investigation)."))
            file_res.report_heuristic(PDFId.AL_PDFID_011)

        res.add_line(line)
        return True

    # noinspection PyMethodMayBeStatic
    def _report_section(self, file_res, res, request):
        if file_res.score > 0 or request.deep_scan:
            file_res.add_section(res)

    def parse_pdfid(self, pdfid_output, request):
        file_res = request.result
        res = ResultSection(SCORE['NULL'], "PDF_iD output:", body_format=TEXT_FORMAT.MEMORY_DUMP)

        for line in pdfid_output.splitlines():
            if not self.parse_line(line, file_res, res):
                return False

        self._report_section(file_res, res, request)

        return True

    # THIS FUNCTION is an extract of the Main() function of the pdfparser.py code from Didier Stevens        
    # noinspection PyPep8Naming
    @staticmethod
    def run_pdfparser(filename, request):
        file_res = request.result
        oPDFParser = None
        try:
            oPDFParser = cPDFParser(filename, False, None)
            cntComment = 0
            cntXref = 0
            cntTrailer = 0
            cntStartXref = 0
            cntIndirectObject = 0
            dicObjectTypes = {}

            while True:
                pdf_obj = oPDFParser.GetObject()
                if pdf_obj is not None:
                    if pdf_obj.type == PDF_ELEMENT_COMMENT:
                        cntComment += 1
                    elif pdf_obj.type == PDF_ELEMENT_XREF:
                        cntXref += 1
                    elif pdf_obj.type == PDF_ELEMENT_TRAILER:
                        cntTrailer += 1
                    elif pdf_obj.type == PDF_ELEMENT_STARTXREF:
                        cntStartXref += 1
                    elif pdf_obj.type == PDF_ELEMENT_INDIRECT_OBJECT:
                        cntIndirectObject += 1
                        obj_type = pdf_obj.GetType()
                        if obj_type not in dicObjectTypes:
                            dicObjectTypes[obj_type] = [pdf_obj.id]
                        else:
                            dicObjectTypes[obj_type].append(pdf_obj.id)
                else:
                    break

            stats_output = 'Comment: %s\nXREF: %s\nTrailer: %s\nStartXref: %s\nIndirect pdf_obj: %s\n' % \
                           (cntComment, cntXref, cntTrailer, cntStartXref, cntIndirectObject)
            names = dicObjectTypes.keys()
            names.sort()
            for key in names:
                stats_output = "%s %s %d: %s\n" % (stats_output, key, len(dicObjectTypes[key]),
                                                   ', '.join(map(lambda x: '%d' % x, dicObjectTypes[key])))
            
            stats_hash = hashlib.sha1(stats_output).hexdigest()
            file_res.add_tag(TAG_TYPE['PDF_STATS_SHA1'], stats_hash, TAG_WEIGHT['MED'])
            
            if file_res.score > 0 or request.deep_scan:
                res = ResultSection(SCORE['NULL'], "PDF-parser --stats output:", body_format=TEXT_FORMAT.MEMORY_DUMP)
                for line in stats_output.splitlines():
                    res.add_line(line)
                file_res.add_section(res)
                
        finally:
            if oPDFParser is not None:
                oPDFParser.CloseOpenFiles()

    # noinspection PyUnusedLocal,PyMethodMayBeStatic
    def _report_embedded_xdp(self, file_res, chunk_number, binary, leftover):
        file_res.add_section(ResultSection(SCORE['INFO'], ["Found %s " % chunk_number, "Embedded PDF (in XDP)"]))
        file_res.add_tag(TAG_TYPE['FILE_SUMMARY'], "Embedded PDF (in XDP)", 10, 'IDENTIFICATION')

    def find_xdp_embedded(self, filename, binary, request):
        file_res = request.result
        if "<pdf" in binary and "<document>"in binary and "<chunk>" in binary:
            chunks = binary.split("<chunk>")

            chunk_number = 0
            leftover = ""
            for chunk in chunks:
                if "</chunk>" not in chunk:
                    leftover += chunk.replace("<document>", "").replace('<pdf xmlns="'
                                                                        'http://ns.adobe.com/xdp/pdf/">', "")
                    continue
            
                chunk_number += 1
                
                un_b64 = None
                # noinspection PyBroadException
                try:
                    un_b64 = b64decode(chunk.split("</chunk>")[0])
                except:
                    self.log.error("Found <pdf>, <document> and <chunk> tags inside an xdp file "
                                   "but could not unbase64 the content.")
                    
                if un_b64:
                    new_filename = "%s_%d.pdf" % (filename, chunk_number)
                    file_path = os.path.join(self.working_directory, new_filename)
                    f = open(file_path, "wb")
                    f.write(un_b64)
                    f.close()
                    request.add_extracted(file_path, "UnXDP from %s" % filename)
            
            if chunk_number > 0:
                self._report_embedded_xdp(file_res, chunk_number, binary, leftover)

    def execute(self, request):
        request.result = Result()
        temp_filename = request.download()
        filename = os.path.basename(temp_filename)

        with open(temp_filename, 'r') as f:
            file_content = f.read()

        if '<xdp:xdp' in file_content:
            self.find_xdp_embedded(filename, file_content, request)
        
        if len(file_content) < 3000000:
            pdf = PDFiD2String(PDF_iD(temp_filename, False, True, False), False)
    
            if pdf:
                if self.parse_pdfid(pdf, request):
                    self.run_pdfparser(temp_filename, request)
        else:
            # a file too big error message would be better but, this will do for now.
            request.result.add_section(ResultSection(SCORE['NULL'], "PDF Analysis of the file was"
                                                                    " skipped because the file is "
                                                                    "too big (limit is 3 MB)."))
