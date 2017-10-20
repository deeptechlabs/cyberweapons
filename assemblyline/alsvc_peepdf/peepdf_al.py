from __future__ import absolute_import

import gc
import hashlib
import os
import re

from base64 import b64decode
from textwrap import dedent

from assemblyline.common.hexdump import hexdump
from assemblyline.al.common.heuristics import Heuristic
from assemblyline.al.common.result import Result, ResultSection
from assemblyline.al.common.result import SCORE, TAG_TYPE, TAG_WEIGHT, TEXT_FORMAT
from assemblyline.al.service.base import ServiceBase

BANNED_TYPES = ["xref", "objstm", "xobject", "metadata", "3d", "pattern", None]


def validate_non_humanreadable_buff(data, buff_min_size=256, whitespace_ratio=0.10):
    ws_count = data.count(" ")
    ws_count += data.count("%20") * 3
    if len(data) >= buff_min_size:
        if ws_count * 1.0 / len(data) < whitespace_ratio:
            return True

    return False


# noinspection PyGlobalUndefined
class PeePDF(ServiceBase):
    AL_PeePDF_001 = Heuristic("AL_PeePDF_001", "Embedded PDF in XDP", "document/pdf",
                              dedent("""\
                                     If there is the <chunk> tag in the PDF file contents, there is an 
                                     embedded PDF in the XDP.
                                     """))
    AL_PeePDF_002 = Heuristic("AL_PeePDF_002", "Large Buffers", "document/pdf",
                              dedent("""\
                                     A buffer was found in the javascript code.
                                     """))
    AL_PeePDF_003 = Heuristic("AL_PeePDF_003", "Contains eval", "document/pdf",
                              dedent("""\
                                     The eval() function is found in the javascript block. This is 
                                     commonly used to launch deofuscated javascript code.
                                     """))
    AL_PeePDF_004 = Heuristic("AL_PeePDF_004", "Contains unescape", "document/pdf",
                              dedent("""\
                                     The unescape() function is found in the javascript block. Malware 
                                     could use this to deobfuscate code blocks.
                                     """))
    AL_PeePDF_005 = Heuristic("AL_PeePDF_005", "Javascript Shellcode", "document/pdf",
                              dedent("""\
                                     Getting the unescaped bytes from the PeePDF tool and running those 
                                     in an emulator, if they execute then there was hidden shallcode 
                                     found inside.
                                     """))
    AL_PeePDF_006 = Heuristic("AL_PeePDF_006", "Unescaped Javascript Buffer", "document/pdf",
                              dedent("""\
                                     If looking for javascript shellcode fails, the javascript is an 
                                     unknown unescaped buffer.
                                     """))
    AL_PeePDF_007 = Heuristic("AL_PeePDF_007", "Suspicious Javascript", "document/pdf",
                              dedent("""\
                                     If the file contents of the PDF has either "eval" or "unescape" or 
                                     we were able to find large buffer variables, this is a good flag 
                                     for malicious content.
                                     """))
    
    SERVICE_ACCEPTS = '(document/pdf|code/xml)'
    SERVICE_CATEGORY = "Static Analysis"
    SERVICE_DESCRIPTION = "This service uses the Python PeePDF library information from PDFs including javascript " \
                          "blocks which it will attempt to deobfuscate, if necessary, for further analysis."
    SERVICE_ENABLED = True
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_CPU_CORES = 0.5
    SERVICE_RAM_MB = 512

    SERVICE_DEFAULT_CONFIG = {
        'max_pdf_size': 3000000
    }

    def __init__(self, cfg=None):
        super(PeePDF, self).__init__(cfg)
        self.max_pdf_size = cfg.get('max_pdf_size', 3000000)

    # noinspection PyUnresolvedReferences
    def import_service_deps(self):
        global analyseJS, isPostscript, PDFParser, vulnsDict, unescape
        from al_services.alsvc_peepdf.peepdf.JSAnalysis import analyseJS, isPostscript, unescape
        from al_services.alsvc_peepdf.peepdf.PDFCore import PDFParser, vulnsDict

    # noinspection PyUnusedLocal,PyMethodMayBeStatic
    def _report_embedded_xdp(self, file_res, chunk_number, binary, leftover):
        file_res.add_section(ResultSection(SCORE['INFO'], ["Found %s " % chunk_number, "Embedded PDF (in XDP)"]))
        file_res.add_tag(TAG_TYPE['FILE_SUMMARY'], "Embedded PDF (in XDP)", 10, 'IDENTIFICATION')
        file_res.report_heuristic(PeePDF.AL_PeePDF_001)

    def find_xdp_embedded(self, filename, cbin, request):
        file_res = request.result
        if "<pdf" in cbin and "<document>"in cbin and "<chunk>" in cbin:
            chunks = cbin.split("<chunk>")

            chunk_number = 0
            leftover = ""
            for chunk in chunks:
                if "</chunk>" not in chunk:
                    leftover += chunk.replace("<document>", "").replace('<pdf xmlns="http://ns.adobe.com/xdp/pdf/">',
                                                                        "")
                    continue

                chunk_number += 1

                un_b64 = None
                # noinspection PyBroadException
                try:
                    un_b64 = b64decode(chunk.split("</chunk>")[0])
                except:
                    self.log.error("Found <pdf>, <document> and <chunk> tags inside an xdp file but could not "
                                   "un-base64 the content.")

                if un_b64:
                    new_filename = "xdp_%d.pdf" % chunk_number
                    file_path = os.path.join(self.working_directory, new_filename)
                    f = open(file_path, "wb")
                    f.write(un_b64)
                    f.close()
                    request.add_extracted(file_path, "UnXDP from %s" % filename)

            if chunk_number > 0:
                self._report_embedded_xdp(file_res, chunk_number, cbin, leftover)

        return file_res

    def execute(self, request):
        request.result = Result()
        temp_filename = request.download()

        # Filter out large documents
        if os.path.getsize(temp_filename) > self.max_pdf_size:
            request.result.add_section(ResultSection(SCORE['NULL'], "PDF Analysis of the file was skipped because the "
                                                                    "file is too big (limit is %i MB)." % (
                                                                    self.max_pdf_size / 1000 / 1000)))
            return

        filename = os.path.basename(temp_filename)
        # noinspection PyUnusedLocal
        file_content = ''
        with open(temp_filename, 'r') as f:
            file_content = f.read()

        if '<xdp:xdp' in file_content:
            self.find_xdp_embedded(filename, file_content, request)

        self.peepdf_analysis(temp_filename, file_content, request)

    # noinspection PyBroadException
    @staticmethod
    def get_big_buffs(data, buff_min_size=256):
        # Hunt for big variables
        var_re = r'[^\\]?"(.*?[^\\])"'
        last_m = None
        out = []

        for m in re.finditer(var_re, data):
            # noinspection PyUnresolvedReferences
            pos = m.regs[0]
            match = m.group(1)
            if last_m:
                last_pos, last_match = last_m
                between = data[last_pos[1]:pos[0] + 1]
                try:
                    between, rest = between.split("//", 1)
                    try:
                        between = between.strip() + rest.split("\n", 1)[1].strip()
                    except:
                        pass
                except:
                    pass
                finally:
                    between = between.strip()

                if between == "+":
                    match = last_match + match
                    pos = (last_pos[0], pos[1])
                else:
                    if validate_non_humanreadable_buff(last_match, buff_min_size=buff_min_size):
                        out.append(last_match)

            last_m = (pos, match)

        if last_m:
            if validate_non_humanreadable_buff(last_m[1]):
                out.append(last_m[1])

        # Hunt for big comments
        var_comm_re = r"<!--(.*?)--\s?>"

        for m in re.finditer(var_comm_re, data, flags=re.DOTALL):
            match = m.group(1)
            if validate_non_humanreadable_buff(match):
                out.append(match)

        return out

    @staticmethod
    def check_dangerous_func(data):
        has_eval = False
        has_unescape = False
        # eval
        temp_eval = data.split("eval")
        if len(temp_eval) > 1:
            idx = 0
            for i in temp_eval[:-1]:
                idx += 1
                if (97 <= ord(i[-1]) <= 122) or (65 <= ord(i[-1]) <= 90):
                    continue
                if (97 <= ord(temp_eval[idx][0]) <= 122) or \
                        (65 <= ord(temp_eval[idx][0]) <= 90):
                    continue

                has_eval = True
                break

        # unescape
        temp_unesc = data.split("unescape")
        if len(temp_unesc) > 1:
            idx = 0
            for i in temp_unesc[:-1]:
                idx += 1
                if (97 <= ord(i[-1]) <= 122) or (65 <= ord(i[-1]) <= 90):
                    continue
                if (97 <= ord(temp_unesc[idx][0]) <= 122) or \
                        (65 <= ord(temp_unesc[idx][0]) <= 90):
                    continue

                has_unescape = True
                break

        return has_eval, has_unescape

    @staticmethod
    def list_first_x(mylist, size=20):
        add_reminder = len(mylist) > size

        mylist = mylist[:size]
        if add_reminder:
            mylist.append("...")

        return str(mylist)

    # noinspection PyBroadException,PyUnboundLocalVariable
    def peepdf_analysis(self, temp_filename, file_content, request):
        file_res = request.result
        try:
            res_list = []
            js_stream = []
            f_list = []
            js_dump = []

            pdf_parser = PDFParser()
            ret, pdf_file = pdf_parser.parse(temp_filename, True, False, file_content)
            if ret == 0:
                stats_dict = pdf_file.getStats()

                if ", ".join(stats_dict['Errors']) == "Bad PDF header, %%EOF not found, PDF sections not found, No " \
                                                      "indirect objects found in the body":
                    # Not a PDF
                    return

                res = ResultSection(SCORE['NULL'], "PDF File information")
                res.add_line('File: ' + stats_dict['File'])
                res.add_line(['MD5: ', stats_dict['MD5']])
                res.add_line(['SHA1: ', stats_dict['SHA1']])
                res.add_line('SHA256: ' + stats_dict['SHA256'])
                res.add_line(['Size: ', stats_dict['Size'], ' bytes'])
                res.add_line('Version: ' + stats_dict['Version'])
                res.add_line('Binary: ' + stats_dict['Binary'])
                res.add_line('Linearized: ' + stats_dict['Linearized'])
                res.add_line('Encrypted: ' + stats_dict['Encrypted'])
                if stats_dict['Encryption Algorithms']:
                    temp = ' ('
                    for algorithmInfo in stats_dict['Encryption Algorithms']:
                        temp += algorithmInfo[0] + ' ' + str(algorithmInfo[1]) + ' bits, '
                    temp = temp[:-2] + ')'
                    res.add_line(temp)
                res.add_line('Updates: ' + stats_dict['Updates'])
                res.add_line('Objects: ' + stats_dict['Objects'])
                res.add_line('Streams: ' + stats_dict['Streams'])
                res.add_line('Comments: ' + stats_dict['Comments'])
                res.add_line('Errors: ' + {True: ", ".join(stats_dict['Errors']),
                                           False: "None"}[len(stats_dict['Errors']) != 0])
                res.add_line("")

                for version in range(len(stats_dict['Versions'])):
                    stats_version = stats_dict['Versions'][version]
                    res_version = ResultSection(SCORE['NULL'], 'Version ' + str(version), parent=res)
                    if stats_version['Catalog'] is not None:
                        res_version.add_line('Catalog: ' + stats_version['Catalog'])
                    else:
                        res_version.add_line('Catalog: ' + 'No')
                    if stats_version['Info'] is not None:
                        res_version.add_line('Info: ' + stats_version['Info'])
                    else:
                        res_version.add_line('Info: ' + 'No')
                    res_version.add_line('Objects (' + stats_version['Objects'][0] + '): ' +
                                         self.list_first_x(stats_version['Objects'][1]))
                    if stats_version['Compressed Objects'] is not None:
                        res_version.add_line('Compressed objects (' + stats_version['Compressed Objects'][0] + '): ' +
                                             self.list_first_x(stats_version['Compressed Objects'][1]))

                    if stats_version['Errors'] is not None:
                        res_version.add_line('Errors (' + stats_version['Errors'][0] + '): ' +
                                             self.list_first_x(stats_version['Errors'][1]))
                    res_version.add_line('Streams (' + stats_version['Streams'][0] + '): ' +
                                         self.list_first_x(stats_version['Streams'][1]))
                    if stats_version['Xref Streams'] is not None:
                        res_version.add_line('Xref streams (' + stats_version['Xref Streams'][0] + '): ' +
                                             self.list_first_x(stats_version['Xref Streams'][1]))
                    if stats_version['Object Streams'] is not None:
                        res_version.add_line('Object streams (' + stats_version['Object Streams'][0] + '): ' +
                                             self.list_first_x(stats_version['Object Streams'][1]))
                    if int(stats_version['Streams'][0]) > 0:
                        res_version.add_line('Encoded (' + stats_version['Encoded'][0] + '): ' +
                                             self.list_first_x(stats_version['Encoded'][1]))
                        if stats_version['Decoding Errors'] is not None:
                            res_version.add_line('Decoding errors (' + stats_version['Decoding Errors'][0] + '): ' +
                                                 self.list_first_x(stats_version['Decoding Errors'][1]))
                    if stats_version['Objects with JS code'] is not None:
                        res_version.add_line('Objects with JS '
                                             'code (' + stats_version['Objects with JS code'][0] + '): ' +
                                             self.list_first_x(stats_version['Objects with JS code'][1]))
                        js_stream.extend(stats_version['Objects with JS code'][1])

                    suspicious_score = SCORE['NULL']
                    actions = stats_version['Actions']
                    events = stats_version['Events']
                    vulns = stats_version['Vulns']
                    elements = stats_version['Elements']
                    if events is not None or actions is not None or vulns is not None or elements is not None:
                        res_suspicious = ResultSection(SCORE['NULL'], 'Suspicious elements', parent=res_version)
                        if events is not None:
                            for event in events:
                                res_suspicious.add_line(event + ': ' + self.list_first_x(events[event]))
                                suspicious_score += SCORE['LOW']
                        if actions is not None:
                            for action in actions:
                                res_suspicious.add_line(action + ': ' + self.list_first_x(actions[action]))
                                suspicious_score += SCORE['LOW']
                        if vulns is not None:
                            for vuln in vulns:
                                if vuln in vulnsDict:
                                    temp = [vuln, ' (']
                                    for vulnCVE in vulnsDict[vuln]:
                                        if len(temp) != 2:
                                            temp.append(',')
                                        temp.append(vulnCVE)
                                        cve_found = re.search("CVE-[0-9]{4}-[0-9]{4}", vulnCVE)
                                        if cve_found:
                                            file_res.add_tag(TAG_TYPE['EXPLOIT_NAME'],
                                                             vulnCVE[cve_found.start():cve_found.end()],
                                                             TAG_WEIGHT['MED'],
                                                             usage='IDENTIFICATION')
                                            file_res.add_tag(TAG_TYPE['FILE_SUMMARY'],
                                                             vulnCVE[cve_found.start():cve_found.end()],
                                                             TAG_WEIGHT['MED'],
                                                             usage='IDENTIFICATION')
                                    temp.append('): ')
                                    temp.append(str(vulns[vuln]))
                                    res_suspicious.add_line(temp)
                                else:
                                    res_suspicious.add_line(vuln + ': ' + str(vulns[vuln]))
                                suspicious_score += SCORE['HIGH']
                        if elements is not None:
                            for element in elements:
                                if element in vulnsDict:
                                    temp = [element, ' (']
                                    for vulnCVE in vulnsDict[element]:
                                        if len(temp) != 2:
                                            temp.append(',')
                                        temp.append(vulnCVE)
                                        cve_found = re.search("CVE-[0-9]{4}-[0-9]{4}", vulnCVE)
                                        if cve_found:
                                            file_res.add_tag(TAG_TYPE['EXPLOIT_NAME'],
                                                             vulnCVE[cve_found.start():cve_found.end()],
                                                             TAG_WEIGHT['MED'],
                                                             usage='IDENTIFICATION')
                                            file_res.add_tag(TAG_TYPE['FILE_SUMMARY'],
                                                             vulnCVE[cve_found.start():cve_found.end()],
                                                             TAG_WEIGHT['MED'],
                                                             usage='IDENTIFICATION')
                                    temp.append('): ')
                                    temp.append(str(elements[element]))
                                    res_suspicious.add_line(temp)
                                    suspicious_score += SCORE['HIGH']
                                else:
                                    res_suspicious.add_line('\t\t' + element + ': ' + str(elements[element]))
                                    suspicious_score += SCORE['LOW']
                        res_suspicious.change_score(suspicious_score)

                    url_score = SCORE['NULL']
                    urls = stats_version['URLs']
                    if urls is not None:
                        res.add_line("")
                        res_url = ResultSection(SCORE['NULL'], 'Found URLs', parent=res)
                        for url in urls:
                            res_url.add_line('\t\t' + url)
                            url_score += SCORE['MED']

                        res_url.change_score(url_score)

                    for obj in stats_version['Objects'][1]:
                        cur_obj = pdf_file.getObject(obj, version)

                        if cur_obj.containsJScode:
                            cur_res = ResultSection(SCORE['NULL'], 'Object [%s %s] contains %s block of Javascript' %
                                                    (obj, version, len(cur_obj.JSCode)))
                            score_modifier = SCORE['NULL']

                            js_idx = 0
                            for js in cur_obj.JSCode:
                                js_idx += 1
                                js_score = 0
                                js_code, unescaped_bytes, _, _ = analyseJS(js)

                                js_dump += [x for x in js_code if not isPostscript(x)]

                                # Malicious characteristics
                                big_buffs = self.get_big_buffs("".join(js_code))
                                if len(big_buffs) > 0:
                                    js_score += SCORE['VHIGH'] * len(big_buffs)
                                has_eval, has_unescape = self.check_dangerous_func("".join(js_code))
                                if has_unescape:
                                    js_score += SCORE['HIGH']
                                if has_eval:
                                    js_score += SCORE['HIGH']

                                js_cmt = ""
                                if has_eval or has_unescape or len(big_buffs) > 0:
                                    score_modifier += js_score
                                    js_cmt = "Suspiciously malicious "
                                    file_res.add_tag(TAG_TYPE['FILE_SUMMARY'], "Suspicious javascript in PDF",
                                                     TAG_WEIGHT['MED'], usage='IDENTIFICATION')
                                    file_res.report_heuristic(PeePDF.AL_PeePDF_007)
                                js_res = ResultSection(0, "%sJavascript Code (block: %s)" % (js_cmt, js_idx),
                                                       parent=cur_res)

                                if js_score > SCORE['NULL']:
                                    temp_js_outname = "object%s-%s_%s.js" % (obj, version, js_idx)
                                    temp_js_path = os.path.join(self.working_directory, temp_js_outname)
                                    temp_js_bin = "".join(js_code).encode("utf-8")
                                    f = open(temp_js_path, "wb")
                                    f.write(temp_js_bin)
                                    f.close()
                                    f_list.append(temp_js_path)

                                    js_res.add_line(["The javascript block was saved as ", temp_js_outname])
                                    if has_eval or has_unescape:
                                        analysis_score = SCORE['NULL']
                                        analysis_res = ResultSection(analysis_score, "[Suspicious Functions]",
                                                                     parent=js_res)
                                        if has_eval:
                                            analysis_res.add_line("eval: This javascript block uses eval() function"
                                                                  " which is often used to launch deobfuscated"
                                                                  " javascript code.")
                                            analysis_score += SCORE['HIGH']
                                            file_res.report_heuristic(PeePDF.AL_PeePDF_003)
                                        if has_unescape:
                                            analysis_res.add_line("unescape: This javascript block uses unescape() "
                                                                  "function. It may be legitimate but it is definitely"
                                                                  " suspicious since malware often use this to "
                                                                  "deobfuscate code blocks.")
                                            analysis_score += SCORE['HIGH']
                                            file_res.report_heuristic(PeePDF.AL_PeePDF_004)

                                        analysis_res.change_score(analysis_score)

                                    buff_idx = 0
                                    for buff in big_buffs:
                                        buff_idx += 1
                                        error, new_buff = unescape(buff)
                                        if error == 0:
                                            buff = new_buff

                                        if buff not in unescaped_bytes:
                                            temp_path_name = None
                                            if ";base64," in buff[:100] and "data:" in buff[:100]:
                                                temp_path_name = "obj%s_unb64_%s.buff" % (obj, buff_idx)
                                                try:
                                                    buff = b64decode(buff.split(";base64,")[1].strip())
                                                    temp_path = os.path.join(self.working_directory, temp_path_name)
                                                    f = open(temp_path, "wb")
                                                    f.write(buff)
                                                    f.close()
                                                    f_list.append(temp_path)
                                                except:
                                                    self.log.error("Found 'data:;base64, ' buffer "
                                                                   "but failed to base64 decode.")
                                                    temp_path_name = None

                                            ResultSection(SCORE['VHIGH'],
                                                          "A %s bytes buffer was found in the javascript "
                                                          "block%s. Here are the first 256 bytes." %
                                                          (len(buff), {True: " and was resubmitted as %s" %
                                                                             temp_path_name,
                                                                       False: ""}[temp_path_name is not None]),
                                                          parent=js_res, body=hexdump(buff[:256]),
                                                          body_format=TEXT_FORMAT.MEMORY_DUMP)
                                            file_res.report_heuristic(PeePDF.AL_PeePDF_002)

                                processed_sc = []
                                sc_idx = 0
                                for sc in unescaped_bytes:
                                    if sc not in processed_sc:
                                        sc_idx += 1
                                        processed_sc.append(sc)

                                        try:
                                            sc = sc.decode("hex")
                                        except:
                                            pass

                                        shell_score = SCORE['VHIGH']
                                        temp_path_name = "obj%s_unescaped_%s.buff" % (obj, sc_idx)

                                        shell_res = ResultSection(shell_score,
                                                                  "Unknown unescaped  %s bytes "
                                                                  "javascript buffer (id: %s) was resubmitted as %s. "
                                                                  "Here are the first 256 bytes." % (len(sc),
                                                                                                     sc_idx,
                                                                                                     temp_path_name),
                                                                  parent=js_res)
                                        shell_res.set_body(hexdump(sc[:256]), TEXT_FORMAT.MEMORY_DUMP)

                                        temp_path = os.path.join(self.working_directory, temp_path_name)
                                        f = open(temp_path, "wb")
                                        f.write(sc)
                                        f.close()
                                        f_list.append(temp_path)

                                        file_res.add_tag(TAG_TYPE['FILE_SUMMARY'], "Unescaped Javascript Buffer",
                                                         TAG_WEIGHT['MED'],
                                                         usage='IDENTIFICATION')
                                        file_res.report_heuristic(PeePDF.AL_PeePDF_006)
                                        score_modifier += shell_score

                            if score_modifier > SCORE['NULL']:
                                res_list.append(cur_res)

                        elif cur_obj.type == "stream":
                            if cur_obj.isEncodedStream and cur_obj.filter is not None:
                                data = cur_obj.decodedStream
                                encoding = cur_obj.filter.value.replace("[", "").replace("]", "").replace("/",
                                                                                                          "").strip()
                                val = cur_obj.rawValue
                                otype = cur_obj.elements.get("/Type", None)
                                sub_type = cur_obj.elements.get("/Subtype", None)
                                length = cur_obj.elements.get("/Length", None)

                            else:
                                data = cur_obj.rawStream
                                encoding = None
                                val = cur_obj.rawValue
                                otype = cur_obj.elements.get("/Type", None)
                                sub_type = cur_obj.elements.get("/Subtype", None)
                                length = cur_obj.elements.get("/Length", None)

                            if otype:
                                otype = otype.value.replace("/", "").lower()
                            if sub_type:
                                sub_type = sub_type.value.replace("/", "").lower()
                            if length:
                                length = length.value

                            if otype == "embeddedfile":
                                if len(data) > 4096:
                                    # TODO: we might have to be smarter here.
                                    cur_res = ResultSection(SCORE['NULL'], 'Embedded file found (%s bytes) [obj: %s %s]'
                                                                           ' and dumped for analysis %s%s%s' %
                                                            (length, obj, version, {True: "(Type: %s) " % otype,
                                                                                    False: ""}[otype is not None],
                                                             {True: "(SubType: %s) " % sub_type,
                                                              False: ""}[sub_type is not None],
                                                             {True: "(Encoded with %s)" % encoding,
                                                              False: ""}[encoding is not None]))
                                    temp_path_name = "EmbeddedFile_%s%s.obj" % (obj, {True: "_%s" % encoding,
                                                                                      False: ""}[encoding is not None])
                                    temp_path = os.path.join(self.working_directory, temp_path_name)
                                    f = open(temp_path, "wb")
                                    f.write(data)
                                    f.close()
                                    f_list.append(temp_path)

                                    cur_res.add_line(["The EmbeddedFile object was saved as ", temp_path_name])
                                    res_list.append(cur_res)

                            elif otype not in BANNED_TYPES:
                                cur_res = ResultSection(SCORE['NULL'], 'Unknown stream found [obj: %s %s] %s%s%s' %
                                                        (obj, version, {True: "(Type: %s) " % otype,
                                                                        False: ""}[otype is not None],
                                                         {True: "(SubType: %s) " % sub_type,
                                                          False: ""}[sub_type is not None],
                                                         {True: "(Encoded with %s)" % encoding,
                                                          False: ""}[encoding is not None]))
                                for line in val.splitlines():
                                    cur_res.add_line(line)

                                emb_res = ResultSection(SCORE.NULL, 'First 256 bytes', parent=cur_res)
                                emb_res.set_body(hexdump(data[:256]), TEXT_FORMAT.MEMORY_DUMP)
                                res_list.append(cur_res)
                        else:
                            pass

                file_res.add_section(res)

                for results in res_list:
                    file_res.add_section(results)

                if js_dump:
                    js_dump_res = ResultSection(SCORE['NULL'], 'Full Javascript dump')

                    temp_js_dump = "javascript_dump.js"
                    temp_js_dump_path = os.path.join(self.working_directory, temp_js_dump)
                    try:
                        temp_js_dump_bin = "\n\n----\n\n".join(js_dump).encode("utf-8")
                    except UnicodeDecodeError:
                        temp_js_dump_bin = "\n\n----\n\n".join(js_dump)
                    temp_js_dump_sha1 = hashlib.sha1(temp_js_dump_bin).hexdigest()
                    f = open(temp_js_dump_path, "wb")
                    f.write(temp_js_dump_bin)
                    f.flush()
                    f.close()
                    f_list.append(temp_js_dump_path)

                    js_dump_res.add_line(["The javascript dump was saved as ", temp_js_dump])
                    js_dump_res.add_line(["The sha1 for the javascript dump is ", temp_js_dump_sha1])

                    file_res.add_tag(TAG_TYPE['PDF_JAVASCRIPT_SHA1'], temp_js_dump_sha1, TAG_WEIGHT['HIGH'],
                                     usage='CORRELATION')
                    file_res.add_section(js_dump_res)

                for filename in f_list:
                    request.add_extracted(filename, "Dumped from %s" % os.path.basename(temp_filename))

            else:
                res = ResultSection(SCORE['INFO'], "ERROR: Could not parse file with peepdf.")
                file_res.add_section(res)
        finally:
            try:
                del pdf_file
            except:
                pass

            try:
                del pdf_parser
            except:
                pass

            gc.collect()
