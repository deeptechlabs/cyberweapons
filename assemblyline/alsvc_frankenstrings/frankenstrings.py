"""
FrankenStrings Service
See README.md for details about this service.
"""
from assemblyline.al.service.base import ServiceBase
from assemblyline.al.common.result import Result, ResultSection, SCORE, TAG_TYPE, TAG_WEIGHT, TEXT_FORMAT

pefile = None
bbcrack = None
PatternMatch = None


class FrankenStrings(ServiceBase):
    SERVICE_CATEGORY = 'Static Analysis'
    SERVICE_ACCEPTS = '.*'
    SERVICE_DESCRIPTION = "Suspicious String Monster"
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_TIMEOUT = 300
    SERVICE_ENABLED = True
    SERVICE_CPU_CORES = 1
    SERVICE_RAM_MB = 256

    def import_service_deps(self):
        global namedtuple, strings, binascii, hashlib, magic, mmap, os, re, string, unicodedata, \
            pefile, bbcrack, PatternMatch
        from collections import namedtuple
        from floss import strings
        import binascii
        import hashlib
        import magic
        import mmap
        import os
        import re
        import string
        import unicodedata
        import pefile
        from al_services.alsvc_frankenstrings.balbuzard.bbcrack import bbcrack
        from al_services.alsvc_frankenstrings.balbuzard.patterns import PatternMatch

    def __init__(self, cfg=None):
        super(FrankenStrings, self).__init__(cfg)
        self.filetypes = ['application',
                          'document',
                          'exec',
                          'image',
                          'Microsoft',
                          'text',
                          ]
        self.hexencode_strings = ['\u',
                                  '%u',
                                  '\\x',
                                  '0x'
                                  ]
        # Unless patterns are added/adjusted to patterns.py, the following should remain at 7:
        self.st_min_length = 7


    def start(self):
        self.log.debug("FrankenStrings service started")

# --- Support Functions ------------------------------------------------------------------------------------------------

    # Will search for ALL IOC patterns.
    def ioc_to_tag(self, data, patterns, res, taglist=False, check_length=False, strs_max_size=0,
                   st_max_length=300):

        if taglist:
            tags = {}

        strs = set()
        jn = False

        # Flare-FLOSS ascii string extract
        for ast in strings.extract_ascii_strings(data, n=self.st_min_length):
            if len(ast.s) < st_max_length:
                strs.add(ast.s)
        # Flare-FLOSS unicode string extract
        for ust in strings.extract_unicode_strings(data, n=self.st_min_length):
            if len(ust.s) < st_max_length:
                strs.add(ust.s)

        if check_length:
            if len(strs) > strs_max_size:
                jn = True

        if len(strs) > 0:
            for s in strs:
                st_value = patterns.ioc_match(s, bogon_ip=True, just_network=jn)
                if len(st_value) > 0:
                    for ty, val in st_value.iteritems():
                        if taglist and ty not in tags:
                            tags[ty] = set()
                        if val == "":
                            asc_asc = unicodedata.normalize('NFKC', val).encode('ascii', 'ignore')
                            if len(asc_asc) < 1001:
                                res.add_tag(TAG_TYPE[ty], asc_asc, TAG_WEIGHT.LOW)
                                if taglist:
                                    tags[ty].add(asc_asc)
                        else:
                            for v in val:
                                if len(v) < 1001:
                                    res.add_tag(TAG_TYPE[ty], v, TAG_WEIGHT.LOW)
                                    if taglist:
                                        tags[ty].add(v)

        if taglist:
            return tags
        else:
            return

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

    @staticmethod
    def decode_bu(data, size):
        """
        Adjusted to take in to account byte, word, dword, qword
        """
        decoded = ''

        if size == 2:
            while data != '':
                decoded += binascii.a2b_hex(data[2:4])
                data = data[4:]
        if size == 4:
            while data != '':
                decoded += binascii.a2b_hex(data[4:6]) + binascii.a2b_hex(data[2:4])
                data = data[6:]
        if size == 8:
            while data != '':
                decoded += binascii.a2b_hex(data[8:10]) + binascii.a2b_hex(data[6:8]) + \
                           binascii.a2b_hex(data[4:6]) + binascii.a2b_hex(data[2:4])
                data = data[10:]
        if size == 16:
            while data != '':
                decoded += binascii.a2b_hex(data[16:18]) + binascii.a2b_hex(data[14:16]) + \
                           binascii.a2b_hex(data[12:14]) + binascii.a2b_hex(data[10:12]) + \
                           binascii.a2b_hex(data[8:10]) + binascii.a2b_hex(data[6:8]) + \
                           binascii.a2b_hex(data[4:6]) + binascii.a2b_hex(data[2:4])
                data = data[18:]

        return decoded

    @staticmethod
    def unicode_longest_string(lisdata):

        maxstr = len(max(lisdata, key=len))
        newstr = ""

        # Test if all match size of longest string (if by chance the data was separated by a character --i.e. ','--).
        # if true, combine all data and return string,
        # else return longest string if greater than 50 bytes,
        # else return empty string

        if all(len(i) == maxstr for i in lisdata):
            for i in lisdata:
                newstr += i
            return newstr
        elif maxstr > 50:
            return max(lisdata, key=len)
        else:
            return newstr

    def decode_encoded_udata(self, request, encoding, data):
        """
        Some code taken from bas64dump.py. Adjusted for different hex lengths.
        """
        decoded_list = []
        shalist = []
        decoded_res = []

        qword = re.compile(r'(?:'+re.escape(encoding)+'[A-Fa-f0-9]{16})+')
        dword = re.compile(r'(?:'+re.escape(encoding)+'[A-Fa-f0-9]{8})+')
        word = re.compile(r'(?:'+re.escape(encoding)+'[A-Fa-f0-9]{4})+')
        by = re.compile(r'(?:'+re.escape(encoding)+'[A-Fa-f0-9]{2})+')

        qbu = re.findall(qword, data)
        if len(qbu) > 0:
            qlstr = self.unicode_longest_string(qbu)
            if len(qlstr) > 50:
                decoded_list.append((self.decode_bu(qlstr, size=16), qlstr[:200]))
        dbu = re.findall(dword, data)
        if len(dbu) > 0:
            dlstr = self.unicode_longest_string(dbu)
            if len(dlstr) > 50:
                decoded_list.append((self.decode_bu(dlstr, size=8), dlstr[:200]))
        wbu = re.findall(word, data)
        if len(wbu) > 0:
            wlstr = self.unicode_longest_string(wbu)
            if len(wlstr) > 50:
                decoded_list.append((self.decode_bu(wlstr, size=4), wlstr[:200]))
        bbu = re.findall(by, data)
        if len(bbu) > 0:
            blstr = self.unicode_longest_string(bbu)
            if len(blstr) > 50:
                decoded_list.append((self.decode_bu(blstr, size=2), blstr[:200]))

        filtered_list = filter(lambda x: len(x[0]) > 30, decoded_list)

        for decoded in filtered_list:
            uniq_char = ''.join(set(decoded[0]))
            if len(decoded[0]) >= 500:
                if len(uniq_char) > 20:
                    sha256hash = hashlib.sha256(decoded[0]).hexdigest()
                    shalist.append(sha256hash)
                    udata_file_path = os.path.join(self.working_directory, "{0}_enchex_{1}_decoded"
                                               .format(sha256hash[0:10], encoding))
                    request.add_extracted(udata_file_path, "Extracted unicode file during FrankenStrings analysis.")
                    with open(udata_file_path, 'wb') as unibu_file:
                        unibu_file.write(decoded[0])
                        self.log.debug("Submitted dropped file for analysis: %s" % udata_file_path)
            else:
                if len(uniq_char) > 6:
                    decoded_res.append((hashlib.sha256(decoded[0]).hexdigest(), len(decoded), decoded[1], decoded[0]))

        return shalist, decoded_res

    # Base64 Parse
    def b64(self, request, b64_string):
        """
        Using some selected code from 'base64dump.py' by Didier Stevens@https://DidierStevens.com
        """
        results = {}
        if len(b64_string) >= 16 and len(b64_string) % 4 == 0:
            try:
                base64data = binascii.a2b_base64(b64_string)
                sha256hash = hashlib.sha256(base64data).hexdigest()
                # Search for embedded files of interest
                if 800 < len(base64data) < 8000000:
                    m = magic.Magic(mime=True)
                    mag = magic.Magic()
                    ftype = m.from_buffer(base64data)
                    mag_ftype = mag.from_buffer(base64data)
                    for ft in self.filetypes:
                        if (ft in ftype and not 'octet-stream' in ftype) or ft in mag_ftype:
                            b64_file_path = os.path.join(self.working_directory, "{}_b64_decoded"
                                                     .format(sha256hash[0:10]))
                            request.add_extracted(b64_file_path, "Extracted b64 file during FrankenStrings analysis.")
                            with open(b64_file_path, 'wb') as b64_file:
                                b64_file.write(base64data)
                                self.log.debug("Submitted dropped file for analysis: %s" % b64_file_path)

                            results[sha256hash] = [len(b64_string), b64_string[0:50],
                                                   "[Possible file contents. See extracted files.]", ""]
                            return results

                if all(ord(c) < 128 for c in base64data):
                    asc_b64 = self.ascii_dump(base64data)
                    # If data has less then 7 uniq chars then ignore
                    uniq_char = ''.join(set(asc_b64))
                    if len(uniq_char) > 6:
                        results[sha256hash] = [len(b64_string), b64_string[0:50], asc_b64, base64data]
            except:
                return results
        return results

    def unhexlify_ascii(self, request, data, tag, patterns, res):
        """
        Plain ascii hex conversion.
        '"""
        filefound = False
        tags = {}
        if len(data) % 2 != 0:
            data = data[:-1]
        try:
            binstr = binascii.unhexlify(data)
        except Exception as e:
            return filefound, tags
        # If data has less than 7 uniq chars return
        uniq_char = ''.join(set(binstr))
        if len(uniq_char) < 7:
            return filefound, tags
        # If data is greater than 500 bytes create extracted file
        if len(binstr) > 500:
            if len(uniq_char) < 20:
                return filefound, tags
            filefound = True
            sha256hash = hashlib.sha256(binstr).hexdigest()
            ascihex_file_path = os.path.join(self.working_directory, "{}_asciihex_decoded"
                                                 .format(sha256hash[0:10]))
            request.add_extracted(ascihex_file_path, "Extracted ascii-hex file during FrankenStrings analysis.")
            with open(ascihex_file_path, 'wb') as fh:
                    fh.write(binstr)
            return filefound, tags
        # Else look for patterns
        tags = self.ioc_to_tag(binstr, patterns, res, taglist=True, st_max_length=1000)
        if len(tags) > 0:
            return filefound, tags
        # Else look for small XOR encoded strings in code files
        if 20 < len(binstr) <= 128 and tag.startswith('code/'):
            xresult = bbcrack(binstr, level='small_string')
            if len(xresult) > 0:
                for transform, regex, match in xresult:
                    if regex.startswith('EXE_'):
                        tags['BB_PESTUDIO_BLACKLIST_STRING'] = {data: [match, transform]}
                    else:
                        tags["BB_{}" .format(regex)] = {data: [match, transform]}
                    return filefound, tags
        return filefound, tags

    def unhexlify_rtf(self, request, data):
        """
        RTF objdata ascii hex extract. Inspired by Talos blog post "How Malformed RTF Defeats Security Engines", and
        help from information in http://www.decalage.info/rtf_tricks. This is a backup to the oletools service.
        Will need more work.
        """
        result = []
        try:
            # Get objdata
            while data.find("\\objdata") != -1:

                obj = data.find("\\objdata")
                data = data[obj:]

                d = ""
                bcount = -1
                # Walk the objdata item and extract until 'real' closing brace reached.
                while bcount != 0:
                    if len(data) == 0:
                        # Did not find 'real' closing brace
                        return result
                    else:
                        c = data[0]
                        if c == '{':
                            bcount -= 1
                        if c == '}':
                            bcount += 1
                        d += c
                        data = data[1:]

                # Transform the data to remove any potential obfuscation:
                # 1. Attempt to find OLESAVETOSTREAM serial string (01050000 02000000 = "OLE 1.0 object")and remove all
                # characters up to doc header if found. This section will need to be improved later.
                olesavetostream = re.compile(r"^\\objdata.{0,2000}"
                                             r"0[\s]*1[\s]*0[\s]*5[\s]*0[\s]*0[\s]*0[\s]*0[\s]*"
                                             r"0[\s]*2[\s]*0[\s]*0[\s]*0[\s]*0",
                                             re.DOTALL)
                if re.search(olesavetostream, d):
                    docstart = d[:2011].upper().find("D0CF11E0")
                    if docstart != -1:
                        d = d[docstart:]
                # 2. Transform any embedded binary data
                if d.find("\\bin") != -1:
                    binreg = re.compile(r"\\bin[0]{0,250}[1-9]{0,4}")
                    for b in re.findall(binreg, d):
                        blen = re.sub("[a-z0]{0,4}", "", b[-4:])
                        rstr = re.escape(b)+"[\s]*"+".{"+blen+"}"
                        d = re.sub(rstr, str(rstr[-int(blen):].encode('hex')), d)
                # 3. Remove remaining control words
                d = re.sub(r"\\[A-Za-z0-9]+[\s]*", "", d)
                # 4. Remove any other characters that are not ascii hex
                d = re.sub("[ -/:-@\[-`{-~g-zG-Z\s\x00]", "", ''.join([x for x in d if ord(x) < 128]))

                # Convert the ascii hex and extract file
                if len(d) > 0:
                    if len(d) % 2 != 0:
                        d = d[:-1]
                    bstr = binascii.unhexlify(d)
                    sha256hash = hashlib.sha256(bstr).hexdigest()
                    ascihex_path = os.path.join(self.working_directory, "{}_rtfobj_hex_decoded"
                                                .format(sha256hash[0:10]))
                    request.add_extracted(ascihex_path, "Extracted rtf objdata ascii hex file during "
                                                        "FrankenStrings analysis.")
                    with open(ascihex_path, 'wb') as fh:
                        fh.write(bstr)
                    result.append(sha256hash)
        except:
            result = []
        return result

    # Executable extraction
    def pe_dump(self, request, temp_file, offset):
        """
        Use PEFile application to find the end of the file (biggest section length wins). Else if PEFile fails, extract
        from offset all the way to the end of the initial file (granted, this is uglier).
        """
        try:
            with open(temp_file, "rb") as f:
                mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

            pedata = mm[offset:]

            try:
                peinfo = pefile.PE(data=pedata)
                lsize = 0
                pefile.PE()
                for section in peinfo.sections:
                    size = section.PointerToRawData + section.SizeOfRawData
                    if size > lsize:
                        lsize = size
                if lsize > 0:
                    pe_extract = pedata[0:lsize]
                else:
                    pe_extract = pedata
            except:
                pe_extract = pedata

            xpe_file_path = os.path.join(self.working_directory, "{}_xorpe_decoded"
                                     .format(hashlib.sha256(pe_extract).hexdigest()[0:10]))
            request.add_extracted(xpe_file_path, "Extracted xor file during FrakenStrings analysis.")
            with open(xpe_file_path, 'wb') as exe_file:
                exe_file.write(pe_extract)
                self.log.debug("Submitted dropped file for analysis: %s" % xpe_file_path)
        finally:
            try:
                mm.close()
            except:
                return

    # Flare Floss Methods:
    @staticmethod
    def sanitize_string_for_printing(s):
        """
        Copyright FireEye Labs
        Extracted code from FireEye Flare-Floss source code found here:
        http://github.com/fireeye/flare-floss
        Return sanitized string for printing.
        :param s: input string
        :return: sanitized string
        """
        try:
            sanitized_string = s.encode('unicode_escape')
            sanitized_string = sanitized_string.replace('\\\\', '\\')  # print single backslashes
            sanitized_string = "".join(c for c in sanitized_string if c in string.printable)
            return sanitized_string
        except:
            return

    @staticmethod
    def filter_unique_decoded(decoded_strings):
        """
        Copyright FireEye Labs
        Extracted code from FireEye Flare-Floss source code found here:
        http://github.com/fireeye/flare-floss
        """
        try:
            unique_values = set()
            originals = []
            for decoded in decoded_strings:
                hashable = (decoded.va, decoded.s, decoded.decoded_at_va, decoded.fva)
                if hashable not in unique_values:
                    unique_values.add(hashable)
                    originals.append(decoded)
            return originals
        except:
            return
        
    @staticmethod
    def decode_strings(vw, function_index, decoding_functions_candidates):
        """
        Copyright FireEye Labs
        Extracted code from FireEye Flare-Floss source code found here:
        http://github.com/fireeye/flare-floss
        FLOSS string decoding algorithm
        :param vw: vivisect workspace
        :param function_index: function data
        :param decoding_functions_candidates: identification manager
        :return: list of decoded strings ([DecodedString])
        """
        try:
            from floss import string_decoder
            decoded_strings = []
            for fva, _ in decoding_functions_candidates:
                for ctx in string_decoder.extract_decoding_contexts(vw, fva):
                    for delta in string_decoder.emulate_decoding_routine(vw, function_index, fva, ctx):
                        for delta_bytes in string_decoder.extract_delta_bytes(delta, ctx.decoded_at_va, fva):
                            for decoded_string in string_decoder.extract_strings(delta_bytes):
                                decoded_strings.append(decoded_string)
            return decoded_strings
        except:
            return

    @staticmethod
    def get_all_plugins():
        """
        Copyright FireEye Labs
        Extracted code from FireEye Flare-Floss source code found here:
        http://github.com/fireeye/flare-floss
        Return all plugins to be run.
        """
        try:
            from floss.interfaces import DecodingRoutineIdentifier
            from floss.plugins import arithmetic_plugin, function_meta_data_plugin, library_function_plugin
            ps = DecodingRoutineIdentifier.implementors()
            if len(ps) == 0:
                ps.append(function_meta_data_plugin.FunctionCrossReferencesToPlugin())
                ps.append(function_meta_data_plugin.FunctionArgumentCountPlugin())
                ps.append(function_meta_data_plugin.FunctionIsThunkPlugin())
                ps.append(function_meta_data_plugin.FunctionBlockCountPlugin())
                ps.append(function_meta_data_plugin.FunctionInstructionCountPlugin())
                ps.append(function_meta_data_plugin.FunctionSizePlugin())
                ps.append(function_meta_data_plugin.FunctionRecursivePlugin())
                ps.append(library_function_plugin.FunctionIsLibraryPlugin())
                ps.append(arithmetic_plugin.XORPlugin())
                ps.append(arithmetic_plugin.ShiftPlugin())
            return ps
        except:
            return

# --- Execute ----------------------------------------------------------------------------------------------------------

    def execute(self, request):
        """
        Main Module.
        """
        result = Result()
        request.result = result
        patterns = PatternMatch()

        # Filters for submission modes. Change at will! (Listed in order of use)
        if request.deep_scan:
            # Maximum size of submitted file to run this service:
            max_size = 8000000
            # String length minimum
            # Used in basic ASCII and UNICODE modules. Also the filter size for any code that sends strings
            # to patterns.py
            # String length maximum
            # Used in basic ASCII and UNICODE modules:
            max_length = 1000000
            # String list maximum size
            # List produced by basic ASCII and UNICODE module results and will determine
            # if patterns.py will only evaluate network IOC patterns:
            st_max_size = 1000000
            # BBcrack maximum size of submitted file to run module:
            bb_max_size = 200000
            # Flare Floss  maximum size of submitted file to run encoded/stacked string modules:
            ff_max_size = 200000
            # Flare Floss minimum string size for encoded/stacked string modules:
            ff_enc_min_length = 7
            ff_stack_min_length = 7
        else:
            max_size = 3000000
            max_length = 300
            st_max_size = 0
            bb_max_size = 200000
            ff_max_size = 200000
            ff_enc_min_length = 7
            ff_stack_min_length = 7

        # Begin analysis

        if (request.task.size or 0) < max_size and not request.tag.startswith("archive/"):
            # Generate section in results set
            from floss import decoding_manager
            from floss import identification_manager as im, stackstrings
            from fuzzywuzzy import process
            from tabulate import tabulate
            import viv_utils

            b64_al_results = []
            encoded_al_results = []
            encoded_al_tags = set()
            stacked_al_results = []
            xor_al_results = []
            unicode_al_results = {}
            unicode_al_dropped_results = []
            asciihex_file_found = False
            asciihex_dict = {}
            asciihex_bb_dict = {}
            rtf_al_results = []

# --- Generate Results -------------------------------------------------------------------------------------------------
            # Static strings -- all file types

            alfile = request.download()
            res = (ResultSection(SCORE.LOW, "FrankenStrings Detected Strings of Interest:",
                                 body_format=TEXT_FORMAT.MEMORY_DUMP))

            with open(alfile, "rb") as f:
                file_data = f.read()

            # Find ASCII & Unicode IOC Strings
            file_plainstr_iocs = self.ioc_to_tag(file_data, patterns, res, taglist=True, check_length=True,
                                                 strs_max_size=st_max_size, st_max_length=max_length)

            # Find Base64 encoded strings and files of interest
            for b64_tuple in re.findall('(([\x20]{0,2}[A-Za-z0-9+/]{10,}={0,2}[\r]?[\n]?){2,})', file_data):
                b64_string = b64_tuple[0].replace('\n', '').replace('\r', '').replace(' ', '')
                uniq_char = ''.join(set(b64_string))
                if len(uniq_char) > 6:
                    b64result = self.b64(request, b64_string)
                    if len(b64result) > 0:
                        b64_al_results.append(b64result)

            # UTF-16 strings
            for ust in strings.extract_unicode_strings(file_data, n=self.st_min_length):
                for b64_tuple in re.findall('(([\x20]{0,2}[A-Za-z0-9+/]{10,}={0,2}[\r]?[\n]?){2,})', ust.s):
                    b64_string = b64_tuple[0].decode('utf-8').replace('\n', '').replace('\r', '').replace(' ', '')
                    uniq_char = ''.join(set(b64_string))
                    if len(uniq_char) > 6:
                        b64result = self.b64(request, b64_string)
                        if len(b64result) > 0:
                            b64_al_results.append(b64result)

            # Balbuzard's bbcrack XOR'd strings to find embedded patterns/PE files of interest
            xresult = []
            if (request.task.size or 0) < bb_max_size:
                if request.deep_scan:
                    xresult = bbcrack(file_data, level=2)
                else:
                    xresult = bbcrack(file_data, level=1)

                xindex = 0
                for transform, regex, offset, score, smatch in xresult:
                    if regex == 'EXE_HEAD':
                        xindex += 1
                        xtemp_file = os.path.join(self.working_directory, "EXE_HEAD_{0}_{1}_{2}.unXORD"
                                                  .format(xindex, offset, score))
                        with open(xtemp_file, 'wb') as xdata:
                            xdata.write(smatch)
                        self.pe_dump(request, xtemp_file, offset)
                        xor_al_results.append('%-20s %-7s %-7s %-50s' % (str(transform), offset, score,
                                                                         "[PE Header Detected. See Extracted files]"))
                    else:
                        xor_al_results.append('%-20s %-7s %-7s %-50s' % (str(transform), offset, score, smatch))

            # Unicode/Hex Strings -- Non-executable files
            if not request.tag.startswith("executable/"):
                for hes in self.hexencode_strings:
                    hes_regex = re.compile(re.escape(hes) + '[A-Fa-f0-9]{2}')
                    if re.search(hes_regex, file_data) is not None:
                        uhash, unires = self.decode_encoded_udata(request, hes, file_data)
                        if len(uhash) > 0:
                            for usha in uhash:
                                unicode_al_dropped_results.append('{0}_{1}' .format(usha, hes))
                        if len(unires) > 0:
                            for i in unires:
                                unicode_al_results[i[0]] = [i[1], i[2], i[3]]

                for hex_tuple in re.findall('(([0-9a-fA-F]{2}){30,})', file_data):
                    hex_string = hex_tuple[0]
                    afile_found, asciihex_results = self.unhexlify_ascii(request, hex_string, request.tag, patterns,
                                                                         res)
                    if afile_found:
                        asciihex_file_found = True
                    if asciihex_results != "":
                        for ask, asi in asciihex_results.iteritems():
                            if ask.startswith('BB_'):
                                ask = ask.split('_', 1)[1]
                                if ask not in asciihex_bb_dict:
                                    asciihex_bb_dict[ask] = []
                                asciihex_bb_dict[ask].append(asi)
                            else:
                                if ask not in asciihex_dict:
                                    asciihex_dict[ask] = []
                                asciihex_dict[ask].append(asi)

                # RTF object data hex
                if file_data.find("\\objdata") != -1:
                    rtf_al_results = self.unhexlify_rtf(request, file_data)

            # Encoded/Stacked strings -- Windows executable file types
            if (request.task.size or 0) < ff_max_size:

                m = magic.Magic()
                file_magic = m.from_buffer(file_data)

                if request.tag.startswith("executable/windows/") and not file_magic.endswith("compressed"):

                    try:
                        vw = viv_utils.getWorkspace(alfile, should_save=False)
                    except:
                        vw = False

                    if vw:
                        try:
                            selected_functions = set(vw.getFunctions())
                            selected_plugins = self.get_all_plugins()

                            # Encoded strings
                            decoding_functions_candidates = im.identify_decoding_functions(vw, selected_plugins,
                                                                                       selected_functions)
                            candidates = decoding_functions_candidates.get_top_candidate_functions(10)
                            function_index = viv_utils.InstructionFunctionIndex(vw)
                            decoded_strings = self.decode_strings(vw, function_index, candidates)
                            decoded_strings = self.filter_unique_decoded(decoded_strings)

                            long_strings = filter(lambda l_ds: len(l_ds.s) >= ff_enc_min_length, decoded_strings)

                            for ds in long_strings:
                                s = self.sanitize_string_for_printing(ds.s)
                                if ds.characteristics["location_type"] == decoding_manager.LocationType.STACK:
                                    offset_string = "[STACK]"
                                elif ds.characteristics["location_type"] == decoding_manager.LocationType.HEAP:
                                    offset_string = "[HEAP]"
                                else:
                                    offset_string = hex(ds.va or 0)
                                encoded_al_results.append((offset_string, hex(ds.decoded_at_va), s))
                                encoded_al_tags.add(s)

                            # Stacked Strings
                            # s.s = stacked string
                            # s.fva = Function
                            # s.frame_offset = Frame Offset
                            stack_strings = list(set(stackstrings.extract_stackstrings(vw, selected_functions)))
                            # Final stacked result list
                            if len(stack_strings) > 0:
                                # Filter min string length
                                extracted_strings = \
                                    list(filter(lambda l_s: len(l_s.s) >= ff_stack_min_length, stack_strings))

                                # Set up list to ensure stacked strings are not compared twice
                                picked = set()
                                # Create namedtuple for groups of like-stacked strings
                                al_tuples = namedtuple('Group', 'stringl funoffl')

                                # Create set of stacked strings for fuzzywuzzy to compare
                                choices = set()
                                for s in extracted_strings:
                                    choices.add(s.s)

                                # Begin Comparison
                                for s in extracted_strings:
                                    if s.s in picked:
                                        pass
                                    else:
                                        # Add stacked string to used-value list (picked)
                                        picked.add(s.s)
                                        # Create lists for 'strings' and 'function:frame offset' results
                                        sstrings = []
                                        funoffs = []
                                        # Append initial stacked string tuple values to lists
                                        indexnum = 1
                                        sstrings.append('{0}:::{1}' .format(indexnum, s.s.encode()))
                                        funoffs.append('{0}:::{1}:{2}' .format(indexnum, hex(s.fva),
                                                                               hex(s.frame_offset)))
                                        # Use fuzzywuzzy process module to compare initial stacked string to remaining
                                        # stack string values
                                        like_ss = process.extract(s.s, choices, limit=50)

                                        if len(like_ss) > 0:
                                            # Filter scores in like_ss with string compare scores less than 75
                                            filtered_likess = filter(lambda ls: ls[1] > 74, like_ss)
                                            if len(filtered_likess) > 0:
                                                for likestring in filtered_likess:
                                                    for subs in extracted_strings:
                                                        if subs == s or subs.s != likestring[0]:
                                                            pass
                                                        else:
                                                            indexnum += 1
                                                            # Add all similar strings to picked list and remove from
                                                            # future comparison list (choices)
                                                            picked.add(subs.s)
                                                            if subs.s in choices:
                                                                choices.remove(subs.s)
                                                            # For all similar stacked strings add values to lists
                                                            sstrings.append('{0}:::{1}' .format(indexnum,
                                                                                                subs.s.encode()))
                                                            funoffs.append('{0}:::{1}:{2}'
                                                                           .format(indexnum, hex(subs.fva),
                                                                                   hex(subs.frame_offset)))

                                        # Remove initial stacked string from comparison list (choices)
                                        if s.s in choices:
                                            choices.remove(s.s)
                                        # Create namedtuple to add to final results
                                        fuzresults = al_tuples(stringl=sstrings, funoffl=funoffs)
                                        # Add namedtuple to final result list
                                        stacked_al_results.append(fuzresults)
                        except:
                            pass
# --- Store Results ----------------------------------------------------------------------------------------------------

            if len(file_plainstr_iocs) > 0 \
                    or len(b64_al_results) > 0 \
                    or len(xor_al_results) > 0 \
                    or len(encoded_al_results) > 0 \
                    or len(stacked_al_results) > 0 \
                    or len(unicode_al_results) > 0 or len(unicode_al_dropped_results) > 0\
                    or asciihex_file_found or len(asciihex_dict) > 0 or len(asciihex_bb_dict) \
                    or len(rtf_al_results) > 0:

                # Store ASCII String Results
                if len(file_plainstr_iocs) > 0:
                    ascii_res = (ResultSection(SCORE.NULL, "FLARE FLOSS Plain IOC Strings:",
                                               body_format=TEXT_FORMAT.MEMORY_DUMP,
                                               parent=res))
                    for k, l in sorted(file_plainstr_iocs.iteritems()):
                        for i in sorted(l):
                            ascii_res.add_line("Found %s string: %s" % (k.replace("_", " "), i))

                # Store B64 Results
                if len(b64_al_results) > 0:
                    b64_res = (ResultSection(SCORE.NULL, "Base64 Strings:", parent=res))
                    b64index = 0
                    for b64dict in b64_al_results:
                        for b64k, b64l in b64dict.iteritems():
                            b64index += 1
                            sub_b64_res = (ResultSection(SCORE.NULL, "Result {}" .format(b64index), parent=b64_res))
                            sub_b64_res.add_line('BASE64 TEXT SIZE: {}' .format(b64l[0]))
                            sub_b64_res.add_line('BASE64 SAMPLE TEXT: {}[........]' .format(b64l[1]))
                            sub_b64_res.add_line('DECODED SHA256: {}'.format(b64k))
                            subb_b64_res = (ResultSection(SCORE.NULL, "DECODED ASCII DUMP:",
                                                          body_format=TEXT_FORMAT.MEMORY_DUMP, parent=sub_b64_res))
                            subb_b64_res.add_line('{}' .format(b64l[2]))
                            if b64l[3] != "":
                                self.ioc_to_tag(b64l[3], patterns, res, st_max_length=1000)


                # Store XOR embedded results
                # Result Graph:
                if len(xor_al_results) > 0:
                    x_res = (ResultSection(SCORE.NULL, "BBCrack XOR'd Strings:", body_format=TEXT_FORMAT.MEMORY_DUMP,
                                           parent=res))
                    xformat_string = '%-20s %-7s %-7s %-50s'
                    xcolumn_names = ('Transform', 'Offset', 'Score', 'Decoded String')
                    x_res.add_line(xformat_string % xcolumn_names)
                    x_res.add_line(xformat_string % tuple(['-' * len(s) for s in xcolumn_names]))
                    for xst in xor_al_results:
                        x_res.add_line(xst)
                # Result Tags:
                for transform, regex, offset, score, smatch in xresult:
                    if not regex.startswith("EXE_"):
                        res.add_tag(TAG_TYPE[regex], smatch, TAG_WEIGHT.LOW)
                        res.add_tag(TAG_TYPE[regex], smatch, TAG_WEIGHT.LOW)

                # Store Unicode Encoded Data:
                if len(unicode_al_results) > 0 or len(unicode_al_dropped_results) > 0:
                    unicode_emb_res = (ResultSection(SCORE.NULL, "Found Unicode-Like Strings in Non-Executable:",
                                                     body_format=TEXT_FORMAT.MEMORY_DUMP,
                                                     parent=res))

                    if len(unicode_al_results) > 0:
                        unires_index = 0
                        for uk, ui in unicode_al_results.iteritems():
                            unires_index += 1
                            sub_uni_res = (ResultSection(SCORE.NULL, "Result {}".format(unires_index),
                                                          parent=unicode_emb_res))
                            sub_uni_res.add_line('ENCODED TEXT SIZE: {}'.format(ui[0]))
                            sub_uni_res.add_line('ENCODED SAMPLE TEXT: {}[........]'.format(ui[1]))
                            sub_uni_res.add_line('DECODED SHA256: {}'.format(uk))
                            subb_uni_res = (ResultSection(SCORE.NULL, "DECODED ASCII DUMP:",
                                                          body_format=TEXT_FORMAT.MEMORY_DUMP,
                                                          parent=sub_uni_res))
                            subb_uni_res.add_line('{}'.format(ui[2]))
                            # Look for IOCs of interest
                            self.ioc_to_tag(ui[2], patterns, res, st_max_length=1000)

                    if len(unicode_al_dropped_results) > 0:
                        for ures in unicode_al_dropped_results:
                            uhas = ures.split('_')[0]
                            uenc = ures.split('_')[1]
                            unicode_emb_res.add_line("Extracted over 50 bytes of possible embedded unicode with {0} "
                                                     "encoding. SHA256: {1}. See extracted files." .format(uenc, uhas))
                # Store Ascii Hex Encoded Data:
                if asciihex_file_found:

                    asciihex_emb_res = (ResultSection(SCORE.NULL, "Found Large Ascii Hex Strings in Non-Executable:",
                                                      body_format=TEXT_FORMAT.MEMORY_DUMP,
                                                      parent=res))
                    asciihex_emb_res.add_line("Extracted possible ascii-hex object(s). See extracted files.")

                if len(asciihex_dict) > 0:
                    asciihex_res = (ResultSection(SCORE.NULL, "ASCII HEX DECODED IOC Strings:",
                                                  body_format=TEXT_FORMAT.MEMORY_DUMP,
                                                  parent=res))
                    for k, l in sorted(asciihex_dict.iteritems()):
                        for i in l:
                            for ii in i:
                                asciihex_res.add_line("Found %s decoded HEX string: %s" % (k.replace("_", " "), ii))

                if len(asciihex_bb_dict) > 0:
                    asciihex_res = (ResultSection(SCORE.NULL, "ASCII HEX AND XOR DECODED IOC Strings:",
                                                  parent=res))
                    xindex = 0
                    for k, l in sorted(asciihex_bb_dict.iteritems()):
                        for i in l:
                            for kk, ii in i.iteritems():
                                xindex += 1
                                asx_res = (ResultSection(SCORE.NULL, "Result {}" .format(xindex),
                                                         parent=asciihex_res))
                                asx_res.add_line("Found %s decoded HEX string, masked with transform %s:"
                                                 % (k.replace("_", " "), ii[1]))
                                asx_res.add_line("Decoded XOR string:")
                                asx_res.add_line(ii[0])
                                asx_res.add_line("Original ASCII HEX String:")
                                asx_res.add_line(kk)
                                res.add_tag(TAG_TYPE[k], ii[0], TAG_WEIGHT.LOW)

                # Store RTF Objdata Encoded Data:
                if len(rtf_al_results) > 0:
                    rtfobjdata_emb_res = (ResultSection(SCORE.NULL, "Found RTF Objdata Strings in Non-Executable:",
                                                        body_format=TEXT_FORMAT.MEMORY_DUMP,
                                                        parent=res))
                    for rres in rtf_al_results:
                        rtfobjdata_emb_res.add_line("Extracted possible RTF objdata objects. SHA256: {}. "
                                                    "See extracted files." .format(rres))

                # Store Encoded String Results
                if len(encoded_al_results) > 0:
                    encoded_res = (ResultSection(SCORE.NULL, "FLARE FLOSS Decoded Strings:",
                                                 body_format=TEXT_FORMAT.MEMORY_DUMP,
                                                 parent=res))
                    encoded_res.add_line(tabulate(encoded_al_results, headers=["Offset", "Called At", "String"]))
                    # Create AL tag for each unique decoded string
                    for st in encoded_al_tags:
                        res.add_tag(TAG_TYPE['FILE_DECODED_STRING'], st[0:75], TAG_WEIGHT.LOW)
                        # Create tags for strings matching indicators of interest
                        if len(st) >= self.st_min_length:
                            self.ioc_to_tag(st, patterns, res, st_max_length=1000)

                # Store Stacked String Results
                if len(stacked_al_results) > 0:
                    stacked_res = (ResultSection(SCORE.NULL, "FLARE FLOSS Stacked Strings:",
                                                 body_format=TEXT_FORMAT.MEMORY_DUMP, parent=res))
                    for s in sorted(stacked_al_results):
                        groupname = re.sub(r'^[0-9]+:::', '', min(s.stringl, key=len))
                        group_res = (ResultSection(SCORE.NULL, "Group:'{0}' Strings:{1}" .format(groupname,
                                                                                                 len(s.stringl)),
                                                   body_format=TEXT_FORMAT.MEMORY_DUMP, parent=stacked_res))
                        group_res.add_line("String List:\n{0}\nFunction:Offset List:\n{1}"
                                           .format(re.sub(r'(^\[|\]$)', '', str(s.stringl)),
                                                   re.sub(r'(^\[|\]$)', '', str(s.funoffl))))
                        # Create tags for strings matching indicators of interest
                        for st in s.stringl:
                            extract_st = re.sub(r'^[0-9]+:::', '', st)
                            if len(extract_st) >= self.st_min_length:
                                self.ioc_to_tag(extract_st, patterns, res, st_max_length=1000)

                result.add_result(res)
