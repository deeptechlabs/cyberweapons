"""
Crow Bar Service
See README.md for details about this service.
"""
from assemblyline.al.service.base import ServiceBase
from assemblyline.al.common.result import Result, ResultSection, SCORE, TAG_TYPE, TAG_WEIGHT, TEXT_FORMAT

import binascii
from collections import Counter
from os import path
import re
import unicodedata


class CrowBar(ServiceBase):
    SERVICE_CATEGORY = 'Static Analysis'
    SERVICE_ACCEPTS = '(code/.*|unknown)'
    SERVICE_DESCRIPTION = "Code File De-obfuscator"
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_TIMEOUT = 150
    SERVICE_ENABLED = True
    SERVICE_CPU_CORES = 0.5
    SERVICE_RAM_MB = 256

    def __init__(self, cfg=None):
        super(CrowBar, self).__init__(cfg)
        self.validchars = \
            ' 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
        self.binchars = ''.join([c for c in map(chr, range(0, 256)) if c not in self.validchars])
        self.max_attempts = 10

    def start(self):
        self.log.debug("CrowBar service started")

    # noinspection PyUnresolvedReferences,PyGlobalUndefined
    def import_service_deps(self):
        global PatternMatch, BeautifulSoup
        from bs4 import BeautifulSoup
        from al_services.alsvc_frankenstrings.balbuzard.patterns import PatternMatch

    # --- Support Modules ----------------------------------------------------------------------------------------------

    def submit_extracted(self, res_file, res, request):
        h = hash(res_file)
        file_path = path.join(self.working_directory, "{}_beautified_script".format(abs(h)))
        request.add_extracted(file_path, "Extracted file during CrowBar analysis.")
        res.add_line("Extracted file during CrowBar analysis.")
        with open(file_path, 'wb') as exe_file:
            res_file = ''.join([x for x in res_file if ord(x) < 128])
            exe_file.write(res_file)

    # noinspection PyBroadException
    @staticmethod
    def decode(data):
        """
        Modified code that was written by Didier Stevens
        https://blog.didierstevens.com/2016/03/29/decoding-vbe/
        """
        try:
            d_decode = {9: '\x57\x6E\x7B', 10: '\x4A\x4C\x41', 11: '\x0B\x0B\x0B', 12: '\x0C\x0C\x0C',
                        13: '\x4A\x4C\x41', 14: '\x0E\x0E\x0E', 15: '\x0F\x0F\x0F', 16: '\x10\x10\x10',
                        17: '\x11\x11\x11', 18: '\x12\x12\x12', 19: '\x13\x13\x13', 20: '\x14\x14\x14',
                        21: '\x15\x15\x15', 22: '\x16\x16\x16', 23: '\x17\x17\x17', 24: '\x18\x18\x18',
                        25: '\x19\x19\x19', 26: '\x1A\x1A\x1A', 27: '\x1B\x1B\x1B', 28: '\x1C\x1C\x1C',
                        29: '\x1D\x1D\x1D', 30: '\x1E\x1E\x1E', 31: '\x1F\x1F\x1F', 32: '\x2E\x2D\x32',
                        33: '\x47\x75\x30', 34: '\x7A\x52\x21', 35: '\x56\x60\x29', 36: '\x42\x71\x5B',
                        37: '\x6A\x5E\x38', 38: '\x2F\x49\x33', 39: '\x26\x5C\x3D', 40: '\x49\x62\x58',
                        41: '\x41\x7D\x3A', 42: '\x34\x29\x35', 43: '\x32\x36\x65', 44: '\x5B\x20\x39',
                        45: '\x76\x7C\x5C', 46: '\x72\x7A\x56', 47: '\x43\x7F\x73', 48: '\x38\x6B\x66',
                        49: '\x39\x63\x4E', 50: '\x70\x33\x45', 51: '\x45\x2B\x6B', 52: '\x68\x68\x62',
                        53: '\x71\x51\x59', 54: '\x4F\x66\x78', 55: '\x09\x76\x5E', 56: '\x62\x31\x7D',
                        57: '\x44\x64\x4A', 58: '\x23\x54\x6D', 59: '\x75\x43\x71', 60: '\x4A\x4C\x41',
                        61: '\x7E\x3A\x60', 62: '\x4A\x4C\x41', 63: '\x5E\x7E\x53', 64: '\x40\x4C\x40',
                        65: '\x77\x45\x42', 66: '\x4A\x2C\x27', 67: '\x61\x2A\x48', 68: '\x5D\x74\x72',
                        69: '\x22\x27\x75', 70: '\x4B\x37\x31', 71: '\x6F\x44\x37', 72: '\x4E\x79\x4D',
                        73: '\x3B\x59\x52', 74: '\x4C\x2F\x22', 75: '\x50\x6F\x54', 76: '\x67\x26\x6A',
                        77: '\x2A\x72\x47', 78: '\x7D\x6A\x64', 79: '\x74\x39\x2D', 80: '\x54\x7B\x20',
                        81: '\x2B\x3F\x7F', 82: '\x2D\x38\x2E', 83: '\x2C\x77\x4C', 84: '\x30\x67\x5D',
                        85: '\x6E\x53\x7E', 86: '\x6B\x47\x6C', 87: '\x66\x34\x6F', 88: '\x35\x78\x79',
                        89: '\x25\x5D\x74', 90: '\x21\x30\x43', 91: '\x64\x23\x26', 92: '\x4D\x5A\x76',
                        93: '\x52\x5B\x25', 94: '\x63\x6C\x24', 95: '\x3F\x48\x2B', 96: '\x7B\x55\x28',
                        97: '\x78\x70\x23', 98: '\x29\x69\x41', 99: '\x28\x2E\x34', 100: '\x73\x4C\x09',
                        101: '\x59\x21\x2A', 102: '\x33\x24\x44', 103: '\x7F\x4E\x3F', 104: '\x6D\x50\x77',
                        105: '\x55\x09\x3B', 106: '\x53\x56\x55', 107: '\x7C\x73\x69', 108: '\x3A\x35\x61',
                        109: '\x5F\x61\x63', 110: '\x65\x4B\x50', 111: '\x46\x58\x67', 112: '\x58\x3B\x51',
                        113: '\x31\x57\x49', 114: '\x69\x22\x4F', 115: '\x6C\x6D\x46', 116: '\x5A\x4D\x68',
                        117: '\x48\x25\x7C', 118: '\x27\x28\x36', 119: '\x5C\x46\x70', 120: '\x3D\x4A\x6E',
                        121: '\x24\x32\x7A', 122: '\x79\x41\x2F', 123: '\x37\x3D\x5F', 124: '\x60\x5F\x4B',
                        125: '\x51\x4F\x5A', 126: '\x20\x42\x2C', 127: '\x36\x65\x57'}

            d_combination = {0: 0, 1: 1, 2: 2, 3: 0, 4: 1, 5: 2, 6: 1, 7: 2, 8: 2, 9: 1, 10: 2, 11: 1, 12: 0, 13: 2,
                             14: 1, 15: 2, 16: 0, 17: 2, 18: 1, 19: 2, 20: 0, 21: 0, 22: 1, 23: 2, 24: 2, 25: 1, 26: 0,
                             27: 2, 28: 1, 29: 2, 30: 2, 31: 1, 32: 0, 33: 0, 34: 2, 35: 1, 36: 2, 37: 1, 38: 2, 39: 0,
                             40: 2, 41: 0, 42: 0, 43: 1, 44: 2, 45: 0, 46: 2, 47: 1, 48: 0, 49: 2, 50: 1, 51: 2, 52: 0,
                             53: 0, 54: 1, 55: 2, 56: 2, 57: 0, 58: 0, 59: 1, 60: 2, 61: 0, 62: 2, 63: 1}

            result = ''
            index = -1
            for char in data \
                    .replace('@&', chr(10)) \
                    .replace('@#', chr(13)) \
                    .replace('@*', '>') \
                    .replace('@!', '<') \
                    .replace('@$', '@'):
                byte = ord(char)
                if byte < 128:
                    index += 1
                if (byte == 9 or 31 < byte < 128) and byte != 60 and byte != 62 and byte != 64:
                    char = [c for c in d_decode[byte]][d_combination[index % 64]]
                result += char
            return result
        except:
            result = None
            return result

    def printable_ratio(self, text):
        return float(float(len(text.translate(None, self.binchars))) / float(len(text)))

    @staticmethod
    def add1b(s, k):
        return ''.join([chr((ord(c) + k) & 0xff) for c in s])

    def charcode(self, text):
        final = False
        output = None
        arrayofints = filter(lambda n: n < 256,
                             map(int, re.findall('(\d+)', str(re.findall('\D{1,2}\d{2,3}', text)))))
        if len(arrayofints) > 20:
            s1 = ''.join(map(chr, arrayofints))
            if self.printable_ratio(s1) > .75 and (float(len(s1)) / float(len(text))) > .10:
                # if the output is mostly readable and big enough
                output = s1

        return final, output

    @staticmethod
    def charcode_hex(text):

        final = False
        output = None
        s1 = text
        enc_str = ['\u', '%u', '\\x', '0x']

        for encoding in enc_str:
            char_len = [(16, re.compile(r'(?:' + re.escape(encoding) + '[A-Fa-f0-9]{16})+')),
                        (8, re.compile(r'(?:' + re.escape(encoding) + '[A-Fa-f0-9]{8})+')),
                        (4, re.compile(r'(?:' + re.escape(encoding) + '[A-Fa-f0-9]{4})+')),
                        (2, re.compile(r'(?:' + re.escape(encoding) + '[A-Fa-f0-9]{2})+'))]

            for r in char_len:
                hexchars = set(re.findall(r[1], text))

                for hc in hexchars:
                    data = hc
                    decoded = ''
                    if r[0] == 2:
                        while data != '':
                            decoded += binascii.a2b_hex(data[2:4])
                            data = data[4:]
                    if r[0] == 4:
                        while data != '':
                            decoded += binascii.a2b_hex(data[4:6]) + binascii.a2b_hex(data[2:4])
                            data = data[6:]
                    if r[0] == 8:
                        while data != '':
                            decoded += binascii.a2b_hex(data[8:10]) + binascii.a2b_hex(data[6:8]) + \
                                       binascii.a2b_hex(data[4:6]) + binascii.a2b_hex(data[2:4])
                            data = data[10:]
                    if r[0] == 16:
                        while data != '':
                            decoded += binascii.a2b_hex(data[16:18]) + binascii.a2b_hex(data[14:16]) + \
                                       binascii.a2b_hex(data[12:14]) + binascii.a2b_hex(data[10:12]) + \
                                       binascii.a2b_hex(data[8:10]) + binascii.a2b_hex(data[6:8]) + \
                                       binascii.a2b_hex(data[4:6]) + binascii.a2b_hex(data[2:4])
                            data = data[18:]

                    # Remove trailing NULL bytes
                    final_dec = re.sub('[\x00]*$', '', decoded)

                    if all(ord(c) < 128 for c in final_dec):
                        s1 = s1.replace(hc, final_dec)

        if s1 != text:
            output = s1

        return final, output

    @staticmethod
    def string_replace(text):
        final = False
        output = None
        if 'replace(' in text.lower():
            # Process string with replace functions calls
            # Such as "SaokzueofpigxoFile".replace(/ofpigx/g, "T").replace(/okzu/g, "v")
            s1 = text
            # Find all occurrences of string replace (JS)
            for strreplace in [o[0] for o in
                               re.findall('(["\'][^"\']+["\']((\.replace\([^)]+\))+))', s1, flags=re.I)]:
                s2 = strreplace
                # Extract all substitutions
                for str1, str2 in re.findall('\.replace\([/\'"]([^,]+)[/\'\"]g?\s*,\s*[\'\"]([^)]*)[\'\"]\)',
                                             s2):
                    # Execute the substitution
                    s2 = s2.replace(str1, str2)
                # Remove the replace calls from the layer (prevent accidental substitutions in the next step)
                s2 = s2[:s2.index('.replace(')]
                s1 = s1.replace(strreplace, s2)

            # Process global string replace
            replacements = [q for q in re.findall('replace\(\s*/([^)]+)/g?, [\'"]([^\'"]*)[\'"]', s1)]
            for str1, str2 in replacements:
                s1 = s1.replace(str1, str2)
            # Process VB string replace
            replacements = [q for q in re.findall('Replace\(\s*["\']?([^,"\']*)["\']?\s*,\s*["\']?([^,"\']*)["\']?\s*,\s*["\']?([^,"\']*)["\']?', s1)]
            for str1, str2, str3 in replacements:
                s1 = s1.replace(str1, str1.replace(str2, str3))
            output = re.sub('\.replace\(\s*/([^)]+)/g?, [\'"]([^\'"]*)[\'"]\)', '', s1)
        return final, output

    def b64decode_str(self, text):
        final = False
        output = None
        b64str = re.findall('"([A-Za-z0-9+/]{4,}=?=?)"', text)
        s1 = text
        for s in b64str:
            if len(s) % 4 == 0:
                try:
                    d = binascii.a2b_base64(s)
                except binascii.Error:
                    continue
                if all(ord(c) < 128 for c in d):
                    s1 = s1.replace(s, d)
        if s1 != text:
            output = s1
        return final, output

    @staticmethod
    def vars_of_fake_arrays(text):
        final = False
        output = None
        replacements = re.findall('var\s+([^\s=]+)\s*=\s*\[([^\]]+)\]\[(\d+)\]', text)
        if len(replacements) > 0:
            #    ,- Make sure we do not process these again
            s1 = re.sub(r'var\s+([^=]+)\s*=', r'XXX \1 =', text)
            for varname, array, pos in replacements:
                try:
                    value = re.split('\s*,\s*', array)[int(pos)]
                except IndexError:
                    # print '[' + array + '][' + pos + ']'
                    raise
                s1 = s1.replace(varname, value)
            if s1 != text:
                output = s1
        return final, output

    @staticmethod
    def array_of_strings(text):
        final = False
        output = None

        replacements = re.findall('var\s+([^\s=]+)\s*=\s*\[([^\]]+)\]\s*;', text)
        if len(replacements) > 0:
            #    ,- Make sure we do not process these again
            s1 = text
            for varname, values in replacements:
                occurences = [int(x) for x in re.findall(varname + '\s*\[(\d+)\]', s1)]
                for i in occurences:
                    try:
                        s1 = re.sub(varname + '\s*\[(%d)\]' % i, values.split(',')[i], s1)
                    except IndexError:
                        # print '[' + array + '][' + pos + ']'
                        raise
            if s1 != text:
                output = s1
        return final, output

    @staticmethod
    def concat_strings(text):
        final = False
        output = None

        s1 = re.sub('[\'"]\s*[+&]\s*[\'"]', '', text)
        if s1 != text:
            output = s1

        return final, output

    @staticmethod
    def powershell_vars(text):
        final = False
        output = None
        replacements_string = re.findall(r'(\$\w+)\s*=[^=]\s*[\"\']([^\"\']+)[\"\']', text)
        replacements_func = re.findall(r'(\$\w+)\s*=[^=]\s*([^\"\'][^\s]+)[\s]', text)
        if len(replacements_string) > 0 or len(replacements_func) > 0:
            #    ,- Make sure we do not process these again
            s1 = re.sub(r'[^_](\$\w+)\s*=', r'_\1 =', text)
            for varname, string in replacements_string:
                s1 = s1.replace(varname, string)
            for varname, string in replacements_func:
                s1 = s1.replace(varname, string)
            if output != text:
                output = s1

        return final, output

    @staticmethod
    def powershell_carets(text):
        final = False
        output = text.replace("^", "")
        if output == text:
            output = None
        return final, output

    def mswordmacro_vars(self, text):
        final = False
        output = None
        s1 = text.replace('\r', '')
        # bad, prevent false var replacements like YG="86"
        replacements = re.findall(r'^((\w+)\s*=\s*("[^"]+"))$', s1, re.M)
        if len(replacements) > 0:
            for full, varname, value in replacements:
                #    Make sure we do not process these again
                if len(re.findall(r'(\b' + varname + r'\b)', s1)) == 1:
                    # If there is only one instance of these, it's noise.
                    s1 = s1.replace(full, '<crowbar:mswordmacro_unused_variable_assignment>')
                else:
                    s1 = s1.replace(full, '<crowbar:mswordmacro_var_assignment>')
                    s1 = re.sub(r'(\b' + varname + r'\b)', value, s1)
                    # Create loop for stacking variables. i.e.
                    # b = "he"
                    # b = b & "llo "
                    # b = b & "world!"
                    repeat_var = value
                    repeat_true = re.findall('(' + repeat_var + '\s*=\s*(".+))', s1)
                    idx = 0
                    while True:
                        if len(repeat_true) == 0 or idx > self.max_attempts:
                            break
                        for fl, vl in repeat_true:
                            s1 = s1.replace(fl, '<crowbar:mswordmacro_var_assignment>')
                            s1 = re.sub(repeat_var, vl, s1)
                            # only do once
                            break
                        repeat_var = vl
                        repeat_true = re.findall('(' + repeat_var + '\s*=\s*(".+))', s1)
                        idx += 1

            if s1 != text:
                output = s1
        return final, output

    def simple_xor_function(self, text):
        final = False
        output = None
        xorstrings = re.findall('(\w+\("((?:[0-9A-Fa-f][0-9A-Fa-f])+)"\s*,\s*"([^"]+)"\))', text)
        option_a = []
        option_b = []
        s1 = text
        for f, x, k in xorstrings:
            res = self.xor_with_key(x.decode("hex"), k)
            if self.printable_ratio(res) == 1:
                option_a.append((f, x, k, res))
                # print 'A:',f,x,k, res
            else:
                option_a.append((f, x, k, None))
            # try by shifting the key by 1
            res = self.xor_with_key(x.decode("hex"), k[1:] + k[0])
            if self.printable_ratio(res) == 1:
                option_b.append((f, x, k, res))
                # print 'B:',f,x,k, res
            else:
                option_b.append((f, x, k, None))

        xorstrings = []
        if None not in map(lambda y: y[3], option_a):
            xorstrings = option_a
        elif None not in map(lambda z: z[3], option_b):
            xorstrings = option_b

        for f, x, k, r in xorstrings:
            if r is not None:
                s1 = s1.replace(f, '"' + r + '"')

        if text != s1:
            output = s1
        return final, output

    @staticmethod
    def xor_with_key(s, k):
        return ''.join([chr(ord(a) ^ ord(b))
                        for a, b in zip(s, (len(s) / len(k) + 1) * k)])

    @staticmethod
    def zp_xor_with_key(s, k):
        return ''.join([a if a == '\0' or a == b else chr(ord(a) ^ ord(b))
                        for a, b in zip(s, (len(s) / len(k) + 1) * k)])

    @staticmethod
    def clean_up_final_layer(text):
        output = re.sub(r'<crowbar:[^>]+>', '', text)
        output = re.sub(r'\n\s*\n', '', output)
        return output

    # noinspection PyBroadException
    def vbe_decode(self, text):
        output = None
        final = False
        try:
            evbe_regex = re.compile(r'#@~\^......==(.+)......==\^#~@')
            evbe_present = re.search(evbe_regex, text)
            if evbe_present:
                evbe_res = self.decode(evbe_present.groups()[0])
                if evbe_res and evbe_present != text:
                    evbe_start = evbe_present.start()
                    evbe_end = evbe_present.end()
                    if evbe_start == 0 and evbe_end == len(text):
                        final = True
                        output = evbe_res
                    else:
                        output = text[:evbe_start] + text + text[:evbe_end]
        except:
            pass
        finally:
            return final, output

    # noinspection PyBroadException
    @staticmethod
    def convert_wide_unicode(text):
        normalized = []
        try:
            conv = text.decode('utf-16').encode('ascii', 'ignore')
            if len(conv) > 0:
                normalized.append(conv)
            else:
                normalized = None
        except:
            normalized = None
        return normalized

    # noinspection PyBroadException
    @staticmethod
    def extract_htmlscript(text):
        scripts = []
        try:
            for s in BeautifulSoup(text, 'lxml').find_all('script'):
                if s.string is not None:
                    scripts.append(s.string)
        except:
            scripts = None
        return scripts

    # --- Run Service --------------------------------------------------------------------------------------------------
    def execute(self, request):
        """
        Main Module.
        """
        result = Result()
        request.result = result

        if (request.task.size or 0) < 50000 and (request.tag.startswith('code') or
                                                 (request.tag == "unknown" and (request.task.size or 0) < 5000)):
            patterns = PatternMatch()

            alfile = request.download()
            with open(alfile, "rb") as f:
                raw = f.read()

            # Get all IOCs that originally hit in file (to filter later- service FrankenStrings SHOULD catch it anyways)
            pat_values = patterns.ioc_match(raw, bogon_ip=True, just_network=False)
            before = []
            for k, val in pat_values.iteritems():
                if val == "":
                    asc_asc = unicodedata.normalize('NFKC', val).encode('ascii', 'ignore')
                    before.append(asc_asc)
                else:
                    for v in val:
                        before.append(v)

            # --- Stage 1 ----------------------------------------------------------------------------------------------
            # Get script(s) that we want
            code_extracts = [
                ('^unknown$', self.convert_wide_unicode),
                ('.*html.*', self.extract_htmlscript)
            ]

            extracted_parts = None
            for tu in code_extracts:
                if re.match(re.compile(tu[0]), request.tag):
                    extracted_parts = tu[1](raw)
                    break
            if extracted_parts:
                parsed = [x for x in extracted_parts]
            else:
                parsed = [raw]

            # --- Stage 2 ----------------------------------------------------------------------------------------------
            # Hack time!
            for script in parsed:
                extract_file = False
                layer = script
                layers_list = []

                if request.deep_scan:
                    self.max_attempts = 50

                techniques = [
                    ('VBE Decode', self.vbe_decode, True),
                    ('MSWord macro vars', self.mswordmacro_vars, False),
                    ('Powershell vars', self.powershell_vars, False),
                    ('Concat strings', self.concat_strings, False),
                    ('String replace', self.string_replace, False),
                    ('Powershell carets', self.powershell_carets, False),
                    ('Array of strings', self.array_of_strings, False),
                    ('Fake array vars', self.vars_of_fake_arrays, False),
                    ('Simple XOR function', self.simple_xor_function, False),
                    ('Charcode', self.charcode, False),
                    ('Charcode hex', self.charcode_hex, False),
                    ('B64 Decode', self.b64decode_str, False)
                ]

                done = False
                idx = 0
                while not done:
                    if idx > self.max_attempts:
                        break
                    done = True
                    for name, technique, extract in techniques:
                        final, res = technique(layer)
                        if res:
                            layers_list.append((name, res))
                            if extract:
                                extract_file = True
                            # Looks like it worked, restart with new layer
                            layer = res
                            done = final
                            if done:
                                break
                    idx += 1

                if len(layers_list) > 0:
                    final_score = len(layers_list) * 10
                    clean = self.clean_up_final_layer(layers_list[-1][1])
                    if clean != raw:
                        pat_values = patterns.ioc_match(clean, bogon_ip=True, just_network=False)
                        after = []
                        for k, val in pat_values.iteritems():
                            if val == "":
                                asc_asc = unicodedata.normalize('NFKC', val).encode('ascii', 'ignore')
                                after.append(asc_asc)
                            else:
                                for v in val:
                                    after.append(v)
                        diff_tags = list(set(before).symmetric_difference(set(after)))
                        # Add additional checks to see if the file should be extracted. 1500 is an arbitrary score...
                        if (len(clean) > 1000 and final_score > 500) or (len(before) < len(after)):
                            extract_file = True
                        res = (ResultSection(SCORE.NULL, "CrowBar detected possible obfuscated script:"))
                        mres = (ResultSection(SCORE.NULL, "The following CrowBar modules made deofuscation attempts:",
                                              parent=res))
                        mres.score = final_score
                        lcount = Counter([x[0] for x in layers_list])
                        for l, c in lcount.iteritems():
                            mres.add_line("{0}, {1} time(s).".format(l, c))
                        if extract_file:
                            self.submit_extracted(clean, res, request)
                        # Display final layer
                        lres = (ResultSection(SCORE.NULL, "Final layer:", body_format=TEXT_FORMAT.MEMORY_DUMP,
                                              parent=res))
                        if extract_file:
                            lres.add_line("First 500 bytes of file:")
                            lres.add_line(clean[:500])
                        else:
                            lres.add_line("First 5000 bytes of file:")
                            lres.add_line(clean[:5000])
                        # Look for all IOCs in final layer
                        if len(pat_values) > 0 and len(diff_tags) > 0:
                            for ty, val in pat_values.iteritems():
                                if val == "":
                                    asc_asc = unicodedata.normalize('NFKC', val).encode('ascii', 'ignore')
                                    if asc_asc in diff_tags:
                                        res.add_tag(TAG_TYPE[ty], asc_asc, TAG_WEIGHT.LOW)
                                else:
                                    for v in val:
                                        if v in diff_tags:
                                            res.add_tag(TAG_TYPE[ty], v, TAG_WEIGHT.LOW)
                        result.add_result(res)
