import binascii
import cStringIO
import math
import operator
import os
import re
import traceback
import xml.dom.minidom
import zlib


CHAR_WHITESPACE = 1
CHAR_DELIMITER = 2
CHAR_REGULAR = 3

CONTEXT_NONE = 1
CONTEXT_OBJ = 2
CONTEXT_XREF = 3
CONTEXT_TRAILER = 4

PDF_ELEMENT_COMMENT = 1
PDF_ELEMENT_INDIRECT_OBJECT = 2
PDF_ELEMENT_XREF = 3
PDF_ELEMENT_TRAILER = 4
PDF_ELEMENT_STARTXREF = 5
PDF_ELEMENT_MALFORMED = 6

def CopyWithoutWhiteSpace(content):
    result = []
    for token in content:
        if token[0] != CHAR_WHITESPACE:
            result.append(token)
    return result

def Obj2Str(content):
    return ''.join(map(lambda x: repr(x[1])[1:-1], CopyWithoutWhiteSpace(content)))

class cPDFDocument:
    def __init__(self, pdf_file):
        self.file = pdf_file
        self.infile = open(pdf_file, 'rb')
        self.ungetted = []
        self.position = -1

    def CloseOpenFiles(self):
        try:
            self.infile.close()
        except:
            pass

    def byte(self):
        if len(self.ungetted) != 0:
            self.position += 1
            return self.ungetted.pop()
        inbyte = self.infile.read(1)
        if not inbyte:
            return None
        self.position += 1
        return ord(inbyte)

    def unget(self, byte):
        self.position -= 1
        self.ungetted.append(byte)

def CharacterClass(byte):
    if byte == 0 or byte == 9 or byte == 10 or byte == 12 or byte == 13 or byte == 32:
        return CHAR_WHITESPACE
    if byte == 0x28 or byte == 0x29 or byte == 0x3C or byte == 0x3E or byte == 0x5B or byte == 0x5D or byte == 0x7B or byte == 0x7D or byte == 0x2F or byte == 0x25:
        return CHAR_DELIMITER
    return CHAR_REGULAR

def IsNumeric(string):
    return re.match('^[0-9]+', string)

class cPDFTokenizer:
    def __init__(self, pdf_file):
        self.oPDF = cPDFDocument(pdf_file)
        self.ungetted = []

    def CloseOpenFiles(self):
        self.oPDF.CloseOpenFiles()
        self.oPDF = None
        pass

    def Token(self):
        if len(self.ungetted) != 0:
            return self.ungetted.pop()
        if self.oPDF == None:
            return None
        self.byte = self.oPDF.byte()
        if self.byte == None:
            return None
        elif CharacterClass(self.byte) == CHAR_WHITESPACE:
            self.token = ''
            while self.byte != None and CharacterClass(self.byte) == CHAR_WHITESPACE:
                self.token = self.token + chr(self.byte)
                self.byte = self.oPDF.byte()
            if self.byte != None:
                self.oPDF.unget(self.byte)
            return (CHAR_WHITESPACE, self.token)
        elif CharacterClass(self.byte) == CHAR_REGULAR:
            self.token = ''
            while self.byte != None and CharacterClass(self.byte) == CHAR_REGULAR:
                self.token = self.token + chr(self.byte)
                self.byte = self.oPDF.byte()
            if self.byte != None:
                self.oPDF.unget(self.byte)
            return (CHAR_REGULAR, self.token)
        else:
            if self.byte == 0x3C:
                self.byte = self.oPDF.byte()
                if self.byte == 0x3C:
                    return (CHAR_DELIMITER, '<<')
                else:
                    self.oPDF.unget(self.byte)
                    return (CHAR_DELIMITER, '<')
            elif self.byte == 0x3E:
                self.byte = self.oPDF.byte()
                if self.byte == 0x3E:
                    return (CHAR_DELIMITER, '>>')
                else:
                    self.oPDF.unget(self.byte)
                    return (CHAR_DELIMITER, '>')
            elif self.byte == 0x25:
                self.token = ''
                while self.byte != None:
                    self.token = self.token + chr(self.byte)
                    if self.byte == 10 or self.byte == 13:
                        self.byte = self.oPDF.byte()
                        break
                    self.byte = self.oPDF.byte()
                if self.byte != None:
                    if self.byte == 10:
                        self.token = self.token + chr(self.byte)
                    else:
                        self.oPDF.unget(self.byte)
                return (CHAR_DELIMITER, self.token)
            return (CHAR_DELIMITER, chr(self.byte))

    def TokenIgnoreWhiteSpace(self):
        token = self.Token()
        while token != None and token[0] == CHAR_WHITESPACE:
            token = self.Token()
        return token

    def unget(self, byte):
        self.ungetted.append(byte)

class cPDFParser:
    def __init__(self, pdf_file, verbose=False, extract=None):
        self.context = CONTEXT_NONE
        self.content = []
        self.oPDFTokenizer = cPDFTokenizer(pdf_file)
        self.verbose = verbose
        self.extract = extract

    def CloseOpenFiles(self):
        self.oPDFTokenizer.CloseOpenFiles()
        pass

    def GetObject(self):
        while True:
            if self.context == CONTEXT_OBJ:
                self.token = self.oPDFTokenizer.Token()
            else:
                self.token = self.oPDFTokenizer.TokenIgnoreWhiteSpace()
            if self.token:
                if self.token[0] == CHAR_DELIMITER:
                    if self.token[1][0] == '%':
                        if self.context == CONTEXT_OBJ:
                            self.content.append(self.token)
                        else:
                            return cPDFElementComment(self.token[1])
                    elif self.token[1] == '/':
                        self.token2 = self.oPDFTokenizer.Token()
                        if (self.token2 != None) and (self.token2[0] == CHAR_REGULAR):
                            if self.context != CONTEXT_NONE:
                                self.content.append((CHAR_DELIMITER, self.token[1] + self.token2[1]))
                            elif self.verbose:
                                print 'todo 1: %s' % (self.token[1] + self.token2[1])
                        else:
                            self.oPDFTokenizer.unget(self.token2)
                            if self.context != CONTEXT_NONE:
                                self.content.append(self.token)
                            elif self.verbose:
                                print 'todo 2: %d %s' % (self.token[0], repr(self.token[1]))
                    elif self.context != CONTEXT_NONE:
                        self.content.append(self.token)
                    elif self.verbose:
                        print 'todo 3: %d %s' % (self.token[0], repr(self.token[1]))
                elif self.token[0] == CHAR_WHITESPACE:
                    if self.context != CONTEXT_NONE:
                        self.content.append(self.token)
                    elif self.verbose:
                        print 'todo 4: %d %s' % (self.token[0], repr(self.token[1]))
                else:
                    if self.context == CONTEXT_OBJ:
                        if self.token[1] == 'endobj':
                            self.oPDFElementIndirectObject = cPDFElementIndirectObject(self.objectId, self.objectVersion, self.content)
                            self.context = CONTEXT_NONE
                            self.content = []
                            return self.oPDFElementIndirectObject
                        else:
                            self.content.append(self.token)
                    elif self.context == CONTEXT_TRAILER:
                        if self.token[1] == 'startxref' or self.token[1] == 'xref':
                            self.oPDFElementTrailer = cPDFElementTrailer(self.content)
                            self.oPDFTokenizer.unget(self.token)
                            self.context = CONTEXT_NONE
                            self.content = []
                            return self.oPDFElementTrailer
                        else:
                            self.content.append(self.token)
                    elif self.context == CONTEXT_XREF:
                        if self.token[1] == 'trailer' or self.token[1] == 'xref':
                            self.oPDFElementXref = cPDFElementXref(self.content)
                            self.oPDFTokenizer.unget(self.token)
                            self.context = CONTEXT_NONE
                            self.content = []
                            return self.oPDFElementXref
                        else:
                            self.content.append(self.token)
                    else:
                        if IsNumeric(self.token[1]):
                            self.token2 = self.oPDFTokenizer.TokenIgnoreWhiteSpace()
                            if(self.token2 != None) and IsNumeric(self.token2[1]):
                                self.token3 = self.oPDFTokenizer.TokenIgnoreWhiteSpace()
                                if (self.token3 != None) and self.token3[1] == 'obj':
                                    # use int insteal of eval because eval interprets '0010' as 8. Looks like sometimes we see a number like 1.0 so convert to float and then int.
                                    self.objectId = int(float(self.token[1]))
                                    self.objectVersion = int(self.token2[1])
                                    self.context = CONTEXT_OBJ
                                else:
                                    self.oPDFTokenizer.unget(self.token3)
                                    self.oPDFTokenizer.unget(self.token2)
                                    if self.verbose:
                                        print 'todo 6: %d %s' % (self.token[0], repr(self.token[1]))
                            else:
                                self.oPDFTokenizer.unget(self.token2)
                                if self.verbose:
                                    print 'todo 7: %d %s' % (self.token[0], repr(self.token[1]))
                        elif self.token[1] == 'trailer':
                            self.context = CONTEXT_TRAILER
                            self.content = [self.token]
                        elif self.token[1] == 'xref':
                            self.context = CONTEXT_XREF
                            self.content = [self.token]
                        elif self.token[1] == 'startxref':
                            self.token2 = self.oPDFTokenizer.TokenIgnoreWhiteSpace()
                            if (self.token2 != None) and IsNumeric(self.token2[1]):
                                # use int insteal of eval because eval interprets '0010' as 8
                                return cPDFElementStartxref(int(self.token2[1]))
                            else:
                                self.oPDFTokenizer.unget(self.token2)
                                if self.verbose:
                                    print 'todo 9: %d %s' % (self.token[0], repr(self.token[1]))
                        elif self.extract:
                            self.bytes = ''
                            while self.token:
                                self.bytes += self.token[1]
                                self.token = self.oPDFTokenizer.Token()
                            return cPDFElementMalformed(self.bytes)
                        elif self.verbose:
                            print 'todo 10: %d %s' % (self.token[0], repr(self.token[1]))
            else:
                break

class cPDFElementComment:
    def __init__(self, comment):
        self.type = PDF_ELEMENT_COMMENT
        self.comment = comment
#                        if re.match('^%PDF-[0-9]\.[0-9]', self.token[1]):
#                            print repr(self.token[1])
#                        elif re.match('^%%EOF', self.token[1]):
#                            print repr(self.token[1])

class cPDFElementXref:
    def __init__(self, content):
        self.type = PDF_ELEMENT_XREF
        self.content = content

class cPDFElementTrailer:
    def __init__(self, content):
        self.type = PDF_ELEMENT_TRAILER
        self.content = content

class cPDFElementIndirectObject:
    def __init__(self, element_id, version, content):
        self.type = PDF_ELEMENT_INDIRECT_OBJECT
        self.id = element_id
        self.version = version
        self.content = content

    def GetType(self):
        content = CopyWithoutWhiteSpace(self.content)
        dictionary = 0
        for i in range(0, len(content)):
            if content[i][0] == CHAR_DELIMITER and content[i][1] == '<<':
                dictionary += 1
            if content[i][0] == CHAR_DELIMITER and content[i][1] == '>>':
                dictionary -= 1
            if dictionary == 1 and content[i][0] == CHAR_DELIMITER and EqualCanonical(content[i][1], '/Type') and i < len(content) - 1:
                return content[i+1][1]
        return ''

    def GetReferences(self):
        content = CopyWithoutWhiteSpace(self.content)
        references = []
        for i in range(0, len(content)):
            if i > 1 and content[i][0] == CHAR_REGULAR and content[i][1] == 'R' and content[i-2][0] == CHAR_REGULAR and IsNumeric(content[i-2][1]) and content[i-1][0] == CHAR_REGULAR and IsNumeric(content[i-1][1]):
                references.append((content[i-2][1], content[i-1][1], content[i][1]))
        return references

    def References(self, index):
        for ref in self.GetReferences():
            if ref[0] == index:
                return True
        return False

    def ContainsStream(self):
        for i in range(0, len(self.content)):
            if self.content[i][0] == CHAR_REGULAR and self.content[i][1] == 'stream':
                return self.content[0:i]
        return False

    def Contains(self, keyword):
        data = ''
        for i in range(0, len(self.content)):
            if self.content[i][1] == 'stream':
                break
            else:
                data += Canonicalize(self.content[i][1])
        return data.upper().find(keyword.upper()) != -1

    def Stream(self, stream_filter=True):
        state = 'start'
        countDirectories = 0
        data = ''
        filters = []
        for i in range(0, len(self.content)):
            if state == 'start':
                if self.content[i][0] == CHAR_DELIMITER and self.content[i][1] == '<<':
                    countDirectories += 1
                if self.content[i][0] == CHAR_DELIMITER and self.content[i][1] == '>>':
                    countDirectories -= 1
                if countDirectories == 1 and self.content[i][0] == CHAR_DELIMITER and EqualCanonical(self.content[i][1], '/Filter'):
                    state = 'stream_filter'
            elif state == 'stream_filter':
                if self.content[i][0] == CHAR_DELIMITER and self.content[i][1][0] == '/':
                    filters = [self.content[i][1]]
                    state = 'search-stream'
                elif self.content[i][0] == CHAR_DELIMITER and self.content[i][1] == '[':
                    state = 'stream_filter-list'
            elif state == 'stream_filter-list':
                if self.content[i][0] == CHAR_DELIMITER and self.content[i][1][0] == '/':
                    filters.append(self.content[i][1])
                elif self.content[i][0] == CHAR_DELIMITER and self.content[i][1] == ']':
                    state = 'search-stream'
            elif state == 'search-stream':
                if self.content[i][0] == CHAR_REGULAR and self.content[i][1] == 'stream':
                    state = 'stream-whitespace'
            elif state == 'stream-whitespace':
                if self.content[i][0] != CHAR_WHITESPACE:
                    data += self.content[i][1]
                state = 'stream-concat'
            elif state == 'stream-concat':
                if self.content[i][0] == CHAR_REGULAR and self.content[i][1] == 'endstream':
                    if stream_filter:
                        return self.Decompress(data, filters)
                    else:
                        return data
                else:
                    data += self.content[i][1]
            else:
                return 'Unexpected stream_filter state'
        return filters

    def Decompress(self, data, filters):
        for data_filter in filters:
            if EqualCanonical(data_filter, '/FlateDecode') or EqualCanonical(data_filter, '/Fl'):
                try:
                    data = FlateDecode(data)
                except:
                    return 'FlateDecode decompress failed'
            elif EqualCanonical(data_filter, '/ASCIIHexDecode') or EqualCanonical(data_filter, '/AHx'):
                try:
                    data = ASCIIHexDecode(data)
                except:
                    return 'ASCIIHexDecode decompress failed'
            elif EqualCanonical(data_filter, '/ASCII85Decode') or EqualCanonical(data_filter, '/A85'):
                try:
                    data = ASCII85Decode(data.rstrip('>'))
                except:
                    return 'ASCII85Decode decompress failed'
            elif EqualCanonical(data_filter, '/LZWDecode') or EqualCanonical(data_filter, '/LZW'):
                try:
                    data = LZWDecode(data)
                except:
                    return 'LZWDecode decompress failed'
            elif EqualCanonical(data_filter, '/RunLengthDecode') or EqualCanonical(data_filter, '/R'):
                try:
                    data = RunLengthDecode(data)
                except:
                    return 'RunLengthDecode decompress failed'
#            elif i.startswith('/CC')                        # CCITTFaxDecode
#            elif i.startswith('/DCT')                       # DCTDecode
            else:
                return 'Unsupported data_filter: %s' % repr(filters)
        if len(filters) == 0:
            return 'No filters'
        else:
            return data

class cPDFElementStartxref:
    def __init__(self, index):
        self.type = PDF_ELEMENT_STARTXREF
        self.index = index

class cPDFElementMalformed:
    def __init__(self, content):
        self.type = PDF_ELEMENT_MALFORMED
        self.content = content


def TrimLWhiteSpace(data):
    while data[0][0] == CHAR_WHITESPACE:
        data = data[1:]
    return data

def TrimRWhiteSpace(data):
    while data[-1][0] == CHAR_WHITESPACE:
        data = data[:-1]
    return data

class cPDFParseDictionary:
    def __init__(self, content, nocanonicalizedoutput):
        self.content = content
        self.nocanonicalizedoutput = nocanonicalizedoutput
        dataTrimmed = TrimLWhiteSpace(TrimRWhiteSpace(self.content))
        if self.isOpenDictionary(dataTrimmed[0]) and self.isCloseDictionary(dataTrimmed[-1]):
            self.parsed = self.ParseDictionary(dataTrimmed)
        else:
            self.parsed = None

    def isOpenDictionary(self, token):
        return token[0] == CHAR_DELIMITER and token[1] == '<<'

    def isCloseDictionary(self, token):
        return token[0] == CHAR_DELIMITER and token[1] == '>>'

    def ParseDictionary(self, tokens):
        state = 0 # start
        dictionary = []
        while tokens != []:
            if state == 0:
                if self.isOpenDictionary(tokens[0]):
                    state = 1
                else:
                    return None
            elif state == 1:
                if self.isOpenDictionary(tokens[0]):
                    pass
                elif self.isCloseDictionary(tokens[0]):
                    return dictionary
                elif tokens[0][0] != CHAR_WHITESPACE:
                    key = ConditionalCanonicalize(tokens[0][1], self.nocanonicalizedoutput)
                    value = []
                    state = 2
            elif state == 2:
                if self.isOpenDictionary(tokens[0]):
                    pass
                elif self.isCloseDictionary(tokens[0]):
                    dictionary.append((key, value))
                    return dictionary
                elif value == [] and tokens[0][0] == CHAR_WHITESPACE:
                    pass
                elif value != [] and tokens[0][1][0] == '/':
                    dictionary.append((key, value))
                    key = ConditionalCanonicalize(tokens[0][1], self.nocanonicalizedoutput)
                    value = []
                    state = 2
                else:
                    value.append(ConditionalCanonicalize(tokens[0][1], self.nocanonicalizedoutput))
            tokens = tokens[1:]

    def retrieve(self):
        return self.parsed

    def PrettyPrint(self, prefix):
        if self.parsed != None:
            print '%s<<' % prefix
            for e in self.parsed:
                print '%s  %s %s' % (prefix, e[0], ''.join(e[1]))
            print '%s>>' % prefix

def FormatOutput(data, raw):
    if raw:
        if type(data) == type([]):
            return ''.join(map(lambda x: x[1], data))
        else:
            return data
    else:
        return repr(data)

def PrintObject(pdf_object, options):
    print 'obj %d %d' % (pdf_object.id, pdf_object.version)
    print ' Type: %s' % ConditionalCanonicalize(pdf_object.GetType(), options.nocanonicalizedoutput)
    print ' Referencing: %s' % ', '.join(map(lambda x: '%s %s %s' % x, pdf_object.GetReferences()))
    stream = pdf_object.ContainsStream()
    oPDFParseDictionary = None
    if stream:
        print ' Contains stream'
        print ' %s' % FormatOutput(stream, options.raw)
        oPDFParseDictionary = cPDFParseDictionary(stream, options.nocanonicalizedoutput)
    else:
        print ' %s' % FormatOutput(pdf_object.content, options.raw)
        oPDFParseDictionary = cPDFParseDictionary(pdf_object.content, options.nocanonicalizedoutput)
    print
    oPDFParseDictionary.PrettyPrint(' ')
    print
    if options.filter and not options.dump:
        filtered = pdf_object.Stream()
        if filtered == []:
            print ' %s' % FormatOutput(pdf_object.content, options.raw)
        else:
            print ' %s' % FormatOutput(filtered, options.raw)
    if options.dump:
        print 'Start dump:'
        print pdf_object.Stream(False)
        print 'End dump'
    print
    return

def Canonicalize(sIn):
    if sIn == "":
        return sIn
    elif sIn[0] != '/':
        return sIn
    elif sIn.find('#') == -1:
        return sIn
    else:
        i = 0
        iLen = len(sIn)
        sCanonical = ''
        while i < iLen:
            if sIn[i] == '#' and i < iLen - 2:
                try:
                    sCanonical += chr(int(sIn[i+1:i+3], 16))
                    i += 2
                except:
                    sCanonical += sIn[i]
            else:
                sCanonical += sIn[i]
            i += 1
        return sCanonical

def EqualCanonical(s1, s2):
    return Canonicalize(s1) == s2

def ConditionalCanonicalize(sIn, nocanonicalizedoutput):
    if nocanonicalizedoutput:
        return sIn
    else:
        return Canonicalize(sIn)

# http://code.google.com/p/pdfminerr/source/browse/trunk/pdfminer/pdfminer/ascii85.py
def ASCII85Decode(data):
    import struct
    n = b = 0
    out = ''
    for c in data:
        if '!' <= c and c <= 'u':
            n += 1
            b = b*85+(ord(c)-33)
            if n == 5:
                out += struct.pack('>L',b)
                n = b = 0
        elif c == 'z':
            assert n == 0
            out += '\0\0\0\0'
        elif c == '~':
            if n:
                for _ in range(5-n):
                    b = b*85+84
                out += struct.pack('>L',b)[:n-1]
            break
    return out

def ASCIIHexDecode(data):
    return binascii.unhexlify(''.join([c for c in data if c not in ' \t\n\r']).rstrip('>'))

def FlateDecode(data):
    return zlib.decompress(data)

def RunLengthDecode(data):
    f = cStringIO.StringIO(data)
    decompressed = ''
    runLength = ord(f.read(1))
    while runLength:
        if runLength < 128:
            decompressed += f.read(runLength + 1)
        if runLength > 128:
            decompressed += f.read(1) * (257 - runLength)
        if runLength == 128:
            break
        runLength = ord(f.read(1))
#    return sub(r'(\d+)(\D)', lambda m: m.group(2) * int(m.group(1)), data)
    return decompressed

#### LZW code sourced from pdfminer
# Copyright (c) 2004-2009 Yusuke Shinyama <yusuke at cs dot nyu dot edu>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the "Software"), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

class LZWDecoder(object):
    def __init__(self, fp):
        self.fp = fp
        self.buff = 0
        self.bpos = 8
        self.nbits = 9
        self.table = None
        self.prevbuf = None
        return

    def readbits(self, bits):
        v = 0
        while 1:
            # the number of remaining bits we can get from the current buffer.
            r = 8-self.bpos
            if bits <= r:
                # |-----8-bits-----|
                # |-bpos-|-bits-|  |
                # |      |----r----|
                v = (v<<bits) | ((self.buff>>(r-bits)) & ((1<<bits)-1))
                self.bpos += bits
                break
            else:
                # |-----8-bits-----|
                # |-bpos-|---bits----...
                # |      |----r----|
                v = (v<<r) | (self.buff & ((1<<r)-1))
                bits -= r
                x = self.fp.read(1)
                if not x: raise EOFError
                self.buff = ord(x)
                self.bpos = 0
        return v

    def feed(self, code):
        x = ''
        if code == 256:
            self.table = [ chr(c) for c in xrange(256) ] # 0-255
            self.table.append(None) # 256
            self.table.append(None) # 257
            self.prevbuf = ''
            self.nbits = 9
        elif code == 257:
            pass
        elif not self.prevbuf:
            x = self.prevbuf = self.table[code]
        else:
            if code < len(self.table):
                x = self.table[code]
                self.table.append(self.prevbuf+x[0])
            else:
                self.table.append(self.prevbuf+self.prevbuf[0])
                x = self.table[code]
            l = len(self.table)
            if l == 511:
                self.nbits = 10
            elif l == 1023:
                self.nbits = 11
            elif l == 2047:
                self.nbits = 12
            self.prevbuf = x
        return x

    def run(self):
        while 1:
            try:
                code = self.readbits(self.nbits)
            except EOFError:
                break
            x = self.feed(code)
            yield x
        return

####

def LZWDecode(data):
    return ''.join(LZWDecoder(cStringIO.StringIO(data)).run())


#########################################################
#                     Helper Classes (PDFID 0.0.11)     #
#########################################################
class cBinaryFile(object):
    def __init__(self, pdf_file):
        self.file = pdf_file
        self.infile = open(pdf_file, 'rb')
        self.ungetted = []

    def CloseOpenFiles(self):
        try:
            self.infile.close()
        except:
            pass

    def byte(self):
        if len(self.ungetted) != 0:
            return self.ungetted.pop()
        inbyte = self.infile.read(1)
        if None == inbyte or '' == inbyte:
            return None
        return ord(inbyte)

    def bytes(self, size):
        if size <= len(self.ungetted):
            result = self.ungetted[0:size]
            del self.ungetted[0:size]
            return result
        inbytes = self.infile.read(size - len(self.ungetted))
        result = self.ungetted + [ord(b) for b in inbytes]
        self.ungetted = []
        return result

    def unget(self, byte):
        self.ungetted.append(byte)

    def ungets(self, byte_array):
        byte_array.reverse()
        self.ungetted.extend(byte_array)

class cPDFDate(object):
    def __init__(self):
        self.state = 0

    def parse(self, char):
        if char == 'D':
            self.state = 1
            return None
        elif self.state == 1:
            if char == ':':
                self.state = 2
                self.digits1 = ''
            else:
                self.state = 0
            return None
        elif self.state == 2:
            if len(self.digits1) < 14:
                if char >= '0' and char <= '9':
                    self.digits1 += char
                    return None
                else:
                    self.state = 0
                    return None
            elif char == '+' or char == '-' or char == 'Z':
                self.state = 3
                self.digits2 = ''
                self.TZ = char
                return None
            elif char == '"':
                self.state = 0
                self.date = 'D:' + self.digits1
                return self.date
            elif char < '0' or char > '9':
                self.state = 0
                self.date = 'D:' + self.digits1
                return self.date
            else:
                self.state = 0
                return None
        elif self.state == 3:
            if len(self.digits2) < 2:
                if char >= '0' and char <= '9':
                    self.digits2 += char
                    return None
                else:
                    self.state = 0
                    return None
            elif len(self.digits2) == 2:
                if char == "'":
                    self.digits2 += char
                    return None
                else:
                    self.state = 0
                    return None
            elif len(self.digits2) < 5:
                if char >= '0' and char <= '9':
                    self.digits2 += char
                    if len(self.digits2) == 5:
                        self.state = 0
                        self.date = 'D:' + self.digits1 + self.TZ + self.digits2
                        return self.date
                    else:
                        return None
                else:
                    self.state = 0
                    return None

def fEntropy(countByte, countTotal):
    if(countTotal == 0):
        return 0.0
    else:
        x = float(countByte) / countTotal
        if x > 0:
            return - x * math.log(x, 2)
        else:
            return 0.0

class cEntropy(object):
    def __init__(self):
        self.allBucket = [0 for i in range(0, 256)] #@UnusedVariable
        self.streamBucket = [0 for i in range(0, 256)] #@UnusedVariable

    def add(self, byte, insideStream):
        self.allBucket[byte] += 1
        if insideStream:
            self.streamBucket[byte] += 1

    def removeInsideStream(self, byte):
        if self.streamBucket[byte] > 0:
            self.streamBucket[byte] -= 1

    def calc(self):
        self.nonStreamBucket = map(operator.sub, self.allBucket, self.streamBucket)
        allCount = sum(self.allBucket)
        streamCount = sum(self.streamBucket)
        nonStreamCount = sum(self.nonStreamBucket)
        return (allCount, sum(map(lambda x: fEntropy(x, allCount), self.allBucket)), streamCount, sum(map(lambda x: fEntropy(x, streamCount), self.streamBucket)), nonStreamCount, sum(map(lambda x: fEntropy(x, nonStreamCount), self.nonStreamBucket)))

class cPDFEOF(object):
    def __init__(self):
        self.token = ''
        self.cntEOFs = 0
        self.cntCharsAfterLastEOF = 0

    def parse(self, char):
        if self.cntEOFs > 0:
            self.cntCharsAfterLastEOF += 1
        if self.token == '' and char == '%':
            self.token += char
            return
        elif self.token == '%' and char == '%':
            self.token += char
            return
        elif self.token == '%%' and char == 'E':
            self.token += char
            return
        elif self.token == '%%E' and char == 'O':
            self.token += char
            return
        elif self.token == '%%EO' and char == 'F':
            self.token += char
            return
        elif self.token == '%%EOF' and (char == '\n' or char == '\r'):
            self.cntEOFs += 1
            self.cntCharsAfterLastEOF = 0
            if char == '\n':
                self.token = ''
            else:
                self.token += char
            return
        elif self.token == '%%EOF\r':
            if char == '\n':
                self.cntCharsAfterLastEOF = 0
            self.token = ''
        else:
            self.token = ''


def FindPDFHeaderRelaxed(oBinaryFile):
    byte_array = oBinaryFile.bytes(1024)
    index = ''.join([chr(byte) for byte in byte_array]).find('%PDF')
    if index == -1:
        oBinaryFile.ungets(byte_array)
        return ([], None)
    for endHeader in range(index + 4, index + 4 + 10):
        if byte_array[endHeader] == 10 or byte_array[endHeader] == 13:
            break
    oBinaryFile.ungets(byte_array[endHeader:])
    return (byte_array[0:endHeader], ''.join([chr(byte) for byte in byte_array[index:endHeader]]))

def Hexcode2String(char):
    if type(char) == int:
        return '#%02x' % char
    else:
        return char

def SwapCase(char):
    if type(char) == int:
        return ord(chr(char).swapcase())
    else:
        return char.swapcase()

def HexcodeName2String(hexcodeName):
    return ''.join(map(Hexcode2String, hexcodeName))

def SwapName(wordExact):
    return map(SwapCase, wordExact)

def UpdateWords(word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut):
    if word != '':
        if slash + word in words:
            words[slash + word][0] += 1
            if hexcode:
                words[slash + word][1] += 1
        elif slash == '/' and allNames:
            words[slash + word] = [1, 0]
            if hexcode:
                words[slash + word][1] += 1
        if slash == '/':
            lastName = slash + word
        if slash == '':
            if word == 'stream':
                insideStream = True
            if word == 'endstream':
                if insideStream == True and oEntropy != None:
                    for char in 'endstream':
                        oEntropy.removeInsideStream(ord(char))
                insideStream = False
        if fOut != None:
            if slash == '/' and '/' + word in ('/JS', '/JavaScript', '/AA', '/OpenAction', '/JBIG2Decode', '/RichMedia', '/Launch'):
                wordExactSwapped = HexcodeName2String(SwapName(wordExact))
                fOut.write(wordExactSwapped)
                print '/%s -> /%s' % (HexcodeName2String(wordExact), wordExactSwapped)
            else:
                fOut.write(HexcodeName2String(wordExact))
    return ('', [], False, lastName, insideStream)

class cCVE_2009_3459:
    def __init__(self):
        self.count = 0

    def Check(self, lastName, word):
        if (lastName == '/Colors' and word.isdigit() and int(word) > 2^24): # decided to alert when the number of colors is expressed with more than 3 bytes
            self.count += 1

def PDF_iD(pdf_file, allNames=False, extraData=False, disarm=False, force=False):
    """Example of XML output:
    <PDF_iD ErrorOccured="False" ErrorMessage="" Filename="test.pdf" Header="%PDF-1.1" IsPDF="True" Version="0.0.4" Entropy="4.28">
            <Keywords>
                    <Keyword Count="7" HexcodeCount="0" Name="obj"/>
                    <Keyword Count="7" HexcodeCount="0" Name="endobj"/>
                    <Keyword Count="1" HexcodeCount="0" Name="stream"/>
                    <Keyword Count="1" HexcodeCount="0" Name="endstream"/>
                    <Keyword Count="1" HexcodeCount="0" Name="xref"/>
                    <Keyword Count="1" HexcodeCount="0" Name="trailer"/>
                    <Keyword Count="1" HexcodeCount="0" Name="startxref"/>
                    <Keyword Count="1" HexcodeCount="0" Name="/Page"/>
                    <Keyword Count="0" HexcodeCount="0" Name="/Encrypt"/>
                    <Keyword Count="1" HexcodeCount="0" Name="/JS"/>
                    <Keyword Count="1" HexcodeCount="0" Name="/JavaScript"/>
                    <Keyword Count="0" HexcodeCount="0" Name="/AA"/>
                    <Keyword Count="1" HexcodeCount="0" Name="/OpenAction"/>
                    <Keyword Count="0" HexcodeCount="0" Name="/JBIG2Decode"/>
            </Keywords>
            <Dates>
                    <Date Value="D:20090128132916+01'00" Name="/ModDate"/>
            </Dates>
    </PDF_iD>
    """

    word = ''
    wordExact = []
    hexcode = False
    lastName = ''
    insideStream = False
    keywords = ('obj',
                'endobj',
                'stream',
                'endstream',
                'xref',
                'trailer',
                'startxref',
                '/Page',
                '/Encrypt',
                '/ObjStm',
                '/JS',
                '/JavaScript',
                '/AA',
                '/OpenAction',
                '/AcroForm',
                '/JBIG2Decode',
                '/RichMedia',
                '/Launch',
               )
    words = {}
    dates = []
    for keyword in keywords:
        words[keyword] = [0, 0]
    slash = ''
    xmlDoc = xml.dom.minidom.getDOMImplementation().createDocument(None, "PDF_iD", None)
    att = xmlDoc.createAttribute('Version')
    att.nodeValue = '0.0.11'
    xmlDoc.documentElement.setAttributeNode(att)
    att = xmlDoc.createAttribute('Filename')
    att.nodeValue = pdf_file
    xmlDoc.documentElement.setAttributeNode(att)
    attErrorOccured = xmlDoc.createAttribute('ErrorOccured')
    xmlDoc.documentElement.setAttributeNode(attErrorOccured)
    attErrorOccured.nodeValue = 'False'
    attErrorMessage = xmlDoc.createAttribute('ErrorMessage')
    xmlDoc.documentElement.setAttributeNode(attErrorMessage)
    attErrorMessage.nodeValue = ''

    oPDFDate = None
    oEntropy = None
    oPDFEOF = None
    oCVE_2009_3459 = cCVE_2009_3459()
    oBinaryFile = None
    try:
        attIsPDF = xmlDoc.createAttribute('IsPDF')
        xmlDoc.documentElement.setAttributeNode(attIsPDF)
        oBinaryFile = cBinaryFile(pdf_file)
        if extraData:
            oPDFDate = cPDFDate()
            oEntropy = cEntropy()
            oPDFEOF = cPDFEOF()
        (bytesHeader, pdfHeader) = FindPDFHeaderRelaxed(oBinaryFile)
        if disarm:
            (pathfile, extension) = os.path.splitext(pdf_file)
            fOut = open(pathfile + '.disarmed' + extension, 'wb')
            for byteHeader in bytesHeader:
                fOut.write(chr(byteHeader))
        else:
            fOut = None
        if oEntropy != None:
            for byteHeader in bytesHeader:
                oEntropy.add(byteHeader, insideStream)
        if pdfHeader == None and not force:
            attIsPDF.nodeValue = 'False'
            return xmlDoc
        else:
            if pdfHeader == None:
                attIsPDF.nodeValue = 'False'
                pdfHeader = ''
            else:
                attIsPDF.nodeValue = 'True'
            att = xmlDoc.createAttribute('Header')
            att.nodeValue = repr(pdfHeader[0:10]).strip("'")
            xmlDoc.documentElement.setAttributeNode(att)
        byte = oBinaryFile.byte()
        while byte != None:
            char = chr(byte)
            charUpper = char.upper()
            if charUpper >= 'A' and charUpper <= 'Z' or charUpper >= '0' and charUpper <= '9':
                word += char
                wordExact.append(char)
            elif slash == '/' and char == '#':
                d1 = oBinaryFile.byte()
                if d1 != None:
                    d2 = oBinaryFile.byte()
                    if d2 != None and (chr(d1) >= '0' and chr(d1) <= '9' or chr(d1).upper() >= 'A' and chr(d1).upper() <= 'F') and (chr(d2) >= '0' and chr(d2) <= '9' or chr(d2).upper() >= 'A' and chr(d2).upper() <= 'F'):
                        word += chr(int(chr(d1) + chr(d2), 16))
                        wordExact.append(int(chr(d1) + chr(d2), 16))
                        hexcode = True
                        if oEntropy != None:
                            oEntropy.add(d1, insideStream)
                            oEntropy.add(d2, insideStream)
                        if oPDFEOF != None:
                            oPDFEOF.parse(d1)
                            oPDFEOF.parse(d2)
                    else:
                        oBinaryFile.unget(d2)
                        oBinaryFile.unget(d1)
                        (word, wordExact, hexcode, lastName, insideStream) = UpdateWords(word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut)
                        if disarm:
                            fOut.write(char)
                else:
                    oBinaryFile.unget(d1)
                    (word, wordExact, hexcode, lastName, insideStream) = UpdateWords(word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut)
                    if disarm:
                        fOut.write(char)
            else:
                oCVE_2009_3459.Check(lastName, word)

                (word, wordExact, hexcode, lastName, insideStream) = UpdateWords(word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut)
                if char == '/':
                    slash = '/'
                else:
                    slash = ''
                if disarm:
                    fOut.write(char)

            if oPDFDate != None and oPDFDate.parse(char) != None:
                dates.append([oPDFDate.date, lastName])

            if oEntropy != None:
                oEntropy.add(byte, insideStream)

            if oPDFEOF != None:
                oPDFEOF.parse(char)

            byte = oBinaryFile.byte()
        (word, wordExact, hexcode, lastName, insideStream) = UpdateWords(word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut)
    except:
        attErrorOccured.nodeValue = 'True'
        attErrorMessage.nodeValue = traceback.format_exc()
    finally:
        if None != oBinaryFile:
            oBinaryFile.CloseOpenFiles()

    if disarm:
        fOut.close()

    attEntropyAll = xmlDoc.createAttribute('TotalEntropy')
    xmlDoc.documentElement.setAttributeNode(attEntropyAll)
    attCountAll = xmlDoc.createAttribute('TotalCount')
    xmlDoc.documentElement.setAttributeNode(attCountAll)
    attEntropyStream = xmlDoc.createAttribute('StreamEntropy')
    xmlDoc.documentElement.setAttributeNode(attEntropyStream)
    attCountStream = xmlDoc.createAttribute('StreamCount')
    xmlDoc.documentElement.setAttributeNode(attCountStream)
    attEntropyNonStream = xmlDoc.createAttribute('NonStreamEntropy')
    xmlDoc.documentElement.setAttributeNode(attEntropyNonStream)
    attCountNonStream = xmlDoc.createAttribute('NonStreamCount')
    xmlDoc.documentElement.setAttributeNode(attCountNonStream)
    if oEntropy != None:
        (countAll, entropyAll , countStream, entropyStream, countNonStream, entropyNonStream) = oEntropy.calc()
        attEntropyAll.nodeValue = '%f' % entropyAll
        attCountAll.nodeValue = '%d' % countAll
        attEntropyStream.nodeValue = '%f' % entropyStream
        attCountStream.nodeValue = '%d' % countStream
        attEntropyNonStream.nodeValue = '%f' % entropyNonStream
        attCountNonStream.nodeValue = '%d' % countNonStream
    else:
        attEntropyAll.nodeValue = ''
        attCountAll.nodeValue = ''
        attEntropyStream.nodeValue = ''
        attCountStream.nodeValue = ''
        attEntropyNonStream.nodeValue = ''
        attCountNonStream.nodeValue = ''
    attCountEOF = xmlDoc.createAttribute('CountEOF')
    xmlDoc.documentElement.setAttributeNode(attCountEOF)
    attCountCharsAfterLastEOF = xmlDoc.createAttribute('CountCharsAfterLastEOF')
    xmlDoc.documentElement.setAttributeNode(attCountCharsAfterLastEOF)
    if oPDFEOF != None:
        attCountEOF.nodeValue = '%d' % oPDFEOF.cntEOFs
        attCountCharsAfterLastEOF.nodeValue = '%d' % oPDFEOF.cntCharsAfterLastEOF
    else:
        attCountEOF.nodeValue = ''
        attCountCharsAfterLastEOF.nodeValue = ''

    eleKeywords = xmlDoc.createElement('Keywords')
    xmlDoc.documentElement.appendChild(eleKeywords)
    for keyword in keywords:
        eleKeyword = xmlDoc.createElement('Keyword')
        eleKeywords.appendChild(eleKeyword)
        att = xmlDoc.createAttribute('Name')
        att.nodeValue = keyword
        eleKeyword.setAttributeNode(att)
        att = xmlDoc.createAttribute('Count')
        att.nodeValue = str(words[keyword][0])
        eleKeyword.setAttributeNode(att)
        att = xmlDoc.createAttribute('HexcodeCount')
        att.nodeValue = str(words[keyword][1])
        eleKeyword.setAttributeNode(att)
    eleKeyword = xmlDoc.createElement('Keyword')
    eleKeywords.appendChild(eleKeyword)
    att = xmlDoc.createAttribute('Name')
    att.nodeValue = '/Colors > 2^24'
    eleKeyword.setAttributeNode(att)
    att = xmlDoc.createAttribute('Count')
    att.nodeValue = str(oCVE_2009_3459.count)
    eleKeyword.setAttributeNode(att)
    att = xmlDoc.createAttribute('HexcodeCount')
    att.nodeValue = str(0)
    eleKeyword.setAttributeNode(att)
    if allNames:
        keys = words.keys()
        keys.sort()
        for word in keys:
            if not word in keywords:
                eleKeyword = xmlDoc.createElement('Keyword')
                eleKeywords.appendChild(eleKeyword)
                att = xmlDoc.createAttribute('Name')
                att.nodeValue = word
                eleKeyword.setAttributeNode(att)
                att = xmlDoc.createAttribute('Count')
                att.nodeValue = str(words[word][0])
                eleKeyword.setAttributeNode(att)
                att = xmlDoc.createAttribute('HexcodeCount')
                att.nodeValue = str(words[word][1])
                eleKeyword.setAttributeNode(att)
    eleDates = xmlDoc.createElement('Dates')
    xmlDoc.documentElement.appendChild(eleDates)
    dates.sort(lambda x, y: cmp(x[0], y[0]))
    for date in dates:
        eleDate = xmlDoc.createElement('Date')
        eleDates.appendChild(eleDate)
        att = xmlDoc.createAttribute('Value')
        att.nodeValue = date[0]
        eleDate.setAttributeNode(att)
        att = xmlDoc.createAttribute('Name')
        att.nodeValue = date[1]
        eleDate.setAttributeNode(att)
    return xmlDoc

def PDFiD2String(xmlDoc, force):
    result = 'PDF_iD %s %s\n' % (xmlDoc.documentElement.getAttribute('Version'), xmlDoc.documentElement.getAttribute('Filename'))
    if xmlDoc.documentElement.getAttribute('ErrorOccured') == 'True':
        return result + '***Error occured***\n%s\n' % xmlDoc.documentElement.getAttribute('ErrorMessage')
    if not force and xmlDoc.documentElement.getAttribute('IsPDF') == 'False':
        return result + ' Not a PDF document\n'
    result += ' PDF Header: %s\n' % xmlDoc.documentElement.getAttribute('Header')
    for node in xmlDoc.documentElement.getElementsByTagName('Keywords')[0].childNodes:
        result += ' %-16s %7d' % (node.getAttribute('Name'), int(node.getAttribute('Count')))
        if int(node.getAttribute('HexcodeCount')) > 0:
            result += '(%d)' % int(node.getAttribute('HexcodeCount'))
        result += '\n'
    if xmlDoc.documentElement.getAttribute('CountEOF') != '':
        result += ' %-16s %7d\n' % ('%%EOF', int(xmlDoc.documentElement.getAttribute('CountEOF')))
    if xmlDoc.documentElement.getAttribute('CountCharsAfterLastEOF') != '':
        result += ' %-16s %7d\n' % ('After last %%EOF', int(xmlDoc.documentElement.getAttribute('CountCharsAfterLastEOF')))
    for node in xmlDoc.documentElement.getElementsByTagName('Dates')[0].childNodes:
        result += ' %-23s %s\n' % (node.getAttribute('Value'), node.getAttribute('Name'))
    if xmlDoc.documentElement.getAttribute('TotalEntropy') != '':
        result += ' Total entropy:           %s (%10s bytes)\n' % (xmlDoc.documentElement.getAttribute('TotalEntropy'), xmlDoc.documentElement.getAttribute('TotalCount'))
    if xmlDoc.documentElement.getAttribute('StreamEntropy') != '':
        result += ' Entropy inside streams:  %s (%10s bytes)\n' % (xmlDoc.documentElement.getAttribute('StreamEntropy'), xmlDoc.documentElement.getAttribute('StreamCount'))
    if xmlDoc.documentElement.getAttribute('NonStreamEntropy') != '':
        result += ' Entropy outside streams: %s (%10s bytes)\n' % (xmlDoc.documentElement.getAttribute('NonStreamEntropy'), xmlDoc.documentElement.getAttribute('NonStreamCount'))
    return result


