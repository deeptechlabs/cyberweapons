#! /usr/bin/env python2
"""
2016-10-21:
Modified version of bbcrack application for AL, original code found here:
https://github.com/decalage2/balbuzard
"""
"""
bbcrack - v0.14 2014-05-22 Philippe Lagadec

bbcrack is a tool to crack malware obfuscation such as XOR, ROL, ADD (and
many combinations), by bruteforcing all possible keys and and checking for
specific patterns (IP addresses, domain names, URLs, known file headers and
strings, etc) using the balbuzard engine.
It is part of the Balbuzard package.

For more info and updates: http://www.decalage.info/balbuzard
"""

# LICENSE:
#
# bbcrack is copyright (c) 2013-2014, Philippe Lagadec (http://www.decalage.info)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


__version__ = '0.13'

# --- IMPORTS ------------------------------------------------------------------

from al_services.alsvc_frankenstrings.balbuzard.balbuzard import Balbuzard
from al_services.alsvc_frankenstrings.balbuzard.patterns import PatternMatch

#--- CLASSES ------------------------------------------------------------------

class Transform_string (object):
    """
    Generic class to define a transform that acts on a string globally.
    """
    # generic name and id for the class:
    gen_name = 'Generic String Transform'
    gen_id   = 'string'

    def __init__(self, params=None):
        """
        constructor for the Transform object.
        This method needs to be overloaded for every specific Transform.
        It should set name and shortname according to the provided parameters.
        (for example shortname="xor_17" for a XOR transform with params=17)
        params: single value or tuple of values, parameters for the transformation
        """
        self.name = 'Undefined String Transform'
        self.shortname = 'undefined_string'
        self.params = params


    def transform_string (self, data):
        """
        Method to be overloaded, only for a transform that acts on a string
        globally.
        This method should apply the transform to the data string, using params
        as parameters, and return the transformed data as a string.
        (the resulting string does not need to have the same length as data)
        """
        raise NotImplementedError

    @staticmethod
    def iter_params ():
        """
        Method to be overloaded.
        This static method should iterate over all possible parameters for the
        transform function, yielding each set of parameters as a single value
        or a tuple of values.
        (for example for a XOR transform, it should yield 1 to 255)
        This method should be used on the Transform class in order to
        instantiate a Transform object with each set of parameters.
        """
        raise NotImplementedError

##    def iter_transform (self, data):
##        """
##        Runs the transform on data for all possible values of the parameters,
##        and yields the transformed data for each possibility.
##        """
##        for params in self.iter_params():
##            #print self.name
##            yield self.transform_string(data, params)


class Transform_char (Transform_string):
    """
    Generic class to define a transform that acts on each character of a string
    separately.
    """
    # generic name for the class:
    gen_name = 'Generic Character Transform'
    gen_id   = 'char'

    def __init__(self, params=None):
        """
        constructor for the Transform object.
        This method needs to be overloaded for every specific Transform.
        It should set name and shortname according to the provided parameters.
        (for example shortname="xor_17" for a XOR transform with params=17)
        params: single value or tuple of values, parameters for the transformation
        """
        self.name = 'Undefined Character Transform'
        self.shortname = 'undefined_char'
        self.params = params


    def transform_string (self, data):
        """
        This method applies the transform to the data string, using params
        as parameters, and return the transformed data as a string.
        Here, each character is transformed separately by calling transform_char.
        A translation table is used to speed up the processing.
        (the resulting string should have the same length as data)
        """
        # for optimal speed, we build a translation table:
        self.trans_table = ''
        for i in xrange(256):
            self.trans_table += self.transform_char(chr(i))
        return data.translate(self.trans_table)

    def transform_char (self, char):
        """
        Method that can be overloaded, only for a transform that acts on a character.
        This method should apply the transform to the provided char, using params
        as parameters, and return the transformed data as a character.
        NOTE: it is usually simpler to overload transform_int and leave this one
        untouched.
        (here character = string of length 1)
        """
        # by default, call transform_int using ord(char), and convert it back
        # to a single character:
        return chr(self.transform_int(ord(char)))


    def transform_int (self, i):
        """
        Method to be overloaded, only for a transform that acts on a character.
        This method should apply the transform to the provided integer which is
        the ASCII code of a character (i.e. ord(c)), using params
        as parameters, and return the transformed data as an integer.
        (here character = string of length 1)
        """
        raise NotImplementedError


#--- TRANSFORMS ---------------------------------------------------------------

class Transform_identity (Transform_string):
    """
    Transform that does not change data.
    """
    # generic name for the class:
    gen_name = 'Identity Transformation, no change to data. Parameters: none.'
    gen_id   = 'identity'

    def __init__(self, params=None):
        self.name = self.gen_name
        self.shortname = self.gen_id
        self.params = None

    def transform_string (self, data):
        return data

    @staticmethod
    def iter_params ():
        yield None


#------------------------------------------------------------------------------
class Transform_XOR (Transform_char):
    """
    XOR Transform
    """
    # generic name for the class:
    gen_name = 'XOR with 8 bits static key A. Parameters: A (1-FF).'
    gen_id   = 'xor'

    def __init__(self, params):
        assert isinstance(params, int)
        assert params>0 and params<256
        self.params = params
        self.name = "XOR %02X" % params
        self.shortname = "xor%02X" % params

    def transform_int (self, i):
        # here params is an integer
        return i ^ self.params

    @staticmethod
    def iter_params ():
        # the XOR key can be 1 to 255 (0 would be identity)
        for key in xrange(1,256):
            yield key


#------------------------------------------------------------------------------
class Transform_XOR_INC (Transform_string):
    """
    XOR Transform, with incrementing key
    """
    # generic name for the class:
    gen_name = 'XOR with 8 bits key A incrementing after each character. Parameters: A (0-FF).'
    gen_id   = 'xor_inc'

    def __init__(self, params):
        assert isinstance(params, int)
        assert params>=0 and params<256
        self.params = params
        self.name = "XOR %02X INC" % params
        self.shortname = "xor%02X_inc" % params

    def transform_string (self, data):
        # here params is an integer
        #TODO: use a list comprehension + join to get better performance
        # this loop is more readable, but likely to  be much slower
        out = ''
        for i in xrange(len(data)):
            xor_key = (self.params + i) & 0xFF
            out += chr(ord(data[i]) ^ xor_key)
        return out

    @staticmethod
    def iter_params ():
        # the XOR key can be 0 to 255 (0 is not identity here)
        for xor_key in xrange(0,256):
            yield xor_key


#------------------------------------------------------------------------------
class Transform_XOR_DEC (Transform_string):
    """
    XOR Transform, with decrementing key
    """
    # generic name for the class:
    gen_name = 'XOR with 8 bits key A decrementing after each character. Parameters: A (0-FF).'
    gen_id   = 'xor_dec'

    def __init__(self, params):
        assert isinstance(params, int)
        assert params>=0 and params<256
        self.params = params
        self.name = "XOR %02X DEC" % params
        self.shortname = "xor%02X_dec" % params

    def transform_string (self, data):
        # here params is an integer
        #TODO: use a list comprehension + join to get better performance
        # this loop is more readable, but likely to  be much slower
        out = ''
        for i in xrange(len(data)):
            xor_key = (self.params + 0xFF - i) & 0xFF
            out += chr(ord(data[i]) ^ xor_key)
        return out

    @staticmethod
    def iter_params ():
        # the XOR key can be 0 to 255 (0 is not identity here)
        for xor_key in xrange(0,256):
            yield xor_key


#------------------------------------------------------------------------------
class Transform_XOR_INC_ROL (Transform_string):
    """
    XOR Transform, with incrementing key, then ROL N bits
    """
    # generic name for the class:
    gen_name = 'XOR with 8 bits key A incrementing after each character, then rotate B bits left. Parameters: A (0-FF), B (1-7).'
    gen_id   = 'xor_inc_rol'

    def __init__(self, params):
        self.params = params
        self.name = "XOR %02X INC then ROL %d" % params
        self.shortname = "xor%02X_inc_rol%d" % params

    def transform_char (self, char):
        # here params is a tuple
        xor_key, rol_bits = self.params
        return chr(rol(ord(char) ^ xor_key, rol_bits))

    def transform_string (self, data):
        # here params is a tuple
        #TODO: use a list comprehension + join to get better performance
        # this loop is more readable, but likely to  be much slower
        xor_key_init, rol_bits = self.params
        out = ''
        for i in xrange(len(data)):
            xor_key = (xor_key_init + i) & 0xFF
            out += chr(rol(ord(data[i]) ^ xor_key, rol_bits))
        return out

    @staticmethod
    def iter_params ():
        "return (XOR key, ROL bits)"
        # the XOR key can be 0 to 255 (0 is not identity here)
        for xor_key in xrange(0,256):
            # the ROL bits can be 1 to 7:
            for rol_bits in xrange(1,8):
                yield (xor_key, rol_bits)


#------------------------------------------------------------------------------
class Transform_SUB_INC (Transform_string):
    """
    SUB Transform, with incrementing key
    """
    # generic name for the class:
    gen_name = 'SUB with 8 bits key A incrementing after each character. Parameters: A (0-FF).'
    gen_id   = 'sub_inc'

    def __init__(self, params):
        assert isinstance(params, int)
        assert params>=0 and params<256
        self.params = params
        self.name = "SUB %02X INC" % params
        self.shortname = "sub%02X_inc" % params

    def transform_string (self, data):
        # here params is an integer
        #TODO: use a list comprehension + join to get better performance
        # this loop is more readable, but likely to  be much slower
        out = ''
        for i in xrange(len(data)):
            key = (self.params + i) & 0xFF
            out += chr((ord(data[i]) - key) & 0xFF)
        return out

    @staticmethod
    def iter_params ():
        # the SUB key can be 0 to 255 (0 is not identity here)
        for key in xrange(0,256):
            yield key


def rol(byte, count):
    byte = (byte << count | byte >> (8-count)) & 0xFF
    return byte

###safety checks
##assert rol(1, 1) == 2
##assert rol(128, 1) == 1
##assert rol(1, 7) == 128
##assert rol(1, 8) == 1

#------------------------------------------------------------------------------
class Transform_XOR_Chained (Transform_string):
    """
    XOR Transform, chained with previous character.
    xor_chained(c[i], key) = c[i] xor c[i-1] xor key
    """
    # generic name for the class:
    gen_name = 'XOR with 8 bits key A chained with previous character. Parameters: A (1-FF).'
    gen_id   = 'xor_chained'

    def __init__(self, params):
        assert isinstance(params, int)
        assert params>=0 and params<256
        self.params = params
        self.name = "XOR %02X Chained" % params
        self.shortname = "xor%02X_chained" % params

    def transform_string (self, data):
        # here params is an integer
        #TODO: it would be much faster to do the xor_chained once, then all
        #      xor transforms using translate() only
        #TODO: use a list comprehension + join to get better performance
        # this loop is more readable, but likely to  be much slower
        if len(data) == 0: return ''
        xor_key = self.params
        # 1st char is just xored with key:
        out = chr(ord(data[0]) ^ xor_key)
        for i in xrange(1, len(data)):
            out += chr(ord(data[i]) ^ xor_key ^ ord(data[i-1]))
        return out

    @staticmethod
    def iter_params ():
        # the XOR key can be 0 to 255 (0 is not identity here)
        for xor_key in xrange(0,256):
            yield xor_key


#------------------------------------------------------------------------------
class Transform_XOR_RChained (Transform_string):
    """
    XOR Transform, chained with next character. (chained on the right)
    xor_rchained(c[i], key) = c[i] xor c[i+1] xor key
    """
    # generic name for the class:
    gen_name = 'XOR with 8 bits key A chained with next character (Reverse order from end to start). Parameters: A (1-FF).'
    gen_id   = 'xor_rchained'

    def __init__(self, params):
        assert isinstance(params, int)
        assert params>=0 and params<256
        self.params = params
        self.name = "XOR %02X RChained" % params
        self.shortname = "xor%02X_rchained" % params

    def transform_string (self, data):
        # here params is an integer
        #TODO: it would be much faster to do the xor_rchained once, then all
        #      xor transforms using translate() only
        #TODO: use a list comprehension + join to get better performance
        # this loop is more readable, but likely to  be much slower
        if len(data) == 0: return ''
        out = ''
        xor_key = self.params
        # all chars except last one are xored with key and next char:
        for i in xrange(len(data)-1):
            out += chr(ord(data[i]) ^ xor_key ^ ord(data[i+1]))
        # last char is just xored with key:
        out += chr(ord(data[len(data)-1]) ^ xor_key)
        return out

    @staticmethod
    def iter_params ():
        # the XOR key can be 0 to 255 (0 is not identity here)
        for xor_key in xrange(0,256):
            yield xor_key


#------------------------------------------------------------------------------
class Transform_XOR_RChainedAll (Transform_string):
    """
    XOR Transform, chained from the right with all following characters.
    (as found in Taidoor malware)
    NOTE: this only works well in harvest mode, when testing all 256
          possibilities, because the key is position-dependent.
    xor_rchained_all(c[i], key) = c[i] xor key xor c[i+1] xor c[i+2]... xor c[N]
    """
    # generic name for the class:
    gen_name = 'XOR Transform, chained from the right with all following characters. Only works well with bbharvest.'
    gen_id   = 'xor_rchained_all'

    def __init__(self, params):
        assert isinstance(params, int)
        assert params>=0 and params<256
        self.params = params
        self.name = "XOR %02X RChained All" % params
        self.shortname = "xor%02X_rchained_all" % params

    def transform_string (self, data):
        # here params is an integer
        #TODO: it would be much faster to do the xor_rchained once, then all
        #      xor transforms using translate() only
        #TODO: use a list comprehension + join to get better performance
        # this loop is more readable, but likely to  be much slower
        if len(data) == 0: return ''
        xor_key = self.params
        # transform data string to list of integers:
        l = map(ord, data)
        # loop from last char to 2nd one:
        for i in xrange(len(data)-1, 1, -1):
            l[i-1] = l[i-1] ^ xor_key ^ l[i]
        # last char is only xored with key:
        l[len(data)-1] = l[len(data)-1] ^ xor_key
        # convert back to list of chars:
        l = map(chr, l)
        out = ''.join(l)
        return out

    @staticmethod
    def iter_params ():
        # the XOR key can be 0 to 255 (0 is not identity here)
        for xor_key in xrange(0,256):
            yield xor_key


#------------------------------------------------------------------------------
class Transform_ROL (Transform_char):
    """
    ROL Transform
    """
    # generic name for the class:
    gen_name = 'ROL - rotate A bits left. Parameters: A (1-7).'
    gen_id   = 'rol'

    def __init__(self, params):
        self.params = params
        self.name = "ROL %d" % params
        self.shortname = "rol%d" % params

    def transform_int (self, i):
        # here params is an int
        rol_bits = self.params
        return rol(i, rol_bits)

    @staticmethod
    def iter_params ():
        "return (ROL bits)"
        # the ROL bits can be 1 to 7:
        for rol_bits in xrange(1,8):
            yield rol_bits


#------------------------------------------------------------------------------
class Transform_XOR_ROL (Transform_char):
    """
    XOR+ROL Transform - first XOR, then ROL
    """
    # generic name for the class:
    gen_name = 'XOR with static 8 bits key A, then rotate B bits left. Parameters: A (1-FF), B (1-7).'
    gen_id   = 'xor_rol'

    def __init__(self, params):
        self.params = params
        self.name = "XOR %02X then ROL %d" % params
        self.shortname = "xor%02X_rol%d" % params

    def transform_int (self, i):
        # here params is a tuple
        xor_key, rol_bits = self.params
        return rol(i ^ xor_key, rol_bits)

    @staticmethod
    def iter_params ():
        "return (XOR key, ROL bits)"
        # the XOR key can be 1 to 255 (0 would be like ROL)
        for xor_key in xrange(1,256):
            # the ROL bits can be 1 to 7:
            for rol_bits in xrange(1,8):
                yield (xor_key, rol_bits)


#------------------------------------------------------------------------------
class Transform_ADD (Transform_char):
    """
    ADD Transform
    """
    # generic name for the class:
    gen_name = 'ADD with 8 bits static key A. Parameters: A (1-FF).'
    gen_id   = 'add'

    def __init__(self, params):
        self.params = params
        self.name = "ADD %02X" % params
        self.shortname = "add%02X" % params

    def transform_int (self, i):
        # here params is an integer
        add_key = self.params
        return (i + add_key) & 0xFF

    @staticmethod
    def iter_params ():
        "return ADD key"
        # the ADD key can be 1 to 255 (0 would be identity):
        for add_key in xrange(1,256):
            yield add_key


#------------------------------------------------------------------------------
class Transform_ADD_ROL (Transform_char):
    """
    ADD+ROL Transform - first ADD, then ROL
    """
    # generic name for the class:
    gen_name = 'ADD with static 8 bits key A, then rotate B bits left. Parameters: A (1-FF), B (1-7).'
    gen_id   = 'add_rol'

    def __init__(self, params):
        self.params = params
        self.name = "ADD %02X then ROL %d" % params
        self.shortname = "add%02X_rol%d" % params

    def transform_int (self, i):
        # here params is a tuple
        add_key, rol_bits = self.params
        return rol((i + add_key) & 0xFF, rol_bits)

    @staticmethod
    def iter_params ():
        "return (ADD key, ROL bits)"
        # the ADD key can be 1 to 255 (0 would be like ROL)
        for add_key in xrange(1,256):
            # the ROL bits can be 1 to 7:
            for rol_bits in xrange(1,8):
                yield (add_key, rol_bits)


#------------------------------------------------------------------------------
class Transform_ROL_ADD (Transform_char):
    """
    ROL+ADD Transform - first ROL, then ADD
    """
    # generic name for the class:
    gen_name = 'rotate A bits left, then ADD with static 8 bits key B. Parameters: A (1-7), B (1-FF).'
    gen_id   = 'rol_add'

    def __init__(self, params):
        self.params = params
        self.name = "ROL %d then ADD %02X" % params
        self.shortname = "rol%d_add%02X" % params

    def transform_int (self, i):
        # here params is a tuple
        rol_bits, add_key = self.params
        return (rol(i, rol_bits) + add_key) & 0xFF

    @staticmethod
    def iter_params ():
        "return (ROL bits, ADD key)"
        # the ROL bits can be 1 to 7:
        for rol_bits in xrange(1,8):
            # the ADD key can be 1 to 255 (0 would be identity)
            for add_key in xrange(1,256):
                yield (rol_bits, add_key)


#------------------------------------------------------------------------------
class Transform_XOR_ADD (Transform_char):
    """
    XOR+ADD Transform - first XOR, then ADD
    """
    # generic name for the class:
    gen_name = 'XOR with 8 bits static key A, then ADD with 8 bits static key B. Parameters: A (1-FF), B (1-FF).'
    gen_id   = 'xor_add'

    def __init__(self, params):
        self.params = params
        self.name = "XOR %02X then ADD %02X" % params
        self.shortname = "xor%02X_add%02X" % params

    def transform_int (self, i):
        # here params is a tuple
        xor_key, add_key = self.params
        return ((i ^ xor_key) + add_key) & 0xFF

    @staticmethod
    def iter_params ():
        "return (XOR key1, ADD key2)"
        # the XOR key can be 1 to 255 (0 would be identity)
        for xor_key in xrange(1,256):
            # the ADD key can be 1 to 255 (0 would be identity):
            for add_key in xrange(1,256):
                yield (xor_key, add_key)


#------------------------------------------------------------------------------
class Transform_ADD_XOR (Transform_char):
    """
    ADD+XOR Transform - first ADD, then XOR
    """
    # generic name for the class:
    gen_name = 'ADD with 8 bits static key A, then XOR with 8 bits static key B. Parameters: A (1-FF), B (1-FF).'
    gen_id   = 'add_xor'

    def __init__(self, params):
        self.params = params
        self.name = "ADD %02X then XOR %02X" % params
        self.shortname = "add%02X_xor%02X" % params

    def transform_int (self, i):
        # here params is a tuple
        add_key, xor_key = self.params
        return ((i + add_key) & 0xFF) ^ xor_key

    @staticmethod
    def iter_params ():
        "return (ADD key1, XOR key2)"
        # the ADD key can be 1 to 255 (0 would be identity):
        for add_key in xrange(1,256):
            # the XOR key can be 1 to 255 (0 would be identity)
            for xor_key in xrange(1,256):
                yield (add_key, xor_key)

#--- CUSTOM XOR BRUTE FORCE ---------------------------------------------------

def xor_simple(a, b):
    out = ""
    for i, c in enumerate(a):
        out += chr(ord(c) ^ ord(b[i % len(b)]))
    return out

def deobfuscate_simple(d, r, m):
    "Take mask and will create a key to unmask suspected data, then check if the xor'd data matches a regex pattern"
    import re
    max_mask = m.lower()
    for i in xrange(1, len(max_mask)+1):
        t_mask = max_mask[:i]
        r_mask = xor_simple(d[:i], t_mask)
        de_enc = xor_simple(d, r_mask)
        if re.match(r, de_enc):
            return de_enc.strip(), r_mask
    return None, None

#--- TRANSFORM GROUPS ---------------------------------------------------------

# Transforms level 1
transform_classes1 = [
    #Transform_identity,
    Transform_XOR,
    Transform_ADD,
    Transform_ROL,
    ]

# Transforms level 2
transform_classes2 = [
    Transform_XOR_ROL,
    Transform_ADD_ROL,
    Transform_ROL_ADD,
    ]

# Transforms level 3
transform_classes3 = [
    Transform_XOR_ADD,
    Transform_ADD_XOR,
    Transform_XOR_INC,
    Transform_XOR_DEC,
    Transform_SUB_INC,
    Transform_XOR_Chained,
    Transform_XOR_RChained,
    Transform_XOR_INC_ROL,
    Transform_XOR_RChainedAll,
    ]

# all transforms
transform_classes_all = transform_classes1 + transform_classes2 + transform_classes3


#--- PATTERNS -----------------------------------------------------------------

#see balbuzard.patterns.py

# === MAIN =====================================================================
"""
2016-10-20: Main Module modified for FrankenStrings AL service
"""

def read_file(filename):
    """
    Open a file, read and return its data as a string.
    """
    f = file(filename, 'rb')
    raw_data = f.read()
    f.close()
    return raw_data


def bbcrack(file_data, level=1):

    raw_data = file_data
    if level == 1 or level == 'small_string':
        transform_classes = transform_classes1
    elif level == 2:
        transform_classes = transform_classes1 + transform_classes2
    else:
        transform_classes = transform_classes_all

    results = []
    bbc = PatternMatch()
    bbcrack_patterns = bbc.bbcr(level=level)

    if level == 'small_string':

        bbz = Balbuzard(bbcrack_patterns)

        # Round 1
        for Transform_class in transform_classes:
            for params in Transform_class.iter_params():
                transform = Transform_class(params)
                data = transform.transform_string(raw_data)
                for pattern, matches in bbz.scan(data):
                    for index, match in matches:
                        regex = pattern.name.split("_", 1)[1]
                        smatch = match
                        if transform.shortname == "xor20":
                            # for basic alpha characters, will essentially convert lower and uppercase.
                            continue
                        results.append((transform.shortname, regex, smatch))
                        return results

        for pattern in bbz.list_patterns():
            pmask = pattern.name.split("_", 1)[0]
            sxor, smask = deobfuscate_simple(raw_data, pattern.pat, pmask)
            if sxor:
                results.append((smask, pattern.name.split("_", 1)[1], sxor))

    # Run bbcrack patterns against transforms

    bbz = Balbuzard(bbcrack_patterns)

    for Transform_class in transform_classes:
        for params in Transform_class.iter_params():
            transform = Transform_class(params)
            data = transform.transform_string(raw_data)
            score = 0
            for pattern, matches in bbz.scan(data):
                for index, match in matches:
                    regex = pattern.name
                    smatch = match
                    if regex == 'EXE_HEAD':
                        score = 100000
                        results.append((transform.shortname, regex, index, score, data))
                        continue
                    if transform.shortname == "xor20":
                        #for basic alpha characters, will essentially convert lower and uppercase.
                        continue
                    score += len(match) * pattern.weight
                    results.append((transform.shortname, regex, index, score, smatch[0:50]))

    return results
# This was coded while listening to The Walkmen "Heaven". --Philippe Lagadec
