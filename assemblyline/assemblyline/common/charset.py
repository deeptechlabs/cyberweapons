import chardet
import re
from copy import copy


def remove_bidir_unicode_controls(in_str):
    # noinspection PyBroadException
    try:
        no_controls_str = ''.join(
            c for c in in_str if c not in [
                u'\u202E', u'\u202B', u'\u202D',
                u'\u202A', u'\u200E', u'\u200F',
            ]
        )
    except:  # pylint:disable=W0702
        no_controls_str = in_str
    
    return no_controls_str


def wrap_bidir_unicode_string(uni_str):
    """
    Wraps str in a LRE (Left-to-Right Embed) unicode control
    Guarantees that str can be concatenated to other strings without 
        affecting their left-to-right direction
    """
    
    if len(uni_str) == 0 or isinstance(uni_str, unicode):  # Not unicode, return it unchanged
        return uni_str
    
    re_obj = re.search(ur'[\u202E\u202B\u202D\u202A\u200E\u200F]', uni_str)
    if re_obj is None or len(re_obj.group()) == 0:  # No unicode bidir controls found, return string unchanged
        return uni_str
    
    # Parse str for unclosed bidir blocks
    count = 0
    for letter in uni_str:
        if letter in [u'\u202A', u'\u202B', u'\u202D', u'\u202E']:  # bidir block open?
            count += 1
        elif letter == u'\u202c':
            if count > 0:
                count -= 1
    
    # close all bidir blocks
    if count > 0:
        uni_str += (u'\u202c' * count)                
    
    # Final wrapper (LTR block) to neutralize any Marks (u+200E and u+200F)
    uni_str = u'\u202A' + uni_str + u'\u202C'
    
    return uni_str

# According to wikipedia, RFC 3629 restricted UTF-8 to end at U+10FFFF.
# This removed the 6, 5 and (irritatingly) half of the 4 byte sequences.
#
# The start byte for 2-byte sequences should be a value between 0xc0 and
# 0xdf but the values 0xc0 and 0xc1 are invalid as they could only be
# the result of an overlong encoding of basic ASCII characters. There
# are similar restrictions on the valid values for 3 and 4-byte sequences.
_valid_utf8 = re.compile(r"""((?:
    [\x09\x0a\x20-\x7e]|             # 1-byte (ASCII excluding control chars).
    [\xc2-\xdf][\x80-\xbf]|          # 2-bytes (excluding overlong sequences).
    [\xe0][\xa0-\xbf][\x80-\xbf]|    # 3-bytes (excluding overlong sequences).

    [\xe1-\xec][\x80-\xbf]{2}|       # 3-bytes.
    [\xed][\x80-\x9f][\x80-\xbf]|    # 3-bytes (up to invalid code points).
    [\xee-\xef][\x80-\xbf]{2}|       # 3-bytes (after invalid code points).

    [\xf0][\x90-\xbf][\x80-\xbf]{2}| # 4-bytes (excluding overlong sequences).
    [\xf1-\xf3][\x80-\xbf]{3}|       # 4-bytes.
    [\xf4][\x80-\x8f][\x80-\xbf]{2}  # 4-bytes (up to U+10FFFF).
    )+)""", re.VERBOSE)


def _escape(t, reversible=True):
    if t[0] % 2:
        return t[1].replace('\\', '\\\\') if reversible else t[1]
    else:
        return ''.join(('\\x%02x' % ord(x)) for x in t[1])


def dotdump(s):
    return ''.join('.' if ord(x) < 32 or ord(x) > 126 else x for x in s)


def escape_str(s, reversible=True):
    t = type(s)
    if t == unicode:
        return escape_str_strict(s.encode('utf8'), reversible)
    elif t != str:
        return s

    return escape_str_strict(s, reversible)


# Returns a string (str) with only valid UTF-8 byte sequences.
def escape_str_strict(s, reversible=True):
    return ''.join([_escape(t, reversible)
                    for t in enumerate(_valid_utf8.split(s))])


def safe_str(s):
    return escape_str(s, reversible=False)


def is_safe_str(s):
    return escape_str(copy(s), reversible=False) == s


# noinspection PyBroadException
def translate_str(s, min_confidence=0.7):
    t = type(s)
    if t == unicode:
        temp = s.encode("raw_unicode_escape")
        if "\\u" in temp:
            return {
                'confidence': 1,
                'encoding': 'unicode',
                'converted': safe_str(s)
            }
        s = temp
    elif t != str:
        raise TypeError('Expected %s or %s got %s' % (str, unicode, t))

    try:
        r = chardet.detect(s)
    except:  # pylint:disable=W0702
        r = {'confidence': 0, 'encoding': 'unknown'}

    if r['confidence'] > 0 and r['confidence'] >= min_confidence:
        try:
            t = s.decode(r['encoding'])
        except:  # pylint:disable=W0702
            t = s
    else:
        t = s

    r['converted'] = safe_str(t)

    return r


# This method not really necessary. More to stop people from rolling their own.
def unescape_str(s):
    return s.decode('string_escape')
