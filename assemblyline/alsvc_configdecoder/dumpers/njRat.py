import datetime
import os
import traceback
import re
import string
import sys
import json
from binascii import *


def hexdump(src, length=16, indent=0):
    """
    source : http://pastebin.com/C3XszsCv
    """
    trans_table = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c + length]
        hexed = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and trans_table[ord(x)]) or '.') for x in chars])
        lines.append("%s%04x  %-*s  %s\n" % (indent * " ", c, length * 3, hexed, printable))
    return ''.join(lines)
    
    

def read_unicode(buf):
    result = ""
    index = 0
    while index < len(buf):
        if buf[index] != "\x00":
            result += buf[index]
            index += 2
        else:
            break
    return result


def read_ascii(buf):
    result = ""
    index = 0
    while index < len(buf):
        if buf[index] != "\x00":
            result += buf[index]
            index += 1
        else:
            break
    return result


def parseToBool(value):
    return "1" == value


def parseToInt(value):
    try:
        return int(value)
    except:
        return value


def extractConfig(memory, config_fields):
    parsed_config = {}
    num_bytes_parsed = 0
    
    for config_field in config_fields:
        field_len = ord(memory[num_bytes_parsed])
        start = num_bytes_parsed + 1
        end = num_bytes_parsed + 1 + field_len
        parsed_config[config_field] = read_unicode(memory[start:end-1])
        
        if config_field == "campaign":
            parsed_config[config_field] = parsed_config[config_field].decode("base64")
        num_bytes_parsed += field_len + 1
    return parsed_config


def getConfig(memory):
    config_fields = {"0.7d":  {"regex": r"WRK.*main.*\x00\x00\x00",
                               "fields": ["campaign", "version", "file", "folder", "mutex", "cnc", "port", "delim", "install"]
                              }, 
                     "0.6.4": {"regex": r"WRK.*Lambda\$__4\x00\x00",
                               "fields": ["campaign", "version", "file", "folder", "mutex", "cnc", "port", "delim", "install"]
                              },
                     "0.3.6": {"regex": r"\x00\x00\x00\x0F\[\x00e\x00n\x00d\x00o\x00f\x00\]\x00\x00",
                               "fields": ["file", "folder", "mutex", "campaign", "version", "cnc", "port", "delim", "install"]
                              },
                     "RedDevil": {"regex": r"WRK.*stub.*\x00\x00\x00\x00",
                               "fields": ["unknown", "folder", "file", "cnc", "unknown2", "unknown3", "unknown4", "unknown5", "unknown6", "port", "mutex"]
                              }
                    }
    for version in config_fields:
        match = re.search(config_fields[version]["regex"], memory)
        if match:
            return extractConfig(memory[match.end():], config_fields[version]["fields"])
    return {}


def count_files(path):
    num_files = 0
    for dirpath, dnames, fnames in os.walk(in_abs):
        for f in fnames:
            num_files += 1
    return num_files

