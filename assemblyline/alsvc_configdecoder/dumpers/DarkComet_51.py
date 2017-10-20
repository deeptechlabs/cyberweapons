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


def rc4crypt(data, key):
    x = 0
    box = range(256)
    for i in range(256):
        x = (x + box[i] + ord(key[i % len(key)])) % 256
        box[i], box[x] = box[x], box[i]
    x = 0
    y = 0
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))

    return ''.join(out)


def getConfig(rc4key, config_str):
    config = {"FWB": "",
              "GENCODE": "",
              "MUTEX": "",
              "NETDATA": "",
              "OFFLINEK": "",
              "SID": "",
              "FTPUPLOADK": "",
              "FTPHOST": "",
              "FTPUSER": "",
              "FTPPASS": "",
              "FTPPORT": "",
              "FTPSIZE": "",
              "FTPROOT": "",
              "PWD": "",
              "KEYNAME": "",
              "MSGTITLE": "",
              "MSGCORE": "",
              "MSGICON": "",
              "EDTPATH": "",
              "EDTDATE": "",
              "COMBOPATH": "",
              "DIRATTRIB": "",
              "FILEATTRIB": "",
              "FWB": ""}
    dec = rc4crypt(unhexlify(config_str), rc4key)
    # print "#" * 20
    # print dec
    # print "#" * 20
    dec_list = dec.split('\n')
    for entries in dec_list[1:-1]:
        if "#EOF DARKCOMET DATA" in entries:
            break
        key, value = entries.split('=')
        key = key.strip()
        value = value.rstrip()[1:-1]
        clean_value = filter(lambda x: x in string.printable, value)
        print key, clean_value
        config[key] = clean_value
    return config


def extractConfig(infected_memory):
    parsed_config = {}
    parsed_config["family"] = "DarkComet"
    parsed_config["version"] = "5.1"
    parsed_config["rc4_key"] = "#KCMDDC51#-890"
    if (parsed_config["rc4_key"] != ""):
        raw_config = getConfig(parsed_config["rc4_key"], infected_memory)
        parsed_config["cnc_urls"] = raw_config["NETDATA"].split("|")
        parsed_config["ftp_urls"] = raw_config["FTPHOST"].split("|")

        parsed_config["firewall_bypass"] = parseToBool(raw_config["FWB"])
        parsed_config["ftp_username"] = raw_config["FTPUSER"]
        parsed_config["ftp_password"] = raw_config["FTPPASS"]
        parsed_config["ftp_rootdir"] = raw_config["FTPROOT"]
        parsed_config["ftp_keylogs"] = parseToBool(raw_config["FTPUPLOADK"])
        parsed_config["gencode"] = raw_config["GENCODE"]
        parsed_config["mutex"] = raw_config["MUTEX"]
        parsed_config["offline_keylogger"] = parseToBool(raw_config["OFFLINEK"])
        parsed_config["password"] = raw_config["PWD"]
        parsed_config["campaign_id"] = raw_config["SID"]
        parsed_config["ftp_size"] = raw_config["FTPSIZE"]
        parsed_config["keyname"] = raw_config["KEYNAME"]
        try:
            unhexed = raw_config["MSGCORE"].decode("hex")
            print "unhexed: ", unhexed
            unhexed.encode('UTF-8')
            parsed_config["msg_text"] = unhexed
        except:
            parsed_config["msg_text"] = "hex:%s" % raw_config["MSGCORE"]
        try:
            raw_config["MSGTITLE"].encode('UTF-8')
            parsed_config["msg_title"] = raw_config["MSGTITLE"]
        except:
            parsed_config["msg_title"] = "hex:%s" % raw_config["MSGTITLE"].encode("hex")
        parsed_config["msg_icon"] = parseToInt(raw_config["MSGICON"])
        parsed_config["persist_path"] = raw_config["EDTPATH"]
        parsed_config["change_date"] = raw_config["EDTDATE"]
        parsed_config["combo_path"] = parseToInt(raw_config["COMBOPATH"])
        parsed_config["dir_attrib"] = parseToInt(raw_config["DIRATTRIB"])
        parsed_config["file_attrib"] = parseToInt(raw_config["FILEATTRIB"])
        parsed_config["fwb"] = parseToInt(raw_config["FWB"])

    return parsed_config
    
content = ""
file_content = ""
if len(sys.argv) < 2:
    print "usage: \"python %s <file_to_extract_from>\"" % sys.argv[0]
    sys.exit(-1)
    
with open(sys.argv[1], "rb") as f_dc:
    file_content = f_dc.read()
    regex_dc51_config = r"D57ABA5857F0AFF67584605E90BE4665C[0-9A-Fa-f]*"
    match = re.search(regex_dc51_config, file_content)
    if match:
        content = match.group()
    

params = extractConfig(content)

print json.dumps(params, indent=1)

