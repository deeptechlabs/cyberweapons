import os

from assemblyline.al.common.result import Classification, TAG_TYPE, TAG_WEIGHT

_CD_RES_TYPE = [
    ('OTHER', 99),          # other or not determined yet
    ('BUFFER', 98),         # asking for a dump....
    ('DOMAIN_NAME', 1),     # for example: www.test.com
    ('FILE_NAME', 2),       # no path, just abc.exe
    ('IMPLANT_NAME', 3),    # or file attribution
    ('ACTOR_NAME', 4)]      # or family?


CD_RES_TYPE = dict([(e[1], e[0]) for e in _CD_RES_TYPE] + _CD_RES_TYPE)

FILTER = ''.join(
    len(repr(chr(x))) == 3 and chr(x) or chr(x) == '\\' and chr(x) or '.'
        for x in range(256)
)

g_type_mapping = {
    CD_RES_TYPE['DOMAIN_NAME']: TAG_TYPE['NET_DOMAIN_NAME'],
    CD_RES_TYPE['FILE_NAME']: TAG_TYPE['FILE_NAME'],
    CD_RES_TYPE['IMPLANT_NAME']: TAG_TYPE['IMPLANT_NAME'],
    CD_RES_TYPE['ACTOR_NAME']: TAG_TYPE['THREAT_ACTOR']
}

def hexdump(src, length=16, ident="", newline='\n'):
    """
    Print buffer as an Hexdumped format

    src -> source buffer
    length = 16 -> number of bytes per line
    indent = "" -> indentation before each lines
    newline = "\n" -> chars used as newline char

    Example of output:
    00000000:  48 54 54 50 2F 31 2E 31 20 34 30 34 20 4E 6F 74  HTTP/1.1 404 Not
    00000010:  20 46 6F 75 6E 64 0D 0A 43 6F 6E 74 65 6E 74 2D   Found..Content-
    ...
    """

    result = ''
    if len(src):
        if type(src[0]) == type(""):
            c = ord
        else:
            c = lambda x: x
        for i in  xrange(0, len(src), length):
            s = src[i:i+length]
            result += "%s%08X:  %s" % (ident, i,
                                       ' '.join(["%02X" % c(x) for x in s]))
            if (len(src) - i) < length:
                diff = length - (len(src) - i)
                result += " " * (diff * 3)
            result += "  %s%s" % \
                (''.join(["%c" % c(x) for x in s]).translate(FILTER), newline)
    return result

def is_printable(string):
    return all(0x1F < ord(c) < 0x7f for c in string)

def normalized_ipv4(address):
    try:
        parts = [int(part) for part in address.split(".")]
        if len(parts) != 4:
            return None

        return ".".join(str(part) for part in parts)
    except: # pylint: disable=W0702
        return None

class ConfigParser(object):
    CLASSIFICATION = Classification.UNRESTRICTED
    NAME = "Base Config Parser"
    RULE = True

    def accept(self, request, hits, content): # pylint: disable=W0613
        if not self.RULE or hits:
            return True
        else:
            return False

    def parse(self, request, hits, content): # pylint: disable=W0613
        return None

class ParsedConfigPayload(object):
    def __init__(self, name, data, description, offset=None):
        self.name = name
        self.data = data
        self.description = description
        self.offset = offset

class ParsedConfigValue(object):
    def __init__(self, name, value, value_type=None, offset=None):
        if value_type == None:
            value_type = CD_RES_TYPE['OTHER']

        self.name = name
        self.value = value
        self.type = value_type
        self.offset = offset

class ParsedConfig(object):
    def __init__(self, parser, version, name=None, classification=None):
        self.classification = classification or parser.CLASSIFICATION
        # the dict will allow easier access and the list will keep the ordering.
        self.config_values_dict = {}
        self.config_values_list = []
        self.name = name or parser.NAME
        self.payload = []
        self.version = version

    def add_payload(self, name, data, description, offset=None):
        cd_payload = ParsedConfigPayload(name, data, description, offset)
        self.payload.append(cd_payload)

    def add_value(self, name, value, value_type=None, offset=None):
        cd_value = ParsedConfigValue(name, value, value_type, offset)

        # store it in the dict
        config_value_by_name = self.config_values_dict.get(name, [])
        config_value_by_name.append(cd_value)
        self.config_values_dict[name] = config_value_by_name

        # store it in the list
        self.config_values_list.append(cd_value)

    def get_all_values(self):
        return self.config_values_list

    def get_value(self, name):
        return self.config_values_dict.get(name, [])

    def report(self, request, section, worker):
        result = request.result

        # for all values ...
        for value in self.get_all_values():
            value_type = type(value.value)

            if value.type != CD_RES_TYPE['BUFFER'] and \
               value_type == str and is_printable(value.value) or \
               value_type == int:
                line = [value.name, " => "]

                value_tag_type = g_type_mapping.get(value.type, None)

                if value_tag_type == TAG_TYPE['NET_DOMAIN_NAME']:
                    value_port_splitted = value.value.split(':')
                    normalized_ip = normalized_ipv4(value_port_splitted[0])
                    if normalized_ip != None:
                        value_tag_type = TAG_TYPE['NET_IP']
                        value.value = normalized_ip
                    else:
                        value.value = value_port_splitted[0]

                if value_tag_type == None:
                    line.append(str(value.value))
                else:
                    if value.value != '':
                        line.append(value.value)
                        result.add_tag(value_tag_type, value.value,
                                       TAG_WEIGHT['HIGH'],
                                       classification=self.classification)

                    if value_tag_type == TAG_TYPE['NET_DOMAIN_NAME'] and \
                       len(value_port_splitted) == 2:
                        line.append(":%s" % value_port_splitted[1])

                if value_type == int:
                    line.append(" (0x%X)" % value.value)

                if value.offset != None:
                    line.append(" [@ 0x%X]" % value.offset)

                section.add_line(line)
            else:
                line = [value.name]

                if value.offset != None:
                    line.append(" [@ 0x%X]" % value.offset)

                line.append(' =>')
                section.add_line(line)
                section.add_line(hexdump(value.value))

        # for all payloads ...
        for payload in self.payload:
            line = ['Extracted a payload ']

            if payload.name != None and payload.name != '':
                line.append('(')
                line.append(payload.name)
                line.append(') ')

            if payload.offset != None:
                line.append('located at: 0x%X' % payload.offset)
                display_name = "%s_0x%X" % (self.name, payload.offset)
            else:
                display_name = self.name
            temp_name = request.tempfile()

            if payload.description != None and payload.description != '':
                line.append(' [%s]' % payload.description)

            section.add_line(line)

            # Write the payload to a file so that it can be submitted.
            with open(temp_name, 'wb') as temp_file:
                temp_file.write(payload.data)

            if not request.add_extracted(temp_name, "config", display_name):
                worker.log.error('An error occurred while submitting file '
                                 'extracted using %s with filename %s.',
                                 self.name, temp_name)
                os.remove(temp_name)

        return True

class NullParsedConfig(object):
    def __init__(self, parser, name=None, classification=None):
        self.classification = classification or parser.CLASSIFICATION
        self.name = name or parser.NAME

