class ConfigDecoderBase(object):
    def __init__(self, name, classification, yara_rule, should_always_work = True, search_only_binaries = False):
        self.name = name
        self.classification = classification
        self.yara_rule = yara_rule
        self.shouldAlwaysWork = should_always_work
        self.search_only_binaries = search_only_binaries
        
    def get_name(self):
        return self.name

    def get_yara_rule(self):
        return self.yara_rule
    
    def has_yara_rule(self):
        return (self.yara_rule != None and len(self.yara_rule) > 0)
    
    def get_classification(self):
        return self.classification
    
    def should_always_work(self):
        return self.shouldAlwaysWork
    
    def search_only_binaries(self):
        return self.search_only_binaries
        
    def extra_validation(self,yara_hit, filename, data):
        if(self.yara_rule == '' or self.yara_rule == None or yara_hit != None):
            return True
        else:
            return False
        
    def decode(self, filename, data):
        return None
    
_CD_RES_TYPE = [
    ('OTHER', 99),          # other or not determined yet
    ('BUFFER', 98),         # asking for a dump....
    ('DOMAIN_NAME', 1),     # for example: www.test.com
    ('FILE_NAME', 2),       # no path, just abc.exe
    ('IMPLANT_NAME', 3),    # or file attribution
    ('ACTOR_NAME', 4)]      # or family?
    
    
CD_RES_TYPE = dict([(e[1], e[0]) for e in _CD_RES_TYPE] + _CD_RES_TYPE)

class ConfigDecoderResultPayload(object):
    def __init__(self, name, data, description, offset=None):
        self.name = name
        self.data = data
        self.description = description
        self.offset = offset
        
class ConfigDecoderResultValue(object):
    def __init__(self, name, value, type=None, offset=None):
        if(type == None):
            type = CD_RES_TYPE['OTHER']
            
        self.name = name
        self.value = value
        self.type = type
        self.offset = offset
        
class ConfigDecoderResult(object):
    def __init__(self, name, version, classification):
        self.rational = None
        # the dict will allow easier access and the list will keep the ordering.
        self.config_values_dict = {}
        self.config_values_list = []
        self.payload = []
        self.name = name
        self.version = version
        self.classification = classification
        
    def add_value(self, name, value, type=None, offset=None):
        cd_value = ConfigDecoderResultValue(name, value, type, offset)
        
        # store it in the dict
        config_value_by_name = self.config_values_dict.get(name, [])
        config_value_by_name.append(cd_value)
        self.config_values_dict[name] = config_value_by_name
        
        # store it in the list
        self.config_values_list.append(cd_value)
        
    def get_value(self, name):
        return self.config_values_dict.get(name, [])
    
    def get_first_value(self, name):
        cdv_list = self.config_values_dict.get(name, [])
        if(len(cdv_list) == 0):
            value = ""
        else:
            value = cdv_list[0].value
            
        return value
    
    def add_payload(self, name, data, description, offset=None):
        cd_payload = ConfigDecoderResultPayload(name, data, description, offset)
        self.payload.append(cd_payload)
    
    def get_all_values(self):
        return self.config_values_list
    
FILTER = ''.join([(len(repr(chr(x)))==3) and chr(x) or chr(x) == '\\' and chr(x) or '.' for x in range(256)])    
def db(src, length=16, ident="", newline = '\n'):
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
            c = lambda x: ord( x )
        else:
            c = lambda x: x
        for i in  xrange(0, len(src), length):
            s = src[i:i+length]
            result += "%s%08X:  %s" % (ident, i, ' '.join(["%02X" % c(x) for x in s]) )
            if (len(src) - i) < length:
                diff = length - (len(src) - i)
                result += " " * (diff * 3)
            result += "  %s%s" % (''.join(["%c" % c(x) for x in s]).translate(FILTER), newline)
    return result    
         
         
class NoConfigFound(Exception):
    """
    This exception is thrown if no config is found in this data
    """
    pass

def IMUL_32(value1, value2):
    return (value1 * value2) & 0xFFFFFFFF

def ADD_32(value1, value2):
    return (value1 + value2) & 0xFFFFFFFF

def SUB_32(value1, value2):
    return (value1 - value2) & 0xFFFFFFFF

def SHL_32(value, num_of_bits):
    return (value << num_of_bits) & 0xFFFFFFFF

def SAR_32(value, num_of_bits):
    new_value = value >> num_of_bits
    
    #if it's a negative number, I have to keep the sign since it's an arithmetic shift
    if(value & 0x80000000 > 0):
        b = 0x80000000
        while(new_value & b == 0):
            new_value |= b
            b = b >> 1
            
    return new_value



        
