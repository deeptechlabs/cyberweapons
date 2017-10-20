import re
import string

from al_services.alsvc_configdecoder import configparser

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

def to_int(value):
    try:
        return int(value)
    except: # pylint: disable=W0702
        return value

class DarkComet51Parser(configparser.ConfigParser):
    NAME = "Dark Comet 5.1"

    def parse(self, request, hits, content):
        parsed = configparser.ParsedConfig(self, "1.0")
        regex_dc51_config = r"D57ABA5857F0AFF67584605E90BE4665C[0-9A-Fa-f]*"
        match = re.search(regex_dc51_config, content)
        if match:
            crypted_config = match.group()
            rc4key = "#KCMDDC51#-890"
            decrypted_config = rc4crypt(crypted_config.decode("hex"), rc4key)
            dec_list = decrypted_config.split('\n')
            for entry in dec_list[1:-1]:
                if "#EOF DARKCOMET DATA" in entry:
                    break
                key, value = entry.split('=', 1)
                key = key.strip()
                value = value.rstrip()[1:-1]
                clean_value = ''.join(x for x in value if x in string.printable)

                # TODO: If "list" becomes a supported type for value,
                #       the keys "NETDATA" and "FTPHOST" should be treated
                #       with *.split("|")

                if key in [
                    "MSGICON", "COMBOPATH", "DIRATTRIB", "FILEATTRIB",
                    "FWB", "FTPUPLOADK", "OFFLINEK"
                ]:
                    clean_value = to_int(clean_value)

                parsed.add_value(key, clean_value)

        return [parsed]

