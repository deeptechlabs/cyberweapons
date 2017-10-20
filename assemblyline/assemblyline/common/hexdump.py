import binascii
from assemblyline.common.chunk import chunk

FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or chr(x) == '\\' and chr(x) or '.' for x in range(256)])


def dump(binary, size=2, sep=" "):
    hexstr = binascii.hexlify(binary)
    return sep.join(chunk(hexstr.upper(), size))


def hexdump(binary, length=16, indent="", indent_size=0, newline='\n', prefix_offset=0):
    """
    Create a string buffer that shows the given data in hexdump format.
    
        src -> source buffer
        length = 16 -> number of bytes per line
        indent = "" -> indentation before each lines
        indent_size = 0 -> number of time to repeat that indentation
        newline = "\n" -> chars used as newline char
        
        Example of output:
        00000000:  48 54 54 50 2F 31 2E 31 20 34 30 34 20 4E 6F 74  HTTP/1.1 404 Not
        00000010:  20 46 6F 75 6E 64 0D 0A 43 6F 6E 74              Found..Cont
        ...
    """
    generator = chunk(binary, length)
    line_frmt = "%%s%%08X:  %%-%ss   %%s" % ((length * 3) - 1)

    out = [line_frmt % (indent * indent_size, prefix_offset + (addr * length), dump(d), d.translate(FILTER))
           for addr, d in enumerate(generator)]
    return newline.join(out)
