#!/usr/bin/env python
from __future__ import print_function

import json
import hashlib
import os
import struct
import sys
import zlib

# noinspection PyPackageRequirements
from Crypto.Cipher import ARC4
from copy import deepcopy

__build_major__ = 1
__build_minor__ = 0
__build_micro__ = 8
__version__ = "CaRT v%d.%d.%d (Python %s)" % (__build_major__,
                                              __build_minor__,
                                              __build_micro__,
                                              ".".join([str(x) for x in sys.version_info[:3]]))


# Format Overview
#
#  MANDATORY HEADER (Not compress, not encrypted.
#  4s     h         Q        16s         Q
# 'CART<VERSION><RESERVED><ARC4KEY><OPT_HEADER_LEN>'
#
# OPTIONAL_HEADER (OPT_HEADER_LEN bytes)
# RC4(<JSON_SERIALIZED_OPTIONAL_HEADER>)
#
# RC4(ZLIB(block encoded stream ))
#
# OPTIONAL_FOOTER_LEN (Q)
# <JSON_SERIALIZED_OPTIONAL_FOOTER>
#
#  MANDATORY FOOTER
#  4s      QQ           Q
# 'TRAC<RESERVED><OPT_FOOTER_LEN>'
#
MANDATORY_HEADER_FMT = '<4shQ16sQ'
MANDATORY_FOOTER_FMT = '<4sQQQ'

VERSION = __build_major__
RESERVED = 0
DEFAULT_ARC4_KEY = b'\x03\x01\x04\x01\x05\x09\x02\x06' * 2   # First 8 digits of PI twice.
if sys.version_info[0] == 2:
    CART_MAGIC = "CART"
    TRAC_MAGIC = "TRAC"
else:
    CART_MAGIC = b"CART"
    TRAC_MAGIC = b"TRAC"

# Must be a dictionary of string to json_serialiable_python_object.
SAMPLE_OPTIONAL_HEADER = {
    'poc': 'bob@organization',
    'name': 'original_filename'
}

# Must be a dictionary of string to json_serialiable_python_object.
# Must be smaller than BLOCK_SIZE (64K)
SAMPLE_OPTIONAL_FOOTER = {
    'md5': '12345....54321',
    'sha1': '1234567...7654321',
    'sha256': '1234567890...0987654321',
    'length': '1234567'
}

BLOCK_SIZE = 64 * 1024


class LengthCounter(object):
    def __init__(self):
        self.name = 'length'
        self.length = 0

    def update(self, chunk):
        self.length += len(chunk)

    def hexdigest(self):
        return str(self.length)


# Digesters must follow a subset of the hashlib interface:
#
# d = digester()
# d.update(chunk)
# ...
# name = d.name
# digest = d.hexdigest()
#
# noinspection PyUnresolvedReferences
DEFAULT_DIGESTS = (hashlib.md5, hashlib.sha1, hashlib.sha256, LengthCounter)


def _write(stream, data):
    stream.write(data)
    return len(data)


def pack_stream(istream, ostream, optional_header=None, optional_footer=None, auto_digests=DEFAULT_DIGESTS,
                arc4_key_override=None):
    if optional_footer is None:
        optional_footer = {}
    if optional_header is None:
        optional_header = {}

    arc4_key = arc4_key_override or DEFAULT_ARC4_KEY
    digesters = [algo() for algo in auto_digests]

    # Build the optional header first if necessary. We need to know
    # it's size before serializing the mandatory header.
    opt_header_len = 0
    opt_header_crypt = None
    pos = 0

    if optional_header:
        cipher = ARC4.new(arc4_key)
        opt_header_json = json.dumps(optional_header, separators=(",", ":"), sort_keys=True)
        opt_header_crypt = cipher.encrypt(opt_header_json)
        opt_header_len = len(opt_header_crypt)

    if arc4_key_override:
        mandatory_header = struct.pack(MANDATORY_HEADER_FMT, CART_MAGIC, VERSION, RESERVED, "\x00"*16, opt_header_len)
    else:
        mandatory_header = struct.pack(MANDATORY_HEADER_FMT, CART_MAGIC, VERSION, RESERVED, arc4_key, opt_header_len)

    pos += _write(ostream, mandatory_header)

    if opt_header_len:
        pos += _write(ostream, opt_header_crypt)

    # restart the RC4 stream for binary stream
    cipher = ARC4.new(arc4_key)
    bz = zlib.compressobj(zlib.Z_BEST_SPEED)
    while True:
        # read the next block from input
        ichunk = istream.read(BLOCK_SIZE)
        if not ichunk:
            break

        # update the various digests with this block
        for digest in digesters:
            digest.update(ichunk)

        # compress and then cipher any resulting output blocks
        maybe_zchunk = bz.compress(ichunk)
        if maybe_zchunk:
            ciphered_chunk = cipher.encrypt(maybe_zchunk)
            pos += _write(ostream, ciphered_chunk)

    # flush the compressor then cipher and output any remaining data
    maybe_zchunk = bz.flush()
    if maybe_zchunk:
        cipher_chunk = cipher.encrypt(maybe_zchunk)
        pos += _write(ostream, cipher_chunk)

    # insert any requests digests into the optional footer.
    for digest in digesters:
        optional_footer[digest.name] = digest.hexdigest()

    opt_footer_pos = pos
    opt_footer_len = 0
    if optional_footer:
        # restart the RC4 stream for the footer.
        cipher = ARC4.new(arc4_key)
        opt_footer_json = json.dumps(optional_footer, separators=(",", ":"), sort_keys=True)
        ciphered_footer = cipher.encrypt(opt_footer_json)
        opt_footer_len = len(ciphered_footer)
        pos += _write(ostream, ciphered_footer)

    mandatory_footer = struct.pack(MANDATORY_FOOTER_FMT, TRAC_MAGIC, 0, opt_footer_pos, opt_footer_len)

    pos += _write(ostream, mandatory_footer)


def _unpack_header(istream, arc4_key_override=None):
    # unpack to output stream, return header / footer
    # First read and unpack the mandatory header. This will tell us the RC4 key
    # and optional header length.
    # Optional header and rest of document are RC4'd
    pos = 0

    # Read and unpack the madatory header.
    mandatory_header_len = struct.calcsize(MANDATORY_HEADER_FMT)
    mandatory_header = istream.read(mandatory_header_len)
    pos += mandatory_header_len
    (_magic, _version, _reserved, arc4_key, opt_header_len) = struct.unpack(
        MANDATORY_HEADER_FMT, mandatory_header)
    if _magic != CART_MAGIC or _version != 1 or _reserved != 0:
        raise TypeError("This is not valid CaRT file")

    if arc4_key_override:
        arc4_key = arc4_key_override

    # Read and unpack any optional header.
    optional_header = {}
    if opt_header_len:
        cipher = ARC4.new(arc4_key)
        optional_header_crypt = istream.read(opt_header_len)
        pos += opt_header_len
        optional_header_json = cipher.decrypt(optional_header_crypt)
        if sys.version_info[0] == 3:
            optional_header_json = optional_header_json.decode()
        try:
            optional_header = json.loads(optional_header_json)
        except ValueError:
            raise ValueError("Invalid ARC4 Key, could not unpack header")
    return arc4_key, optional_header, pos


def unpack_stream(istream, ostream, arc4_key_override=None):
    # unpack to output stream, return header / footer
    # First read and unpack the mandatory header. This will tell us the RC4 key
    # and optional header length.
    # Optional header and rest of document are RC4'd
    (arc4_key, optional_header, pos) = _unpack_header(istream, arc4_key_override=arc4_key_override)

    # Read / Unpack / Output the binary stream 1 block at a time.
    cipher = ARC4.new(arc4_key)
    bz = zlib.decompressobj()
    last_chunk = ''
    while True:
        crypt_chunk = istream.read(BLOCK_SIZE)
        pos += len(crypt_chunk)
        if not crypt_chunk:
            break

        zchunk = cipher.decrypt(crypt_chunk)
        maybe_ochunk = bz.decompress(zchunk)
        if maybe_ochunk:
            ostream.write(maybe_ochunk)
            last_chunk = crypt_chunk
        else:
            last_chunk += crypt_chunk

    # unused data will be the
    footer_offset = len(last_chunk) - struct.calcsize(MANDATORY_FOOTER_FMT)

    mandatory_footer_raw = last_chunk[footer_offset:]
    (magic, _reserved, opt_footer_pos, opt_footer_len) = struct.unpack(MANDATORY_FOOTER_FMT, mandatory_footer_raw)

    opt_footer_offset = footer_offset - opt_footer_len

    optional_footer = {}
    if opt_footer_len:
        cipher = ARC4.new(arc4_key)
        optional_crypt = last_chunk[opt_footer_offset:opt_footer_offset + opt_footer_len]

        optional_footer_json = cipher.decrypt(optional_crypt)
        if sys.version_info[0] == 3:
            optional_footer_json = optional_footer_json.decode()
        optional_footer = json.loads(optional_footer_json)
    return optional_header, optional_footer


def mpack_helper(input_path, output_path, operation, optional_header=None, optional_footer=None,
                 arc4_key_override=None):
    fin = open(input_path, 'rb')
    fout = open(output_path, 'wb')
    if operation == pack_stream:
        if not optional_header:
            optional_header = {'name': os.path.basename(input_path)}
        rval = operation(fin, fout, optional_header=optional_header, optional_footer=optional_footer,
                         arc4_key_override=arc4_key_override)
    else:
        rval = operation(fin, fout, arc4_key_override=arc4_key_override)
    fin.close()
    fout.close()
    return rval


def pack_file(input_path, output_path, optional_header=None, optional_footer=None, arc4_key_override=None):
    # noinspection PyTypeChecker
    return mpack_helper(input_path,
                        output_path,
                        pack_stream,
                        optional_header=optional_header,
                        optional_footer=optional_footer,
                        arc4_key_override=arc4_key_override)


def unpack_file(input_path, output_path, arc4_key_override=None):
    # noinspection PyTypeChecker
    return mpack_helper(input_path, output_path, unpack_stream, arc4_key_override=arc4_key_override)


def get_metadata_only(input_path, arc4_key_override=None):
    metadata = {}
    with open(input_path, 'rb') as fin:
        (arc4_key, optional_header, _) = _unpack_header(fin, arc4_key_override=arc4_key_override)
        metadata.update(optional_header)
        mandatory_footer_size = struct.calcsize(MANDATORY_FOOTER_FMT)
        fin.seek(-1 * mandatory_footer_size, os.SEEK_END)
        mandatory_footer_raw = fin.read(mandatory_footer_size)
        (_magic, _reserved, opt_footer_pos, opt_footer_len) = struct.unpack(
            MANDATORY_FOOTER_FMT, mandatory_footer_raw)
        if opt_footer_len:
            fin.seek(opt_footer_pos)
            opt_footer_raw = fin.read(opt_footer_len)
            cipher = ARC4.new(arc4_key)
            optional_footer_json = cipher.decrypt(opt_footer_raw)

            if sys.version_info[0] == 3:
                optional_footer_json = optional_footer_json.decode()
            optional_footer = json.loads(optional_footer_json)
            metadata.update(optional_footer)

    return metadata


def is_cart(buff):
    # noinspection PyBroadException
    try:
        mandatory_header_len = struct.calcsize(MANDATORY_HEADER_FMT)
        mandatory_header = buff[:mandatory_header_len]
        cart, version, reserved, _, _ = struct.unpack(MANDATORY_HEADER_FMT, mandatory_header)
        if cart == CART_MAGIC and version == 1 and reserved == 0:
            return True
        else:
            return False
    except Exception:
        return False


def main():
    import base64

    if sys.version_info[0] == 2:
        # noinspection PyUnresolvedReferences,PyPep8Naming
        import ConfigParser as configparser
        # noinspection PyUnresolvedReferences
        import peeker
    else:
        # noinspection PyUnresolvedReferences
        import configparser
        # noinspection PyUnresolvedReferences
        import cart.peeker as peeker

    from optparse import OptionParser

    header_defaults = {}
    delete = False
    force = False
    keep_meta = False
    rc4_override = None

    config = configparser.ConfigParser()
    config.read([os.path.expanduser('~/.cart/cart.cfg')])
    for section in config.sections():
        if section == "global":
            if 'delete' in config.options('global'):
                delete = config.getboolean('global', 'delete')

            if 'force' in config.options('global'):
                force = config.getboolean('global', 'force')

            if 'keep_meta' in config.options('global'):
                keep_meta = config.getboolean('global', 'keep_meta')

            if 'rc4_key' in config.options('global'):
                rc4_override = base64.b64decode(config.get('global', 'rc4_key'))
        else:
            for option in config.options(section):
                header_defaults[option] = config.get(section, option)

    usage = "usage: %prog [options] file1 file2 ... fileN"
    parser = OptionParser(usage=usage, version=__version__)
    parser.add_option("-d", "--delete", action="store_true", dest="delete", default=False,
                      help="Delete original after operation succeeded")
    parser.add_option("-f", "--force", action="store_true", dest="force", default=False,
                      help="Replace output file if it already exists")
    parser.add_option("-i", "--ignore", action="store_true", dest="ignore", default=False,
                      help="Ignore RC4 key from conf file")
    parser.add_option("-j", "--jsonmeta", dest="jsonmeta", help="Provide header metadata as json blob")
    parser.add_option("-k", "--key", dest="key", help="Use private RC4 key (base64 encoded). "
                                                      "Same key must be provided to unCaRT.")
    parser.add_option("-m", "--meta", action="store_true", dest="meta", default=False,
                      help="Keep metadata around when extracting CaRTs")
    parser.add_option("-n", "--name", dest="filename", help="Use this value as metadata filename")
    parser.add_option("-o", "--outfile", dest="outfile", help="Set output file")
    parser.add_option("-s", "--showmeta", action="store_true", dest="showmeta", default=False,
                      help="Only show the file metadata")

    (options, args) = parser.parse_args()

    stream_mode = False
    if not args:
        if os.name == "posix" and not sys.stdin.isatty():
            stream_mode = True
        else:
            parser.print_help()
            exit()
    
    delete = options.delete or delete
    force = options.force or force
    keep_meta = options.meta or keep_meta
    if options.key:
        rc4_override = base64.b64decode(options.key)
    if rc4_override:
        rc4_override += "\x00" * (16 - len(rc4_override))
    if options.filename:
        header_defaults['name'] = options.filename
    output_file = options.outfile
    show_meta = options.showmeta
    if options.ignore:
        rc4_override = None
    if options.jsonmeta:
        header_defaults.update(json.loads(options.jsonmeta))

    if header_defaults.get('name', None) and len(args) > 1:
        print("ERR: Cannot set 'filename' option when UN/CaRTing multiple files")
        exit(2)

    if output_file and len(args) > 1:
        print("ERR: Cannot set 'outfile' option when UN/CaRTing multiple files")
        exit(2)

    if stream_mode:
        input_stream = peeker.Peeker(sys.stdin)
        if output_file:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            output_stream = open(output_file, "wb")
        else:
            output_stream = sys.stdout

        first_bytes = input_stream.peek(65535)
        if is_cart(first_bytes):
            unpack_stream(input_stream, output_stream, arc4_key_override=rc4_override)
        else:
            pack_stream(input_stream, output_stream, header_defaults, arc4_key_override=rc4_override)
        sys.stdout.flush()
    else:
        for cur_file in args:
            cur_header = deepcopy(header_defaults)
            if not os.path.exists(cur_file):
                print("ERR: file '%s' does not exists" % cur_file)
                if len(args) > 1:
                    continue
                else:
                    exit(4)

            file_in = open(cur_file, 'rb')
            first_bytes = file_in.read(struct.calcsize(MANDATORY_HEADER_FMT))
            file_in.close()
            if is_cart(first_bytes):
                # noinspection PyBroadException
                try:
                    cur_metadata = get_metadata_only(cur_file, arc4_key_override=rc4_override)
                except Exception:
                    print("ERR: Could not extract header from CaRT file '%s'. Invalid RC4 key!" % cur_file)
                    if len(args) > 1:
                        continue
                    else:
                        exit(5)
                if show_meta:
                    print(json.dumps(cur_metadata, sort_keys=True, indent=4))
                else:
                    if not output_file:
                        backup_name = os.path.basename(cur_file)
                        if backup_name.endswith(".cart"):
                            backup_name = backup_name[:-5]
                        else:
                            backup_name += ".uncart"
                        output_file = cur_metadata.get('name', backup_name)
                    output_file = os.path.join(os.path.dirname(cur_file), output_file)

                    if os.path.exists(output_file) and not force:
                        print("ERR: file '%s' already exists" % output_file)
                        if len(args) > 1:
                            continue
                        else:
                            exit(3)

                    # noinspection PyBroadException
                    try:
                        os.makedirs(os.path.dirname(output_file))
                    except Exception:
                        pass

                    header, footer = unpack_file(cur_file, output_file, arc4_key_override=rc4_override)
                    if keep_meta:
                        outmeta = {}
                        outmeta.update(header)
                        outmeta.update(footer)
                        output_meta_file = open(output_file+".cartmeta", "wb")
                        output_meta_file.write(json.dumps(outmeta, sort_keys=True, indent=4))
                        output_meta_file.close()
                    
                    if delete:
                        os.unlink(cur_file)
                    
                    output_file = None
            else:
                if show_meta:
                    cur_metadata = {}
                    meta_file_path = cur_file + ".cartmeta"
                    if os.path.exists(meta_file_path):
                        cur_metadata.update(json.loads(open(meta_file_path, 'rb').read()))
                    print(json.dumps(cur_metadata, sort_keys=True, indent=4))
                else:
                    if not output_file:
                        output_file = cur_file+".cart"

                    if os.path.exists(output_file) and not force:
                        print("ERR: file '%s' already exists" % output_file)
                        if len(args) > 1:
                            continue
                        else:
                            exit(3)

                    meta_file_path = cur_file + ".cartmeta"
                    if os.path.exists(meta_file_path):
                        cur_header.update(json.loads(open(meta_file_path, 'rb').read()))
                    
                    # noinspection PyBroadException
                    try:
                        os.makedirs(os.path.dirname(output_file))
                    except Exception:
                        pass

                    if not cur_header.get("name", None):
                        cur_header['name'] = os.path.basename(cur_file)

                    pack_file(cur_file, output_file, optional_header=cur_header, arc4_key_override=rc4_override)
                    
                    if delete:
                        os.unlink(cur_file)
                        if os.path.exists(meta_file_path):
                            os.unlink(meta_file_path)

                    output_file = None


if __name__ == '__main__':
    main()
