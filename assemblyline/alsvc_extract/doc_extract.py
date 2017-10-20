#!/usr/bin/env python2.7
# Note:
# All algorithms, constants, etc taken from:
#  https://msdn.microsoft.com/en-us/library/cc313071(v=office.12).aspx

import struct
import hashlib
import math
import binascii
import tempfile

from Crypto.Cipher import AES, DES3, ARC2, ARC4, DES
from lxml import etree
from olefile import olefile


class PasswordError(Exception):
    pass


class ExtractionError(Exception):
    pass


def get_bit(i, n, mask = 1):
    """Helper function, extract bits from a bitmask"""
    return (i >> n) & mask


def derive_key_v2(hash_val, key_size):
    """Algorithm from MS-OFFCRYPTO 2.3.4.7"""
    tmp_buffer = ['\x36'] * 64
    for i, c in enumerate(hash_val):
        tmp_buffer[i] = chr(ord(tmp_buffer[i]) ^ ord(hash_val[i]))

    x1 = hashlib.sha1("".join(tmp_buffer)).digest()
    derived_key = x1

    if key_size >= len(derived_key):
        tmp_buffer = ['\x5C'] * 64
        for i, c in enumerate(hash_val):
            tmp_buffer[i] = chr(ord(tmp_buffer[i]) ^ ord(hash_val[i]))

        x2 = hashlib.sha1("".join(tmp_buffer)).digest()

        derived_key += x2

    return derived_key[:key_size]


def generate_enc_key_v2(password, salt, key_size):
    """Algorithm from MS-OFFCRYPTO 2.3.4.7"""
    h_step = hashlib.sha1(salt + password.encode("utf-16")[2:]).digest()
    struct_template = "I%is" % hashlib.sha1().digest_size

    for i in xrange(50000):
        h_step = hashlib.sha1(struct.pack(struct_template, i, h_step)).digest()

    block = 0
    h_final = hashlib.sha1(h_step + struct.pack("I", block)).digest()

    key = derive_key_v2(h_final, key_size)
    return key


def check_password_v2(password, metadata):
    """Method described in MS-OFFCRYPTO 2.3.4.9"""
    key = generate_enc_key_v2(password, metadata['salt'], metadata['enc_header']['KeySize'])

    aes = AES.new(key, mode=AES.MODE_ECB)
    vhash = aes.decrypt(metadata['verifier_hash'])[:metadata['verifier_len']]
    vdata = aes.decrypt(metadata['verifier_data'])
    hash = hashlib.sha1(vdata).digest()
    return vhash == hash


def adjust_buf_len(buffer, length, pad="\x36"):
    if len(buffer) < length:
        buffer += pad * (length - len(buffer))
    elif len(buffer) > length:
        buffer = buffer[:length]
    return buffer


def generate_enc_key_v4(password, salt, spins, hash, key_size, block_key):
    """Algorithm from MS-OFFCRYPTO 2.3.4.11"""
    h_step = hash(salt + password.encode("utf-16")[2:]).digest()
    struct_template = "I%is" % hash().digest_size
    for i in xrange(spins):
        h_step = hash(struct.pack(struct_template, i, h_step)).digest()

    h_final = hash(h_step + block_key).digest()
    return adjust_buf_len(h_final, key_size, "\x36")


def pad_buffer(buffer, block_size, pad="\x00"):
    return buffer + pad*(block_size - (len(buffer) % block_size))


def check_password_v4(password, metadata):
    """Method described in MS-OFFCRYPTO 2.3.4.9 to 2.3.4.13"""

    # Constants from MS-OFFCRYPTO 2.3.4.10
    hash_alg = {
        "SHA1": hashlib.sha1,
        "SHA-1": hashlib.sha1,
        "SHA256": hashlib.sha256,
        "SHA384": hashlib.sha384,
        "SHA512": hashlib.sha512,
        "MD5": hashlib.md5
    }
    crypto_alg = {
        "AES": AES,
        "3DES": DES3,
        "RC2": ARC2,
        "RC4": ARC4,
        "DES": DES
    }
    block_key_1 = "\xfe\xa7\xd2\x76\x3b\x4b\x9e\x79"
    block_key_2 = "\xd7\xaa\x0f\x6d\x30\x61\x34\x4e"
    block_key_3 = "\x14\x6e\x0b\xe7\xab\xac\xd0\xd6"

    chain_mode = {
        "ChainingModeCBC": "MODE_CBC",
        "ChainingModeCFB": "MODE_CFB"
    }
    try:
        salt = metadata['encryptedKey']['saltValue']
        hash = hash_alg[metadata['encryptedKey']['hashAlgorithm']]
        spin_count = int(metadata['encryptedKey']['spinCount'])
        key_size = int(metadata['encryptedKey']['keyBits'])/8
        enc_method = crypto_alg[metadata['encryptedKey']['cipherAlgorithm']]
        mode = chain_mode[metadata['encryptedKey']['cipherChaining']]
        mode = getattr(enc_method, mode)
        hash_size = int(metadata['encryptedKey']['hashSize'])
    except KeyError:
        raise ExtractionError("Unsupported encryption method used.")

    key1 = generate_enc_key_v4(password, salt, spin_count, hash, key_size, block_key_1)
    key2 = generate_enc_key_v4(password, salt, spin_count, hash, key_size, block_key_2)
    key3 = generate_enc_key_v4(password, salt, spin_count, hash, key_size, block_key_3)
    iv = adjust_buf_len(salt, enc_method.block_size, "\x36")

    encryptor1 = enc_method.new(key1, mode=mode, IV=iv)
    encryptor2 = enc_method.new(key2, mode=mode, IV=iv)
    encryptor3 = enc_method.new(key3, mode=mode, IV=iv)

    v_hash = encryptor2.decrypt(metadata['encryptedKey']['encryptedVerifierHashValue'])
    e1 = encryptor1.decrypt(metadata['encryptedKey']['encryptedVerifierHashInput'])
    h1 = hash(e1).digest()
    if h1 == v_hash[:hash_size]:
        metadata['KeyValue'] = encryptor3.decrypt(metadata['encryptedKey']['encryptedKeyValue'])
        return True
    else:
        return False


def check_password(password, metadata):
    if metadata["ver_maj"] == 4 and metadata["ver_min"] == 4 and metadata["flags"] == 0x40:
        return check_password_v4(password, metadata)
    elif (metadata["ver_maj"] == 2 or metadata["ver_maj"] == 3 or metadata["ver_maj"] == 4) and metadata["ver_min"] == 3:
        raise ExtractionError("Error, unsupported encryption.")
    elif (metadata["ver_maj"] == 2 or metadata["ver_maj"] == 3 or metadata["ver_maj"] == 4) and metadata["ver_min"] == 2:
        return check_password_v2(password, metadata)


def decode_flags_v2(flags):
    """Flags laid out in MS-OFFCRPYTO 2.3.1"""
    out = {
        'fCryptoAPI': get_bit(flags, 2) == 1,
        'fExternal': get_bit(flags, 4) == 1,
        'fAES': get_bit(flags, 5) == 1
    }

    return out


def decode_stream_v2(password, metadata, package, out_file):
    """Structure laid out in MS-OFFCRYPTO 2.3.4.4"""
    decoded_len = struct.unpack("Q", package.read(8))[0]
    ks = metadata['enc_header']['KeySize']

    key = generate_enc_key_v2(password, metadata['salt'], ks)

    aes = AES.new(key, mode=AES.MODE_ECB)
    block_count = int(math.ceil(decoded_len/float(ks)))
    remainder = int(ks - (decoded_len % float(ks)))
    for i in xrange(block_count):
        cipher_t = package.read(ks)

        plain_t = aes.decrypt(cipher_t)
        if i == block_count-1:
            plain_t = plain_t[:remainder]

        out_file.write(plain_t)


def decode_stream_v4(metadata, package, out_file):
    """Structure laid out in MS-OFFCRYPTO 2.3.4.15"""
    # Constants from MS-OFFCRYPTO 2.3.4.10
    hash_alg = {
        "SHA1": hashlib.sha1,
        "SHA-1": hashlib.sha1,
        "SHA256": hashlib.sha256,
        "SHA384": hashlib.sha384,
        "SHA512": hashlib.sha512,
        "MD5": hashlib.md5
    }
    crypto_alg = {
        "AES": AES,
        "3DES": DES3,
        "RC2": ARC2,
        "RC4": ARC4,
        "DES": DES
    }

    chain_mode = {
        "ChainingModeCBC": "MODE_CBC",
        "ChainingModeCFB": "MODE_CFB"
    }
    try:
        salt = metadata['keyData']['saltValue']
        hash = hash_alg[metadata['keyData']['hashAlgorithm']]
        enc_method = crypto_alg[metadata['keyData']['cipherAlgorithm']]
        mode = chain_mode[metadata['keyData']['cipherChaining']]
        mode = getattr(enc_method, mode)
    except KeyError:
        raise ExtractionError("Unsupported encryption method used.")

    decoded_len = struct.unpack("Q", package.read(8))[0]

    key_value = metadata['KeyValue']
    block_len = 4096

    block_count = int(math.ceil(decoded_len / float(block_len)))
    remainder = enc_method.block_size - (decoded_len % enc_method.block_size)
    for i in xrange(block_count):
        block = package.read(block_len)
        iv = hash(salt + struct.pack("I", i)).digest()
        iv = adjust_buf_len(iv, enc_method.block_size, "\x36")
        encryptor = enc_method.new(key_value, mode=mode, IV=iv)

        plain_t = encryptor.decrypt(block)
        if i == block_count - 1:
            plain_t = plain_t[:-remainder]

        out_file.write(plain_t)


def decode_stream(password, metadata, package, out_file):
    if metadata["ver_maj"] == 4 and metadata["ver_min"] == 4 and metadata["flags"] == 0x40:
        return decode_stream_v4(metadata, package, out_file)
    elif (metadata["ver_maj"] == 2 or metadata["ver_maj"] == 3 or metadata["ver_maj"] == 4) and metadata["ver_min"] == 3:
        pass
    elif (metadata["ver_maj"] == 2 or metadata["ver_maj"] == 3 or metadata["ver_maj"] == 4) and metadata["ver_min"] == 2:
        return decode_stream_v2(password, metadata, package, out_file)


def parse_enc_info_v2(doc, header):
    """Structures laid out in MS-OFFCRYPTO 2.3.2 and 2.3.3"""
    enc_header = {}

    # constants from MS-OFFCRYPTO 2.3.4.5
    ALGID_ENUM = {
        0x00006801: "RC4",
        0x0000660E: "128-bit AES",
        0x0000660F: "192-bit AES",
        0x00006610: "256-bit AES"
    }

    ALGIDHASH_ENUM = {
        0x00000000: 'SHA-1',
        0x00008004: 'SHA-1'
    }

    # noinspection PyBroadException
    try:
        fixed = struct.unpack("I", doc.read(4))
        header["size"] = fixed[0]
        fixed = struct.unpack("IIIIIIII", doc.read(8*4))
        enc_header['flags'] = fixed[0]
        enc_header['SizeExtra'] = fixed[1]
        enc_header['AlgID'] = ALGID_ENUM.get(fixed[2], fixed[2])
        enc_header['AlgIDHash'] = ALGIDHASH_ENUM.get(fixed[3], fixed[3])
        enc_header['KeySize'] = fixed[4]/8
        enc_header['ProviderType'] = fixed[5]
        enc_header['Reserved1'] = fixed[6]
        enc_header['Reserved2'] = fixed[7]
        enc_header['CSPName'] = doc.read(header["size"]-(8*4)).decode("utf-16")
        enc_header["flags"] = decode_flags_v2(enc_header["flags"])
        header["enc_header"] = enc_header
        header["flags"] = decode_flags_v2(header["flags"])
        if header["enc_header"]['AlgID'] == "RC4":
            raise ExtractionError("Error, cannot handle RC4")

        doc.read(4)   # "salt_len" unused, by spec must be 16
        header['salt'] = doc.read(16)
        header['verifier_data'] = doc.read(16)
        header['verifier_len'] = struct.unpack("I", doc.read(4))[0]
        header['verifier_hash'] = doc.read(32)
    except:
        raise ExtractionError("Error, could not parse file, probably corrupt.")

    return header


def parse_enc_info_v3(doc, header):
    raise ExtractionError("Unsupported encryption method used")


def parse_enc_info_v4(doc, header):
    """Structures laid out in MS-OFFCRYPTO 2.3.4.10"""
    # noinspection PyBroadException
    try:
        tree = etree.parse(doc)
    except:
        raise ExtractionError("Invalid encryption definition")

    for x in tree.getroot().iter():
        for suffix in ["keyData", "dataIntegrity", "encryptedKey"]:
            if x.tag.endswith(suffix):
                header[suffix] = dict(x.attrib)

    try:
        header['keyData']['saltValue'] = binascii.a2b_base64(header['keyData']['saltValue'])
        header["dataIntegrity"]["encryptedHmacValue"] = binascii.a2b_base64(header["dataIntegrity"]["encryptedHmacValue"])
        header["dataIntegrity"]["encryptedHmacKey"] = binascii.a2b_base64(header["dataIntegrity"]["encryptedHmacKey"])
        header["encryptedKey"]["encryptedVerifierHashInput"] = binascii.a2b_base64(
            header["encryptedKey"]["encryptedVerifierHashInput"])
        header["encryptedKey"]["saltValue"] = binascii.a2b_base64(header["encryptedKey"]["saltValue"])
        header["encryptedKey"]["encryptedVerifierHashValue"] = binascii.a2b_base64(
            header["encryptedKey"]["encryptedVerifierHashValue"])
        header["encryptedKey"]["encryptedKeyValue"] = binascii.a2b_base64(
            header["encryptedKey"]["encryptedKeyValue"])
    except KeyError:
        raise ExtractionError("Unsupported encryption method used")
    return header


def parse_enc_info(doc):
    header = {}

    fixed = struct.unpack("HHI", doc.read(8))
    header["ver_maj"] = fixed[0]
    header["ver_min"] = fixed[1]
    header["flags"] = fixed[2]
    if header["ver_maj"] == 4 and header["ver_min"] == 4 and header["flags"] == 0x40:
        return parse_enc_info_v4(doc, header)
    elif (header["ver_maj"] == 2 or header["ver_maj"] == 3 or header["ver_maj"] == 4) and header["ver_min"] == 3:
        return parse_enc_info_v3(doc, header)
    elif (header["ver_maj"] == 2 or header["ver_maj"] == 3 or header["ver_maj"] == 4) and header["ver_min"] == 2:
        return parse_enc_info_v2(doc, header)
    else:
        raise ExtractionError("Unsupported version %i:%i" % (header["ver_maj"], header["ver_min"]))


def extract_docx(filename, password_list, output_folder):
    """
    Exceptions:
     - ValueError: Document is an unsupported format.
     - PasswordError: Document is a supported format, but the password is unknown.
     - ExtractionError: Document is encrypted but not in a supported format.

    :param filename: Name of the potential docx file
    :param password_list: a list of password strings, ascii or unicode
    :param output_folder: a path to a directory where we can write to
    :return: The filename we wrote. Else, an exception is thrown.
    """
    if not olefile.isOleFile(filename):
        raise ValueError("Not OLE")

    try:
        of = olefile.OleFileIO(filename)
    except IOError:
        raise ValueError("Corrupted OLE Document")

    if of.exists("WordDocument"):
        # Cannot parse these files yet
        raise ValueError("Legacy Word Document")

    elif of.exists("EncryptionInfo") and of.exists("EncryptedPackage"):
        metadata = parse_enc_info(of.openstream("EncryptionInfo"))

        password = None
        for pass_try in password_list:
            if check_password(pass_try, metadata) is True:
                password = pass_try
                break

        if password is None:
            raise PasswordError("Could not find correct password")

        tf = tempfile.NamedTemporaryFile(dir=output_folder, suffix=".docx", delete=False)
        decode_stream(password, metadata, of.openstream("EncryptedPackage"), tf)
        name = tf.name
        tf.close()
        return name, password
    else:
        raise ValueError("Not encrypted")

if __name__ == "__main__":
    import sys
    # Usage: file.docx password
    print extract_docx(sys.argv[1], [sys.argv[2]], ".")
