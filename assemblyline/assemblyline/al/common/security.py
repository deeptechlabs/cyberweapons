import base64
import hashlib
import hmac
import os
import re
import struct
import time

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto import Random
from passlib.hash import bcrypt

MIN_LEN = 8
UPPERCASE = r'[A-Z]'
LOWERCASE = r'[a-z]'
MIXCASE = r'[a-zA-Z]'
NUMBER = r'[0-9]'
SPECIAL = r'[ !#$@%&\'()*+,-./[\\\]^_`{|}~"]'


def generate_async_keys(key_size=2048):
    random_generator = Random.new().read
    key = RSA.generate(key_size, random_generator)
    return key.publickey().exportKey(), key.exportKey()


def load_async_key(key_def, use_pkcs=False):
    key = RSA.importKey(key_def)

    if use_pkcs:
        Random.atfork()
        return PKCS1_v1_5.new(key)

    return key


def get_hotp_token(secret, intervals_no):
    key = base64.b32decode(secret, True)
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = ord(h[19]) & 15
    h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    return h


def get_totp_token(secret):
    return get_hotp_token(secret, intervals_no=int(time.time())//30)


def generate_random_secret():
    return base64.b32encode(os.urandom(25))


def get_password_hash(password):
    if password is None or len(password) == 0:
        return None

    return bcrypt.encrypt(password)


def verify_password(password, pw_hash):
    try:
        return bcrypt.verify(password, pw_hash)
    except ValueError:
        return False
    except TypeError:
        return False


def check_password_requirements(password, strict=True):
    check_upper = re.compile(UPPERCASE)
    check_lower = re.compile(LOWERCASE)
    check_mixed = re.compile(MIXCASE)
    check_number = re.compile(NUMBER)
    check_special = re.compile(SPECIAL)

    if get_password_hash(password) is None:
        return True

    if len(password) < MIN_LEN:
        return False

    if strict and len(check_upper.findall(password)) == 0:
        return False

    if strict and len(check_lower.findall(password)) == 0:
        return False

    if not strict and len(check_mixed.findall(password)) == 0:
        return False

    if len(check_number.findall(password)) == 0:
        return False

    if strict and len(check_special.findall(password)) == 0:
        return False

    return True

if __name__ == "__main__":
    print check_password_requirements("hello123")
    print check_password_requirements("Hello123", strict=False)
    print check_password_requirements("helloworld1", strict=False)
    print check_password_requirements("hello123!")
    print check_password_requirements("Hello12!")
    print generate_random_secret()
    pub, priv = generate_async_keys()
    print pub
    print priv
