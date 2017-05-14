#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# basicRAT GCM testing
# https://github.com/vesche/basicRAT
#

import os
import socket
import random

from binascii import hexlify
from core.aes_gcm import *
from Crypto.Util.number import long_to_bytes, bytes_to_long


def hamming(a,b):
	return sum((a[k] != b[k]) for k in range(min(len(a), len(b))))


def main():
	key = os.urandom(32)
	encryptor = AES_GCM(key)
	decryptor = AES_GCM(key)

	host = ('localhost', 5555)
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	server.bind(host)
	server.listen(5)

	client.connect(host)
	conn, addr = server.accept()

	IV = 0
	for i in range(10):
		try:
			plain = os.urandom(1024*1024*10) # 10MB
			while plain:
				cipher, tag = encryptor.encrypt(IV, plain[:4096])
				conn.send(cipher+long_to_bytes(tag, 16))

				x = client.recv(4096+16)
				cipher2 = x[:-16]
				tag2 = bytes_to_long(x[-16:])
				plain2 = decryptor.decrypt(IV, cipher2, tag2)
				assert plain[:4096] == plain2
				plain = plain[4096:]
				IV += 1
			print '10MB done!'
		except AssertionError:
			if len(plain) != len(plain2):
				print 'lengths dont match!\nOrig:{}\nNew:{}'.format(len(plain), len(plain2))

			print '{} out of {} are incorrect!'.format(hamming(plain, plain2), len(plain2))

	print 'Done!'


if __name__ == '__main__':
	main()
