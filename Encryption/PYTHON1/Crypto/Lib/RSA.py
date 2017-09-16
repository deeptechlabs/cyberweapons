
#
#   RSA.py : RSA encryption/decryption
# 
#  Part of the Python Cryptography Toolkit, version 1.0.0
# 
#  Copyright (C) 1995, A.M. Kuchling
# 
# Distribute and use freely; there are no restrictions on further 
# dissemination and usage except those imposed by the laws of your 
# country of residence.
# 

import pubkey

error = 'RSA module'
keydata=['d', 'e', 'n']

# Generate an RSA key with N bits
def generate(N, randfunc, verbose=None):
    obj=RSAobj()
    # Generate random number from 0 to 8
    difference=ord(randfunc(1)) & 8
    # Generate the prime factors of n
    if verbose: apply(verbose, ('p\n',))
    obj.p=pubkey.Prime(N/2, randfunc)
    if verbose: apply(verbose, ('q\n',))
    obj.q=pubkey.Prime((N/2)+difference, randfunc)
    obj.n=obj.p*obj.q
    # Generate encryption exponent
    if verbose: apply(verbose, ('e\n',))
    obj.e=pubkey.Prime(17, randfunc)
    if verbose: apply(verbose, ('d\n',))
    obj.d=pubkey.Inverse(obj.e, (obj.p-1)*(obj.q-1))
    return obj

# Construct an RSA object
def construct(tuple):
    obj=RSAobj()
    if len(tuple) not in [2,3,5]:
        raise error, 'argument for construct() wrong length' 
    if len(tuple) in [2,3,5]:
        obj.n=tuple[0]
        obj.e=tuple[1]
    if len(tuple) in [3,5] :
        obj.d=tuple[2]
    if len(tuple)==5:
        obj.p=tuple[4]
        obj.q=tuple[5]
    return obj

class RSAobj(pubkey.pubkey):
    def _encrypt(self, plaintext, K=''):
    	if self.n<=plaintext:
	    raise error, 'Plaintext too large'
	return (pow(plaintext, self.e, self.n),)
    def _decrypt(self, ciphertext):
	if (not hasattr(self, 'd')):
	    raise error, 'Private key not available in this object'
	if self.n<=ciphertext[0]:
	    raise error, 'Ciphertext too large'
	return pow(ciphertext[0], self.d, self.n)
	
    def size(self):
        bits, power = 0,1L
	if (power<self.n): bits, power = bits+1, power<<1
	return bits-1
	
    def hasprivate(self):
	if hasattr(self, 'd'): return 1
	else: return 0

    def publickey(self):
        newobj=RSAobj()
	del newobj.d
    def _sign(self, M, K=''):
	return (self._decrypt((M,)),)
    def _validate(self, M, sig):
	m2=self._encrypt(sig[0])
	if m2[0]==M: return 1
	else: return 0

object = RSAobj


