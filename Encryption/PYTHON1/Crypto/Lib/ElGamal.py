
#
#   ElGamal.py : ElGamal encryption/decryption and signatures
# 
#  Part of the Python Cryptography Toolkit, version 1.0.0
# 
#  Copyright (C) 1995, A.M. Kuchling
# 
# Distribute and use freely; there are no restrictions on further 
# dissemination and usage except those imposed by the laws of your 
# country of residence.
# 

from pubkey import *

error = 'ElGamal module'
keydata=['y', 'x', 'g', 'p']

# Generate an ElGamal key with N bits
def generate(N, randfunc, verbose=None):
    obj=ElGamalobj()
    # Generate prime p
    if verbose: apply(verbose, ('p\n',))
    obj.p=bignum(Prime(N, randfunc))
    # Generate random number g
    if verbose: apply(verbose, ('g\n',))
    size=N-1-(ord(randfunc(1)) & 63) # g will be from 1--64 bits smaller than p
    if size<1: size=N-1
    while (1):
        obj.g=bignum(Prime(size, randfunc))
        if obj.g<obj.p: break
        size=(size+1) % N
        if size==0: size=4
    # Generate random number x
    if verbose: apply(verbose, ('x\n',))
    while (1):
        size=N-1-ord(randfunc(1)) # x will be from 1 to 256 bits smaller than p
        if size>2: break
    while (1):
        obj.x=bignum(Prime(size, randfunc))
        if obj.x<obj.p: break
        size=(size+1) % N
        if size==0: size=4
    if verbose: apply(verbose, ('y\n',))
    obj.y=pow(obj.g, obj.x, obj.p)
    return obj
    
def construct(tuple):
    obj=ElGamalobj()
    if len(tuple) not in [3,4]:
        raise error, 'argument for construct() wrong length' 
    if len(tuple) in [3,4]:
        obj.p=tuple[0]
        obj.g=tuple[1]
        obj.y=tuple[2]
    if len(tuple)==4:
        obj.x=tuple[3]
    return obj
    
class ElGamalobj(pubkey):
    def _encrypt(self, M, K):
        a=pow(self.g, K, self.p)
        b=( M*pow(self.y, K, self.p) ) % self.p
	return ( a,b )
    def _decrypt(self, M):
	if (not hasattr(self, 'x')):
	    raise error, 'Private key not available in this object'
        ax=pow(M[0], self.x, self.p)
        plaintext=(M[1] * Inverse(ax, self.p ) ) % self.p
	return plaintext
        
    def size(self):
        bits, power = 0,1L
	while (power<self.p): bits, power = bits+1, power<<1
	return bits-1
	
    def hasprivate(self):
	if hasattr(self, 'x'): return 1
	else: return 0

    def publickey(self):
        newobj=ElGamalobj()
	del newobj.d

    def _sign(self, M, K):
	if (not hasattr(self, 'x')):
	    raise error, 'Private key not available in this object'
        p1=self.p-1
        if (GCD(K, p1)!=1):
            raise error, 'Bad K value: GCD(K,p-1)!=1'
        a=pow(self.g, K, self.p)
        t=(M-self.x*a) % p1
        while t<0: t=t+p1
        b=(t*Inverse(K, p1)) % p1
        return (a, b)
    def _validate(self, M, sig):
        v1=pow(self.y, sig[0], self.p)
        v1=(v1*pow(sig[0], sig[1], self.p)) % self.p
        v2=pow(self.g, M, self.p)
        if v1==v2: return 1
        return 0
        
object=ElGamalobj
