#
#   pubkey.py : Internal functions for public key operations
# 
#  Part of the Python Cryptography Toolkit, version 1.0.0
# 
#  Copyright (C) 1995, A.M. Kuchling
# 
# Distribute and use freely; there are no restrictions on further 
# dissemination and usage except those imposed by the laws of your 
# country of residence.
# 

try:
    import mpz
    bignum=long
#    bignum=mpz.mpz           # Temporarily disabled; the 'outrageous exponent'
                             # error messes things up.
except ImportError:
    bignum=long
    
def RandomNumber(N, randfunc):
    str=randfunc(N/8)
    char=ord(randfunc(1))>>(8-(N%8))
    return Str2Int(chr(char)+str)
    
def Int2Str(n):
    s=''
    while n>0:
        s=chr(n & 255)+s
        n=n>>8
    return s

def Str2Int(s):
    if type(s)!=types.StringType: return s   # Integers will be left alone
    return reduce(lambda x,y : x*256+ord(y), s, 0L)
    
def GCD(x,y):
    if x<0: x=-x
    if y<0: y=-y
    while x>0: x,y = y%x, x
    return y

def Inverse(u, v):
    u3, v3 = long(u), long(v)
    u1, v1 = 1L, 0L
    while v3>0:
	q=u3/v3
	u1, v1 = v1, u1-v1*q
	u3, v3 = v3, u3-v3*q
    while u1<0: u1=u1+v
    return u1
    
# Given a number of bits to generate and a random generation function,
# find a prime number of the appropriate size.

def Prime(N, randfunc):
    number=RandomNumber(N, randfunc) | 1
    while (not PrimeNumber(number)):
        number=number+2
    return number

def PrimeNumber(N):
    for i in sieve:
        if (N % i)==0: return 0
    N1=N - 1L ; n=1L
    while (n<N): n=n<<1L # Compute number of bits in N
    for j in sieve:
        a=long(j) ; d=1L ; t=n
        while (t):  # Iterate over the bits in N1
            x=(d*d) % N
            if x==1L and d!=1L and d!=N1: return 0  # Square root of 1 found
            if N1 & t: d=(x*a) % N
            else: d=x
            t=t>>1L
        if d!=1L: return 0
        return 1

# Simple sieving method, & Fermat test
##def PrimeNumber(N):
##    for i in sieve:
##        if (N % i)==0: return 0
##    N1=N-1
##    for i in sieve:
##        if pow(i, N1, N) != 1: return 0
##    return 1

sieve=[2,3,5,7,11,13,17,19,23,29,31,37,41]

# Basic public key class
import types
class pubkey:
    def __init__(self):
	pass

    def __getstate__(self): 
        """To keep key objects platform-independent, the key data is
        converted to standard Python long integers before being
        written out.  It will then be reconverted as necessary on
        restoration."""
        d=self.__dict__
        for key in keydata:
            if d.has_key(key): d[key]=long(d[key])
        return d

    def __setstate__(self, d): 
        """On unpickling a key object, the key data is converted to the big
number representation being used, whether that is Python long
integers, MPZ objects, or whatever."""
        for key in keydata:
            if d.has_key(key): self.__dict__[key]=bignum(d[key])

    def encrypt(self, plaintext, K):
	wasString=0
	if type(plaintext)==types.StringType:
	    plaintext=Str2Int(plaintext) ; wasString=1
	if type(K)==types.StringType:
	    K=Str2Int(K)
	ciphertext=self._encrypt(plaintext, K)
	if wasString: return tuple(map(Int2Str, ciphertext))
	else: return ciphertext
	
    def decrypt(self, ciphertext):
	wasString=0
	if types.StringType in map(type, ciphertext):
	    ciphertext=tuple(map(Str2Int, ciphertext)) ; wasString=1
	plaintext=self._decrypt(ciphertext)
	if wasString: return Int2Str(plaintext)
	else: return plaintext

    def sign(self, M, K):
	if (not self.hasprivate()):
	    raise error, 'Private key not available in this object'
	if type(M)==types.StringType: M=Str2Int(M)
	if type(K)==types.StringType: K=Str2Int(K)
	return self._sign(M, K)
    def validate(self, M, signature):
	if type(M)==types.StringType: M=Str2Int(M)
	return self._validate(M, signature)
	
    # The following methods will usually be left alone, except for
    # signature-only algorithms.  They both return Boolean values
    # recording whether this key can sign and encrypt; the result may,
    # if overridden, depend on the key.
    def cansign(self): return 1
    def canencrypt(self): return 1

    # The following methods will certainly be overridden by
    # subclasses.
    
    # size(): Return the max. number of bits that can be handled by this key
    def size(self): return 0
    # hasprivate(): Boolean denoting whether the object contains
    #               private components
    def hasprivate(self): return 0
    def publickey(self): return self
	
    
