
#
#   DSA.py : Digital Signature Algorithm
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
import sha

error = 'DSA module'
keydata=['y', 'x', 'g', 'p', 'q']

def generateQ(L, randfunc):
    S=randfunc(20)
    hash1=sha.new(S).digest()
    hash2=sha.new(Int2Str(Str2Int(S)+1)).digest()
    q = bignum(0)
    for i in range(0,20):
        c=ord(hash1[i])^ord(hash2[i])
        if i==0: c=c | 128
        if i==19: c= c | 1
        q=q*256+c
    while (not PrimeNumber(q)):
        q=q+2
    if pow(2,159L)<q<pow(2,160L): return S, q
    raise error, 'Bad q value generated'
    
# Generate a DSA modulus with L bits
def generate(L, randfunc, verbose=None):
    if L<160: raise error, 'Key length <160 bits'
    obj=DSAobj()
    # Generate string S and prime q
    if verbose: apply(verbose, ('p, q\n',))
    while (1):
        S, obj.q = generateQ(L, randfunc)
        n=(L-1)/160
        C, N, V = 0, 2, {}
	b=(obj.q >> 5) & 15
	powb=pow(bignum(2), b)
	powL1=pow(bignum(2), L-1)
        while C<4096:
            for k in range(0, n+1):
		V[k]=Str2Int(sha.new(S+str(N)+str(k)).digest())
            W=V[n] % powb
            for k in range(n-1, -1, -1): W=(W<<160L)+V[k]
            X=W+powL1
            p=X-(X%(2*obj.q)-1)
            if powL1<=p and PrimeNumber(p): break
            C, N = C+1, N+n+1
        if C<4096: break
	if verbose: apply(verbose, ('4096 multiples failed\n',) )
    obj.p = p
    power=(p-1)/obj.q
    if verbose: apply(verbose, ('h,g\n',))
    while (1):
        h=Str2Int(randfunc(L)) % (p-1)
        g=pow(h, power, p)
        if 1<h<p-1 and g>1: break
    obj.g=g
    if verbose: apply(verbose, ('x,y\n',))
    while (1):
        x=Str2Int(randfunc(20))
        if 0<x<obj.q: break
    obj.x, obj.y=x, pow(g, x, p)
    return obj
    
def construct(tuple):
    obj=DSAobj()
    if len(tuple) not in [4,5]:
        raise error, 'argument for construct() wrong length' 
    if len(tuple) in [4,5]:
        obj.p=tuple[0]
        obj.q=tuple[1]
        obj.g=tuple[2]
        obj.y=tuple[3]
    if len(tuple)==5:
        obj.x=tuple[4]
    return obj
    
class DSAobj(pubkey):
    def _encrypt(self, s, Kstr):
        raise error, 'Algorithm cannot en/decrypt data'
    def _decrypt(self, s):
        raise error, 'Algorithm cannot en/decrypt data'
        
    def size(self):
        bits, power = 0,1L
	while (power<self.p): bits, power = bits+1, power<<1
	return bits-1
	
    def hasprivate(self):
	if hasattr(self, 'x'): return 1
	else: return 0

    def cansign(self):
	return 1
    def canencrypt(self):
	return 0
	
    def publickey(self):
        newobj=DSAobj()
	del newobj.x

    def _sign(self, M, K):
	if (self.q<=K):
	    raise error, 'K is greater than q'
        r=pow(self.g, K, self.p) % self.q
        s=(Inverse(K, self.q)*(M+self.x*r)) % self.q
        return (r,s)
    def _validate(self, M, sig):
        r, s = sig
	if r<=0 or r>=self.q or s<=0 or s>=self.q: return 0
        w=Inverse(s, self.q)
        u1, u2 = (M*w) % self.q, (r*w) % self.q
        v1=pow(self.g, u1, self.p)
	v2=pow(self.y, u2, self.p)
	v=((v1*v2) % self.p)
	v=v % self.q
        if v==r: return 1
        return 0
        
object=DSAobj


