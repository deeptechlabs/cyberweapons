#
#   ESIGN.py  -- XXX doesn't work yet!
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

error = 'ESIGN module'
keydata=['n', 'p', 'q']
SecurityParam=8				# This can be varied

# Generate an ESIGN key at least N bits long
def generate(N, randfunc, verbose=None):
    obj=ESIGNobj()
    if verbose: apply(verbose, ('p\n',))
    obj.p=Prime(N/3+1, randfunc)
    if verbose: apply(verbose, ('q\n',))
    obj.q=Prime(N/3+1, randfunc)
    obj.n=obj.p*obj.p*obj.q
    return obj
    
def construct(tuple):
    obj=ESIGNobj()
    if len(tuple) not in [1,3]:
        raise error, 'argument for construct() wrong length' 
    if len(tuple) in [1,3]:
        obj.n=tuple[0]
    if len(tuple)==3:
        obj.p=tuple[1]
        obj.q=tuple[2]
    return obj
    
class ESIGNobj(pubkey):
    def _encrypt(self, M, K):
        raise error, 'Algorithm cannot en/decrypt data'
    def _decrypt(self, M):
        raise error, 'Algorithm cannot en/decrypt data'
        
    def size(self):
        bits, power = 0,1L
	while (power<self.n): bits, power = bits+1, power<<1 
	return bits-1
	
    def hasprivate(self):
	if hasattr(self, 'p') and hasattr(self, 'q'): return 1
	else: return 0

    def canencrypt(self):
	return 0
	
    def publickey(self):
        newobj=ESIGNobj()
	del newobj.p, newobj.q

    def _sign(self, M, K):
	if self.p*self.q<=K:
	    raise error, 'K > pq'
	u=pow(K, SecurityParam, self.n)
	v=SecurityParam*pow(K, SecurityParam-1, self.p)
	v=Inverse(v % self.p, self.p)
	prod=self.p*self.q
	w=((M-u)%self.n) #* Inverse(self.p*self.q, self.n)
	if w % prod==0: w=w/prod
	else: w=w/prod+1
	print w
	s=K+((w*v) % self.p)*self.p*self.q
	return (s,)
	
    def _validate(self, M, sig):
        s=sig[0]
	v=pow(s, SecurityParam, self.n)
	a=self.size()/3+1
	print M, s, v, M+pow(2L, a)
	if M<=v<M+pow(2L, a): return 1
	else: return 0
object=ESIGNobj


