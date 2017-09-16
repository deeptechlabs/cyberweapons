#!/usr/local/bin/python
#
#  randpool.py : Cryptographically strong random number generation
#
# Part of the Python Cryptography Toolkit, version 1.0.0
#
# Copyright (C) 1995, A.M. Kuchling
#
# Distribute and use freely; there are no restrictions on further 
# dissemination and usage except those imposed by the laws of your 
# country of residence.
#
  

"""randpool.py : Cryptographically strong random number generation.

The implementation here is similar to the one in PGP.  To be
cryptographically strong, it must be difficult to determine the RNG's
output, whether in the future or the past.  This is done by using
encryption algorithms to "stir" the random data.

Entropy is gathered in the same fashion as PGP; the highest-resolution
clock around is read and the data is added to the random number pool.
A conservative estimate of the entropy is then kept.

For an example that maintains a persistent random number pool, see
RSAgen.py in the Demo/crypto directory."""

from PCTpubkey import *
import time

class randpool:
    def __init__(self, numbytes = 128, cipher='idea', hash='md5'):
        exec('import '+cipher)
        exec( 'ciphmod='+cipher)
        self.entropy, self._addPos = 0,0
        self._event1, self._event2 = 0,0
        self._addPos, self._getPos = 0,ciphmod.keysize
        self.bytes, self.cipher, self.hash=numbytes, cipher, hash
        self.bits=self.bytes*8
        self._randpool = '\000' * self.bytes
	# Linux supports a /dev/random device; soon other OSes will, too.
	# We'll grab some randomness from it.
	try:
	    f=open('/dev/prandom')
	    data=f.read(self.bytes)
	    f.close()
	    self.addBytes(data)
	    # Conservative entropy estimate: The number of bits of
	    # data obtained from /dev/prandom, divided by 4.
	    self.entropy=self.entropy+len(data)*2
	except IOError, (num, msg):
	    if num!=2: raise IOError, (num, msg)
	    # If the file wasn't found, ignore the error
    def stir(self):
        exec('import '+self.cipher)
        exec( 'cipher='+self.cipher)
        exec('import '+self.hash)
        exec( 'hash='+self.hash)
        entropy=self.entropy
        import time
        self.addEvent(time.time())
        h=hash.new(self._randpool)
        for i in [ 4, 8,12]:
            h.update(self._randpool+self._randpool[0:i])
            c=cipher.new(h.digest(), cipher.CBC, self._randpool[-cipher.blocksize:])
            self._randpool=c.encrypt(self._randpool)
            self._randpool=c.encrypt(self._randpool)
            self._randpool=c.encrypt(self._randpool)
        self._addPos, self._getPos = 0, cipher.keysize
        self.addEvent(time.time())
        # Paranoia is a Good Thing in cryptographic applications.
        # While the call to addEvent() may be adding entropy to the
        # pool, we won't take that into account.    
        self.entropy=entropy
    def getBytes(self, num):
        s=''
        i, pool = self._getPos, self._randpool
        for j in range(0, num):
            s=s+self._randpool[i]
            i=(i+1) % self.bytes
            if (i==0):
                self.stir()
                i=self._getPos
        self._getPos = i
        self.entropy=self.entropy-8*num
        if self.entropy<0: self.entropy=0
        return s

    def addEvent(self, event, s=''):
        event=long(event*1000)
        delta=self._noise()
        s=s+Int2Str(event)+4*chr(0xaa)+Int2Str(long(delta))
        self._addBytes(s)
        if event==self._event1 and event==self._event2:
            bits=0
        else:
            bits=0
            while (delta): delta, bits = delta>>1, bits+1
            if (bits>8): bits=8
        self._event1, self._event2 = event, self._event1
        self.entropy=self.entropy+bits
        if self.entropy>self.bytes*8:
            self.entropy=self.bytes*8
        return self.entropy

    # Private functions
    def _noise(self):
        if not self.__dict__.has_key('_lastcounter'):
            self._lastcounter=time.time()
        if not self.__dict__.has_key('_ticksize'):
            self._noiseTickSize()
        t=time.time()
        delta = (t - self._lastcounter)/self._ticksize*1e6
        self._lastcounter = t
        self._addBytes(Int2Str(long(1000*time.time())))
        self._addBytes(Int2Str(long(1000*time.clock())))
        self._addBytes(Int2Str(long(1000*time.time())))
        self._addBytes(Int2Str(long(delta)))
	delta=delta % 0x1000000		# Reduce delta so it fits into an int
        return int(delta)

    def _noiseTickSize(self):
        interval=[]
        t=time.time()
        for i in range(0,100):
            t2=time.time()
            delta=int((t2-t)*1e6)
            t=t2
            interval.append(delta)
        interval.sort()
        self._ticksize=interval[len(interval)/2]
    def _addBytes(self, s):
        i, pool = self._addPos, self._randpool
        for j in range(0, len(s)):
            pool=pool[0:i] + chr(ord(pool[i]) ^ ord(s[j])) + pool[i+1:]
            i=(i+1) % self.bytes
        self._addPos, self._randpool = i, pool
