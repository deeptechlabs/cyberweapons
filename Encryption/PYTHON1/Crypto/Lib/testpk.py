#!/usr/local/bin/python

import sys
import randpool

class randfile(randpool.randpool):
    def __init__(self, filename='', numbytes = 384, cipher='idea', hash='md5'):
        self.filename=filename
        try:
            import pickle
            f=open(filename, 'r')
            temp=pickle.load(f)
            for key in temp.__dict__.keys():
                self.__dict__[key]=temp.__dict__[key]
            f.close()
        except IOError:
            randpool.randpool.__init__(self, numbytes, cipher, hash)
        self.stir()     # Wash the random pool
        self.stir()
        self.stir()
    def Save(self):
        import pickle
        self.stir()     # Wash the random pool
        self.stir()
        self.stir()
        f=open(self.filename, 'w')
        pickle.dump(self, f)
        f.close()        
    def Randomize(self):
        import os, string, termios, TERMIOS, time
        bits=self.bits-self.entropy
        if bits==0: return              # No entropy required, so we exit.
        print bits,'bits of entropy are now required.  Please type on the keyboard'
        print 'until enough randomness has been accumulated.'
        fd=0
        old=termios.tcgetattr(fd)
        new=termios.tcgetattr(fd)
        new[3]=new[3] & ~TERMIOS.ICANON & ~TERMIOS.ECHO
        termios.tcsetattr(fd, TERMIOS.TCSANOW, new)
        s=''    # We'll save the characters typed and add them to the pool.
        exec('import '+self.hash)
        exec( 'hash='+self.hash)
        try:
            while (self.entropy<self.bits):
                temp=string.rjust(str(self.bits-self.entropy), 6)
                os.write(1, temp)
#                termios.tcflush(0, TERMIOS.TCIFLUSH) # XXX Leave this in?
                s=s+os.read(0, 1)
                self.addEvent(time.time())
                os.write(1, 6*chr(8))
            self.addEvent(time.time(), s+hash.new(s).digest() )
        finally:
            termios.tcsetattr(fd, TERMIOS.TCSAFLUSH, old)
        print '\n\007 Enough.\n'
        time.sleep(3)
        termios.tcflush(0, TERMIOS.TCIFLUSH)

# Entropy is a precious resource.  Unfortunately, primality testing
# requires lots of random numbers.  It's wasteful to consume real
# entropy for this purpose, since generating a 50-bit key would then
# require thousands of bits of entropy.  Instead, we request more
# randomness than we need, and then stir the random data with an
# encryption function.  We don't care whether or not successive values
# are correlated or not, as long as the end product depended on so
# many bits of entropy.

class smallrand:
    def __init__(self, randfunc, ciphername, N):
        exec('import '+ ciphername)
        exec('cipher='+ciphername)
        length=(N/cipher.blocksize+1)*cipher.blocksize
        self.pool=randfunc(length)
        key=randfunc(cipher.keysize)
        self.ciph=cipher.new(key, cipher.CBC, randfunc(cipher.blocksize))
    def getBytes(self, N):
        s=''
        self.pool=self.ciph.encrypt(self.pool)
        while len(s)<N:
            s=s+self.pool
            self.pool=self.ciph.encrypt(self.pool)
        self.pool=self.ciph.encrypt(self.pool)
        return s[0:N]

import pubkey
def testpubkey(randfunc, module):
    global key
    N=512				# Key size, measured in bits

    print ' Generating', N, 'bit key'
    import sys
    key=module.generate(N, randfunc, sys.stdout.write)

    print ' Key data:', key.__dict__
    plaintext="Hello"

    if key.canencrypt():
	print ' Encryption/decryption test'
	K=pubkey.Prime(10, randfunc)
	ciphertext=key.encrypt(plaintext, K)
	if key.decrypt(ciphertext)!=plaintext:
	    print 'Mismatch decrypting plaintext'

    if key.cansign():
	print ' Signature test'
	K=pubkey.Prime(30, randfunc)
	signature=key.sign(plaintext, K)
	result=key.validate(plaintext, signature)
	if not result:
	    print " Sig. verification failed when it should have succeeded"
	result=key.validate(plaintext[:-1], signature)
	if result:
	    print " Sig. verification succeeded when it should have failed"
	plaintext=plaintext[:-3]+chr( 1 ^ ord(plaintext[-3]) )+plaintext[-3:]
	result=key.validate(plaintext, signature)
	if result:
	    print " Sig. verification succeeded when it should have failed"
	
# Set up a random pool; we won't bother to actually fill it
print ' Initializing random pool'
r=randfile('randseed', 384)
r.stir()
randfunc=r.getBytes

##print 'Testing ESIGN.py'
##import ESIGN
##testpubkey(randfunc, ESIGN)
##r.stir()
##
print 'Testing RSA.py'
import RSA
testpubkey(randfunc, RSA)
r.stir()

print 'Testing DSA.py'
import DSA
testpubkey(randfunc, DSA)
r.stir()

print 'Testing ElGamal.py'
import ElGamal
testpubkey(randfunc, ElGamal)
r.stir()


