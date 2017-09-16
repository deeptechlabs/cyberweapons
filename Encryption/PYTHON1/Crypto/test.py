#
# Test script for the Python Cryptography package.
#

import sys
sys.path=['./src']+sys.path
sys.path.append('./test')
from routines import *

print 'Hash Functions:'
print '==============='
teststr='1'				# Build 128K of test data
for i in xrange(0, 17):
    teststr=teststr+teststr
import data

# Test/benchmark MD2 hash algorithm ; the test data is taken from
# RFC1319, "The MD2 Message-Digest Algorithm"
try:
    import md2
except ImportError:
    print 'MD2 module not available'
else:
    print 'MD2:'
    try:
	import data
    except ImportError:
	print '  Test suite data not available'
    else:
        print '  Verifying against test suite...'
        for text, hash in data.md2:
            HashCompare(md2, text, hash)
        print '  Completed'
        import time
        obj=md2.new()
        start=time.time()
        s=obj.update(teststr)
        end=time.time()
        print '  Benchmark for 128K: ', 128/(end-start), 'K/sec'
        del obj

# Test/benchmark MD4 hash algorithm ; the test data is taken from
# RFC1186B, "The MD4 Message-Digest Algorithm"
try:
    import md4
except ImportError:
    print 'MD4 module not available'
else:
    print 'MD4:'
    try:
	import data
    except ImportError:
	print '  Test suite data not available'
    else:
        print '  Verifying against test suite...'
        for text, hash in data.md4:
            HashCompare(md4, text, hash)
        print '  Completed'
        import time
        obj=md4.new()
        start=time.time()
        s=obj.update(teststr)
        end=time.time()
        print '  Benchmark for 128K: ', 128/(end-start), 'K/sec'
        del obj

# Test/benchmark MD5 hash algorithm ; the test data is taken from
# RFC1321, "The MD5 Message-Digest Algorithm"
try:
    import md5
except ImportError:
    print 'MD5 module not available'
else:
    print 'MD5:'
    try:
	import data
    except ImportError:
	print '  Test suite data not available'
    else:
        print '  Verifying against test suite...'
        for text, hash in data.md5:
            HashCompare(md5, text, hash)
        print '  Completed'
        import time
        obj=md5.new()
        start=time.time()
        s=obj.update(teststr)
        end=time.time()
        print '  Benchmark for 128K: ', 128/(end-start), 'K/sec'
        del obj

# Test/benchmark SHA hash algorithm
try:
    import sha
except ImportError:
    print 'SHA module not available'
else:
    print 'SHA:'
    print '  Verifying against test suite...'
    for text, hash in data.sha:
        HashCompare(sha, text, hash)
    # Compute value for 1 megabyte of a's...
    obj, astring=sha.new(), 1000*'a'
    for i in range(0,1000): obj.update(astring)
    result=obj.digest()
    if result!=Hex2Str('34AA973CD4C4DAA4F61EEB2BDBAD27316534016F'):
	die('sha produces incorrect result on 1E6*"a"')
    print '  Completed'
    obj=sha.new()
    start=time.time()
    s=obj.update(teststr)
    end=time.time()
    print '  Benchmark for 128K: ', 128/(end-start), 'K/sec'
    del obj, astring

# Test/benchmark HAVAL
try:
    import haval
except ImportError:
    print 'HAVAL module not available'
else:
    print 'HAVAL:'
    try:
	import data
	print '  Verifying against test suite...'
	for (passes, length, text, hash) in data.haval:
	    ID=str(passes)+'-pass, '+str(length)+'-bit HAVAL '
	    obj=haval.new('', passes, length)
	    obj.update(text)
	    s1=obj.digest()
	    if (s1!=Hex2Str(hash)):
		die(ID+'produces incorrect result on string "'+text+'"')
	    s2=obj.digest()
	    if s2!=s1: die(ID+'produces incorrect result on second hashing')
	    s3=obj.copy().digest()
	    if s3!=s1: die(ID+'produces incorrect result after copying')
	print '  Completed'
    except ImportError:
	print '  Test suite data not available'
    obj=haval.new()
    import time
    start=time.time()
    s=obj.update(teststr)
    end=time.time()
    print '  Benchmark for 128K: ', 128/(end-start), 'K/sec'
    del obj

print '\nStream Ciphers:'
print '==============='

# Test ARC4 stream cipher
arc4=TestStreamCipher('ARC4')
if (arc4!=None):
    try:
        import data
    except ImportError:
        print '  Test suite data not available'
    else:
        for entry in data.arc4:
            key,plain,cipher=entry
            key=Hex2Str(key)
            plain=Hex2Str(plain)
            cipher=Hex2Str(cipher)
            obj=arc4.new(key)
            ciphertext=obj.encrypt(plain)
	    if (ciphertext!=cipher):
		die('ARC4 failed on entry '+`entry`)
	print '  ARC4 test suite completed'

# Test Sapphire stream cipher
sapphire=TestStreamCipher('Sapphire')
if (sapphire!=None):
    try:
        import data
    except ImportError:
        print '  Test suite data not available'
    else:
        result=Hex2Str(data.sapphire)
        obj=sapphire.new('testSapphirekey')
        s=''
        for i in range(0,256):
            s=s+chr(i)
        s=obj.encrypt(s)
        if (s!=result):
            die('Sapphire fails verification test')
	print '  Sapphire test suite completed'

print '\nBlock Ciphers:'
print '=============='

ciph=TestBlockCipher('DES3')	        # Triple DES
if (ciph!=None):
    try:
	import data
    except ImportError:
	print '  Test suite data not available'
    else:
        print '  Verifying against test suite...'
	for entry in data.des3:
	    key,plain,cipher=entry
	    key=Hex2Str(key)
	    plain=Hex2Str(plain)
	    cipher=Hex2Str(cipher)
	    obj=ciph.new(key, ciph.ECB)
	    ciphertext=obj.encrypt(plain)
	    if (ciphertext!=cipher):
		die('DES3 failed on entry '+`entry`)
                for i in ciphertext: print hex(ord(i)),
                print
	print '  Completed'

ciph=TestBlockCipher('Blowfish')	# Bruce Schneier's Blowfish cipher
if (ciph!=None):
    try:
	import data
    except ImportError:
	print '  Test suite data not available'
    else:
        print '  Verifying against test suite...'
	for entry in data.blowfish:
	    key,plain,cipher=entry
	    key=Hex2Str(key)
	    plain=Hex2Str(plain)
	    cipher=Hex2Str(cipher)
	    obj=ciph.new(key, ciph.ECB)
	    ciphertext=obj.encrypt(plain)
	    if (ciphertext!=cipher):
		die('Blowfish failed on entry '+`entry`)
                for i in ciphertext: print hex(ord(i)),
                print
	print '  Completed'

ciph=TestBlockCipher('Diamond', chr(8))      # M.P. Johnson's Diamond
if (ciph!=None):
    try:
	import data
    except ImportError:
	print '  Test suite data not available'
    else:
        print '  Verifying against test suite...'
	for entry in data.diamond:
	    key,plain,cipher=entry
	    key=Hex2Str(key)
	    plain=Hex2Str(plain)
	    cipher=Hex2Str(cipher)
	    obj=ciph.new(key, ciph.ECB)
	    ciphertext=obj.encrypt(plain)
	    if (ciphertext!=cipher):
		die('Diamond failed on entry '+`entry`)
	print '  Completed'

ciph=TestBlockCipher('IDEA')            # IDEA block cipher
if (ciph!=None):
    try:
	import data
    except ImportError:
	print '  Test suite data not available'
    else:
        print '  Verifying against test suite...'
	for entry in data.idea:
	    key,plain,cipher=entry
	    key=Hex2Str(key)
	    plain=Hex2Str(plain)
	    cipher=Hex2Str(cipher)
	    obj=ciph.new(key, ciph.ECB)
	    ciphertext=obj.encrypt(plain)
	    if (ciphertext!=cipher):
		die('IDEA failed on entry '+`entry`)
	print '  Completed'

# Test/benchmark DES block cipher
des=TestBlockCipher('DES')
if (des!=None):
    # Various tests taken from the DES library packaged with Kerberos V4
    obj=des.new(Hex2Str('0123456789abcdef'), des.ECB)
    s=obj.encrypt('Now is t')
    if (s!=Hex2Str('3fa40e8a984d4815')):
	die('DES fails test 1')
    obj=des.new(Hex2Str('08192a3b4c5d6e7f'), des.ECB)
    s=obj.encrypt('\000\000\000\000\000\000\000\000')
    if (s!=Hex2Str('25ddac3e96176467')):
	die('DES fails test 2')
    obj=des.new(Hex2Str('0123456789abcdef'), des.CBC,
		Hex2Str('1234567890abcdef'))
    s=obj.encrypt("Now is the time for all ")
    if (s!=Hex2Str('e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6')):
	die('DES fails test 3')
    obj=des.new(Hex2Str('0123456789abcdef'), des.CBC,
		Hex2Str('fedcba9876543210'))
    s=obj.encrypt("7654321 Now is the time for \000\000\000\000")
    if (s!=Hex2Str("ccd173ffab2039f4acd8aefddfd8a1eb468e91157888ba681d269397f7fe62b4")):
	die('DES fails test 4')
    del obj,s

    try:
	import data
    except ImportError:
	print '  Test suite data not available'
    else:
        print '  Verifying against test suite...'
	for entry in data.des:
	    key,plain,cipher=entry
	    key=Hex2Str(key)
	    plain=Hex2Str(plain)
	    cipher=Hex2Str(cipher)
	    obj=des.new(key, des.ECB)
	    ciphertext=obj.encrypt(plain)
	    if (ciphertext!=cipher):
		die('DES failed on entry '+`entry`)
	print '  Completed'

# Ronald Rivest's RC5 algorithm
ciph=TestBlockCipher('RC5', chr(0x10)+chr(32)+chr(12)+chr(16))
if (ciph!=None):
    try:
	import data
    except ImportError:
	print '  Test suite data not available'
    else:
        print '  Verifying against test suite...'
	for entry in data.rc5:
	    key,plain,cipher=entry
	    key=Hex2Str(key)
	    plain=Hex2Str(plain)
	    cipher=Hex2Str(cipher)
	    obj=ciph.new(key, ciph.ECB)
	    ciphertext=obj.encrypt(plain)
	    if (ciphertext!=cipher):
		die('RC5 failed on entry '+`entry`)
                for i in ciphertext: print hex(ord(i)),
                print
	print '  Completed'

# Test Michael Wood's REDOC III cipher
TestBlockCipher('REDOC3')



print '\nMiscellaneous Modules'
print   '====================='
try:
    import crypt, ufcrypt
except ImportError:
    print "Can't compare crypt and ufcrypt"
else:
    print 'Crypt/UFcrypt'
    list = []
    saltchars = './abcdefghijklmnopqrstuvwxyz01234567890QWERTYUIOPASDFGHJKLZXCVBNM'
    N=3000
    for i in range(0,N/150):
        s1 = (i / len(saltchars)) % len(saltchars)
        s2 = i % len(saltchars)
        salt = saltchars[s1] +saltchars[s2]
        for j in range(0, 150):
            word = salt + 'AMK' + salt+saltchars[j % len(saltchars)]
            list.append( (word,salt) )

    print ' Testing for equality...'
    for (word, salt) in list:
        s1=crypt.crypt(word, salt)
        s2=ufcrypt.crypt(word, salt)
        if (s1!=s2):
            die('Error: crypt/ufcrypt mismatch for '+word+', '+salt)

    print ' Measuring overhead'
    start=time.time()
    for (word, salt) in list:
        pass
    overhead=time.time()-start

    print ' Timing crypt and ufcrypt'
    start=time.time()
    for (word, salt) in list:
        s1=crypt.crypt(word, salt)
    crypttime=time.time()-start-overhead
    start=time.time()
    for (word, salt) in list:
        s1=ufcrypt.crypt(word, salt)
    ufcrypttime=time.time()-start-overhead
    print ' crypt: ', N, 'encryptions in', crypttime, 'seconds (',
    print N/crypttime,'crypt/sec'
    print ' UFcrypt: ', N, 'encryptions in', ufcrypttime, 'seconds (',
    print N/ufcrypttime,'crypt/sec'
    print

