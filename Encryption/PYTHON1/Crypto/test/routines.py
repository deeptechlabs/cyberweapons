def die(string):
    import sys
    print '***ERROR: ', string
#    sys.exit(0)   # Will default to continuing onward...

def Hex2Str(str):
    s=''
    for i in range(0,len(str),2):
	s=s+chr(eval('0x'+str[i:i+2]))
    return s
    
def TestBlockCipher(cipher, prefix = ''):
    import string, time
    lower=string.lower(cipher)
    try:
        exec('import '+lower)
    except ImportError:
        print cipher, 'module not available'
        return None
    print cipher+ ':'
    exec('ciph = '+lower)
    str='1'				# Build 128K of test data
    for i in xrange(0, 17):
        str=str+str
    if ciph.keysize==0: ciph.keysize=16
    password = prefix+'password12345678Extra text for password'[0:ciph.keysize]
    IV = 'Test IV Test IV Test IV Test'[0:ciph.blocksize]

    print '  Testing ECB mode with key '+ `password`
    obj=ciph.new(password, ciph.ECB)
    print '    Sanity check'
    text='1234567812345678'[0:ciph.blocksize]
    c=obj.encrypt(text)
    if (obj.decrypt(c)!=text): die('Error encrypting "'+text+'"')
    text='KuchlingKuchling'[0:ciph.blocksize]
    c=obj.encrypt(text)
    if (obj.decrypt(c)!=text): die('Error encrypting "'+text+'"')
    text='NotTodayNotEver!'[0:ciph.blocksize]
    c=obj.encrypt(text)
    if (obj.decrypt(c)!=text): die('Error encrypting "'+text+'"')

    start=time.time()
    s=obj.encrypt(str)
    s2=obj.decrypt(s)
    end=time.time()
    if (str!=s2):
	die('Error in resulting plaintext from ECB mode')
    print '    Benchmark for 256K: ', 256/(end-start), 'K/sec'
    del obj
    
    print '  Testing CFB mode with key ' + `password`+ ' IV "Test IV@"'
    obj1=ciph.new(password, ciph.CFB, IV)
    obj2=ciph.new(password, ciph.CFB, IV)
    start=time.time()
    ciphertext=obj1.encrypt(str[0:65536])
    plaintext=obj2.decrypt(ciphertext)
    end=time.time()
    if (plaintext!=str[0:65536]):
	die('Error in resulting plaintext from CFB mode')
    print '    Benchmark for  64K: ', 64/(end-start), 'K/sec'
    del obj1, obj2
    
    print '  Testing CBC mode with key ' + `password`+ ' IV "Test IV@"'
    obj1=ciph.new(password, ciph.CBC, IV)
    obj2=ciph.new(password, ciph.CBC, IV)
    start=time.time()
    ciphertext=obj1.encrypt(str)
    plaintext=obj2.decrypt(ciphertext)
    end=time.time()
    if (plaintext!=str):
	die('Error in resulting plaintext from CBC mode')
    print '    Benchmark for 256K: ', 256/(end-start), 'K/sec'
    del obj1, obj2

    print '  Testing PGP mode with key ' + `password`+ ' IV "Test IV@"'
    obj1=ciph.new(password, ciph.PGP, IV)
    obj2=ciph.new(password, ciph.PGP, IV)
    start=time.time()
    ciphertext=obj1.encrypt(str)
    plaintext=obj2.decrypt(ciphertext)
    end=time.time()
    if (plaintext!=str):
	die('Error in resulting plaintext from PGP mode')
    print '    Benchmark for 256K: ', 256/(end-start), 'K/sec'
    del obj1, obj2
    return ciph

    # Test the IV handling
    obj1=ciph.new(password, ciph.CBC, IV)
    plaintext='Test'*(ciph.blocksize/4)*3
    ciphertext1=obj1.encrypt(plaintext)
    obj1.IV=IV
    ciphertext2=obj1.encrypt(plaintext)
    if ciphertext1!=ciphertext2:
        die('Error in setting IV')
    
def TestStreamCipher(cipher):
    import string, time
    lower=string.lower(cipher)
    try:
        exec('import '+lower)
    except ImportError:
        print cipher, 'module not available'
        return None
    print cipher + ':'
    exec('ciph = '+lower)
    str='1'				# Build 128K of test data
    for i in xrange(0, 17):
        str=str+str
    if ciph.keysize==0: ciph.keysize=16
    password = 'password12345678Extra text for password'[0:ciph.keysize]
    
    obj1=ciph.new(password)
    obj2=ciph.new(password)
    print '  Sanity check'
    text='1234567812345678Python'
    c=obj1.encrypt(text)
    if (obj2.decrypt(c)!=text): die('Error encrypting "'+text+'"')
    text='B1FF I2 A R3A11Y |<00L D00D!!!!!'
    c=obj1.encrypt(text)
    if (obj2.decrypt(c)!=text): die('Error encrypting "'+text+'"')
    text='SpamSpamSpamSpamSpamSpamSpamSpamSpam'
    c=obj1.encrypt(text)
    if (obj2.decrypt(c)!=text): die('Error encrypting "'+text+'"')

    start=time.time()
    s=obj1.encrypt(str)
    str=obj2.decrypt(s)
    end=time.time()
    print '    Benchmark for 256K: ', 256/(end-start), 'K/sec'
    del obj1, obj2
    return ciph
    
def HashCompare(hash, strg, result):
    obj=hash.new(strg)
    s=obj.digest()
    s1=s
    temp=0L
    while (s!=''):
	temp=temp*256+ord(s[0])
	s=s[1:]
    if (result!=temp):
	die(`hash`+' produces incorrect result on string "'+strg+'"')
    s2=obj.digest()
    if s2!=s1: die(`hash`+' produces incorrect result on second hashing')
    s3=obj.copy().digest()
    if s3!=s1: die(`hash`+' produces incorrect result after copying')

    del temp, s

