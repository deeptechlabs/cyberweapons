#!/usr/local/bin/python

# Using the public key defined in testkey.py, sign all *.pyc files in
# the listed directories.

from testkey import *
import md5, os, glob, sys
import marshal

dir = ''
if (len(sys.argv)>1): dir=os.path.join(sys.argv[1], '/')
filelist=glob.glob(dir + '*.pyc')
for file in filelist:
    input=open(file, 'rb')
    try:
	os.unlink(file[:-4]+'.pys')	# Delete any existing signed file
    except os.error, tuple:
	if (tuple[0]==2): pass		# Ignore 'file not found' error
	else: raise os.error, tuple
    output=open(file[:-4]+'.pys', 'wb')
    data=input.read()
    hash=md5.new(data).digest()		# Compute hash of the code object
    signature=key.sign(hash, '')	# Sign the hash
    marshal.dump(signature, output)     # Save signature to the file
    output.write(data)			# Copy code object to signed file
    input.close()
    output.close()
    print os.path.basename(file)+ ' processed.'



