#!/usr/local/bin/python

# crack.py : Simple password cracker
# Nowhere near as powerful as Alex Muffett's Crack, but at least it's short.
# If no arguments are given on the command line, /etc/passwd will be read;
# if one argument is given, that file (which is assumed to be a copy
# of some /etc/passwd file) will be read.
#
# The file './wordlist' is then read completely into memory, and the
# words in it are then tried as possible passwords.  
#
# Uses Ultra-fast crypt(), if available; otherwise, uses plain
# crypt() from the C library.

try:
    from ufcrypt import *
except ImportError:
    import crypt
    
import pwd, string, sys

if len(sys.argv)>1:
    f=open(sys.argv[1], 'r')		# Read an arbitrary file
    L=[]
    while (1):
	line=f.readline()
	if line=='': break
	list=string.splitfields(line, ':')[0:2]
	list=map(lambda w: string.strip(w), list)
	L.append(tuple(list))
    L=filter(lambda x: len(x)==2, L)
    f.close()
else:
    L=pwd.getpwall()		# List all entries in /etc/passwd

f=open('./wordlist', 'r')		# Read list of words to try
wordlist=f.readlines()
f.close()
wordlist=map(lambda w: string.strip(w), wordlist)# Remove newlines

for line in L:				# Loop through all the entries
    login, password=line[0], line[1]
    if ',' in password:                 # Remove aging info, if present
	index=string.find(password, ',')
	password=password[:index]
    if password=='': print 'Has no password' ; continue
    print string.ljust(login, 10), ':',
    if '*' in password: print "Can't login as this ID" ; continue
    sys.stdout.flush()
    salt, Found = password[0:2], 0
    for word in wordlist:		# Try every word in the list
	if crypt(word, salt)==password:
	    print 'Password: [%s]' % word ; Found=1; break
    if not Found: print 'Not found'

    
