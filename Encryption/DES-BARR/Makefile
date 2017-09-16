#
# Change the CFLAGS and MANDIR and BINDIR to suit your machine.
#
# Type "make" to build and test.
# Type "make -n install" to see how to install the code
#
# use -DBSD for Berkley systems

#default C compiler
#CC=cc
CFLAGS=-O -DBSD
LDFLAGS=-O

#gnu C compiler
#CC=gcc
#CFLAGS=-O -Wall 

MANDIR=/usr/local/man/man1
BINDIR=/usr/local/bin

# no changes needed below this line

# atob and btoa are exact copies from the compress4.0 distribution
AUXSRC=atob.c btoa.1 btoa.c
AUXEXE=atob btoa

SRC=README Makefile	\
	cipher.h des.h desdefs.h \
	cipher.c descfb.c deskey.c desblock.c sboxp.c getkey.c \
	destest.c desvalid.c testcfb.c \
	cipher.1 cmail\
	testdata.des testin.cfb testout.cfb testin testout \
	$(AUXSRC)

all:		cipher test $(AUXEXE)

cipher:		cipher.o getkey.o deskey.o desblock.o sboxp.o descfb.o 
		$(CC) $(LDFLAGS) -o $@ $@.o getkey.o deskey.o \
		desblock.o sboxp.o descfb.o 

decipher:	cipher
		ln cipher decipher

desvalid:	desvalid.o desblock.o sboxp.o
		$(CC) $(LDFLAGS) -o $@ $@.o desblock.o sboxp.o

destest:	destest.o desblock.o
		$(CC) $(LDFLAGS) -o $@ $@.o desblock.o sboxp.o

testcfb:	testcfb.o descfb.o desblock.o sboxp.o
		$(CC) $(LDFLAGS) -o $@ $@.o descfb.o desblock.o sboxp.o

cipher.o:	cipher.h des.h

cipher.man:	cipher.1
		nroff -man <cipher.1 | col -b >cipher.man

atob:		atob.o
		$(CC) $(LDFLAGS) -o $@ $@.o

btoa:		btoa.o
		$(CC) $(LDFLAGS) -o $@ $@.o

despass:	despass.o desblock.o sboxp.o
		$(CC) $(LDFLAGS) -o $@ $@.o desblock.o sboxp.o

uxpass:		uxpass.o
		$(CC) $(LDFLAGS) -o $@ $@.o

despass.o:	cipher.h des.h
descfb.o:	des.h
deskey.o:	des.h
sboxp.o:	desdefs.h

desblock.o:	desblock.s
		$(CC) $(CFLAGS) -c desblock.s

desblock.s:	desblock.c desdefs.h
		$(CC) $(CFLAGS) -S desblock.c

time:		cipher
		time cipher -i00 -x00 <testin3 >x

gprof: 		time
		gprof -b cipher >gprof.out

test:		destest desvalid testdata.des cipher decipher testcfb testin.cfb
		@echo des subroutine Tests
		desvalid -v < testdata.des
		destest -v
		@echo desCFB subroutine Tests with varying block sizes
		testcfb -s 1 <testin.cfb >x; cmp x testout.cfb
		testcfb -s 2 <testin.cfb >x; cmp x testout.cfb
		testcfb -s 3 <testin.cfb >x; cmp x testout.cfb
		testcfb -s 4 <testin.cfb >x; cmp x testout.cfb
		testcfb -s 5 <testin.cfb >x; cmp x testout.cfb
		testcfb -s 9 <testin.cfb >x; cmp x testout.cfb
		testcfb -s 15 <testin.cfb >x; cmp x testout.cfb
		testcfb -s 17 <testin.cfb >x; cmp x testout.cfb
		@rm x
		@echo cipher program Tests -- single encipherment
		cipher -x0123456789abcdef -i1234567890abcdef <testin.cfb >x
		cmp testout.cfb x
		cipher -d -x0123456789abcdef -i1234567890abcdef <x >y
		cmp testin.cfb y
		cipher -k bigtestkey <testin >x; cmp testout x
		cipher -d -k bigtestkey <x >y; cmp testin y
		@echo Multiple encipherment
		decipher -k test <testin | cipher -k test >x; cmp x testin
		cipher -k "phartles and" -k "jaymes beer" <testin >x
		cipher -d -k "jaymes beer" -k "phartles and" <x >y
		cmp testin y
		decipher -ek "phartles and" <testin | cipher -k "jaymes beer" >z
		cmp x z
		@echo Mixed triple encryption
		cipher -ek k1 -dk k2 -ek k3 <testin >x
		cipher -dk k3 -ek k2 -dk k1 <x >y; cmp testin y
		decipher -k k3 <x | cipher -k k2 | decipher -k k1 >z
		cmp testin z
		@rm x y z
		@echo "Expect 16 weak key warnings:"
		@cipher -xe001e001f101f101 </dev/null >/dev/null
		@cipher -x01e001e001f101f1 </dev/null >/dev/null
		@cipher -xfe1ffe1ffe0efe0e </dev/null >/dev/null
		@cipher -x1ffe1ffe0efe0efe </dev/null >/dev/null
		@cipher -xe01fe01ff10ef10e </dev/null >/dev/null
		@cipher -x1fe01fe00ef10ef1 </dev/null >/dev/null
		@cipher -x01fe01fe01fe01fe </dev/null >/dev/null
		@cipher -xfe01fe01fe01fe01 </dev/null >/dev/null
		@cipher -x011f011f010e010e </dev/null >/dev/null
		@cipher -x1f011f010e010e01 </dev/null >/dev/null
		@cipher -xe0fee0fef1fef1fe </dev/null >/dev/null
		@cipher -xfee0fee0fef1fef1 </dev/null >/dev/null
		@cipher -x0101010101010101 </dev/null >/dev/null
		@cipher -xfefefefefefefefe </dev/null >/dev/null
		@cipher -xe0e0e0e0f1f1f1f1 </dev/null >/dev/null
		@cipher -x1f1f1f1f0e0e0e0e </dev/null >/dev/null

install:	cipher cipher.1 $(AUXEXE)
		cp cipher $(BINDIR)
		ln $(BINDIR)/cipher $(BINDIR)/decipher
		cp cipher.1 $(MANDIR)
		cp btoa atob $(BINDIR)
		cp btoa.1 $(MANDIR)
		ln $(MANDIR)/btoa.1 $(MANDIR)/atob.1

tar:		$(SRC)
		tar -cvf - $(SRC) | compress >cipher.tar.Z

shar:		$(SRC)
		shar $(SRC) >cipher.shar

arc:		cipher.lzh

cipher.lzh:	$(SRC)
		lharc c cipher.lzh $(SRC)

clean:
		rm -f cipher.o desvalid.o destest.o testcfb.o
		rm -f desblock.s desblock.o sboxp.o getkey.o descfb.o deskey.o
		rm -f btoa.o atob.o
		rm -f despass.o uxpass.o

clobber: 	clean
		rm -f cipher decipher destest desvalid testcfb
		rm -f atob btoa
		rm -f despass uxpass
		rm -f $(AUXEXE)
