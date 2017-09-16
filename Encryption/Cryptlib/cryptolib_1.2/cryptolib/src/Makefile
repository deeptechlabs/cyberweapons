PROC = $(ARCH)

LIBDIR = ../lib/${PROC}
OBJDIR = ../obj/${PROC}
INCLUDE = .

# SOURCE FILES

MATHSRC = msbtable.c longmult.c coremult.c bignum.c bigmath.c fastmult.c \
	bigpow.c getrand.c primes.c euclid.c quadres.c jacobi.c newton.c

RANDSRC = fsrRand.c desRand.c unix_truerand.c quantize.c

CRYPTSRC = des.c desmodes.c md2.c md4.c md5.c shs.c mdigest.c \
	rsa.c elgamal.c dsa.c rabin.c dh.c

UTILSSRC = ioutils.c memalloc.c fasn1.c filenet.c bufasn1.c bufnet.c


# OBJFILES

MATHOBJ = $(OBJDIR)/msbtable.o $(OBJDIR)/coremult.o $(OBJDIR)/bignum.o $(OBJDIR)/bigmath.o \
	  $(OBJDIR)/fastmult.o $(OBJDIR)/bigpow.o $(OBJDIR)/primes.o $(OBJDIR)/euclid.o \
	  $(OBJDIR)/quadres.o $(OBJDIR)/jacobi.o $(OBJDIR)/newton.o $(OBJDIR)/longmult.o \
	  $(OBJDIR)/fsrRand.o $(OBJDIR)/desRand.o

RANDOBJ = $(OBJDIR)/truerand.o $(OBJDIR)/getrand.o $(OBJDIR)/quantize.o

CRYPTOBJ = $(OBJDIR)/des.o $(OBJDIR)/desmodes.o $(OBJDIR)/md2.o $(OBJDIR)/md4.o \
	   $(OBJDIR)/md5.o $(OBJDIR)/shs.o $(OBJDIR)/mdigest.o \
	   $(OBJDIR)/rsa.o $(OBJDIR)/elgamal.o $(OBJDIR)/dsa.o $(OBJDIR)/rabin.o $(OBJDIR)/dh.o

UTILSOBJ = $(OBJDIR)/ioutils.o $(OBJDIR)/memalloc.o $(OBJDIR)/fasn1.o $(OBJDIR)/filenet.o \
	   $(OBJDIR)/bufasn1.o $(OBJDIR)/bufnet.o

# ANSI C Compilers and Flags

# non-ansi (K_and_R) C Compiler
#CFLAGS= -O -DK_AND_R -I$(INCLUDE) -c
#CC = cc

# Standard C Compilers and Flags
CFLAGS= -O4 -I$(INCLUDE) -c -DNDEBUG -ansi
CC = gcc

# Solaris flags when not using gcc
#CFLAGS= -O -I$(INCLUDE) -c
#CC = cc

default:
	@echo "Assembly versions of 32 bit multiplication primitives exist for"
	@echo "mips, sparc2, sparc10 and 80386, 80486 and pentium archs."
	@echo "make sgi"
	@echo "make sunos_sparc2"
	@echo "make sunos_sparc10"
	@echo "make solaris_sparc2"
	@echo "make solaris_sparc10"
	@echo "make dos"
	@echo "make 80x86_unix"
	@echo "accordingly.  If you are none of these,"
	@echo "make libcrypt."
	@echo "This makefile assumes a ../obj and a ../lib"

sgi: $(MATHOBJ) $(CRYPTOBJ) $(UTILSOBJ)
	$(CC) $(CFLAGS)  -o $(OBJDIR)/longmult.o sgi_longmult.s
	$(CC) $(CFLAGS)  -DTRUERAND -o $(OBJDIR)/truerand.o unix_truerand.c
	$(CC) $(CFLAGS)  -o $(OBJDIR)/quantize.o quantize.c
	$(CC) $(CFLAGS)  -DTRUERAND -o $(OBJDIR)/getrand.o getrand.c
	rm -rf $(LIBDIR)/libcrypt.a
	ar r $(LIBDIR)/libcrypt.a $(MATHOBJ) $(CRYPTOBJ) $(RANDOBJ) $(UTILSOBJ)
	ranlib $(LIBDIR)/libcrypt.a

sunos_sparc2: $(MATHOBJ) $(CRYPTOBJ) $(UTILSOBJ)
	$(CC) $(CFLAGS)  -o $(OBJDIR)/longmult.o sparc2_longmult.s
	$(CC) $(CFLAGS)  -DTRUERAND -o $(OBJDIR)/truerand.o unix_truerand.c
	$(CC) $(CFLAGS)  -o $(OBJDIR)/quantize.o quantize.c
	$(CC) $(CFLAGS)  -DTRUERAND -o $(OBJDIR)/getrand.o getrand.c
	rm -rf $(LIBDIR)/libcrypt.a
	ar r $(LIBDIR)/libcrypt.a $(MATHOBJ) $(CRYPTOBJ) $(RANDOBJ) $(UTILSOBJ)
	ranlib $(LIBDIR)/libcrypt.a

sunos_sparc10: $(MATHOBJ) $(CRYPTOBJ) $(UTILSOBJ)
	$(CC) $(CFLAGS)  -o $(OBJDIR)/longmult.o sparc10_longmult.s
	$(CC) $(CFLAGS)  -DTRUERAND -o $(OBJDIR)/truerand.o unix_truerand.c
	$(CC) $(CFLAGS)  -o $(OBJDIR)/quantize.o quantize.c
	$(CC) $(CFLAGS)  -DTRUERAND -o $(OBJDIR)/getrand.o getrand.c
	rm -rf $(LIBDIR)/libcrypt.a
	ar r $(LIBDIR)/libcrypt.a $(MATHOBJ) $(CRYPTOBJ) $(RANDOBJ) $(UTILSOBJ)
	ranlib $(LIBDIR)/libcrypt.a

solaris_sparc2: $(MATHOBJ) $(CRYPTOBJ) $(UTILSOBJ)
	$(CC) $(CFLAGS)  -o $(OBJDIR)/longmult.o solaris_sparc2_longmult.s
	$(CC) -I$(INCLUDE) -DTRUERAND -c  -o $(OBJDIR)/truerand.o unix_truerand.c
	$(CC) -I$(INCLUDE) -c -o $(OBJDIR)/quantize.o quantize.c
	$(CC) $(CFLAGS)  -DTRUERAND -o $(OBJDIR)/getrand.o getrand.c
	rm -rf $(LIBDIR)/libcrypt.a
	ar r $(LIBDIR)/libcrypt.a $(MATHOBJ) $(CRYPTOBJ) $(RANDOBJ) $(UTILSOBJ)

solaris_sparc10: $(MATHOBJ) $(CRYPTOBJ) $(UTILSOBJ)
	$(CC) $(CFLAGS)  -o $(OBJDIR)/longmult.o solaris_sparc10_longmult.s
	$(CC) -I$(INCLUDE) -c  -DTRUERAND -o $(OBJDIR)/truerand.o unix_truerand.c
	$(CC) -I$(INCLUDE) -c -o $(OBJDIR)/quantize.o quantize.c
	$(CC) $(CFLAGS)  -DTRUERAND -o $(OBJDIR)/getrand.o getrand.c
	rm -rf $(LIBDIR)/libcrypt.a
	ar r $(LIBDIR)/libcrypt.a $(MATHOBJ) $(CRYPTOBJ) $(RANDOBJ) $(UTILSOBJ)

80x86_unix: $(MATHOBJ) $(CRYPTOBJ) $(UTILSOBJ)
	$(CC) $(CFLAGS)  -o $(OBJDIR)/longmult.o 80x86_unix_lmult.s
	$(CC) -DTRUERAND -I$(INCLUDE) -c -o $(OBJDIR)/truerand.o unix_truerand.c
	$(CC) -I$(INCLUDE) -c -o $(OBJDIR)/quantize.o quantize.c
	$(CC) $(CFLAGS)  -DTRUERAND -o $(OBJDIR)/getrand.o getrand.c
	rm -rf $(LIBDIR)/libcrypt.a
	ar r $(LIBDIR)/libcrypt.a $(MATHOBJ) $(CRYPTOBJ) $(RANDOBJ) $(UTILSOBJ)
	ranlib $(LIBDIR)/libcrypt.a

dos: $(MATHOBJ) $(CRYPTOBJ) $(UTILSOBJ)
	$(CC) $(CFLAGS)  -o $(OBJDIR)/longmult.o 80x86_dos_lmult.s
	$(CC) -DNTRUERAND -I$(INCLUDE) -c -o $(OBJDIR)/truerand.o unix_truerand.c
	$(CC) -DNO_QUANTIZE -I$(INCLUDE) -c -o $(OBJDIR)/quantize.o quantize.c
	$(CC) $(CFLAGS)  -DNTRUERAND -o $(OBJDIR)/getrand.o getrand.c
	rm -rf $(LIBDIR)/libcrypt.a
	ar r $(LIBDIR)/libcrypt.a $(MATHOBJ) $(CRYPTOBJ) $(RANDOBJ) $(UTILSOBJ)
	ranlib $(LIBDIR)/libcrypt.a

libcrypt: $(MATHOBJ) $(CRYPTOBJ) $(UTILSOBJ)
	$(CC) $(CFLAGS)  -DTRUERAND -o $(OBJDIR)/truerand.o unix_truerand.c
	$(CC) $(CFLAGS)  -o $(OBJDIR)/quantize.o quantize.c
	$(CC) $(CFLAGS)  -DTRUERAND -o $(OBJDIR)/getrand.o getrand.c
	rm -rf $(LIBDIR)/libcrypt.a
	ar r $(LIBDIR)/libcrypt.a $(MATHOBJ) $(CRYPTOBJ) $(RANDOBJ) $(UTILSOBJ)
	ranlib $(LIBDIR)/libcrypt.a

$(OBJDIR)/longmult.o: longmult.c
	$(CC) $(CFLAGS)  -o $(OBJDIR)/longmult.o longmult.c

$(OBJDIR)/fasn1.o: fasn1.c
	$(CC) $(CFLAGS) -o $(OBJDIR)/fasn1.o fasn1.c

$(OBJDIR)/filenet.o: filenet.c
	$(CC) $(CFLAGS) -o $(OBJDIR)/filenet.o filenet.c

$(OBJDIR)/bufasn1.o: bufasn1.c
	$(CC) $(CFLAGS) -o $(OBJDIR)/bufasn1.o bufasn1.c

$(OBJDIR)/bufnet.o: bufnet.c
	$(CC) $(CFLAGS)  -o $(OBJDIR)/bufnet.o bufnet.c

$(OBJDIR)/msbtable.o: msbtable.c
	$(CC) $(CFLAGS)  -o $(OBJDIR)/msbtable.o msbtable.c

$(OBJDIR)/coremult.o: coremult.c  
	$(CC) $(CFLAGS)  -o $(OBJDIR)/coremult.o coremult.c

$(OBJDIR)/bignum.o: bignum.c  
	$(CC) $(CFLAGS)  -o $(OBJDIR)/bignum.o bignum.c

$(OBJDIR)/bigmath.o: bigmath.c  
	$(CC) $(CFLAGS)  -o $(OBJDIR)/bigmath.o bigmath.c

$(OBJDIR)/fastmult.o: fastmult.c  
	$(CC) $(CFLAGS)  -o $(OBJDIR)/fastmult.o fastmult.c

$(OBJDIR)/bigpow.o: bigpow.c  
	$(CC) $(CFLAGS)  -o $(OBJDIR)/bigpow.o bigpow.c

$(OBJDIR)/primes.o: primes.c  
	$(CC) $(CFLAGS)  -o $(OBJDIR)/primes.o primes.c

$(OBJDIR)/euclid.o: euclid.c  
	$(CC) $(CFLAGS)  -o $(OBJDIR)/euclid.o euclid.c

$(OBJDIR)/quadres.o: quadres.c  
	$(CC) $(CFLAGS)  -o $(OBJDIR)/quadres.o quadres.c

$(OBJDIR)/jacobi.o: jacobi.c  
	$(CC) $(CFLAGS)  -o $(OBJDIR)/jacobi.o jacobi.c

$(OBJDIR)/newton.o: newton.c  
	$(CC) $(CFLAGS)  -o $(OBJDIR)/newton.o newton.c

$(OBJDIR)/fsrRand.o: fsrRand.c 
	$(CC) $(CFLAGS)  -o $(OBJDIR)/fsrRand.o fsrRand.c

$(OBJDIR)/desRand.o: desRand.c 
	$(CC) $(CFLAGS)  -o $(OBJDIR)/desRand.o desRand.c

$(OBJDIR)/des.o: des.c  
	$(CC) $(CFLAGS)  -o $(OBJDIR)/des.o des.c

$(OBJDIR)/desmodes.o: desmodes.c  
	$(CC) $(CFLAGS)  -o $(OBJDIR)/desmodes.o desmodes.c

$(OBJDIR)/md2.o: md2.c  
	$(CC) $(CFLAGS)  -o $(OBJDIR)/md2.o md2.c

$(OBJDIR)/md4.o: md4.c  
	$(CC) $(CFLAGS)  -o $(OBJDIR)/md4.o md4.c

$(OBJDIR)/md5.o: md5.c  
	$(CC) $(CFLAGS)  -o $(OBJDIR)/md5.o md5.c

$(OBJDIR)/shs.o: shs.c  
	$(CC) $(CFLAGS)  -o $(OBJDIR)/shs.o shs.c

$(OBJDIR)/mdigest.o: mdigest.c  
	$(CC) $(CFLAGS)  -o $(OBJDIR)/mdigest.o mdigest.c

$(OBJDIR)/rsa.o: rsa.c  
	$(CC) $(CFLAGS) -D_GORDON  -o $(OBJDIR)/rsa.o rsa.c

$(OBJDIR)/elgamal.o: elgamal.c  
	$(CC) $(CFLAGS)  -o $(OBJDIR)/elgamal.o elgamal.c

$(OBJDIR)/dsa.o: dsa.c  
	$(CC) $(CFLAGS)  -o $(OBJDIR)/dsa.o dsa.c

$(OBJDIR)/rabin.o: rabin.c  
	$(CC) $(CFLAGS)  -o $(OBJDIR)/rabin.o rabin.c

$(OBJDIR)/dh.o: dh.c  
	$(CC) $(CFLAGS)  -o $(OBJDIR)/dh.o dh.c

$(OBJDIR)/ioutils.o: ioutils.c  
	$(CC) $(CFLAGS)  -o $(OBJDIR)/ioutils.o ioutils.c

$(OBJDIR)/memalloc.o: memalloc.c  
	$(CC) $(CFLAGS)  -o $(OBJDIR)/memalloc.o memalloc.c


clean:
	rm -f $(OBJDIR)/*.o

clobber:
	rm -f $(OBJDIR)/*.o *~ $(LIBDIR)/libcrypt.a

