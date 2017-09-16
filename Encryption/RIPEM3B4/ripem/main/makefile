# This is the makefile for ripem.
# If you need to change anything, most likely it'll be the
# CC and/or COPTS options below.
# To make the exportable signature-only RIPEMSIG, add -DRIPEMSIG
# to the definition of CMISC and define TESTS as testsig.

CC = gcc
COPTS = -O 
CMISC = -I. -I$(RSAREF_DIR)
TESTS= test

# Uncomment lines below to make RIPEMSIG
# CMISC = -I. -I$(RSAREF_DIR) -DRIPEMSIG
# TESTS= testsig
# end of RIPEMSIG stuff

LFLAGS=
MAKE=make
EXE=ripem
STRIP=strip
LN=ln

DES = des.o
RSAREF_DIR = ../rsaref/source
CMDLINE_DIR = ../cmdline
RSAREF_ROUTINES = $(RSAREF_DIR)/desc.o $(RSAREF_DIR)/digit.o $(RSAREF_DIR)/md2c.o $(RSAREF_DIR)/md5c.o $(RSAREF_DIR)/nn.o $(RSAREF_DIR)/prime.o $(RSAREF_DIR)/r_encode.o $(RSAREF_DIR)/r_enhanc.o $(RSAREF_DIR)/r_keygen.o $(RSAREF_DIR)/r_random.o $(RSAREF_DIR)/r_stdlib.o $(RSAREF_DIR)/rsa.o
RSAREF_LIB = ../rsaref/install/rsaref.a
DDES_ROUTINES = ddes.o
RIPEM_LIB_OBJS = crackhed.o derkey.o keyder.o hexbin.o bfstream.o pubinfo.o rdwrmsg.o ripemmai.o ripemsoc.o strutil.o keyman.o list.o bemparse.o certutil.o pemformt.o pkcformt.o
RIPEM_ROUTINES = $(RIPEM_LIB_OBJS) ripemcmd.o getopt.o getsys.o parsit.o usage.o usagemsg.o
RCERTS_ROUTINES = $(RIPEM_LIB_OBJS) rcerts.o getopt.o getsys.o parsit.o usage.o rcertsms.o
LIBS = $(RSAREF_LIB)


all:
	@echo "Makefile for RIPEM Privacy Enhanced Mail program."
	@echo " "
	@echo "Check the makefile and when it is set up properly,"
	@echo "make one of the following targets:"
	@echo " "
	@echo "    make sun         [ SunOS 4.1 ]"
	@echo "    make sunacc      [ SunOS 4.1, Sun's ANSI ACC compiler ]"
	@echo "    make suncc       [ SunOS 4.1, Sun's bundled CC compiler ]"
	@echo "    make solaris2    [ Solaris 2.x, aka SunOS 5.x ]"
	@echo "    make solaris2gcc [ Solaris 2.x, aka SunOS 5.x ]"
	@echo "    make next        [ NeXTStep 2.x and 3.0, 680x0 or 486 ]"
	@echo "    make aix         [ IBM AIX, esp. RS/6000 ]"
	@echo "    make aix386      [ IBM AIX/386 on IBM PS/2 ]"
	@echo "    make aix370      [ IBM AIX/370 on IBM 3090 ]"
	@echo "    make aixesa      [ IBM AIX/ESA (OSF/1) on IBM 390 ]"
	@echo "    make sgiirix4    [ Silicon Graphics Irix 4.0.5 ]"
	@echo "    make sgiirix5    [ Silicon Graphics Irix 5.1.1 ]"
	@echo "    make hp          [ HP/UX, esp. 9000/7xx ]"
	@echo "    make dec         [ DECstations running ULTRIX ]"
	@echo "    make alpha       [ DEC Alpha running OSF/1 ]"  
	@echo "    make moto88k     [ Motorola 88000 running System V/88 ]"
	@echo "    make sysv386     [ Unix System V.3.2/386 with GCC ]"
	@echo "    make i386bsd     [ 386BSD ]"
	@echo "    make linux       [ 386/486 Linux, no socket support ]"
	@echo "    make sco         [ SCO ODT 2.0 ]"
	@echo "    make aux3.0      [ A/UX 3.0 ]"
	@echo "    make aux3.0-gcc  [ A/UX 3.0 with GCC ]"
	@echo "    make apollo      [ Apollo sr10.3.5, w/gcc ]"
	@echo "    make mips        [ RISC/os 4.52 ]"
	@echo " "
	@echo "Other platforms supported:  MS-DOS and Macintosh; see install.txt"

clean:
	rm -f *.o ripem 

bemparse.h:	bemparse.c
	cproto bemparse.c >bemparse.h
	
crackhpr.h: crackhed.c
	cproto crackhed.c >crackhpr.h
	
derkeypr.h: derkey.c
	cproto derkey.c >derkeypr.h

getsyspr.h: $(CMDLINE_DIR)/getsys.c
	cproto $(CMDLINE_DIR)/getsys.c >getsyspr.h

keyderpr.h: keyder.c
	cproto keyder.c >keyderpr.h

keymanpr.h: keyman.c
	cproto keyman.c >keymanpr.h

listprot.h: list.c
	cproto list.c >listprot.h

pubinfop.h: pubinfo.c
	cproto pubinfo.c >pubinfop.h

rdwrmsgp.h: rdwrmsg.c
	cproto rdwrmsg.c >rdwrmsgp.h
	
ripempro.h: ripemmai.c
	cproto ripemmai.c >ripempro.h

ripemsop.h: ripemsoc.c
	cproto ripemsoc.c >ripemsop.h

strutilp.h: strutil.c
	cproto strutil.c >strutilp.h

ripem:  $(RIPEM_ROUTINES)
	$(CC) -o ripem $(CFLAGS) $(RIPEM_ROUTINES)

	
# For Sun Microsystems
sun:
	@echo "Compiling for Sun (SunOS 4.1)..."
	@$(MAKE) CC=$(CC) \
	  CFLAGS='-O  $(CMISC) -DUNIX -DUSEBSD -DUSE_SOCKETS -DSUN -DUNISTD -DDOGETRUSAGE -DPROTOTYPES=1 -DUSE_TERMIOS' \
	             LIBS="" \
	          EXE=ripem linkit rcerts $(TESTS) benchmark

# For Sun Microsystems, with unbundled ANSI ACC compiler.
#
# Notes: If this will be *running* *only* on Sparc 10 class machines
#        (SuperSPARC) add -cg92 to the beginning of CFLAGS below.
#        It will speed up the benchmark by 40%, however if you
#        run -cg92 code on a non-SuperSPARC machine it will run
#        *twice* as slow (compared to leaving the -cg92 off).
#
#        Choose WISELY!
#
sunacc:
	@echo "Compiling for Sun (SunOS 4.1), with new ANSI ACC compiler..."
	@$(MAKE) CC=acc \
	  CFLAGS='-O3 $(CMISC) -DUNIX -DUSEBSD -DUSE_SOCKETS -DSUN -DUNISTD -DDOGETRUSAGE -DPROTOTYPES=1 -DUSE_TERMIOS' \
	             LIBS="" \
	          EXE=ripem linkit rcerts $(TESTS) benchmark

# For Sun Microsystems, with braindead bundled CC compiler.
suncc:
	@echo "Compiling for Sun (SunOS 4.1), with old CC compiler..."
	@$(MAKE) CC=cc \
	  CFLAGS='-O3 $(CMISC) -DUNIX -DUSEBSD -DUSE_SOCKETS -DSUN -DUNISTD -DSUNCC -DDOGETRUSAGE -DPROTOTYPES=0 -Dconst= -DUSE_TERMIOS' \
	             LIBS="" \
	          EXE=ripem linkit rcerts $(TESTS) benchmark

# For Solaris 2.x (aka SunOS 5.x) with SPARCompilers 2.x
solaris2:
	@echo "Compiling for Solaris 2.x ..."
	@$(MAKE) CC='cc' \
	  CFLAGS='-fast -xO4 $(CMISC) -DUNIX -DUSEBSD -DUSE_SOCKETS -DSUN -DSYSV -DSVR4 -DSOLARIS -DUNISTD -DPROTOTYPES=1 -DUSE_TERMIOS' \
                LFLAGS='-fast' LIBS="-lnsl -lsocket" \
	          EXE=ripem linkit rcerts $(TESTS) benchmark

# For Solaris 2.x (aka SunOS 5.x) with GNU C 2.x
solaris2gcc:
	@echo "Compiling for Solaris 2.x ..."
	@$(MAKE) CC='gcc' \
	  CFLAGS='-O4 -g -finline-functions $(CMISC) -DUNIX -DUSEBSD -DUSE_SOCKETS -DSUN -DSYSV -DSVR4 -DSOLARIS -DUNISTD -DPROTOTYPES=1 -DUSE_TERMIOS' \
                LFLAGS='-g' LIBS="-lnsl -lsocket" \
	          EXE=ripem linkit rcerts $(TESTS) benchmark

# For NeXT computers
next: 
	@echo "Compiling for NeXT..."
	@$(MAKE) CC=cc \
	  CFLAGS='-O  $(CMISC) -DUNIX -DUSEBSD -DUSE_SOCKETS -DDOGETRUSAGE -DPROTOTYPES=1' \
	             LIBS="" \
	          EXE=ripem linkit rcerts $(TESTS) benchmark

# For AIX on RS/6000.
aix:
	@echo "Compiling for AIX on RS/6000"
	@$(MAKE) CC=cc \
	  CFLAGS='-O $(CMISC) -DUNIX -DUSE_SOCKETS -DAIX -DUSEBSD -DDOGETRUSAGE -D_ALL_SOURCE -DUNISTD -DPROTOTYPES=1 -DUSE_TERMIOS' \
		LIBS="" EXE=ripem linkit rcerts $(TESTS) benchmark

# For AIX on IBM 3090.
aix370:
	@echo "Compiling for AIX/370 on IBM 3090"
	@$(MAKE) LFLAGS='-xa -s' CC='cc -Hxa'\
	  CFLAGS='-O $(CMISC) -DUNIX -DUSE_SOCKETS -DAIX -DUSEBSD -DDOGETRUSAGE -D_ALL_SOURCE -DUNISTD -DPROTOTYPES=1 -D_BSD -DBSD_INCLUDES ' \
		LIBS="" EXE=ripem linkit rcerts $(TESTS) benchmark

# For AIX/ESA (OSF/1) on IBM 390.
aixesa:
	@echo "Compiling for AIX/ESA on IBM 390"
	@$(MAKE) LFLAGS='-xa' CC='cc -Hxa'\
	  CFLAGS='-O $(CMISC) -DUNIX -DUSE_SOCKETS -DUSEBSD -DDOGETRUSAGE -DUNISTD -DPROTOTYPES=1 -D_BSD -DBSD_INCLUDES -Hoff=Char_default_unsigned ' \
		LIBS="" EXE=ripem linkit rcerts $(TESTS) benchmark

# For AIX on IBM PS/2.
aix386:
	@echo "Compiling for AIX/386 on IBM PS/2"
	@$(MAKE) CC=cc \
	  CFLAGS='-O $(CMISC) -DUNIX -DUSE_SOCKETS -DAIX -DUSEBSD -DDOGETRUSAGE -DUNISTD -DPROTOTYPES=1 -D_BSD -DBSD_INCLUDES -Hoff=Char_default_unsigned' \
		LIBS="" EXE=ripem linkit rcerts $(TESTS) benchmark

# For HP/UX.
hp:
	@echo "Compiling for HP/UX..."
	@$(MAKE) CC=$(CC) \
	  CFLAGS='-O $(CMISC) -DUNIX -DUSE_SOCKETS -DHP -DUSE_TERMIOS -DUSEBSD -DPROTOTYPES=1' \
	             LIBS="" \
	          EXE=ripem linkit rcerts $(TESTS) benchmark

aux3.0:
	@echo "Compiling for A/UX3.0..."
	@$(MAKE) CC=cc \
	  CFLAGS='-O $(CMISC) -DUNIX -DUSE_SOCKETS -DHP -DUSE_TERMIOS -DUSEBSD -DPROTOTYPES=0' \
	             LIBS="-lbsd -lcurses -ltermcap -lposix" \
	          EXE=ripem linkit rcerts $(TESTS) benchmark

aux3.0-gcc:
	@echo "Compiling for A/UX3.0... with gcc"
	@$(MAKE) CC=gcc \
	  CFLAGS='-O2 $(CMISC) -DUNIX -DUSE_SOCKETS -DHP -DUSE_TERMIOS -DUSEBSD -DPROTOTYPES=1' \
	             LIBS="-lbsd -lcurses -ltermcap -lposix" \
	          EXE=ripem linkit rcerts $(TESTS) benchmark

# For ULTRIX
dec:
	@echo "Compiling for ULTRIX..."
	@$(MAKE) CC=gcc \
	  CFLAGS='-O $(CMISC) -DUNIX -DUSE_SOCKETS  -DUSEBSD -DULTRIX -DPROTOTYPES=1' \
	             LIBS="" \
	          EXE=ripem linkit rcerts $(TESTS) benchmark

# For Alpha OSF/1
alpha:
	@echo "Compiling for Alpha (OSF/1 2.0B)..."
	@$(MAKE) CC=$(CC) \
	   CFLAGS='-O  $(CMISC) -DUNIX -DUSEBSD -DUSE_SOCKETS \
	     -DUNISTD -DDOGETRUSAGE -DPROTOTYPES=1 -DUSE_TERMIOS' \
	             LIBS="" \
	      EXE=ripem linkit rcerts $(TESTS) benchmark

# For MIPS running RISC/os
mips:
	@echo "Compiling for RISC/os..."
	@$(MAKE) CC=/usr/bsd43/bin/cc \
		CFLAGS='-O $(CMISC) -DUNIX -DUSE_SOCKETS -DUSEBSD -DPROTOTYPES=1' \
		LIBS="" \
		EXE=ripem linkit rcerts $(TESTS) benchmark

linux:
	@echo "Compiling for linux 0.98"
	@$(MAKE) CC=cc \
	  CFLAGS='-O -m486 $(CMISC) -DUSE_TERMIOS -DUNIX -DUSE_BSD -DPROTOTYPES=1' \
		LIBS=""\
		EXE=ripem linkit rcerts $(TESTS) benchmark 

sco:
	@echo "Compiling for SCO ODT 2.0 using gcc "
	@$(MAKE) CC=gcc \
	  CFLAGS='-O $(CMISC) -DUNIX -DSYSV -Dsco -DUSE_SOCKETS  -DPROTOTYPES=1' \
		LIBS="/usr/lib/libsocket.a /usr/lib/libyp.a /usr/lib/librpc.a" \
		EXE=ripem linkit rcerts $(TESTS) benchmark 

sysv386:
	@echo "Compiling for Unix System V.3.2/386 using gcc "
	@$(MAKE) CC=gcc \
		CFLAGS='-O $(CMISC) -DUNIX -DSYSV -DSVRV32 -DPROTOTYPES=1' \
		LIBS="-lpt -lnet -lnsl_s -lbsd" \
		EXE=ripem linkit rcerts $(TESTS) benchmark				

# For Motorola 88k systems
moto88k:
	@echo "Compiling for Motorola 88k..."
	@$(MAKE) CC=$(CC) \
	  CFLAGS='-O $(CMISC) -DUNIX -DSYSV -DMOTOROLA -DUSE_SOCKETS  -DPROTOTYPES=1' \
		LIBS="" \
		EXE=ripem linkit rcerts $(TESTS) benchmark

sgiirix4:
	@echo "Compiling for SGI Irix 4.0.5..."
	@$(MAKE) CC=cc \
	  CFLAGS='-xansi -D__STDC__ -D_POSIX_SOURCE -D_ALL_SOURCE -Dsgi -DUNIX -DSYSV -DUSE_SOCKETS  -Umips -DPROTOTYPES=1 $(CMISC)' \
		LIBS="" \
		EXE=ripem linkit rcerts $(TESTS) benchmark

sgiirix5:
	@echo "Compiling for SGI Irix 5.1.1..."
	@$(MAKE) CC=cc \
	  CFLAGS='-D_POSIX_SOURCE -D_ALL_SOURCE -Dsgi -DUNIX -DSYSV -D_BSD_TYPES -DUSE_SOCKETS  -DPROTOTYPES=1 $(CMISC) -Umips' \
	   LIBS="" \
	   EXE=ripem linkit rcerts $(TESTS) benchmark


# For 386BSD Microsystems
i386bsd:
	@echo "Compiling for 386BSD..."
	@$(MAKE) CC=$(CC) \
	  CFLAGS='-O $(CMISC) -DUNIX -DUSEBSD -DUSE_SOCKETS -DI386BSD -DUNISTD -DDOGETRUSAGE -DPROTOTYPES=1' \
	             LIBS="" \
	          EXE=ripem linkit rcerts $(TESTS) benchmark

# For Apollo
apollo:
	@echo "Compiling for Apollo (DomainOS sr10.3.5)..."
	@$(MAKE) CC=$(CC) \
	  CFLAGS='-O4 $(CMISC) -DUNIX -DUSEBSD -DUSE_SOCKETS -DDOGETRUSAGE -DPROTOTYPES=1' \
	             LIBS="" \
	          EXE=ripem linkit rcerts $(TESTS) benchmark

linkit: $(RIPEM_ROUTINES) $(RSAREF_LIB)
	@echo "Linking $(EXE)..."
	$(CC) $(CFLAGS) $(LFLAGS) -o $(EXE) $(RIPEM_ROUTINES) $(RSAREF_LIB) $(LIBS)
	$(STRIP) $(EXE)
	chmod 755 $(EXE)
	rm -f ../test/$(EXE)
	$(LN) $(EXE) ../test
	@ls -l $(EXE)
	@echo "RIPEM has been built."
	
rcerts: $(RCERTS_ROUTINES) $(RSAREF_LIB)
	@echo "Linking rcerts..."
	$(CC) $(CFLAGS) $(LFLAGS) -o rcerts $(RCERTS_ROUTINES) $(RSAREF_LIB) $(LIBS)
	$(STRIP) rcerts
	chmod 755 rcerts
	@echo "rcerts has been built."
	
test:
	@echo " "
	@echo "Testing RIPEM decryption."
	time ./ripem -d -p ../test/test1.pub -s ../test/test1.prv -k test1pw \
	    -i ../test/message.enc -y rpub.cl.msu.edu -u test
	@echo "Testing RIPEM EDE decryption."
	time ./ripem -d -p ../test/test1.pub -s ../test/test1.prv -k test1pw \
	    -i ../test/ede-msg.enc -y rpub.cl.msu.edu -u test
	@echo "Testing RIPEM encryption."
	time ./ripem -e -p ../test/test1.pub -s ../test/test1.prv -k test1pw \
	    -i ../test/message2 -o ../test/teste.enc -y rpub.cl.msu.edu -u test \
		 -h pr -R c -C c
	@echo "If diff reports differences below, you may have problems."
	@diff -c ../test/message2.enc ../test/teste.enc
	@echo "** Test of RIPEM decryption/encryption complete."

testsig:
	@echo " "
	@echo "Testing RIPEM signing."
	time ./ripem -e -m mic-clear -p ../test/test1.pub -s ../test/test1.prv \
		-k test1pw -u test -i ../test/signin.txt -o ../test/signout.txt \
		-h pr -R c -C c
	@echo "If diff reports differences below, you may have problems."
	@diff -c ../test/signout2.txt ../test/signout.txt
	@echo " "
	@echo "Testing RIPEM signature verification."
	@echo "==> Look for \"Signature status: VALID.\" below."
	time ./ripem -d -p ../test/test1.pub -s ../test/test1.prv \
		-k test1pw -u test -i ../test/signed.txt  

benchmark:
	@echo " "
	@rm -f pubkeys privkey
	@echo "RIPEM key generation benchmark starting.  "
	@echo "Takes < 30 seconds for most workstations."
	time ./ripem -g -H . -k test1pw -u test -R c -C b
	@echo "Test key generation complete. "
	@echo "If diff reports differences below, you may have problems."
	@head -12 privkey >../test/test212.prv
	@diff -c ../test/test212.prv ../test/test112.prv
	@echo "** RIPEM key generation benchmark complete. " 
	@echo "If your machine isn't in benchmrk.txt, please email the above"
	@echo "results with machine specs to mrr@ripem.msu.edu.   Thanks."

getopt.o : $(CMDLINE_DIR)/getopt.c
	$(CC) $(CFLAGS) -c $(CMDLINE_DIR)/getopt.c

getsys.o : $(CMDLINE_DIR)/getsys.c
	$(CC) $(CFLAGS) -c $(CMDLINE_DIR)/getsys.c

parsit.o : $(CMDLINE_DIR)/parsit.c
	$(CC) $(CFLAGS) -c $(CMDLINE_DIR)/parsit.c

ripemcmd.o : $(CMDLINE_DIR)/ripemcmd.c
	$(CC) $(CFLAGS) -c $(CMDLINE_DIR)/ripemcmd.c

rcerts.o : $(CMDLINE_DIR)/rcerts.c
	$(CC) $(CFLAGS) -c $(CMDLINE_DIR)/rcerts.c

rcertsms.o : $(CMDLINE_DIR)/rcertsms.c
	$(CC) $(CFLAGS) -c $(CMDLINE_DIR)/rcertsms.c

usage.o : $(CMDLINE_DIR)/usage.c
	$(CC) $(CFLAGS) -c $(CMDLINE_DIR)/usage.c

usagemsg.o : $(CMDLINE_DIR)/usagemsg.c
	$(CC) $(CFLAGS) -c $(CMDLINE_DIR)/usagemsg.c

