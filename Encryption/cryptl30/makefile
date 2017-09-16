#****************************************************************************
#*																			*
#*							Makefile for cryptlib 3.0						*
#*																			*
#****************************************************************************

# This file is shared between the Unix and BeOS versions.  To use it to build
# the BeOS version, uncomment the defines marked with the "BeOS:" comment
# below.
#
# "The makefile is looking really perverse.  You're getting the hang of it"
#														- Chris Wedgwood.
#
# At least it doesn't pipe itself through sed yet.
#
# Note that the self-test program pulls in parts of cryptlib to ensure that
# the self-configuration works.  Because this is handled by the makefile, you
# can't just 'make testlib' after making changes, you need to use 'make; make
# testlib'.

# Naming information: Major and minor version numbers and project and library
# names.  The patch level is always zero because patches imply bugs and my
# code is perfect.

MAJ		= 3
MIN		= 0
PLV		= 0
PROJ	= crypt
LIBNAME	= lib$(PROJ).a
SLIBNAME = lib$(PROJ).so.$(MAJ).$(MIN).$(PLV)

# Extra compiler options for debugging.  Add this to the CFLAGS to provide an
# extra level of warnings about potential problems when using gcc.

DEBUG_FLAGS	= -Wall -Wshadow -Wcast-align -Wconversion -Wredundant-decls -Winline

# Compiler options.  The IRIX cc doesn't recognise -fpic, but generates PIC
# by default anyway, so to make this work under IRIX just remove the -fpic.
# The PHUX compiler requires +z for PIC.
#
# To enable use of a particular key database interface, add -DDBX_<name> to
# the CFLAGS or SCFLAGS as appropriate (you can enable more than one database
# interface if required).  You also need to set TESTLIB (defined further
# down) to link the appropriate database library or libraries with the self-
# test code.
#
# If the OS supports it, the multithreaded version of cryptlib will be built.
# To specifically disable this, add -DNO_THREADS.

CFLAGS	= -c -D__UNIX__ -I.
SCFLAGS = -fpic -c -D__UNIX__ -I.

# BeOS: Use the following defines instead of the current ones

# CFLAGS	= -c -O2 -D__BEOS__ -I.
# SCFLAGS	= -c -O2 -D__BEOS__ -I.
# LIBS	= -ldll -lbe				# Extra libs needed for the shared lib.

# To link the self-test code with a key database, uncomment the following
# and substitute the name or names of the database libraries you'll be using.

# TESTLIB	= -lmsql

# Paths and command names.  We have to be careful with comments attached to
# path defines because some makes don't strip trailing spaces.
#
# The reason for the almost-identical defines for path and dir is because of
# the braindamaged BSDI mkdir (and rmdir) which break if the path ends in a
# '/', it's easier to have separate defines than to drop a '/' into every
# path.
#
# The options for the shared library link should work on most systems which
# handle shared libraries, but may need to be tuned for some systems since
# there's no standard for shared libraries, and different versions of gcc
# also changed the way this was handled.  If the current line doesn't work,
# try one of the following ones:
#
# *BSD's:		$(LD) -Bshareable -o lib$(PROJ).so.$(MAJ)
# Solaris:		$(LD) -G -ldl -o lib$(PROJ).so.$(MAJ)
# Linux:		$(LD) -Bshareable -ldl -o lib$(PROJ).so.$(MAJ)
# IRIX, OSF/1:	$(LD) -shared -o lib$(PROJ).so.$(MAJ)
# HPUX:			$(LD) -shared -Wl,-soname,lib$(PROJ).so.$(MAJ)

STATIC_OBJ_PATH = ./static-obj/
STATIC_OBJ_DIR = ./static-obj
SHARED_OBJ_PATH = ./shared-obj/
SHARED_OBJ_DIR = ./shared-obj
LIBPATH	= ./
CPP		= $(CC) -E
LD		= $(CC)						# Static link
SLD		= $(LD) -shared -Wl									# Shared link
SHELL	= /bin/sh

# Default target and obj file path.  This is changed depending on whether
# we're building the static or shared library, the default is to build the
# static library.

TARGET	= $(LIBPATH)$(LIBNAME)
OBJPATH	= $(STATIC_OBJ_PATH)

# Some makes don't pass defines down when they recursively invoke make, so we
# need to manually pass them along.  The following macro contains all defines
# which we want to pass to recursive calls to make.

DEFINES	= $(TARGET) OBJPATH=$(OBJPATH)

#****************************************************************************
#*																			*
#*								Common Dependencies							*
#*																			*
#****************************************************************************

# The object files which make up the library

BNOBJS		= $(OBJPATH)bn_add.o $(OBJPATH)bn_blind.o $(OBJPATH)bn_div.o \
			  $(OBJPATH)bn_exp.o $(OBJPATH)bn_gcd.o $(OBJPATH)bn_lib.o \
			  $(OBJPATH)bn_mod.o $(OBJPATH)bn_mont.o $(OBJPATH)bn_mul.o \
			  $(OBJPATH)bn_mulw.o $(OBJPATH)bn_recp.o $(OBJPATH)bn_shift.o \
			  $(OBJPATH)bn_sqr.o $(OBJPATH)bn_sub.o $(OBJPATH)bn_word.o

CRYPTOBJS	= $(OBJPATH)bf_ecb.o $(OBJPATH)bf_enc.o $(OBJPATH)bf_skey.o \
			  $(OBJPATH)c_ecb.o $(OBJPATH)c_enc.o $(OBJPATH)c_skey.o \
			  $(OBJPATH)des_enc.o $(OBJPATH)ecb3_enc.o $(OBJPATH)ecb_enc.o \
			  $(OBJPATH)idea.o $(OBJPATH)rc2.o $(OBJPATH)rc4_enc.o \
			  $(OBJPATH)rc4_skey.o $(OBJPATH)rc5.o $(OBJPATH)safer.o \
			  $(OBJPATH)set_key.o $(OBJPATH)skipjack.o

ENVOBJS		= $(OBJPATH)deenvel.o $(OBJPATH)envelope.o $(OBJPATH)octetstr.o \
			  $(OBJPATH)pgp_deen.o $(OBJPATH)pgp_misc.o $(OBJPATH)resource.o

HASHOBJS	= $(OBJPATH)md2.o $(OBJPATH)md4.o $(OBJPATH)md5_dgst.o \
			  $(OBJPATH)mdc2dgst.o $(OBJPATH)ripemd.o $(OBJPATH)ripecore.o \
			  $(OBJPATH)sha_dgst.o $(OBJPATH)sha1dgst.o

KEYOBJS		= $(OBJPATH)asn1.o $(OBJPATH)asn1keys.o $(OBJPATH)asn1objs.o \
			  $(OBJPATH)asn1oid.o $(OBJPATH)cert.o $(OBJPATH)certchk.o \
			  $(OBJPATH)certchn.o $(OBJPATH)certcomp.o $(OBJPATH)certechk.o \
			  $(OBJPATH)certedef.o $(OBJPATH)certexrw.o $(OBJPATH)certext.o \
			  $(OBJPATH)certio.o $(OBJPATH)certsig.o $(OBJPATH)certstr.o \
			  $(OBJPATH)certrust.o $(OBJPATH)cms.o $(OBJPATH)stream.o

LIBOBJS		= $(OBJPATH)crypt.o $(OBJPATH)cryptapi.o $(OBJPATH)cryptcfg.o \
			  $(OBJPATH)cryptcrt.o $(OBJPATH)cryptdbx.o \
			  $(OBJPATH)cryptdev.o $(OBJPATH)cryptenv.o \
			  $(OBJPATH)cryptkey.o $(OBJPATH)cryptkrn.o \
			  $(OBJPATH)cryptlib.o $(OBJPATH)cryptmch.o \
			  $(OBJPATH)cryptmis.o $(OBJPATH)cryptses.o $(OBJPATH)lib_3des.o \
			  $(OBJPATH)lib_bf.o $(OBJPATH)lib_cast.o $(OBJPATH)lib_dbms.o \
			  $(OBJPATH)lib_des.o $(OBJPATH)lib_dh.o $(OBJPATH)lib_dsa.o \
			  $(OBJPATH)lib_elg.o $(OBJPATH)lib_hmd5.o $(OBJPATH)lib_hrmd.o \
			  $(OBJPATH)lib_hsha.o $(OBJPATH)lib_idea.o $(OBJPATH)lib_kg.o \
			  $(OBJPATH)lib_keyx.o $(OBJPATH)lib_md2.o $(OBJPATH)lib_md4.o \
			  $(OBJPATH)lib_md5.o $(OBJPATH)lib_mdc2.o $(OBJPATH)lib_rc2.o \
			  $(OBJPATH)lib_rc4.o $(OBJPATH)lib_rc5.o $(OBJPATH)lib_ripe.o \
			  $(OBJPATH)lib_rsa.o $(OBJPATH)lib_safr.o $(OBJPATH)lib_sha.o \
			  $(OBJPATH)lib_sign.o $(OBJPATH)lib_skip.o

MISCOBJS	= $(OBJPATH)dbxhttp.o $(OBJPATH)dbxldap.o $(OBJPATH)dbxmsql.o \
			  $(OBJPATH)dbxmysql.o $(OBJPATH)dbxoracl.o $(OBJPATH)dbxpgp.o \
			  $(OBJPATH)dbxpk12.o $(OBJPATH)dbxpk15.o $(OBJPATH)dbxpostg.o \
			  $(OBJPATH)dbxscard.o $(OBJPATH)dev_fort.o $(OBJPATH)dev_pk11.o \
			  $(OBJPATH)dev_sys.o $(OBJPATH)net_tcp.o $(OBJPATH)rndunix.o \
			  $(OBJPATH)scmisc.o

SESSOBJS	= $(OBJPATH)ssh.o $(OBJPATH)ssl.o

ZLIBOBJS	= $(OBJPATH)adler32.o $(OBJPATH)deflate.o $(OBJPATH)infblock.o \
			  $(OBJPATH)infcodes.o $(OBJPATH)inffast.o $(OBJPATH)inflate.o \
			  $(OBJPATH)inftrees.o $(OBJPATH)infutil.o $(OBJPATH)trees.o \
			  $(OBJPATH)zutil.o

OBJS		= $(ASMOBJS) $(BNOBJS) $(CRYPTOBJS) $(ENVOBJS) $(HASHOBJS) \
			  $(KEYOBJS) $(LIBOBJS) $(MISCOBJS) $(SESSOBJS) $(ZLIBOBJS)

# Various functions all make use of certain headers so we define the
# dependencies once here

ASN1_DEP = keymgmt/asn1.h keymgmt/asn1objs.h keymgmt/asn1oid.h \
		   keymgmt/ber.h keymgmt/stream.h

CRYPT_DEP	= cryptlib.h crypt.h cryptos.h

ECC_DEP = crypt/ec_crypt.h crypt/ec_curve.h crypt/ec_field.h \
		  crypt/ec_param.h crypt/ec_vlong.h

ZLIB_DEP = zlib/zconf.h zlib/zlib.h zlib/zutil.h

#****************************************************************************
#*																			*
#*							Default and High-level Targets					*
#*																			*
#****************************************************************************

# Find the system type and use a conditional make depending on that and the
# endianness, which is piped in from the endianness-detection program (who
# needs autoconf in order to be ugly).
#
# A few SVR4 unames don't report the OS name properly (eg SCO, Olivetti Unix)
# so it's necessary to specify the SVR4 target on the command line.
#
# The unnecessary deletion of the '.' by the tr command is to work around a
# problem in the SunOS uname -r which returns a number with no OS name so
# that tr can't find any alphabetics to delete.

default:
		@if [ ! -d $(STATIC_OBJ_PATH) ] ; then mkdir $(STATIC_OBJ_DIR) ; fi
		@make endian > /dev/null
		@make CFLAGS="$(CFLAGS) `./endian` \
		-DOSVERSION=`uname -r | tr -d '[A-Z].' | cut -c 1`" \
		LIBS="$(LIBS)" `uname`

# Build the shared library

shared:
		@if [ ! -d $(SHARED_OBJ_PATH) ] ; then mkdir $(SHARED_OBJ_DIR) ; fi
		@make endian > /dev/null
		@make TARGET=$(LIBPATH)$(SLIBNAME) OBJPATH=$(SHARED_OBJ_PATH) \
		CFLAGS="$(SCFLAGS) `./endian` \
		-DOSVERSION=`uname -r | tr -d '[A-Z].' | cut -c 1`" \
		LIBS="$(LIBS)" `uname`

# Build the endianness-test program.  The output of this is a preprocessor
# define which is piped back into make to control the cryptlib endianness.

endian:					endian.c
						@$(CC) endian.c -o endian

# Frohe Ostern.

babies:
		@echo "Good grief, what do you think I am?  The Unix environment is capable, but"
		@echo "not that capable."

cookies:
		@echo "Mix 250g flour, 150g sugar, 125g butter, an egg, a few drops of vanilla"
		@echo "essence, and 1 tsp baking powder into a dough, cut cookies from rolls of"
		@echo "dough, bake for about 15 minutes at 180C until they turn very light brown"
		@echo "at the edges."

love:
		@echo "Nicht wahr?"
		@echo

#****************************************************************************
#*																			*
#*					Rules to build the encryption library					*
#*																			*
#****************************************************************************

# Main directory

$(OBJPATH)crypt.o:		$(CRYPT_DEP) cryptctx.h crypt.c
						$(CC) $(CFLAGS) crypt.c -o $(OBJPATH)crypt.o

$(OBJPATH)cryptapi.o:	$(CRYPT_DEP) hash/md2.h hash/md4.h hash/md5.h \
						hash/sha.h cryptapi.c
						$(CC) $(CFLAGS) cryptapi.c -o $(OBJPATH)cryptapi.o

$(OBJPATH)cryptcfg.o:	$(CRYPT_DEP) cryptcfg.c
						$(CC) $(CFLAGS) cryptcfg.c -o $(OBJPATH)cryptcfg.o

$(OBJPATH)cryptcrt.o:	$(CRYPT_DEP) keymgmt/cert.h cryptcrt.c
						$(CC) $(CFLAGS) cryptcrt.c -o $(OBJPATH)cryptcrt.o

$(OBJPATH)cryptdbx.o:	$(CRYPT_DEP) misc/keyset.h keymgmt/asn1objs.h \
						cryptdbx.c
						$(CC) $(CFLAGS) cryptdbx.c -o $(OBJPATH)cryptdbx.o

$(OBJPATH)cryptdev.o:	$(CRYPT_DEP) misc/device.h cryptdev.c
						$(CC) $(CFLAGS) cryptdev.c -o $(OBJPATH)cryptdev.o

$(OBJPATH)cryptenv.o:	$(CRYPT_DEP) envelope/envelope.h $(ASN1_DEP) \
						cryptenv.c
						$(CC) $(CFLAGS) cryptenv.c -o $(OBJPATH)cryptenv.o

$(OBJPATH)cryptkey.o:	$(CRYPT_DEP) cryptctx.h cryptkey.c
						$(CC) $(CFLAGS) cryptkey.c -o $(OBJPATH)cryptkey.o

$(OBJPATH)cryptkrn.o:	$(CRYPT_DEP) cryptkrn.c
						$(CC) $(CFLAGS) cryptkrn.c -o $(OBJPATH)cryptkrn.o

$(OBJPATH)cryptlib.o:	$(CRYPT_DEP) cryptlib.c
						$(CC) $(CFLAGS) cryptlib.c -o $(OBJPATH)cryptlib.o

$(OBJPATH)cryptmch.o:	$(CRYPT_DEP) cryptmch.c
						$(CC) $(CFLAGS) cryptmch.c -o $(OBJPATH)cryptmch.o

$(OBJPATH)cryptmis.o:	$(CRYPT_DEP) cryptmis.c
						$(CC) $(CFLAGS) cryptmis.c -o $(OBJPATH)cryptmis.o

$(OBJPATH)cryptses.o:	$(CRYPT_DEP) cryptses.c
						$(CC) $(CFLAGS) cryptses.c -o $(OBJPATH)cryptses.o

$(OBJPATH)lib_3des.o:	$(CRYPT_DEP) cryptctx.h crypt/des.h lib_3des.c
						$(CC) $(CFLAGS) lib_3des.c -o $(OBJPATH)lib_3des.o

$(OBJPATH)lib_bf.o:		$(CRYPT_DEP) cryptctx.h crypt/blowfish.h lib_bf.c
						$(CC) $(CFLAGS) lib_bf.c -o $(OBJPATH)lib_bf.o

$(OBJPATH)lib_cast.o:	$(CRYPT_DEP) cryptctx.h crypt/cast.h lib_cast.c
						$(CC) $(CFLAGS) lib_cast.c -o $(OBJPATH)lib_cast.o

$(OBJPATH)lib_dbms.o:	$(CRYPT_DEP) misc/keyset.h lib_dbms.c
						$(CC) $(CFLAGS) lib_dbms.c -o $(OBJPATH)lib_dbms.o

$(OBJPATH)lib_des.o:	$(CRYPT_DEP) cryptctx.h crypt/testdes.h crypt/des.h \
						lib_des.c
						$(CC) $(CFLAGS) lib_des.c -o $(OBJPATH)lib_des.o

$(OBJPATH)lib_dh.o:		$(CRYPT_DEP) cryptctx.h bn/bn.h lib_dh.c
						$(CC) $(CFLAGS) lib_dh.c -o $(OBJPATH)lib_dh.o

$(OBJPATH)lib_dsa.o:	$(CRYPT_DEP) cryptctx.h bn/bn.h lib_dsa.c
						$(CC) $(CFLAGS) lib_dsa.c -o $(OBJPATH)lib_dsa.o

$(OBJPATH)lib_elg.o:	$(CRYPT_DEP) cryptctx.h bn/bn.h lib_elg.c
						$(CC) $(CFLAGS) lib_elg.c -o $(OBJPATH)lib_elg.o

$(OBJPATH)lib_hmd5.o:	$(CRYPT_DEP) cryptctx.h hash/md5.h lib_hmd5.c
						$(CC) $(CFLAGS) lib_hmd5.c -o $(OBJPATH)lib_hmd5.o

$(OBJPATH)lib_hrmd.o:	$(CRYPT_DEP) cryptctx.h hash/ripemd.h lib_hrmd.c
						$(CC) $(CFLAGS) lib_hrmd.c -o $(OBJPATH)lib_hrmd.o

$(OBJPATH)lib_hsha.o:	$(CRYPT_DEP) cryptctx.h hash/sha.h lib_hsha.c
						$(CC) $(CFLAGS) lib_hsha.c -o $(OBJPATH)lib_hsha.o

$(OBJPATH)lib_idea.o:	$(CRYPT_DEP) cryptctx.h crypt/idea.h lib_idea.c
						$(CC) $(CFLAGS) lib_idea.c -o $(OBJPATH)lib_idea.o

$(OBJPATH)lib_keyx.o:	$(CRYPT_DEP) cryptctx.h $(ASN1_DEP) lib_keyx.c
						$(CC) $(CFLAGS) lib_keyx.c -o $(OBJPATH)lib_keyx.o

$(OBJPATH)lib_kg.o:		$(CRYPT_DEP) cryptctx.h bn/bn_prime.h lib_kg.c
						$(CC) $(CFLAGS) lib_kg.c -o $(OBJPATH)lib_kg.o

$(OBJPATH)lib_md2.o:	$(CRYPT_DEP) cryptctx.h hash/md2.h lib_md2.c
						$(CC) $(CFLAGS) lib_md2.c -o $(OBJPATH)lib_md2.o

$(OBJPATH)lib_md4.o:	$(CRYPT_DEP) cryptctx.h hash/md4.h lib_md4.c
						$(CC) $(CFLAGS) lib_md4.c -o $(OBJPATH)lib_md4.o

$(OBJPATH)lib_md5.o:	$(CRYPT_DEP) cryptctx.h hash/md5.h lib_md5.c
						$(CC) $(CFLAGS) lib_md5.c -o $(OBJPATH)lib_md5.o

$(OBJPATH)lib_mdc2.o:	$(CRYPT_DEP) cryptctx.h hash/mdc2.h lib_mdc2.c
						$(CC) $(CFLAGS) lib_mdc2.c -o $(OBJPATH)lib_mdc2.o

$(OBJPATH)lib_rc2.o:	$(CRYPT_DEP) cryptctx.h crypt/rc2.h lib_rc2.c
						$(CC) $(CFLAGS) lib_rc2.c -o $(OBJPATH)lib_rc2.o

$(OBJPATH)lib_rc4.o:	$(CRYPT_DEP) cryptctx.h crypt/rc4.h lib_rc4.c
						$(CC) $(CFLAGS) lib_rc4.c -o $(OBJPATH)lib_rc4.o

$(OBJPATH)lib_rc5.o:	$(CRYPT_DEP) cryptctx.h crypt/rc5.h lib_rc5.c
						$(CC) $(CFLAGS) lib_rc5.c -o $(OBJPATH)lib_rc5.o

$(OBJPATH)lib_ripe.o:	$(CRYPT_DEP) cryptctx.h hash/ripemd.h lib_ripe.c
						$(CC) $(CFLAGS) lib_ripe.c -o $(OBJPATH)lib_ripe.o

$(OBJPATH)lib_rsa.o:	$(CRYPT_DEP) cryptctx.h bn/bn.h lib_rsa.c
						$(CC) $(CFLAGS) lib_rsa.c -o $(OBJPATH)lib_rsa.o

$(OBJPATH)lib_safr.o:	$(CRYPT_DEP) cryptctx.h crypt/safer.h lib_safr.c
						$(CC) $(CFLAGS) lib_safr.c -o $(OBJPATH)lib_safr.o

$(OBJPATH)lib_sha.o:	$(CRYPT_DEP) cryptctx.h hash/sha.h lib_sha.c
						$(CC) $(CFLAGS) lib_sha.c -o $(OBJPATH)lib_sha.o

$(OBJPATH)lib_sign.o:	$(CRYPT_DEP) cryptctx.h $(ASN1_DEP) lib_sign.c
						$(CC) $(CFLAGS) lib_sign.c -o $(OBJPATH)lib_sign.o

$(OBJPATH)lib_skip.o:	$(CRYPT_DEP) cryptctx.h lib_skip.c
						$(CC) $(CFLAGS) lib_skip.c -o $(OBJPATH)lib_skip.o

# bn subdirectory

$(OBJPATH)bn_add.o:		bn/bn.h bn/bn_lcl.h bn/bn_add.c
						$(CC) $(CFLAGS) bn/bn_add.c -o $(OBJPATH)bn_add.o

$(OBJPATH)bn_blind.o:	bn/bn.h bn/bn_lcl.h bn/bn_blind.c
						$(CC) $(CFLAGS) bn/bn_blind.c -o $(OBJPATH)bn_blind.o

$(OBJPATH)bn_div.o:		bn/bn.h bn/bn_lcl.h bn/bn_div.c
						$(CC) $(CFLAGS) bn/bn_div.c -o $(OBJPATH)bn_div.o

$(OBJPATH)bn_exp.o:		bn/bn.h bn/bn_lcl.h bn/bn_exp.c
						$(CC) $(CFLAGS) bn/bn_exp.c -o $(OBJPATH)bn_exp.o

$(OBJPATH)bn_gcd.o:		bn/bn.h bn/bn_lcl.h bn/bn_gcd.c
						$(CC) $(CFLAGS) bn/bn_gcd.c -o $(OBJPATH)bn_gcd.o

$(OBJPATH)bn_lib.o:		bn/bn.h bn/bn_lcl.h bn/bn_lib.c
						$(CC) $(CFLAGS) bn/bn_lib.c -o $(OBJPATH)bn_lib.o

$(OBJPATH)bn_mod.o:		bn/bn.h bn/bn_lcl.h bn/bn_mod.c
						$(CC) $(CFLAGS) bn/bn_mod.c -o $(OBJPATH)bn_mod.o

$(OBJPATH)bn_mont.o:	bn/bn.h bn/bn_lcl.h bn/bn_mont.c
						$(CC) $(CFLAGS) bn/bn_mont.c -o $(OBJPATH)bn_mont.o

$(OBJPATH)bn_mul.o:		bn/bn.h bn/bn_lcl.h bn/bn_mul.c
						$(CC) $(CFLAGS) bn/bn_mul.c -o $(OBJPATH)bn_mul.o

$(OBJPATH)bn_mulw.o:	bn/bn.h bn/bn_lcl.h bn/bn_mulw.c
						$(CC) $(CFLAGS) bn/bn_mulw.c -o $(OBJPATH)bn_mulw.o

$(OBJPATH)bn_recp.o:	bn/bn.h bn/bn_lcl.h bn/bn_recp.c
						$(CC) $(CFLAGS) bn/bn_recp.c -o $(OBJPATH)bn_recp.o

$(OBJPATH)bn_shift.o:	bn/bn.h bn/bn_lcl.h bn/bn_shift.c
						$(CC) $(CFLAGS) bn/bn_shift.c -o $(OBJPATH)bn_shift.o

$(OBJPATH)bn_sqr.o:		bn/bn.h bn/bn_lcl.h bn/bn_sqr.c
						$(CC) $(CFLAGS) bn/bn_sqr.c -o $(OBJPATH)bn_sqr.o

$(OBJPATH)bn_sub.o:		bn/bn.h bn/bn_lcl.h bn/bn_sub.c
						$(CC) $(CFLAGS) bn/bn_sub.c -o $(OBJPATH)bn_sub.o

$(OBJPATH)bn_word.o:	bn/bn.h bn/bn_lcl.h bn/bn_word.c
						$(CC) $(CFLAGS) bn/bn_word.c -o $(OBJPATH)bn_word.o

# crypt subdirectory

$(OBJPATH)bf_ecb.o:		crypt/bf_locl.h crypt/blowfish.h crypt/bf_ecb.c
						$(CC) $(CFLAGS) crypt/bf_ecb.c -o $(OBJPATH)bf_ecb.o

$(OBJPATH)bf_enc.o:		crypt/bf_locl.h crypt/blowfish.h crypt/bf_enc.c
						$(CC) $(CFLAGS) crypt/bf_enc.c -o $(OBJPATH)bf_enc.o

$(OBJPATH)bf_skey.o:	crypt/bf_locl.h crypt/bf_pi.h crypt/blowfish.h \
						crypt/bf_skey.c
						$(CC) $(CFLAGS) crypt/bf_skey.c -o $(OBJPATH)bf_skey.o

$(OBJPATH)c_ecb.o:		crypt/cast_lcl.h crypt/cast.h crypt/c_ecb.c
						$(CC) $(CFLAGS) crypt/c_ecb.c -o $(OBJPATH)c_ecb.o

$(OBJPATH)c_enc.o:		crypt/cast_lcl.h crypt/cast.h crypt/c_enc.c
						$(CC) $(CFLAGS) crypt/c_enc.c -o $(OBJPATH)c_enc.o

$(OBJPATH)c_skey.o:		crypt/cast_lcl.h crypt/cast.h crypt/cast_s.h \
						crypt/c_skey.c
						$(CC) $(CFLAGS) crypt/c_skey.c -o $(OBJPATH)c_skey.o

$(OBJPATH)des_enc.o:	crypt/des.h crypt/des_locl.h crypt/des_enc.c
						$(CC) $(CFLAGS) crypt/des_enc.c -o $(OBJPATH)des_enc.o

$(OBJPATH)ecb3_enc.o:	crypt/des.h crypt/des_locl.h crypt/ecb3_enc.c
						$(CC) $(CFLAGS) crypt/ecb3_enc.c -o $(OBJPATH)ecb3_enc.o

$(OBJPATH)ecb_enc.o:	crypt/des.h crypt/des_locl.h crypt/spr.h crypt/ecb_enc.c
						$(CC) $(CFLAGS) crypt/ecb_enc.c -o $(OBJPATH)ecb_enc.o

$(OBJPATH)ec_crypt.o:	$(ECC_DEP) crypt/ec_crypt.c
						$(CC) $(CFLAGS) -DUSE_BNLIB crypt/ec_crypt.c \
						-o $(OBJPATH)ec_crypt.o

$(OBJPATH)ec_curve.o:	$(ECC_DEP) crypt/ec_curve.c
						$(CC) $(CFLAGS) -DUSE_BNLIB crypt/ec_curve.c \
						-o $(OBJPATH)ec_curve.o

$(OBJPATH)ec_field.o:	$(ECC_DEP) crypt/ec_field.c
						$(CC) $(CFLAGS) -DUSE_BNLIB crypt/ec_field.c \
						-o $(OBJPATH)ec_field.o

$(OBJPATH)ec_param.o:	$(ECC_DEP) crypt/ec_param.c
						$(CC) $(CFLAGS) -DUSE_BNLIB crypt/ec_param.c \
						-o $(OBJPATH)ec_param.o

$(OBJPATH)ec_vlong.o:	$(ECC_DEP) crypt/ec_vlong.c
						$(CC) $(CFLAGS) -DUSE_BNLIB crypt/ec_vlong.c \
						-o $(OBJPATH)ec_vlong.o

$(OBJPATH)idea.o:		$(CRYPT_DEP) crypt/idea.h crypt/idea.c
						$(CC) $(CFLAGS) crypt/idea.c -o $(OBJPATH)idea.o

$(OBJPATH)rc2.o:		$(CRYPT_DEP) crypt/rc2.h crypt/rc2.c
						$(CC) $(CFLAGS) crypt/rc2.c -o $(OBJPATH)rc2.o

$(OBJPATH)rc4_enc.o:	crypt/rc4_locl.h crypt/rc4.h crypt/rc4_enc.c
						$(CC) $(CFLAGS) crypt/rc4_enc.c -o $(OBJPATH)rc4_enc.o

$(OBJPATH)rc4_skey.o:	crypt/rc4_locl.h crypt/rc4.h crypt/rc4_skey.c
						$(CC) $(CFLAGS) crypt/rc4_skey.c -o $(OBJPATH)rc4_skey.o

$(OBJPATH)rc5.o:		$(CRYPT_DEP) crypt/rc5.h crypt/rc5.c
						$(CC) $(CFLAGS) crypt/rc5.c -o $(OBJPATH)rc5.o

$(OBJPATH)safer.o:		$(CRYPT_DEP) crypt/safer.h crypt/safer.c
						$(CC) $(CFLAGS) crypt/safer.c -o $(OBJPATH)safer.o

$(OBJPATH)set_key.o:	crypt/des.h crypt/des_locl.h crypt/podd.h \
						crypt/sk.h crypt/set_key.c
						$(CC) $(CFLAGS) crypt/set_key.c -o $(OBJPATH)set_key.o

$(OBJPATH)skipjack.o:	crypt/skipjack.c
						$(CC) $(CFLAGS) crypt/skipjack.c -o $(OBJPATH)skipjack.o

# envelope subdirectory

$(OBJPATH)deenvel.o:	$(CRYPT_DEP) envelope/envelope.h $(ASN1_DEP) \
						envelope/deenvel.c
						$(CC) $(CFLAGS) envelope/deenvel.c -o $(OBJPATH)deenvel.o

$(OBJPATH)envelope.o:	$(CRYPT_DEP) envelope/envelope.h $(ASN1_DEP) \
						envelope/envelope.c
						$(CC) $(CFLAGS) envelope/envelope.c -o $(OBJPATH)envelope.o

$(OBJPATH)octetstr.o:	$(CRYPT_DEP) envelope/envelope.h $(ASN1_DEP) \
						envelope/octetstr.c
						$(CC) $(CFLAGS) envelope/octetstr.c -o $(OBJPATH)octetstr.o

$(OBJPATH)pgp_deen.o:	$(CRYPT_DEP) envelope/pgp.h envelope/pgp_deen.c
						$(CC) $(CFLAGS) envelope/pgp_deen.c \
						-o $(OBJPATH)pgp_deen.o

$(OBJPATH)pgp_misc.o:	$(CRYPT_DEP) envelope/pgp.h envelope/pgp_misc.c
						$(CC) $(CFLAGS) envelope/pgp_misc.c \
						-o $(OBJPATH)pgp_misc.o

$(OBJPATH)resource.o:	$(CRYPT_DEP) envelope/envelope.h envelope/resource.c
						$(CC) $(CFLAGS) envelope/resource.c -o \
						$(OBJPATH)resource.o

# hash subdirectory

$(OBJPATH)md2.o:		$(CRYPT_DEP) hash/md2.h hash/md2.c
						$(CC) $(CFLAGS) hash/md2.c -o $(OBJPATH)md2.o

$(OBJPATH)md4.o:		$(CRYPT_DEP) hash/md4.h hash/md4.c
						$(CC) $(CFLAGS) hash/md4.c -o $(OBJPATH)md4.o

$(OBJPATH)md5_dgst.o:	hash/md5.h hash/md5_locl.h hash/md5_dgst.c
						$(CC) $(CFLAGS) hash/md5_dgst.c -o $(OBJPATH)md5_dgst.o

$(OBJPATH)mdc2dgst.o:	hash/mdc2.h hash/mdc2dgst.c
						$(CC) $(CFLAGS) hash/mdc2dgst.c -o $(OBJPATH)mdc2dgst.o

$(OBJPATH)ripemd.o:		$(CRYPT_DEP) hash/ripemd.h hash/ripemd.c
						$(CC) $(CFLAGS) hash/ripemd.c -o $(OBJPATH)ripemd.o

$(OBJPATH)ripecore.o:	$(CRYPT_DEP) hash/ripemd.h hash/ripecore.c
						$(CC) $(CFLAGS) hash/ripecore.c -o $(OBJPATH)ripecore.o

$(OBJPATH)sha_dgst.o:	hash/sha.h hash/sha_locl.h hash/sha_dgst.c
						$(CC) $(CFLAGS) hash/sha_dgst.c -o $(OBJPATH)sha_dgst.o

$(OBJPATH)sha1dgst.o:	hash/sha.h hash/sha_locl.h hash/sha1dgst.c
						$(CC) $(CFLAGS) hash/sha1dgst.c -o $(OBJPATH)sha1dgst.o

# keymgmt subdirectory

$(OBJPATH)asn1.o:		$(CRYPT_DEP) $(ASN1_DEP) keymgmt/asn1.c
						$(CC) $(CFLAGS) keymgmt/asn1.c -o $(OBJPATH)asn1.o

$(OBJPATH)asn1keys.o:	$(CRYPT_DEP) $(ASN1_DEP) keymgmt/asn1keys.c
						$(CC) $(CFLAGS) keymgmt/asn1keys.c \
						-o $(OBJPATH)asn1keys.o

$(OBJPATH)asn1objs.o:	$(CRYPT_DEP) $(ASN1_DEP) keymgmt/asn1objs.c
						$(CC) $(CFLAGS) keymgmt/asn1objs.c \
						-o $(OBJPATH)asn1objs.o

$(OBJPATH)asn1oid.o:	$(CRYPT_DEP) $(ASN1_DEP) keymgmt/asn1oid.c
						$(CC) $(CFLAGS) keymgmt/asn1oid.c \
						-o $(OBJPATH)asn1oid.o

$(OBJPATH)cert.o:		$(CRYPT_DEP) $(ASN1_DEP) keymgmt/cert.h \
						keymgmt/cert.c
						$(CC) $(CFLAGS) keymgmt/cert.c -o $(OBJPATH)cert.o

$(OBJPATH)certchk.o:	$(CRYPT_DEP) $(ASN1_DEP) keymgmt/cert.h \
						keymgmt/certchk.c
						$(CC) $(CFLAGS) keymgmt/certchk.c \
						-o $(OBJPATH)certchk.o

$(OBJPATH)certchn.o:	$(CRYPT_DEP) $(ASN1_DEP) keymgmt/cert.h \
						keymgmt/certchn.c
						$(CC) $(CFLAGS) keymgmt/certchn.c \
						-o $(OBJPATH)certchn.o

$(OBJPATH)certcomp.o:	$(CRYPT_DEP) $(ASN1_DEP) keymgmt/cert.h \
						keymgmt/certcomp.c
						$(CC) $(CFLAGS) keymgmt/certcomp.c \
						-o $(OBJPATH)certcomp.o

$(OBJPATH)certechk.o:	$(CRYPT_DEP) $(ASN1_DEP) keymgmt/cert.h \
						keymgmt/certechk.c
						$(CC) $(CFLAGS) keymgmt/certechk.c \
						-o $(OBJPATH)certechk.o

$(OBJPATH)certedef.o:	$(CRYPT_DEP) $(ASN1_DEP) keymgmt/cert.h \
						keymgmt/certedef.c
						$(CC) $(CFLAGS) keymgmt/certedef.c \
						-o $(OBJPATH)certedef.o

$(OBJPATH)certexrw.o:	$(CRYPT_DEP) $(ASN1_DEP) keymgmt/cert.h \
						keymgmt/certexrw.c
						$(CC) $(CFLAGS) keymgmt/certexrw.c \
						-o $(OBJPATH)certexrw.o

$(OBJPATH)certext.o:	$(CRYPT_DEP) $(ASN1_DEP) keymgmt/cert.h \
						keymgmt/certext.c
						$(CC) $(CFLAGS) keymgmt/certext.c \
						-o $(OBJPATH)certext.o

$(OBJPATH)certio.o:		$(CRYPT_DEP) $(ASN1_DEP) keymgmt/cert.h \
						keymgmt/certio.c
						$(CC) $(CFLAGS) keymgmt/certio.c \
						-o $(OBJPATH)certio.o

$(OBJPATH)certsig.o:	$(CRYPT_DEP) keymgmt/asn1.h keymgmt/cert.h \
						keymgmt/certsig.c
						$(CC) $(CFLAGS) keymgmt/certsig.c -o $(OBJPATH)certsig.o

$(OBJPATH)certstr.o:	$(CRYPT_DEP) keymgmt/asn1.h keymgmt/cert.h \
						keymgmt/certstr.c
						$(CC) $(CFLAGS) keymgmt/certstr.c -o $(OBJPATH)certstr.o

$(OBJPATH)certrust.o:	$(CRYPT_DEP) keymgmt/asn1.h keymgmt/cert.h \
						keymgmt/certrust.c
						$(CC) $(CFLAGS) keymgmt/certrust.c -o $(OBJPATH)certrust.o

$(OBJPATH)cms.o:		$(CRYPT_DEP) $(ASN1_DEP) keymgmt/cert.h \
						keymgmt/cms.c
						$(CC) $(CFLAGS) keymgmt/cms.c \
						-o $(OBJPATH)cms.o

$(OBJPATH)stream.o:		$(CRYPT_DEP) $(ASN1_DEP) keymgmt/stream.c
						$(CC) $(CFLAGS) keymgmt/stream.c \
						-o $(OBJPATH)stream.o

# misc subdirectory

$(OBJPATH)dbxhttp.o:	$(CRYPT_DEP) misc/keyset.h misc/dbxhttp.c
						$(CC) $(CFLAGS) misc/dbxhttp.c -o $(OBJPATH)dbxhttp.o

$(OBJPATH)dbxldap.o:	$(CRYPT_DEP) misc/keyset.h misc/dbxldap.c
						$(CC) $(CFLAGS) misc/dbxldap.c -o $(OBJPATH)dbxldap.o

$(OBJPATH)dbxmsql.o:	$(CRYPT_DEP) misc/keyset.h misc/dbxmsql.c
						$(CC) $(CFLAGS) misc/dbxmsql.c -o $(OBJPATH)dbxmsql.o

$(OBJPATH)dbxmysql.o:	$(CRYPT_DEP) misc/keyset.h misc/dbxmysql.c
						$(CC) $(CFLAGS) misc/dbxmysql.c -o $(OBJPATH)dbxmysql.o

$(OBJPATH)dbxoracl.o:	$(CRYPT_DEP) misc/keyset.h misc/dbxoracl.c
						$(CC) $(CFLAGS) misc/dbxoracl.c -o $(OBJPATH)dbxoracl.o

$(OBJPATH)dbxpgp.o:		$(CRYPT_DEP) envelope/pgp.h misc/dbxpgp.c
						$(CC) $(CFLAGS) misc/dbxpgp.c -o $(OBJPATH)dbxpgp.o

$(OBJPATH)dbxpk12.o:	$(CRYPT_DEP) misc/keyset.h misc/dbxpk12.c
						$(CC) $(CFLAGS) misc/dbxpk12.c -o $(OBJPATH)dbxpk12.o

$(OBJPATH)dbxpk15.o:	$(CRYPT_DEP) misc/keyset.h misc/dbxpk15.c
						$(CC) $(CFLAGS) misc/dbxpk15.c -o $(OBJPATH)dbxpk15.o

$(OBJPATH)dbxpostg.o:	$(CRYPT_DEP) misc/keyset.h misc/dbxpostg.c
						$(CC) $(CFLAGS) misc/dbxpostg.c -o $(OBJPATH)dbxpostg.o

$(OBJPATH)dbxscard.o:	$(CRYPT_DEP) misc/keyset.h misc/scard.h misc/dbxscard.c
						$(CC) $(CFLAGS) misc/dbxscard.c -o $(OBJPATH)dbxscard.o

$(OBJPATH)dev_fort.o:	$(CRYPT_DEP) misc/device.h misc/dev_fort.c
						$(CC) $(CFLAGS) misc/dev_fort.c -o $(OBJPATH)dev_fort.o

$(OBJPATH)dev_pk11.o:	$(CRYPT_DEP) misc/device.h misc/dev_pk11.c
						$(CC) $(CFLAGS) misc/dev_pk11.c -o $(OBJPATH)dev_pk11.o

$(OBJPATH)dev_sys.o:	$(CRYPT_DEP) misc/device.h misc/dev_sys.c
						$(CC) $(CFLAGS) misc/dev_sys.c -o $(OBJPATH)dev_sys.o

$(OBJPATH)net_tcp.o:	$(CRYPT_DEP) misc/net.h misc/net_tcp.c
						$(CC) $(CFLAGS) misc/net_tcp.c -o $(OBJPATH)net_tcp.o

$(OBJPATH)rndunix.o:	$(CRYPT_DEP) misc/random.h misc/rndunix.c
						$(CC) $(CFLAGS) misc/rndunix.c -o $(OBJPATH)rndunix.o

$(OBJPATH)scmisc.o:		misc/scard.h misc/scmisc.c
						$(CC) $(CFLAGS) misc/scmisc.c -o $(OBJPATH)scmisc.o

# session subdirectory 

$(OBJPATH)ssh.o:		misc/net.h session/session.h session/ssh.c
						$(CC) $(CFLAGS) session/ssh.c -o $(OBJPATH)ssh.o

$(OBJPATH)ssl.o:		misc/net.h session/session.h session/ssl.c
						$(CC) $(CFLAGS) session/ssl.c -o $(OBJPATH)ssl.o

# zlib subdirectory

$(OBJPATH)adler32.o:	$(ZLIB_DEP) zlib/adler32.c
						$(CC) $(CFLAGS) zlib/adler32.c -o $(OBJPATH)adler32.o

$(OBJPATH)deflate.o:	$(ZLIB_DEP) zlib/deflate.c
						$(CC) $(CFLAGS) zlib/deflate.c -o $(OBJPATH)deflate.o

$(OBJPATH)infblock.o:	$(ZLIB_DEP) zlib/infblock.h zlib/inftrees.h \
						zlib/infcodes.h zlib/infutil.h zlib/infblock.c
						$(CC) $(CFLAGS) zlib/infblock.c \
						-o $(OBJPATH)infblock.o

$(OBJPATH)infcodes.o:	$(ZLIB_DEP) zlib/infblock.h zlib/inffast.h \
						zlib/inftrees.h zlib/infcodes.h zlib/infutil.h \
						zlib/infcodes.c
						$(CC) $(CFLAGS) zlib/infcodes.c \
						-o $(OBJPATH)infcodes.o

$(OBJPATH)inffast.o:	$(ZLIB_DEP) zlib/infblock.h zlib/inffast.h \
						zlib/inftrees.h zlib/infcodes.h zlib/infutil.h \
						zlib/inffast.c
						$(CC) $(CFLAGS) zlib/inffast.c \
						-o $(OBJPATH)inffast.o

$(OBJPATH)inflate.o:	$(ZLIB_DEP) zlib/infblock.h zlib/inflate.c
						$(CC) $(CFLAGS) zlib/inflate.c -o $(OBJPATH)inflate.o

$(OBJPATH)inftrees.o:	$(ZLIB_DEP) zlib/inftrees.h zlib/inftrees.c
						$(CC) $(CFLAGS) zlib/inftrees.c \
						-o $(OBJPATH)inftrees.o

$(OBJPATH)infutil.o:	$(ZLIB_DEP) zlib/infblock.h zlib/inffast.h \
						zlib/inftrees.h zlib/infcodes.h zlib/infutil.c
						$(CC) $(CFLAGS) zlib/infutil.c -o $(OBJPATH)infutil.o

$(OBJPATH)trees.o:		$(ZLIB_DEP) zlib/trees.c
						$(CC) $(CFLAGS) zlib/trees.c -o $(OBJPATH)trees.o

$(OBJPATH)zutil.o:		$(ZLIB_DEP) zlib/zutil.c
						$(CC) $(CFLAGS) zlib/zutil.c -o $(OBJPATH)zutil.o

# Build the asm equivalents of various C modules.  These are built before any
# other files and override the .o's which are produced by compiling the C
# equivalents of the asm files, so that (provided the build succeeds) the .o
# files which would be created from the C code will never be created because
# the asm-derived .o's already exist.
#
# Since these targets aren't files, we can't use make to build them as
# required (actually some makes will allow two sets of dependencies for a
# target, but this doesn't give us any control over whether we want the .o
# built from the .s or the .c).  A workaround for this is to use a quick
# shell hack to only build the files if they don't already exist - this is
# OK since they'll only be built once.
#
# The following pseudo-dependencies build the x86 asm modules, which cover
# every major encryption algorithm and the bignum code.

asm_bf:					crypt/bx86unix.cpp
						@if [ ! -f $(OBJPATH)bf_enc.o ] ; \
						then $(CPP) -D$(ASMFLAGS) crypt/bx86unix.cpp | \
						$(AS) -o $(OBJPATH)bf_enc.o ; fi

asm_bn:					bn/bn86unix.cpp
						@if [ ! -f $(OBJPATH)bn_mulw.o ] ; \
						then $(CPP) -D$(ASMFLAGS) bn/bn86unix.cpp | \
						$(AS) -o $(OBJPATH)bn_mulw.o ; fi

asm_cast:				crypt/cx86unix.cpp
						@if [ ! -f $(OBJPATH)castcore.o ] ; \
						then $(CPP) -D$(ASMFLAGS) crypt/cx86unix.cpp | \
						$(AS) -o $(OBJPATH)c_enc.o ; fi

asm_des:				crypt/dx86unix.cpp
						@if [ ! -f $(OBJPATH)des_enc.o ] ; \
						then $(CPP) -D$(ASMFLAGS) crypt/dx86unix.cpp | \
						$(AS) -o $(OBJPATH)des_enc.o ; fi

asm_rc4:				crypt/rx86unix.cpp
						@if [ ! -f $(OBJPATH)rc4_enc.o ] ; \
						then $(CPP) -D$(ASMFLAGS) crypt/rx86unix.cpp | \
						$(AS) -o $(OBJPATH)rc4_enc.o ; fi

asm_md5:				hash/mx86unix.cpp
						@if [ ! -f $(OBJPATH)md5core.o ] ; \
						then $(CPP) -D$(ASMFLAGS) hash/mx86unix.cpp | \
						$(AS) -o $(OBJPATH)md5core.o ; fi

asm_sha1:				hash/sx86unix.cpp
						@if [ ! -f $(OBJPATH)sha1core.o ] ; \
						then $(CPP) -D$(ASMFLAGS) hash/sx86unix.cpp | \
						$(AS) -o $(OBJPATH)sha1core.o ; fi

asm_ripemd:				hash/asm.h hash/rmd160cp.S
						@if [ ! -f $(OBJPATH)ripecore.o ] ; \
						then $(CPP) -D$(ASMFLAGS) hash/rmd160cp.S | \
						$(AS) -o $(OBJPATH)ripecore.o ; fi

		# The kludge in the first line is necessary for &%#^$%^#& gcc
		# which refuses to preprocess a file even if explicitly told to
		# using -E if it doesn't like the extension on the file.  In
		# addition this comment has to be above the depedency, since some
		# versions of GNU make will echo it to the screen if it's below
		# it.

asm_targets:
		@if [ ! -f hash/rmd160cp.S ] ; \
			then mv hash/rmd160cp.s hash/rmd160cp.S ; fi
		@make asm_bf ASMFLAGS=$(ASMFLAGS)
		@make asm_bn ASMFLAGS=$(ASMFLAGS)
		@make asm_cast ASMFLAGS=$(ASMFLAGS)
		@make asm_des ASMFLAGS=$(ASMFLAGS)
		@make asm_md5 ASMFLAGS=$(ASMFLAGS)
		@make asm_sha1 ASMFLAGS=$(ASMFLAGS)
		@make asm_rc4 ASMFLAGS=$(ASMFLAGS)
		@make asm_ripemd ASMFLAGS=$(ASMFLAGS)

# The pseudo-dependencies to build the asm modules for other processors.
# Only the bignum code is done in asm for these.

asm_alpha:				bn/alpha.s
						$(AS) bn/alpha.s -o $(OBJPATH)bn_mulw.o

asm_phux:				bn/pa-risc2.s
						$(AS) bn/pa-risc2.s -o $(OBJPATH)bn_mulw.o

asm_mips:				bn/r3000.s
						$(AS) bn/r3000.s -o $(OBJPATH)bn_mulw.o

asm_sparc:				bn/sparc.s
						$(AS) bn/sparc.s -o $(OBJPATH)bn_mulw.o

# The test program

certinst.o:				cryptlib.h crypt.h test/test.h test/certinst.c
						$(CC) $(CFLAGS) test/certinst.c

certutil.o:				cryptlib.h crypt.h test/test.h test/certutil.c
						$(CC) $(CFLAGS) test/certutil.c

testcert.o:				cryptlib.h crypt.h test/test.h test/testcert.c
						$(CC) $(CFLAGS) test/testcert.c

testenv.o:				cryptlib.h crypt.h test/test.h test/testenv.c
						$(CC) $(CFLAGS) test/testenv.c

testhl.o:				cryptlib.h crypt.h test/test.h test/testhl.c
						$(CC) $(CFLAGS) test/testhl.c

testkey.o:				cryptlib.h crypt.h test/test.h test/testkey.c
						$(CC) $(CFLAGS) test/testkey.c

testlib.o:				cryptlib.h crypt.h test/test.h test/testlib.c
						$(CC) $(CFLAGS) test/testlib.c

# Create the library, either as a static or shared library.  The main test
# program is also listed as a dependency since we need to use OS-specific
# compiler options for it which a simple 'make testlib' won't give us (the
# test program checks whether the compiler options were set correctly when
# building the library, so it needs to include a few library-specific files
# which wouldn't be used in an normal program).
#
# The use of ar and ranlib is rather system-dependant.  Some ar's (eg OSF1)
# create the .SYMDEF file by default, some require the 's' option, and some
# require the use of ranlib altogether because ar doesn't recognise the 's'
# option.  The following first tries 'ar rcs' (which works on most systems)
# and if that fails falls back to 'ar rc' followed by ranlib.
#
# Building the shared library is even more system-dependant, we check for
# various OS's we know about and adjust the link as appropriate.  Bug alert:
# PHUX is sensitive to whitespace at the end of the line, accidentally leaving
# a space after the '\' leads to bizarre error messages.

$(LIBPATH)$(LIBNAME):	$(OBJS) certutil.o testcert.o testenv.o testhl.o \
						testkey.o testlib.o
						@ar rcs $(LIBPATH)$(LIBNAME) $(OBJS) || \
						( ar rc $(LIBPATH)$(LIBNAME) $(OBJS) && \
						  ranlib $(LIBPATH)$(LIBNAME) )

$(LIBPATH)$(SLIBNAME):	$(OBJS) certutil.o testcert.o testenv.o testhl.o \
						testkey.o testlib.o
						@if [ `uname` = 'HP-UX' ] ; \
							then ld -b -o lib$(PROJ).sl $(OBJS) ; \
							strip lib$(PROJ).sl ; \
						else \
							$(SLD) -o $(LIBPATH)$(SLIBNAME) $(OBJS) ; \
							strip $(LIBPATH)$(SLIBNAME) ; \
						fi

# Link everything into the test programs.  Some OS's require the linking of
# a special library (usually libw.a) for widechar support, since the shared
# library is built with ld we can include this via LIBS but the static
# library is build with ar and this doesn't work (we could use ld -o, but
# this is somewhat ugly).  In addition where the OS supports threads we also
# need to link in the thread library.  To link things correctly, we test for
# the OS's which require special libraries as part of the link command and
# add the correct linker flags (usually -lw for the i18n support and -lthread
# for threading support) as appropriate.  The OS's which are known to require
# special libraries, and the required libraries, are:
#
#	Irix:				-lw
#	SunOS 5 (Slowaris):	-lw -lthread
#	BSDI:				-lgcc
#	OSF1/DEC Unix:		-lpthread
#	AIX:				-lpthreads
#
# After the shared stuff is built, you can test it with:
#
#	/sbin/ldconfig . >& /dev/null
#	LD_LIBRARY_PATH=.
#	ldd ./testlib

testlib:	$(LIBNAME) certutil.o testcert.o testenv.o testhl.o testkey.o testlib.o
			@if [ `uname` = 'IRIX' ] || [ `uname` = 'IRIX32' ] ; \
				then $(LD) -o testlib $(LDFLAGS) certutil.o testcert.o \
				testenv.o testhl.o testkey.o testlib.o -L. -l$(PROJ) -lw \
				$(TESTLIBS) ; \
			elif [ `uname` = 'SunOS' ] && [ `uname -r | tr -d '[A-Z].' | cut -c 1` = '5' ] ; \
				then $(LD) -o testlib $(LDFLAGS) certutil.o testcert.o \
				testenv.o testhl.o testkey.o testlib.o -L. -l$(PROJ) -lw \
				-lthread $(TESTLIBS) ; \
			elif [ `uname` = 'BSD/OS' ] ; \
				then $(LD) -o testlib $(LDFLAGS) certutil.o testcert.o \
				testenv.o testhl.o testkey.o testlib.o -L. -l$(PROJ) -lgcc \
				$(TESTLIBS) ; \
			elif [ `uname` = 'OSF1' ] ; \
				then $(LD) -o testlib $(LDFLAGS) certutil.o testcert.o \
				testenv.o testhl.o testkey.o testlib.o -L. -l$(PROJ) \
				-lpthread $(TESTLIBS) ; \
			elif [ `uname` = 'AIX' ] ; \
				then $(LD) -o testlib $(LDFLAGS) certutil.o testcert.o \
				testenv.o testhl.o testkey.o testlib.o -L. -l$(PROJ) \
				-lpthreads $(TESTLIBS) ; \
			else \
				$(LD) -o testlib $(LDFLAGS) certutil.o testcert.o testenv.o \
				testhl.o testkey.o testlib.o -L. -l$(PROJ) $(TESTLIBS) ; \
			fi

certinst:	$(LIBNAME) certinst.o
			@if [ `uname` = 'IRIX' ] || [ `uname` = 'IRIX32' ] ; \
				then $(LD) -o certinst $(LDFLAGS) certinst.o -L. -l$(PROJ) \
				-lw $(TESTLIBS) ; \
			elif [ `uname` = 'SunOS' ] && [ `uname -r | tr -d '[A-Z].' | cut -c 1` = '5' ] ; \
				then $(LD) -o certinst $(LDFLAGS) certinst.o -L. -l$(PROJ) \
				-lw -lthread $(TESTLIBS) ; \
			elif [ `uname` = 'BSD/OS' ] ; \
				then $(LD) -o certinst $(LDFLAGS) certinst.o -L. -l$(PROJ) \
				-lgcc $(TESTLIBS) ; \
			elif [ `uname` = 'OSF1' ] ; \
				then $(LD) -o certinst $(LDFLAGS) certinst.o -L. -l$(PROJ) \
				-lpthread $(TESTLIBS) ; \
			elif [ `uname` = 'AIX' ] ; \
				then $(LD) -o certinst $(LDFLAGS) certinst.o -L. -l$(PROJ) \
				-lpthreads $(TESTLIBS) ; \
			else \
				$(LD) -o certinst $(LDFLAGS) certinst.o -L. -l$(PROJ) \
				$(TESTLIBS) ; \
			fi

stestlib:	certutil.o testcert.o testenv.o testhl.o testkey.o testlib.o
			@$(LD) -o testlib $(LDFLAGS) certutil.o testcert.o testenv.o \
			testhl.o testkey.o testlib.o $(SLIBNAME)

#****************************************************************************
#*																			*
#*						Defines for each variation of Unix					*
#*																			*
#****************************************************************************

# Aches: A vaguely Unix-compatible OS designed by IBM.

AIX:
		@make $(DEFINES) CFLAGS="$(CFLAGS) -O2"

# Apollo:

Apollo:
		@make $(DEFINES) CFLAGS="$(CFLAGS) -O4"

# AUX: su root; rm -rf /; echo "Now install MkLinux"

A/UX:
		@make $(DEFINES) CFLAGS="$(CFLAGS) -O4"

# Millions of Intel BSD's (many are really BSE's, with incredibly archaic
#						  development tools and libs): cc is gcc except when
#						  it isn't.

BSD386:
		@make asm_targets ASMFLAGS=BSDI
		@make $(DEFINES) CFLAGS="$(CFLAGS) -fomit-frame-pointer -O3 -DASM_X86"
iBSD:
		@make asm_targets ASMFLAGS=BSDI
		@make $(DEFINES) CFLAGS="$(CFLAGS) -fomit-frame-pointer -O3 -DASM_X86"
BSD/OS:
		@echo "The most common version of this OS uses an incredibly old version of as"
		@echo "which doesn't handle 486 opcodes, so the asm code is disabled by default."
		@echo "If you've upgraded to a newer as, uncomment the 'make asm_targets' line"
		@echo "in the BSD/OS section of the makefile to use the much faster asm code."
		@echo "You may also need to play with the compiler type, since the default is an "
		@echo "equally archaic version of gcc."
#		@make asm_targets CPP="gcc -E" ASMFLAGS=BSDI
		@make $(DEFINES) CC=gcc CFLAGS="$(CFLAGS) -fomit-frame-pointer -O3 -DASM_X86"
FreeBSD:
		@echo "The most common version of this OS uses an incredibly old version of as"
		@echo "which doesn't handle 486 opcodes, so the asm code is disabled by default."
		@echo "If you've upgraded to a newer as, uncomment the 'make asm_targets' line"
		@echo "in the FreeBSD section of the makefile to use the much faster asm code."
#		@make asm_targets CPP="gcc -E" ASMFLAGS=BSDI
		@make $(DEFINES) CFLAGS="$(CFLAGS) -fomit-frame-pointer -O3 -DASM_X86"

# Convex:

Convex:
		@make $(DEFINES) CFLAGS="$(CFLAGS) -O4"

# DGUX: cc is a modified gcc.

dgux:
		@make $(DEFINES) CFLAGS="$(CFLAGS) -ansi -fomit-frame-pointer -O3"

# Esix: wall "Run away!!! Run away!!!"; newfs /dev/userdisk

# PHUX: A SYSVR2 layer with a SYSVR3 glaze on top of an adapted BSD 4.2
#		kernel.  Use cc, the exact incantation varies somewhat depending on
#		which version of PHUX you're running.  For 9.x you need to use
#		'-Aa -D_HPUX_SOURCE' to get the compiler into ANSI mode, in 10.x this
#		changed to just '-Ae', and after 10.30 -Ae was the default mode.
#		With PA-RISC 2 you should probably also define +DD64 to compile in
#		64-bit mode under PHUX 11.x.  In addition the PHUX compilers don't
#		recognise -On like the rest of the universe but use +On instead so if
#		you're using gcc instead of cc/c89 you'll need to change things to:
#
#			@make $(DEFINES) CFLAGS="$(CFLAGS) -fomit-frame-pointer -O3"
#
#		Newer compilers can use +Oall to apply all optimisations (even the
#		dodgy ones).  Typically going from +O2 -> +O3 -> +O4 gives a ~10-15%
#		improvement at each step.  Finally, when making the shared lib you 
#		can only use +O2, not +O3, because it gives the compiler the speed 
#		wobbles.
#
#		Note that the PHUX compilers (especially the earlier ones) are 
#		horribly broken and will produce all sorts of of bogus warnings of 
#		non-problems, eg:
#
#			/usr/ccs/bin/ld: (Warning) Quadrant change in relocatable 
#							 expression in subspace $CODE$
#
#		(translation: Klingons off the starboard bow!).  The code contains 
#		workarounds for non-errors (for example applying a cast to anything 
#		magically turns it into an rvalue), but it's not worth fixing the 
#		warnings for something like this.

HP-UX:
		@make asm_phux
		@make $(DEFINES) CFLAGS="$(CFLAGS) -Ae +O3"

# Irix: There's some sort of problem with r3000.s which means that
#		bn_mul_words never appears in the .o, for now we disable its
#		use and use the (somewhat slower) bn_mulw.c.  If someone can
#		figure out the problem it'll allow the slightly faster asm
#		code to be used.

IRIX:
#		@make asm_mips
		@make $(DEFINES) CFLAGS="$(CFLAGS) -O3" LIBS="$(LIBS) -lw"
IRIX64:
#		@make asm_mips
		@make $(DEFINES) CFLAGS="$(CFLAGS) -O3" LIBS="$(LIBS) -lw"

# ISC Unix: Use gcc

ISC:
		@make asm_targets ASMFLAGS=OUT
		@make $(DEFINES) CC=gcc CFLAGS="$(CFLAGS) -fomit-frame-pointer -O3 -DASM_X86"

# Linux: cc is gcc.  The 1e-5 users with rather old versions of Linux will
#		 need to make the asm targets with ASMFLAGS=OUT to build the a.out
#		 version of the asm core routines.

Linux:
		@make asm_targets ASMFLAGS=ELF
		@make $(DEFINES) CFLAGS="$(CFLAGS) -fomit-frame-pointer -O3 -DASM_X86"

LinuxPPC:
		@make $(DEFINES) CFLAGS="$(CFLAGS) -DBNINCLUDE=bnippc.h \
		-fomit-frame-pointer -O3" ASMOBJS=$(OBJPATH)bnippc.o

# MiNT: Use gcc

MiNT:
		@make $(DEFINES) CC=gcc CFLAGS="$(CFLAGS) -fomit-frame-pointer -O3"

# NeXT 3.0:

NeXT:
		@make $(DEFINES) LDFLAGS="-object -s"

# OSF 1: Use gcc and the asm version of the bn routines.  If you're using
#		 the OSF1 cc you need to use "-std1" to force ANSI compliance and
#		 change the optimization CFLAGS.  For gcc we need to specify
#		 -fno-asm since pthread.h includes c_asm.h which contains a
#		 declaration
#
#			long asm( const char *,...);
#
#		 which conflicst with the hcc asm keyword.  This asm stuff is only
#		 used when inline asm alternatives to the Posix threading functions
#		 are enabled which isn't done by default so in theory we could also
#		 fix this by defining asm to something else before including pthread.h,
#		 but it's safer to just turn off asm in gcc since it's not used
#		 anywhere.

OSF1:
		@make asm_alpha
		@make $(DEFINES) CC=gcc CFLAGS="$(CFLAGS) -fomit-frame-pointer \
		-fno-asm -O3"

# QNX 4.x:

QNX:
		@make asm_targets ASMFLAGS=ELF
		@make $(DEFINES) CFLAGS="$(CFLAGS) -O4 -DASM_X86"

# SCO: Unlike the entire rest of the world, SCO doesn't use -On, although it
#	   does recognise -O3 to mean "turn off pass 3 optimization".  The SCO cc
#	   is in fact a mutant version of Microsoft C 6.0, so we use the usual
#	   MSC optimization options except for the unsafe ones.  -Olx is
#	   equivalent to -Oegilt.  Unless SCO rewrote half the compiler when
#	   noone was looking, you won't be getting much optimization for your -O.
#
#	   Actually it turns out that the only thing you get with -Olx is
#	   compiler bugs, so we only use -O, and even with that you get internal
#	   compiler faults which it traps and forces a compiler restart on,
#	   presumably with optimisations disabled.
#
#	   SCO is basically too braindamaged to support any of the asm builds.
#	   as won't take input from stdin and dumps core on the crypto .S files,
#	   and cc/as barf on bni80386.s.  Even compiling the straight C code
#	   gives a whole slew of internal compiler errors/failed assertions.  If
#	   you have a setup which works (ie with GNU tools installed) then you
#	   can use the following to build the library.
#
#		@make asm_targets ASMFLAGS=ELF
#		@make $(DEFINES) CFLAGS="$(CFLAGS) -DBNINCLUDE=bni80386.h -O3 \
#		-DASM_X86" ASMOBJS=$(OBJPATH)bni80386.o
#
#	   For another taste of the wonderful SCO compiler, take the trivial lex
#	   example from the dragon book, lex it, and compile it.  Either the
#	   compiler will core dump from a SIGSEGV or the resulting program will
#	   from a SIGILL, depending on what level of optimization you use (a
#	   compiler that'll produce illegal code as output is pretty impressive).
#
#	   In addition the SCO cc ignores the path for output files and dumps the
#	   whole mess in the same directory as the source files.  This means you
#	   need to set STATIC_OBJ_PATH = . in order for the library to be built,
#	   however the following rule does this for you by forwarding down the
#	   $(TARGET) define rather than $(DEFINES) which also includes the output
#	   path.
#
#	   If you're building the shared version after building the static one
#	   you need to manually remove all the object files before trying to
#	   build it, although it's extremely unlikely that SCO can handle this
#	   anyway so it's probably not worth bothering with.
#
#	   Cool, the SCO comment is now longer than the comments for all the
#	   other Unix variants put together.

SCO:
		@echo "Please read the entry for SCO in the makefile before continuing."
		@make $(TARGET) CFLAGS="$(CFLAGS) -O"

# Sun/Slowaris: Use gcc.  If you're running Slowaris on an x86 box, you
#				should also make the various asm_xxx targets (see one of the
#				x86-derived targets for how to do this).  If you're using the
#				Sun compiler, use -Xt to switch it from Sun C to ANSI C mode.

SunOS:
		@if [ `uname -m` = 'i86pc' ] ; \
		then echo "To enable use of the x86 asm code please edit the Solaris makefile entry." ; \
		else make asm_sparc ; \
		fi
		@if [ `uname -r | tr -d '[A-Z].' | cut -c 1` = '5' ] ; \
		then make $(DEFINES) CC=gcc CFLAGS="$(CFLAGS) -fomit-frame-pointer \
		-O3" LIBS="$(LIBS) -lw" ; \
		else make $(DEFINES) CC=gcc CFLAGS="$(CFLAGS) -fomit-frame-pointer \
		-O3" ; \
		fi

# SVR4: Better results can be obtained by upgrading your OS to 4.4 BSD.
#		A few SVR4 unames don't report the OS name properly (eg SCO, Olivetti
#		Unix) so it's necessary to specify the SVR4 target on the command
#		line.  Note that SCO has a special-case target because of the weird
#		compiler it uses and multitudinous other SCO braindamage, so you
#		should use 'make SCO' (or, even better, 'make it go away') rather
#		than 'make SVR4'.

SVR4:
		@make $(DEFINES) CFLAGS="$(CFLAGS) -O3"

# Ultrix: Use vcc or gcc

ULTRIX:
		@make asm_mips
		@make $(DEFINES) CC=gcc CFLAGS="$(CFLAGS) -fomit-frame-pointer -O3"

# Amdahl UTS 4:

UTS4:
		@make $(DEFINES) CFLAGS="$(CFLAGS) -Xc -O4"

#****************************************************************************
#*																			*
#*								Defines for other OS's						*
#*																			*
#****************************************************************************

BeOS:
		@make $(DEFINES) CC=mwcc AR="mwcc -xml -o" \
		SLD="mwcc -xms -f crypt.exp" \
		CFLAGS="$(CFLAGS) -DBNINCLUDE=bnippc.h" ASMOBJS=$(OBJPATH)bnippc.o

#****************************************************************************
#*																			*
#*						Clean up after make has finished					*
#*																			*
#****************************************************************************

clean:
		rm -f $(STATIC_OBJ_PATH)*.o $(SHARED_OBJ_PATH)*.o *.o core testlib \
		stestlib endian $(LIBNAME) $(SLIBNAME)
