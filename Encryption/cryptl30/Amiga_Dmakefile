#****************************************************************************
#*																			*
#*						Makefile for the encryption library					*
#*																			*
#****************************************************************************

CC		= dcc -v -c

PROJ	= crypt
LIBNAME	= $(PROJ).lib

# Where object files go (/tmp is a good place)
OUTPATH	= DObjs/
# Extension for object files
OBJ		= .o

# Linker (just use the C compiler)
LD		= dcc -v
# Echo to screen command
ECHO	= echo
# The make command
MAKE	= dmake

# The object files which make up the library

OBJS	= $(OUTPATH)crypt$(OBJ) $(OUTPATH)lib_3des$(OBJ) $(OUTPATH)lib_des$(OBJ) $(OUTPATH)lib_idea$(OBJ) $(OUTPATH)lib_mdc$(OBJ) $(OUTPATH)lib_null$(OBJ) $(OUTPATH)lib_rc4$(OBJ) $(OUTPATH)idea$(OBJ) $(OUTPATH)3ecb_enc$(OBJ) $(OUTPATH)ecb_enc$(OBJ) $(OUTPATH)pcbc_enc$(OBJ) $(OUTPATH)set_key$(OBJ) $(OUTPATH)rc4$(OBJ) $(OUTPATH)shs$(OBJ)

#****************************************************************************
#*																			*
#*			If no args are given, print a usage message and exit			*
#*																			*
#****************************************************************************

default:	$(LIBNAME)

love:
		@$(ECHO) "Nicht wahr?"
		@$(ECHO)

#****************************************************************************
#*																			*
#*					Rules to build the encryption library					*
#*																			*
#****************************************************************************

# Main directory

$(OUTPATH)crypt$(OBJ):		crypt.h crypt.c
							$(CC) -o %(left) crypt.c

$(OUTPATH)lib_3des$(OBJ):	crypt.h libdes/des.h lib_3des.c
							$(CC) -o %(left) lib_3des.c

$(OUTPATH)lib_des$(OBJ):	crypt.h testdes.h libdes/des.h lib_des.c
							$(CC) -o %(left) lib_des.c

$(OUTPATH)lib_idea$(OBJ):	crypt.h idea/idea.h testidea.h lib_idea.c
							$(CC) -o %(left) lib_idea.c

$(OUTPATH)lib_mdc$(OBJ):	crypt.h mdc/shs.h lib_mdc.c
							$(CC) -o %(left) lib_mdc.c

$(OUTPATH)lib_null$(OBJ):	crypt.h lib_null.c
							$(CC) -o %(left) lib_null.c

$(OUTPATH)lib_rc4$(OBJ):	crypt.h testrc4.h rc4/rc4.h lib_rc4.c
							$(CC) -o %(left) lib_rc4.c

$(OUTPATH)test$(OBJ):		crypt.h test.c
							$(CC) -o %(left) test.c

# idea subdirectory

$(OUTPATH)idea$(OBJ):		idea/idea.h idea/idea.c
							$(CC) -o %(left) idea/idea.c

# libdes subdirectory

$(OUTPATH)3ecb_enc$(OBJ):	libdes/des.h libdes/des_locl.h libdes/3ecb_enc.c
							$(CC) -o %(left) libdes/3ecb_enc.c

$(OUTPATH)ecb_enc$(OBJ):	libdes/des.h libdes/des_locl.h libdes/spr.h libdes/version.h libdes/ecb_enc.c
							$(CC) -o %(left) libdes/ecb_enc.c

$(OUTPATH)pcbc_enc$(OBJ):	libdes/des.h libdes/des_locl.h libdes/pcbc_enc.c
							$(CC) -o %(left) libdes/pcbc_enc.c

$(OUTPATH)set_key$(OBJ):	libdes/des.h libdes/des_locl.h libdes/podd.h libdes/sk.h libdes/set_key.c
							$(CC) -o %(left) libdes/set_key.c

# rc4 subdirectory

$(OUTPATH)rc4$(OBJ):		rc4/rc4.h rc4/rc4.c
							$(CC) -o %(left) rc4/rc4.c

# mdc subdirectory

$(OUTPATH)shs$(OBJ):		mdc/shs.h mdc/shs.c
							$(CC) -o %(left) mdc/shs.c

# Create the library.  The test program is also listed as a dependancy
# since we need to use OS-specific compiler options for it which a
# simple 'make test' won't give us (yuck).

$(LIBNAME):					$(OBJS) $(OUTPATH)test$(OBJ)
							join as $(LIBNAME) $(OBJS)

# Link everything into a test program

test:	$(LIBNAME) $(OUTPATH)test$(OBJ)
		$(LD) -o testcrypt $(OUTPATH)test$(OBJ) -l$(PROJ)

#****************************************************************************
#*																			*
#*						Cleanup after make has finished						*
#*																			*
#****************************************************************************

clean:
		delete force #?.o testcrypt $(LIBNAME)
