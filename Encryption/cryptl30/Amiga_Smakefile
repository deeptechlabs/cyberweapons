#****************************************************************************
#*																			*
#*						Makefile for the encryption library					*
#*																			*
#****************************************************************************

CC		= sc

PROJ	= crypt
LIBNAME	= $(PROJ).lib

OUTPATH	= SObjs/			# Where object files go (/tmp is a good place)
OBJ		= .o				# Extension for object files

LD		= $(CC) link		# Linker (just use the C compiler)
ECHO	= echo				# Echo to screen command
MAKE	= smake				# The make command

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
							$(CC) objname $@ crypt.c

$(OUTPATH)lib_3des$(OBJ):	crypt.h libdes/des.h lib_3des.c
							$(CC) objname $@ lib_3des.c

$(OUTPATH)lib_des$(OBJ):	crypt.h testdes.h libdes/des.h lib_des.c
							$(CC) objname $@ lib_des.c

$(OUTPATH)lib_idea$(OBJ):	crypt.h idea/idea.h testidea.h lib_idea.c
							$(CC) objname $@ lib_idea.c

$(OUTPATH)lib_mdc$(OBJ):	crypt.h mdc/shs.h lib_mdc.c
							$(CC) objname $@ lib_mdc.c

$(OUTPATH)lib_null$(OBJ):	crypt.h lib_null.c
							$(CC) objname $@ lib_null.c

$(OUTPATH)lib_rc4$(OBJ):	crypt.h testrc4.h rc4/rc4.h lib_rc4.c
							$(CC) objname $@ lib_rc4.c

$(OUTPATH)test$(OBJ):		crypt.h test.c
							$(CC) objname $@ test.c

# idea subdirectory

$(OUTPATH)idea$(OBJ):		idea/idea.h idea/idea.c
							$(CC) objname $@ idea/idea.c

# libdes subdirectory

$(OUTPATH)3ecb_enc$(OBJ):	libdes/des.h libdes/des_locl.h libdes/3ecb_enc.c
							$(CC) objname $@ libdes/3ecb_enc.c

$(OUTPATH)ecb_enc$(OBJ):	libdes/des.h libdes/des_locl.h libdes/spr.h libdes/version.h libdes/ecb_enc.c
							$(CC) objname $@ libdes/ecb_enc.c

$(OUTPATH)pcbc_enc$(OBJ):	libdes/des.h libdes/des_locl.h libdes/pcbc_enc.c
							$(CC) objname $@ libdes/pcbc_enc.c

$(OUTPATH)set_key$(OBJ):	libdes/des.h libdes/des_locl.h libdes/podd.h libdes/sk.h libdes/set_key.c
							$(CC) objname $@ libdes/set_key.c

# rc4 subdirectory

$(OUTPATH)rc4$(OBJ):		rc4/rc4.h rc4/rc4.c
							$(CC) objname $@ rc4/rc4.c

# mdc subdirectory

$(OUTPATH)shs$(OBJ):		mdc/shs.h mdc/shs.c
							$(CC) objname $@ mdc/shs.c

# Create the library.  The test program is also listed as a dependancy
# since we need to use OS-specific compiler options for it which a
# simple 'make test' won't give us (yuck).

$(LIBNAME):					$(OBJS) $(OUTPATH)test$(OBJ)
							oml -n -b $(LIBNAME) r $(OBJS)

# Link everything into a test program

test:	$(LIBNAME) $(OUTPATH)test$(OBJ)
		@$(LD) pname testcrypt $(OUTPATH)test$(OBJ) lib $(LIBNAME)

#****************************************************************************
#*																			*
#*						Cleanup after make has finished						*
#*																			*
#****************************************************************************

clean:
		delete force \#?.o testcrypt $(LIBNAME)
