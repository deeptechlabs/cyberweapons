# Microsoft Visual C++ generated build script - Do not modify

PROJ = RIPEM
DEBUG = 0
PROGTYPE = 4
CALLER = 
ARGS = 
DLLS = 
D_RCDEFINES = -d_DEBUG
R_RCDEFINES = -dNDEBUG
ORIGIN = MSVC
ORIGIN_VER = 1.00
PROJPATH = D:\CIP\RIPEM\MAIN\
USEMFC = 0
CC = cl
CPP = cl
CXX = cl
CCREATEPCHFLAG = 
CPPCREATEPCHFLAG = 
CUSEPCHFLAG = 
CPPUSEPCHFLAG = 
FIRSTC = BEMPARSE.C  
FIRSTCPP =             
RC = rc
CFLAGS_D_LIB = /nologo /Za /W3 /Z7 /AL /Od /D "_DEBUG" /D "MSDOS" /I "..\rsaref\source" /FR /GA 
CFLAGS_R_LIB = /nologo /Gs /Za /W3 /AL /Op- /Ox /D "NDEBUG" /I "..\rsaref\source" /FR /GA 
RCFLAGS = /nologo
RESFLAGS = /nologo
RUNFLAGS = 
OBJS_EXT = 
LIBS_EXT = 
!if "$(DEBUG)" == "1"
CFLAGS = $(CFLAGS_D_LIB)
LFLAGS = 
LIBS = 
MAPFILE = nul
RCDEFINES = $(D_RCDEFINES)
!else
CFLAGS = $(CFLAGS_R_LIB)
LFLAGS = 
LIBS = 
MAPFILE = nul
RCDEFINES = $(R_RCDEFINES)
!endif
!if [if exist MSVC.BND del MSVC.BND]
!endif
SBRS = BEMPARSE.SBR \
		BFSTREAM.SBR \
		CERTUTIL.SBR \
		CRACKHED.SBR \
		DERKEY.SBR \
		HEXBIN.SBR \
		KEYDER.SBR \
		KEYMAN.SBR \
		LIST.SBR \
		PUBINFO.SBR \
		RDWRMSG.SBR \
		RIPEMMAI.SBR \
		RIPEMSOC.SBR \
		STRUTIL.SBR


BEMPARSE_DEP = d:\cip\ripem\main\ripem.h \
	d:\cip\ripem\main\p.h \
	d:\cip\ripem\main\bemparse.h


BFSTREAM_DEP = d:\cip\ripem\main\ripem.h \
	d:\cip\ripem\main\p.h \
	d:\cip\ripem\main\bfstream.h


CERTUTIL_DEP = d:\cip\ripem\main\ripem.h \
	d:\cip\ripem\main\p.h \
	d:\cip\ripem\main\bfstream.h \
	d:\cip\ripem\main\certder.h \
	d:\cip\ripem\main\keyderpr.h \
	d:\cip\ripem\main\derkeypr.h \
	d:\cip\ripem\main\keyfield.h \
	d:\cip\ripem\main\pubinfop.h \
	d:\cip\ripem\main\certutil.h \
	d:\cip\ripem\main\keymanpr.h \
	d:\cip\ripem\main\headers.h \
	d:\cip\ripem\main\rdwrmsgp.h


CRACKHED_DEP = d:\cip\ripem\main\ripem.h \
	d:\cip\ripem\main\p.h \
	d:\cip\ripem\main\headers.h \
	d:\cip\ripem\main\bfstream.h \
	d:\cip\ripem\main\crackhpr.h \
	d:\cip\ripem\main\strutilp.h \
	d:\cip\ripem\main\hexbinpr.h \
	d:\cip\ripem\main\derkeypr.h \
	d:\cip\ripem\main\certder.h \
	d:\cip\ripem\main\certutil.h


DERKEY_DEP = d:\cip\ripem\main\ripem.h \
	d:\cip\ripem\main\p.h \
	d:\cip\ripem\main\derkeypr.h \
	d:\cip\ripem\main\certder.h


HEXBIN_DEP = d:\cip\ripem\main\hexbinpr.h


KEYDER_DEP = d:\cip\ripem\main\ripem.h \
	d:\cip\ripem\main\p.h \
	d:\cip\ripem\main\keyderpr.h \
	d:\cip\ripem\main\certder.h \
	d:\cip\ripem\main\derkeypr.h


KEYMAN_DEP = d:\cip\ripem\main\ripem.h \
	d:\cip\ripem\main\p.h \
	d:\cip\ripem\main\keyfield.h \
	d:\cip\ripem\main\keymanpr.h \
	d:\cip\ripem\main\strutilp.h \
	d:\cip\ripem\main\derkeypr.h \
	d:\cip\ripem\main\hexbinpr.h \
	d:\cip\ripem\main\ripemsop.h \
	d:\cip\ripem\main\pubinfop.h \
	d:\cip\ripem\main\keyderpr.h \
	d:\cip\ripem\main\bfstream.h \
	d:\cip\ripem\main\rdwrmsgp.h \
	d:\cip\ripem\main\certder.h \
	d:\cip\ripem\main\certutil.h \
	d:\cip\ripem\main\bemparse.h


LIST_DEP = d:\cip\ripem\main\ripem.h \
	d:\cip\ripem\main\p.h \
	d:\cip\ripem\main\strutilp.h


PUBINFO_DEP = d:\cip\ripem\main\ripem.h \
	d:\cip\ripem\main\p.h \
	d:\cip\ripem\main\headers.h \
	d:\cip\ripem\main\keyfield.h \
	d:\cip\ripem\main\pubinfop.h \
	d:\cip\ripem\main\protserv.h \
	d:\cip\ripem\main\strutilp.h


RDWRMSG_DEP = d:\cip\ripem\main\ripem.h \
	d:\cip\ripem\main\p.h \
	d:\cip\ripem\main\headers.h \
	d:\cip\ripem\main\bfstream.h \
	d:\cip\ripem\main\rdwrmsgp.h \
	d:\cip\ripem\main\strutilp.h


RIPEMMAI_DEP = d:\cip\ripem\main\ripem.h \
	d:\cip\ripem\main\p.h \
	d:\cip\ripem\main\headers.h \
	d:\cip\ripem\main\keyfield.h \
	d:\cip\ripem\main\strutilp.h \
	d:\cip\ripem\main\keyderpr.h \
	d:\cip\ripem\main\derkeypr.h \
	d:\cip\ripem\main\keymanpr.h \
	d:\cip\ripem\main\bemparse.h \
	d:\cip\ripem\main\hexbinpr.h \
	d:\cip\ripem\main\bfstream.h \
	d:\cip\ripem\main\crackhpr.h \
	d:\cip\ripem\main\rdwrmsgp.h \
	d:\cip\ripem\main\certder.h \
	d:\cip\ripem\main\certutil.h \
	d:\cip\ripem\main\version.h


RIPEMSOC_DEP = d:\cip\ripem\main\ripem.h \
	d:\cip\ripem\main\p.h \
	d:\cip\ripem\main\ripemsop.h \
	d:\cip\ripem\main\keyfield.h \
	d:\cip\ripem\main\protserv.h \
	d:\cip\ripem\main\strutilp.h \
	d:\cip\ripem\main\pubinfop.h


STRUTIL_DEP = d:\cip\ripem\main\ripem.h \
	d:\cip\ripem\main\p.h \
	d:\cip\ripem\main\strutilp.h \
	d:\cip\ripem\main\hexbinpr.h


all:  $(PROJ).LIB 

BEMPARSE.OBJ:  BEMPARSE.C $(BEMPARSE_DEP)
	$(CC) $(CFLAGS) $(CCREATEPCHFLAG) /c BEMPARSE.C

BFSTREAM.OBJ:  BFSTREAM.C $(BFSTREAM_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c BFSTREAM.C

CERTUTIL.OBJ:  CERTUTIL.C $(CERTUTIL_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c CERTUTIL.C

CRACKHED.OBJ:  CRACKHED.C $(CRACKHED_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c CRACKHED.C

DERKEY.OBJ: DERKEY.C $(DERKEY_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c DERKEY.C

HEXBIN.OBJ: HEXBIN.C $(HEXBIN_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c HEXBIN.C

KEYDER.OBJ: KEYDER.C $(KEYDER_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c KEYDER.C

KEYMAN.OBJ: KEYMAN.C $(KEYMAN_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c KEYMAN.C

LIST.OBJ:   LIST.C $(LIST_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c LIST.C

PEMFORMT.OBJ:  PEMFORMT.C
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c PEMFORMT.C

PKCFORMT.OBJ:  PKCFORMT.C
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c PKCFORMT.C

PUBINFO.OBJ:   PUBINFO.C $(PUBINFO_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c PUBINFO.C

RDWRMSG.OBJ:   RDWRMSG.C $(RDWRMSG_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c RDWRMSG.C

RIPEMMAI.OBJ:  RIPEMMAI.C $(RIPEMMAI_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c RIPEMMAI.C

RIPEMSOC.OBJ:  RIPEMSOC.C $(RIPEMSOC_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c RIPEMSOC.C

STRUTIL.OBJ:   STRUTIL.C $(STRUTIL_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c STRUTIL.C

$(PROJ).LIB::  BEMPARSE.OBJ BFSTREAM.OBJ CERTUTIL.OBJ CRACKHED.OBJ DERKEY.OBJ HEXBIN.OBJ \
	KEYDER.OBJ KEYMAN.OBJ LIST.OBJ PEMFORMT.OBJ PKCFORMT.PKC PUBINFO.OBJ RDWRMSG.OBJ RIPEMMAI.OBJ RIPEMSOC.OBJ \
	STRUTIL.OBJ $(OBJS_EXT)
	echo >NUL @<<$(PROJ).CRF
$@ /PAGESIZE:64
y
+BEMPARSE.OBJ &
+BFSTREAM.OBJ &
+CERTUTIL.OBJ &
+CRACKHED.OBJ &
+DERKEY.OBJ &
+HEXBIN.OBJ &
+KEYDER.OBJ &
+KEYMAN.OBJ &
+LIST.OBJ &
+PEMFORMT.OBJ &
+PKCFORMT.OBJ &
+PUBINFO.OBJ &
+RDWRMSG.OBJ &
+RIPEMMAI.OBJ &
+RIPEMSOC.OBJ &
+STRUTIL.OBJ &
;
<<
	if exist $@ del $@
	lib @$(PROJ).CRF

#$(PROJ).BSC: $(SBRS)
#   bscmake @<<
#/o$@ $(SBRS)
#<<
