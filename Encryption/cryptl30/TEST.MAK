# Microsoft Visual C++ generated build script - Do not modify

PROJ = TEST
DEBUG = 1
PROGTYPE = 3
CALLER = 
ARGS = 
DLLS = 
D_RCDEFINES = -d_DEBUG
R_RCDEFINES = -dNDEBUG
ORIGIN = MSVC
ORIGIN_VER = 1.00
PROJPATH = P:\WINDOWS\
USEMFC = 0
CC = cl
CPP = cl
CXX = cl
CCREATEPCHFLAG = 
CPPCREATEPCHFLAG = 
CUSEPCHFLAG = 
CPPUSEPCHFLAG = 
FIRSTC = TESTHL.C    
FIRSTCPP =             
RC = rc
CFLAGS_D_WTTY = /nologo /G2 /Mq /W3 /Zi /AL /Od /D "_DEBUG" /D "__WIN16__" /Fd"TEST.PDB"
CFLAGS_R_WTTY = /nologo /Gs /G2 /Mq /W3 /AL /Ox /D "NDEBUG" 
LFLAGS_D_WTTY = /NOLOGO /NOD /PACKC:57344 /ALIGN:16 /ONERROR:NOEXE /CO
LFLAGS_R_WTTY = /NOLOGO /NOD /PACKC:57344 /ALIGN:16 /ONERROR:NOEXE
LIBS_D_WTTY = oldnames libw llibcewq
LIBS_R_WTTY = oldnames libw llibcewq
RCFLAGS = /nologo
RESFLAGS = /nologo
RUNFLAGS = 
DEFFILE = TEST.DEF
OBJS_EXT = 
LIBS_EXT = CL16.LIB 
!if "$(DEBUG)" == "1"
CFLAGS = $(CFLAGS_D_WTTY)
LFLAGS = $(LFLAGS_D_WTTY)
LIBS = $(LIBS_D_WTTY)
MAPFILE = nul
RCDEFINES = $(D_RCDEFINES)
DEFFILE=P:\WINDOWS\TEST.DEF
!else
CFLAGS = $(CFLAGS_R_WTTY)
LFLAGS = $(LFLAGS_R_WTTY)
LIBS = $(LIBS_R_WTTY)
MAPFILE = nul
RCDEFINES = $(R_RCDEFINES)
DEFFILE=P:\WINDOWS\TEST.DEF
!endif
!if [if exist MSVC.BND del MSVC.BND]
!endif
SBRS = TESTHL.SBR \
		TESTLIB.SBR \
		TESTCERT.SBR \
		TESTENV.SBR \
		CERTUTIL.SBR \
		TESTKEY.SBR


CL16_DEP = 

TESTHL_DEP = p:\capi.h \
	p:\test/test.h \
	test/test.h


TESTLIB_DEP = p:\capi.h \
	p:\test/test.h \
	test/test.h \
	p:\crypt.h \
	p:\cryptos.h


TESTCERT_DEP = p:\capi.h \
	p:\test/test.h \
	test/test.h


TESTENV_DEP = p:\capi.h \
	p:\test/test.h \
	test/test.h


CERTUTIL_DEP = p:\capi.h \
	p:\test\test.h \
	test/test.h


TESTKEY_DEP = p:\capi.h \
	p:\test/test.h \
	test/test.h


all:	$(PROJ).EXE

TESTHL.OBJ:	..\TEST\TESTHL.C $(TESTHL_DEP)
	$(CC) $(CFLAGS) $(CCREATEPCHFLAG) /c ..\TEST\TESTHL.C

TESTLIB.OBJ:	..\TEST\TESTLIB.C $(TESTLIB_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\TEST\TESTLIB.C

TESTCERT.OBJ:	..\TEST\TESTCERT.C $(TESTCERT_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\TEST\TESTCERT.C

TESTENV.OBJ:	..\TEST\TESTENV.C $(TESTENV_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\TEST\TESTENV.C

CERTUTIL.OBJ:	..\TEST\CERTUTIL.C $(CERTUTIL_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\TEST\CERTUTIL.C

TESTKEY.OBJ:	..\TEST\TESTKEY.C $(TESTKEY_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\TEST\TESTKEY.C


$(PROJ).EXE::	TESTHL.OBJ TESTLIB.OBJ TESTCERT.OBJ TESTENV.OBJ CERTUTIL.OBJ TESTKEY.OBJ $(OBJS_EXT) $(DEFFILE)
	echo >NUL @<<$(PROJ).CRF
TESTHL.OBJ +
TESTLIB.OBJ +
TESTCERT.OBJ +
TESTENV.OBJ +
CERTUTIL.OBJ +
TESTKEY.OBJ +
$(OBJS_EXT)
$(PROJ).EXE
$(MAPFILE)
d:\msvc\lib\+
CL16.LIB+
$(LIBS)
$(DEFFILE);
<<
	link $(LFLAGS) @$(PROJ).CRF
	$(RC) $(RESFLAGS) $@


run: $(PROJ).EXE
	$(PROJ) $(RUNFLAGS)


$(PROJ).BSC: $(SBRS)
	bscmake @<<
/o$@ $(SBRS)
<<
