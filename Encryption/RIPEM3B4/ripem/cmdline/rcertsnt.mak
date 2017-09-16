# Microsoft Developer Studio Generated NMAKE File, Based on rcertsnt.dsp
!IF "$(CFG)" == ""
CFG=rcertsnt - Win32 Release
!MESSAGE No configuration specified. Defaulting to rcertsnt - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "rcertsnt - Win32 Release" && "$(CFG)" !=\
 "rcertsnt - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "rcertsnt.mak" CFG="rcertsnt - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "rcertsnt - Win32 Release" (based on\
 "Win32 (x86) Console Application")
!MESSAGE "rcertsnt - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "rcertsnt - Win32 Release"

OUTDIR=.\rcertsnt
INTDIR=.\rcertsnt
# Begin Custom Macros
OutDir=.\rcertsnt
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\rcertsnt.exe"

!ELSE 

ALL : "$(OUTDIR)\rcertsnt.exe"

!ENDIF 

CLEAN :
   -@erase "$(INTDIR)\getopt.obj"
   -@erase "$(INTDIR)\getsys.obj"
   -@erase "$(INTDIR)\parsit.obj"
   -@erase "$(INTDIR)\rcerts.obj"
   -@erase "$(INTDIR)\rcertsms.obj"
   -@erase "$(INTDIR)\usage.obj"
   -@erase "$(INTDIR)\vc50.idb"
   -@erase "$(OUTDIR)\rcertsnt.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /ML /W3 /GX /O2 /I "..\rsaref\source" /I "..\main" /D "NDEBUG"\
 /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D "WINNT" /D "MSDOS"\
 /Fp"$(INTDIR)\rcertsnt.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\rcertsnt/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\rcertsnt.bsc" 
BSC32_SBRS= \
   
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib\
 odbccp32.lib /nologo /subsystem:console /incremental:no\
 /pdb:"$(OUTDIR)\rcertsnt.pdb" /machine:I386 /out:"$(OUTDIR)\rcertsnt.exe" 
LINK32_OBJS= \
   "$(INTDIR)\getopt.obj" \
   "$(INTDIR)\getsys.obj" \
   "$(INTDIR)\parsit.obj" \
   "$(INTDIR)\rcerts.obj" \
   "$(INTDIR)\rcertsms.obj" \
   "$(INTDIR)\usage.obj" \
   "..\main\Release\mainnt.lib" \
   "..\rsaref\install\rsarefnt\rsarefnt.lib"

"$(OUTDIR)\rcertsnt.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "rcertsnt - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\rcertsnt.exe"

!ELSE 

ALL : "$(OUTDIR)\rcertsnt.exe"

!ENDIF 

CLEAN :
   -@erase "$(INTDIR)\getopt.obj"
   -@erase "$(INTDIR)\getsys.obj"
   -@erase "$(INTDIR)\parsit.obj"
   -@erase "$(INTDIR)\rcerts.obj"
   -@erase "$(INTDIR)\rcertsms.obj"
   -@erase "$(INTDIR)\usage.obj"
   -@erase "$(INTDIR)\vc50.idb"
   -@erase "$(INTDIR)\vc50.pdb"
   -@erase "$(OUTDIR)\rcertsnt.exe"
   -@erase "$(OUTDIR)\rcertsnt.ilk"
   -@erase "$(OUTDIR)\rcertsnt.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MLd /W3 /Gm /GX /Zi /Od /I "..\rsaref\source" /I "..\main" /D\
 "_DEBUG" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D "WINNT" /D "MSDOS"\
 /Fp"$(INTDIR)\rcertsnt.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\rcertsnt.bsc" 
BSC32_SBRS= \
   
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib\
 odbccp32.lib /nologo /subsystem:console /incremental:yes\
 /pdb:"$(OUTDIR)\rcertsnt.pdb" /debug /machine:I386\
 /out:"$(OUTDIR)\rcertsnt.exe" /pdbtype:sept 
LINK32_OBJS= \
   "$(INTDIR)\getopt.obj" \
   "$(INTDIR)\getsys.obj" \
   "$(INTDIR)\parsit.obj" \
   "$(INTDIR)\rcerts.obj" \
   "$(INTDIR)\rcertsms.obj" \
   "$(INTDIR)\usage.obj" \
   "..\main\Release\mainnt.lib" \
   "..\rsaref\install\rsarefnt\rsarefnt.lib"

"$(OUTDIR)\rcertsnt.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 

.c{$(CPP_OBJS)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(CPP_OBJS)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(CPP_OBJS)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(CPP_SBRS)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(CPP_SBRS)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(CPP_SBRS)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<


!IF "$(CFG)" == "rcertsnt - Win32 Release" || "$(CFG)" ==\
 "rcertsnt - Win32 Debug"
SOURCE=.\getopt.c
DEP_CPP_GETOP=\
   ".\getoptpr.h"\
   

"$(INTDIR)\getopt.obj" : $(SOURCE) $(DEP_CPP_GETOP) "$(INTDIR)"


SOURCE=.\getsys.c

!IF  "$(CFG)" == "rcertsnt - Win32 Release"

DEP_CPP_GETSY=\
   "..\main\p.h"\
   "..\main\ripem.h"\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\getsyspr.h"\
   

"$(INTDIR)\getsys.obj" : $(SOURCE) $(DEP_CPP_GETSY) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "rcertsnt - Win32 Debug"

DEP_CPP_GETSY=\
   "..\main\p.h"\
   "..\main\ripem.h"\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\getsyspr.h"\
   {$(INCLUDE)}"sys\stat.h"\
   {$(INCLUDE)}"sys\types.h"\
   {$(INCLUDE)}"unistd.h"\
   

"$(INTDIR)\getsys.obj" : $(SOURCE) $(DEP_CPP_GETSY) "$(INTDIR)"


!ENDIF 

SOURCE=.\parsit.c
DEP_CPP_PARSI=\
   ".\parsitpr.h"\
   

"$(INTDIR)\parsit.obj" : $(SOURCE) $(DEP_CPP_PARSI) "$(INTDIR)"


SOURCE=.\rcerts.c

!IF  "$(CFG)" == "rcertsnt - Win32 Release"

DEP_CPP_RCERT=\
   "..\main\p.h"\
   "..\main\ripem.h"\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\getoptpr.h"\
   ".\getsyspr.h"\
   ".\parsitpr.h"\
   ".\usagepro.h"\
   

"$(INTDIR)\rcerts.obj" : $(SOURCE) $(DEP_CPP_RCERT) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "rcertsnt - Win32 Debug"

DEP_CPP_RCERT=\
   "..\main\p.h"\
   "..\main\ripem.h"\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\getoptpr.h"\
   ".\getsyspr.h"\
   ".\parsitpr.h"\
   ".\usagepro.h"\
   {$(INCLUDE)}"sys\types.h"\
   

"$(INTDIR)\rcerts.obj" : $(SOURCE) $(DEP_CPP_RCERT) "$(INTDIR)"


!ENDIF 

SOURCE=.\rcertsms.c

"$(INTDIR)\rcertsms.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\usage.c
DEP_CPP_USAGE=\
   ".\usagepro.h"\
   

"$(INTDIR)\usage.obj" : $(SOURCE) $(DEP_CPP_USAGE) "$(INTDIR)"



!ENDIF 

