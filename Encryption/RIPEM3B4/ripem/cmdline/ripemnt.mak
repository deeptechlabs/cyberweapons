# Microsoft Developer Studio Generated NMAKE File, Based on ripemnt.dsp
!IF "$(CFG)" == ""
CFG=ripemnt - Win32 Release
!MESSAGE No configuration specified. Defaulting to ripemnt - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "ripemnt - Win32 Release" && "$(CFG)" !=\
 "ripemnt - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "ripemnt.mak" CFG="ripemnt - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "ripemnt - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "ripemnt - Win32 Debug" (based on "Win32 (x86) Console Application")
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

!IF  "$(CFG)" == "ripemnt - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ripemnt.exe"

!ELSE 

ALL : "$(OUTDIR)\ripemnt.exe"

!ENDIF 

CLEAN :
   -@erase "$(INTDIR)\getopt.obj"
   -@erase "$(INTDIR)\getsys.obj"
   -@erase "$(INTDIR)\parsit.obj"
   -@erase "$(INTDIR)\ripemcmd.obj"
   -@erase "$(INTDIR)\usage.obj"
   -@erase "$(INTDIR)\usagemsg.obj"
   -@erase "$(INTDIR)\vc50.idb"
   -@erase "$(OUTDIR)\ripemnt.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /ML /W3 /GX /O2 /I "..\rsaref\source" /I "..\main" /D "NDEBUG"\
 /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D "WINNT" /D "MSDOS" /Fp"$(INTDIR)\ripemnt.pch" /YX\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\Release/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ripemnt.bsc" 
BSC32_SBRS= \
   
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib\
 odbccp32.lib /nologo /subsystem:console /incremental:no\
 /pdb:"$(OUTDIR)\ripemnt.pdb" /machine:I386 /out:"$(OUTDIR)\ripemnt.exe" 
LINK32_OBJS= \
   "$(INTDIR)\getopt.obj" \
   "$(INTDIR)\getsys.obj" \
   "$(INTDIR)\parsit.obj" \
   "$(INTDIR)\ripemcmd.obj" \
   "$(INTDIR)\usage.obj" \
   "$(INTDIR)\usagemsg.obj" \
   "..\main\Release\mainnt.lib" \
   "..\rsaref\install\rsarefnt\rsarefnt.lib"

"$(OUTDIR)\ripemnt.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "ripemnt - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ripemnt.exe"

!ELSE 

ALL : "$(OUTDIR)\ripemnt.exe"

!ENDIF 

CLEAN :
   -@erase "$(INTDIR)\getopt.obj"
   -@erase "$(INTDIR)\getsys.obj"
   -@erase "$(INTDIR)\parsit.obj"
   -@erase "$(INTDIR)\ripemcmd.obj"
   -@erase "$(INTDIR)\usage.obj"
   -@erase "$(INTDIR)\usagemsg.obj"
   -@erase "$(INTDIR)\vc50.idb"
   -@erase "$(INTDIR)\vc50.pdb"
   -@erase "$(OUTDIR)\ripemnt.exe"
   -@erase "$(OUTDIR)\ripemnt.ilk"
   -@erase "$(OUTDIR)\ripemnt.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MLd /W3 /Gm /GX /Zi /Od /I "..\rsaref\source" /I "..\main" /D\
 "_DEBUG" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D "MSDOS" /D "WINNT"\
 /Fp"$(INTDIR)\ripemnt.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ripemnt.bsc" 
BSC32_SBRS= \
   
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib\
 odbccp32.lib /nologo /subsystem:console /incremental:yes\
 /pdb:"$(OUTDIR)\ripemnt.pdb" /debug /machine:I386 /out:"$(OUTDIR)\ripemnt.exe"\
 /pdbtype:sept 
LINK32_OBJS= \
   "$(INTDIR)\getopt.obj" \
   "$(INTDIR)\getsys.obj" \
   "$(INTDIR)\parsit.obj" \
   "$(INTDIR)\ripemcmd.obj" \
   "$(INTDIR)\usage.obj" \
   "$(INTDIR)\usagemsg.obj" \
   "..\main\Release\mainnt.lib" \
   "..\rsaref\install\rsarefnt\rsarefnt.lib"

"$(OUTDIR)\ripemnt.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
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


!IF "$(CFG)" == "ripemnt - Win32 Release" || "$(CFG)" ==\
 "ripemnt - Win32 Debug"
SOURCE=.\getopt.c
DEP_CPP_GETOP=\
   ".\getoptpr.h"\
   

"$(INTDIR)\getopt.obj" : $(SOURCE) $(DEP_CPP_GETOP) "$(INTDIR)"


SOURCE=.\getsys.c

!IF  "$(CFG)" == "ripemnt - Win32 Release"

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


!ELSEIF  "$(CFG)" == "ripemnt - Win32 Debug"

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


SOURCE=.\ripemcmd.c

!IF  "$(CFG)" == "ripemnt - Win32 Release"

DEP_CPP_RIPEM=\
   "..\main\p.h"\
   "..\main\ripem.h"\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\r_random.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\getoptpr.h"\
   ".\getsyspr.h"\
   ".\parsitpr.h"\
   ".\usagepro.h"\
   

"$(INTDIR)\ripemcmd.obj" : $(SOURCE) $(DEP_CPP_RIPEM) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ripemnt - Win32 Debug"

DEP_CPP_RIPEM=\
   "..\main\p.h"\
   "..\main\ripem.h"\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\r_random.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\getoptpr.h"\
   ".\getsyspr.h"\
   ".\parsitpr.h"\
   ".\usagepro.h"\
   {$(INCLUDE)}"sys\types.h"\
   

"$(INTDIR)\ripemcmd.obj" : $(SOURCE) $(DEP_CPP_RIPEM) "$(INTDIR)"


!ENDIF 

SOURCE=.\usage.c
DEP_CPP_USAGE=\
   ".\usagepro.h"\
   

"$(INTDIR)\usage.obj" : $(SOURCE) $(DEP_CPP_USAGE) "$(INTDIR)"


SOURCE=.\usagemsg.c

"$(INTDIR)\usagemsg.obj" : $(SOURCE) "$(INTDIR)"



!ENDIF 

