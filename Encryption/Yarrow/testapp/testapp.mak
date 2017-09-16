# Microsoft Developer Studio Generated NMAKE File, Based on testapp.dsp
!IF "$(CFG)" == ""
CFG=testapp - Win32 Debug
!MESSAGE No configuration specified. Defaulting to testapp - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "testapp - Win32 Release" && "$(CFG)" !=\
 "testapp - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "testapp.mak" CFG="testapp - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "testapp - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "testapp - Win32 Debug" (based on "Win32 (x86) Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "testapp - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\testapp.exe"

!ELSE 

ALL : "prngcore - Win32 Release" "$(OUTDIR)\testapp.exe"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"prngcore - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\testapp.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(OUTDIR)\testapp.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /ML /W3 /GX /O2 /I "..\entropyhooks" /I "..\prngcore" /D\
 "WIN32" /D "NDEBUG" /D "_WINDOWS" /Fp"$(INTDIR)\testapp.pch" /YX\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\Release/
CPP_SBRS=.

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

MTL=midl.exe
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /o NUL /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\testapp.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=prngcore.lib kernel32.lib user32.lib gdi32.lib winspool.lib\
 comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib\
 odbc32.lib odbccp32.lib /nologo /subsystem:windows /incremental:no\
 /pdb:"$(OUTDIR)\testapp.pdb" /machine:I386 /out:"$(OUTDIR)\testapp.exe"\
 /libpath:"..\prngcore\release" 
LINK32_OBJS= \
	"$(INTDIR)\testapp.obj" \
	"..\prngcore\Release\prngcore.lib"

"$(OUTDIR)\testapp.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "testapp - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\testapp.exe"

!ELSE 

ALL : "prngcore - Win32 Debug" "$(OUTDIR)\testapp.exe"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"prngcore - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\testapp.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(INTDIR)\vc50.pdb"
	-@erase "$(OUTDIR)\testapp.exe"
	-@erase "$(OUTDIR)\testapp.ilk"
	-@erase "$(OUTDIR)\testapp.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MLd /W3 /Gm /GX /Zi /Od /I "..\entropyhooks" /I "..\prngcore"\
 /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /Fp"$(INTDIR)\testapp.pch" /YX\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.

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

MTL=midl.exe
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /o NUL /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\testapp.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=prngcore.lib kernel32.lib user32.lib gdi32.lib winspool.lib\
 comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib\
 odbc32.lib odbccp32.lib /nologo /subsystem:windows /incremental:yes\
 /pdb:"$(OUTDIR)\testapp.pdb" /debug /machine:I386 /out:"$(OUTDIR)\testapp.exe"\
 /pdbtype:sept /libpath:"..\prngcore\debug" 
LINK32_OBJS= \
	"$(INTDIR)\testapp.obj" \
	"..\prngcore\Debug\prngcore.lib"

"$(OUTDIR)\testapp.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "testapp - Win32 Release" || "$(CFG)" ==\
 "testapp - Win32 Debug"
SOURCE=.\testapp.c

!IF  "$(CFG)" == "testapp - Win32 Release"

DEP_CPP_TESTA=\
	"..\entropyhooks\entropysources.h"\
	"..\prngcore\yarrow.h"\
	

"$(INTDIR)\testapp.obj" : $(SOURCE) $(DEP_CPP_TESTA) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "testapp - Win32 Debug"

DEP_CPP_TESTA=\
	"..\prngcore\usersources.h"\
	"..\prngcore\yarrow.h"\
	

"$(INTDIR)\testapp.obj" : $(SOURCE) $(DEP_CPP_TESTA) "$(INTDIR)"


!ENDIF 

!IF  "$(CFG)" == "testapp - Win32 Release"

"prngcore - Win32 Release" : 
   cd "\Work\PRNG\yarrow\prngcore"
   $(MAKE) /$(MAKEFLAGS) /F .\prngcore.mak CFG="prngcore - Win32 Release" 
   cd "..\testapp"

"prngcore - Win32 ReleaseCLEAN" : 
   cd "\Work\PRNG\yarrow\prngcore"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F .\prngcore.mak CFG="prngcore - Win32 Release"\
 RECURSE=1 
   cd "..\testapp"

!ELSEIF  "$(CFG)" == "testapp - Win32 Debug"

"prngcore - Win32 Debug" : 
   cd "\Work\PRNG\yarrow\prngcore"
   $(MAKE) /$(MAKEFLAGS) /F .\prngcore.mak CFG="prngcore - Win32 Debug" 
   cd "..\testapp"

"prngcore - Win32 DebugCLEAN" : 
   cd "\Work\PRNG\yarrow\prngcore"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F .\prngcore.mak CFG="prngcore - Win32 Debug"\
 RECURSE=1 
   cd "..\testapp"

!ENDIF 


!ENDIF 

