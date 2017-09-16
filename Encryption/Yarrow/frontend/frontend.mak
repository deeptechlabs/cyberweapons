# Microsoft Developer Studio Generated NMAKE File, Based on frontend.dsp
!IF "$(CFG)" == ""
CFG=frontend - Win32 Debug
!MESSAGE No configuration specified. Defaulting to frontend - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "frontend - Win32 Release" && "$(CFG)" !=\
 "frontend - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "frontend.mak" CFG="frontend - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "frontend - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "frontend - Win32 Debug" (based on "Win32 (x86) Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "frontend - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\frontend.exe"

!ELSE 

ALL : "prngcore - Win32 Release" "entropyhooks - Win32 Release"\
 "$(OUTDIR)\frontend.exe"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"entropyhooks - Win32 ReleaseCLEAN" "prngcore - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\FrontEnd.obj"
	-@erase "$(INTDIR)\frontend.res"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(OUTDIR)\frontend.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /ML /W3 /GX /O2 /I "..\entropyhooks" /I "..\prngcore" /I\
 "..\Zlib" /I "..\smf" /D "WIN32" /D "NDEBUG" /D "_WINDOWS"\
 /Fp"$(INTDIR)\frontend.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
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
RSC_PROJ=/l 0x1009 /fo"$(INTDIR)\frontend.res" /d "NDEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\frontend.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=prngcore.lib entropyhooks.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib\
 uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /incremental:no\
 /pdb:"$(OUTDIR)\frontend.pdb" /machine:I386 /out:"$(OUTDIR)\frontend.exe"\
 /libpath:"..\prngcore\release" /libpath:"..\entropyhooks\release" 
LINK32_OBJS= \
	"$(INTDIR)\FrontEnd.obj" \
	"$(INTDIR)\frontend.res" \
	"..\entropyhooks\Release\entropyhooks.lib" \
	"..\prngcore\Release\prngcore.lib"

"$(OUTDIR)\frontend.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "frontend - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\frontend.exe"

!ELSE 

ALL : "prngcore - Win32 Debug" "entropyhooks - Win32 Debug"\
 "$(OUTDIR)\frontend.exe"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"entropyhooks - Win32 DebugCLEAN" "prngcore - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\FrontEnd.obj"
	-@erase "$(INTDIR)\frontend.res"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(INTDIR)\vc50.pdb"
	-@erase "$(OUTDIR)\frontend.exe"
	-@erase "$(OUTDIR)\frontend.ilk"
	-@erase "$(OUTDIR)\frontend.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MLd /W3 /Gm /GX /Zi /Od /I "..\entropyhooks" /I "..\prngcore"\
 /I "..\Zlib" /I "..\smf" /D "WIN32" /D "_DEBUG" /D "_WINDOWS"\
 /Fp"$(INTDIR)\frontend.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
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
RSC_PROJ=/l 0x1009 /fo"$(INTDIR)\frontend.res" /d "_DEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\frontend.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=prngcore.lib entropyhooks.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib\
 uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /incremental:yes\
 /pdb:"$(OUTDIR)\frontend.pdb" /debug /machine:I386\
 /out:"$(OUTDIR)\frontend.exe" /pdbtype:sept /libpath:"..\prngcore\debug"\
 /libpath:"..\entropyhooks\debug" 
LINK32_OBJS= \
	"$(INTDIR)\FrontEnd.obj" \
	"$(INTDIR)\frontend.res" \
	"..\entropyhooks\Debug\entropyhooks.lib" \
	"..\prngcore\Debug\prngcore.lib"

"$(OUTDIR)\frontend.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "frontend - Win32 Release" || "$(CFG)" ==\
 "frontend - Win32 Debug"
SOURCE=.\FrontEnd.c

!IF  "$(CFG)" == "frontend - Win32 Release"

DEP_CPP_FRONT=\
	"..\entropyhooks\entropysources.h"\
	"..\entropyhooks\hooks.h"\
	"..\prngcore\comp.h"\
	"..\prngcore\prng.h"\
	"..\prngcore\sha1mod.h"\
	"..\prngcore\yarrow.h"\
	"..\smf\smf.h"\
	"..\zlib\zconf.h"\
	"..\zlib\zlib.h"\
	".\frontend.h"\
	

"$(INTDIR)\FrontEnd.obj" : $(SOURCE) $(DEP_CPP_FRONT) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "frontend - Win32 Debug"

DEP_CPP_FRONT=\
	"..\entropyhooks\entropysources.h"\
	"..\entropyhooks\hooks.h"\
	"..\prngcore\prng.h"\
	"..\prngcore\yarrow.h"\
	".\frontend.h"\
	

"$(INTDIR)\FrontEnd.obj" : $(SOURCE) $(DEP_CPP_FRONT) "$(INTDIR)"


!ENDIF 

SOURCE=.\frontend.rc
DEP_RSC_FRONTE=\
	".\frontend.h"\
	".\icon1.ico"\
	

"$(INTDIR)\frontend.res" : $(SOURCE) $(DEP_RSC_FRONTE) "$(INTDIR)"
	$(RSC) $(RSC_PROJ) $(SOURCE)


!IF  "$(CFG)" == "frontend - Win32 Release"

"entropyhooks - Win32 Release" : 
   cd "\Work\PRNG\yarrow\entropyhooks"
   $(MAKE) /$(MAKEFLAGS) /F .\entropyhooks.mak\
 CFG="entropyhooks - Win32 Release" 
   cd "..\frontend"

"entropyhooks - Win32 ReleaseCLEAN" : 
   cd "\Work\PRNG\yarrow\entropyhooks"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F .\entropyhooks.mak\
 CFG="entropyhooks - Win32 Release" RECURSE=1 
   cd "..\frontend"

!ELSEIF  "$(CFG)" == "frontend - Win32 Debug"

"entropyhooks - Win32 Debug" : 
   cd "\Work\PRNG\yarrow\entropyhooks"
   $(MAKE) /$(MAKEFLAGS) /F .\entropyhooks.mak CFG="entropyhooks - Win32 Debug"\
 
   cd "..\frontend"

"entropyhooks - Win32 DebugCLEAN" : 
   cd "\Work\PRNG\yarrow\entropyhooks"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F .\entropyhooks.mak\
 CFG="entropyhooks - Win32 Debug" RECURSE=1 
   cd "..\frontend"

!ENDIF 

!IF  "$(CFG)" == "frontend - Win32 Release"

"prngcore - Win32 Release" : 
   cd "\Work\PRNG\yarrow\prngcore"
   $(MAKE) /$(MAKEFLAGS) /F .\prngcore.mak CFG="prngcore - Win32 Release" 
   cd "..\frontend"

"prngcore - Win32 ReleaseCLEAN" : 
   cd "\Work\PRNG\yarrow\prngcore"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F .\prngcore.mak CFG="prngcore - Win32 Release"\
 RECURSE=1 
   cd "..\frontend"

!ELSEIF  "$(CFG)" == "frontend - Win32 Debug"

"prngcore - Win32 Debug" : 
   cd "\Work\PRNG\yarrow\prngcore"
   $(MAKE) /$(MAKEFLAGS) /F .\prngcore.mak CFG="prngcore - Win32 Debug" 
   cd "..\frontend"

"prngcore - Win32 DebugCLEAN" : 
   cd "\Work\PRNG\yarrow\prngcore"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F .\prngcore.mak CFG="prngcore - Win32 Debug"\
 RECURSE=1 
   cd "..\frontend"

!ENDIF 


!ENDIF 

