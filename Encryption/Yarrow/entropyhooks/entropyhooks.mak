# Microsoft Developer Studio Generated NMAKE File, Based on entropyhooks.dsp
!IF "$(CFG)" == ""
CFG=entropyhooks - Win32 Debug
!MESSAGE No configuration specified. Defaulting to entropyhooks - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "entropyhooks - Win32 Release" && "$(CFG)" !=\
 "entropyhooks - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "entropyhooks.mak" CFG="entropyhooks - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "entropyhooks - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "entropyhooks - Win32 Debug" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "entropyhooks - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\entropyhooks.dll"

!ELSE 

ALL : "smf - Win32 Release" "$(OUTDIR)\entropyhooks.dll"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"smf - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\hooks.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(OUTDIR)\entropyhooks.dll"
	-@erase "$(OUTDIR)\entropyhooks.exp"
	-@erase "$(OUTDIR)\entropyhooks.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /GX /O2 /I "..\smf" /D "WIN32" /D "NDEBUG" /D\
 "_WINDOWS" /Fp"$(INTDIR)\entropyhooks.pch" /YX /Fo"$(INTDIR)\\"\
 /Fd"$(INTDIR)\\" /FD /c 
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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\entropyhooks.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=smf.lib kernel32.lib user32.lib gdi32.lib winspool.lib\
 comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib\
 odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /incremental:no\
 /pdb:"$(OUTDIR)\entropyhooks.pdb" /machine:I386\
 /out:"$(OUTDIR)\entropyhooks.dll" /implib:"$(OUTDIR)\entropyhooks.lib"\
 /libpath:"..\smf\release" 
LINK32_OBJS= \
	"$(INTDIR)\hooks.obj" \
	"..\smf\Release\smf.lib"

"$(OUTDIR)\entropyhooks.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

SOURCE=$(InputPath)
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

ALL : $(DS_POSTBUILD_DEP)

# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

$(DS_POSTBUILD_DEP) : "smf - Win32 Release" "$(OUTDIR)\entropyhooks.dll"
   copy release\entropyhooks.dll C:\windows\system
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ELSEIF  "$(CFG)" == "entropyhooks - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\entropyhooks.dll"

!ELSE 

ALL : "smf - Win32 Debug" "$(OUTDIR)\entropyhooks.dll"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"smf - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\hooks.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(INTDIR)\vc50.pdb"
	-@erase "$(OUTDIR)\entropyhooks.dll"
	-@erase "$(OUTDIR)\entropyhooks.exp"
	-@erase "$(OUTDIR)\entropyhooks.ilk"
	-@erase "$(OUTDIR)\entropyhooks.lib"
	-@erase "$(OUTDIR)\entropyhooks.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /Gm /GX /Zi /Od /I "..\smf" /D "WIN32" /D "_DEBUG" /D\
 "_WINDOWS" /Fp"$(INTDIR)\entropyhooks.pch" /YX /Fo"$(INTDIR)\\"\
 /Fd"$(INTDIR)\\" /FD /c 
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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\entropyhooks.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=smf.lib kernel32.lib user32.lib gdi32.lib winspool.lib\
 comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib\
 odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /incremental:yes\
 /pdb:"$(OUTDIR)\entropyhooks.pdb" /debug /machine:I386\
 /out:"$(OUTDIR)\entropyhooks.dll" /implib:"$(OUTDIR)\entropyhooks.lib"\
 /pdbtype:sept /libpath:"..\smf\debug" 
LINK32_OBJS= \
	"$(INTDIR)\hooks.obj" \
	"..\smf\Debug\smf.lib"

"$(OUTDIR)\entropyhooks.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

SOURCE=$(InputPath)
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

ALL : $(DS_POSTBUILD_DEP)

# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

$(DS_POSTBUILD_DEP) : "smf - Win32 Debug" "$(OUTDIR)\entropyhooks.dll"
   copy debug\entropyhooks.dll C:\windows\system
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ENDIF 


!IF "$(CFG)" == "entropyhooks - Win32 Release" || "$(CFG)" ==\
 "entropyhooks - Win32 Debug"
SOURCE=.\hooks.c
DEP_CPP_HOOKS=\
	"..\smf\smf.h"\
	".\entropysources.h"\
	".\hooks.h"\
	".\hookspriv.h"\
	

"$(INTDIR)\hooks.obj" : $(SOURCE) $(DEP_CPP_HOOKS) "$(INTDIR)"


!IF  "$(CFG)" == "entropyhooks - Win32 Release"

"smf - Win32 Release" : 
   cd "\Work\PRNG\yarrow\smf"
   $(MAKE) /$(MAKEFLAGS) /F .\smf.mak CFG="smf - Win32 Release" 
   cd "..\entropyhooks"

"smf - Win32 ReleaseCLEAN" : 
   cd "\Work\PRNG\yarrow\smf"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F .\smf.mak CFG="smf - Win32 Release" RECURSE=1\
 
   cd "..\entropyhooks"

!ELSEIF  "$(CFG)" == "entropyhooks - Win32 Debug"

"smf - Win32 Debug" : 
   cd "\Work\PRNG\yarrow\smf"
   $(MAKE) /$(MAKEFLAGS) /F .\smf.mak CFG="smf - Win32 Debug" 
   cd "..\entropyhooks"

"smf - Win32 DebugCLEAN" : 
   cd "\Work\PRNG\yarrow\smf"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F .\smf.mak CFG="smf - Win32 Debug" RECURSE=1 
   cd "..\entropyhooks"

!ENDIF 


!ENDIF 

