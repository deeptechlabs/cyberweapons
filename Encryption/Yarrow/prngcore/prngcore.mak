# Microsoft Developer Studio Generated NMAKE File, Based on prngcore.dsp
!IF "$(CFG)" == ""
CFG=prngcore - Win32 Debug
!MESSAGE No configuration specified. Defaulting to prngcore - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "prngcore - Win32 Release" && "$(CFG)" !=\
 "prngcore - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "prngcore.mak" CFG="prngcore - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "prngcore - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "prngcore - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "prngcore - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\prngcore.dll"

!ELSE 

ALL : "smf - Win32 Release" "$(OUTDIR)\prngcore.dll"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"smf - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\95only.obj"
	-@erase "$(INTDIR)\comp.obj"
	-@erase "$(INTDIR)\ntonly.obj"
	-@erase "$(INTDIR)\prng.obj"
	-@erase "$(INTDIR)\sha1mod.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(OUTDIR)\prngcore.dll"
	-@erase "$(OUTDIR)\prngcore.exp"
	-@erase "$(OUTDIR)\prngcore.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /GX /O2 /I "..\smf" /I "..\entropyhooks" /I "..\Zlib"\
 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /Fp"$(INTDIR)\prngcore.pch" /YX\
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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\prngcore.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=zlibr.lib th32.lib smf.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib\
 uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll\
 /incremental:no /pdb:"$(OUTDIR)\prngcore.pdb" /machine:I386\
 /out:"$(OUTDIR)\prngcore.dll" /implib:"$(OUTDIR)\prngcore.lib"\
 /libpath:"..\smf\release" /libpath:"..\Zlib" 
LINK32_OBJS= \
	"$(INTDIR)\95only.obj" \
	"$(INTDIR)\comp.obj" \
	"$(INTDIR)\ntonly.obj" \
	"$(INTDIR)\prng.obj" \
	"$(INTDIR)\sha1mod.obj" \
	"..\smf\Release\smf.lib"

"$(OUTDIR)\prngcore.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

SOURCE=$(InputPath)
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

ALL : $(DS_POSTBUILD_DEP)

# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

$(DS_POSTBUILD_DEP) : "smf - Win32 Release" "$(OUTDIR)\prngcore.dll"
   copy release\prngcore.dll C:\windows\system
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ELSEIF  "$(CFG)" == "prngcore - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\prngcore.dll"

!ELSE 

ALL : "smf - Win32 Debug" "$(OUTDIR)\prngcore.dll"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"smf - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\95only.obj"
	-@erase "$(INTDIR)\comp.obj"
	-@erase "$(INTDIR)\ntonly.obj"
	-@erase "$(INTDIR)\prng.obj"
	-@erase "$(INTDIR)\sha1mod.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(INTDIR)\vc50.pdb"
	-@erase "$(OUTDIR)\prngcore.dll"
	-@erase "$(OUTDIR)\prngcore.exp"
	-@erase "$(OUTDIR)\prngcore.ilk"
	-@erase "$(OUTDIR)\prngcore.lib"
	-@erase "$(OUTDIR)\prngcore.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /Gm /GX /Zi /Od /I "..\smf" /I "..\entropyhooks" /I\
 "..\Zlib" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /Fp"$(INTDIR)\prngcore.pch" /YX\
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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\prngcore.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=zlibd.lib smf.lib kernel32.lib user32.lib gdi32.lib winspool.lib\
 comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib\
 odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /incremental:yes\
 /pdb:"$(OUTDIR)\prngcore.pdb" /debug /machine:I386\
 /out:"$(OUTDIR)\prngcore.dll" /implib:"$(OUTDIR)\prngcore.lib" /pdbtype:sept\
 /libpath:"..\smf\debug" /libpath:"..\Zlib" 
LINK32_OBJS= \
	"$(INTDIR)\95only.obj" \
	"$(INTDIR)\comp.obj" \
	"$(INTDIR)\ntonly.obj" \
	"$(INTDIR)\prng.obj" \
	"$(INTDIR)\sha1mod.obj" \
	"..\smf\Debug\smf.lib"

"$(OUTDIR)\prngcore.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

SOURCE=$(InputPath)
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

ALL : $(DS_POSTBUILD_DEP)

# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

$(DS_POSTBUILD_DEP) : "smf - Win32 Debug" "$(OUTDIR)\prngcore.dll"
   copy debug\prngcore.dll C:\windows\system
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ENDIF 


!IF "$(CFG)" == "prngcore - Win32 Release" || "$(CFG)" ==\
 "prngcore - Win32 Debug"
SOURCE=.\95only.c

!IF  "$(CFG)" == "prngcore - Win32 Release"

DEP_CPP_95ONL=\
	".\95only.h"\
	".\userdefines.h"\
	

"$(INTDIR)\95only.obj" : $(SOURCE) $(DEP_CPP_95ONL) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "prngcore - Win32 Debug"

DEP_CPP_95ONL=\
	".\95only.h"\
	".\userdefines.h"\
	

"$(INTDIR)\95only.obj" : $(SOURCE) $(DEP_CPP_95ONL) "$(INTDIR)"


!ENDIF 

SOURCE=.\comp.c

!IF  "$(CFG)" == "prngcore - Win32 Release"

DEP_CPP_COMP_=\
	"..\smf\smf.h"\
	"..\zlib\zlib.h"\
	".\comp.h"\
	{$(INCLUDE)}"..\zlib\zconf.h"\
	{$(INCLUDE)}"sys\types.h"\
	

"$(INTDIR)\comp.obj" : $(SOURCE) $(DEP_CPP_COMP_) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "prngcore - Win32 Debug"

DEP_CPP_COMP_=\
	"..\smf\smf.h"\
	"..\zlib\zlib.h"\
	".\comp.h"\
	{$(INCLUDE)}"..\zlib\zconf.h"\
	

"$(INTDIR)\comp.obj" : $(SOURCE) $(DEP_CPP_COMP_) "$(INTDIR)"


!ENDIF 

SOURCE=.\ntonly.c

!IF  "$(CFG)" == "prngcore - Win32 Release"

DEP_CPP_NTONL=\
	".\ntonly.h"\
	".\userdefines.h"\
	

"$(INTDIR)\ntonly.obj" : $(SOURCE) $(DEP_CPP_NTONL) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "prngcore - Win32 Debug"

DEP_CPP_NTONL=\
	".\userdefines.h"\
	

"$(INTDIR)\ntonly.obj" : $(SOURCE) $(DEP_CPP_NTONL) "$(INTDIR)"


!ENDIF 

SOURCE=.\prng.c

!IF  "$(CFG)" == "prngcore - Win32 Release"

DEP_CPP_PRNG_=\
	"..\entropyhooks\entropysources.h"\
	"..\smf\smf.h"\
	"..\zlib\zlib.h"\
	".\assertverify.h"\
	".\comp.h"\
	".\prng.h"\
	".\prngpriv.h"\
	".\sha1mod.h"\
	".\userdefines.h"\
	".\yarrow.h"\
	{$(INCLUDE)}"..\zlib\zconf.h"\
	
NODEP_CPP_PRNG_=\
	".\ntsec.h"\
	

"$(INTDIR)\prng.obj" : $(SOURCE) $(DEP_CPP_PRNG_) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "prngcore - Win32 Debug"

DEP_CPP_PRNG_=\
	"..\entropyhooks\entropysources.h"\
	"..\smf\smf.h"\
	"..\zlib\zlib.h"\
	".\95only.h"\
	".\assertverify.h"\
	".\comp.h"\
	".\prng.h"\
	".\prng.mut"\
	".\prngpriv.h"\
	".\sha1mod.h"\
	".\userdefines.h"\
	".\usersources.h"\
	".\yarrow.h"\
	{$(INCLUDE)}"..\zlib\zconf.h"\
	

"$(INTDIR)\prng.obj" : $(SOURCE) $(DEP_CPP_PRNG_) "$(INTDIR)"


!ENDIF 

SOURCE=.\sha1mod.c
DEP_CPP_SHA1M=\
	".\sha1mod.h"\
	

"$(INTDIR)\sha1mod.obj" : $(SOURCE) $(DEP_CPP_SHA1M) "$(INTDIR)"


!IF  "$(CFG)" == "prngcore - Win32 Release"

"smf - Win32 Release" : 
   cd "\Work\PRNG\yarrow\smf"
   $(MAKE) /$(MAKEFLAGS) /F .\smf.mak CFG="smf - Win32 Release" 
   cd "..\prngcore"

"smf - Win32 ReleaseCLEAN" : 
   cd "\Work\PRNG\yarrow\smf"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F .\smf.mak CFG="smf - Win32 Release" RECURSE=1\
 
   cd "..\prngcore"

!ELSEIF  "$(CFG)" == "prngcore - Win32 Debug"

"smf - Win32 Debug" : 
   cd "\Work\PRNG\yarrow\smf"
   $(MAKE) /$(MAKEFLAGS) /F .\smf.mak CFG="smf - Win32 Debug" 
   cd "..\prngcore"

"smf - Win32 DebugCLEAN" : 
   cd "\Work\PRNG\yarrow\smf"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F .\smf.mak CFG="smf - Win32 Debug" RECURSE=1 
   cd "..\prngcore"

!ENDIF 


!ENDIF 

