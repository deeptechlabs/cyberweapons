# Microsoft Developer Studio Generated NMAKE File, Based on mainnt.dsp
!IF "$(CFG)" == ""
CFG=mainnt - Win32 Release
!MESSAGE No configuration specified. Defaulting to mainnt - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "mainnt - Win32 Release" && "$(CFG)" != "mainnt - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mainnt.mak" CFG="mainnt - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mainnt - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "mainnt - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

CPP=cl.exe

!IF  "$(CFG)" == "mainnt - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mainnt.lib"

!ELSE 

ALL : "$(OUTDIR)\mainnt.lib"

!ENDIF 

CLEAN :
   -@erase "$(INTDIR)\bemparse.obj"
   -@erase "$(INTDIR)\bfstream.obj"
   -@erase "$(INTDIR)\certutil.obj"
   -@erase "$(INTDIR)\crackhed.obj"
   -@erase "$(INTDIR)\derkey.obj"
   -@erase "$(INTDIR)\hexbin.obj"
   -@erase "$(INTDIR)\keyder.obj"
   -@erase "$(INTDIR)\keyman.obj"
   -@erase "$(INTDIR)\list.obj"
   -@erase "$(INTDIR)\pemformt.obj"
   -@erase "$(INTDIR)\pkcformt.obj"
   -@erase "$(INTDIR)\pubinfo.obj"
   -@erase "$(INTDIR)\rdwrmsg.obj"
   -@erase "$(INTDIR)\ripemmai.obj"
   -@erase "$(INTDIR)\ripemsoc.obj"
   -@erase "$(INTDIR)\strutil.obj"
   -@erase "$(INTDIR)\vc50.idb"
   -@erase "$(OUTDIR)\mainnt.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /ML /W3 /GX /O2 /I "..\rsaref\source" /D "NDEBUG" /D "WIN32"\
 /D "_WINDOWS" /D "__STDC__" /Fp"$(INTDIR)\mainnt.pch" /YX /Fo"$(INTDIR)\\"\
 /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\Release/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mainnt.bsc" 
BSC32_SBRS= \
   
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\mainnt.lib" 
LIB32_OBJS= \
   "$(INTDIR)\bemparse.obj" \
   "$(INTDIR)\bfstream.obj" \
   "$(INTDIR)\certutil.obj" \
   "$(INTDIR)\crackhed.obj" \
   "$(INTDIR)\derkey.obj" \
   "$(INTDIR)\hexbin.obj" \
   "$(INTDIR)\keyder.obj" \
   "$(INTDIR)\keyman.obj" \
   "$(INTDIR)\list.obj" \
   "$(INTDIR)\pemformt.obj" \
   "$(INTDIR)\pkcformt.obj" \
   "$(INTDIR)\pubinfo.obj" \
   "$(INTDIR)\rdwrmsg.obj" \
   "$(INTDIR)\ripemmai.obj" \
   "$(INTDIR)\ripemsoc.obj" \
   "$(INTDIR)\strutil.obj"

"$(OUTDIR)\mainnt.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ELSEIF  "$(CFG)" == "mainnt - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mainnt.lib"

!ELSE 

ALL : "$(OUTDIR)\mainnt.lib"

!ENDIF 

CLEAN :
   -@erase "$(INTDIR)\bemparse.obj"
   -@erase "$(INTDIR)\bfstream.obj"
   -@erase "$(INTDIR)\certutil.obj"
   -@erase "$(INTDIR)\crackhed.obj"
   -@erase "$(INTDIR)\derkey.obj"
   -@erase "$(INTDIR)\hexbin.obj"
   -@erase "$(INTDIR)\keyder.obj"
   -@erase "$(INTDIR)\keyman.obj"
   -@erase "$(INTDIR)\list.obj"
   -@erase "$(INTDIR)\pemformt.obj"
   -@erase "$(INTDIR)\pkcformt.obj"
   -@erase "$(INTDIR)\pubinfo.obj"
   -@erase "$(INTDIR)\rdwrmsg.obj"
   -@erase "$(INTDIR)\ripemmai.obj"
   -@erase "$(INTDIR)\ripemsoc.obj"
   -@erase "$(INTDIR)\strutil.obj"
   -@erase "$(INTDIR)\vc50.idb"
   -@erase "$(OUTDIR)\mainnt.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MLd /W3 /GX /Z7 /Od /I "..\rsaref\source" /D "_DEBUG" /D\
 "WIN32" /D "_WINDOWS" /D "__STDC__" /Fp"$(INTDIR)\mainnt.pch" /YX\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mainnt.bsc" 
BSC32_SBRS= \
   
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\mainnt.lib" 
LIB32_OBJS= \
   "$(INTDIR)\bemparse.obj" \
   "$(INTDIR)\bfstream.obj" \
   "$(INTDIR)\certutil.obj" \
   "$(INTDIR)\crackhed.obj" \
   "$(INTDIR)\derkey.obj" \
   "$(INTDIR)\hexbin.obj" \
   "$(INTDIR)\keyder.obj" \
   "$(INTDIR)\keyman.obj" \
   "$(INTDIR)\list.obj" \
   "$(INTDIR)\pemformt.obj" \
   "$(INTDIR)\pkcformt.obj" \
   "$(INTDIR)\pubinfo.obj" \
   "$(INTDIR)\rdwrmsg.obj" \
   "$(INTDIR)\ripemmai.obj" \
   "$(INTDIR)\ripemsoc.obj" \
   "$(INTDIR)\strutil.obj"

"$(OUTDIR)\mainnt.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
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


!IF "$(CFG)" == "mainnt - Win32 Release" || "$(CFG)" == "mainnt - Win32 Debug"
SOURCE=.\bemparse.c

!IF  "$(CFG)" == "mainnt - Win32 Release"

DEP_CPP_BEMPA=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\bemparse.h"\
   ".\p.h"\
   ".\ripem.h"\
   

"$(INTDIR)\bemparse.obj" : $(SOURCE) $(DEP_CPP_BEMPA) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "mainnt - Win32 Debug"

DEP_CPP_BEMPA=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\bemparse.h"\
   ".\p.h"\
   ".\ripem.h"\
   

"$(INTDIR)\bemparse.obj" : $(SOURCE) $(DEP_CPP_BEMPA) "$(INTDIR)"


!ENDIF 

SOURCE=.\bfstream.c

!IF  "$(CFG)" == "mainnt - Win32 Release"

DEP_CPP_BFSTR=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\bfstream.h"\
   ".\p.h"\
   ".\ripem.h"\
   

"$(INTDIR)\bfstream.obj" : $(SOURCE) $(DEP_CPP_BFSTR) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "mainnt - Win32 Debug"

DEP_CPP_BFSTR=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\bfstream.h"\
   ".\p.h"\
   ".\ripem.h"\
   

"$(INTDIR)\bfstream.obj" : $(SOURCE) $(DEP_CPP_BFSTR) "$(INTDIR)"


!ENDIF 

SOURCE=.\certutil.c

!IF  "$(CFG)" == "mainnt - Win32 Release"

DEP_CPP_CERTU=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\bfstream.h"\
   ".\certder.h"\
   ".\certutil.h"\
   ".\derkeypr.h"\
   ".\headers.h"\
   ".\keyderpr.h"\
   ".\keyfield.h"\
   ".\keymanpr.h"\
   ".\p.h"\
   ".\pubinfop.h"\
   ".\rdwrmsgp.h"\
   ".\ripem.h"\
   

"$(INTDIR)\certutil.obj" : $(SOURCE) $(DEP_CPP_CERTU) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "mainnt - Win32 Debug"

DEP_CPP_CERTU=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\bfstream.h"\
   ".\certder.h"\
   ".\certutil.h"\
   ".\derkeypr.h"\
   ".\headers.h"\
   ".\keyderpr.h"\
   ".\keyfield.h"\
   ".\keymanpr.h"\
   ".\p.h"\
   ".\pubinfop.h"\
   ".\rdwrmsgp.h"\
   ".\ripem.h"\
   

"$(INTDIR)\certutil.obj" : $(SOURCE) $(DEP_CPP_CERTU) "$(INTDIR)"


!ENDIF 

SOURCE=.\crackhed.c

!IF  "$(CFG)" == "mainnt - Win32 Release"

DEP_CPP_CRACK=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\bfstream.h"\
   ".\certder.h"\
   ".\certutil.h"\
   ".\crackhpr.h"\
   ".\derkeypr.h"\
   ".\headers.h"\
   ".\hexbinpr.h"\
   ".\p.h"\
   ".\ripem.h"\
   ".\strutilp.h"\
   

"$(INTDIR)\crackhed.obj" : $(SOURCE) $(DEP_CPP_CRACK) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "mainnt - Win32 Debug"

DEP_CPP_CRACK=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\bfstream.h"\
   ".\certder.h"\
   ".\certutil.h"\
   ".\crackhpr.h"\
   ".\derkeypr.h"\
   ".\headers.h"\
   ".\hexbinpr.h"\
   ".\p.h"\
   ".\ripem.h"\
   ".\strutilp.h"\
   

"$(INTDIR)\crackhed.obj" : $(SOURCE) $(DEP_CPP_CRACK) "$(INTDIR)"


!ENDIF 

SOURCE=.\derkey.c

!IF  "$(CFG)" == "mainnt - Win32 Release"

DEP_CPP_DERKE=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\certder.h"\
   ".\derkeypr.h"\
   ".\p.h"\
   ".\ripem.h"\
   

"$(INTDIR)\derkey.obj" : $(SOURCE) $(DEP_CPP_DERKE) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "mainnt - Win32 Debug"

DEP_CPP_DERKE=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\certder.h"\
   ".\derkeypr.h"\
   ".\p.h"\
   ".\ripem.h"\
   

"$(INTDIR)\derkey.obj" : $(SOURCE) $(DEP_CPP_DERKE) "$(INTDIR)"


!ENDIF 

SOURCE=.\hexbin.c
DEP_CPP_HEXBI=\
   ".\hexbinpr.h"\
   

"$(INTDIR)\hexbin.obj" : $(SOURCE) $(DEP_CPP_HEXBI) "$(INTDIR)"


SOURCE=.\keyder.c

!IF  "$(CFG)" == "mainnt - Win32 Release"

DEP_CPP_KEYDE=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\certder.h"\
   ".\derkeypr.h"\
   ".\keyderpr.h"\
   ".\p.h"\
   ".\ripem.h"\
   

"$(INTDIR)\keyder.obj" : $(SOURCE) $(DEP_CPP_KEYDE) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "mainnt - Win32 Debug"

DEP_CPP_KEYDE=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\certder.h"\
   ".\derkeypr.h"\
   ".\keyderpr.h"\
   ".\p.h"\
   ".\ripem.h"\
   

"$(INTDIR)\keyder.obj" : $(SOURCE) $(DEP_CPP_KEYDE) "$(INTDIR)"


!ENDIF 

SOURCE=.\keyman.c

!IF  "$(CFG)" == "mainnt - Win32 Release"

DEP_CPP_KEYMA=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\bemparse.h"\
   ".\bfstream.h"\
   ".\certder.h"\
   ".\certutil.h"\
   ".\derkeypr.h"\
   ".\hexbinpr.h"\
   ".\keyderpr.h"\
   ".\keyfield.h"\
   ".\keymanpr.h"\
   ".\p.h"\
   ".\pubinfop.h"\
   ".\rdwrmsgp.h"\
   ".\ripem.h"\
   ".\ripemsop.h"\
   ".\strutilp.h"\
   

"$(INTDIR)\keyman.obj" : $(SOURCE) $(DEP_CPP_KEYMA) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "mainnt - Win32 Debug"

DEP_CPP_KEYMA=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\bemparse.h"\
   ".\bfstream.h"\
   ".\certder.h"\
   ".\certutil.h"\
   ".\derkeypr.h"\
   ".\hexbinpr.h"\
   ".\keyderpr.h"\
   ".\keyfield.h"\
   ".\keymanpr.h"\
   ".\p.h"\
   ".\pubinfop.h"\
   ".\rdwrmsgp.h"\
   ".\ripem.h"\
   ".\ripemsop.h"\
   ".\strutilp.h"\
   
NODEP_CPP_KEYMA=\
   ".\ddes.h"\
   

"$(INTDIR)\keyman.obj" : $(SOURCE) $(DEP_CPP_KEYMA) "$(INTDIR)"


!ENDIF 

SOURCE=.\list.c

!IF  "$(CFG)" == "mainnt - Win32 Release"

DEP_CPP_LIST_=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\p.h"\
   ".\ripem.h"\
   ".\strutilp.h"\
   

"$(INTDIR)\list.obj" : $(SOURCE) $(DEP_CPP_LIST_) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "mainnt - Win32 Debug"

DEP_CPP_LIST_=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\p.h"\
   ".\ripem.h"\
   ".\strutilp.h"\
   

"$(INTDIR)\list.obj" : $(SOURCE) $(DEP_CPP_LIST_) "$(INTDIR)"


!ENDIF 

SOURCE=.\pemformt.c

!IF  "$(CFG)" == "mainnt - Win32 Release"

DEP_CPP_PEMFO=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\bemparse.h"\
   ".\bfstream.h"\
   ".\certder.h"\
   ".\certutil.h"\
   ".\crackhpr.h"\
   ".\derkeypr.h"\
   ".\headers.h"\
   ".\hexbinpr.h"\
   ".\keyderpr.h"\
   ".\keyfield.h"\
   ".\keymanpr.h"\
   ".\p.h"\
   ".\rdwrmsgp.h"\
   ".\ripem.h"\
   ".\strutilp.h"\
   

"$(INTDIR)\pemformt.obj" : $(SOURCE) $(DEP_CPP_PEMFO) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "mainnt - Win32 Debug"

DEP_CPP_PEMFO=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\bemparse.h"\
   ".\bfstream.h"\
   ".\certder.h"\
   ".\certutil.h"\
   ".\crackhpr.h"\
   ".\derkeypr.h"\
   ".\headers.h"\
   ".\hexbinpr.h"\
   ".\keyderpr.h"\
   ".\keyfield.h"\
   ".\keymanpr.h"\
   ".\p.h"\
   ".\rdwrmsgp.h"\
   ".\ripem.h"\
   ".\strutilp.h"\
   {$(INCLUDE)}"sys\types.h"\
   

"$(INTDIR)\pemformt.obj" : $(SOURCE) $(DEP_CPP_PEMFO) "$(INTDIR)"


!ENDIF 

SOURCE=.\pkcformt.c

!IF  "$(CFG)" == "mainnt - Win32 Release"

DEP_CPP_PKCFO=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\bemparse.h"\
   ".\bfstream.h"\
   ".\certder.h"\
   ".\certutil.h"\
   ".\derkeypr.h"\
   ".\headers.h"\
   ".\hexbinpr.h"\
   ".\keyderpr.h"\
   ".\keyfield.h"\
   ".\keymanpr.h"\
   ".\p.h"\
   ".\ripem.h"\
   ".\strutilp.h"\
   

"$(INTDIR)\pkcformt.obj" : $(SOURCE) $(DEP_CPP_PKCFO) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "mainnt - Win32 Debug"

DEP_CPP_PKCFO=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\bemparse.h"\
   ".\bfstream.h"\
   ".\certder.h"\
   ".\certutil.h"\
   ".\derkeypr.h"\
   ".\headers.h"\
   ".\hexbinpr.h"\
   ".\keyderpr.h"\
   ".\keyfield.h"\
   ".\keymanpr.h"\
   ".\p.h"\
   ".\ripem.h"\
   ".\strutilp.h"\
   {$(INCLUDE)}"sys\types.h"\
   

"$(INTDIR)\pkcformt.obj" : $(SOURCE) $(DEP_CPP_PKCFO) "$(INTDIR)"


!ENDIF 

SOURCE=.\pubinfo.c

!IF  "$(CFG)" == "mainnt - Win32 Release"

DEP_CPP_PUBIN=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\headers.h"\
   ".\keyfield.h"\
   ".\p.h"\
   ".\protserv.h"\
   ".\pubinfop.h"\
   ".\ripem.h"\
   ".\strutilp.h"\
   

"$(INTDIR)\pubinfo.obj" : $(SOURCE) $(DEP_CPP_PUBIN) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "mainnt - Win32 Debug"

DEP_CPP_PUBIN=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\headers.h"\
   ".\keyfield.h"\
   ".\p.h"\
   ".\protserv.h"\
   ".\pubinfop.h"\
   ".\ripem.h"\
   ".\strutilp.h"\
   

"$(INTDIR)\pubinfo.obj" : $(SOURCE) $(DEP_CPP_PUBIN) "$(INTDIR)"


!ENDIF 

SOURCE=.\rdwrmsg.c

!IF  "$(CFG)" == "mainnt - Win32 Release"

DEP_CPP_RDWRM=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\bfstream.h"\
   ".\headers.h"\
   ".\p.h"\
   ".\rdwrmsgp.h"\
   ".\ripem.h"\
   ".\strutilp.h"\
   

"$(INTDIR)\rdwrmsg.obj" : $(SOURCE) $(DEP_CPP_RDWRM) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "mainnt - Win32 Debug"

DEP_CPP_RDWRM=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\bfstream.h"\
   ".\headers.h"\
   ".\p.h"\
   ".\rdwrmsgp.h"\
   ".\ripem.h"\
   ".\strutilp.h"\
   

"$(INTDIR)\rdwrmsg.obj" : $(SOURCE) $(DEP_CPP_RDWRM) "$(INTDIR)"


!ENDIF 

SOURCE=.\ripemmai.c

!IF  "$(CFG)" == "mainnt - Win32 Release"

DEP_CPP_RIPEM=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\bemparse.h"\
   ".\bfstream.h"\
   ".\certder.h"\
   ".\certutil.h"\
   ".\derkeypr.h"\
   ".\headers.h"\
   ".\hexbinpr.h"\
   ".\keyderpr.h"\
   ".\keyfield.h"\
   ".\keymanpr.h"\
   ".\p.h"\
   ".\rdwrmsgp.h"\
   ".\ripem.h"\
   ".\strutilp.h"\
   ".\version.h"\
   

"$(INTDIR)\ripemmai.obj" : $(SOURCE) $(DEP_CPP_RIPEM) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "mainnt - Win32 Debug"

DEP_CPP_RIPEM=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\bemparse.h"\
   ".\bfstream.h"\
   ".\certder.h"\
   ".\certutil.h"\
   ".\derkeypr.h"\
   ".\headers.h"\
   ".\hexbinpr.h"\
   ".\keyderpr.h"\
   ".\keyfield.h"\
   ".\keymanpr.h"\
   ".\p.h"\
   ".\rdwrmsgp.h"\
   ".\ripem.h"\
   ".\strutilp.h"\
   ".\version.h"\
   {$(INCLUDE)}"sys\types.h"\
   

"$(INTDIR)\ripemmai.obj" : $(SOURCE) $(DEP_CPP_RIPEM) "$(INTDIR)"


!ENDIF 

SOURCE=.\ripemsoc.c

!IF  "$(CFG)" == "mainnt - Win32 Release"

DEP_CPP_RIPEMS=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\keyfield.h"\
   ".\p.h"\
   ".\protserv.h"\
   ".\pubinfop.h"\
   ".\ripem.h"\
   ".\ripemsop.h"\
   ".\strutilp.h"\
   

"$(INTDIR)\ripemsoc.obj" : $(SOURCE) $(DEP_CPP_RIPEMS) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "mainnt - Win32 Debug"

DEP_CPP_RIPEMS=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\keyfield.h"\
   ".\p.h"\
   ".\protserv.h"\
   ".\pubinfop.h"\
   ".\ripem.h"\
   ".\ripemsop.h"\
   ".\strutilp.h"\
   {$(INCLUDE)}"sys\types.h"\
   {$(INCLUDE)}"unistd.h"\
   

"$(INTDIR)\ripemsoc.obj" : $(SOURCE) $(DEP_CPP_RIPEMS) "$(INTDIR)"


!ENDIF 

SOURCE=.\strutil.c

!IF  "$(CFG)" == "mainnt - Win32 Release"

DEP_CPP_STRUT=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\hexbinpr.h"\
   ".\p.h"\
   ".\ripem.h"\
   ".\strutilp.h"\
   

"$(INTDIR)\strutil.obj" : $(SOURCE) $(DEP_CPP_STRUT) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "mainnt - Win32 Debug"

DEP_CPP_STRUT=\
   "..\rsaref\source\des.h"\
   "..\rsaref\source\global.h"\
   "..\rsaref\source\md2.h"\
   "..\rsaref\source\md5.h"\
   "..\rsaref\source\rc5_32.h"\
   "..\rsaref\source\rsaref.h"\
   "..\rsaref\source\rx2.h"\
   "..\rsaref\source\sha1.h"\
   ".\hexbinpr.h"\
   ".\p.h"\
   ".\ripem.h"\
   ".\strutilp.h"\
   

"$(INTDIR)\strutil.obj" : $(SOURCE) $(DEP_CPP_STRUT) "$(INTDIR)"


!ENDIF 


!ENDIF 

