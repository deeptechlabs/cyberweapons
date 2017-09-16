# Microsoft Developer Studio Generated NMAKE File, Based on rsarefnt.dsp
!IF "$(CFG)" == ""
CFG=rsarefnt - Win32 Release
!MESSAGE No configuration specified. Defaulting to rsarefnt - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "rsarefnt - Win32 Release" && "$(CFG)" !=\
 "rsarefnt - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "rsarefnt.mak" CFG="rsarefnt - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "rsarefnt - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "rsarefnt - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "rsarefnt - Win32 Release"

OUTDIR=.\rsarefnt
INTDIR=.\rsarefnt
# Begin Custom Macros
OutDir=.\rsarefnt
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\rsarefnt.lib"

!ELSE 

ALL : "$(OUTDIR)\rsarefnt.lib"

!ENDIF 

CLEAN :
   -@erase "$(INTDIR)\desc.obj"
   -@erase "$(INTDIR)\digit.obj"
   -@erase "$(INTDIR)\md2c.obj"
   -@erase "$(INTDIR)\md5c.obj"
   -@erase "$(INTDIR)\nn.obj"
   -@erase "$(INTDIR)\prime.obj"
   -@erase "$(INTDIR)\r_dh.obj"
   -@erase "$(INTDIR)\r_encode.obj"
   -@erase "$(INTDIR)\r_enhanc.obj"
   -@erase "$(INTDIR)\r_keygen.obj"
   -@erase "$(INTDIR)\r_random.obj"
   -@erase "$(INTDIR)\r_stdlib.obj"
   -@erase "$(INTDIR)\rc5_32st.obj"
   -@erase "$(INTDIR)\rsa.obj"
   -@erase "$(INTDIR)\rx2c.obj"
   -@erase "$(INTDIR)\sha1c.obj"
   -@erase "$(INTDIR)\vc50.idb"
   -@erase "$(OUTDIR)\rsarefnt.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /ML /W3 /GX /O2 /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D\
 "USE_386_ASM" /Fp"$(INTDIR)\rsarefnt.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\"\
 /FD /c 
CPP_OBJS=.\rsarefnt/
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

BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\rsarefnt.bsc" 
BSC32_SBRS= \
   
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\rsarefnt.lib" 
LIB32_OBJS= \
   "$(INTDIR)\desc.obj" \
   "$(INTDIR)\digit.obj" \
   "$(INTDIR)\md2c.obj" \
   "$(INTDIR)\md5c.obj" \
   "$(INTDIR)\nn.obj" \
   "$(INTDIR)\prime.obj" \
   "$(INTDIR)\r_dh.obj" \
   "$(INTDIR)\r_encode.obj" \
   "$(INTDIR)\r_enhanc.obj" \
   "$(INTDIR)\r_keygen.obj" \
   "$(INTDIR)\r_random.obj" \
   "$(INTDIR)\r_stdlib.obj" \
   "$(INTDIR)\rc5_32st.obj" \
   "$(INTDIR)\rsa.obj" \
   "$(INTDIR)\rx2c.obj" \
   "$(INTDIR)\sha1c.obj"

"$(OUTDIR)\rsarefnt.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ELSEIF  "$(CFG)" == "rsarefnt - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\rsarefnt.lib"

!ELSE 

ALL : "$(OUTDIR)\rsarefnt.lib"

!ENDIF 

CLEAN :
   -@erase "$(INTDIR)\desc.obj"
   -@erase "$(INTDIR)\digit.obj"
   -@erase "$(INTDIR)\md2c.obj"
   -@erase "$(INTDIR)\md5c.obj"
   -@erase "$(INTDIR)\nn.obj"
   -@erase "$(INTDIR)\prime.obj"
   -@erase "$(INTDIR)\r_dh.obj"
   -@erase "$(INTDIR)\r_encode.obj"
   -@erase "$(INTDIR)\r_enhanc.obj"
   -@erase "$(INTDIR)\r_keygen.obj"
   -@erase "$(INTDIR)\r_random.obj"
   -@erase "$(INTDIR)\r_stdlib.obj"
   -@erase "$(INTDIR)\rc5_32st.obj"
   -@erase "$(INTDIR)\rsa.obj"
   -@erase "$(INTDIR)\rx2c.obj"
   -@erase "$(INTDIR)\sha1c.obj"
   -@erase "$(INTDIR)\vc50.idb"
   -@erase "$(OUTDIR)\rsarefnt.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MLd /W3 /GX /Z7 /Od /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D\
 "USE_386_ASM" /Fp"$(INTDIR)\rsarefnt.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\"\
 /FD /c 
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

BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\rsarefnt.bsc" 
BSC32_SBRS= \
   
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\rsarefnt.lib" 
LIB32_OBJS= \
   "$(INTDIR)\desc.obj" \
   "$(INTDIR)\digit.obj" \
   "$(INTDIR)\md2c.obj" \
   "$(INTDIR)\md5c.obj" \
   "$(INTDIR)\nn.obj" \
   "$(INTDIR)\prime.obj" \
   "$(INTDIR)\r_dh.obj" \
   "$(INTDIR)\r_encode.obj" \
   "$(INTDIR)\r_enhanc.obj" \
   "$(INTDIR)\r_keygen.obj" \
   "$(INTDIR)\r_random.obj" \
   "$(INTDIR)\r_stdlib.obj" \
   "$(INTDIR)\rc5_32st.obj" \
   "$(INTDIR)\rsa.obj" \
   "$(INTDIR)\rx2c.obj" \
   "$(INTDIR)\sha1c.obj"

"$(OUTDIR)\rsarefnt.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "rsarefnt - Win32 Release" || "$(CFG)" ==\
 "rsarefnt - Win32 Debug"
SOURCE=..\source\desc.c

!IF  "$(CFG)" == "rsarefnt - Win32 Release"

DEP_CPP_DESC_=\
   "..\source\des.h"\
   "..\source\global.h"\
   "..\source\md2.h"\
   "..\source\md5.h"\
   "..\source\rc5_32.h"\
   "..\source\rsaref.h"\
   "..\source\rx2.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\desc.obj" : $(SOURCE) $(DEP_CPP_DESC_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "rsarefnt - Win32 Debug"

DEP_CPP_DESC_=\
   "..\source\des.h"\
   "..\source\global.h"\
   "..\source\md2.h"\
   "..\source\md5.h"\
   "..\source\rc5_32.h"\
   "..\source\rsaref.h"\
   "..\source\rx2.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\desc.obj" : $(SOURCE) $(DEP_CPP_DESC_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\source\digit.c

!IF  "$(CFG)" == "rsarefnt - Win32 Release"

DEP_CPP_DIGIT=\
   "..\source\des.h"\
   "..\source\digit.h"\
   "..\source\global.h"\
   "..\source\md2.h"\
   "..\source\md5.h"\
   "..\source\nn.h"\
   "..\source\rc5_32.h"\
   "..\source\rsaref.h"\
   "..\source\rx2.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\digit.obj" : $(SOURCE) $(DEP_CPP_DIGIT) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "rsarefnt - Win32 Debug"

DEP_CPP_DIGIT=\
   "..\source\des.h"\
   "..\source\digit.h"\
   "..\source\global.h"\
   "..\source\md2.h"\
   "..\source\md5.h"\
   "..\source\nn.h"\
   "..\source\rc5_32.h"\
   "..\source\rsaref.h"\
   "..\source\rx2.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\digit.obj" : $(SOURCE) $(DEP_CPP_DIGIT) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\source\md2c.c

!IF  "$(CFG)" == "rsarefnt - Win32 Release"

DEP_CPP_MD2C_=\
   "..\source\global.h"\
   "..\source\md2.h"\
   

"$(INTDIR)\md2c.obj" : $(SOURCE) $(DEP_CPP_MD2C_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "rsarefnt - Win32 Debug"

DEP_CPP_MD2C_=\
   "..\source\global.h"\
   "..\source\md2.h"\
   

"$(INTDIR)\md2c.obj" : $(SOURCE) $(DEP_CPP_MD2C_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\source\md5c.c

!IF  "$(CFG)" == "rsarefnt - Win32 Release"

DEP_CPP_MD5C_=\
   "..\source\global.h"\
   "..\source\md5.h"\
   

"$(INTDIR)\md5c.obj" : $(SOURCE) $(DEP_CPP_MD5C_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "rsarefnt - Win32 Debug"

DEP_CPP_MD5C_=\
   "..\source\global.h"\
   "..\source\md5.h"\
   

"$(INTDIR)\md5c.obj" : $(SOURCE) $(DEP_CPP_MD5C_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\source\nn.c

!IF  "$(CFG)" == "rsarefnt - Win32 Release"

DEP_CPP_NN_C8=\
   "..\source\des.h"\
   "..\source\digit.h"\
   "..\source\global.h"\
   "..\source\longlong.h"\
   "..\source\md2.h"\
   "..\source\md5.h"\
   "..\source\nn.h"\
   "..\source\rc5_32.h"\
   "..\source\rsaref.h"\
   "..\source\rx2.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\nn.obj" : $(SOURCE) $(DEP_CPP_NN_C8) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "rsarefnt - Win32 Debug"

DEP_CPP_NN_C8=\
   "..\source\des.h"\
   "..\source\digit.h"\
   "..\source\global.h"\
   "..\source\longlong.h"\
   "..\source\md2.h"\
   "..\source\md5.h"\
   "..\source\nn.h"\
   "..\source\rc5_32.h"\
   "..\source\rsaref.h"\
   "..\source\rx2.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\nn.obj" : $(SOURCE) $(DEP_CPP_NN_C8) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\source\prime.c

!IF  "$(CFG)" == "rsarefnt - Win32 Release"

DEP_CPP_PRIME=\
   "..\source\des.h"\
   "..\source\global.h"\
   "..\source\md2.h"\
   "..\source\md5.h"\
   "..\source\nn.h"\
   "..\source\prime.h"\
   "..\source\r_random.h"\
   "..\source\rc5_32.h"\
   "..\source\rsaref.h"\
   "..\source\rx2.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\prime.obj" : $(SOURCE) $(DEP_CPP_PRIME) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "rsarefnt - Win32 Debug"

DEP_CPP_PRIME=\
   "..\source\des.h"\
   "..\source\global.h"\
   "..\source\md2.h"\
   "..\source\md5.h"\
   "..\source\nn.h"\
   "..\source\prime.h"\
   "..\source\r_random.h"\
   "..\source\rc5_32.h"\
   "..\source\rsaref.h"\
   "..\source\rx2.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\prime.obj" : $(SOURCE) $(DEP_CPP_PRIME) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\source\r_dh.c

!IF  "$(CFG)" == "rsarefnt - Win32 Release"

DEP_CPP_R_DH_=\
   "..\source\des.h"\
   "..\source\global.h"\
   "..\source\md2.h"\
   "..\source\md5.h"\
   "..\source\nn.h"\
   "..\source\prime.h"\
   "..\source\r_random.h"\
   "..\source\rc5_32.h"\
   "..\source\rsaref.h"\
   "..\source\rx2.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\r_dh.obj" : $(SOURCE) $(DEP_CPP_R_DH_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "rsarefnt - Win32 Debug"

DEP_CPP_R_DH_=\
   "..\source\des.h"\
   "..\source\global.h"\
   "..\source\md2.h"\
   "..\source\md5.h"\
   "..\source\nn.h"\
   "..\source\prime.h"\
   "..\source\r_random.h"\
   "..\source\rc5_32.h"\
   "..\source\rsaref.h"\
   "..\source\rx2.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\r_dh.obj" : $(SOURCE) $(DEP_CPP_R_DH_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\source\r_encode.c

!IF  "$(CFG)" == "rsarefnt - Win32 Release"

DEP_CPP_R_ENC=\
   "..\source\des.h"\
   "..\source\global.h"\
   "..\source\md2.h"\
   "..\source\md5.h"\
   "..\source\rc5_32.h"\
   "..\source\rsaref.h"\
   "..\source\rx2.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\r_encode.obj" : $(SOURCE) $(DEP_CPP_R_ENC) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "rsarefnt - Win32 Debug"

DEP_CPP_R_ENC=\
   "..\source\des.h"\
   "..\source\global.h"\
   "..\source\md2.h"\
   "..\source\md5.h"\
   "..\source\rc5_32.h"\
   "..\source\rsaref.h"\
   "..\source\rx2.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\r_encode.obj" : $(SOURCE) $(DEP_CPP_R_ENC) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\source\r_enhanc.c

!IF  "$(CFG)" == "rsarefnt - Win32 Release"

DEP_CPP_R_ENH=\
   "..\source\des.h"\
   "..\source\global.h"\
   "..\source\md2.h"\
   "..\source\md5.h"\
   "..\source\r_random.h"\
   "..\source\rc5_32.h"\
   "..\source\rsa.h"\
   "..\source\rsaref.h"\
   "..\source\rx2.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\r_enhanc.obj" : $(SOURCE) $(DEP_CPP_R_ENH) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "rsarefnt - Win32 Debug"

DEP_CPP_R_ENH=\
   "..\source\des.h"\
   "..\source\global.h"\
   "..\source\md2.h"\
   "..\source\md5.h"\
   "..\source\r_random.h"\
   "..\source\rc5_32.h"\
   "..\source\rsa.h"\
   "..\source\rsaref.h"\
   "..\source\rx2.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\r_enhanc.obj" : $(SOURCE) $(DEP_CPP_R_ENH) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\source\r_keygen.c

!IF  "$(CFG)" == "rsarefnt - Win32 Release"

DEP_CPP_R_KEY=\
   "..\source\des.h"\
   "..\source\global.h"\
   "..\source\md2.h"\
   "..\source\md5.h"\
   "..\source\nn.h"\
   "..\source\prime.h"\
   "..\source\r_random.h"\
   "..\source\rc5_32.h"\
   "..\source\rsaref.h"\
   "..\source\rx2.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\r_keygen.obj" : $(SOURCE) $(DEP_CPP_R_KEY) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "rsarefnt - Win32 Debug"

DEP_CPP_R_KEY=\
   "..\source\des.h"\
   "..\source\global.h"\
   "..\source\md2.h"\
   "..\source\md5.h"\
   "..\source\nn.h"\
   "..\source\prime.h"\
   "..\source\r_random.h"\
   "..\source\rc5_32.h"\
   "..\source\rsaref.h"\
   "..\source\rx2.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\r_keygen.obj" : $(SOURCE) $(DEP_CPP_R_KEY) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\source\r_random.c

!IF  "$(CFG)" == "rsarefnt - Win32 Release"

DEP_CPP_R_RAN=\
   "..\source\des.h"\
   "..\source\global.h"\
   "..\source\md2.h"\
   "..\source\md5.h"\
   "..\source\r_random.h"\
   "..\source\rc5_32.h"\
   "..\source\rsaref.h"\
   "..\source\rx2.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\r_random.obj" : $(SOURCE) $(DEP_CPP_R_RAN) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "rsarefnt - Win32 Debug"

DEP_CPP_R_RAN=\
   "..\source\des.h"\
   "..\source\global.h"\
   "..\source\md2.h"\
   "..\source\md5.h"\
   "..\source\r_random.h"\
   "..\source\rc5_32.h"\
   "..\source\rsaref.h"\
   "..\source\rx2.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\r_random.obj" : $(SOURCE) $(DEP_CPP_R_RAN) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\source\r_stdlib.c

!IF  "$(CFG)" == "rsarefnt - Win32 Release"

DEP_CPP_R_STD=\
   "..\source\des.h"\
   "..\source\global.h"\
   "..\source\md2.h"\
   "..\source\md5.h"\
   "..\source\rc5_32.h"\
   "..\source\rsaref.h"\
   "..\source\rx2.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\r_stdlib.obj" : $(SOURCE) $(DEP_CPP_R_STD) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "rsarefnt - Win32 Debug"

DEP_CPP_R_STD=\
   "..\source\des.h"\
   "..\source\global.h"\
   "..\source\md2.h"\
   "..\source\md5.h"\
   "..\source\rc5_32.h"\
   "..\source\rsaref.h"\
   "..\source\rx2.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\r_stdlib.obj" : $(SOURCE) $(DEP_CPP_R_STD) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\source\rc5_32st.c

!IF  "$(CFG)" == "rsarefnt - Win32 Release"

DEP_CPP_RC5_3=\
   "..\source\des.h"\
   "..\source\global.h"\
   "..\source\md2.h"\
   "..\source\md5.h"\
   "..\source\rc5_32.h"\
   "..\source\rsaref.h"\
   "..\source\rx2.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\rc5_32st.obj" : $(SOURCE) $(DEP_CPP_RC5_3) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "rsarefnt - Win32 Debug"

DEP_CPP_RC5_3=\
   "..\source\des.h"\
   "..\source\global.h"\
   "..\source\md2.h"\
   "..\source\md5.h"\
   "..\source\rc5_32.h"\
   "..\source\rsaref.h"\
   "..\source\rx2.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\rc5_32st.obj" : $(SOURCE) $(DEP_CPP_RC5_3) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\source\rsa.c

!IF  "$(CFG)" == "rsarefnt - Win32 Release"

DEP_CPP_RSA_C=\
   "..\source\des.h"\
   "..\source\global.h"\
   "..\source\md2.h"\
   "..\source\md5.h"\
   "..\source\nn.h"\
   "..\source\r_random.h"\
   "..\source\rc5_32.h"\
   "..\source\rsa.h"\
   "..\source\rsaref.h"\
   "..\source\rx2.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\rsa.obj" : $(SOURCE) $(DEP_CPP_RSA_C) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "rsarefnt - Win32 Debug"

DEP_CPP_RSA_C=\
   "..\source\des.h"\
   "..\source\global.h"\
   "..\source\md2.h"\
   "..\source\md5.h"\
   "..\source\nn.h"\
   "..\source\r_random.h"\
   "..\source\rc5_32.h"\
   "..\source\rsa.h"\
   "..\source\rsaref.h"\
   "..\source\rx2.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\rsa.obj" : $(SOURCE) $(DEP_CPP_RSA_C) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\source\rx2c.c

!IF  "$(CFG)" == "rsarefnt - Win32 Release"

DEP_CPP_RX2C_=\
   "..\source\des.h"\
   "..\source\global.h"\
   "..\source\md2.h"\
   "..\source\md5.h"\
   "..\source\rc5_32.h"\
   "..\source\rsaref.h"\
   "..\source\rx2.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\rx2c.obj" : $(SOURCE) $(DEP_CPP_RX2C_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "rsarefnt - Win32 Debug"

DEP_CPP_RX2C_=\
   "..\source\des.h"\
   "..\source\global.h"\
   "..\source\md2.h"\
   "..\source\md5.h"\
   "..\source\rc5_32.h"\
   "..\source\rsaref.h"\
   "..\source\rx2.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\rx2c.obj" : $(SOURCE) $(DEP_CPP_RX2C_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\source\sha1c.c
DEP_CPP_SHA1C=\
   "..\source\global.h"\
   "..\source\sha1.h"\
   

"$(INTDIR)\sha1c.obj" : $(SOURCE) $(DEP_CPP_SHA1C) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)



!ENDIF 

