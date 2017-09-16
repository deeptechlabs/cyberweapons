# Microsoft Developer Studio Project File - Name="rsarefnt" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 5.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=rsarefnt - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "rsarefnt.mak".
!MESSAGE 
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

# Begin Project
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe

!IF  "$(CFG)" == "rsarefnt - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "rsarefnt"
# PROP BASE Intermediate_Dir "rsarefnt"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "rsarefnt"
# PROP Intermediate_Dir "rsarefnt"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /W3 /GX /O2 /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "USE_386_ASM" /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "rsarefnt - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /W3 /GX /Z7 /Od /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "USE_386_ASM" /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ENDIF 

# Begin Target

# Name "rsarefnt - Win32 Release"
# Name "rsarefnt - Win32 Debug"
# Begin Source File

SOURCE=..\source\des.h
# End Source File
# Begin Source File

SOURCE=..\source\desc.c
# End Source File
# Begin Source File

SOURCE=..\source\digit.c
# End Source File
# Begin Source File

SOURCE=..\source\digit.h
# End Source File
# Begin Source File

SOURCE=..\source\global.h
# End Source File
# Begin Source File

SOURCE=..\source\longlong.h
# End Source File
# Begin Source File

SOURCE=..\source\md2.h
# End Source File
# Begin Source File

SOURCE=..\source\md2c.c
# End Source File
# Begin Source File

SOURCE=..\source\md5.h
# End Source File
# Begin Source File

SOURCE=..\source\md5c.c
# End Source File
# Begin Source File

SOURCE=..\source\nn.c
# End Source File
# Begin Source File

SOURCE=..\source\nn.h
# End Source File
# Begin Source File

SOURCE=..\source\prime.c
# End Source File
# Begin Source File

SOURCE=..\source\prime.h
# End Source File
# Begin Source File

SOURCE=..\source\r_dh.c
# End Source File
# Begin Source File

SOURCE=..\source\r_encode.c
# End Source File
# Begin Source File

SOURCE=..\source\r_enhanc.c
# End Source File
# Begin Source File

SOURCE=..\source\r_keygen.c
# End Source File
# Begin Source File

SOURCE=..\source\r_random.c
# End Source File
# Begin Source File

SOURCE=..\source\r_random.h
# End Source File
# Begin Source File

SOURCE=..\source\r_stdlib.c
# End Source File
# Begin Source File

SOURCE=..\source\rc5_32.h
# End Source File
# Begin Source File

SOURCE=..\source\rc5_32st.c
# End Source File
# Begin Source File

SOURCE=..\source\rsa.c
# End Source File
# Begin Source File

SOURCE=..\source\rsa.h
# End Source File
# Begin Source File

SOURCE=..\source\rsaref.h
# End Source File
# Begin Source File

SOURCE=..\source\rx2.h
# End Source File
# Begin Source File

SOURCE=..\source\rx2c.c
# End Source File
# Begin Source File

SOURCE=..\source\sha1.h
# End Source File
# Begin Source File

SOURCE=..\source\sha1c.c
# End Source File
# End Target
# End Project
