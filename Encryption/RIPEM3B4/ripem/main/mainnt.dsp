# Microsoft Developer Studio Project File - Name="mainnt" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 5.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=mainnt - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "mainnt.mak".
!MESSAGE 
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

# Begin Project
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe

!IF  "$(CFG)" == "mainnt - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /W3 /GX /O2 /I "..\rsaref\source" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "__STDC__" /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "mainnt - Win32 Debug"

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
# ADD CPP /nologo /W3 /GX /Z7 /Od /I "..\rsaref\source" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "__STDC__" /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ENDIF 

# Begin Target

# Name "mainnt - Win32 Release"
# Name "mainnt - Win32 Debug"
# Begin Source File

SOURCE=.\bemparse.c
# End Source File
# Begin Source File

SOURCE=.\bemparse.h
# End Source File
# Begin Source File

SOURCE=.\bfstream.c
# End Source File
# Begin Source File

SOURCE=.\bfstream.h
# End Source File
# Begin Source File

SOURCE=.\certutil.c
# End Source File
# Begin Source File

SOURCE=.\certutil.h
# End Source File
# Begin Source File

SOURCE=.\crackhed.c
# End Source File
# Begin Source File

SOURCE=.\crackhpr.h
# End Source File
# Begin Source File

SOURCE=.\derkey.c
# End Source File
# Begin Source File

SOURCE=.\derkeypr.h
# End Source File
# Begin Source File

SOURCE=.\hexbin.c
# End Source File
# Begin Source File

SOURCE=.\hexbinpr.h
# End Source File
# Begin Source File

SOURCE=.\keyder.c
# End Source File
# Begin Source File

SOURCE=.\keyderpr.h
# End Source File
# Begin Source File

SOURCE=.\keyman.c
# End Source File
# Begin Source File

SOURCE=.\keymanpr.h
# End Source File
# Begin Source File

SOURCE=.\list.c
# End Source File
# Begin Source File

SOURCE=.\pemformt.c
# End Source File
# Begin Source File

SOURCE=.\pkcformt.c
# End Source File
# Begin Source File

SOURCE=.\pubinfo.c
# End Source File
# Begin Source File

SOURCE=.\pubinfop.h
# End Source File
# Begin Source File

SOURCE=.\rdwrmsg.c
# End Source File
# Begin Source File

SOURCE=.\rdwrmsgp.h
# End Source File
# Begin Source File

SOURCE=.\ripemmai.c
# End Source File
# Begin Source File

SOURCE=.\ripemsoc.c
# End Source File
# Begin Source File

SOURCE=.\ripemsop.h
# End Source File
# Begin Source File

SOURCE=.\strutil.c
# End Source File
# Begin Source File

SOURCE=.\strutilp.h
# End Source File
# End Target
# End Project
