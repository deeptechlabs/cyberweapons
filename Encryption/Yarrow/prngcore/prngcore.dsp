# Microsoft Developer Studio Project File - Name="prngcore" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 5.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=prngcore - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "prngcore.mak".
!MESSAGE 
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

# Begin Project
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "prngcore - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "..\smf" /I "..\entropyhooks" /I "..\Zlib" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /o NUL /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /o NUL /win32
# ADD BASE RSC /l 0x1009 /d "NDEBUG"
# ADD RSC /l 0x1009 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 zlibr.lib th32.lib smf.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386 /libpath:"..\smf\release" /libpath:"..\Zlib"
# Begin Special Build Tool
SOURCE=$(InputPath)
PostBuild_Cmds=copy release\prngcore.dll C:\windows\system
# End Special Build Tool

!ELSEIF  "$(CFG)" == "prngcore - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /Zi /Od /I "..\smf" /I "..\entropyhooks" /I "..\Zlib" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /o NUL /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /o NUL /win32
# ADD BASE RSC /l 0x1009 /d "_DEBUG"
# ADD RSC /l 0x1009 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 zlibd.lib smf.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept /libpath:"..\smf\debug" /libpath:"..\Zlib"
# SUBTRACT LINK32 /verbose
# Begin Special Build Tool
SOURCE=$(InputPath)
PostBuild_Cmds=copy debug\prngcore.dll C:\windows\system
# End Special Build Tool

!ENDIF 

# Begin Target

# Name "prngcore - Win32 Release"
# Name "prngcore - Win32 Debug"
# Begin Group "Source"

# PROP Default_Filter "c"
# Begin Source File

SOURCE=.\95only.c
# End Source File
# Begin Source File

SOURCE=.\comp.c
# End Source File
# Begin Source File

SOURCE=.\ntonly.c
# End Source File
# Begin Source File

SOURCE=.\prng.c
# End Source File
# Begin Source File

SOURCE=.\prng.mut
# End Source File
# Begin Source File

SOURCE=.\sha1mod.c
# End Source File
# End Group
# Begin Group "Headers"

# PROP Default_Filter "h"
# Begin Source File

SOURCE=.\95only.h
# End Source File
# Begin Source File

SOURCE=.\assertverify.h
# End Source File
# Begin Source File

SOURCE=.\comp.h
# End Source File
# Begin Source File

SOURCE=.\ntonly.h
# End Source File
# Begin Source File

SOURCE=.\prng.h
# End Source File
# Begin Source File

SOURCE=.\prngpriv.h
# End Source File
# Begin Source File

SOURCE=.\sha1mod.h
# End Source File
# Begin Source File

SOURCE=.\userdefines.h
# End Source File
# Begin Source File

SOURCE=.\usersources.h
# End Source File
# Begin Source File

SOURCE=.\yarrow.h
# End Source File
# End Group
# End Target
# End Project
