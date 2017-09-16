# Microsoft Developer Studio Project File - Name="Crypt32" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=CRYPT32 - WIN32 RELEASE
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "Crypt32.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "Crypt32.mak" CFG="CRYPT32 - WIN32 RELEASE"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "Crypt32 - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "Crypt32 - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "Crypt32 - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir ".\Release"
# PROP BASE Intermediate_Dir ".\Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir ".\Release"
# PROP Intermediate_Dir ".\Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
F90=fl32.exe
# ADD BASE F90 /I "Release/"
# ADD F90 /I "Release/"
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MT /W3 /O2 /D "NDEBUG" /D "INC_CHILD" /D "DEV_PKCS11" /D "DEV_FORTEZZA" /FD /c
# SUBTRACT CPP /YX
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 kernel32.lib user32.lib advapi32.lib /nologo /subsystem:windows /dll /pdb:none /machine:I386 /out:".\Release/CL32.dll"

!ELSEIF  "$(CFG)" == "Crypt32 - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir ".\Debug"
# PROP BASE Intermediate_Dir ".\Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir ".\Test32"
# PROP Intermediate_Dir ".\Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
F90=fl32.exe
# ADD BASE F90 /I "Debug/"
# ADD F90 /I "Debug/"
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MT /W3 /Gm /Zi /Od /D "INC_CHILD" /D "DEV_PKCS11" /D "DEV_FORTEZZA" /FD /c
# SUBTRACT CPP /Fr /YX
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /debug /machine:I386
# ADD LINK32 kernel32.lib user32.lib advapi32.lib /nologo /subsystem:windows /dll /pdb:none /debug /machine:I386 /out:".\Test32/CL32.dll"

!ENDIF 

# Begin Target

# Name "Crypt32 - Win32 Release"
# Name "Crypt32 - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;hpj;bat;for;f90"
# Begin Group "Bignum library"

# PROP Default_Filter ""
# Begin Source File

SOURCE=\bn\bn_add.c
# End Source File
# Begin Source File

SOURCE=\bn\bn_blind.c
# End Source File
# Begin Source File

SOURCE=\bn\bn_div.c
# End Source File
# Begin Source File

SOURCE=\bn\bn_exp.c
# End Source File
# Begin Source File

SOURCE=\bn\bn_gcd.c
# End Source File
# Begin Source File

SOURCE=\bn\bn_lib.c
# End Source File
# Begin Source File

SOURCE=\bn\bn_mod.c
# End Source File
# Begin Source File

SOURCE=\bn\bn_mont.c
# End Source File
# Begin Source File

SOURCE=\bn\bn_mul.c
# End Source File
# Begin Source File

SOURCE=\bn\bn_recp.c
# End Source File
# Begin Source File

SOURCE=\bn\bn_shift.c
# End Source File
# Begin Source File

SOURCE=\bn\bn_sqr.c
# End Source File
# Begin Source File

SOURCE=\bn\bn_sub.c
# End Source File
# Begin Source File

SOURCE=\bn\bn_word.c
# End Source File
# Begin Source File

SOURCE="\bn\bn-win32.obj"
# End Source File
# End Group
# Begin Group "Crypt/Hash algorithms"

# PROP Default_Filter ""
# Begin Source File

SOURCE=\crypt\bf_ecb.c
# End Source File
# Begin Source File

SOURCE=\crypt\bf_skey.c
# End Source File
# Begin Source File

SOURCE=\crypt\c_ecb.c
# End Source File
# Begin Source File

SOURCE=\crypt\c_skey.c
# End Source File
# Begin Source File

SOURCE=\crypt\ecb3_enc.c
# End Source File
# Begin Source File

SOURCE=\crypt\ecb_enc.c
# End Source File
# Begin Source File

SOURCE=\crypt\idea.c
# End Source File
# Begin Source File

SOURCE=\crypt\idea_386.c
# End Source File
# Begin Source File

SOURCE=\hash\md2.c
# End Source File
# Begin Source File

SOURCE=\hash\md4.c
# End Source File
# Begin Source File

SOURCE=\hash\md5_dgst.c
# End Source File
# Begin Source File

SOURCE=\hash\mdc2dgst.c
# End Source File
# Begin Source File

SOURCE=\crypt\rc2.c
# End Source File
# Begin Source File

SOURCE=\crypt\rc4_skey.c
# End Source File
# Begin Source File

SOURCE=\crypt\rc5.c
# End Source File
# Begin Source File

SOURCE=\hash\ripemd.c
# End Source File
# Begin Source File

SOURCE=\hash\rmd160cp.c
# End Source File
# Begin Source File

SOURCE=\crypt\safer.c
# End Source File
# Begin Source File

SOURCE=\crypt\set_key.c
# End Source File
# Begin Source File

SOURCE=\hash\sha1dgst.c
# End Source File
# Begin Source File

SOURCE=\hash\sha_dgst.c
# End Source File
# Begin Source File

SOURCE=\crypt\skipjack.c
# End Source File
# Begin Source File

SOURCE="\crypt\b-win32.obj"
# End Source File
# Begin Source File

SOURCE="\crypt\c-win32.obj"
# End Source File
# Begin Source File

SOURCE="\crypt\d-win32.obj"
# End Source File
# Begin Source File

SOURCE="\hash\m-win32.obj"
# End Source File
# Begin Source File

SOURCE="\crypt\r-win32.obj"
# End Source File
# Begin Source File

SOURCE="\hash\s-win32.obj"
# End Source File
# End Group
# Begin Group "Devices"

# PROP Default_Filter ""
# Begin Source File

SOURCE=\misc\dev_fort.c
# End Source File
# Begin Source File

SOURCE=\misc\dev_pk11.c
# End Source File
# Begin Source File

SOURCE=\misc\dev_sys.c
# End Source File
# Begin Source File

SOURCE=\misc\scase.c
# End Source File
# Begin Source File

SOURCE=\misc\scgemplu.c
# End Source File
# Begin Source File

SOURCE=\misc\scmisc.c
# End Source File
# Begin Source File

SOURCE=\misc\sctowito.c
# End Source File
# End Group
# Begin Group "Lib_xxx glue code"

# PROP Default_Filter ""
# Begin Source File

SOURCE=\lib_3des.c
# End Source File
# Begin Source File

SOURCE=\lib_bf.c
# End Source File
# Begin Source File

SOURCE=\lib_cast.c
# End Source File
# Begin Source File

SOURCE=\lib_des.c
# End Source File
# Begin Source File

SOURCE=\lib_dh.c
# End Source File
# Begin Source File

SOURCE=\lib_dsa.c
# End Source File
# Begin Source File

SOURCE=\lib_elg.c
# End Source File
# Begin Source File

SOURCE=\lib_hmd5.c
# End Source File
# Begin Source File

SOURCE=\lib_hrmd.c
# End Source File
# Begin Source File

SOURCE=\lib_hsha.c
# End Source File
# Begin Source File

SOURCE=\lib_idea.c
# End Source File
# Begin Source File

SOURCE=\lib_kg.c
# End Source File
# Begin Source File

SOURCE=\lib_md2.c
# End Source File
# Begin Source File

SOURCE=\lib_md4.c
# End Source File
# Begin Source File

SOURCE=\lib_md5.c
# End Source File
# Begin Source File

SOURCE=\lib_mdc2.c
# End Source File
# Begin Source File

SOURCE=\lib_rc2.c
# End Source File
# Begin Source File

SOURCE=\lib_rc4.c
# End Source File
# Begin Source File

SOURCE=\lib_rc5.c
# End Source File
# Begin Source File

SOURCE=\lib_ripe.c
# End Source File
# Begin Source File

SOURCE=\lib_rsa.c
# End Source File
# Begin Source File

SOURCE=\lib_safr.c
# End Source File
# Begin Source File

SOURCE=\lib_sha.c
# End Source File
# Begin Source File

SOURCE=\lib_skip.c
# End Source File
# End Group
# Begin Group "Misc"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\Crypt32.def
# End Source File
# Begin Source File

SOURCE=.\Crypt32.rc
# End Source File
# Begin Source File

SOURCE=\misc\dbxhttp.c
# End Source File
# Begin Source File

SOURCE=\misc\dbxldap.c
# End Source File
# Begin Source File

SOURCE=\misc\dbxmsql.c
# End Source File
# Begin Source File

SOURCE=\misc\dbxodbc.c
# End Source File
# Begin Source File

SOURCE=\misc\dbxpgp.c
# End Source File
# Begin Source File

SOURCE=\misc\dbxpk12.c
# End Source File
# Begin Source File

SOURCE=\misc\dbxpk15.c
# End Source File
# Begin Source File

SOURCE=\misc\dbxscard.c
# End Source File
# Begin Source File

SOURCE=\envelope\pgp_deen.c
# End Source File
# Begin Source File

SOURCE=\envelope\pgp_misc.c
# End Source File
# Begin Source File

SOURCE=\misc\rndwin32.c
# End Source File
# Begin Source File

SOURCE=\keymgmt\stream.c
# End Source File
# End Group
# Begin Group "Zlib"

# PROP Default_Filter ""
# Begin Source File

SOURCE=\zlib\adler32.c
# End Source File
# Begin Source File

SOURCE=\zlib\deflate.c
# End Source File
# Begin Source File

SOURCE=\zlib\infblock.c
# End Source File
# Begin Source File

SOURCE=\zlib\infcodes.c
# End Source File
# Begin Source File

SOURCE=\zlib\inffast.c
# End Source File
# Begin Source File

SOURCE=\zlib\inflate.c
# End Source File
# Begin Source File

SOURCE=\zlib\inftrees.c
# End Source File
# Begin Source File

SOURCE=\zlib\infutil.c
# End Source File
# Begin Source File

SOURCE=\zlib\trees.c
# End Source File
# Begin Source File

SOURCE=\zlib\zutil.c
# End Source File
# Begin Source File

SOURCE=\zlib\gvmat32.obj
# End Source File
# End Group
# Begin Group "Envelopes/Sessions"

# PROP Default_Filter ""
# Begin Source File

SOURCE=\session\cmp.c
# End Source File
# Begin Source File

SOURCE=\envelope\deenvel.c
# End Source File
# Begin Source File

SOURCE=\envelope\envelope.c
# End Source File
# Begin Source File

SOURCE=\misc\net_tcp.c
# End Source File
# Begin Source File

SOURCE=\envelope\octetstr.c
# End Source File
# Begin Source File

SOURCE=\envelope\resource.c
# End Source File
# Begin Source File

SOURCE=\session\ssh.c
# End Source File
# Begin Source File

SOURCE=\session\ssl.c
# End Source File
# End Group
# Begin Group "Key Management"

# PROP Default_Filter ""
# Begin Source File

SOURCE=\keymgmt\asn1.c
# End Source File
# Begin Source File

SOURCE=\keymgmt\asn1keys.c
# End Source File
# Begin Source File

SOURCE=\keymgmt\asn1objs.c
# End Source File
# Begin Source File

SOURCE=\keymgmt\asn1oid.c
# End Source File
# Begin Source File

SOURCE=\keymgmt\cert.c
# End Source File
# Begin Source File

SOURCE=\keymgmt\certchk.c
# End Source File
# Begin Source File

SOURCE=\keymgmt\certchn.c
# End Source File
# Begin Source File

SOURCE=\keymgmt\certcomp.c
# End Source File
# Begin Source File

SOURCE=\keymgmt\certechk.c
# End Source File
# Begin Source File

SOURCE=\keymgmt\certedef.c
# End Source File
# Begin Source File

SOURCE=\keymgmt\certexrw.c
# End Source File
# Begin Source File

SOURCE=\keymgmt\certext.c
# End Source File
# Begin Source File

SOURCE=\keymgmt\certio.c
# End Source File
# Begin Source File

SOURCE=\keymgmt\certrust.c
# End Source File
# Begin Source File

SOURCE=\keymgmt\certsig.c
# End Source File
# Begin Source File

SOURCE=\keymgmt\certstr.c
# End Source File
# Begin Source File

SOURCE=\keymgmt\cms.c
# End Source File
# End Group
# Begin Source File

SOURCE=\crypt.c
# End Source File
# Begin Source File

SOURCE=\cryptapi.c
# End Source File
# Begin Source File

SOURCE=\cryptcfg.c
# End Source File
# Begin Source File

SOURCE=\cryptcrt.c
# End Source File
# Begin Source File

SOURCE=\cryptdbx.c
# End Source File
# Begin Source File

SOURCE=\cryptdev.c
# End Source File
# Begin Source File

SOURCE=\cryptenv.c
# End Source File
# Begin Source File

SOURCE=\cryptkey.c
# End Source File
# Begin Source File

SOURCE=\cryptkrn.c
# End Source File
# Begin Source File

SOURCE=\cryptlib.c
# End Source File
# Begin Source File

SOURCE=\cryptmch.c
# End Source File
# Begin Source File

SOURCE=\cryptmis.c
# End Source File
# Begin Source File

SOURCE=\cryptses.c
# End Source File
# Begin Source File

SOURCE=\lib_dbms.c
# End Source File
# Begin Source File

SOURCE=\lib_keyx.c
# End Source File
# Begin Source File

SOURCE=\lib_sign.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl;fi;fd"
# Begin Source File

SOURCE=\keymgmt\asn1.h
# End Source File
# Begin Source File

SOURCE=\keymgmt\asn1objs.h
# End Source File
# Begin Source File

SOURCE=\keymgmt\asn1oid.h
# End Source File
# Begin Source File

SOURCE=\keymgmt\cert.h
# End Source File
# Begin Source File

SOURCE=\keymgmt\certattr.h
# End Source File
# Begin Source File

SOURCE=\crypt.h
# End Source File
# Begin Source File

SOURCE=\cryptacl.h
# End Source File
# Begin Source File

SOURCE=\cryptctx.h
# End Source File
# Begin Source File

SOURCE=\cryptkrn.h
# End Source File
# Begin Source File

SOURCE=\cryptlib.h
# End Source File
# Begin Source File

SOURCE=\misc\device.h
# End Source File
# Begin Source File

SOURCE=\envelope\envelope.h
# End Source File
# Begin Source File

SOURCE=\misc\keyset.h
# End Source File
# Begin Source File

SOURCE=\misc\net.h
# End Source File
# Begin Source File

SOURCE=\session\session.h
# End Source File
# Begin Source File

SOURCE=\keymgmt\stream.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;cnt;rtf;gif;jpg;jpeg;jpe"
# Begin Source File

SOURCE=.\Crypt32.ico
# End Source File
# End Group
# End Target
# End Project
