ORIGIN = PWB
ORIGIN_VER = 2.0
PROJ = ripem
PROJFILE = ripem.mak
DEBUG = 0

BSCMAKE = bscmake
SBRPACK = sbrpack
NMAKEBSC1  = set
NMAKEBSC2  = nmake
CC  = cl
CFLAGS_G  = /AL /W2 /Za /DPROTOTYPES=1 /DUSE_SOCKETS /BATCH
CFLAGS_D  = /f /Od /Zi
CFLAGS_R  = /f- /Ot /Ol /Og /Oe /Oi /Gs /I..\rsaref\source
CXX  = cl
CXXFLAGS_G      = /W2 /BATCH
CXXFLAGS_D      = /f /Zi /Od
CXXFLAGS_R      = /f- /Ot /Oi /Ol /Oe /Og /Gs /I..\rsaref\source
MAPFILE_D  = NUL
MAPFILE_R  = NUL
LFLAGS_G  = /NOI /STACK:26000 /BATCH /ONERROR:NOEXE
LFLAGS_D  = /CO /FAR /PACKC
LFLAGS_R  = /EXE /FAR /PACKC
LINKER  = link
ILINK  = ilink
LRF  = echo > NUL
ILFLAGS = /a /e

FILES  = ADDUSER.C BEMPARSE.C CRACKHED.C DERKEY.C GETOPT.C GETSYS.C HEXBIN.C\
		  KEYDER.C KEYMAN.C LIST.C MSC7.C PARSIT.C  PRENCODE.C\
		  RDWRMSG.C RIPEMMAI.C STRUTIL.C USAGE.C USAGEMSG.C\
		  ..\rsaref\test\rsaref.lib DDES.C RIPEMSOC.C PUBINFO.C\
		  ..\..\..\FTPDEV\NETMSC5.1\LNETLIB.LIB\
		  ..\..\..\FTPDEV\NETMSC5.1\LPC.LIB\
		  ..\..\..\FTPDEV\NETMSC5.1\LSOCKET.LIB
OBJS    = ADDUSER.obj BEMPARSE.obj CRACKHED.obj DERKEY.obj GETOPT.obj GETSYS.obj\
		  HEXBIN.obj KEYDER.obj KEYMAN.obj LIST.obj MSC7.obj PARSIT.obj\
			PRENCODE.obj RDWRMSG.obj RIPEMMAI.obj STRUTIL.obj\
		  USAGE.obj USAGEMSG.obj DDES.obj RIPEMSOC.obj PUBINFO.obj
LIBS_EXT  = ..\rsaref\test\rsaref.lib ..\..\..\FTPDEV\NETMSC5.1\LNETLIB.LIB\
		  ..\..\..\FTPDEV\NETMSC5.1\LPC.LIB\
		  ..\..\..\FTPDEV\NETMSC5.1\LSOCKET.LIB
LIBS    = $(LIBS_EXT)
SBRS    = ADDUSER.sbr BEMPARSE.sbr CRACKHED.sbr DERKEY.sbr GETOPT.sbr GETSYS.sbr\
		  HEXBIN.sbr KEYDER.sbr KEYMAN.sbr LIST.sbr MSC7.sbr PARSIT.sbr\
		  PRENCODE.sbr RDWRMSG.sbr RIPEMMAI.sbr STRUTIL.sbr\
		  USAGE.sbr USAGEMSG.sbr DDES.sbr RIPEMSOC.sbr PUBINFO.sbr

all: $(PROJ).exe

.SUFFIXES:
.SUFFIXES:
.SUFFIXES: .obj .sbr .c

ADDUSER.obj : ADDUSER.C global.h c:\cip\rsaref\source\rsaref.h ripem.h list.h\
		  listprot.h strutilp.h keyfield.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_D) /FoADDUSER.obj ADDUSER.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_R) /FoADDUSER.obj ADDUSER.C
<<
!ENDIF

ADDUSER.sbr : ADDUSER.C global.h c:\cip\rsaref\source\rsaref.h ripem.h list.h\
		  listprot.h strutilp.h keyfield.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_D) /FRADDUSER.sbr ADDUSER.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_R) /FRADDUSER.sbr ADDUSER.C
<<
!ENDIF

BEMPARSE.obj : BEMPARSE.C bemparse.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_D) /FoBEMPARSE.obj BEMPARSE.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_R) /FoBEMPARSE.obj BEMPARSE.C
<<
!ENDIF

BEMPARSE.sbr : BEMPARSE.C bemparse.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_D) /FRBEMPARSE.sbr BEMPARSE.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_R) /FRBEMPARSE.sbr BEMPARSE.C
<<
!ENDIF

CRACKHED.obj : CRACKHED.C global.h c:\cip\rsaref\source\rsaref.h ripem.h\
		  ripemglo.h prcodepr.h crackhpr.h strutilp.h hexbinpr.h derkeypr.h\
		  list.h keyfield.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_D) /FoCRACKHED.obj CRACKHED.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_R) /FoCRACKHED.obj CRACKHED.C
<<
!ENDIF

CRACKHED.sbr : CRACKHED.C global.h c:\cip\rsaref\source\rsaref.h ripem.h\
		  ripemglo.h prcodepr.h crackhpr.h strutilp.h hexbinpr.h derkeypr.h\
		  list.h keyfield.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_D) /FRCRACKHED.sbr CRACKHED.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_R) /FRCRACKHED.sbr CRACKHED.C
<<
!ENDIF

DERKEY.obj : DERKEY.C global.h c:\cip\rsaref\source\rsaref.h ripem.h\
		  derkeypr.h list.h keyfield.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_D) /FoDERKEY.obj DERKEY.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_R) /FoDERKEY.obj DERKEY.C
<<
!ENDIF

DERKEY.sbr : DERKEY.C global.h c:\cip\rsaref\source\rsaref.h ripem.h\
		  derkeypr.h list.h keyfield.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_D) /FRDERKEY.sbr DERKEY.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_R) /FRDERKEY.sbr DERKEY.C
<<
!ENDIF

GETOPT.obj : GETOPT.C
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_D) /FoGETOPT.obj GETOPT.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_R) /FoGETOPT.obj GETOPT.C
<<
!ENDIF

GETOPT.sbr : GETOPT.C
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_D) /FRGETOPT.sbr GETOPT.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_R) /FRGETOPT.sbr GETOPT.C
<<
!ENDIF

GETSYS.obj : GETSYS.C global.h c:\cip\rsaref\source\rsaref.h ripem.h\
		  getsyspr.h strutilp.h list.h keyfield.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_D) /FoGETSYS.obj GETSYS.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_R) /FoGETSYS.obj GETSYS.C
<<
!ENDIF

GETSYS.sbr : GETSYS.C global.h c:\cip\rsaref\source\rsaref.h ripem.h\
		  getsyspr.h strutilp.h list.h keyfield.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_D) /FRGETSYS.sbr GETSYS.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_R) /FRGETSYS.sbr GETSYS.C
<<
!ENDIF

HEXBIN.obj : HEXBIN.C
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_D) /FoHEXBIN.obj HEXBIN.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_R) /FoHEXBIN.obj HEXBIN.C
<<
!ENDIF

HEXBIN.sbr : HEXBIN.C
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_D) /FRHEXBIN.sbr HEXBIN.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_R) /FRHEXBIN.sbr HEXBIN.C
<<
!ENDIF

KEYDER.obj : KEYDER.C global.h c:\cip\rsaref\source\rsaref.h ripem.h\
		  keyderpr.h list.h keyfield.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_D) /FoKEYDER.obj KEYDER.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_R) /FoKEYDER.obj KEYDER.C
<<
!ENDIF

KEYDER.sbr : KEYDER.C global.h c:\cip\rsaref\source\rsaref.h ripem.h\
		  keyderpr.h list.h keyfield.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_D) /FRKEYDER.sbr KEYDER.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_R) /FRKEYDER.sbr KEYDER.C
<<
!ENDIF

KEYMAN.obj : KEYMAN.C global.h c:\cip\rsaref\source\rsaref.h\
		  c:\cip\rsaref\source\md5.h ripem.h ripemglo.h ddes.h keymanpr.h\
		  strutilp.h derkeypr.h prcodepr.h hexbinpr.h getsyspr.h ripemsop.h\
		  pubinfop.h keyderpr.h bemparse.h list.h keyfield.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_D) /FoKEYMAN.obj KEYMAN.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_R) /FoKEYMAN.obj KEYMAN.C
<<
!ENDIF

KEYMAN.sbr : KEYMAN.C global.h c:\cip\rsaref\source\rsaref.h\
		  c:\cip\rsaref\source\md5.h ripem.h ripemglo.h ddes.h keymanpr.h\
		  strutilp.h derkeypr.h prcodepr.h hexbinpr.h getsyspr.h ripemsop.h\
		  pubinfop.h keyderpr.h bemparse.h list.h keyfield.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_D) /FRKEYMAN.sbr KEYMAN.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_R) /FRKEYMAN.sbr KEYMAN.C
<<
!ENDIF

LIST.obj : LIST.C list.h listprot.h strutilp.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_D) /FoLIST.obj LIST.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_R) /FoLIST.obj LIST.C
<<
!ENDIF

LIST.sbr : LIST.C list.h listprot.h strutilp.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_D) /FRLIST.sbr LIST.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_R) /FRLIST.sbr LIST.C
<<
!ENDIF

MSC7.obj : MSC7.C
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_D) /FoMSC7.obj MSC7.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_R) /FoMSC7.obj MSC7.C
<<
!ENDIF

MSC7.sbr : MSC7.C
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_D) /FRMSC7.sbr MSC7.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_R) /FRMSC7.sbr MSC7.C
<<
!ENDIF

PARSIT.obj : PARSIT.C
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_D) /FoPARSIT.obj PARSIT.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_R) /FoPARSIT.obj PARSIT.C
<<
!ENDIF

PARSIT.sbr : PARSIT.C
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_D) /FRPARSIT.sbr PARSIT.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_R) /FRPARSIT.sbr PARSIT.C
<<
!ENDIF

PRENCODE.obj : PRENCODE.C prcodepr.h prencode.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_D) /FoPRENCODE.obj PRENCODE.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_R) /FoPRENCODE.obj PRENCODE.C
<<
!ENDIF

PRENCODE.sbr : PRENCODE.C prcodepr.h prencode.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_D) /FRPRENCODE.sbr PRENCODE.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_R) /FRPRENCODE.sbr PRENCODE.C
<<
!ENDIF

RDWRMSG.obj : RDWRMSG.C global.h c:\cip\rsaref\source\rsaref.h ripem.h\
		  ripemglo.h rdwrmsgp.h strutilp.h listprot.h adduserp.h list.h\
		  keyfield.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_D) /FoRDWRMSG.obj RDWRMSG.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_R) /FoRDWRMSG.obj RDWRMSG.C
<<
!ENDIF

RDWRMSG.sbr : RDWRMSG.C global.h c:\cip\rsaref\source\rsaref.h ripem.h\
		  ripemglo.h rdwrmsgp.h strutilp.h listprot.h adduserp.h list.h\
		  keyfield.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_D) /FRRDWRMSG.sbr RDWRMSG.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_R) /FRRDWRMSG.sbr RDWRMSG.C
<<
!ENDIF

RIPEMMAI.obj : RIPEMMAI.C global.h c:\cip\rsaref\source\rsaref.h ripem.h\
		  ripemglo.h prcodepr.h usagepro.h getoptpr.h ripempro.h\
		  getsyspr.h strutilp.h keyderpr.h derkeypr.h keymanpr.h listprot.h\
		  adduserp.h ..\rsaref\source\r_random.h bemparse.h hexbinpr.h crackhpr.h rdwrmsgp.h\
		  parsitpr.h p.h list.h keyfield.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_D) /FoRIPEMMAI.obj RIPEMMAI.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_R) /FoRIPEMMAI.obj RIPEMMAI.C
<<
!ENDIF

RIPEMMAI.sbr : RIPEMMAI.C global.h c:\cip\rsaref\source\rsaref.h ripem.h\
		  ripemglo.h prcodepr.h usagepro.h getoptpr.h ripempro.h\
		  getsyspr.h strutilp.h keyderpr.h derkeypr.h keymanpr.h listprot.h\
		  adduserp.h ..\rsaref\source\r_random.h bemparse.h hexbinpr.h crackhpr.h rdwrmsgp.h\
		  parsitpr.h p.h list.h keyfield.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_D) /FRRIPEMMAI.sbr RIPEMMAI.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_R) /FRRIPEMMAI.sbr RIPEMMAI.C
<<
!ENDIF

STRUTIL.obj : STRUTIL.C boolean.h strutilp.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_D) /FoSTRUTIL.obj STRUTIL.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_R) /FoSTRUTIL.obj STRUTIL.C
<<
!ENDIF

STRUTIL.sbr : STRUTIL.C boolean.h strutilp.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_D) /FRSTRUTIL.sbr STRUTIL.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_R) /FRSTRUTIL.sbr STRUTIL.C
<<
!ENDIF

USAGE.obj : USAGE.C
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_D) /FoUSAGE.obj USAGE.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_R) /FoUSAGE.obj USAGE.C
<<
!ENDIF

USAGE.sbr : USAGE.C
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_D) /FRUSAGE.sbr USAGE.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_R) /FRUSAGE.sbr USAGE.C
<<
!ENDIF

USAGEMSG.obj : USAGEMSG.C
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_D) /FoUSAGEMSG.obj USAGEMSG.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_R) /FoUSAGEMSG.obj USAGEMSG.C
<<
!ENDIF

USAGEMSG.sbr : USAGEMSG.C
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_D) /FRUSAGEMSG.sbr USAGEMSG.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_R) /FRUSAGEMSG.sbr USAGEMSG.C
<<
!ENDIF

DDES.obj : DDES.C ddes.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_D) /FoDDES.obj DDES.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_R) /FoDDES.obj DDES.C
<<
!ENDIF

DDES.sbr : DDES.C ddes.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_D) /FRDDES.sbr DDES.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_R) /FRDDES.sbr DDES.C
<<
!ENDIF

RIPEMSOC.obj : RIPEMSOC.C global.h c:\cip\rsaref\source\rsaref.h ripem.h\
		  ripemsop.h ripemglo.h keyfield.h protserv.h list.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_D) /FoRIPEMSOC.obj RIPEMSOC.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_R) /FoRIPEMSOC.obj RIPEMSOC.C
<<
!ENDIF

RIPEMSOC.sbr : RIPEMSOC.C global.h c:\cip\rsaref\source\rsaref.h ripem.h\
		  ripemsop.h ripemglo.h keyfield.h protserv.h list.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_D) /FRRIPEMSOC.sbr RIPEMSOC.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_R) /FRRIPEMSOC.sbr RIPEMSOC.C
<<
!ENDIF

PUBINFO.obj : PUBINFO.C boolean.h keyfield.h pubinfop.h global.h\
		  c:\cip\rsaref\source\rsaref.h ripem.h list.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_D) /FoPUBINFO.obj PUBINFO.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_R) /FoPUBINFO.obj PUBINFO.C
<<
!ENDIF

PUBINFO.sbr : PUBINFO.C boolean.h keyfield.h pubinfop.h global.h\
		  c:\cip\rsaref\source\rsaref.h ripem.h list.h
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_D) /FRPUBINFO.sbr PUBINFO.C
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_R) /FRPUBINFO.sbr PUBINFO.C
<<
!ENDIF


$(PROJ).bsc : $(SBRS)
		  $(BSCMAKE) @<<
$(BRFLAGS) $(SBRS)
<<

$(PROJ).exe : $(OBJS) $(LIBS)
!IF $(DEBUG)
		  $(LRF) @<<$(PROJ).lrf
$(RT_OBJS: = +^
) $(OBJS: = +^
)
$@
$(MAPFILE_D)
$(LIBS: = +^
) +
$(LLIBS_G: = +^
) +
$(LLIBS_D: = +^
)
$(DEF_FILE) $(LFLAGS_G) $(LFLAGS_D);
<<
!ELSE
		  $(LRF) @<<$(PROJ).lrf
$(RT_OBJS: = +^
) $(OBJS: = +^
)
$@
$(MAPFILE_R)
$(LIBS: = +^
) +
$(LLIBS_G: = +^
) +
$(LLIBS_R: = +^
)
$(DEF_FILE) $(LFLAGS_G) $(LFLAGS_R);
<<
!ENDIF
		  $(LINKER) @$(PROJ).lrf


.c.obj :
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_D) /Fo$@ $<
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/c $(CFLAGS_G)
$(CFLAGS_R) /Fo$@ $<
<<
!ENDIF

.c.sbr :
!IF $(DEBUG)
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_D) /FR$@ $<
<<
!ELSE
		  @$(CC) @<<$(PROJ).rsp
/Zs $(CFLAGS_G)
$(CFLAGS_R) /FR$@ $<
<<
!ENDIF


run: $(PROJ).exe
		  $(PROJ).exe $(RUNFLAGS)

debug: $(PROJ).exe
		  CV $(CVFLAGS) $(PROJ).exe $(RUNFLAGS)
