$! --- VMS.com ---
$!
$ GoSub defines
$ GoSub linker_options
$ If (P1 .nes. "")
$ Then 
$   GoSub 'P1'
$ Else
$   GoSub lib
$   GoSub destest
$   GoSub rpw
$   GoSub speed
$   GoSub des
$ EndIF
$!
$ Exit
$!
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
$!
$DEFINES:
$ LINKOPTS := "VAX_LINKER_OPTIONS.OPT"
$!
$ OBJS  = "cbc_cksum.obj,cbc_encrypt.obj,ecb_encrypt.obj,pcbc_encrypt.obj," + -
          "quad_cksum.obj,random_key.obj,read_password.obj,set_key.obj,"    + -
          "string_to_key.obj,enc_read.obj,enc_write.obj,fcrypt.obj"
$!
$ LIBDES = "cbc_cksum.c,cbc_encrypt.c,ecb_encrypt.c,enc_read.c,"           + -
           "enc_write.c,pcbc_encrypt.c,quad_cksum.c,random_key.c,"         + -
           "read_password.c,set_key.c,string_to_key.c,fcrypt.c"
$ Return
$!
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
$!
$LINKER_OPTIONS:
$ If (f$search(LINKOPTS) .eqs. "")
$ Then
$   Create 'LINKOPTS'
$DECK
! Default system options file to link against the sharable C runtime library
!
Sys$Share:VAXcRTL.exe/Share
$EOD
$ EndIF
$ Return
$!
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
$!
$LIB:
$ CC 'LIBDES'
$ If (f$search("LIBDES.OLB") .nes. "")
$ Then Library /Object /Replace libdes 'OBJS'
$ Else Library /Create /Object  libdes 'OBJS'
$ EndIF
$ Return
$!
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
$!
$DESTEST:
$ CC destest
$ Link /Exec=destest destest.obj,libdes/LIBRARY,'linkopts'/Option
$ Return
$!
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
$!
$RPW:
$ CC rpw
$ Link /Exec=rpw  rpw.obj,libdes/LIBRARY,'linkopts'/Option
$ Return
$!
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
$!
$SPEED:
$ CC speed
$ Link /Exec=speed speed.obj,libdes/LIBRARY,'linkopts'/Option
$ Return
$!
$!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
$!
$DES:
$ CC des
$ Link /Exec=des des.obj,libdes/LIBRARY,'linkopts'/Option
$ Return
