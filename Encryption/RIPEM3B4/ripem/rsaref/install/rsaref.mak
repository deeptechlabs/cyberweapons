# This is a MAKEFILE for Microsoft's NMAKE

# extension for object files
O = obj

# commands
CC = cl
LIB = lib

# name of temporary library script
TEMPFILE = $(TEMP)\temp.mak

# The places to look for include files (in order).
INCL =  -I. -I$(RSAREFDIR)

# Normal C flags.
CFLAGS = -Ox -W3 -AL $(INCL) -nologo -c
LFLAGS = /stack:26000

# Debugging C flags.
# CFLAGS =  -W3 -AL -Zi -Od $(INCL) -nologo -c
# LFLAGS = /codeview /map /stack:26000
 
# The location of the common source directory.
RSAREFDIR = ..\source\#
RSAREFLIB = rsaref.lib

# The location of the demo source directory.
RDEMODIR = ..\rdemo\#

all : rsaref.lib
# all : rdemo.exe dhdemo.exe

rdemo.exe : rdemo.$(O) $(RSAREFLIB)
	link @<<rdemo.lnk
$(LFLAGS) rdemo.$(O)
$@,NUL,
$(RSAREFLIB);
<<NOKEEP

dhdemo.exe : dhdemo.$(O) $(RSAREFLIB)
	link @<<dhdemo.lnk
$(LFLAGS) dhdemo.$(O)
$@,,
$(RSAREFLIB);
<<NOKEEP

$(RSAREFLIB) : desc.$(O) digit.$(O) md2c.$(O) md5c.$(O) nn.$(O) prime.$(O)\
  rsa.$(O) r_encode.$(O) r_dh.$(O) r_enhanc.$(O) r_keygen.$(O) r_random.$(O)\
  r_stdlib.$(O)
  @del rsaref.lib
  @$(LIB) @rsaref.lrf

rdemo.$(O) : $(RDEMODIR)rdemo.c $(RSAREFDIR)global.h $(RSAREFDIR)rsaref.h
	$(CC) $(CFLAGS) $(RDEMODIR)rdemo.c

dhdemo.$(O) : $(RDEMODIR)dhdemo.c $(RSAREFDIR)global.h $(RSAREFDIR)rsaref.h
	$(CC) $(CFLAGS) $(RDEMODIR)dhdemo.c

!INCLUDE $(RSAREFDIR)targets.mak
