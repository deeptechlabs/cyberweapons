# This is a makefile for UNIX

# extension for object files
O = o

# commands
CC = gcc
LIB = ar

# name of temporary library script
TEMPFILE = $(TEMP)/temp.mak

# standard include directory
STDINCDIR=/usr/include

# The places to look for include files (in order).
INCL =  -I. -I$(RSAREFDIR) -I$(STDINCDIR)

# name of main executable to build
PROG = all

# Normal C flags.
CFLAGS = $(INCL) -O -c -DPROTOTYPES=1
MFLAGS = -I. -I$(RSAREFDIR)

# The location of the common source directory.
RSAREFDIR = ../source/
RSAREFLIB = rsaref.a

# The location of the demo source directory.
RDEMODIR = ../rdemo/

all : rdemo dhdemo

rdemo : rdemo.$(O) $(RSAREFLIB)
	$(CC) -o $@ rdemo.$(O) $(RSAREFLIB)

dhdemo : dhdemo.$(O) $(RSAREFLIB)
	$(CC) -o $@ dhdemo.$(O) $(RSAREFLIB)

$(RSAREFLIB) : desc.$(O) digit.$(O) md2c.$(O) md5c.$(O) nn.$(O) prime.$(O)\
  rsa.$(O) r_encode.$(O) r_dh.$(O) r_enhanc.$(O) r_keygen.$(O) r_random.$(O)\
  r_stdlib.$(O) sha1c.$(O) rx2c.$(O) rc5_32st.$(O)
	$(LIB) r $@ $?
	ranlib $@

rdemo.$(O) : $(RDEMODIR)rdemo.c $(RSAREFDIR)global.h $(RSAREFDIR)rsaref.h
	$(CC) $(CFLAGS) $(RDEMODIR)rdemo.c

dhdemo.$(O) : $(RDEMODIR)dhdemo.c $(RSAREFDIR)global.h $(RSAREFDIR)rsaref.h
	$(CC) $(CFLAGS) $(RDEMODIR)dhdemo.c

include $(RSAREFDIR)targets.mak
