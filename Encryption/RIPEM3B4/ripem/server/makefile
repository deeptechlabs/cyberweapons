CC = gcc
CFLAGS = -O -I../../gdbm-1.5 -I../rsaref/source -I../main

READ_ROUTINES=readsock.o 

SEND_ROUTINES=sendsock.o

COPY_ROUTINES=copymail.o

CRE_ROUTINES=crekeydb.o ../main/pubinfo.o ../main/strutil.o ../main/hexbin.o ../rsaref/test/rsaref.a 
DUM_ROUTINES=credumpb.o
RKEYSERV_ROUTINES=rkeyserv.o ../main/strutil.o opeclo.o ../main/hexbin.o
RKEYREG_ROUTINES=rkeyreg.o ../main/strutil.o ../main/pubinfo.o ../main/list.o ../main/hexbin.o sendnetmail.o startnetmail.o getreta.o run.o 
DB2FLAT_ROUTINES=db2flat.o opeclo.o ../main/pubinfo.o ../main/strutil.o ../main/hexbin.o
GIVEPUBS_ROUTINES=givepubs.o ../main/strutil.o ../main/hexbin.o startnetmail.o getreta.o
REDIR_ROUTINES=redirsrv.o

GDBM_INC=../../gdbm-1.5
GDBM_LIB=../../gdbm-1.5/global.o ../../gdbm-1.5/gdbm.a
RSA_LIB=../rsaref/test/rsaref.a

default:
	@echo "     Makefile for RIPEM UDP-based public key server"
	@echo " "
	@echo "The code here is likely to be of interest only to sites who wish"
	@echo "to become public key servers."
	@echo " "
	@echo "To make the programs in this directory, you must get the GNU"
	@echo "database library gdbm-1.5.tar.Z and install it in the directory"
	@echo "../../gdbm-1.5 (relative to this directory).  Also, do a make"
	@echo "on RIPEM itself before doing a make of the server."
	@echo " "
	@echo "When you are ready, do a   make all"

all: rkeyserv rkeyreg copymail db2flat crekeydb givepubs redirsrv

clean:
	rm -f rkeyserv rkeyreg copymail db2flat crekeydb givepubs redirsrv

#copyutils: ../main/strutil.c ../main/pubinfo.c ../main/list.c
#	cp ../main/strutil.c ../main/pubinfo.c ../main/list.c .
#	touch copyutils

# readsock: Unused test program to benchmark UDP performance.
readsock: $(READ_ROUTINES)
	$(CC) -o readsock $(CFLAGS) $(READ_ROUTINES)

# sendsock: Unused test program, companion of readsock.
sendsock: $(SEND_ROUTINES)
	$(CC) -o sendsock $(CFLAGS) $(SEND_ROUTINES)

# crekeydb: Program to create random-access key database from flat file.
crekeydb: $(CRE_ROUTINES)
	$(CC) -o crekeydb $(CFLAGS) -I$(GDBM_INC) $(CRE_ROUTINES) $(GDBM_LIB)

# credumpb: Unused test program to create a dummy key database.
credumpb: $(DUM_ROUTINES)
	$(CC) -o credumpb $(CFLAGS) -I$(GDBM_INC) $(DUM_ROUTINES) $(GDBM_LIB)

rkeyserp.h: rkeyserv.c
	cproto rkeyserv.c >rkeyserp.h

# rkeyserv: The RIPEM UDP-based key server.
rkeyserv: $(RKEYSERV_ROUTINES)
	$(CC) -o rkeyserv $(CFLAGS) -I$(GDBM_INC) $(RKEYSERV_ROUTINES) $(GDBM_LIB) $(RSA_LIB)

# copymail: Simple helper program to receive incoming email-based key requests.
copymail: $(COPY_ROUTINES)
	$(CC) -o copymail $(CFLAGS) $(COPY_ROUTINES) $(RSA_LIB)

# givepubs: Program to send a file (public key flat file) to a user via email.
givepubs: $(GIVEPUBS_ROUTINES)
	$(CC) -o givepubs $(CFLAGS) $(GIVEPUBS_ROUTINES) $(RSA_LIB)

# rkeyreg:  Program to register keys.
rkeyreg: $(RKEYREG_ROUTINES)
	$(CC) -o rkeyreg $(CFLAGS) -I$(GDBM_INC) $(RKEYREG_ROUTINES) $(GDBM_LIB) $(RSA_LIB)

# db2flat:  Program to convert GDBM random key file to flat ASCII file.
db2flat: $(DB2FLAT_ROUTINES)
	$(CC) -o db2flat $(CFLAGS) -I$(GDBM_INC) $(DB2FLAT_ROUTINES) $(GDBM_LIB) $(RSA_LIB)

# redirsrv: Program to redirect UDP-based key queries to another server,
#  intended primarily for use in case a server has to be shut down for
#  administrative reasons.
redirsrv: $(REDIR_ROUTINES)
	$(CC) -o redirsrv $(CFLAGS) $(REDIR_ROUTINES) $(RSA_LIB)
