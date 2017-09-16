# Makefile for RIPEM utilities in ripem/util
CC=gcc
CFLAGS=-I../main

PRCODE_ROUTINES=tprencod.o prencode.o ../main/usage.o ../main/getopt.o

all: man2code prencode stripmsg nobksp quote tstbem

prencode: $(PRCODE_ROUTINES)
	$(CC) -o prencode $(CFLAGS) $(PRCODE_ROUTINES)

stripmsg: stripmsg.o
	$(CC) -o stripmsg $(CFLAGS) stripmsg.o
	
man2code: man2code.o
	$(CC) -o man2code man2code.o 

nobksp: nobksp.o
	$(CC) -o nobksp nobksp.o

quote: quote.o ../main/getopt.o
	$(CC) -o quote quote.o ../main/getopt.o

tstbem: tstbem.o ../main/bemparse.o
	$(CC) -o tstbem tstbem.o ../main/bemparse.o

