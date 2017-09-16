## The location of the -lucre source
LUCREINC=-I../-lucre-0.8.1
LUCRELIB=-L../-lucre-0.8.1 -lucre

## The location of the SSLeay include files and library
SSLEAYINC=-I/usr/local/SSLeay/include
SSLEAYLIB=-L/usr/local/SSLeay/lib -lcrypto

## The location of the Berkeley db include files and library (if necessary)
DBINC=
DBLIB=-ldb

## Any other libraries you may need (use "-lnsl -lsocket" for Solaris)
MORELIBS=

## Your compiler
CC=gcc

CFLAGS=-Wall -g $(LUCREINC) $(SSLEAYINC) $(DBINC)

PROG=s-lc

OBJS=main.o openacc.o deposit.o withd.o pay.o getpay.o reqpay.o expreq.o \
     balance.o passwd.o

$(PROG): $(OBJS)
	$(CC) -o $(PROG) $(OBJS) $(LUCRELIB) $(SSLEAYLIB) $(DBLIB) $(MORELIBS)

$(OBJS): client.h

clean:
	-rm -f $(OBJS)

veryclean: clean
	-rm -f $(PROG)
