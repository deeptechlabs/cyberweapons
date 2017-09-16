CFLAGS=-O -DLITTLE_ENDIAN
all: descalc descycle descert certify radlogin benchmark des uuencode uudecode

des: main.o des.o getpass.o misc.o
	cc -o des main.o des.o getpass.o misc.o

benchmark: benchmark.o des.o
	cc -o benchmark benchmark.o des.o

radlogin: radlogin.o des.o
	cc -o radlogin radlogin.o des.o

descert: descert.o des.o
	cc -o descert descert.o des.o

descalc: descalc.o des.o
	cc -o descalc descalc.o des.o

descycle: descycle.o des.o
	cc -o descycle descycle.o des.o

certify: descert testdata
	descert < testdata
	touch certify

radlogin.o: radlogin.c
	cc -c -O -DUTMP_FILE=\"/etc/utmp\" radlogin.c

uuencode: uuencode.o
	cc -o uuencode uuencode.o

uudecode: uudecode.o
	cc -o uudecode uudecode.o

clean:
	rm -f descalc descycle descert certify radlogin benchmark des *.o
	rm -f uuencode uudecode
