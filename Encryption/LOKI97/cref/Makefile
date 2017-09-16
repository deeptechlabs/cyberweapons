#	Make loki97

CFLAGS=	-g
PROGS=	aestest aestime test_ecb test_cbc test_cfb1
OBJ=	loki97.o aestest.o aestime.o test_ecb.o test_cbc.o test_cfb1.o
XLIB=	loki97.o

all:	$(PROGS)

aestest:	aestest.o $(XLIB)
	cc -o aestest aestest.o $(XLIB)

aestime:	aestime.o $(XLIB)
	cc -o aestime aestime.o $(XLIB)

test_ecb:	test_ecb.o $(XLIB)
	cc -o test_ecb test_ecb.o $(XLIB)

test_cbc:	test_cbc.o $(XLIB)
	cc -o test_cbc test_cbc.o $(XLIB)

test_cfb1:	test_cfb1.o $(XLIB)
	cc -o test_cfb1 test_cfb1.o $(XLIB)

test:	$(PROGS)
	test_ecb 2>&1 | less
	test_cbc 2>&1 | less
	test_cfb1 2>&1 | less

clean:
	-rm $(OBJ)

clobber:	clean
	-rm $(PROGS)
