# $Id: Makefile,v 1.1 1992/01/08 05:04:15 wengland Exp wengland $
#
# $Log: Makefile,v $
# Revision 1.1  1992/01/08  05:04:15  wengland
# Initial revision
#
#
#  A one program release does not seem to need a Makefile
#  however, here is one anyway.
#
#  Bill England,
#  Stephen Software Systems Inc., Tacoma/Seattle, +1 800 829 1684
#

# c compiler options for gcc.
# comment out if using regular compiler cc.

CC_OPT = -pipe 
CC=gcc -O

OBJECT_NAME=random.o

random.o:	random.c
	echo "Testing random number generator:"
	$(CC) $(CC_OPT) -DTESTRAND random.c
	./a.out
	rm a.out
	$(CC) $(CC_OPT) -c random.c 

clean:
	rm -f random.o a.out
