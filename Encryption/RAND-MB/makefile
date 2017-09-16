# makefile for librand
# tested on Sparc-20 (SunOS 4.x) and P100 (BSDI) only.
# You're on your own elsewhere.  Read the comments for scary warnings.
#
# Usage: int randbyte();
#
#* The authors of this software are Don Mitchell, Matt Blaze & Jack Lacy.
#*              Copyright (c) 1995 by AT&T.
#* Permission to use, copy, and modify this software without fee
#* is hereby granted, provided that this entire notice is included in
#* all copies of any software which is or includes a copy or
#* modification of this software and in all copies of the supporting
#* documentation for such software.
#*
#* This software may be subject to United States export controls.
#*
#* THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
#* WARRANTY.  IN PARTICULAR, NEITHER THE AUTHORS NOR AT&T MAKE ANY
#* REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY

SRCS=randbyte.c truerand.c shs.c
OBJS=randbyte.o truerand.o shs.o
CC=gcc
CFLAGS=
# No -O in CFLAGS! On some compilers, this optimizes out the counter...

librand.a: $(OBJS)
	ar rcv librand.a $(OBJS)
	ranlib librand.a

randtest: randtest.c $(SRCS)
	cc -DDEBUGRND randtest.c $(SRCS) -o randtest

librand.shar: makefile $(SRCS) randtest.c
	shar makefile $(SRCS) randtest.c > librand.shar
