# CAST-128 in C
# Written by Steve Reid <sreid@sea-to-sky.net>
# 100% Public Domain - no warranty
# Released 1997.10.11

CC = gcc
CFLAGS = -O2 -fomit-frame-pointer -Wall -pedantic

all: casttest

casttest:	cast.o casttest.o
	$(CC) $(CFLAGS) -o casttest cast.o casttest.o

clean:
	rm -f *.o *.core

