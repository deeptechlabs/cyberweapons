CC=cc
CCOPTS=-O2 -s

NROFF=nroff
NROFFOPTS=-man

default: all

all: snuffle unsnuffle snuffle.man

shar: snuffle.shar

snuffle: snuffle.o hash512.o sboxes.o Makefile
       $(CC) $(CCOPTS) -o snuffle snuffle.o hash512.o sboxes.o

unsnuffle: unsnuffle.o hash512.o sboxes.o Makefile
       $(CC) $(CCOPTS) -o unsnuffle unsnuffle.o hash512.o sboxes.o

snuffle.o: snuffle.c snefru.h
       $(CC) $(CCOPTS) -c snuffle.c

unsnuffle.o: unsnuffle.c snefru.h
       $(CC) $(CCOPTS) -c unsnuffle.c

snuffle.man: snuffle.1 Makefile
       $(NROFF) $(NROFFOPTS) < snuffle.1 > snuffle.man

snuffle.shar: Makefile README snuffle.1 snuffle.c unsnuffle.c
       shar Makefile README snuffle.1 snuffle.c unsnuffle.c > snuffle.shar
       chmod 400 snuffle.shar
