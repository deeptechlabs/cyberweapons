
CC=gcc
CFLAGS=-O2

cert:	cert.o speedc.o 
	${CC} ${CFLAGS} cert.o speedc.o -o $@
cert.o speedc.o: speedc.h 


howfast:	howfast.o speedc.o 
	${CC} ${CFLAGS} howfast.o speedc.o -o $@
howfast.o speedc.o: speedc.h 

