OFILES= serial.o main.o frequency.o chi.o gap.o poker.o coupon.o permute.o runs.o maximum.o mtuple.o gamma.o
CFILES= serial.c main.c frequency.c chi.c gap.c poker.c coupon.c permute.c runs.c maximum.c mtuple.c gamma.c
CFLAGS= -O

chisquare: $(OFILES) bash.h
	cc $(CFLAGS) -o chisquare $(OFILES) -lm

clean:
	rm -f $(OFILES)

lint:
	lint -lm $(CFILES)

bundle:
	bundle makefile bash.h $(CFILES) > BUN.randtests
