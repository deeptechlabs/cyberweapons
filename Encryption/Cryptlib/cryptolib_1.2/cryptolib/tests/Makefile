INCLUDE = ../src
LIBFILES = ../lib/$(ARCH)/libcrypt.a
OBJDIR = ../obj/$(ARCH)
EXECDIR = ../bin/$(ARCH)

# normal ansi C compiler flags
CFLAGS= -O4 -I$(INCLUDE)  -c -DNDEBUG
LDFLAGS= -O4 -I$(INCLUDE) -DNDEBUG
CC = gcc

# Solaris ansi C compiler flags
#CFLAGS= -O  -I$(INCLUDE)  -c -DNDEBUG
#LDFLAGS= -O -I$(INCLUDE) -DNDEBUG
#CC = cc

# non ansi C compiler flags
#CFLAGS= -O -DK_AND_R -I$(INCLUDE)  -c -DNDEBUG
#LDFLAGS= -O4 -I$(INCLUDE) -DNDEBUG
#CC = cc

all: testFileDES testrand testbpow testEG testDH testRSA testRabin testDSA test_gsp testDigest

$(OBJDIR)/testFileDES.o: testFileDES.c $(LIBFILES)
	$(CC) $(CFLAGS) -o $(OBJDIR)/testFileDES.o testFileDES.c

testFileDES: $(OBJDIR)/testFileDES.o $(UTILS) $(LIBFILES)  
	$(CC) -o $(EXECDIR)/testFileDES $(LDFLAGS) $(OBJDIR)/testFileDES.o $(UTILS) $(LIBFILES) 
$(OBJDIR)/testrand.o: testrand.c $(LIBFILES)
	$(CC) $(CFLAGS) -o $(OBJDIR)/testrand.o testrand.c

testrand: $(OBJDIR)/testrand.o $(LIBFILES)  
	$(CC) -o $(EXECDIR)/testrand $(LDFLAGS)  $(OBJDIR)/testrand.o $(LIBFILES) 

$(OBJDIR)/testbpow.o: testbpow.c $(LIBFILES)
	$(CC) $(CFLAGS) -o $(OBJDIR)/testbpow.o testbpow.c

testbpow: $(OBJDIR)/testbpow.o $(LIBFILES)  
	$(CC) -o $(EXECDIR)/testbpow $(LDFLAGS) $(OBJDIR)/testbpow.o $(LIBFILES)

$(OBJDIR)/testEG.o: testEG.c $(LIBFILES)
	$(CC) $(CFLAGS) -o $(OBJDIR)/testEG.o testEG.c

testEG: $(OBJDIR)/testEG.o $(LIBFILES)  
	$(CC) -o $(EXECDIR)/testEG $(LDFLAGS) $(OBJDIR)/testEG.o $(LIBFILES) 

$(OBJDIR)/testDH.o: testDH.c $(LIBFILES)
	$(CC) $(CFLAGS) -o $(OBJDIR)/testDH.o testDH.c

testDH: $(OBJDIR)/testDH.o $(LIBFILES)  
	$(CC) -o $(EXECDIR)/testDH $(LDFLAGS) $(OBJDIR)/testDH.o $(LIBFILES) 

$(OBJDIR)/testRSA.o: testRSA.c $(LIBFILES)
	$(CC) $(CFLAGS) -o $(OBJDIR)/testRSA.o testRSA.c

testRSA: $(OBJDIR)/testRSA.o $(LIBFILES)  
	$(CC) -o $(EXECDIR)/testRSA $(LDFLAGS) $(OBJDIR)/testRSA.o $(LIBFILES) 

$(OBJDIR)/testRabin.o: testRabin.c $(LIBFILES)
	$(CC) $(CFLAGS) -o $(OBJDIR)/testRabin.o testRabin.c

testRabin: $(OBJDIR)/testRabin.o $(LIBFILES)  
	$(CC) -o $(EXECDIR)/testRabin $(LDFLAGS) $(OBJDIR)/testRabin.o $(LIBFILES) 

$(OBJDIR)/testDSA.o: testDSA.c $(LIBFILES)
	$(CC) $(CFLAGS) -o $(OBJDIR)/testDSA.o testDSA.c

testDSA: $(OBJDIR)/testDSA.o $(LIBFILES)  
	$(CC) -o $(EXECDIR)/testDSA $(LDFLAGS) $(OBJDIR)/testDSA.o $(LIBFILES) 

$(OBJDIR)/testDigest.o: testDigest.c $(LIBFILES)
	$(CC) $(CFLAGS) -o $(OBJDIR)/testDigest.o testDigest.c

testDigest: $(OBJDIR)/testDigest.o $(LIBFILES)  
	$(CC) -o $(EXECDIR)/testDigest $(LDFLAGS) $(OBJDIR)/testDigest.o $(LIBFILES) 

$(OBJDIR)/test_gsp.o: test_gsp.c $(LIBFILES)
	$(CC) $(CFLAGS) -o $(OBJDIR)/test_gsp.o test_gsp.c

test_gsp: $(OBJDIR)/test_gsp.o $(LIBFILES)  
	$(CC) -o $(EXECDIR)/test_gsp $(LDFLAGS) $(OBJDIR)/test_gsp.o $(LIBFILES) 

clean:
	rm -f $(OBJDIR)/*.o

clobber:
	rm -f $(OBJDIR)/*.o $(EXECDIR)/{testrand test_gsp testbpow testRSA \
					testRabin testEG testDH \
					testDSA testDigest testFileDES }


