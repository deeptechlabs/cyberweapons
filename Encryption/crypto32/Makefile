CC = gcc
CXX = c++
AR = ar
RANLIB = ranlib
 
CPPFLAGS =
CFLAGS = -O2
CXXFLAGS = -O2 -fpermissive -w
LDFLAGS =
 
SRCS = $(shell ls *.cpp)
OBJS = $(SRCS:.cpp=.o)
TESTOBJS = test.o bench.o validat1.o validat2.o validat3.o
LIBOBJS = $(filter-out $(TESTOBJS),$(OBJS))
 
all: cryptest.exe

clean:
	rm -f cryptest.exe libcrypt.a $(LIBOBJS) $(TESTOBJS)

libcrypt.a: $(LIBOBJS)
	$(AR) crv $@ $(LIBOBJS)
	$(RANLIB) $@
 
cryptest.exe: $(TESTOBJS) libcrypt.a
	$(CXX) -o $@ $(CXXFLAGS) $(TESTOBJS) -L. -lcrypt $(LDFLAGS) $(LDLIBS)
 
.SUFFIXES: .cpp
 
.cpp.o:
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $<
