desc.$(O) : $(RSAREFDIR)desc.c $(RSAREFDIR)global.h $(RSAREFDIR)rsaref.h\
  $(RSAREFDIR)des.h
	$(CC) $(CFLAGS) $(RSAREFDIR)desc.c

digit.$(O) : $(RSAREFDIR)digit.c $(RSAREFDIR)global.h $(RSAREFDIR)rsaref.h\
  $(RSAREFDIR)nn.h $(RSAREFDIR)digit.h
	$(CC) $(CFLAGS) $(RSAREFDIR)digit.c

md2c.$(O) : $(RSAREFDIR)md2c.c $(RSAREFDIR)global.h $(RSAREFDIR)md2.h
	$(CC) $(CFLAGS) $(RSAREFDIR)md2c.c

md5c.$(O) : $(RSAREFDIR)md5c.c $(RSAREFDIR)global.h $(RSAREFDIR)md5.h
	$(CC) $(CFLAGS) $(RSAREFDIR)md5c.c

nn.$(O) : $(RSAREFDIR)nn.c $(RSAREFDIR)global.h $(RSAREFDIR)rsaref.h\
  $(RSAREFDIR)nn.h $(RSAREFDIR)digit.h
	$(CC) $(CFLAGS) $(RSAREFDIR)nn.c

prime.$(O) : $(RSAREFDIR)prime.c $(RSAREFDIR)global.h $(RSAREFDIR)rsaref.h\
  $(RSAREFDIR)r_random.h $(RSAREFDIR)nn.h $(RSAREFDIR)prime.h
	$(CC) $(CFLAGS) $(RSAREFDIR)prime.c

rsa.$(O) : $(RSAREFDIR)rsa.c $(RSAREFDIR)global.h $(RSAREFDIR)rsaref.h\
  $(RSAREFDIR)r_random.h $(RSAREFDIR)rsa.h $(RSAREFDIR)nn.h
	$(CC) $(CFLAGS) $(RSAREFDIR)rsa.c

r_dh.$(O) : $(RSAREFDIR)r_dh.c $(RSAREFDIR)global.h\
  $(RSAREFDIR)rsaref.h $(RSAREFDIR)r_random.h $(RSAREFDIR)nn.h\
  $(RSAREFDIR)prime.h
	$(CC) $(CFLAGS) $(RSAREFDIR)r_dh.c

r_encode.$(O) : $(RSAREFDIR)r_encode.c $(RSAREFDIR)global.h\
  $(RSAREFDIR)rsaref.h
	$(CC) $(CFLAGS) $(RSAREFDIR)r_encode.c

r_enhanc.$(O) : $(RSAREFDIR)r_enhanc.c $(RSAREFDIR)global.h\
  $(RSAREFDIR)rsaref.h $(RSAREFDIR)r_random.h $(RSAREFDIR)rsa.h
	$(CC) $(CFLAGS) $(RSAREFDIR)r_enhanc.c

r_keygen.$(O) : $(RSAREFDIR)r_keygen.c $(RSAREFDIR)global.h\
  $(RSAREFDIR)rsaref.h $(RSAREFDIR)r_random.h $(RSAREFDIR)nn.h\
  $(RSAREFDIR)prime.h
	$(CC) $(CFLAGS) $(RSAREFDIR)r_keygen.c

r_random.$(O) : $(RSAREFDIR)r_random.c $(RSAREFDIR)global.h\
  $(RSAREFDIR)rsaref.h $(RSAREFDIR)r_random.h $(RSAREFDIR)md5.h
	$(CC) $(CFLAGS) $(RSAREFDIR)r_random.c

r_stdlib.$(O) : $(RSAREFDIR)r_stdlib.c $(RSAREFDIR)global.h\
  $(RSAREFDIR)rsaref.h
	$(CC) $(CFLAGS) $(RSAREFDIR)r_stdlib.c

# Dependencies for header files

$(RSAREDIR)rsaref.h : $(RSAREFDIR)md2.h $(RSAREFDIR)md5.h $(RSAREFDIR)des.h
