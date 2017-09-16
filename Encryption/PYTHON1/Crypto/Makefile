
all : source
	cp Setup.in Makefile.pre.in src
	cd src ; make -f Makefile.pre.in Makefile ; make
#	mv src/python .

source :
	/usr/local/bin/python buildkit

clean : 
	rm -f `find . -name '*~'` python
	rm -f `find . -name '*.pyc'`
	mkdir src ; cd src ; rm -f *
	cd Doc ; rm -f *.ps *.log *.aux *.ilg 

distrib : clean
	cd Doc ; rm -f html/* ; texi2html crypt.texi html ; makeinfo crypt.texi ; tex crypt.texi ; texindex crypt.cp ; tex crypt.texi
	util/resign README INSTALL curiosa/README
	cd ../.. ; tar -cvf Extensions/Crypto/Distrib/pycrypt.tar -X Extensions/Crypto/excludefiles Extensions/Crypto 
	cd Doc ; rm -f *.?? *.log *.aux *.ilg 

