# Makefile for root directory of "ripem" tree.
# (RIPEM Privacy-Enhanced Mailer, that is)
#
# This simple Makefile just prints some instructions. 

all:
	@echo "** Unix Makefile for RIPEM email encryption program."
	@echo " "
	@echo "There are two phases:  making the RSAREF toolkit archive,"
	@echo "and making RIPEM itself."
	@echo "You need to do:"
	@echo "  cd rsaref/install"
	@echo "  make   "
	@echo " "
	@echo "Then you need to make RIPEM itself.  Type:"
	@echo "  cd ../../main"
	@echo "  make  (this will give you more instructions)"
	@echo " "
	@echo "For more information, refer to:"
	@echo "  rsaref/doc/install.txt  and  doc/install.txt"

clean:
	rm -f main/*.o main/ripem rsaref/test/*.o rsaref/test/rsaref.a
	rm -f rsaref/install/rdemo rsaref/install/*.o rsaref/install/*.a
	rm -f rsaref/install/dhdemo
	rm -f main/core test/core main/preferen main/crls
	rm -f cmdline/*.o cmdline/ripem main/pubkeys main/privkey
	rm -f rsaref/source/nn.s rsaref/test/rdemo
	rm -f server/*.o server/sendsock server/readsock server/rkeyserv
	rm -f server/copymail server/credumpb server/crekeydb server/testmail
	rm -f server/rkeyreg
	rm -f test/ripem test/test2* test/*.dbg test/teste.enc test/*mrr*
	rm -f util/*.o util/man2code util/tprencod util/stripmsg util/prencode
	rm -f util/nobksp util/quote
	rm -f server/strutil.c server/pubinfo.c server/list.c
	rm -f server/*.o server/copymail server/rkeyreg server/rkeyserv
	rm -f server/sendsock server/readsock server/db2flat server/givepubs
	rm -f server/redirsrv

