## Your compiler
CC=gcc

## The location of the SSLeay include files
SSLEAYINC=-I/usr/local/SSLeay/include

## The location of the Berkeley db include files (if necessary)
DBINC=

CFLAGS=-Wall -g $(SSLEAYINC) $(DBINC)

OBJS=main.o \
     m_msg.o m_encoding.o m_setup_req.o m_hdr_stuff.o m_sigmsg.o \
     m_setup.o m_bank_mkey.o m_prot_setup.o m_protocols.o m_userinfo.o \
     m_openacc1.o m_rsaenc.o m_encrypt.o m_bank_encr.o m_openacc2.o \
     m_bankhdr.o m_bank_repl.o m_cinfo.o m_onl_curr.o m_curr.o m_error.o \
     m_userprivkey.o m_userkey.o m_userrec.o m_status.o m_statement.o \
     m_payment_hdr.o m_onl_coin.o m_pcoins.o m_payment.o m_dep.o \
     m_deposit.o m_dep_1ack.o m_dep_ack.o m_userhdr.o m_wdfin.o \
     m_withdraw3.o m_withdraw4.o m_coindata.o m_payreq.o \
     u_sig.o u_crypt.o \
     p_setup.o p_bankhdr.o p_openacc.o p_deposit.o \
     w_wallet.o w_user.o w_create.o w_bankkeys.o w_common.o w_curr.o \
     w_status.o w_deposit.o w_db.o w_recdb.o w_cashdb.o w_tally.o \
     w_withdraw.o w_wddb.o w_paydb.o w_payment.o

libucre.a: $(OBJS)
	ar rcs libucre.a $(OBJS)

clean:
	-rm -f $(OBJS)

veryclean: clean
	-rm -f libucre.a    
