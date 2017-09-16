#include "lucre.h"

/*
   PAYMENT_HDR =
     [
       int	bankID
       int	protocol
       int	amount
       int	currency
       int	ncoins
       time	timestamp
       int	expires
       int	shop_bankID
       string	shop_accID
       data	payer_hash
       data	descr_hash
       ----
       int	flags
       string	descr
       string	comment
       data	payer_code
       int	seqno
       time	rcv_time
       int	payment_version
     ]
 */

/* If you manually change any of the fields above the dashes, be _sure_
   to call EC_M_snap_payment_hdr() to update the snapshot! */

/* Note the weirdness that "expires" is a time_t that is compiled as an int */

EC_M_Payment_hdr EC_M_new_payment_hdr(UInt32 bankID, EC_M_Protocol protocol,
    UInt32 amount, EC_M_Currency currency, UInt32 ncoins, time_t timestamp,
    time_t expires, UInt32 shop_bankID, char *shop_accID, Byte *payer_hash,
    UInt32 payer_hashlen, Byte *descr_hash, UInt32 descr_hashlen,
    UInt32 flags, char *descr, char *comment, Byte *payer_code,
    UInt32 payer_codelen, UInt32 seqno, time_t rcv_time,
    UInt32 payment_version)
{
    EC_M_Payment_hdr newpayment_hdr;
    EC_Errno err = EC_ERR_NONE;

    if ((payer_hashlen && !payer_hash) || (descr_hashlen && !descr_hash)
     || (payer_codelen && !payer_code) || !shop_accID || !descr || !comment)
	return NULL;
    newpayment_hdr =
	(EC_M_Payment_hdr) EC_G_malloc(sizeof(struct EC_M_Payment_hdr_s));
    if (!newpayment_hdr) return newpayment_hdr;

    newpayment_hdr->bankID = bankID;
    newpayment_hdr->protocol = protocol;
    newpayment_hdr->amount = amount;
    newpayment_hdr->currency = currency;
    newpayment_hdr->ncoins = ncoins;
    newpayment_hdr->timestamp = timestamp;
    newpayment_hdr->expires = expires;
    newpayment_hdr->shop_bankID = shop_bankID;
    newpayment_hdr->shop_accID = shop_accID;
    newpayment_hdr->payer_hash = payer_hash;
    newpayment_hdr->payer_hashlen = payer_hashlen;
    newpayment_hdr->descr_hash = descr_hash;
    newpayment_hdr->descr_hashlen = descr_hashlen;
    newpayment_hdr->flags = flags;
    newpayment_hdr->descr = descr;
    newpayment_hdr->comment = comment;
    newpayment_hdr->payer_code = payer_code;
    newpayment_hdr->payer_codelen = payer_codelen;
    newpayment_hdr->seqno = seqno;
    newpayment_hdr->rcv_time = rcv_time;
    newpayment_hdr->payment_version = payment_version;
    newpayment_hdr->snapdata = NULL;
    newpayment_hdr->snaplen = 0;

    /* Since the SHA of the payment_hdr is important, we keep around a
       copy of the compiled version of the part before the dashes */
    err = EC_M_snap_payment_hdr(newpayment_hdr);
    if (!err) return newpayment_hdr;

    /* Free _just_ the payment_hdr record, not its fields! */
    EC_G_free(newpayment_hdr);
    return NULL;
}

EC_M_Payment_hdr EC_M_clone_payment_hdr(EC_M_Payment_hdr payment_hdr)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Payment_hdr newpayment_hdr;
    UInt32 bankID;
    EC_M_Protocol protocol;
    UInt32 amount;
    EC_M_Currency currency;
    UInt32 ncoins;
    time_t timestamp;
    time_t expires;
    UInt32 shop_bankID;
    char *shop_accID = NULL;
    Byte *payer_hash = NULL;
    UInt32 payer_hashlen;
    Byte *descr_hash = NULL;
    UInt32 descr_hashlen;
    UInt32 flags;
    char *descr = NULL;
    char *comment = NULL;
    Byte *payer_code = NULL;
    UInt32 payer_codelen;
    UInt32 seqno;
    time_t rcv_time;
    UInt32 payment_version;
    Byte *snapdata;
    UInt32 snaplen;

    err = EC_M_examine_payment_hdr(payment_hdr, &bankID, &protocol, &amount,
	    &currency, &ncoins, &timestamp, &expires, &shop_bankID,
	    &shop_accID, &payer_hash, &payer_hashlen, &descr_hash,
	    &descr_hashlen, &flags, &descr, &comment, &payer_code,
	    &payer_codelen, &seqno, &rcv_time, &payment_version,
	    &snapdata, &snaplen);
    if (!err) {
	newpayment_hdr = EC_M_new_payment_hdr(bankID, protocol, amount,
	    currency, ncoins, timestamp, expires, shop_bankID,
	    shop_accID, payer_hash, payer_hashlen, descr_hash,
	    descr_hashlen, flags, descr, comment, payer_code,
	    payer_codelen, seqno, rcv_time, payment_version);
	if (newpayment_hdr) {
	    EC_M_free_data(newpayment_hdr->snapdata);
	    newpayment_hdr->snapdata = snapdata;
	    newpayment_hdr->snaplen = snaplen;
	    return newpayment_hdr;
	}
    }

    if (shop_accID) EC_G_free(shop_accID);
    EC_M_free_data(payer_hash);
    EC_M_free_data(descr_hash);
    if (descr) EC_G_free(descr);
    if (comment) EC_G_free(comment);
    EC_M_free_data(payer_code);
    EC_M_free_data(snapdata);

    return NULL;
}

EC_Errno EC_M_examine_payment_hdr(EC_M_Payment_hdr payment_hdr, UInt32 *bankID,
    EC_M_Protocol *protocol, UInt32 *amount, EC_M_Currency *currency,
    UInt32 *ncoins, time_t *timestamp, time_t *expires, UInt32 *shop_bankID,
    char **shop_accID, Byte **payer_hash, UInt32 *payer_hashlen,
    Byte **descr_hash, UInt32 *descr_hashlen, UInt32 *flags, char **descr,
    char **comment, Byte **payer_code, UInt32 *payer_codelen, UInt32 *seqno,
    time_t *rcv_time, UInt32 *payment_version, Byte **snapdata,
    UInt32 *snaplen)
{ 
    UInt32 mybankID;
    EC_M_Protocol myprotocol;
    UInt32 myamount;
    EC_M_Currency mycurrency;
    UInt32 myncoins;
    time_t mytimestamp;
    time_t myexpires;
    UInt32 myshop_bankID;
    char *myshop_accID = NULL;
    Byte *mypayer_hash = NULL;
    UInt32 mypayer_hashlen;
    Byte *mydescr_hash = NULL;
    UInt32 mydescr_hashlen;
    UInt32 myflags;
    char *mydescr = NULL;
    char *mycomment = NULL;
    Byte *mypayer_code = NULL;
    UInt32 mypayer_codelen;
    UInt32 myseqno;
    time_t myrcv_time;
    UInt32 mypayment_version;
    Byte *mysnapdata;
    UInt32 mysnaplen;

    if (!payment_hdr) return EC_ERR_INTERNAL;

    mybankID = payment_hdr->bankID;
    myprotocol = payment_hdr->protocol;
    myamount = payment_hdr->amount;
    mycurrency = payment_hdr->currency;
    myncoins = payment_hdr->ncoins;
    mytimestamp = payment_hdr->timestamp;
    myexpires = payment_hdr->expires;
    myshop_bankID = payment_hdr->shop_bankID;
    myshop_accID = EC_G_strdup(payment_hdr->shop_accID);
    mypayer_hashlen = payment_hdr->payer_hashlen;
    mypayer_hash = EC_M_clone_data(payment_hdr->payer_hash, mypayer_hashlen);
    mydescr_hashlen = payment_hdr->descr_hashlen;
    mydescr_hash = EC_M_clone_data(payment_hdr->descr_hash, mydescr_hashlen);
    myflags = payment_hdr->flags;
    mydescr = EC_G_strdup(payment_hdr->descr);
    mycomment = EC_G_strdup(payment_hdr->comment);
    mypayer_codelen = payment_hdr->payer_codelen;
    mypayer_code = EC_M_clone_data(payment_hdr->payer_code, mypayer_codelen);
    myseqno = payment_hdr->seqno;
    myrcv_time = payment_hdr->rcv_time;
    mypayment_version = payment_hdr->payment_version;
    mysnaplen = payment_hdr->snaplen;
    mysnapdata = EC_M_clone_data(payment_hdr->snapdata, mysnaplen);

    if ((mypayer_hashlen && !mypayer_hash)
     || (mydescr_hashlen && !mydescr_hash)
     || (mypayer_codelen && !mypayer_code)
     || (mysnaplen && !mysnapdata)
     || !myshop_accID || !mydescr || !mycomment) {
	/* Didn't copy properly; abort */
	if (myshop_accID) EC_G_free(myshop_accID);
	EC_M_free_data(mypayer_hash);
	EC_M_free_data(mydescr_hash);
	if (mydescr) EC_G_free(mydescr);
	if (mycomment) EC_G_free(mycomment);
	EC_M_free_data(mypayer_code);
	EC_M_free_data(mysnapdata);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    if (bankID) *bankID = mybankID;
    if (protocol) *protocol = myprotocol;
    if (amount) *amount = myamount;
    if (currency) *currency = mycurrency;
    if (ncoins) *ncoins = myncoins;
    if (timestamp) *timestamp = mytimestamp;
    if (expires) *expires = myexpires;
    if (shop_bankID) *shop_bankID = myshop_bankID;
    if (shop_accID) *shop_accID = myshop_accID;
	else EC_G_free(myshop_accID);
    if (payer_hash) *payer_hash = mypayer_hash;
	else EC_M_free_data(mypayer_hash);
    if (payer_hashlen) *payer_hashlen = mypayer_hashlen;
    if (descr_hash) *descr_hash = mydescr_hash;
	else EC_M_free_data(mydescr_hash);
    if (descr_hashlen) *descr_hashlen = mydescr_hashlen;
    if (flags) *flags = myflags;
    if (descr) *descr = mydescr;
	else EC_G_free(mydescr);
    if (comment) *comment = mycomment;
	else EC_G_free(mycomment);
    if (payer_code) *payer_code = mypayer_code;
	else EC_M_free_data(mypayer_code);
    if (payer_codelen) *payer_codelen = mypayer_codelen;
    if (seqno) *seqno = myseqno;
    if (rcv_time) *rcv_time = myrcv_time;
    if (payment_version) *payment_version = mypayment_version;
    if (snapdata) *snapdata = mysnapdata;
	else EC_M_free_data(mysnapdata);
    if (snaplen) *snaplen = mysnaplen;

    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_payment_hdr(EC_M_Payment_hdr payment_hdr1,
    EC_M_Payment_hdr payment_hdr2)
{
    if (!payment_hdr1 || !payment_hdr2) return 1;

    if (payment_hdr1->bankID != payment_hdr2->bankID
     || payment_hdr1->protocol != payment_hdr2->protocol
     || payment_hdr1->amount != payment_hdr2->amount
     || payment_hdr1->currency != payment_hdr2->currency
     || payment_hdr1->ncoins != payment_hdr2->ncoins
     || payment_hdr1->timestamp != payment_hdr2->timestamp
     || payment_hdr1->expires != payment_hdr2->expires
     || payment_hdr1->shop_bankID != payment_hdr2->shop_bankID
     || strcmp(payment_hdr1->shop_accID, payment_hdr2->shop_accID)
     || payment_hdr1->payer_hashlen != payment_hdr2->payer_hashlen
     || EC_M_cmp_data(payment_hdr1->payer_hash, payment_hdr2->payer_hash,
			 payment_hdr1->payer_hashlen)
     || payment_hdr1->descr_hashlen != payment_hdr2->descr_hashlen
     || EC_M_cmp_data(payment_hdr1->descr_hash, payment_hdr2->descr_hash,
			 payment_hdr1->descr_hashlen)
     || payment_hdr1->flags != payment_hdr2->flags
     || strcmp(payment_hdr1->descr, payment_hdr2->descr)
     || strcmp(payment_hdr1->comment, payment_hdr2->comment)
     || payment_hdr1->payer_codelen != payment_hdr2->payer_codelen
     || EC_M_cmp_data(payment_hdr1->payer_code, payment_hdr2->payer_code,
			 payment_hdr1->payer_codelen)
     || payment_hdr1->seqno != payment_hdr2->seqno
     || payment_hdr1->rcv_time != payment_hdr2->rcv_time
     || payment_hdr1->payment_version != payment_hdr2->payment_version
     || payment_hdr1->snaplen != payment_hdr2->snaplen
     || EC_M_cmp_data(payment_hdr1->snapdata, payment_hdr2->snapdata,
			 payment_hdr1->snaplen))
	return 1;

    return 0;
}

void EC_M_free_payment_hdr(EC_M_Payment_hdr payment_hdr)
{
    if (payment_hdr) {
	if (payment_hdr->shop_accID) EC_G_free(payment_hdr->shop_accID);
	EC_M_free_data(payment_hdr->payer_hash);
	EC_M_free_data(payment_hdr->descr_hash);
	if (payment_hdr->descr) EC_G_free(payment_hdr->descr);
	if (payment_hdr->comment) EC_G_free(payment_hdr->comment);
	EC_M_free_data(payment_hdr->payer_code);
	EC_M_free_data(payment_hdr->snapdata);
	EC_G_free(payment_hdr);
    }
}

EC_Errno EC_M_compile_payment_hdr(EC_M_Payment_hdr payment_hdr, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!payment_hdr
     || (payment_hdr->payer_hashlen && !payment_hdr->payer_hash)
     || (payment_hdr->descr_hashlen && !payment_hdr->descr_hash)
     || (payment_hdr->payer_codelen && !payment_hdr->payer_code)
     || !payment_hdr->shop_accID || !payment_hdr->descr
     || !payment_hdr->comment || payment_hdr->snaplen < 3
     || !payment_hdr->snapdata || !msg)
	return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    /* Use the saved snapshot for the first bit, but remember _not_
       to include the EOR that's at the end of the snapshot */
    if (!err) err = EC_M_append_msg(payment_hdr->snapdata,
			payment_hdr->snaplen - 1, msg);
    /*
    if (!err) err = EC_M_compile_sor(EC_M_REC_PAYMENT_HDR, msg);
    if (!err) err = EC_M_compile_int(payment_hdr->bankID, msg);
    if (!err) err = EC_M_compile_int(payment_hdr->protocol, msg);
    if (!err) err = EC_M_compile_int(payment_hdr->amount, msg);
    if (!err) err = EC_M_compile_int(payment_hdr->currency, msg);
    if (!err) err = EC_M_compile_int(payment_hdr->ncoins, msg);
    if (!err) err = EC_M_compile_time(payment_hdr->timestamp, msg);
    if (!err) err = EC_M_compile_int(payment_hdr->expires, msg);
    if (!err) err = EC_M_compile_int(payment_hdr->shop_bankID, msg);
    if (!err) err = EC_M_compile_string(payment_hdr->shop_accID, msg);
    if (!err) err = EC_M_compile_data(payment_hdr->payer_hash,
					payment_hdr->payer_hashlen, msg);
    if (!err) err = EC_M_compile_data(payment_hdr->descr_hash,
					payment_hdr->descr_hashlen, msg);
    */
    if (!err) err = EC_M_compile_int(payment_hdr->flags, msg);
    if (!err) err = EC_M_compile_string(payment_hdr->descr, msg);
    if (!err) err = EC_M_compile_string(payment_hdr->comment, msg);
    if (!err) err = EC_M_compile_data(payment_hdr->payer_code,
					payment_hdr->payer_codelen, msg);
    if (!err) err = EC_M_compile_int(payment_hdr->seqno, msg);
    if (!err) err = EC_M_compile_time(payment_hdr->rcv_time, msg);
    if (!err) err = EC_M_compile_int(payment_hdr->payment_version, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_payment_hdr(EC_M_Payment_hdr *payment_hdr, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos, msgpos2;
    UInt32 bankID;
    EC_M_Protocol protocol;
    UInt32 amount;
    EC_M_Currency currency;
    UInt32 ncoins;
    time_t timestamp;
    UInt32 intexpires;
    time_t expires;
    UInt32 shop_bankID;
    char *shop_accID = NULL;
    Byte *payer_hash = NULL;
    UInt32 payer_hashlen;
    Byte *descr_hash = NULL;
    UInt32 descr_hashlen;
    UInt32 flags;
    char *descr = NULL;
    char *comment = NULL;
    Byte *payer_code = NULL;
    UInt32 payer_codelen;
    UInt32 seqno;
    time_t rcv_time;
    UInt32 payment_version;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_PAYMENT_HDR, msg);
    if (!err) err = EC_M_decompile_int(&bankID, msg);
    if (!err) err = EC_M_decompile_int(&protocol, msg);
    if (!err) err = EC_M_decompile_int(&amount, msg);
    if (!err) err = EC_M_decompile_int(&currency, msg);
    if (!err) err = EC_M_decompile_int(&ncoins, msg);
    if (!err) err = EC_M_decompile_time(&timestamp, msg);
    if (!err) err = EC_M_decompile_int(&intexpires, msg);
    if (!err) expires = (time_t)intexpires;
    if (!err) err = EC_M_decompile_int(&shop_bankID, msg);
    if (!err) err = EC_M_decompile_string(&shop_accID, msg);
    if (!err) err = EC_M_decompile_data(&payer_hash, &payer_hashlen, msg);
    if (!err) err = EC_M_decompile_data(&descr_hash, &descr_hashlen, msg);

    if (!err) msgpos2 = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_int(&flags, msg);
    if (!err) err = EC_M_decompile_string(&descr, msg);
    if (!err) err = EC_M_decompile_string(&comment, msg);
    if (!err) err = EC_M_decompile_data(&payer_code, &payer_codelen, msg);
    if (!err) err = EC_M_decompile_int(&seqno, msg);
    if (!err) err = EC_M_decompile_time(&rcv_time, msg);
    if (!err) err = EC_M_decompile_int(&payment_version, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && payment_hdr) {
	*payment_hdr = EC_M_new_payment_hdr(bankID, protocol, amount,
	    currency, ncoins, timestamp, expires, shop_bankID,
	    shop_accID, payer_hash, payer_hashlen, descr_hash,
	    descr_hashlen, flags, descr, comment, payer_code,
	    payer_codelen, seqno, rcv_time, payment_version);
	if (!*payment_hdr) err = EC_ERR_INTERNAL;
	else {
	    /* Get the exact encoding that was used, and put it in the
	       snapshot */
	    EC_M_free_data((*payment_hdr)->snapdata);
	    /* +1 for the EOR */
	    (*payment_hdr)->snaplen = msgpos2.begin+1-msgpos.begin;
	    (*payment_hdr)->snapdata = EC_M_clone_data(msg->data+msgpos.begin,
		(*payment_hdr)->snaplen);
	    if ((*payment_hdr)->snapdata) {
		/* Write in the EOR by hand */
		(*payment_hdr)->snapdata[(*payment_hdr)->snaplen-1] = 0xa1;
		return EC_ERR_NONE;
	    } else {
		EC_M_free_payment_hdr(*payment_hdr);
		*payment_hdr = NULL;
		return EC_ERR_INTERNAL;
	    }
	}
    }

    EC_M_seek_msg(msgpos, msg);
    if (shop_accID) EC_G_free(shop_accID);
    EC_M_free_data(payer_hash);
    EC_M_free_data(descr_hash);
    if (descr) EC_G_free(descr);
    if (comment) EC_G_free(comment);
    EC_M_free_data(payer_code);
    return err;
}

EC_Errno EC_M_snap_payment_hdr(EC_M_Payment_hdr payment_hdr)
{
    /* Make a compiled version of the top half of a payment_hdr */

    EC_M_Msg msg;
    EC_Errno err = EC_ERR_NONE;

    /* Allocate a msg */
    msg = EC_M_new_msg();
    if (!msg) return EC_ERR_INTERNAL;

    /* Compile part of the payment_hdr */
    if (!err) err = EC_M_compile_sor(EC_M_REC_PAYMENT_HDR, msg);
    if (!err) err = EC_M_compile_int(payment_hdr->bankID, msg);
    if (!err) err = EC_M_compile_int(payment_hdr->protocol, msg);
    if (!err) err = EC_M_compile_int(payment_hdr->amount, msg);
    if (!err) err = EC_M_compile_int(payment_hdr->currency, msg);
    if (!err) err = EC_M_compile_int(payment_hdr->ncoins, msg);
    if (!err) err = EC_M_compile_time(payment_hdr->timestamp, msg);
    if (!err) err = EC_M_compile_int(payment_hdr->expires, msg);
    if (!err) err = EC_M_compile_int(payment_hdr->shop_bankID, msg);
    if (!err) err = EC_M_compile_string(payment_hdr->shop_accID, msg);
    if (!err) err = EC_M_compile_data(payment_hdr->payer_hash,
					payment_hdr->payer_hashlen, msg);
    if (!err) err = EC_M_compile_data(payment_hdr->descr_hash,
					payment_hdr->descr_hashlen, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (err) {
	EC_M_free_msg(msg);
	return err;
    }

    /* Get the data */
    EC_M_free_data(payment_hdr->snapdata);
    payment_hdr->snaplen = msg->end - msg->begin;
    payment_hdr->snapdata = EC_M_clone_data(msg->data+msg->begin,
				payment_hdr->snaplen);
    EC_M_free_msg(msg);
    if (!payment_hdr->snapdata) {
	payment_hdr->snaplen = 0;
	return EC_ERR_INTERNAL;
    }

    return EC_ERR_NONE;
}
