#include "lucre.h"

/*
   COINDATA =
     [
       int  seqno
       int  keyversion
       MPI  n		; n
       MPI  fn		; f(n)
       MPI  r		; r
       MPI  fnrh	; f(n)*r^h
       MPI  fn1hr	; f(n)^(1/h)*r
       MPI  fn1h	; f(n)^(1/h)
       int  paymentid
     ]

    Note: setting 'r' to a random MPI is covered by Dr. David Chaum's
          blinding patent.  Application developers who have not licensed
          this patent from him are required to set 'r' to 1.  (Technically,
          you can put whatever you want in 'r' in the database, but when
          you send 'f(n)*r^h' to the bank to be signed, 'r' must be 1,
          unless you are allowed to use blinding.)
 */

EC_M_Coindata EC_M_new_coindata(UInt32 seqno, UInt32 keyversion, BIGNUM *n,
    BIGNUM *fn, BIGNUM *r, BIGNUM *fnrh, BIGNUM *fn1hr, BIGNUM *fn1h,
    UInt32 paymentid)
{
    EC_M_Coindata newcoindata;

    newcoindata =
	(EC_M_Coindata) EC_G_malloc(sizeof(struct EC_M_Coindata_s));
    if (!newcoindata) return newcoindata;

    newcoindata->seqno = seqno;
    newcoindata->keyversion = keyversion;
    newcoindata->n = n;
    newcoindata->fn = fn;
    newcoindata->r = r;
    newcoindata->fnrh = fnrh;
    newcoindata->fn1hr = fn1hr;
    newcoindata->fn1h = fn1h;
    newcoindata->paymentid = paymentid;
    newcoindata->next = NULL;
    return newcoindata;
}

EC_M_Coindata EC_M_clone_coindata(EC_M_Coindata coindata)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Coindata newcoindata;
    UInt32 seqno;
    UInt32 keyversion;
    BIGNUM *n = NULL;
    BIGNUM *fn = NULL;
    BIGNUM *r = NULL;
    BIGNUM *fnrh = NULL;
    BIGNUM *fn1hr = NULL;
    BIGNUM *fn1h = NULL;
    UInt32 paymentid;
    
    err = EC_M_examine_coindata(coindata, &seqno, &keyversion, &n, &fn, &r,
	&fnrh, &fn1hr, &fn1h, &paymentid);
    if (!err) {
	newcoindata = EC_M_new_coindata(seqno, keyversion, n, fn, r, fnrh,
	    fn1hr, fn1h, paymentid);
	if (newcoindata) return newcoindata;
    }

    EC_M_free_MPI(n);
    EC_M_free_MPI(fn);
    EC_M_free_MPI(r);
    EC_M_free_MPI(fnrh);
    EC_M_free_MPI(fn1hr);
    EC_M_free_MPI(fn1h);
    return NULL;
}

EC_Errno EC_M_examine_coindata(EC_M_Coindata coindata, UInt32 *seqno,
    UInt32 *keyversion, BIGNUM **n, BIGNUM **fn, BIGNUM **r, BIGNUM **fnrh,
    BIGNUM **fn1hr, BIGNUM **fn1h, UInt32 *paymentid)
{ 
    UInt32 myseqno;
    UInt32 mykeyversion;
    BIGNUM *myn;
    BIGNUM *myfn;
    BIGNUM *myr;
    BIGNUM *myfnrh;
    BIGNUM *myfn1hr;
    BIGNUM *myfn1h;
    UInt32 mypaymentid;

    if (!coindata) return EC_ERR_INTERNAL;

    myseqno = coindata->seqno;
    mykeyversion = coindata->keyversion;
    myn = EC_M_clone_MPI(coindata->n);
    myfn = EC_M_clone_MPI(coindata->fn);
    myr = EC_M_clone_MPI(coindata->r);
    myfnrh = EC_M_clone_MPI(coindata->fnrh);
    myfn1hr = EC_M_clone_MPI(coindata->fn1hr);
    myfn1h = EC_M_clone_MPI(coindata->fn1h);
    mypaymentid = coindata->paymentid;

    if (!myn || !myfn || !myr || !myfnrh || !myfn1hr || !myfn1h) {
	EC_M_free_MPI(myn);
	EC_M_free_MPI(myfn);
	EC_M_free_MPI(myr);
	EC_M_free_MPI(myfnrh);
	EC_M_free_MPI(myfn1hr);
	EC_M_free_MPI(myfn1h);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    if (seqno) *seqno = myseqno;
    if (keyversion) *keyversion = mykeyversion;
    if (n) *n = myn; else EC_M_free_MPI(myn);
    if (fn) *fn = myfn; else EC_M_free_MPI(myfn);
    if (r) *r = myr; else EC_M_free_MPI(myr);
    if (fnrh) *fnrh = myfnrh; else EC_M_free_MPI(myfnrh);
    if (fn1hr) *fn1hr = myfn1hr; else EC_M_free_MPI(myfn1hr);
    if (fn1h) *fn1h = myfn1h; else EC_M_free_MPI(myfn1h);
    if (paymentid) *paymentid = mypaymentid;
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_coindata(EC_M_Coindata coindata1, EC_M_Coindata coindata2)
{
    if (!coindata1 || !coindata2) return 1;

    if (coindata1->seqno != coindata2->seqno
     || coindata1->keyversion != coindata2->keyversion
     || EC_M_cmp_MPI(coindata1->n, coindata2->n)
     || EC_M_cmp_MPI(coindata1->fn, coindata2->fn)
     || EC_M_cmp_MPI(coindata1->r, coindata2->r)
     || EC_M_cmp_MPI(coindata1->fnrh, coindata2->fnrh)
     || EC_M_cmp_MPI(coindata1->fn1hr, coindata2->fn1hr)
     || EC_M_cmp_MPI(coindata1->fn1h, coindata2->fn1h)
     || coindata1->paymentid != coindata2->paymentid)
	return 1;

    return 0;
}

void EC_M_free_coindata(EC_M_Coindata coindata)
{
    if (coindata) {
	EC_M_free_MPI(coindata->n);
	EC_M_free_MPI(coindata->fn);
	EC_M_free_MPI(coindata->r);
	EC_M_free_MPI(coindata->fnrh);
	EC_M_free_MPI(coindata->fn1hr);
	EC_M_free_MPI(coindata->fn1h);
	EC_G_free(coindata);
    }
}

EC_Errno EC_M_compile_coindata(EC_M_Coindata coindata, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!coindata || !msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_COINDATA, msg);
    if (!err) err = EC_M_compile_int(coindata->seqno, msg);
    if (!err) err = EC_M_compile_int(coindata->keyversion, msg);
    if (!err) err = EC_M_compile_MPI(coindata->n, msg);
    if (!err) err = EC_M_compile_MPI(coindata->fn, msg);
    if (!err) err = EC_M_compile_MPI(coindata->r, msg);
    if (!err) err = EC_M_compile_MPI(coindata->fnrh, msg);
    if (!err) err = EC_M_compile_MPI(coindata->fn1hr, msg);
    if (!err) err = EC_M_compile_MPI(coindata->fn1h, msg);
    if (!err) err = EC_M_compile_int(coindata->paymentid, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_coindata(EC_M_Coindata *coindata, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    UInt32 seqno;
    UInt32 keyversion;
    BIGNUM *n = NULL;
    BIGNUM *fn = NULL;
    BIGNUM *r = NULL;
    BIGNUM *fnrh = NULL;
    BIGNUM *fn1hr = NULL;
    BIGNUM *fn1h = NULL;
    UInt32 paymentid;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_COINDATA, msg);
    if (!err) err = EC_M_decompile_int(&seqno, msg);
    if (!err) err = EC_M_decompile_int(&keyversion, msg);
    if (!err) err = EC_M_decompile_MPI(&n, msg);
    if (!err) err = EC_M_decompile_MPI(&fn, msg);
    if (!err) err = EC_M_decompile_MPI(&r, msg);
    if (!err) err = EC_M_decompile_MPI(&fnrh, msg);
    if (!err) err = EC_M_decompile_MPI(&fn1hr, msg);
    if (!err) err = EC_M_decompile_MPI(&fn1h, msg);
    if (!err) err = EC_M_decompile_int(&paymentid, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && coindata) {
	*coindata = EC_M_new_coindata(seqno, keyversion, n, fn, r, fnrh,
	    fn1hr, fn1h, paymentid);
	if (!*coindata) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    EC_M_free_MPI(n);
    EC_M_free_MPI(fn);
    EC_M_free_MPI(r);
    EC_M_free_MPI(fnrh);
    EC_M_free_MPI(fn1hr);
    EC_M_free_MPI(fn1h);
    return err;
}
