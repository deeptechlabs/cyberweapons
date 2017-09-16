#include "lucre.h"

/*
   WDFIN =
     [
       int	keyversion
       int	ncoins
       {
       int	seqno
       MPI	R
       }[ncoins]
     ]

     Note weirdnesses in encoding:

     If R is 0, we encode {int seqno; MPI R;} as {int 0; int seqno;}

     When this is part of a WITHDRAW3, we leave off the SOR and EOR.
 */

EC_M_Wdfin EC_M_new_wdfin(UInt32 keyversion, UInt32 ncoins,
    UInt32 *seqno, BIGNUM **R)
{
    EC_M_Wdfin newwdfin;

    if (ncoins && (!seqno || !R)) return NULL;
    newwdfin =
	(EC_M_Wdfin) EC_G_malloc(sizeof(struct EC_M_Wdfin_s));
    if (!newwdfin) return newwdfin;

    newwdfin->keyversion = keyversion;
    newwdfin->ncoins = ncoins;
    newwdfin->seqno = seqno;
    newwdfin->R = R;

    return newwdfin;
}

EC_M_Wdfin EC_M_clone_wdfin(EC_M_Wdfin wdfin)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Wdfin newwdfin;
    UInt32 keyversion;
    UInt32 ncoins = 0;
    UInt32 *seqno = NULL;
    BIGNUM **R = NULL;

    int i;
    
    err = EC_M_examine_wdfin(wdfin, &keyversion, &ncoins, &seqno, &R);
    if (!err) {
	newwdfin = EC_M_new_wdfin(keyversion, ncoins, seqno, R);
	if (newwdfin) return newwdfin;
    }

    if (seqno) EC_G_free(seqno);
    for(i=0;i<ncoins;++i)
	if (R) EC_M_free_MPI(R[i]);
    if (R) EC_G_free(R);

    return NULL;
}

EC_Errno EC_M_examine_wdfin(EC_M_Wdfin wdfin, UInt32 *keyversion,
    UInt32 *ncoins, UInt32 **seqno, BIGNUM ***R)
{ 
    UInt32 mykeyversion;
    UInt32 myncoins;
    UInt32 *myseqno;
    BIGNUM **myR;

    int i;
    int seenbad = 0;

    if (!wdfin) return EC_ERR_INTERNAL;

    mykeyversion = wdfin->keyversion;
    myncoins = wdfin->ncoins;
    myseqno = (UInt32 *)EC_G_malloc(sizeof(UInt32)*myncoins);
    if (myseqno) for(i=0;i<myncoins;++i) {
	myseqno[i] = wdfin->seqno[i];
    }
    myR = (BIGNUM **)EC_G_malloc(sizeof(BIGNUM *)*myncoins);
    if (myR) for(i=0;i<myncoins;++i) {
	myR[i] = EC_M_clone_MPI(wdfin->R[i]);
	if (!myR[i]) seenbad = 1;
    }

    if (!seqno || !myR || seenbad) {
	/* Didn't copy properly; abort */
	if (seqno) EC_G_free(seqno);
	for(i=0;i<myncoins;++i)
	    if (myR) EC_M_free_MPI(myR[i]);
	if (myR) EC_G_free(myR);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    if (keyversion) *keyversion = mykeyversion;
    if (ncoins) *ncoins = myncoins;
    if (seqno) *seqno = myseqno; else EC_G_free(myseqno);
    if (R) *R = myR; else {
	for(i=0;i<myncoins;++i) EC_G_free(myR[i]);
	EC_G_free(myR);
    }
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_wdfin(EC_M_Wdfin wdfin1, EC_M_Wdfin wdfin2)
{
    int i;

    if (!wdfin1 || !wdfin2) return 1;

    if (wdfin1->keyversion != wdfin2->keyversion
     || wdfin1->ncoins != wdfin2->ncoins)
	return 1;

    if (wdfin1->ncoins &&
	(!wdfin1->R || !wdfin2->R || !wdfin1->seqno || !wdfin2->seqno))
	return 1;

    for(i=0;i<wdfin1->ncoins;++i)
	if (wdfin1->seqno[i] != wdfin2->seqno[i]
	 || EC_M_cmp_MPI(wdfin1->R[i], wdfin2->R[i]))
	    return 1;

    return 0;
}

void EC_M_free_wdfin(EC_M_Wdfin wdfin)
{
    int i;

    if (wdfin) {
	if (wdfin->seqno) EC_G_free(wdfin->seqno);
	for(i=0;i<wdfin->ncoins;++i)
	    if (wdfin->R) EC_M_free_MPI(wdfin->R[i]);
	if (wdfin->R) EC_G_free(wdfin->R);
	EC_G_free(wdfin);
    }
}

EC_Errno EC_M_compile_wdfin(EC_M_Wdfin wdfin, EC_M_Msg msg, UInt32 skip_wrap)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    int i;

    if (!wdfin || 
	(wdfin->ncoins && (!wdfin->seqno || !wdfin->R)) ||
	!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!skip_wrap && !err) err = EC_M_compile_sor(EC_M_REC_WDFIN, msg);
    if (!err) err = EC_M_compile_int(wdfin->keyversion, msg);
    if (!err) err = EC_M_compile_int(wdfin->ncoins, msg);
    for (i=0;i<wdfin->ncoins;++i) {
	if (BN_is_zero(wdfin->R[i])) {
	    if (!err) err = EC_M_compile_int(0, msg);
	    if (!err) err = EC_M_compile_int(wdfin->seqno[i], msg);
	} else {
	    if (!err) err = EC_M_compile_int(wdfin->seqno[i], msg);
	    if (!err) err = EC_M_compile_MPI(wdfin->R[i], msg);
	}
    }
    if (!skip_wrap && !err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_wdfin(EC_M_Wdfin *wdfin, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    UInt32 keyversion;
    UInt32 ncoins = 0;
    UInt32 *seqno = NULL;
    BIGNUM **R = NULL;
    EC_M_Fieldtype fieldtype;
    EC_M_Rectype rectype;

    int i, saw_header;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    /* Here, we have to figure out whether there's a header or not... */
    if (!err) err = EC_M_examine_msg(&fieldtype, &rectype, msg);
    if (!err) {
	if (fieldtype == EC_M_FIELD_SOR && rectype == EC_M_REC_WDFIN)
	    saw_header = 1;
	else if (fieldtype == EC_M_FIELD_INT)
	    saw_header = 0;
	else return EC_ERR_INTERNAL;
    }

    if (!err && saw_header) err = EC_M_decompile_sor(EC_M_REC_WDFIN, msg);
    if (!err) err = EC_M_decompile_int(&keyversion, msg);
    if (!err) err = EC_M_decompile_int(&ncoins, msg);
    if (!err) {
	seqno = (UInt32 *)EC_G_malloc(sizeof(UInt32)*ncoins);
	if (!seqno) err = EC_ERR_INTERNAL;
	R = (BIGNUM **)EC_G_malloc(sizeof(BIGNUM *)*ncoins);
	if (!R) err = EC_ERR_INTERNAL;
    }
    for (i=0;i<ncoins;++i) {
	if (!err) err = EC_M_decompile_int(&seqno[i], msg);
	if (!err && seqno[i]) {
	    if (!err) err = EC_M_decompile_MPI(&R[i], msg);
	} else {
	    if (!err) err = EC_M_decompile_int(&seqno[i], msg);
	    if (!err) {
		R[i] = BN_new();
		if (!R[i]) err = EC_ERR_INTERNAL;
		else err = (BN_zero(R[i]) ? EC_ERR_NONE : EC_ERR_INTERNAL);
	    }
	}
    }
    if (!err && saw_header) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && wdfin) {
	*wdfin = EC_M_new_wdfin(keyversion, ncoins, seqno, R);
	if (!*wdfin) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    if (seqno) EC_G_free(seqno);
    for(i=0;i<ncoins;++i)
	if (R) EC_M_free_MPI(R[i]);
    if (R) EC_G_free(R);
    return err;
}
