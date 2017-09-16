#include "lucre.h"

/*
   DEP =
     [
        int   seqno
        payment_hdr
        pcoins
     ]
 */

EC_M_Dep EC_M_new_dep(UInt32 seqno, EC_M_Payment_hdr payment_hdr,
    EC_M_Pcoins pcoins)
{
    EC_M_Dep newdep;

    if (!payment_hdr || !pcoins) return NULL;
    newdep = (EC_M_Dep) EC_G_malloc(sizeof(struct EC_M_Dep_s));
    if (!newdep) return newdep;

    newdep->seqno = seqno;
    newdep->payment_hdr = payment_hdr;
    newdep->pcoins = pcoins;
    return newdep;
}

EC_M_Dep EC_M_clone_dep(EC_M_Dep dep)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Dep newdep;
    UInt32 seqno;
    EC_M_Payment_hdr payment_hdr = NULL;
    EC_M_Pcoins pcoins = NULL;
    
    err = EC_M_examine_dep(dep, &seqno, &payment_hdr, &pcoins);
    if (!err) {
	newdep = EC_M_new_dep(seqno, payment_hdr, pcoins);
	if (newdep) return newdep;
    }

    EC_M_free_payment_hdr(payment_hdr);
    EC_M_free_pcoins(pcoins);
    return NULL;
}

EC_Errno EC_M_examine_dep(EC_M_Dep dep, UInt32 *seqno,
    EC_M_Payment_hdr *payment_hdr, EC_M_Pcoins *pcoins)
{ 
    UInt32 myseqno;
    EC_M_Payment_hdr mypayment_hdr;
    EC_M_Pcoins mypcoins;

    if (!dep) return EC_ERR_INTERNAL;

    myseqno = dep->seqno;
    mypayment_hdr = EC_M_clone_payment_hdr(dep->payment_hdr);
    mypcoins = EC_M_clone_pcoins(dep->pcoins);

    if (!mypayment_hdr || !mypcoins) {
	/* Didn't copy properly; abort */
	EC_M_free_payment_hdr(mypayment_hdr);
	EC_M_free_pcoins(mypcoins);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    if (seqno) *seqno = myseqno;
    if (payment_hdr) *payment_hdr = mypayment_hdr; else EC_M_free_payment_hdr(mypayment_hdr);
    if (pcoins) *pcoins = mypcoins; else EC_M_free_pcoins(mypcoins);
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_dep(EC_M_Dep dep1, EC_M_Dep dep2)
{
    if (!dep1 || !dep2) return 1;

    if (dep1->seqno != dep2->seqno
     || EC_M_cmp_payment_hdr(dep1->payment_hdr, dep2->payment_hdr)
     || EC_M_cmp_pcoins(dep1->pcoins, dep2->pcoins))
	return 1;

    return 0;
}

void EC_M_free_dep(EC_M_Dep dep)
{
    if (dep) {
	EC_M_free_payment_hdr(dep->payment_hdr);
	EC_M_free_pcoins(dep->pcoins);
	EC_G_free(dep);
    }
}

EC_Errno EC_M_compile_dep(EC_M_Dep dep, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!dep || !dep->payment_hdr || !dep->pcoins || !msg)
	return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_DEP, msg);
    if (!err) err = EC_M_compile_int(dep->seqno, msg);
    if (!err) err = EC_M_compile_payment_hdr(dep->payment_hdr, msg);
    if (!err) err = EC_M_compile_pcoins(dep->pcoins, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_dep(EC_M_Dep *dep, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    UInt32 seqno;
    EC_M_Payment_hdr payment_hdr = NULL;
    EC_M_Pcoins pcoins = NULL;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_DEP, msg);
    if (!err) err = EC_M_decompile_int(&seqno, msg);
    if (!err) err = EC_M_decompile_payment_hdr(&payment_hdr, msg);
    if (!err) err = EC_M_decompile_pcoins(&pcoins, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && dep) {
	*dep = EC_M_new_dep(seqno, payment_hdr, pcoins);
	if (!*dep) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    EC_M_free_payment_hdr(payment_hdr);
    EC_M_free_pcoins(pcoins);
    return err;
}
