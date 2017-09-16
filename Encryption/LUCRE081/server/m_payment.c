#include "lucre.h"

/*
   PAYMENT =
     [
        payment_hdr
        pcoins
     ]
 */

EC_M_Payment EC_M_new_payment(EC_M_Payment_hdr payment_hdr,
    EC_M_Pcoins pcoins)
{
    EC_M_Payment newpayment;

    if (!payment_hdr || !pcoins) return NULL;
    newpayment = (EC_M_Payment) EC_G_malloc(sizeof(struct EC_M_Payment_s));
    if (!newpayment) return newpayment;

    newpayment->payment_hdr = payment_hdr;
    newpayment->pcoins = pcoins;
    return newpayment;
}

EC_M_Payment EC_M_clone_payment(EC_M_Payment payment)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Payment newpayment;
    EC_M_Payment_hdr payment_hdr = NULL;
    EC_M_Pcoins pcoins = NULL;
    
    err = EC_M_examine_payment(payment, &payment_hdr, &pcoins);
    if (!err) {
	newpayment = EC_M_new_payment(payment_hdr, pcoins);
	if (newpayment) return newpayment;
    }

    EC_M_free_payment_hdr(payment_hdr);
    EC_M_free_pcoins(pcoins);
    return NULL;
}

EC_Errno EC_M_examine_payment(EC_M_Payment payment,
    EC_M_Payment_hdr *payment_hdr, EC_M_Pcoins *pcoins)
{ 
    EC_M_Payment_hdr mypayment_hdr;
    EC_M_Pcoins mypcoins;

    if (!payment) return EC_ERR_INTERNAL;

    mypayment_hdr = EC_M_clone_payment_hdr(payment->payment_hdr);
    mypcoins = EC_M_clone_pcoins(payment->pcoins);

    if (!mypayment_hdr || !mypcoins) {
	/* Didn't copy properly; abort */
	EC_M_free_payment_hdr(mypayment_hdr);
	EC_M_free_pcoins(mypcoins);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    if (payment_hdr) *payment_hdr = mypayment_hdr; else EC_M_free_payment_hdr(mypayment_hdr);
    if (pcoins) *pcoins = mypcoins; else EC_M_free_pcoins(mypcoins);
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_payment(EC_M_Payment payment1, EC_M_Payment payment2)
{
    if (!payment1 || !payment2) return 1;

    if (EC_M_cmp_payment_hdr(payment1->payment_hdr, payment2->payment_hdr)
     || EC_M_cmp_pcoins(payment1->pcoins, payment2->pcoins))
	return 1;

    return 0;
}

void EC_M_free_payment(EC_M_Payment payment)
{
    if (payment) {
	EC_M_free_payment_hdr(payment->payment_hdr);
	EC_M_free_pcoins(payment->pcoins);
	EC_G_free(payment);
    }
}

EC_Errno EC_M_compile_payment(EC_M_Payment payment, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!payment || !payment->payment_hdr || !payment->pcoins || !msg)
	return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_PAYMENT, msg);
    if (!err) err = EC_M_compile_payment_hdr(payment->payment_hdr, msg);
    if (!err) err = EC_M_compile_pcoins(payment->pcoins, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_payment(EC_M_Payment *payment, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    EC_M_Payment_hdr payment_hdr = NULL;
    EC_M_Pcoins pcoins = NULL;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_PAYMENT, msg);
    if (!err) err = EC_M_decompile_payment_hdr(&payment_hdr, msg);
    if (!err) err = EC_M_decompile_pcoins(&pcoins, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && payment) {
	*payment = EC_M_new_payment(payment_hdr, pcoins);
	if (!*payment) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    EC_M_free_payment_hdr(payment_hdr);
    EC_M_free_pcoins(pcoins);
    return err;
}
