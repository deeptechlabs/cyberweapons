#include <time.h>
#include "lucre.h"

/* Create and parse the messages in the DEPOSIT/DEP_ACK protocol */

EC_Errno EC_P_create_deposit(UInt32 numdeps, EC_M_Dep *givendep,
    EC_M_Userrec userrec, EC_M_Bank_mkey bank_mkey, time_t stamp, EC_M_Msg msg)
{
    EC_M_Hdr_stuff hdr_stuff;
    EC_M_Userhdr userhdr;
    EC_M_Deposit deposit;
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msg submsg;
    EC_M_Bank_encr bank_encr;
    EC_M_Dep *dep;

    int seenbad, i;

    if ((numdeps && !givendep) || !userrec || !bank_mkey || !msg)
	return EC_ERR_INTERNAL;

    /* Create the hdr_stuff header */
    hdr_stuff = EC_M_new_hdr_stuff(EC_LIB_VERNUM, stamp);
    if (!hdr_stuff) {
	return EC_ERR_INTERNAL;
    }

    /* Create the userhdr header */
    userhdr = EC_M_new_userhdr(userrec->userID, stamp, bank_mkey->bankID);
    if (!userhdr) {
	EC_M_free_hdr_stuff(hdr_stuff);
	return EC_ERR_INTERNAL;
    }

    /* Prepare the array of dep messages */
    dep = (EC_M_Dep *)EC_G_malloc((sizeof(EC_M_Dep)*numdeps));
    if (numdeps && !dep) {
	EC_M_free_userhdr(userhdr);
	EC_M_free_hdr_stuff(hdr_stuff);
	return EC_ERR_INTERNAL;
    }

    /* Copy each dep message */
    seenbad = 0;
    for(i=0;i<numdeps;++i) dep[i] = NULL;
    for(i=0;i<numdeps;++i) {
	/* Create the dep */
	dep[i] = EC_M_clone_dep(givendep[i]);
	if (!dep[i]) {
	    seenbad = 1;
	    break;
	}
	/* Fix the flags */
	dep[i]->payment_hdr->flags = 0x11;
	/* Remove any non-essential information before sending it off */
	if (dep[i]->payment_hdr->descr)
	    EC_G_free(dep[i]->payment_hdr->descr);
	dep[i]->payment_hdr->descr = EC_G_strdup("");
	if (dep[i]->payment_hdr->comment)
	    EC_G_free(dep[i]->payment_hdr->comment);
	dep[i]->payment_hdr->comment = EC_G_strdup("");
	EC_M_free_data(dep[i]->payment_hdr->payer_code);
	dep[i]->payment_hdr->payer_code = NULL;
	dep[i]->payment_hdr->payer_codelen = 0;
	dep[i]->payment_hdr->seqno = 0;
	dep[i]->payment_hdr->rcv_time = 0;
	dep[i]->payment_hdr->payment_version = 0;
	if (!dep[i]->payment_hdr->descr || !dep[i]->payment_hdr->comment) {
	    seenbad = 1;
	    break;
	}
    }

    if (seenbad) {
	/* Oh, well. */
	for(i=0;i<numdeps;++i) {
	    EC_M_free_dep(dep[i]);
	}
	EC_G_free(dep);
	EC_M_free_userhdr(userhdr);
	EC_M_free_hdr_stuff(hdr_stuff);
	return EC_ERR_INTERNAL;
    }

    /* Create the deposit message */
    deposit = EC_M_new_deposit(numdeps, dep);
    if (!deposit) {
	for(i=0;i<numdeps;++i) {
	    EC_M_free_dep(dep[i]);
	}
	EC_G_free(dep);
	EC_M_free_userhdr(userhdr);
	EC_M_free_hdr_stuff(hdr_stuff);
	return EC_ERR_INTERNAL;
    }

    /* Compile the message */
    submsg = EC_M_new_msg();
    if (!submsg) {
	EC_M_free_deposit(deposit);
	EC_M_free_userhdr(userhdr);
	EC_M_free_hdr_stuff(hdr_stuff);
	return EC_ERR_INTERNAL;
    }
    if (!err) err = EC_M_compile_hdr_stuff(hdr_stuff, submsg);
    if (!err) err = EC_M_compile_userhdr(userhdr, submsg);
    if (!err) err = EC_M_compile_deposit(deposit, submsg);

    /* Free the message objects */
    EC_M_free_deposit(deposit);
    EC_M_free_userhdr(userhdr);
    EC_M_free_hdr_stuff(hdr_stuff);

    if (err) {
	EC_M_free_msg(submsg);
	return err;
    }

    /* Encrypt the message */
    bank_encr = EC_U_rsa_encrypt_msg(EC_M_CRYPTALG_112_3DES,
	bank_mkey->keynumber, bank_mkey->bank_n, bank_mkey->bank_e, submsg);
    if (!bank_encr) {
	EC_M_free_msg(submsg);
	return EC_ERR_INTERNAL;
    }

    err = EC_M_compile_bank_encr(bank_encr, msg);
    EC_M_free_bank_encr(bank_encr);

    return err;
}
