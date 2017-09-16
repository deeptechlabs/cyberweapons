#include <time.h>
#include "lucre.h"

/* Parse BANKHDR messages */

EC_Errno EC_P_parse_bankhdr(EC_M_Msg msg,
    EC_M_Bank_mkey (*find_mkey)(UInt32 bankID, UInt32 keyno, void *state),
    void *state, EC_M_Bank_repl *bank_repl, EC_M_Msg *submsg,
    EC_M_Error *error)
{
    EC_M_Bankhdr bankhdr = NULL;
    EC_M_Bank_mkey bank_mkey = NULL;
    EC_M_Bank_repl mybank_repl = NULL;
    EC_M_Sigmsg sigmsg = NULL;
    EC_M_Msg mysubmsg = NULL;
    EC_Errno err = EC_ERR_NONE;
    EC_M_Fieldtype fieldtype;
    EC_M_Rectype rectype;

    if (!msg || !find_mkey) return EC_ERR_INTERNAL;

    /* Check the type of message */
    err = EC_M_examine_msg(&fieldtype, &rectype, msg);
    if (err) return EC_ERR_INTERNAL;

    if (fieldtype != EC_M_FIELD_SOR) {
	/* Ummm... no. */
	return EC_ERR_INTERNAL;
    }

    if (rectype == EC_M_REC_ERROR) {
	/* Uh, oh.  Return the error message. */
	return EC_M_decompile_error(error, msg);
    }

    /* Decompile the bankhdr message */
    err = EC_M_decompile_bankhdr(&bankhdr, msg);
    if (err) return EC_ERR_INTERNAL;

    /* Use the information in the header to pick a bank_mkey */
    bank_mkey = find_mkey(bankhdr->bankID, bankhdr->keyno, state);
    EC_M_free_bankhdr(bankhdr);
    if (!bank_mkey) {
	return EC_ERR_INTERNAL;
    }

    /* Decompile the sigmsg */
    err = EC_M_decompile_sigmsg(&sigmsg, msg);
    if (err) {
	EC_M_free_bank_mkey(bank_mkey);
	return EC_ERR_INTERNAL;
    }

    /* Check the signature */
    if (!EC_U_verify_sigmsg(sigmsg, bank_mkey->bank_n, bank_mkey->bank_e)) {
	/* Bad signature! */
	EC_M_free_sigmsg(sigmsg);
	EC_M_free_bank_mkey(bank_mkey);
	return EC_ERR_INTERNAL;
    }
    EC_M_free_bank_mkey(bank_mkey);

    /* The sig's OK; save a copy of the message */
    mysubmsg = EC_M_clone_msg(sigmsg->msg);
    EC_M_free_sigmsg(sigmsg);
    if (!mysubmsg) {
	return EC_ERR_INTERNAL;
    }

    /* Grab the bank_repl from the signed message */
    err = EC_M_decompile_bank_repl(&mybank_repl, mysubmsg);
    if (err) {
	EC_M_free_msg(mysubmsg);
	return EC_ERR_INTERNAL;
    }

    /* Assign the pieces */
    if (bank_repl) *bank_repl = mybank_repl;
	else EC_M_free_bank_repl(mybank_repl);
    if (submsg) *submsg = mysubmsg; else EC_M_free_msg(mysubmsg);
    
    return EC_ERR_NONE;
}
