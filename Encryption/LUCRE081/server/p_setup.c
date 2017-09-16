#include <time.h>
#include "lucre.h"

/* Create and parse the messages in the SETUP_REQ/SETUP protocol */

EC_Errno EC_P_create_setup_req(time_t stamp, EC_M_Msg msg)
{
    EC_M_Hdr_stuff hdr_stuff;
    EC_M_Setup_req setup_req;
    EC_Errno err = EC_ERR_NONE;

    /* Create the message objects */
    if (!msg) return EC_ERR_INTERNAL;

    /* Create the hdr_stuff header */
    hdr_stuff = EC_M_new_hdr_stuff(EC_LIB_VERNUM, stamp);

    /* Create the SETUP_REQ message */
    setup_req = EC_M_new_setup_req();

    /* Compile the message */
    if (!err) err = EC_M_compile_hdr_stuff(hdr_stuff, msg);
    if (!err) err = EC_M_compile_setup_req(setup_req, msg);

    /* Free the message objects */
    EC_M_free_hdr_stuff(hdr_stuff);
    EC_M_free_setup_req(setup_req);

    /* Return the message */
    if (!err) return EC_ERR_NONE;

    EC_M_free_msg(msg);
    return err;
}

EC_Errno EC_P_parse_setup(EC_M_Msg msg, BIGNUM *setup_n, BIGNUM *setup_e,
    EC_M_Bank_mkey *bank_mkey, char **bankname, EC_M_Protocols *protocols,
    EC_M_Error *error)
{
    EC_M_Setup setup;
    EC_M_Bank_mkey mybank_mkey = NULL;
    char *mybankname = NULL;
    EC_M_Protocols myprotocols = NULL;
    EC_Errno err = EC_ERR_NONE;
    EC_M_Fieldtype fieldtype;
    EC_M_Rectype rectype;

    if (!msg || !setup_n || !setup_e) return EC_ERR_INTERNAL;

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

    /* Decompile the message */
    err = EC_M_decompile_setup(&setup, msg);
    if (err) return EC_ERR_INTERNAL;

    /* Check the signature */
    if (!EC_U_verify_sigmsg(setup->sigmsg, setup_n, setup_e)) {
	/* Bad signature! */
	return EC_ERR_INTERNAL;
    }

    /* Decompile the pieces */
    if (!err) err = EC_M_decompile_bank_mkey(&mybank_mkey, setup->sigmsg->msg);
    if (!err) err = EC_M_decompile_string(&mybankname, setup->sigmsg->msg);
    if (!err) err = EC_M_decompile_protocols(&myprotocols, setup->sigmsg->msg);

    /* Free the setup message */
    EC_M_free_setup(setup);

    /* Is all OK? */
    if (err) {
	/* Free the pieces and abort */
	EC_M_free_bank_mkey(mybank_mkey);
	if (mybankname) EC_G_free(mybankname);
	EC_M_free_protocols(myprotocols);
	return EC_ERR_INTERNAL;
    }

    /* Assign the pieces */
    if (bank_mkey) *bank_mkey = mybank_mkey;
	else EC_M_free_bank_mkey(mybank_mkey);
    if (bankname) *bankname = mybankname; else EC_G_free(mybankname);
    if (protocols) *protocols = myprotocols;
	else EC_M_free_protocols(myprotocols);
    
    return EC_ERR_NONE;
}
