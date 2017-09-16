#include <time.h>
#include "lucre.h"

/* Create and parse the messages in the OPENACC1/OPENACC2 protocol */

EC_Errno EC_P_create_openacc1(char *accID, EC_M_Currency currency,
    BIGNUM *acc_n, BIGNUM *acc_e, EC_M_Protocol protocol, char *password,
    EC_M_Bank_mkey bank_mkey, time_t stamp, EC_M_Msg msg)
{
    EC_M_Hdr_stuff hdr_stuff;
    EC_M_Userinfo userinfo;
    EC_M_Openacc1 openacc1;
    EC_Errno err = EC_ERR_NONE;
    char *myaccID;
    char *myname;
    char *myemail;
    BIGNUM *myacc_n;
    BIGNUM *myacc_e;
    char *mypassword;
    EC_M_Msg submsg;
    EC_M_Bank_encr bank_encr;

    if (!accID || !acc_n || !acc_e || !password || !bank_mkey || !msg)
	return EC_ERR_INTERNAL;

    /* Create the hdr_stuff header */
    hdr_stuff = EC_M_new_hdr_stuff(EC_LIB_VERNUM, stamp);
    if (!hdr_stuff) {
	return EC_ERR_INTERNAL;
    }

    /* Create the userinfo message */
    myname = EC_G_malloc(1);
    if (!myname) {
	EC_M_free_hdr_stuff(hdr_stuff);
	return EC_ERR_INTERNAL;
    }
    myemail = EC_G_malloc(1);
    if (!myemail) {
	EC_M_free_hdr_stuff(hdr_stuff);
	EC_G_free(myname);
	return EC_ERR_INTERNAL;
    }
    *myname = '\0';
    *myemail = '\0';
    myaccID = EC_G_strdup(accID);
    if (!myaccID) {
	EC_G_free(myname);
	EC_G_free(myemail);
	EC_M_free_hdr_stuff(hdr_stuff);
	return EC_ERR_INTERNAL;
    }
    userinfo = EC_M_new_userinfo(myaccID, myname, myemail, currency);
    if (!userinfo) {
	EC_G_free(myaccID);
	EC_G_free(myname);
	EC_G_free(myemail);
	EC_M_free_hdr_stuff(hdr_stuff);
	return EC_ERR_INTERNAL;
    }

    myacc_n = EC_M_clone_MPI(acc_n);
    myacc_e = EC_M_clone_MPI(acc_e);
    mypassword = EC_G_strdup(password);
    if (!myacc_n || !myacc_e || !mypassword) {
	EC_M_free_userinfo(userinfo);
	EC_M_free_MPI(myacc_n);
	EC_M_free_MPI(myacc_e);
	if (mypassword) EC_G_free(mypassword);
	EC_M_free_hdr_stuff(hdr_stuff);
	return EC_ERR_INTERNAL;
    }

    /* Create the OPENACC1 message */
    openacc1 = EC_M_new_openacc1(userinfo, myacc_n, myacc_e, protocol,
		bank_mkey->keynumber, mypassword);
    if (!openacc1) {
	EC_M_free_userinfo(userinfo);
	EC_M_free_MPI(myacc_n);
	EC_M_free_MPI(myacc_e);
	EC_G_free(mypassword);
	EC_M_free_hdr_stuff(hdr_stuff);
	return EC_ERR_INTERNAL;
    }

    /* Compile the message */
    submsg = EC_M_new_msg();
    if (!submsg) {
	EC_M_free_openacc1(openacc1);
	EC_M_free_hdr_stuff(hdr_stuff);
	return EC_ERR_INTERNAL;
    }
    if (!err) err = EC_M_compile_hdr_stuff(hdr_stuff, submsg);
    if (!err) err = EC_M_compile_openacc1(openacc1, submsg);

    /* Free the message objects */
    EC_M_free_hdr_stuff(hdr_stuff);
    EC_M_free_openacc1(openacc1);

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
