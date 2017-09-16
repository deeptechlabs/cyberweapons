#include "lucre.h"

/*
   openacc1 =
     [
        userinfo
        MPI     n
        MPI     e
        int     protocol
        int     keyno
        string  password
     ]
 */

EC_M_Openacc1 EC_M_new_openacc1(EC_M_Userinfo userinfo, BIGNUM *n,
    BIGNUM *e, EC_M_Protocol protocol, UInt32 keyno, char *password)
{
    EC_M_Openacc1 newopenacc1;

    if (!userinfo || !n || !e || !password) return NULL;
    newopenacc1 = (EC_M_Openacc1) EC_G_malloc(sizeof(struct EC_M_Openacc1_s));
    if (!newopenacc1) return newopenacc1;

    newopenacc1->userinfo = userinfo;
    newopenacc1->n = n;
    newopenacc1->e = e;
    newopenacc1->protocol = protocol;
    newopenacc1->keyno = keyno;
    newopenacc1->password = password;
    return newopenacc1;
}

EC_M_Openacc1 EC_M_clone_openacc1(EC_M_Openacc1 openacc1)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Openacc1 newopenacc1;
    EC_M_Userinfo userinfo = NULL;
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    EC_M_Protocol protocol;
    UInt32 keyno;
    char *password = NULL;
    
    err = EC_M_examine_openacc1(openacc1, &userinfo, &n, &e, &protocol, &keyno,
	&password);
    if (!err) {
	newopenacc1 = EC_M_new_openacc1(userinfo, n, e, protocol, keyno,
	    password);
	if (newopenacc1) return newopenacc1;
    }

    EC_M_free_userinfo(userinfo);
    EC_M_free_MPI(n);
    EC_M_free_MPI(e);
    if (password) EC_G_free(password);
    return NULL;
}

EC_Errno EC_M_examine_openacc1(EC_M_Openacc1 openacc1, EC_M_Userinfo *userinfo,
    BIGNUM **n, BIGNUM **e, EC_M_Protocol *protocol, UInt32 *keyno,
    char **password)
{ 
    EC_M_Userinfo myuserinfo;
    BIGNUM *myn;
    BIGNUM *mye;
    EC_M_Protocol myprotocol;
    UInt32 mykeyno;
    char *mypassword;

    if (!openacc1) return EC_ERR_INTERNAL;

    myuserinfo = EC_M_clone_userinfo(openacc1->userinfo);
    myn = EC_M_clone_MPI(openacc1->n);
    mye = EC_M_clone_MPI(openacc1->e);
    myprotocol = openacc1->protocol;
    mykeyno = openacc1->keyno;
    mypassword = EC_G_strdup(openacc1->password);

    if (!myuserinfo || !myn || !mye || !mypassword) {
	/* Didn't copy properly; abort */
	EC_M_free_userinfo(myuserinfo);
	EC_M_free_MPI(myn);
	EC_M_free_MPI(mye);
	if (mypassword) EC_G_free(mypassword);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    if (userinfo) *userinfo = myuserinfo; else EC_M_free_userinfo(myuserinfo);
    if (n) *n = myn; else EC_M_free_MPI(myn);
    if (e) *e = mye; else EC_M_free_MPI(mye);
    if (protocol) *protocol = myprotocol;
    if (keyno) *keyno = mykeyno;
    if (password) *password = mypassword; else EC_G_free(mypassword);
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_openacc1(EC_M_Openacc1 openacc11, EC_M_Openacc1 openacc12)
{
    if (!openacc11 || !openacc12) return 1;

    if (EC_M_cmp_userinfo(openacc11->userinfo, openacc12->userinfo)
     || EC_M_cmp_MPI(openacc11->n, openacc12->n)
     || EC_M_cmp_MPI(openacc11->e, openacc12->e)
     || openacc11->protocol != openacc12->protocol
     || openacc11->keyno != openacc12->keyno
     || strcmp(openacc11->password, openacc12->password))
	return 1;

    return 0;
}

void EC_M_free_openacc1(EC_M_Openacc1 openacc1)
{
    if (openacc1) {
	EC_M_free_userinfo(openacc1->userinfo);
	EC_M_free_MPI(openacc1->n);
	EC_M_free_MPI(openacc1->e);
	if (openacc1->password) EC_G_free(openacc1->password);
	EC_G_free(openacc1);
    }
}

EC_Errno EC_M_compile_openacc1(EC_M_Openacc1 openacc1, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!openacc1 || !openacc1->userinfo || !openacc1->n || !openacc1->e
	|| !openacc1->password || !msg)
	return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_OPENACC1, msg);
    if (!err) err = EC_M_compile_userinfo(openacc1->userinfo, msg);
    if (!err) err = EC_M_compile_MPI(openacc1->n, msg);
    if (!err) err = EC_M_compile_MPI(openacc1->e, msg);
    if (!err) err = EC_M_compile_int(openacc1->protocol, msg);
    if (!err) err = EC_M_compile_int(openacc1->keyno, msg);
    if (!err) err = EC_M_compile_string(openacc1->password, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_openacc1(EC_M_Openacc1 *openacc1, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    EC_M_Userinfo userinfo = NULL;
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    EC_M_Protocol protocol;
    UInt32 keyno;
    char *password = NULL;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_OPENACC1, msg);
    if (!err) err = EC_M_decompile_userinfo(&userinfo, msg);
    if (!err) err = EC_M_decompile_MPI(&n, msg);
    if (!err) err = EC_M_decompile_MPI(&e, msg);
    if (!err) err = EC_M_decompile_int(&protocol, msg);
    if (!err) err = EC_M_decompile_int(&keyno, msg);
    if (!err) err = EC_M_decompile_string(&password, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && openacc1) {
	*openacc1 = EC_M_new_openacc1(userinfo, n, e, protocol,
	    keyno, password);
	if (!*openacc1) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    EC_M_free_userinfo(userinfo);
    EC_M_free_MPI(n);
    EC_M_free_MPI(e);
    if (password) EC_G_free(password);
    return err;
}
