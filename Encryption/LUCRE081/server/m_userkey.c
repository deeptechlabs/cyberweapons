#include "lucre.h"

/*
   USERKEY =
     [
       MPI  n
       MPI  e
       int  keyno
       [ USERPRIVCRYPT
         encrypt  privkey
       ]
     ]
 */

EC_M_Userkey EC_M_new_userkey(BIGNUM *n, BIGNUM *e, UInt32 keyno,
    EC_M_Encrypt privkey)
{
    EC_M_Userkey newuserkey;

    newuserkey =
	(EC_M_Userkey) EC_G_malloc(sizeof(struct EC_M_Userkey_s));
    if (!newuserkey) return newuserkey;

    newuserkey->n = n;
    newuserkey->e = e;
    newuserkey->keyno = keyno;
    newuserkey->privkey = privkey;
    return newuserkey;
}

EC_M_Userkey EC_M_clone_userkey(EC_M_Userkey userkey)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Userkey newuserkey;
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    UInt32 keyno;
    EC_M_Encrypt privkey = NULL;
    
    err = EC_M_examine_userkey(userkey, &n, &e, &keyno, &privkey);
    if (!err) {
	newuserkey = EC_M_new_userkey(n, e, keyno, privkey);
	if (newuserkey) return newuserkey;
    }

    EC_M_free_MPI(n);
    EC_M_free_MPI(e);
    EC_M_free_encrypt(privkey);
    return NULL;
}

EC_Errno EC_M_examine_userkey(EC_M_Userkey userkey, BIGNUM **n,
    BIGNUM **e, UInt32 *keyno, EC_M_Encrypt *privkey)
{ 
    BIGNUM *myn;
    BIGNUM *mye;
    UInt32 mykeyno;
    EC_M_Encrypt myprivkey;

    if (!userkey) return EC_ERR_INTERNAL;

    myn = EC_M_clone_MPI(userkey->n);
    mye = EC_M_clone_MPI(userkey->e);
    mykeyno = userkey->keyno;
    myprivkey = EC_M_clone_encrypt(userkey->privkey);

    if (!myn || !mye || !myprivkey) {
	EC_M_free_MPI(myn);
	EC_M_free_MPI(mye);
	EC_M_free_encrypt(myprivkey);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    if (n) *n = myn; else EC_M_free_MPI(myn);
    if (e) *e = mye; else EC_M_free_MPI(mye);
    if (keyno) *keyno = mykeyno;
    if (privkey) *privkey = myprivkey; else EC_M_free_encrypt(myprivkey);
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_userkey(EC_M_Userkey userkey1, EC_M_Userkey userkey2)
{
    if (!userkey1 || !userkey2) return 1;

    if (EC_M_cmp_MPI(userkey1->n,userkey2->n)
     || EC_M_cmp_MPI(userkey1->e,userkey2->e)
     || userkey1->keyno != userkey2->keyno
     || EC_M_cmp_encrypt(userkey1->privkey,userkey2->privkey))
	return 1;

    return 0;
}

void EC_M_free_userkey(EC_M_Userkey userkey)
{
    if (userkey) {
	EC_M_free_MPI(userkey->n);
	EC_M_free_MPI(userkey->e);
	EC_M_free_encrypt(userkey->privkey);
	EC_G_free(userkey);
    }
}

EC_Errno EC_M_compile_userkey(EC_M_Userkey userkey, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!userkey || !msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_USERKEY, msg);
    if (!err) err = EC_M_compile_MPI(userkey->n, msg);
    if (!err) err = EC_M_compile_MPI(userkey->e, msg);
    if (!err) err = EC_M_compile_int(userkey->keyno, msg);
    if (!err) err = EC_M_compile_sor(EC_M_REC_USERPRIVENC, msg);
    if (!err) err = EC_M_compile_encrypt(userkey->privkey, msg);
    if (!err) err = EC_M_compile_eor(msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_userkey(EC_M_Userkey *userkey, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    UInt32 keyno;
    EC_M_Encrypt privkey = NULL;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_USERKEY, msg);
    if (!err) err = EC_M_decompile_MPI(&n, msg);
    if (!err) err = EC_M_decompile_MPI(&e, msg);
    if (!err) err = EC_M_decompile_int(&keyno, msg);
    if (!err) err = EC_M_decompile_sor(EC_M_REC_USERPRIVENC, msg);
    if (!err) err = EC_M_decompile_encrypt(&privkey, msg);
    if (!err) err = EC_M_decompile_eor(msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && userkey) {
	*userkey = EC_M_new_userkey(n, e, keyno, privkey);
	if (!*userkey) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    EC_M_free_MPI(n);
    EC_M_free_MPI(e);
    EC_M_free_encrypt(privkey);
    return err;
}
