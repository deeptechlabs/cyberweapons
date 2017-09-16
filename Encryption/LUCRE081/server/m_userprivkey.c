#include "lucre.h"

/*
   USERPRIVKEY =
     [
       MPI  d
       MPI  q
       MPI  p
       MPI  iqmp ; (1/q) mod p
     ]
 */

EC_M_Userprivkey EC_M_new_userprivkey(BIGNUM *d, BIGNUM *q, BIGNUM *p,
    BIGNUM *iqmp)
{
    EC_M_Userprivkey newuserprivkey;

    newuserprivkey =
	(EC_M_Userprivkey) EC_G_malloc(sizeof(struct EC_M_Userprivkey_s));
    if (!newuserprivkey) return newuserprivkey;

    newuserprivkey->d = d;
    newuserprivkey->q = q;
    newuserprivkey->p = p;
    newuserprivkey->iqmp = iqmp;
    return newuserprivkey;
}

EC_M_Userprivkey EC_M_clone_userprivkey(EC_M_Userprivkey userprivkey)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Userprivkey newuserprivkey;
    BIGNUM *d = NULL;
    BIGNUM *q = NULL;
    BIGNUM *p = NULL;
    BIGNUM *iqmp = NULL;
    
    err = EC_M_examine_userprivkey(userprivkey, &d, &q, &p, &iqmp);
    if (!err) {
	newuserprivkey = EC_M_new_userprivkey(d, q, p, iqmp);
	if (newuserprivkey) return newuserprivkey;
    }

    EC_M_free_MPI(d);
    EC_M_free_MPI(q);
    EC_M_free_MPI(p);
    EC_M_free_MPI(iqmp);
    return NULL;
}

EC_Errno EC_M_examine_userprivkey(EC_M_Userprivkey userprivkey, BIGNUM **d,
    BIGNUM **q, BIGNUM **p, BIGNUM **iqmp)
{ 
    BIGNUM *myd;
    BIGNUM *myq;
    BIGNUM *myp;
    BIGNUM *myiqmp;

    if (!userprivkey) return EC_ERR_INTERNAL;

    myd = EC_M_clone_MPI(userprivkey->d);
    myq = EC_M_clone_MPI(userprivkey->q);
    myp = EC_M_clone_MPI(userprivkey->p);
    myiqmp = EC_M_clone_MPI(userprivkey->iqmp);

    if (!myd || !myq || !myp || !myiqmp) {
	EC_M_free_MPI(myd);
	EC_M_free_MPI(myq);
	EC_M_free_MPI(myp);
	EC_M_free_MPI(myiqmp);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    if (d) *d = myd; else EC_M_free_MPI(myd);
    if (q) *q = myq; else EC_M_free_MPI(myq);
    if (p) *p = myp; else EC_M_free_MPI(myp);
    if (iqmp) *iqmp = myiqmp; else EC_M_free_MPI(myiqmp);
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_userprivkey(EC_M_Userprivkey userprivkey1, EC_M_Userprivkey userprivkey2)
{
    if (!userprivkey1 || !userprivkey2) return 1;

    if (EC_M_cmp_MPI(userprivkey1->d,userprivkey2->d)
     || EC_M_cmp_MPI(userprivkey1->q,userprivkey2->q)
     || EC_M_cmp_MPI(userprivkey1->p,userprivkey2->p)
     || EC_M_cmp_MPI(userprivkey1->iqmp,userprivkey2->iqmp))
	return 1;

    return 0;
}

void EC_M_free_userprivkey(EC_M_Userprivkey userprivkey)
{
    if (userprivkey) {
	EC_M_free_MPI(userprivkey->d);
	EC_M_free_MPI(userprivkey->q);
	EC_M_free_MPI(userprivkey->p);
	EC_M_free_MPI(userprivkey->iqmp);
	EC_G_free(userprivkey);
    }
}

EC_Errno EC_M_compile_userprivkey(EC_M_Userprivkey userprivkey, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!userprivkey || !msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_USERPRIVKEY, msg);
    if (!err) err = EC_M_compile_MPI(userprivkey->d, msg);
    if (!err) err = EC_M_compile_MPI(userprivkey->q, msg);
    if (!err) err = EC_M_compile_MPI(userprivkey->p, msg);
    if (!err) err = EC_M_compile_MPI(userprivkey->iqmp, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_userprivkey(EC_M_Userprivkey *userprivkey, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    BIGNUM *d = NULL;
    BIGNUM *q = NULL;
    BIGNUM *p = NULL;
    BIGNUM *iqmp = NULL;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_USERPRIVKEY, msg);
    if (!err) err = EC_M_decompile_MPI(&d, msg);
    if (!err) err = EC_M_decompile_MPI(&q, msg);
    if (!err) err = EC_M_decompile_MPI(&p, msg);
    if (!err) err = EC_M_decompile_MPI(&iqmp, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && userprivkey) {
	*userprivkey = EC_M_new_userprivkey(d, q, p, iqmp);
	if (!*userprivkey) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    EC_M_free_MPI(d);
    EC_M_free_MPI(q);
    EC_M_free_MPI(p);
    EC_M_free_MPI(iqmp);
    return err;
}
