#include "lucre.h"

/*
   ONL_COIN =
     [
       int  keyversion
       MPI  n
       MPI  sig
       int  value	; optional
     ]
 */

EC_M_Onl_coin EC_M_new_onl_coin(UInt32 keyversion, BIGNUM *n, BIGNUM *sig,
    UInt32 value)
{
    EC_M_Onl_coin newonl_coin;

    newonl_coin =
	(EC_M_Onl_coin) EC_G_malloc(sizeof(struct EC_M_Onl_coin_s));
    if (!newonl_coin) return newonl_coin;

    newonl_coin->keyversion = keyversion;
    newonl_coin->n = n;
    newonl_coin->sig = sig;
    newonl_coin->value = value;
    return newonl_coin;
}

EC_M_Onl_coin EC_M_clone_onl_coin(EC_M_Onl_coin onl_coin)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Onl_coin newonl_coin;
    UInt32 keyversion;
    BIGNUM *n = NULL;
    BIGNUM *sig = NULL;
    UInt32 value;
    
    err = EC_M_examine_onl_coin(onl_coin, &keyversion, &n, &sig, &value);
    if (!err) {
	newonl_coin = EC_M_new_onl_coin(keyversion, n, sig, value);
	if (newonl_coin) return newonl_coin;
    }

    EC_M_free_MPI(n);
    EC_M_free_MPI(sig);
    return NULL;
}

EC_Errno EC_M_examine_onl_coin(EC_M_Onl_coin onl_coin, UInt32 *keyversion,
    BIGNUM **n, BIGNUM **sig, UInt32 *value)
{ 
    UInt32 mykeyversion;
    BIGNUM *myn;
    BIGNUM *mysig;
    UInt32 myvalue;

    if (!onl_coin) return EC_ERR_INTERNAL;

    mykeyversion = onl_coin->keyversion;
    myn = EC_M_clone_MPI(onl_coin->n);
    mysig = EC_M_clone_MPI(onl_coin->sig);
    myvalue = onl_coin->value;

    if (!myn || !mysig) {
	EC_M_free_MPI(myn);
	EC_M_free_MPI(mysig);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    if (keyversion) *keyversion = mykeyversion;
    if (n) *n = myn; else EC_M_free_MPI(myn);
    if (sig) *sig = mysig; else EC_M_free_MPI(mysig);
    if (value) *value = myvalue;
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_onl_coin(EC_M_Onl_coin onl_coin1, EC_M_Onl_coin onl_coin2)
{
    if (!onl_coin1 || !onl_coin2) return 1;

    if (onl_coin1->keyversion != onl_coin2->keyversion
     || EC_M_cmp_MPI(onl_coin1->n, onl_coin2->n)
     || EC_M_cmp_MPI(onl_coin1->sig, onl_coin2->sig)
     || onl_coin1->value != onl_coin2->value)
	return 1;

    return 0;
}

void EC_M_free_onl_coin(EC_M_Onl_coin onl_coin)
{
    if (onl_coin) {
	EC_M_free_MPI(onl_coin->n);
	EC_M_free_MPI(onl_coin->sig);
	EC_G_free(onl_coin);
    }
}

EC_Errno EC_M_compile_onl_coin(EC_M_Onl_coin onl_coin, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!onl_coin || !msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_ONL_COIN, msg);
    if (!err) err = EC_M_compile_int(onl_coin->keyversion, msg);
    if (!err) err = EC_M_compile_MPI(onl_coin->n, msg);
    if (!err) err = EC_M_compile_MPI(onl_coin->sig, msg);
    if (!err) err = EC_M_compile_int(onl_coin->value, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_onl_coin(EC_M_Onl_coin *onl_coin, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    UInt32 keyversion;
    BIGNUM *n = NULL;
    BIGNUM *sig = NULL;
    UInt32 value = 0;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_ONL_COIN, msg);
    if (!err) err = EC_M_decompile_int(&keyversion, msg);
    if (!err) err = EC_M_decompile_MPI(&n, msg);
    if (!err) err = EC_M_decompile_MPI(&sig, msg);
    if (!err) EC_M_decompile_int(&value, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && onl_coin) {
	*onl_coin = EC_M_new_onl_coin(keyversion, n, sig, value);
	if (!*onl_coin) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    EC_M_free_MPI(n);
    EC_M_free_MPI(sig);
    return err;
}
