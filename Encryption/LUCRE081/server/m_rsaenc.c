#include "lucre.h"

/*
   RSAENC =
     [
       MPI  key
     ]
 */

EC_M_Rsaenc EC_M_new_rsaenc(BIGNUM *key)
{
    EC_M_Rsaenc newrsaenc;

    newrsaenc =
	(EC_M_Rsaenc) EC_G_malloc(sizeof(struct EC_M_Rsaenc_s));
    if (!newrsaenc) return newrsaenc;

    newrsaenc->key = key;
    return newrsaenc;
}

EC_M_Rsaenc EC_M_clone_rsaenc(EC_M_Rsaenc rsaenc)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Rsaenc newrsaenc;
    BIGNUM *key = NULL;
    
    err = EC_M_examine_rsaenc(rsaenc, &key);
    if (!err) {
	newrsaenc = EC_M_new_rsaenc(key);
	if (newrsaenc) return newrsaenc;
    }

    EC_M_free_MPI(key);
    return NULL;
}

EC_Errno EC_M_examine_rsaenc(EC_M_Rsaenc rsaenc, BIGNUM **key)
{ 
    BIGNUM *mykey;

    if (!rsaenc) return EC_ERR_INTERNAL;

    mykey = EC_M_clone_MPI(rsaenc->key);

    if (!mykey) {
	EC_M_free_MPI(mykey);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    if (key) *key = mykey; else EC_M_free_MPI(mykey);
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_rsaenc(EC_M_Rsaenc rsaenc1, EC_M_Rsaenc rsaenc2)
{
    if (!rsaenc1 || !rsaenc2) return 1;

    if (EC_M_cmp_MPI(rsaenc1->key,rsaenc2->key))
	return 1;

    return 0;
}

void EC_M_free_rsaenc(EC_M_Rsaenc rsaenc)
{
    if (rsaenc) {
	EC_M_free_MPI(rsaenc->key);
	EC_G_free(rsaenc);
    }
}

EC_Errno EC_M_compile_rsaenc(EC_M_Rsaenc rsaenc, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!rsaenc || !msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_RSAENC, msg);
    if (!err) err = EC_M_compile_MPI(rsaenc->key, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_rsaenc(EC_M_Rsaenc *rsaenc, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    BIGNUM *key = NULL;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_RSAENC, msg);
    if (!err) err = EC_M_decompile_MPI(&key, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && rsaenc) {
	*rsaenc = EC_M_new_rsaenc(key);
	if (!*rsaenc) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    EC_M_free_MPI(key);
    return err;
}
