#include "lucre.h"

/*
   ONL_CURR =
     [
       MPI	coin_n
       int	ndenom
       MPI	coin_e[ndenom]
       MPI	seal_n
       MPI	seal_e
     ]
 */

EC_M_Onl_curr EC_M_new_onl_curr(BIGNUM *coin_n, UInt32 ndenom,
    BIGNUM **coin_e, BIGNUM *seal_n, BIGNUM *seal_e)
{
    EC_M_Onl_curr newonl_curr;

    if (!coin_n || (ndenom && !coin_e) || !seal_n || !seal_e) return NULL;
    newonl_curr =
	(EC_M_Onl_curr) EC_G_malloc(sizeof(struct EC_M_Onl_curr_s));
    if (!newonl_curr) return newonl_curr;

    newonl_curr->coin_n = coin_n;
    newonl_curr->ndenom = ndenom;
    newonl_curr->coin_e = coin_e;
    newonl_curr->seal_n = seal_n;
    newonl_curr->seal_e = seal_e;

    return newonl_curr;
}

EC_M_Onl_curr EC_M_clone_onl_curr(EC_M_Onl_curr onl_curr)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Onl_curr newonl_curr;
    BIGNUM *coin_n = NULL;
    UInt32 ndenom = 0;
    BIGNUM **coin_e = NULL;
    BIGNUM *seal_n = NULL;
    BIGNUM *seal_e = NULL;

    int i;
    
    err = EC_M_examine_onl_curr(onl_curr, &coin_n, &ndenom, &coin_e,
	    &seal_n, &seal_e);
    if (!err) {
	newonl_curr = EC_M_new_onl_curr(coin_n, ndenom, coin_e,
	    seal_n, seal_e);
	if (newonl_curr) return newonl_curr;
    }

    EC_M_free_MPI(coin_n);
    for(i=0;i<ndenom;++i)
	if (coin_e) EC_M_free_MPI(coin_e[i]);
    if (coin_e) EC_G_free(coin_e);
    EC_M_free_MPI(seal_n);
    EC_M_free_MPI(seal_e);

    return NULL;
}

EC_Errno EC_M_examine_onl_curr(EC_M_Onl_curr onl_curr, BIGNUM **coin_n,
    UInt32 *ndenom, BIGNUM ***coin_e, BIGNUM **seal_n, BIGNUM **seal_e)
{ 
    BIGNUM *mycoin_n;
    UInt32 myndenom;
    BIGNUM **mycoin_e;
    BIGNUM *myseal_n;
    BIGNUM *myseal_e;

    int i;
    int seenbad = 0;

    if (!onl_curr) return EC_ERR_INTERNAL;

    mycoin_n = EC_M_clone_MPI(onl_curr->coin_n);
    myndenom = onl_curr->ndenom;
    mycoin_e = (BIGNUM **)EC_G_malloc(sizeof(BIGNUM *)*myndenom);
    if (mycoin_e) for(i=0;i<myndenom;++i) {
	mycoin_e[i] = EC_M_clone_MPI(onl_curr->coin_e[i]);
	if (!mycoin_e[i]) seenbad = 1;
    }
    myseal_n = EC_M_clone_MPI(onl_curr->seal_n);
    myseal_e = EC_M_clone_MPI(onl_curr->seal_e);

    if (!mycoin_n || !mycoin_e || !myseal_n || !myseal_e || seenbad) {
	/* Didn't copy properly; abort */
	EC_M_free_MPI(mycoin_n);
	for(i=0;i<myndenom;++i)
	    if (mycoin_e) EC_M_free_MPI(mycoin_e[i]);
	if (mycoin_e) EC_G_free(mycoin_e);
	EC_M_free_MPI(myseal_n);
	EC_M_free_MPI(myseal_e);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    if (coin_n) *coin_n = mycoin_n; else EC_M_free_MPI(mycoin_n);
    if (ndenom) *ndenom = myndenom;
    if (coin_e) *coin_e = mycoin_e; else {
	for(i=0;i<myndenom;++i) EC_G_free(mycoin_e[i]);
	EC_G_free(mycoin_e);
    }
    if (seal_n) *seal_n = myseal_n; else EC_M_free_MPI(myseal_n);
    if (seal_e) *seal_e = myseal_e; else EC_M_free_MPI(myseal_e);
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_onl_curr(EC_M_Onl_curr onl_curr1, EC_M_Onl_curr onl_curr2)
{
    int i;

    if (!onl_curr1 || !onl_curr2) return 1;

    if (EC_M_cmp_MPI(onl_curr1->coin_n, onl_curr2->coin_n)
     || onl_curr1->ndenom != onl_curr2->ndenom
     || EC_M_cmp_MPI(onl_curr1->seal_n, onl_curr2->seal_n)
     || EC_M_cmp_MPI(onl_curr1->seal_e, onl_curr2->seal_e))
	return 1;

    if (onl_curr1->ndenom &&
	(!onl_curr1->coin_e || !onl_curr2->coin_e))
	return 1;

    for(i=0;i<onl_curr1->ndenom;++i)
	if (EC_M_cmp_MPI(onl_curr1->coin_e[i], onl_curr2->coin_e[i]))
	    return 1;

    return 0;
}

void EC_M_free_onl_curr(EC_M_Onl_curr onl_curr)
{
    int i;

    if (onl_curr) {
	EC_M_free_MPI(onl_curr->coin_n);
	for(i=0;i<onl_curr->ndenom;++i)
	    if (onl_curr->coin_e) EC_M_free_MPI(onl_curr->coin_e[i]);
	if (onl_curr->coin_e) EC_G_free(onl_curr->coin_e);
	EC_M_free_MPI(onl_curr->seal_n);
	EC_M_free_MPI(onl_curr->seal_e);
	EC_G_free(onl_curr);
    }
}

EC_Errno EC_M_compile_onl_curr(EC_M_Onl_curr onl_curr, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    int i;

    if (!onl_curr || !onl_curr->coin_n ||
	(onl_curr->ndenom && !onl_curr->coin_e) ||
	!onl_curr->seal_n || !onl_curr->seal_e ||
	!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_ONL_CURR, msg);
    if (!err) err = EC_M_compile_MPI(onl_curr->coin_n, msg);
    if (!err) err = EC_M_compile_int(onl_curr->ndenom, msg);
    for (i=0;i<onl_curr->ndenom;++i)
	if (!err) err = EC_M_compile_MPI(onl_curr->coin_e[i], msg);
    if (!err) err = EC_M_compile_MPI(onl_curr->seal_n, msg);
    if (!err) err = EC_M_compile_MPI(onl_curr->seal_e, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_onl_curr(EC_M_Onl_curr *onl_curr, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    BIGNUM *coin_n = NULL;
    UInt32 ndenom = 0;
    BIGNUM **coin_e = NULL;
    BIGNUM *seal_n = NULL;
    BIGNUM *seal_e = NULL;

    int i;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_ONL_CURR, msg);
    if (!err) err = EC_M_decompile_MPI(&coin_n, msg);
    if (!err) err = EC_M_decompile_int(&ndenom, msg);
    if (!err) {
	coin_e = (BIGNUM **)EC_G_malloc(sizeof(BIGNUM *)*ndenom);
	if (!coin_e) err = EC_ERR_INTERNAL;
    }
    for (i=0;i<ndenom;++i)
	if (!err) err = EC_M_decompile_MPI(&coin_e[i], msg);
    if (!err) err = EC_M_decompile_MPI(&seal_n, msg);
    if (!err) err = EC_M_decompile_MPI(&seal_e, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && onl_curr) {
	*onl_curr = EC_M_new_onl_curr(coin_n, ndenom, coin_e, seal_n, seal_e);
	if (!*onl_curr) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    EC_M_free_MPI(coin_n);
    for(i=0;i<ndenom;++i)
	if (coin_e) EC_M_free_MPI(coin_e[i]);
    if (coin_e) EC_G_free(coin_e);
    EC_M_free_MPI(seal_n);
    EC_M_free_MPI(seal_e);
    return err;
}
