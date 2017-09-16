#include "lucre.h"

/*
   pcoins =
     [
       onl_coin
       ...
     ]
 */

EC_M_Pcoins EC_M_new_pcoins(UInt32 numcoins, EC_M_Onl_coin *onl_coin)
{
    EC_M_Pcoins newpcoins;

    if (numcoins && !onl_coin) return NULL;
    newpcoins = (EC_M_Pcoins) EC_G_malloc(sizeof(struct EC_M_Pcoins_s));
    if (!newpcoins) return newpcoins;

    newpcoins->numcoins = numcoins;
    newpcoins->onl_coin = onl_coin;
    return newpcoins;
}

EC_M_Pcoins EC_M_clone_pcoins(EC_M_Pcoins pcoins)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Pcoins newpcoins;
    UInt32 numcoins = 0;
    EC_M_Onl_coin *onl_coin = NULL;

    int i;
    
    err = EC_M_examine_pcoins(pcoins, &numcoins, &onl_coin);
    if (!err) {
	newpcoins = EC_M_new_pcoins(numcoins, onl_coin);
	if (newpcoins) return newpcoins;
    }

    for(i=0;i<numcoins;++i)
	if (onl_coin) EC_M_free_onl_coin(onl_coin[i]);
    if (onl_coin) EC_G_free(onl_coin);

    return NULL;
}

EC_Errno EC_M_examine_pcoins(EC_M_Pcoins pcoins, UInt32 *numcoins,
    EC_M_Onl_coin **onl_coin)
{ 
    UInt32 mynumcoins;
    EC_M_Onl_coin *myonl_coin;

    int i;
    int seenbad = 0;

    if (!pcoins) return EC_ERR_INTERNAL;

    mynumcoins = pcoins->numcoins;
    myonl_coin =
	(EC_M_Onl_coin *)EC_G_malloc(sizeof(EC_M_Onl_coin)*mynumcoins);
    if (myonl_coin) for(i=0;i<mynumcoins;++i) {
	myonl_coin[i] = EC_M_clone_onl_coin(pcoins->onl_coin[i]);
	if (!myonl_coin[i]) seenbad = 1;
    }

    if (!myonl_coin || seenbad) {
	/* Didn't copy properly; abort */
	for(i=0;i<mynumcoins;++i)
	    if (myonl_coin) EC_M_free_onl_coin(myonl_coin[i]);
	if (myonl_coin) EC_G_free(myonl_coin);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    if (numcoins) *numcoins = mynumcoins;
    if (onl_coin) *onl_coin = myonl_coin; else {
	for(i=0;i<mynumcoins;++i) EC_M_free_onl_coin(myonl_coin[i]);
	EC_G_free(myonl_coin);
    }
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_pcoins(EC_M_Pcoins pcoins1, EC_M_Pcoins pcoins2)
{
    int i;

    if (!pcoins1 || !pcoins2) return 1;

    if (pcoins1->numcoins != pcoins2->numcoins)
	return 1;

    if (pcoins1->numcoins &&
	(!pcoins1->onl_coin || !pcoins2->onl_coin))
	return 1;

    for(i=0;i<pcoins1->numcoins;++i) {
	if (EC_M_cmp_onl_coin(pcoins1->onl_coin[i],
	    pcoins2->onl_coin[i]))
	    return 1;
    }

    return 0;
}

void EC_M_free_pcoins(EC_M_Pcoins pcoins)
{
    int i;

    if (pcoins) {
	for(i=0;i<pcoins->numcoins;++i)
	    if (pcoins->onl_coin)
		EC_M_free_onl_coin(pcoins->onl_coin[i]);
	if (pcoins->onl_coin) EC_G_free(pcoins->onl_coin);
	EC_G_free(pcoins);
    }
}

EC_Errno EC_M_compile_pcoins(EC_M_Pcoins pcoins, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    int i;

    if (!pcoins || (pcoins->numcoins && !pcoins->onl_coin) || !msg)
	return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_PCOINS, msg);
    for(i=0;i<pcoins->numcoins;++i)
	if (!err) err = EC_M_compile_onl_coin(pcoins->onl_coin[i], msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_pcoins(EC_M_Pcoins *pcoins, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    UInt32 numcoins = 0;
    EC_M_Onl_coin *onl_coin = NULL;

    EC_M_Fieldtype fieldtype;
    EC_M_Rectype rectype;
    int i;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_PCOINS, msg);
    while(!err) {
	if (!err) err = EC_M_examine_msg(&fieldtype, &rectype, msg);
	if (!err) if (fieldtype != EC_M_FIELD_SOR ||
			rectype != EC_M_REC_ONL_COIN) break;
	if (!err) {
	    EC_M_Onl_coin *newonl_coin =
		(EC_M_Onl_coin *)EC_G_realloc(onl_coin,
		sizeof(EC_M_Onl_coin)*(numcoins+1));
	    if (!newonl_coin) {
		if (onl_coin) EC_G_free(onl_coin);
		err = EC_ERR_INTERNAL;
	    } else {
		onl_coin = newonl_coin;
	    }
	}
	if (!err) err = EC_M_decompile_onl_coin(&onl_coin[numcoins], msg);
	if (!err) ++numcoins;
    }
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && pcoins) {
	*pcoins = EC_M_new_pcoins(numcoins, onl_coin);
	if (!*pcoins) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    for(i=0;i<numcoins;++i)
	if (onl_coin) EC_M_free_onl_coin(onl_coin[i]);
    if (onl_coin) EC_G_free(onl_coin);
    return err;
}
