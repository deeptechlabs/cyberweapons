#include "lucre.h"

/*
   WITHDRAW3 =
     [
       int  protocol
       int  flags
       int  total_coins
       wdfin             ; but without the SOR/EOR for some reason
       ...
     ]
 */

EC_M_Withdraw3 EC_M_new_withdraw3(EC_M_Protocol protocol, UInt32 flags,
    UInt32 total_coins, UInt32 numwds, EC_M_Wdfin *wdfin)
{
    EC_M_Withdraw3 newwithdraw3;

    if (numwds && !wdfin) return NULL;
    newwithdraw3 = (EC_M_Withdraw3) EC_G_malloc(sizeof(struct EC_M_Withdraw3_s));
    if (!newwithdraw3) return newwithdraw3;

    newwithdraw3->protocol = protocol;
    newwithdraw3->flags = flags;
    newwithdraw3->total_coins = total_coins;
    newwithdraw3->numwds = numwds;
    newwithdraw3->wdfin = wdfin;
    return newwithdraw3;
}

EC_M_Withdraw3 EC_M_clone_withdraw3(EC_M_Withdraw3 withdraw3)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Withdraw3 newwithdraw3;
    EC_M_Protocol protocol;
    UInt32 flags;
    UInt32 total_coins;
    UInt32 numwds = 0;
    EC_M_Wdfin *wdfin = NULL;

    int i;
    
    err = EC_M_examine_withdraw3(withdraw3, &protocol, &flags, &total_coins,
				    &numwds, &wdfin);
    if (!err) {
	newwithdraw3 = EC_M_new_withdraw3(protocol, flags, total_coins,
					    numwds, wdfin);
	if (newwithdraw3) return newwithdraw3;
    }

    for(i=0;i<numwds;++i)
	if (wdfin) EC_M_free_wdfin(wdfin[i]);
    if (wdfin) EC_G_free(wdfin);

    return NULL;
}

EC_Errno EC_M_examine_withdraw3(EC_M_Withdraw3 withdraw3,
    EC_M_Protocol *protocol, UInt32 *flags, UInt32 *total_coins,
    UInt32 *numwds, EC_M_Wdfin **wdfin)
{ 
    EC_M_Protocol myprotocol;
    UInt32 myflags;
    UInt32 mytotal_coins;
    UInt32 mynumwds;
    EC_M_Wdfin *mywdfin;

    int i;
    int seenbad = 0;

    if (!withdraw3 || (withdraw3->numwds && !withdraw3->wdfin))
	return EC_ERR_INTERNAL;

    myprotocol = withdraw3->protocol;
    myflags = withdraw3->flags;
    mytotal_coins = withdraw3->total_coins;
    mynumwds = withdraw3->numwds;
    mywdfin =
	(EC_M_Wdfin *)EC_G_malloc(sizeof(EC_M_Wdfin)*mynumwds);
    if (mywdfin) for(i=0;i<mynumwds;++i) {
	mywdfin[i] = EC_M_clone_wdfin(withdraw3->wdfin[i]);
	if (!mywdfin[i]) seenbad = 1;
    }

    if (!mywdfin || seenbad) {
	/* Didn't copy properly; abort */
	for(i=0;i<mynumwds;++i)
	    if (mywdfin) EC_M_free_wdfin(mywdfin[i]);
	if (mywdfin) EC_G_free(mywdfin);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    if (protocol) *protocol = myprotocol;
    if (flags) *flags = myflags;
    if (total_coins) *total_coins = mytotal_coins;
    if (numwds) *numwds = mynumwds;
    if (wdfin) *wdfin = mywdfin; else {
	for(i=0;i<mynumwds;++i) EC_M_free_wdfin(mywdfin[i]);
	EC_G_free(mywdfin);
    }
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_withdraw3(EC_M_Withdraw3 withdraw31, EC_M_Withdraw3 withdraw32)
{
    int i;

    if (!withdraw31 || !withdraw32) return 1;

    if (withdraw31->protocol != withdraw32->protocol
     || withdraw31->flags != withdraw32->flags
     || withdraw31->total_coins != withdraw32->total_coins
     || withdraw31->numwds != withdraw32->numwds)
	return 1;

    if (withdraw31->numwds &&
	(!withdraw31->wdfin || !withdraw32->wdfin))
	return 1;

    for(i=0;i<withdraw31->numwds;++i) {
	if (EC_M_cmp_wdfin(withdraw31->wdfin[i],
	    withdraw32->wdfin[i]))
	    return 1;
    }

    return 0;
}

void EC_M_free_withdraw3(EC_M_Withdraw3 withdraw3)
{
    int i;

    if (withdraw3) {
	for(i=0;i<withdraw3->numwds;++i)
	    if (withdraw3->wdfin)
		EC_M_free_wdfin(withdraw3->wdfin[i]);
	if (withdraw3->wdfin) EC_G_free(withdraw3->wdfin);
	EC_G_free(withdraw3);
    }
}

EC_Errno EC_M_compile_withdraw3(EC_M_Withdraw3 withdraw3, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    int i;

    if (!withdraw3 || (withdraw3->numwds && !withdraw3->wdfin) || !msg)
	return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_WITHDRAW3, msg);
    if (!err) err = EC_M_compile_int(withdraw3->protocol, msg);
    if (!err) err = EC_M_compile_int(withdraw3->flags, msg);
    if (!err) err = EC_M_compile_int(withdraw3->total_coins, msg);
    for(i=0;i<withdraw3->numwds;++i)
	if (!err && withdraw3->wdfin[i]->ncoins)
	    err = EC_M_compile_wdfin(withdraw3->wdfin[i], msg, 1);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_withdraw3(EC_M_Withdraw3 *withdraw3, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    EC_M_Protocol protocol;
    UInt32 flags;
    UInt32 total_coins;
    UInt32 numwds = 0;
    EC_M_Wdfin *wdfin = NULL;

    EC_M_Fieldtype fieldtype;
    EC_M_Rectype rectype;
    int i;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_WITHDRAW3, msg);
    if (!err) err = EC_M_decompile_int(&protocol, msg);
    if (!err) err = EC_M_decompile_int(&flags, msg);
    if (!err) err = EC_M_decompile_int(&total_coins, msg);
    while(!err) {
	if (!err) err = EC_M_examine_msg(&fieldtype, &rectype, msg);
	if (!err) if ((fieldtype != EC_M_FIELD_SOR ||
			rectype != EC_M_REC_WDFIN)
		    && fieldtype != EC_M_FIELD_INT) break;
	if (!err) {
	    EC_M_Wdfin *newwdfin =
		(EC_M_Wdfin *)EC_G_realloc(wdfin,
		sizeof(EC_M_Wdfin)*(numwds+1));
	    if (!newwdfin) {
		if (wdfin) EC_G_free(wdfin);
		err = EC_ERR_INTERNAL;
	    } else {
		wdfin = newwdfin;
	    }
	}
	if (!err) err = EC_M_decompile_wdfin(&wdfin[numwds], msg);
	if (!err) ++numwds;
    }
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && withdraw3) {
	*withdraw3 = EC_M_new_withdraw3(protocol, flags, total_coins,
					    numwds, wdfin);
	if (!*withdraw3) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    for(i=0;i<numwds;++i)
	if (wdfin) EC_M_free_wdfin(wdfin[i]);
    if (wdfin) EC_G_free(wdfin);
    return err;
}
