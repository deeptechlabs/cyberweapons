#include "lucre.h"

/*
   WITHDRAW4 =
     [
       int  protocol
       int  total_coins
       wdfin             ; but without the SOR/EOR for some reason
       ...
     ]
 */

EC_M_Withdraw4 EC_M_new_withdraw4(EC_M_Protocol protocol,
    UInt32 total_coins, UInt32 numwds, EC_M_Wdfin *wdfin)
{
    EC_M_Withdraw4 newwithdraw4;

    if (numwds && !wdfin) return NULL;
    newwithdraw4 = (EC_M_Withdraw4) EC_G_malloc(sizeof(struct EC_M_Withdraw4_s));
    if (!newwithdraw4) return newwithdraw4;

    newwithdraw4->protocol = protocol;
    newwithdraw4->total_coins = total_coins;
    newwithdraw4->numwds = numwds;
    newwithdraw4->wdfin = wdfin;
    return newwithdraw4;
}

EC_M_Withdraw4 EC_M_clone_withdraw4(EC_M_Withdraw4 withdraw4)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Withdraw4 newwithdraw4;
    EC_M_Protocol protocol;
    UInt32 total_coins;
    UInt32 numwds = 0;
    EC_M_Wdfin *wdfin = NULL;

    int i;
    
    err = EC_M_examine_withdraw4(withdraw4, &protocol, &total_coins,
				    &numwds, &wdfin);
    if (!err) {
	newwithdraw4 = EC_M_new_withdraw4(protocol, total_coins,
					    numwds, wdfin);
	if (newwithdraw4) return newwithdraw4;
    }

    for(i=0;i<numwds;++i)
	if (wdfin) EC_M_free_wdfin(wdfin[i]);
    if (wdfin) EC_G_free(wdfin);

    return NULL;
}

EC_Errno EC_M_examine_withdraw4(EC_M_Withdraw4 withdraw4,
    EC_M_Protocol *protocol, UInt32 *total_coins,
    UInt32 *numwds, EC_M_Wdfin **wdfin)
{ 
    EC_M_Protocol myprotocol;
    UInt32 mytotal_coins;
    UInt32 mynumwds;
    EC_M_Wdfin *mywdfin;

    int i;
    int seenbad = 0;

    if (!withdraw4 || (withdraw4->numwds && !withdraw4->wdfin))
	return EC_ERR_INTERNAL;

    myprotocol = withdraw4->protocol;
    mytotal_coins = withdraw4->total_coins;
    mynumwds = withdraw4->numwds;
    mywdfin =
	(EC_M_Wdfin *)EC_G_malloc(sizeof(EC_M_Wdfin)*mynumwds);
    if (mywdfin) for(i=0;i<mynumwds;++i) {
	mywdfin[i] = EC_M_clone_wdfin(withdraw4->wdfin[i]);
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
    if (total_coins) *total_coins = mytotal_coins;
    if (numwds) *numwds = mynumwds;
    if (wdfin) *wdfin = mywdfin; else {
	for(i=0;i<mynumwds;++i) EC_M_free_wdfin(mywdfin[i]);
	EC_G_free(mywdfin);
    }
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_withdraw4(EC_M_Withdraw4 withdraw41, EC_M_Withdraw4 withdraw42)
{
    int i;

    if (!withdraw41 || !withdraw42) return 1;

    if (withdraw41->protocol != withdraw42->protocol
     || withdraw41->total_coins != withdraw42->total_coins
     || withdraw41->numwds != withdraw42->numwds)
	return 1;

    if (withdraw41->numwds &&
	(!withdraw41->wdfin || !withdraw42->wdfin))
	return 1;

    for(i=0;i<withdraw41->numwds;++i) {
	if (EC_M_cmp_wdfin(withdraw41->wdfin[i],
	    withdraw42->wdfin[i]))
	    return 1;
    }

    return 0;
}

void EC_M_free_withdraw4(EC_M_Withdraw4 withdraw4)
{
    int i;

    if (withdraw4) {
	for(i=0;i<withdraw4->numwds;++i)
	    if (withdraw4->wdfin)
		EC_M_free_wdfin(withdraw4->wdfin[i]);
	if (withdraw4->wdfin) EC_G_free(withdraw4->wdfin);
	EC_G_free(withdraw4);
    }
}

EC_Errno EC_M_compile_withdraw4(EC_M_Withdraw4 withdraw4, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    int i;

    if (!withdraw4 || (withdraw4->numwds && !withdraw4->wdfin) || !msg)
	return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_WITHDRAW4, msg);
    if (!err) err = EC_M_compile_int(withdraw4->protocol, msg);
    if (!err) err = EC_M_compile_int(withdraw4->total_coins, msg);
    for(i=0;i<withdraw4->numwds;++i)
	if (!err) err = EC_M_compile_wdfin(withdraw4->wdfin[i], msg, 1);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_withdraw4(EC_M_Withdraw4 *withdraw4, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    EC_M_Protocol protocol;
    UInt32 total_coins;
    UInt32 numwds = 0;
    EC_M_Wdfin *wdfin = NULL;

    EC_M_Fieldtype fieldtype;
    EC_M_Rectype rectype;
    int i;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_WITHDRAW4, msg);
    if (!err) err = EC_M_decompile_int(&protocol, msg);
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
    if (!err && withdraw4) {
	*withdraw4 = EC_M_new_withdraw4(protocol, total_coins,
					    numwds, wdfin);
	if (!*withdraw4) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    for(i=0;i<numwds;++i)
	if (wdfin) EC_M_free_wdfin(wdfin[i]);
    if (wdfin) EC_G_free(wdfin);
    return err;
}
