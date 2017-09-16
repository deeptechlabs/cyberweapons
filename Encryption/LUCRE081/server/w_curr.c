#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include "lucre.h"

/* Look up a currency in a wallet; 0 means find the highest keyversion */
EC_M_Curr EC_W_curr_lookup(EC_W_Wallet wallet, UInt32 bankID,
    EC_M_Currency currency, UInt32 keyversion)
{
    char *currfname;
    int currfd;
    EC_M_Msg currmsg;
    EC_M_Curr curr = NULL;
    EC_M_Curr match = NULL;
    EC_Errno err;
    EC_W_Locktype oldlock;
    char bankext[40];   /* Big enough for a UInt32 */

    if (!wallet) return NULL;

    /* Remove the _value_ part of the keyversion */
    keyversion &= ~EC_M_KEYVER_VALMASK;

    /* Check the cache first */
    if (wallet->curr_cache && wallet->userrec->bankID == bankID &&
	wallet->curr_cache->numcurrs == 1 &&
	wallet->curr_cache->cinfo[0]->currency == currency &&
	wallet->curr_cache->cinfo[0]->keyversion == keyversion) {
	return EC_M_clone_curr(wallet->curr_cache);
    }

    /* Get a read lock on the wallet */
    err = EC_W_wallet_templock(wallet, EC_W_LOCK_READ, &oldlock);
    if (err) {
        return NULL;
    }

    /* Open the curr file */
    sprintf(bankext, "-%d", bankID);
    currfname = EC_W_wallet_mkfname(wallet->name, EC_W_CURRFNAME, bankext);
    if (!currfname) {
	EC_W_wallet_lock(wallet, oldlock);
	return NULL;
    }

    currfd = open(currfname, O_RDONLY);
    EC_G_free(currfname);
    if (currfd < 0) {
	EC_W_wallet_lock(wallet, oldlock);
	return NULL;
    }

    /* Read currencies from the file */
    currmsg = EC_M_new_msg();
    if (!currmsg) {
	close(currfd);
	EC_W_wallet_lock(wallet, oldlock);
	return NULL;
    }
    while (!EC_M_BTE_decode(currmsg, EC_G_read_in, &currfd)) {
	err = EC_M_decompile_curr(&curr, currmsg);
	if (err) continue;
	if (curr->numcurrs == 1 &&
	    curr->cinfo[0]->currency == currency &&
	    (curr->cinfo[0]->keyversion == keyversion ||
	      (!keyversion &&
	        (!match ||
	          match->cinfo[0]->keyversion
	            <= curr->cinfo[0]->keyversion)))) {
	    EC_M_free_curr(match);
	    match = curr;
	} else {
	    EC_M_free_curr(curr);
	}
	EC_M_clear_msg(currmsg);
    }
    EC_M_free_msg(currmsg);
    close(currfd);
    EC_W_wallet_lock(wallet, oldlock);

    /* Update the cache if we found a match */
    if (match) {
	EC_M_free_curr(wallet->curr_cache);
	wallet->curr_cache = EC_M_clone_curr(match);
    }
    return match;
}

/* Write a currency record containing exactly 1 currency to the
   curr file of a wallet */
static EC_Errno EC_W_curr1_write(EC_W_Wallet wallet, UInt32 bankID,
    EC_M_Curr curr)
{
    char *currfname;
    int currfd;
    EC_M_Msg currmsg;
    EC_Errno err;
    EC_M_Curr oldcurr;
    EC_W_Locktype oldlock;
    char bankext[40];   /* Big enough for a UInt32 */

    if (!wallet || !curr || curr->numcurrs != 1) return EC_ERR_INTERNAL;

    /* See if the record is already in the file */
    oldcurr = EC_W_curr_lookup(wallet, bankID, curr->cinfo[0]->currency,
	curr->cinfo[0]->keyversion);
    if (oldcurr) {
	if (!EC_M_cmp_curr(oldcurr, curr)) {
	    /* Match! */
	    EC_M_free_curr(oldcurr);
	    return EC_ERR_NONE;
	}
	EC_M_free_curr(oldcurr);
    }

    /* Compile the curr record */
    currmsg = EC_M_new_msg();
    if (!currmsg) {
	return EC_ERR_INTERNAL;
    }
    err = EC_M_compile_curr(curr, currmsg);
    if (err) {
	EC_M_free_msg(currmsg);
	return EC_ERR_INTERNAL;
    }

    /* Get a write lock on the wallet */
    err = EC_W_wallet_templock(wallet, EC_W_LOCK_WRITE, &oldlock);
    if (err) {
        EC_M_free_msg(currmsg);
        return EC_ERR_INTERNAL;
    }

    /* Open the curr file */
    sprintf(bankext, "-%d", bankID);
    currfname = EC_W_wallet_mkfname(wallet->name, EC_W_CURRFNAME, bankext);
    if (!currfname) {
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_msg(currmsg);
	return EC_ERR_INTERNAL;
    }

    currfd = open(currfname, O_CREAT|O_APPEND|O_WRONLY, S_IRUSR|S_IWUSR);
    EC_G_free(currfname);
    if (currfd < 0) {
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_msg(currmsg);
	return EC_ERR_INTERNAL;
    }

    /* Write the record */
    err = EC_M_BTE_encode(currmsg, EC_G_write_out, &currfd);
    EC_M_free_msg(currmsg);
    close(currfd);
    EC_W_wallet_lock(wallet, oldlock);
    if (err) {
	return EC_ERR_INTERNAL;
    }

    /* All OK; update the cache */
    EC_M_free_curr(wallet->curr_cache);
    wallet->curr_cache = EC_M_clone_curr(curr);

    return EC_ERR_NONE;
}

/* Write a currency record to the curr file of a wallet */
EC_Errno EC_W_curr_write(EC_W_Wallet wallet, UInt32 bankID, EC_M_Curr curr)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Curr subcurr;
    EC_M_Cinfo *cinfo;
    EC_M_Onl_curr *onl_curr;
    UInt32 i;

    if (!wallet || !curr) return EC_ERR_INTERNAL;

    /* Construct a new CURR structure for each currency in curr */
    for(i=0;i<curr->numcurrs;++i) {
	cinfo = (EC_M_Cinfo *)EC_G_malloc(sizeof(EC_M_Cinfo));
	onl_curr = (EC_M_Onl_curr *)EC_G_malloc(sizeof(EC_M_Onl_curr));
	if (!cinfo || !onl_curr) {
	    if (cinfo) EC_G_free(cinfo);
	    if (onl_curr) EC_G_free(onl_curr);
	    err = EC_ERR_INTERNAL;
	    continue;
	}
	cinfo[0] = EC_M_clone_cinfo(curr->cinfo[i]);
	onl_curr[0] = EC_M_clone_onl_curr(curr->onl_curr[i]);
	if (!cinfo[0] || !onl_curr[0]) {
	    EC_M_free_cinfo(cinfo[0]);
	    EC_M_free_onl_curr(onl_curr[0]);
	    EC_G_free(cinfo);
	    EC_G_free(onl_curr);
	    err = EC_ERR_INTERNAL;
	    continue;
	}
	subcurr = EC_M_new_curr(1, cinfo, onl_curr);
	if (!subcurr) {
	    EC_M_free_cinfo(cinfo[0]);
	    EC_M_free_onl_curr(onl_curr[0]);
	    EC_G_free(cinfo);
	    EC_G_free(onl_curr);
	    err = EC_ERR_INTERNAL;
	    continue;
	}
	if (EC_W_curr1_write(wallet, bankID, subcurr)) {
	    err = EC_ERR_INTERNAL;
	}
	EC_M_free_curr(subcurr);
    }

    return err;
}
