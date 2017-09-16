#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include "lucre.h"

/* Look up a bank_mkey in a wallet; keynumber = 0 means highest in database,
    or whatever's in the cache. */
EC_M_Bank_mkey EC_W_bankkeys_lookup(EC_W_Wallet wallet, UInt32 bankID,
    UInt32 keynumber)
{
    char *bkeyfname;
    int bkeyfd;
    EC_M_Msg bkeymsg;
    EC_M_Bank_mkey bkey = NULL;
    EC_M_Bank_mkey match = NULL;
    EC_Errno err;
    EC_W_Locktype oldlock;

    if (!wallet) return NULL;

    /* Check the cache first */
    if (wallet->bkey_cache && wallet->bkey_cache->bankID == bankID &&
	(!keynumber || wallet->bkey_cache->keynumber == keynumber)) {
	return EC_M_clone_bank_mkey(wallet->bkey_cache);
    }

    /* Get a read lock on the wallet */
    err = EC_W_wallet_templock(wallet, EC_W_LOCK_READ, &oldlock);
    if (err) {
	return NULL;
    }

    /* Open the bankkeys file */
    bkeyfname = EC_W_wallet_mkfname(wallet->name, EC_W_BKEYFNAME, "");
    if (!bkeyfname) {
	EC_W_wallet_lock(wallet, oldlock);
	return NULL;
    }

    bkeyfd = open(bkeyfname, O_RDONLY);
    EC_G_free(bkeyfname);
    if (bkeyfd < 0) {
	EC_W_wallet_lock(wallet, oldlock);
	return NULL;
    }

    /* Read bank_mkeys from the file */
    bkeymsg = EC_M_new_msg();
    if (!bkeymsg) {
	EC_W_wallet_lock(wallet, oldlock);
	close(bkeyfd);
	return NULL;
    }
    while (!EC_M_BTE_decode(bkeymsg, EC_G_read_in, &bkeyfd)) {
	err = EC_M_decompile_bank_mkey(&bkey, bkeymsg);
	if (err) continue;
	if (bkey->bankID == bankID && (bkey->keynumber == keynumber
	|| (!keynumber && (!match || match->keynumber <= bkey->keynumber)))) {
	    EC_M_free_bank_mkey(match);
	    match = bkey;
	} else {
	    EC_M_free_bank_mkey(bkey);
	}
	EC_M_clear_msg(bkeymsg);
    }
    EC_M_free_msg(bkeymsg);
    close(bkeyfd);
    EC_W_wallet_lock(wallet, oldlock);

    if (match) {
	EC_M_free_bank_mkey(wallet->bkey_cache);
	wallet->bkey_cache = EC_M_clone_bank_mkey(match);
    }
    return match;
}

/* Write a bank_mkey to the bankkeys file of a wallet */
EC_Errno EC_W_bankkeys_write(EC_W_Wallet wallet, EC_M_Bank_mkey bank_mkey)
{
    char *bkeyfname;
    int bkeyfd;
    EC_M_Msg bkeymsg;
    EC_Errno err;
    EC_M_Bank_mkey old_mkey;
    EC_W_Locktype oldlock;

    if (!wallet || !bank_mkey) return EC_ERR_INTERNAL;

    /* See if the record is already in the file */
    old_mkey = EC_W_bankkeys_lookup(wallet, bank_mkey->bankID,
	bank_mkey->keynumber);
    if (old_mkey) {
	if (!EC_M_cmp_bank_mkey(old_mkey, bank_mkey)) {
	    /* Match! */
	    EC_M_free_bank_mkey(old_mkey);
	    return EC_ERR_NONE;
	}
	EC_M_free_bank_mkey(old_mkey);
    }

    /* Compile the bank_mkey record */
    bkeymsg = EC_M_new_msg();
    if (!bkeymsg) {
	return EC_ERR_INTERNAL;
    }
    err = EC_M_compile_bank_mkey(bank_mkey, bkeymsg);
    if (err) {
	EC_M_free_msg(bkeymsg);
	return EC_ERR_INTERNAL;
    }

    /* Get a write lock on the wallet */
    err = EC_W_wallet_templock(wallet, EC_W_LOCK_WRITE, &oldlock);
    if (err) {
	EC_M_free_msg(bkeymsg);
	return EC_ERR_INTERNAL;
    }

    /* Open the bankkeys file */
    bkeyfname = EC_W_wallet_mkfname(wallet->name, EC_W_BKEYFNAME, "");
    if (!bkeyfname) {
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_msg(bkeymsg);
	return EC_ERR_INTERNAL;
    }

    bkeyfd = open(bkeyfname, O_CREAT|O_APPEND|O_WRONLY, S_IRUSR|S_IWUSR);
    EC_G_free(bkeyfname);
    if (bkeyfd < 0) {
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_msg(bkeymsg);
	return EC_ERR_INTERNAL;
    }

    /* Write the record */
    err = EC_M_BTE_encode(bkeymsg, EC_G_write_out, &bkeyfd);
    EC_M_free_msg(bkeymsg);
    close(bkeyfd);
    EC_W_wallet_lock(wallet, oldlock);
    if (err) {
	return EC_ERR_INTERNAL;
    }

    /* All OK; update the cache */
    EC_M_free_bank_mkey(wallet->bkey_cache);
    wallet->bkey_cache = EC_M_clone_bank_mkey(bank_mkey);

    return EC_ERR_NONE;
}

/* A helpful wrapper */
EC_M_Bank_mkey EC_W_find_mkey(UInt32 bankID, UInt32 keynumber, void *state)
{
    EC_W_Wallet wallet = state ? *(EC_W_Wallet *)state : NULL;

    return EC_W_bankkeys_lookup(wallet, bankID, keynumber);
}
