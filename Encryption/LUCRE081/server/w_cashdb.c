#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include "lucre.h"

/* Determine the name of the cashdb */
char *EC_W_cashdb_mkfname(EC_W_Wallet wallet, UInt32 bankID,
    EC_M_Currency currency, UInt32 keyversion)
{
    char ext[100];   /* Big enough for the %d's to expand */

    sprintf(ext, "-%d-%d.db", bankID, currency);
    return EC_W_wallet_mkfname("", EC_W_CASHDBFNAME, ext);
}

EC_M_Coindata EC_W_cashdb_gencoin(UInt32 bankID, EC_M_Onl_curr onl_curr,
    UInt32 keyversion, UInt32 seqno)
{
    EC_M_Coindata coin;
    EC_Errno err;
    UInt32 res;
    UInt32 currversion, denom;
    BIGNUM *n = NULL;
    BIGNUM *fn = NULL;
    BIGNUM *r = NULL;
    BIGNUM *fnrh = NULL;
    BIGNUM *fn1hr = NULL;
    BIGNUM *fn1h = NULL;

    /* Make sure we have the right values */
    currversion = keyversion & ~EC_M_KEYVER_VALMASK;
    denom = keyversion & EC_M_KEYVER_VALMASK;

    if (!onl_curr || !onl_curr->coin_n || onl_curr->ndenom <= denom
	|| !onl_curr->coin_e[denom]) return NULL;

    n = BN_new();
    r = BN_new();
    fnrh = BN_new();
    fn1hr = BN_new();
    fn1h = BN_new();

    if (!n || !r || !fnrh || !fn1hr || !fn1h) {
	EC_M_free_MPI(n);
	EC_M_free_MPI(r);
	EC_M_free_MPI(fnrh);
	EC_M_free_MPI(fn1hr);
	EC_M_free_MPI(fn1h);
	return NULL;
    }
    /* Pick n.  You can do this randomly, or, if your bank has a
       recovery scheme, you should adhere to it.  However, doing so
       probably requires you to license Dr. Chaum's blinding patent. */
    res = 1;
    if (res) res = BN_rand(n, BN_num_bits(onl_curr->coin_n), 0, 0);

    /* Set default values for the other fields */
    if (res) res = BN_one(r);
    if (res) res = BN_zero(fn1hr);
    if (res) res = BN_zero(fn1h);

    /* Calculate f(n) */
    if (res) {
	EC_M_Msg nmsg = EC_M_new_msg();
	if (nmsg) {
	    err = EC_M_compile_MPI(n, nmsg);
	    if (!err) fn = EC_U_f(2, nmsg->data+nmsg->begin,
				    nmsg->end-nmsg->begin, onl_curr->coin_n);
	    EC_M_free_msg(nmsg);
	}
	if (!fn) res = 0;
    }

    /* Set the value to send to the bank (which is the key for the database) */
    if (res) res = (BN_copy(fnrh, fn) != NULL);

    if (!res) {
	EC_M_free_MPI(n);
	EC_M_free_MPI(fn);
	EC_M_free_MPI(r);
	EC_M_free_MPI(fnrh);
	EC_M_free_MPI(fn1hr);
	EC_M_free_MPI(fn1h);
	return NULL;
    }

    coin = EC_M_new_coindata(seqno, keyversion, n, fn, r, fnrh,
				fn1hr, fn1h, 0);
    if (!coin) {
	EC_M_free_MPI(n);
	EC_M_free_MPI(fn);
	EC_M_free_MPI(r);
	EC_M_free_MPI(fnrh);
	EC_M_free_MPI(fn1hr);
	EC_M_free_MPI(fn1h);
	return NULL;
    }

    return coin;
}

/* Create an unsigned coin with of the given value, and insert it into
   the cash db.  Set pfnrh to point to its index (an MPI representing
   f(n)*r^h) and pseqno to point to its sequence number. */
EC_Errno EC_W_cashdb_newcoin(EC_W_Wallet wallet, UInt32 bankID,
    EC_M_Curr curr, UInt32 keyversion, BIGNUM **pfnrh, UInt32 *pseqno)
{
    EC_Errno err = EC_ERR_NONE;
    EC_W_Locktype oldlock;
    Int32 res;
    UInt32 seqno;
    EC_W_Db cashdb;
    char *cashdbname = NULL;
    EC_M_Coindata coin;
    EC_M_Msg keymsg, datamsg;
    BIGNUM *fnrh;

    static EC_M_Msg seqnomsg = NULL;

    if (!wallet || !curr) return EC_ERR_INTERNAL;

    /* Get a temporary write lock on the wallet */
    err = EC_W_wallet_templock(wallet, EC_W_LOCK_WRITE, &oldlock);
    if (err) {
	return EC_ERR_INTERNAL;
    }

    /* Make sure keyversion is set right */
    keyversion = (curr->cinfo[0]->keyversion & ~EC_M_KEYVER_VALMASK)
               | (keyversion & EC_M_KEYVER_VALMASK);

    /* Make the cash db name */
    cashdbname = EC_W_cashdb_mkfname(wallet, bankID,
	curr->cinfo[0]->currency, curr->cinfo[0]->keyversion);
    if (!cashdbname) {
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Open the database */
    cashdb = EC_W_db_open(wallet, cashdbname, O_RDWR);
    EC_G_free(cashdbname);
    if (!cashdb) {
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Make the key to look up the sequence number, if it's not yet been
	made. */
    if (!seqnomsg) {
	seqnomsg = EC_M_new_msg();
	if (!seqnomsg) {
	    EC_W_db_close(cashdb);
	    EC_W_wallet_lock(wallet, oldlock);
	    return EC_ERR_INTERNAL;
	}
	/* The key string is the compiled version of "seqno" */
	err = EC_M_compile_string("seqno", seqnomsg);
	if (err) {
	    EC_M_free_msg(seqnomsg);
	    EC_W_db_close(cashdb);
	    EC_W_wallet_lock(wallet, oldlock);
	    return EC_ERR_INTERNAL;
	}
    }

    /* Look up the current sequence number */
    res = EC_W_db_get(cashdb, seqnomsg, &datamsg);
    if (res < 0) {
	EC_W_db_close(cashdb);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }
    if (res) {
	/* Not found; create a new one */
	datamsg = EC_M_new_msg();
	if (!datamsg) {
	    EC_W_db_close(cashdb);
	    EC_W_wallet_lock(wallet, oldlock);
	    return EC_ERR_INTERNAL;
	}
	err = EC_M_compile_int(1, datamsg);
	if (err) {
	    EC_M_free_msg(datamsg);
	    EC_W_db_close(cashdb);
	    EC_W_wallet_lock(wallet, oldlock);
	    return EC_ERR_INTERNAL;
	}
    }

    /* The next sequence number should be the first thing in datamsg */
    err = EC_M_decompile_int(&seqno, datamsg);
    if (err) {
	EC_M_free_msg(datamsg);
	EC_W_db_close(cashdb);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }
    /* Increment the seqno and store it back */
    datamsg->begin = 0;
    datamsg->end = 0;
    err = EC_M_compile_int(seqno+1, datamsg);
    if (err) {
	EC_M_free_msg(datamsg);
	EC_W_db_close(cashdb);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }
    res = EC_W_db_put(cashdb, seqnomsg, datamsg);
    if (res) {
	EC_M_free_msg(datamsg);
	EC_W_db_close(cashdb);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Create a new coin */
    coin = EC_W_cashdb_gencoin(bankID, curr->onl_curr[0], keyversion, seqno);
    if (!coin) {
	EC_M_free_msg(datamsg);
	EC_W_db_close(cashdb);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Create a keymsg; the key is the fnrh value of the coin */
    keymsg = EC_M_new_msg();
    if (!keymsg) {
	EC_M_free_coindata(coin);
	EC_M_free_msg(datamsg);
	EC_W_db_close(cashdb);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    err = EC_M_compile_MPI(coin->fnrh, keymsg);
    if (err) {
	EC_M_free_msg(keymsg);
	EC_M_free_coindata(coin);
	EC_M_free_msg(datamsg);
	EC_W_db_close(cashdb);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Compile the coin */
    EC_M_clear_msg(datamsg);
    err = EC_M_compile_coindata(coin, datamsg);
    if (err) {
	EC_M_free_msg(keymsg);
	EC_M_free_coindata(coin);
	EC_M_free_msg(datamsg);
	EC_W_db_close(cashdb);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Make a copy of the key to pass back */
    fnrh = EC_M_clone_MPI(coin->fnrh);
    EC_M_free_coindata(coin);
    if (pfnrh && !fnrh) {
	EC_M_free_msg(keymsg);
	EC_M_free_msg(datamsg);
	EC_W_db_close(cashdb);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Insert the coin into the database */
    res = EC_W_db_put(cashdb, keymsg, datamsg);
    EC_M_free_msg(keymsg);
    EC_M_free_msg(datamsg);
    EC_W_db_close(cashdb);
    EC_W_wallet_lock(wallet, oldlock);
    if (res) {
	return EC_ERR_INTERNAL;
    }

    /* Make a note of the key we used */
    if (pfnrh) *pfnrh = fnrh; else EC_M_free_MPI(fnrh);
    if (pseqno) *pseqno = seqno;

    return EC_ERR_NONE;
}

/* Put the responses in wdfin into the database.  Set *pamt to the total
   value of the coins successfully stored from this wdfin. */
EC_Errno EC_W_cashdb_finish(EC_W_Wallet wallet, UInt32 bankID,
    EC_M_Currency currency, EC_M_Wdfin wdfin, UInt32 *pamt)
{
    EC_Errno err = EC_ERR_NONE;
    EC_W_Locktype oldlock;
    EC_M_Curr curr;
    Int32 res;
    UInt32 denom, value, totamt;
    EC_W_Db cashdb;
    char *cashdbname = NULL;
    EC_M_Coindata coin;
    EC_M_Msg keymsg, datamsg;
    BIGNUM *fnrh;
    BN_CTX *ctx;
    EC_M_Status status;
    int i;

    if (!wallet || !wdfin) return EC_ERR_INTERNAL;

    /* Retrive the curr record appropriate to this keyversion */
    curr = EC_W_curr_lookup(wallet, bankID, currency, wdfin->keyversion);
    if (!curr) return EC_ERR_INTERNAL;

    /* Get a temporary write lock on the wallet */
    err = EC_W_wallet_templock(wallet, EC_W_LOCK_WRITE, &oldlock);
    if (err) {
	EC_M_free_curr(curr);
	return EC_ERR_INTERNAL;
    }

    /* Make the cash db name */
    cashdbname = EC_W_cashdb_mkfname(wallet, bankID,
	curr->cinfo[0]->currency, curr->cinfo[0]->keyversion);
    if (!cashdbname) {
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_curr(curr);
	return EC_ERR_INTERNAL;
    }

    /* Open the database */
    cashdb = EC_W_db_open(wallet, cashdbname, O_RDWR);
    EC_G_free(cashdbname);
    if (!cashdb) {
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_curr(curr);
	return EC_ERR_INTERNAL;
    }

    ctx = BN_CTX_new();
    if (!ctx) {
	EC_W_db_close(cashdb);
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_curr(curr);
	return EC_ERR_INTERNAL;
    }
    fnrh = BN_new();
    if (!fnrh) {
	BN_CTX_free(ctx);
	EC_W_db_close(cashdb);
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_curr(curr);
	return EC_ERR_INTERNAL;
    }

    denom = wdfin->keyversion & EC_M_KEYVER_VALMASK;
    value = (1 << denom) * curr->cinfo[0]->base_val;
    totamt = 0;

    /* For each signature in the wdfin, */
    for(i=0;i<wdfin->ncoins;++i) {
	/* Did we get a signature? */
	if (BN_is_zero(wdfin->R[i])) continue;

	/* Check what was signed */
	res = BN_mod_exp(fnrh, wdfin->R[i], curr->onl_curr[0]->coin_e[denom],
				curr->onl_curr[0]->coin_n, ctx);
	if (!res) continue;

	/* Create a keymsg; the key is the fnrh value */
	keymsg = EC_M_new_msg();
	if (!keymsg) continue;

	err = EC_M_compile_MPI(fnrh, keymsg);
	if (err) {
	    EC_M_free_msg(keymsg);
	    continue;
	}

	/* Look it up in the database */
	res = EC_W_db_get(cashdb, keymsg, &datamsg);
	if (res) {
	    EC_M_free_msg(keymsg);
	    continue;
	}

	/* Decompile the datamsg */
	err = EC_M_decompile_coindata(&coin, datamsg);
	if (err) {
	    EC_M_free_msg(datamsg);
	    EC_M_free_msg(keymsg);
	    continue;
	}

	/* Put the signature in the coin record */
	if (!BN_copy(coin->fn1hr, wdfin->R[i])) {
	    EC_M_free_coindata(coin);
	    EC_M_free_msg(datamsg);
	    EC_M_free_msg(keymsg);
	    continue;
	}

	/* Fill out the rest of the fields */
	if (!BN_copy(coin->fn1h, coin->fn1hr)) {
	    EC_M_free_coindata(coin);
	    EC_M_free_msg(datamsg);
	    EC_M_free_msg(keymsg);
	    continue;
	}

	/* Compile it back */
	EC_M_clear_msg(datamsg);
	err = EC_M_compile_coindata(coin, datamsg);
	EC_M_free_coindata(coin);
	if (err) {
	    EC_M_free_msg(datamsg);
	    EC_M_free_msg(keymsg);
	    continue;
	}
	res = EC_W_db_put(cashdb, keymsg, datamsg);
	EC_M_free_msg(datamsg);
	EC_M_free_msg(keymsg);
	if (res) {
	    continue;
	}

	/* Just in case */
	EC_W_db_sync(cashdb);
	
	/* At this point, the coin should be successfully stored. */
	totamt += value;
    }

    if (pamt) *pamt = totamt;

    /* That was fun.  Close up. */
    EC_M_free_MPI(fnrh);
    BN_CTX_free(ctx);
    EC_W_db_close(cashdb);
    EC_M_free_curr(curr);

    /* Update our amount of cash-on-hand if this is the default bank and
       currency */
    if (bankID == wallet->userrec->bankID
     && currency == wallet->userrec->currency) {
	status = EC_W_status_read(wallet);
	if (status) {
	    status->cash += totamt;
	    EC_W_status_write(wallet, status);
	    EC_M_free_status(status);
	}
    }

    EC_W_wallet_lock(wallet, oldlock);

    return EC_ERR_NONE;
}

/* For each coin in the wdfin (which was part of a WITHDRAW3 message),
   check to see if it's complete.  If not, remove it from the database. */
EC_Errno EC_W_cashdb_clean(EC_W_Wallet wallet, UInt32 bankID,
    EC_M_Currency currency, EC_M_Wdfin wdfin)
{
    EC_Errno err = EC_ERR_NONE;
    EC_W_Locktype oldlock;
    Int32 res;
    EC_W_Db cashdb;
    char *cashdbname = NULL;
    EC_M_Coindata coin;
    EC_M_Msg keymsg, datamsg;
    int i;

    if (!wallet || !wdfin) return EC_ERR_INTERNAL;

    /* Get a temporary write lock on the wallet */
    err = EC_W_wallet_templock(wallet, EC_W_LOCK_WRITE, &oldlock);
    if (err) {
	return EC_ERR_INTERNAL;
    }

    /* Make the cash db name */
    cashdbname = EC_W_cashdb_mkfname(wallet, bankID, currency,
	wdfin->keyversion);
    if (!cashdbname) {
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Open the database */
    cashdb = EC_W_db_open(wallet, cashdbname, O_RDWR);
    EC_G_free(cashdbname);
    if (!cashdb) {
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* For each signature in the wdfin, */
    for(i=0;i<wdfin->ncoins;++i) {
	/* Create a keymsg; the key is wdfin->R[i] */
	keymsg = EC_M_new_msg();
	if (!keymsg) continue;

	err = EC_M_compile_MPI(wdfin->R[i], keymsg);
	if (err) {
	    EC_M_free_msg(keymsg);
	    continue;
	}

	/* Look it up in the database */
	res = EC_W_db_get(cashdb, keymsg, &datamsg);
	if (res) {
	    EC_M_free_msg(keymsg);
	    continue;
	}

	/* Decompile the datamsg */
	err = EC_M_decompile_coindata(&coin, datamsg);
	if (err) {
	    EC_M_free_msg(datamsg);
	    EC_M_free_msg(keymsg);
	    continue;
	}

	/* Is it incomplete? */
	if (BN_is_zero(coin->fn1h)) {
	    /* Yup; delete it from the database */
	    EC_W_db_del(cashdb, keymsg);
	}
	EC_M_free_msg(datamsg);
	EC_M_free_msg(keymsg);
    }

    /* Close up. */
    EC_W_db_close(cashdb);
    EC_W_wallet_lock(wallet, oldlock);

    return EC_ERR_NONE;
}

#if 0
/* Retrieve a coindata from the cashdb, given its fnrh value */
EC_M_Coindata EC_W_cashdb_get(EC_W_Wallet wallet, BIGNUM *fnrh)
{
    EC_Errno err = EC_ERR_NONE;
    EC_W_Locktype oldlock;
    Int32 res;
    EC_W_Db cashdb;
    EC_M_Coindata coindata;
    EC_M_Msg keymsg, datamsg;

    if (!wallet || !seqno) return NULL;

    /* Create the key */
    keymsg = EC_M_new_msg();
    if (!keymsg) {
	return NULL;
    }
    err = EC_M_compile_MPI(fnrh, keymsg);
    if (err) {
	EC_M_free_msg(keymsg);
	return NULL;
    }

    /* Get a temporary read lock on the wallet */
    err = EC_W_wallet_templock(wallet, EC_W_LOCK_READ, &oldlock);
    if (err) {
	EC_M_free_msg(keymsg);
	return NULL;
    }

    /* Make the cash db name */
    cashdbname = EC_W_cashdb_mkfname(wallet, bankID,
	curr->cinfo[0]->currency, curr->cinfo[0]->keyversion);
    if (!cashdbname) {
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_curr(curr);
	return EC_ERR_INTERNAL;
    }

    /* Open the database */
    cashdb = EC_W_db_open(wallet, cashdbname, O_RDWR);
    EC_G_free(cashdbname);
    /* Open the database */
    cashdb = EC_W_db_open(wallet, EC_W_CASHDBFNAME, O_RDONLY);
    if (!cashdb) {
	EC_M_free_msg(keymsg);
	EC_W_wallet_lock(wallet, oldlock);
	return NULL;
    }

    /* Retrieve the data */
    res = EC_W_db_get(cashdb, keymsg, &datamsg);
    EC_M_free_msg(keymsg);
    EC_W_db_close(cashdb);
    EC_W_wallet_lock(wallet, oldlock);
    if (res) {
	return NULL;
    }

    /* Decompile the datamsg */
    err = EC_M_decompile_dep(&dep, datamsg);
    EC_M_free_msg(datamsg);

    return dep;
}
#endif

/* Delete the coins listed in a coindata chain from the cash db */
EC_Errno EC_W_cashdb_del(EC_W_Wallet wallet, UInt32 bankID,
    EC_M_Currency currency, EC_M_Coindata coindata)
{
    EC_Errno err = EC_ERR_NONE;
    EC_W_Locktype oldlock;
    EC_W_Db cashdb;
    char *cashdbname;
    EC_M_Msg keymsg;
    UInt32 butot;
    EC_M_Curr curr;
    EC_M_Status status;

    if (!wallet) return EC_ERR_INTERNAL;

    /* Create the key msg */
    keymsg = EC_M_new_msg();
    if (!keymsg) {
	return EC_ERR_INTERNAL;
    }

    /* Get a temporary write lock on the wallet */
    err = EC_W_wallet_templock(wallet, EC_W_LOCK_WRITE, &oldlock);
    if (err) {
	EC_M_free_msg(keymsg);
	return EC_ERR_INTERNAL;
    }

    /* Make the cash db name */
    cashdbname = EC_W_cashdb_mkfname(wallet, bankID, currency, 0);
    if (!cashdbname) {
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Open the database */
    cashdb = EC_W_db_open(wallet, cashdbname, O_RDWR);
    EC_G_free(cashdbname);
    if (!cashdb) {
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_msg(keymsg);
	return EC_ERR_INTERNAL;
    }

    /* For each coin in the chain, create a key and delete the db entry */
    butot = 0;
    while(coindata) {
	keymsg->begin = 0;
	keymsg->end = 0;
	err = EC_M_compile_MPI(coindata->fnrh, keymsg);
	if (err) {
	    EC_W_db_close(cashdb);
	    EC_W_wallet_lock(wallet, oldlock);
	    EC_M_free_msg(keymsg);
	    return EC_ERR_INTERNAL;
	}

	/* Delete the data */
	EC_W_db_del(cashdb, keymsg);

	butot += (1 << ( (coindata->keyversion) & EC_M_KEYVER_VALMASK ) );

	coindata = coindata->next;
    }

    /* Free up */
    EC_M_free_msg(keymsg);
    EC_W_db_close(cashdb);

    /* Update our amount of cash-on-hand if this is the default bank and
       currency */
    if (bankID == wallet->userrec->bankID
     && currency == wallet->userrec->currency) {

	/* Retrive the curr record appropriate to this keyversion */
	curr = EC_W_curr_lookup(wallet, bankID, currency, 0);
	if (curr) {
	    UInt32 totamt = butot * curr->cinfo[0]->base_val;
	    status = EC_W_status_read(wallet);
	    if (status) {
		if (status->cash >= totamt) status->cash -= totamt;
		else status->cash = 0;
		EC_W_status_write(wallet, status);
		EC_M_free_status(status);
	    }
	    EC_M_free_curr(curr);
	}
    }

    EC_W_wallet_lock(wallet, oldlock);

    return EC_ERR_NONE;
}

/* Add certain coins we have to a tally */
EC_Errno EC_W_cashdb_tally(EC_W_Wallet wallet, UInt32 bankID,
    EC_M_Currency currency, UInt32 keyversion, EC_W_Tallyflags tallyflags,
    EC_W_Tally tally)
{
    EC_Errno err = EC_ERR_NONE;
    EC_W_Locktype oldlock;
    char *cashdbname;
    Int32 res;
    EC_W_Db cashdb;
    EC_M_Msg datamsg;

    if (!wallet || !tally) return EC_ERR_INTERNAL;

    /* Get a temporary read lock on the wallet */
    err = EC_W_wallet_templock(wallet, EC_W_LOCK_READ, &oldlock);
    if (err) {
	return EC_ERR_INTERNAL;
    }

    if (!(tallyflags & EC_W_TALLY_ONEDENOM))
	keyversion &= ~EC_M_KEYVER_VALMASK;
	
    /* Make the cash db name */
    cashdbname = EC_W_cashdb_mkfname(wallet, bankID, currency, keyversion);
    if (!cashdbname) {
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }
    /* Open the database */
    cashdb = EC_W_db_open(wallet, cashdbname, O_RDONLY);
    EC_G_free(cashdbname);
    if (!cashdb) {
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_NONE;
    }

    /* Retrieve coins from the database */
    while(!(res = EC_W_db_seq(cashdb, NULL, &datamsg))) {
	EC_M_Fieldtype fieldtype;
	EC_M_Rectype rectype;
	EC_M_Coindata coindata;

	/* Check that this is, in fact, a coindata message */
	err = EC_M_examine_msg(&fieldtype, &rectype, datamsg);
	if (err) break;
	if (fieldtype != EC_M_FIELD_SOR || rectype != EC_M_REC_COINDATA)
	    continue;

	/* Get the new data */
	err = EC_M_decompile_coindata(&coindata, datamsg);
	EC_M_free_msg(datamsg);
	if (err) break;

	/* See if it's a coin we're interested in */
	if ((BN_is_zero(coindata->n) || BN_is_zero(coindata->fn1h))
	 && !(tallyflags & EC_W_TALLY_INCOMPLETE)) {
	    /* This coin is not yet complete and we're not interested */
	    EC_M_free_coindata(coindata);
	    continue;
	}
	if ((!BN_is_zero(coindata->n) && !BN_is_zero(coindata->fn1h))
	 && (tallyflags & EC_W_TALLY_INCOMPLETE)) {
	    /* This coin is complete and we're not interested */
	    EC_M_free_coindata(coindata);
	    continue;
	}
	if (coindata->paymentid && !(tallyflags & EC_W_TALLY_PAID)) {
	    /* This coin has been used and we're not interested */
	    EC_M_free_coindata(coindata);
	    continue;
	}
	if (!coindata->paymentid && (tallyflags & EC_W_TALLY_PAID)) {
	    /* This coin has not been used and we're not interested */
	    EC_M_free_coindata(coindata);
	    continue;
	}
	if (keyversion) {
	    /* Check the keyversion; the following mess zeros the low
	       5 bits of coindata->keyversion before comparing to keyversion,
	       but only if EC_W_TALLY_ONEDENOM is not asserted. */
	    if ((coindata->keyversion &
		~((tallyflags & EC_W_TALLY_ONEDENOM) ?
		    0 : EC_M_KEYVER_VALMASK)) != keyversion) {
		/* Wrong keyversion */
		EC_M_free_coindata(coindata);
		continue;
	    }
	}

	/* This coin's OK */
	err = EC_W_tally_inc_coin(tally, coindata->keyversion, 1, tallyflags,
	    coindata);
	EC_M_free_coindata(coindata);
	if (err) {
	    break;
	}
    }

    if (res < 0) err = EC_ERR_INTERNAL;

    EC_W_db_close(cashdb);
    EC_W_wallet_lock(wallet, oldlock);

    if (err) return err;

    return EC_ERR_NONE;
}
