#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>
#include "lucre.h"

/* The wd database stores compiled signed WITHDRAW3 messages to the bank,
   along with the original headers, and an encrypted version.  Messages
   are inserted into this db just after they are encrypted to the bank,
   and they are removed when a reply is received and processed.  Always
   check this database before creating a new withdraw message; if
   there's something here, you probably want to try to send that to the
   bank again. */

/* Insert a generated withdrawal message into the wd database, with the
    given sequence number.  If successful, it frees the given msg. */
EC_Errno EC_W_wddb_put(EC_W_Wallet wallet, EC_M_Msg wdmsg,
    time_t stamp)
{
    EC_Errno err = EC_ERR_NONE;
    EC_W_Locktype oldlock;
    Int32 res;
    EC_W_Db wddb;
    EC_M_Msg keymsg;

    if (!wallet || !wdmsg) return EC_ERR_INTERNAL;

    /* Get a temporary write lock on the wallet */
    err = EC_W_wallet_templock(wallet, EC_W_LOCK_WRITE, &oldlock);
    if (err) {
	return EC_ERR_INTERNAL;
    }

    /* Open the database */
    wddb = EC_W_db_open(wallet, EC_W_WDDBFNAME, O_RDWR);
    if (!wddb) {
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Create a key for the stamp */
    keymsg = EC_M_new_msg();
    if (!keymsg) {
	EC_W_db_close(wddb);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }
    err = EC_M_compile_time(stamp, keymsg);
    if (err) {
	EC_M_free_msg(keymsg);
	EC_W_db_close(wddb);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Insert the msg into the database */
    res = EC_W_db_put(wddb, keymsg, wdmsg);
    EC_M_free_msg(keymsg);
    EC_W_db_close(wddb);
    EC_W_wallet_lock(wallet, oldlock);
    if (res) {
	return EC_ERR_INTERNAL;
    }

    /* Free the inserted msg */
    EC_M_free_msg(wdmsg);

    return EC_ERR_NONE;
}

EC_M_Msg EC_W_wddb_get(EC_W_Wallet wallet, time_t stamp)
{
    EC_Errno err = EC_ERR_NONE;
    EC_W_Locktype oldlock;
    Int32 res;
    EC_W_Db wddb;
    EC_M_Msg keymsg, datamsg;

    if (!wallet) return NULL;

    /* Create the key */
    keymsg = EC_M_new_msg();
    if (!keymsg) {
	return NULL;
    }
    err = EC_M_compile_time(stamp, keymsg);
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

    /* Open the database */
    wddb = EC_W_db_open(wallet, EC_W_WDDBFNAME, O_RDONLY);
    if (!wddb) {
	EC_M_free_msg(keymsg);
	EC_W_wallet_lock(wallet, oldlock);
	return NULL;
    }

    /* Retrieve the data */
    res = EC_W_db_get(wddb, keymsg, &datamsg);
    EC_M_free_msg(keymsg);
    EC_W_db_close(wddb);
    EC_W_wallet_lock(wallet, oldlock);
    if (res) {
	return NULL;
    }

    /* Decompile the datamsg */
    return datamsg;
}

/* Delete the msg with the given seqno from the wd database.  Also,
   delete any partial coins in the cashdb that were queried with this
   msg. */
EC_Errno EC_W_wddb_del(EC_W_Wallet wallet, time_t stamp)
{
    EC_Errno err = EC_ERR_NONE;
    EC_W_Locktype oldlock;
    EC_W_Db wddb;
    EC_M_Msg keymsg;
    EC_M_Msg datamsg;
    Int32 res;

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

    /* Open the database */
    wddb = EC_W_db_open(wallet, EC_W_WDDBFNAME, O_RDWR);
    if (!wddb) {
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_msg(keymsg);
	return EC_ERR_INTERNAL;
    }

    err = EC_M_compile_time(stamp, keymsg);
    if (err) {
	EC_W_db_close(wddb);
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_msg(keymsg);
	return EC_ERR_INTERNAL;
    }

    /* Read the data */
    res = EC_W_db_get(wddb, keymsg, &datamsg);
    if (!res) {
	EC_M_Fieldtype fieldtype;
	EC_M_Rectype rectype;
	EC_M_Sigmsg sigmsg = NULL;
	EC_M_Withdraw3 withdraw3 = NULL;
	UInt32 i;

	/* Get the SIGMSG that was stored */
	while(!(err = EC_M_examine_msg(&fieldtype, &rectype, datamsg))) {
	    if (fieldtype == EC_M_FIELD_NONE) {
		break;
	    } else if (fieldtype == EC_M_FIELD_SOR
		    && rectype == EC_M_REC_SIGMSG) {
		/* Get the submsg out */
		err = EC_M_decompile_sigmsg(&sigmsg, datamsg);
		if (err) break;
	    } else {
		err = EC_M_transfer_field(datamsg, NULL);
		if (err) break;
	    }
	}
	EC_M_free_msg(datamsg);

	/* Now do the same with the submsg */
	if (!err && sigmsg) {
	    while(!(err = EC_M_examine_msg(&fieldtype, &rectype,
					    sigmsg->msg))) {
		if (fieldtype == EC_M_FIELD_NONE) {
		    break;
		} else if (fieldtype == EC_M_FIELD_SOR
			&& rectype == EC_M_REC_WITHDRAW3) {
		    /* Get the withdraw3 out */
		    err = EC_M_decompile_withdraw3(&withdraw3, sigmsg->msg);
		    if (err) break;
		} else {
		    err = EC_M_transfer_field(sigmsg->msg, NULL);
		    if (err) break;
		}
	    }
	    EC_M_free_sigmsg(sigmsg);
	}

	/* Now go through the WITHDRAW3 and delete any partial coins we
	    asked for that we still don't have an answer to */
	if (!err && withdraw3) {
	    for(i=0;i<withdraw3->numwds;++i) {
		err = EC_W_cashdb_clean(wallet, wallet->userrec->bankID,
			wallet->userrec->currency, withdraw3->wdfin[i]);
		if (err) break;
	    }
	    EC_M_free_withdraw3(withdraw3);
	}
    }

    /* Delete the data */
    EC_W_db_del(wddb, keymsg);

    /* Free up */
    EC_M_free_msg(keymsg);
    EC_W_db_close(wddb);
    EC_W_wallet_lock(wallet, oldlock);

    return err;
}

/* Get all of the sequence numbers in the wd database */
EC_Errno EC_W_wddb_get_all(EC_W_Wallet wallet, time_t **pstamp,
    UInt32 *pnumstamps)
{
    EC_Errno err = EC_ERR_NONE;
    EC_W_Locktype oldlock;
    Int32 res;
    EC_W_Db wddb;
    time_t *stamp;
    UInt32 numstamps;
    EC_M_Msg keymsg;

    if (!wallet || !pstamp || !pnumstamps) return EC_ERR_INTERNAL;

    /* Get a temporary read lock on the wallet */
    err = EC_W_wallet_templock(wallet, EC_W_LOCK_READ, &oldlock);
    if (err) {
	return EC_ERR_INTERNAL;
    }

    /* Open the database */
    wddb = EC_W_db_open(wallet, EC_W_WDDBFNAME, O_RDONLY);
    if (!wddb) {
	EC_W_wallet_lock(wallet, oldlock);
	*pstamp = NULL;
	*pnumstamps = 0;
	return EC_ERR_NONE;
    }

    stamp = NULL;
    numstamps = 0;

    /* Retrieve the data */
    while(!(res = EC_W_db_seq(wddb, &keymsg, NULL))) {
	EC_M_Fieldtype fieldtype;
	EC_M_Rectype rectype;
	time_t *newstamp;

	/* Check that this is, in fact, a timestamp */
	err = EC_M_examine_msg(&fieldtype, &rectype, keymsg);
	if (err) break;
	if (fieldtype != EC_M_FIELD_TIME)
	    continue;

	/* Allocate a new space */
	newstamp = EC_G_realloc(stamp, sizeof(time_t)*(numstamps+1));
	if (!newstamp) {
	    EC_M_free_msg(keymsg);
	    err = EC_ERR_INTERNAL;
	    break;
	}
	stamp = newstamp;
	stamp[numstamps] = 0;

	/* Get the new data */
	err = EC_M_decompile_time(&stamp[numstamps], keymsg);
	++numstamps;
	EC_M_free_msg(keymsg);
	if (err) break;
    }

    if (res < 0) err = EC_ERR_INTERNAL;

    if (err) {
	/* Clean up */
	if (stamp) EC_G_free(stamp);
    }

    EC_W_db_close(wddb);
    EC_W_wallet_lock(wallet, oldlock);

    if (err) return err;

    /* Store the results */
    *pstamp = stamp;
    *pnumstamps = numstamps;

    return EC_ERR_NONE;
}
