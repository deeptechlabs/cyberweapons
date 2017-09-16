#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>
#include "lucre.h"

/* Insert a generated Payment into the payments database.  If successful,
    sets seqno to the seqno that was assigned to it, and frees the payment. */
EC_Errno EC_W_paydb_put(EC_W_Wallet wallet, EC_M_Payment payment,
    UInt32 *pseqno)
{
    EC_Errno err = EC_ERR_NONE;
    EC_W_Locktype oldlock;
    Int32 res;
    UInt32 seqno;
    EC_W_Db paydb;
    EC_M_Msg keymsg, datamsg;

    static EC_M_Msg seqnomsg = NULL;

    if (!wallet || !payment) return EC_ERR_INTERNAL;

    /* Get a temporary write lock on the wallet */
    err = EC_W_wallet_templock(wallet, EC_W_LOCK_WRITE, &oldlock);
    if (err) {
	return EC_ERR_INTERNAL;
    }

    /* Open the database */
    paydb = EC_W_db_open(wallet, EC_W_PAYDBFNAME, O_RDWR);
    if (!paydb) {
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Make the key to look up the sequence number, if it's not yet been
	made. */
    if (!seqnomsg) {
	seqnomsg = EC_M_new_msg();
	if (!seqnomsg) {
	    EC_W_db_close(paydb);
	    EC_W_wallet_lock(wallet, oldlock);
	    return EC_ERR_INTERNAL;
	}
	/* The key string is the compiled version of "seqno" */
	err = EC_M_compile_string("seqno", seqnomsg);
	if (err) {
	    EC_M_free_msg(seqnomsg);
	    EC_W_db_close(paydb);
	    EC_W_wallet_lock(wallet, oldlock);
	    return EC_ERR_INTERNAL;
	}
    }

    /* Look up the current sequence number */
    res = EC_W_db_get(paydb, seqnomsg, &datamsg);
    if (res < 0) {
	EC_W_db_close(paydb);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }
    if (res) {
	/* Not found; create a new one */
	datamsg = EC_M_new_msg();
	if (!datamsg) {
	    EC_W_db_close(paydb);
	    EC_W_wallet_lock(wallet, oldlock);
	    return EC_ERR_INTERNAL;
	}
	err = EC_M_compile_int(1, datamsg);
	if (err) {
	    EC_M_free_msg(datamsg);
	    EC_W_db_close(paydb);
	    EC_W_wallet_lock(wallet, oldlock);
	    return EC_ERR_INTERNAL;
	}
    }
    /* Get a keymsg ready for later */
    keymsg = EC_M_new_msg();
    if (!keymsg) {
	EC_M_free_msg(datamsg);
	EC_W_db_close(paydb);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* The next sequence number should be the first thing in datamsg */
    err = EC_M_decompile_int(&seqno, datamsg);
    if (err) {
	EC_M_free_msg(keymsg);
	EC_M_free_msg(datamsg);
	EC_W_db_close(paydb);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }
    /* Increment the seqno and store it back */
    datamsg->begin = 0;
    datamsg->end = 0;
    err = EC_M_compile_int(seqno+1, datamsg);
    if (err) {
	EC_M_free_msg(keymsg);
	EC_M_free_msg(datamsg);
	EC_W_db_close(paydb);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }
    res = EC_W_db_put(paydb, seqnomsg, datamsg);
    if (res) {
	EC_M_free_msg(keymsg);
	EC_M_free_msg(datamsg);
	EC_W_db_close(paydb);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Get the key ready */
    err = EC_M_compile_int(seqno, keymsg);
    if (err) {
	EC_M_free_msg(keymsg);
	EC_M_free_msg(datamsg);
	EC_W_db_close(paydb);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Load some fields of the payment */
    payment->payment_hdr->seqno = seqno;

    /* Compile the payment */
    EC_M_clear_msg(datamsg);
    err = EC_M_compile_payment(payment, datamsg);
    if (err) {
	EC_M_free_msg(keymsg);
	EC_M_free_msg(datamsg);
	EC_W_db_close(paydb);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Insert it into the database */
    res = EC_W_db_put(paydb, keymsg, datamsg);
    EC_M_free_msg(keymsg);
    EC_M_free_msg(datamsg);
    EC_W_db_close(paydb);
    EC_W_wallet_lock(wallet, oldlock);
    if (res) {
	return EC_ERR_INTERNAL;
    }

    /* Make a note of the key we used */
    if (pseqno) *pseqno = seqno;
    EC_M_free_payment(payment);

    return EC_ERR_NONE;
}

EC_M_Payment EC_W_paydb_get(EC_W_Wallet wallet, UInt32 seqno)
{
    EC_Errno err = EC_ERR_NONE;
    EC_W_Locktype oldlock;
    Int32 res;
    EC_W_Db paydb;
    EC_M_Payment payment;
    EC_M_Msg keymsg, datamsg;

    if (!wallet || !seqno) return NULL;

    /* Create the key */
    keymsg = EC_M_new_msg();
    if (!keymsg) {
	return NULL;
    }
    err = EC_M_compile_int(seqno, keymsg);
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
    paydb = EC_W_db_open(wallet, EC_W_PAYDBFNAME, O_RDONLY);
    if (!paydb) {
	EC_M_free_msg(keymsg);
	EC_W_wallet_lock(wallet, oldlock);
	return NULL;
    }

    /* Retrieve the data */
    res = EC_W_db_get(paydb, keymsg, &datamsg);
    EC_M_free_msg(keymsg);
    EC_W_db_close(paydb);
    EC_W_wallet_lock(wallet, oldlock);
    if (res) {
	return NULL;
    }

    /* Decompile the datamsg */
    err = EC_M_decompile_payment(&payment, datamsg);
    EC_M_free_msg(datamsg);

    return payment;
}

/* Delete the given payment from the payments db */
EC_Errno EC_W_paydb_del(EC_W_Wallet wallet, UInt32 seqno)
{
    EC_Errno err = EC_ERR_NONE;
    EC_W_Locktype oldlock;
    EC_W_Db paydb;
    EC_M_Msg keymsg;

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
    paydb = EC_W_db_open(wallet, EC_W_PAYDBFNAME, O_RDWR);
    if (!paydb) {
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_msg(keymsg);
	return EC_ERR_INTERNAL;
    }

    /* Create a key and delete the db entry */
    err = EC_M_compile_int(seqno, keymsg);
    if (err) {
	EC_W_db_close(paydb);
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_msg(keymsg);
	return EC_ERR_INTERNAL;
    }

    /* Delete the data */
    EC_W_db_del(paydb, keymsg);

    /* Free up */
    EC_M_free_msg(keymsg);
    EC_W_db_close(paydb);
    EC_W_wallet_lock(wallet, oldlock);

    return EC_ERR_NONE;
}

/* Get all of the entries in the received payments db */
EC_Errno EC_W_paydb_get_all(EC_W_Wallet wallet, EC_M_Payment **ppayment,
    UInt32 *pnumpayments)
{
    EC_Errno err = EC_ERR_NONE;
    EC_W_Locktype oldlock;
    Int32 res;
    EC_W_Db paydb;
    EC_M_Payment *payment;
    UInt32 numpayments;
    EC_M_Msg datamsg;
    int i;

    if (!wallet || !ppayment || !pnumpayments) return EC_ERR_INTERNAL;

    /* Get a temporary read lock on the wallet */
    err = EC_W_wallet_templock(wallet, EC_W_LOCK_READ, &oldlock);
    if (err) {
	return EC_ERR_INTERNAL;
    }

    /* Open the database */
    paydb = EC_W_db_open(wallet, EC_W_PAYDBFNAME, O_RDONLY);
    if (!paydb) {
	EC_W_wallet_lock(wallet, oldlock);
	*ppayment = NULL;
	*pnumpayments = 0;
	return EC_ERR_NONE;
    }

    payment = NULL;
    numpayments = 0;

    /* Retrieve the data */
    while(!(res = EC_W_db_seq(paydb, NULL, &datamsg))) {
	EC_M_Fieldtype fieldtype;
	EC_M_Rectype rectype;
	EC_M_Payment *newpayment;

	/* Check that this is, in fact, a payment message */
	err = EC_M_examine_msg(&fieldtype, &rectype, datamsg);
	if (err) break;
	if (fieldtype != EC_M_FIELD_SOR || rectype != EC_M_REC_PAYMENT)
	    continue;

	/* Allocate a new space */
	newpayment = EC_G_realloc(payment,
	    sizeof(EC_M_Payment)*(numpayments+1));
	if (!newpayment) {
	    EC_M_free_msg(datamsg);
	    err = EC_ERR_INTERNAL;
	    break;
	}
	payment = newpayment;
	payment[numpayments] = NULL;

	/* Get the new data */
	err = EC_M_decompile_payment(&payment[numpayments], datamsg);
	++numpayments;
	EC_M_free_msg(datamsg);
	if (err) break;
    }

    if (res < 0) err = EC_ERR_INTERNAL;

    if (err) {
	/* Clean up */
	for (i=0;i<numpayments;++i) EC_M_free_payment(payment[i]);
	if (payment) EC_G_free(payment);
    }

    EC_W_db_close(paydb);
    EC_W_wallet_lock(wallet, oldlock);

    if (err) return err;

    /* Store the results */
    *ppayment = payment;
    *pnumpayments = numpayments;

    return EC_ERR_NONE;
}
