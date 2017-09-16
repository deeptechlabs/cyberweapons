#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>
#include "lucre.h"

/* Insert a received Payment into the recevied payments database.  If
    successful, sets seqno to the seqno that was assigned to it, and frees
    the payment */
EC_Errno EC_W_recdb_put(EC_W_Wallet wallet, EC_M_Payment payment,
    UInt32 *pseqno)
{
    EC_Errno err = EC_ERR_NONE;
    EC_W_Locktype oldlock;
    Int32 res;
    UInt32 seqno;
    EC_W_Db recdb;
    EC_M_Payment_hdr phdr;
    EC_M_Pcoins pcoins;
    EC_M_Dep dep;
    EC_M_Msg keymsg, datamsg;

    static EC_M_Msg seqnomsg = NULL;

    if (!wallet || !payment) return EC_ERR_INTERNAL;

    /* Extract pieces from the payment */
    err = EC_M_examine_payment(payment, &phdr, &pcoins);
    if (err) {
	return EC_ERR_INTERNAL;
    }

    /* Construct a dep message */
    dep = EC_M_new_dep(0, phdr, pcoins);
    if (!dep) {
	return EC_ERR_INTERNAL;
    }

    /* Get a temporary write lock on the wallet */
    err = EC_W_wallet_templock(wallet, EC_W_LOCK_WRITE, &oldlock);
    if (err) {
	EC_M_free_dep(dep);
	return EC_ERR_INTERNAL;
    }

    /* Open the database */
    recdb = EC_W_db_open(wallet, EC_W_RECDBFNAME, O_RDWR);
    if (!recdb) {
	EC_M_free_dep(dep);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Make the key to look up the sequence number, if it's not yet been
	made. */
    if (!seqnomsg) {
	seqnomsg = EC_M_new_msg();
	if (!seqnomsg) {
	    EC_M_free_dep(dep);
	    EC_W_db_close(recdb);
	    EC_W_wallet_lock(wallet, oldlock);
	    return EC_ERR_INTERNAL;
	}
	/* The key string is the compiled version of "seqno" */
	err = EC_M_compile_string("seqno", seqnomsg);
	if (err) {
	    EC_M_free_dep(dep);
	    EC_M_free_msg(seqnomsg);
	    EC_W_db_close(recdb);
	    EC_W_wallet_lock(wallet, oldlock);
	    return EC_ERR_INTERNAL;
	}
    }

    /* Look up the current sequence number */
    res = EC_W_db_get(recdb, seqnomsg, &datamsg);
    if (res < 0) {
	EC_M_free_dep(dep);
	EC_W_db_close(recdb);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }
    if (res) {
	/* Not found; create a new one */
	datamsg = EC_M_new_msg();
	if (!datamsg) {
	    EC_M_free_dep(dep);
	    EC_W_db_close(recdb);
	    EC_W_wallet_lock(wallet, oldlock);
	    return EC_ERR_INTERNAL;
	}
	err = EC_M_compile_int(1, datamsg);
	if (err) {
	    EC_M_free_dep(dep);
	    EC_M_free_msg(datamsg);
	    EC_W_db_close(recdb);
	    EC_W_wallet_lock(wallet, oldlock);
	    return EC_ERR_INTERNAL;
	}
    }
    /* Get a keymsg ready for later */
    keymsg = EC_M_new_msg();
    if (!keymsg) {
	EC_M_free_dep(dep);
	EC_M_free_msg(datamsg);
	EC_W_db_close(recdb);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* The next sequence number should be the first thing in datamsg */
    err = EC_M_decompile_int(&seqno, datamsg);
    if (err) {
	EC_M_free_dep(dep);
	EC_M_free_msg(keymsg);
	EC_M_free_msg(datamsg);
	EC_W_db_close(recdb);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }
    /* Increment the seqno and store it back */
    datamsg->begin = 0;
    datamsg->end = 0;
    err = EC_M_compile_int(seqno+1, datamsg);
    if (err) {
	EC_M_free_dep(dep);
	EC_M_free_msg(keymsg);
	EC_M_free_msg(datamsg);
	EC_W_db_close(recdb);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }
    res = EC_W_db_put(recdb, seqnomsg, datamsg);
    if (res) {
	EC_M_free_dep(dep);
	EC_M_free_msg(keymsg);
	EC_M_free_msg(datamsg);
	EC_W_db_close(recdb);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }
    err = EC_M_compile_int(seqno, keymsg);
    if (err) {
	EC_M_free_dep(dep);
	EC_M_free_msg(keymsg);
	EC_M_free_msg(datamsg);
	EC_W_db_close(recdb);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Load some fields of dep */
    dep->seqno = seqno;
    dep->payment_hdr->seqno = seqno;
    dep->payment_hdr->rcv_time = time(NULL);

    /* Compile dep */
    EC_M_clear_msg(datamsg);
    err = EC_M_compile_dep(dep, datamsg);
    EC_M_free_dep(dep);
    if (err) {
	EC_M_free_msg(keymsg);
	EC_M_free_msg(datamsg);
	EC_W_db_close(recdb);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Insert it into the database */
    res = EC_W_db_put(recdb, keymsg, datamsg);
    EC_M_free_msg(keymsg);
    EC_M_free_msg(datamsg);
    EC_W_db_close(recdb);
    EC_W_wallet_lock(wallet, oldlock);
    if (res) {
	return EC_ERR_INTERNAL;
    }

    /* Make a note of the key we used */
    if (pseqno) *pseqno = seqno;
    EC_M_free_payment(payment);

    return EC_ERR_NONE;
}

EC_M_Dep EC_W_recdb_get(EC_W_Wallet wallet, UInt32 seqno)
{
    EC_Errno err = EC_ERR_NONE;
    EC_W_Locktype oldlock;
    Int32 res;
    EC_W_Db recdb;
    EC_M_Dep dep;
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
    recdb = EC_W_db_open(wallet, EC_W_RECDBFNAME, O_RDONLY);
    if (!recdb) {
	EC_M_free_msg(keymsg);
	EC_W_wallet_lock(wallet, oldlock);
	return NULL;
    }

    /* Retrieve the data */
    res = EC_W_db_get(recdb, keymsg, &datamsg);
    EC_M_free_msg(keymsg);
    EC_W_db_close(recdb);
    EC_W_wallet_lock(wallet, oldlock);
    if (res) {
	return NULL;
    }

    /* Decompile the datamsg */
    err = EC_M_decompile_dep(&dep, datamsg);
    EC_M_free_msg(datamsg);

    return dep;
}

/* Delete the payments listed in a dep_ack from the received payments db */
EC_Errno EC_W_recdb_del(EC_W_Wallet wallet, EC_M_Dep_ack dep_ack)
{
    EC_Errno err = EC_ERR_NONE;
    EC_W_Locktype oldlock;
    EC_W_Db recdb;
    EC_M_Msg keymsg;
    int i;

    if (!wallet || !dep_ack) return EC_ERR_INTERNAL;

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
    recdb = EC_W_db_open(wallet, EC_W_RECDBFNAME, O_RDWR);
    if (!recdb) {
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_msg(keymsg);
	return EC_ERR_INTERNAL;
    }

    /* For each ack, create a key and delete the db entry */
    for (i=0;i<dep_ack->numacks;++i) {
	keymsg->begin = 0;
	keymsg->end = 0;
	err = EC_M_compile_int(dep_ack->dep_1ack[i]->seqno, keymsg);
	if (err) {
	    EC_W_db_close(recdb);
	    EC_W_wallet_lock(wallet, oldlock);
	    EC_M_free_msg(keymsg);
	    return EC_ERR_INTERNAL;
	}

	/* Delete the data */
	EC_W_db_del(recdb, keymsg);
    }

    /* Free up */
    EC_M_free_msg(keymsg);
    EC_W_db_close(recdb);
    EC_W_wallet_lock(wallet, oldlock);

    return EC_ERR_NONE;
}

/* Get all of the entries in the received payments db */
EC_Errno EC_W_recdb_get_all(EC_W_Wallet wallet, EC_M_Dep **pdep,
    UInt32 *pnumdeps)
{
    EC_Errno err = EC_ERR_NONE;
    EC_W_Locktype oldlock;
    Int32 res;
    EC_W_Db recdb;
    EC_M_Dep *dep;
    UInt32 numdeps;
    EC_M_Msg datamsg;
    int i;

    if (!wallet || !pdep || !pnumdeps) return EC_ERR_INTERNAL;

    /* Get a temporary read lock on the wallet */
    err = EC_W_wallet_templock(wallet, EC_W_LOCK_READ, &oldlock);
    if (err) {
	return EC_ERR_INTERNAL;
    }

    /* Open the database */
    recdb = EC_W_db_open(wallet, EC_W_RECDBFNAME, O_RDONLY);
    if (!recdb) {
	EC_W_wallet_lock(wallet, oldlock);
	*pdep = NULL;
	*pnumdeps = 0;
	return EC_ERR_NONE;
    }

    dep = NULL;
    numdeps = 0;

    /* Retrieve the data */
    while(!(res = EC_W_db_seq(recdb, NULL, &datamsg))) {
	EC_M_Fieldtype fieldtype;
	EC_M_Rectype rectype;
	EC_M_Dep *newdep;

	/* Check that this is, in fact, a dep message */
	err = EC_M_examine_msg(&fieldtype, &rectype, datamsg);
	if (err) break;
	if (fieldtype != EC_M_FIELD_SOR || rectype != EC_M_REC_DEP) continue;

	/* Allocate a new space */
	newdep = EC_G_realloc(dep, sizeof(EC_M_Dep)*(numdeps+1));
	if (!newdep) {
	    EC_M_free_msg(datamsg);
	    err = EC_ERR_INTERNAL;
	    break;
	}
	dep = newdep;
	dep[numdeps] = NULL;

	/* Get the new data */
	err = EC_M_decompile_dep(&dep[numdeps], datamsg);
	++numdeps;
	EC_M_free_msg(datamsg);
	if (err) break;
    }

    if (res < 0) err = EC_ERR_INTERNAL;

    if (err) {
	/* Clean up */
	for (i=0;i<numdeps;++i) EC_M_free_dep(dep[i]);
	if (dep) EC_G_free(dep);
    }

    EC_W_db_close(recdb);
    EC_W_wallet_lock(wallet, oldlock);

    if (err) return err;

    /* Store the results */
    *pdep = dep;
    *pnumdeps = numdeps;

    return EC_ERR_NONE;
}
