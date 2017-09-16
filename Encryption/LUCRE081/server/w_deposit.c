#include <time.h>
#include "lucre.h"

/*

Here's how to receive a payment and deposit it into your bank account:

    EC_W_Wallet wallet;			// your wallet
    EC_M_Msg msg;			// the message to be passed around
    EC_Errno err;			// for error checking
    UInt32 seqno;			// the sequence number to be assigned
    					//   to the payment
    UInt32 accepted, amount;		// the results of the deposit

    // Fill these in before you start:
    char walletid[];			// The name of your wallet
    EC_M_Payment payment;		// The received payment

    wallet = EC_W_wallet_open(walletid);
    msg = EC_M_new_msg();
    err = EC_W_recdb_put(wallet, payment, &seqno);
    // The received payment has now been freed
    err = EC_W_deposit_payment_1(wallet, msg, seqno);
    send msg
    EC_M_clear_msg(msg);
    receive the response into msg
    err = EC_W_deposit_payment_2(wallet, msg, seqno, &accepted, &amount);
    EC_M_free_msg(msg);
    EC_W_wallet_close(wallet);

    // Check the reply; for example:
    printf("Deposit %d %s: %d\n", seqno,
	accepted ? "accepted" : "rejected", amount);

If you have to abort before receiving a response from the bank, or if
deposit_payment_*() fails, you can always use deposit_all_payments_1() later
(see below).

Once a payment is put into the payments db with recdb_put(), it stays there
until a dep_ack comes back from the bank with its seqno in it, at which point
it is deleted.  If you have to abort before the reply, then at any time
in the future, you can call deposit_all_payments_1() to try again.  Note,
however, that you won't know whether the deposit will be accepted until you
do, so it's up to you to decide what to tell the client from which you
received the payment.  Here's how to call deposit_all_payments_1():

    EC_W_Wallet wallet;			// your wallet
    EC_M_Msg msg;			// the message to be passed around
    EC_M_Dep_ack dep_ack;		// filled in by the bank's reply
    EC_Errno err;			// for error checking
    UInt32 numdeps;			// the number of deposits to be made

    // Fill these in before you start:
    char walletid[];			// The name of your wallet
    EC_M_Payment payment;		// The received payment

    wallet = EC_W_wallet_open(walletid);
    msg = EC_M_new_msg();
    dep_ack = NULL;
    err = EC_W_deposit_all_payments_1(wallet, msg, &numdeps);
    if (!err && numdeps) {
	send msg
	EC_M_clear_msg(msg);
	receive the response into msg
	err = EC_W_deposit_all_payments_2(wallet, msg, &dep_ack);
    }
    EC_M_free_msg(msg);
    EC_W_wallet_close(wallet);

    // Check the reply however you want; for example:
    for(i=0;i<dep_ack->numacks;++i) {
	printf("Deposit %d %s: %d\n",
	    dep_ack->dep_1ack[i]->seqno,
	    dep_ack->dep_1ack[i]->result == 3 ? "accepted" : "rejected",
	    dep_ack->dep_1ack[i]->amount);
    }

    // For each dep_1ack, a result of 3 indicates deposit seqno was accepted
    //   for the given amount.  A result of 4 indicates the deposit was
    //   rejected, and the amount field contains a code for the reason.

    // Don't forget to free the dep_ack!
    EC_M_free_dep_ack(dep_ack);

As you can see, it's very similar, except you get to check the results
yourself (and remember to free the dep_ack!).  If you like, you can
even call deposit_all_payments_2() instead of deposit_payment_2() after
calling deposit_payment_1().  This will allow you to check the results
of a single deposit in the same manner as a multiple deposit, if you prefer.

Read and write locks are obtained for short periods during these
functions.  The wallet need not be locked while awaiting a response from
the bank.

*/

/* Step 1:
    Before:
	wallet is an open wallet
	msg is a newly-allocated message
	pnumdeps points to a UInt32 that will get the number of outstanding
	  deposits
    After:
	msg contains the DEPOSIT message to send to the bank
	*pnumdeps is the number of deposits in the message; if it is 0,
	  you don't need to call deposit_all_payments_2()
*/
EC_Errno EC_W_deposit_all_payments_1(EC_W_Wallet wallet, EC_M_Msg msg,
    UInt32 *pnumdeps)
{
    time_t stamp;
    EC_Errno err;
    EC_M_Dep *dep;
    UInt32 numdeps;
    EC_M_Bank_mkey bank_mkey;
    int i;

    if (!wallet || !msg)
	return EC_ERR_INTERNAL;

    /* Get the next timestamp */
    stamp = EC_W_timestamp(wallet);
    if (!stamp) stamp = time(NULL);

    /* Get the bank_mkey */
    bank_mkey = EC_W_bankkeys_lookup(wallet, wallet->userrec->bankID, 0);
    if (!bank_mkey) {
	return EC_ERR_INTERNAL;
    }

    /* Get the all of the deposits from the database */
    err = EC_W_recdb_get_all(wallet, &dep, &numdeps);
    if (err) {
	EC_M_free_bank_mkey(bank_mkey);
	return EC_ERR_INTERNAL;
    }

    if (numdeps == 0) {
	if (pnumdeps) *pnumdeps = 0;
	return EC_ERR_NONE;
    }

    /* Create the deposit message */
    err = EC_P_create_deposit(numdeps, dep, wallet->userrec, bank_mkey,
	stamp, msg);
    EC_M_free_bank_mkey(bank_mkey);
    if (dep) {
	for(i=0;i<numdeps;++i) {
	    EC_M_free_dep(dep[i]);
	}
	EC_G_free(dep);
    }

    if (!err && pnumdeps) *pnumdeps = numdeps;

    return err;
}

/* Step 2:
    Before:
	wallet is an open wallet
	msg contains the DEP_ACK message received from the bank
	pdep_ack points to a dep_ack variable with value NULL
    After:
	msg is empty, and should be free_msg()'d
	pdep_ack points to a newly-allocated Dep_ack structure which
	  you can examine, and then free_dep_ack()
	any payments for which a reply is received (successful or not)
	  are removed from the payments database
*/
EC_Errno EC_W_deposit_all_payments_2(EC_W_Wallet wallet, EC_M_Msg msg,
    EC_M_Dep_ack *pdep_ack)
{
    EC_Errno err;
    EC_M_Bank_repl bank_repl = NULL;
    EC_M_Msg rmsg = NULL;
    EC_M_Error error = NULL;
    EC_M_Fieldtype fieldtype;
    EC_M_Rectype rectype;

    if (!wallet || !msg || !pdep_ack) return EC_ERR_INTERNAL;

    /* Strip off the bank header */
    err = EC_P_parse_bankhdr(msg, EC_W_find_mkey, &wallet, &bank_repl,
	&rmsg, &error);
    if (err) {
	return err;
    }
    if (error) {
	/* An ERROR message was returned from the bank. */
	EC_W_handle_error(wallet, error);
	EC_M_free_error(error);
	return EC_ERR_INTERNAL;
    }

    *pdep_ack = NULL;

    /* Look at the received message */
    while (!(err = EC_M_examine_msg(&fieldtype, &rectype, rmsg))) {
        if (fieldtype == EC_M_FIELD_NONE) {
            break;
        } else if (fieldtype != EC_M_FIELD_SOR) {
            /* This shouldn't be; ignore the field */
            err = EC_M_transfer_field(rmsg, NULL);
            if (err) break;
        } else if (rectype == EC_M_REC_DEP_ACK) {
            /* Decompile the message */
            EC_M_free_dep_ack(*pdep_ack);
            err = EC_M_decompile_dep_ack(pdep_ack, rmsg);
            if (err) break;
        } else {
            /* Handle the common messages */
            err = EC_W_handle_common(wallet, rmsg);
            if (err) break;
        }
    }

    EC_M_free_msg(rmsg);

    if (err) {
	EC_M_free_bank_repl(bank_repl);
	EC_M_free_dep_ack(*pdep_ack);
	*pdep_ack = NULL;
	return err;
    }

    /* Handle the bank_repl */
    err = EC_W_handle_bank_repl(wallet, bank_repl);
    EC_M_free_bank_repl(bank_repl);
    if (err) {
	EC_M_free_dep_ack(*pdep_ack);
	*pdep_ack = NULL;
	return err;
    }

    /* Remove the ack'd payments from the database */
    err = EC_W_recdb_del(wallet, *pdep_ack);
    if (err) {
	EC_M_free_dep_ack(*pdep_ack);
	*pdep_ack = NULL;
	return err;
    }

    return EC_ERR_NONE;
}

/* Step 1:
    Before:
	wallet is an open wallet
	msg is a newly-allocated message
	seqno is the seqno for the payment in the payments db, as set by
	  EC_W_recdb_put()
    After:
	msg contains the DEPOSIT message to send to the bank
*/
EC_Errno EC_W_deposit_payment_1(EC_W_Wallet wallet, EC_M_Msg msg,
    UInt32 seqno)
{
    time_t stamp;
    EC_Errno err;
    EC_M_Dep dep;
    EC_M_Bank_mkey bank_mkey;

    if (!wallet || !msg || !seqno)
	return EC_ERR_INTERNAL;

    /* Get the next timestamp */
    stamp = EC_W_timestamp(wallet);
    if (!stamp) stamp = time(NULL);

    /* Get the bank_mkey */
    bank_mkey = EC_W_bankkeys_lookup(wallet, wallet->userrec->bankID, 0);
    if (!bank_mkey) {
	return EC_ERR_INTERNAL;
    }

    /* Get the deposit from the database, indexed by recdbkey */
    dep = EC_W_recdb_get(wallet, seqno);
    if (!dep) {
	EC_M_free_bank_mkey(bank_mkey);
	return EC_ERR_INTERNAL;
    }

    /* Create the deposit message */
    err = EC_P_create_deposit(1, &dep, wallet->userrec, bank_mkey, stamp, msg);
    EC_M_free_dep(dep);
    EC_M_free_bank_mkey(bank_mkey);

    return err;
}

/* Step 2:
    Before:
	wallet is an open wallet
	msg contains the DEP_ACK message received from the bank
	seqno is the seqno passed to depoit_payment_1()
	paccepted and pamount point to UInt32s that will get the results
	  of the deposit
    After:
	msg is empty, and should be free_msg()'d
	*paccepted is 1 if the deposit was accepted, 0 otherwise
	*amount is the amount of the accepted deposit, or the error code
	  for the rejected deposit
	any payments for which a reply is received (successful or not)
	  are removed from the payments database
*/
EC_Errno EC_W_deposit_payment_2(EC_W_Wallet wallet, EC_M_Msg msg,
    UInt32 seqno, UInt32 *paccepted, UInt32 *pamount)
{
    EC_Errno err;
    EC_M_Dep_ack dep_ack = NULL;
    int i;
    int found = 0;

    /* Get the list of dep_acks from the msg */
    err = EC_W_deposit_all_payments_2(wallet, msg, &dep_ack);
    if (err) return err;

    /* Search for the one with the right seqno */
    for(i=0;i<dep_ack->numacks;++i) {
	if (dep_ack->dep_1ack[i]->seqno == seqno) {
	    if (paccepted) *paccepted = (dep_ack->dep_1ack[i]->result == 3);
	    if (pamount) *pamount = dep_ack->dep_1ack[i]->amount;
	    found = 1;
	    break;
	}
    }
    EC_M_free_dep_ack(dep_ack);

    /* We didn't find the one we wanted? */
    if (!found) return EC_ERR_INTERNAL;

    return EC_ERR_NONE;
}
