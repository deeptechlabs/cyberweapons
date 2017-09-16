#include <time.h>
#include "lucre.h"

/*

To withdraw money:

    EC_W_Wallet wallet;			// your wallet
    EC_M_Msg msg;			// the message to be passed around
    EC_Errno err;			// for error checking

    // Fill these in before you start:
    char walletid[];			// The name of your wallet
    UInt32 amount;			// The amount you would like to
    					//   withdraw
    UInt32 minpayments;			// The number of each of the
    					//   small denominations that you
    					//   would like to have after the
    					//   withdrawal

    wallet = EC_W_wallet_open(walletid);
    msg = EC_M_new_msg();
    err = EC_W_withdraw_1(wallet, msg, amount, minpayments);
    send msg
    EC_M_clear_msg(msg);
    receive the response into msg
    err = EC_W_withdraw_2(wallet, msg, &amount);
    EC_M_free_msg(msg);
    EC_W_wallet_close(wallet);

    // The amount that was actually withdrawn is now in amount:
    printf("%d cents withdrawn\n", amount);

If you don't get a parsable reply from the bank after you send your
withdrawal request, it is _very important_ not to send another one!
If the bank got your message, it has already withdrawn the money from your
account.  In order to get the ecash, you need to send the exact same
request again.  Here's how to do that:

    EC_W_Wallet wallet;			// your wallet
    EC_M_Msg msg;			// the message to be passed around
    EC_Errno err;			// for error checking
    UInt32 nolds;			// the number of old messages
    time_t *stamps;			// their sequence numbers
    int i;

    // Fill these in before you start:
    char walletid[];			// The name of you wallet

    wallet = EC_W_wallet_open(walletid);
    msg = EC_M_new_msg();
    err = WC_W_wddb_get_all(wallet, &stamps, &nolds);
    if (nolds) printf("%d old messages found\n", nolds);
    for(i=0;i<nolds;++i) {
	err = EC_W_withdraw_old_1(wallet, msg, stamps[i]);
	send msg
	EC_M_clear_msg(msg);
	receive the response into msg
	err = EC_W_withdraw_2(wallet, msg, &amount);
	printf("%d cents withdrawn\n", amount);
	EC_M_clear_msg(msg);
    }
    EC_M_free_msg(msg);
    EC_W_wallet_close(wallet);

*/

EC_Errno EC_W_withdraw_1(EC_W_Wallet wallet, EC_M_Msg msg, UInt32 amount,
    UInt32 minpayments)
{
    EC_Errno err;
    EC_M_Curr curr;
    EC_W_Tally tally, needtally;
    EC_M_Bank_mkey bank_mkey;
    UInt32 buneeded, buleft, coinsleft, denom, budenom, totvalue;
    struct EC_W_Tally1_s *needver;
    EC_M_Wdfin *wdfin;
    UInt32 totcoins;
    EC_W_Locktype oldlock;
    EC_M_Hdr_stuff hdr_stuff;
    EC_M_Userhdr userhdr; 
    EC_M_Msg submsg, clonemsg, storemsg;
    EC_M_Sigmsg sigmsg;
    EC_M_Bank_encr bank_encr;
    EC_M_Withdraw3 withdraw3;
    EC_M_Status status;
    time_t stamp;
    UInt32 bankID;
    EC_M_Currency currency;
    int i;

    if (!wallet || !msg) return EC_ERR_INTERNAL;

    /* Don't bother going on if we don't have a private key available */
    if (!wallet->userprivkey) return EC_ERR_INTERNAL;

    /* Get the default bankID and currency */
    bankID = wallet->userrec->bankID;
    currency = wallet->userrec->currency;

    /* Look up the most recent curr record */
    curr = EC_W_curr_lookup(wallet, bankID, currency, 0);
    if (!curr) return EC_ERR_INTERNAL;

    /* Get the bank_mkey */
    bank_mkey = EC_W_bankkeys_lookup(wallet, wallet->userrec->bankID, 0);
    if (!bank_mkey) {
	EC_M_free_curr(curr);
        return EC_ERR_INTERNAL;
    }

    /* Tally up the coins in the wallet */
    tally = EC_W_new_tally();
    if (!tally) {
	EC_M_free_bank_mkey(bank_mkey);
	EC_M_free_curr(curr);
	return EC_ERR_INTERNAL;
    }

    err = EC_W_cashdb_tally(wallet, bankID, currency, 0,
	EC_W_TALLY_MERGECVER, tally);
    if (err) {
	EC_W_free_tally(tally);
	EC_M_free_bank_mkey(bank_mkey);
	EC_M_free_curr(curr);
	return err;
    }

    /* Count what we got */
    totvalue = EC_W_tally_value(tally, NULL);

    /* Divide the amount we want by base_amt to get base units */
    buneeded = amount / curr->cinfo[0]->base_val;

    /* Figure out how many coins of each denomination we need */
    buleft = buneeded;
    coinsleft = bank_mkey->maxcoins;
    needtally = EC_W_new_tally();
    if (!needtally) {
	EC_W_free_tally(tally);
	EC_M_free_bank_mkey(bank_mkey);
	EC_M_free_curr(curr);
	return err;
    }
    /* Make sure we have at least one currversion */
    err = EC_W_tally_inc(needtally, curr->cinfo[0]->keyversion,
			    0, EC_W_TALLY_NONE);
    if (err) {
	EC_W_free_tally(tally);
	EC_W_free_tally(needtally);
	EC_M_free_bank_mkey(bank_mkey);
	EC_M_free_curr(curr);
	return err;
    }

    /* Satisfy the minpayments requirement */

    for(denom = 0, budenom = 1;
        denom < curr->onl_curr[0]->ndenom;
        ++denom, budenom <<= 1) {
	/* Try to get at least (minpayments) of this denomination */
	err = EC_W_tally_inc(tally, denom, 0, EC_W_TALLY_MERGECVER);
	if (err) {
	    EC_W_free_tally(needtally);
	    EC_W_free_tally(tally);
	    EC_M_free_bank_mkey(bank_mkey);
	    EC_M_free_curr(curr);
	    return err;
	}
	while (tally->ver[0].ncoins[denom] < minpayments && coinsleft
	    && budenom <= buleft) {
	    /* Add a new coin of this denomination */
	    err = EC_W_tally_inc(needtally, curr->cinfo[0]->keyversion | denom,
		1, EC_W_TALLY_NONE);
	    if (!err) err = EC_W_tally_inc(tally, denom, 1,
		EC_W_TALLY_MERGECVER);
	    if (err) {
		EC_W_free_tally(needtally);
		EC_W_free_tally(tally);
		EC_M_free_bank_mkey(bank_mkey);
		EC_M_free_curr(curr);
		return err;
	    }
	    /* Update the requirements */
	    buleft -= budenom;
	    --coinsleft;
	}
	if (!coinsleft || budenom > buleft) break;
    }

    /* We don't care what we have anymore */
    EC_W_free_tally(tally);

    /* OK; now just get whatever we can, from high denominations to low */
    denom = curr->onl_curr[0]->ndenom - 1;
    budenom = 1 << denom;
    while(coinsleft && buleft && budenom) {
	if (budenom <= buleft) {
	    /* Add a new coin of this denomination */
	    err = EC_W_tally_inc(needtally, curr->cinfo[0]->keyversion | denom,
		1, EC_W_TALLY_NONE);
	    if (err) {
		EC_W_free_tally(needtally);
		EC_M_free_bank_mkey(bank_mkey);
		EC_M_free_curr(curr);
		return err;
	    }
	    /* Update the requirements */
	    buleft -= budenom;
	    --coinsleft;
	} else {
	    if (denom == 0) break;
	    --denom;
	    budenom >>= 1;
	}
    }

    /* Now we turn the tally of coins we need into a WITHDRAW3 message */

    /* Get a write lock */
    err = EC_W_wallet_templock(wallet, EC_W_LOCK_WRITE, &oldlock);
    if (err) {
	EC_W_free_tally(needtally);
	EC_M_free_bank_mkey(bank_mkey);
	EC_M_free_curr(curr);
	return EC_ERR_INTERNAL;
    }

    /* Update our cash-on-hand */
    status = EC_W_status_read(wallet);
    if (status) {
	status->cash = totvalue;
	EC_W_status_write(wallet, status);
	EC_M_free_status(status);
    }

    /* Construct a wdfin for each denomination */
    needver = &(needtally->ver[0]);

    wdfin =
	(EC_M_Wdfin *)EC_G_malloc(sizeof(EC_M_Wdfin)*needver->ndenom);
    if (!wdfin) {
	EC_W_wallet_lock(wallet, oldlock);
	EC_W_free_tally(needtally);
	EC_M_free_bank_mkey(bank_mkey);
	EC_M_free_curr(curr);
	return EC_ERR_INTERNAL;
    }
    totcoins = 0;
    for(denom = 0; denom < needver->ndenom; ++denom) wdfin[denom] = NULL;
    for(denom = 0; denom < needver->ndenom; ++denom) {
	UInt32 *seqno;
	BIGNUM **R;

	seqno = (UInt32 *)EC_G_malloc(sizeof(UInt32)*needver->ncoins[denom]);
	R = (BIGNUM **)EC_G_malloc(sizeof(BIGNUM *)*needver->ncoins[denom]);
	if (!seqno || !R) {
	    if (seqno) EC_G_free(seqno);
	    if (R) EC_G_free(R);
	    err = EC_ERR_INTERNAL;
	    break;
	}

	/* Fill in the wdfin */
	for(i=0;i<needver->ncoins[denom];++i) R[i] = NULL;
	for(i=0;i<needver->ncoins[denom];++i) {
	    if (!err) {
		err = EC_W_cashdb_newcoin(wallet, bankID, curr,
				denom, &R[i], &seqno[i]);
	    }
	}
	if (err) {
	    for(i=0;i<needver->ncoins[denom];++i) EC_M_free_MPI(R[i]);
	    EC_G_free(seqno);
	    EC_G_free(R);
	    break;
	}
	wdfin[denom] = EC_M_new_wdfin(curr->cinfo[0]->keyversion | denom,
	    needver->ncoins[denom], seqno, R);
	if (!wdfin[denom]) {
	    for(i=0;i<needver->ncoins[denom];++i) EC_M_free_MPI(R[i]);
	    EC_G_free(seqno);
	    EC_G_free(R);
	    err = EC_ERR_INTERNAL;
	    break;
	}
	totcoins += needver->ncoins[denom];
    }
    EC_M_free_curr(curr);

    if (err) {
	EC_G_free(wdfin);
	EC_W_free_tally(needtally);
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_bank_mkey(bank_mkey);
	return err;
    }

    /* Create the WITHDRAW3 message */
    withdraw3 = EC_M_new_withdraw3(EC_M_PROT_ONLINE_COINS, 0, totcoins,
	needver->ndenom, wdfin);
    if (!withdraw3) {
	EC_G_free(wdfin);
	EC_W_free_tally(needtally);
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_bank_mkey(bank_mkey);
	return EC_ERR_INTERNAL;
    }
    EC_W_free_tally(needtally);

    /* Create and compile the headers */
    submsg = EC_M_new_msg();
    if (!submsg) {
	EC_M_free_withdraw3(withdraw3);
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_bank_mkey(bank_mkey);
	return EC_ERR_INTERNAL;
    }
    
    if (!err) err = EC_M_compile_withdraw3(withdraw3, submsg);
    EC_M_free_withdraw3(withdraw3);

    if (err) {
	EC_M_free_msg(submsg);
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_bank_mkey(bank_mkey);
        return EC_ERR_INTERNAL;
    }

    /* Sign the message */
    sigmsg = EC_U_sign_sigmsg(wallet->userrec->userkey->n,
	wallet->userprivkey->d, submsg);
    if (!sigmsg) {
	EC_M_free_msg(submsg);
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_bank_mkey(bank_mkey);
        return EC_ERR_INTERNAL;
    }

    /* Compile the sigmsg */
    submsg = EC_M_new_msg();
    if (!submsg) {
	EC_M_free_sigmsg(sigmsg);
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_bank_mkey(bank_mkey);
        return EC_ERR_INTERNAL;
    }

    /* Get the next timestamp */
    stamp = EC_W_timestamp(wallet);
    if (!stamp) stamp = time(NULL);

    /* Create the hdr_stuff header */
    hdr_stuff = EC_M_new_hdr_stuff(EC_LIB_VERNUM, stamp);
    if (!hdr_stuff) {
	EC_M_free_msg(submsg);
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_bank_mkey(bank_mkey);
        return EC_ERR_INTERNAL;
    }

    /* Create the userhdr header */
    userhdr = EC_M_new_userhdr(wallet->userrec->userID, stamp,
	bank_mkey->bankID);
    if (!userhdr) {
        EC_M_free_hdr_stuff(hdr_stuff);
	EC_M_free_msg(submsg);
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_bank_mkey(bank_mkey);
        return EC_ERR_INTERNAL;
    }

    err = EC_M_compile_hdr_stuff(hdr_stuff, submsg);
    if (!err) err = EC_M_compile_userhdr(userhdr, submsg);
    if (!err) err = EC_M_compile_sigmsg(sigmsg, submsg);
    EC_M_free_hdr_stuff(hdr_stuff);
    EC_M_free_userhdr(userhdr);
    EC_M_free_sigmsg(sigmsg);
    if (err) {
	EC_M_free_msg(submsg);
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_bank_mkey(bank_mkey);
        return EC_ERR_INTERNAL;
    }

    /* Save the WITHDRAW3 message for storage in the wd database */
    clonemsg = EC_M_clone_msg(submsg);
    if (!clonemsg) {
	EC_M_free_msg(submsg);
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_bank_mkey(bank_mkey);
        return EC_ERR_INTERNAL;
    }

    /* Encrypt the sigmsg */
    bank_encr = EC_U_rsa_encrypt_msg(EC_M_CRYPTALG_112_3DES,
        bank_mkey->keynumber, bank_mkey->bank_n, bank_mkey->bank_e, submsg);
    if (!bank_encr) {
	EC_M_free_msg(clonemsg);
        EC_M_free_msg(submsg);
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_bank_mkey(bank_mkey);
        return EC_ERR_INTERNAL;
    }

    /* Compile the encrypted message */
    err = EC_M_compile_bank_encr(bank_encr, msg);
    EC_M_free_bank_encr(bank_encr);

    /* Make the thing to store */
    storemsg = EC_M_clone_msg(msg);
    if (!storemsg) {
	EC_M_free_msg(clonemsg);
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_bank_mkey(bank_mkey);
        return EC_ERR_INTERNAL;
    }
    err = EC_M_append_msg(clonemsg->data+clonemsg->begin,
			    clonemsg->end-clonemsg->begin, storemsg);
    EC_M_free_msg(clonemsg);
    if (err) {
	EC_M_free_msg(storemsg);
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_bank_mkey(bank_mkey);
        return EC_ERR_INTERNAL;
    }

    /* Store it */
    err = EC_W_wddb_put(wallet, storemsg, stamp);
    if (err) {
	EC_M_free_msg(storemsg);
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_bank_mkey(bank_mkey);
        return EC_ERR_INTERNAL;
    }
    EC_W_wallet_lock(wallet, oldlock);

    EC_M_free_bank_mkey(bank_mkey);

    return EC_ERR_NONE;
}

EC_Errno EC_W_withdraw_old_1(EC_W_Wallet wallet, EC_M_Msg msg, time_t stamp)
{
    EC_M_Msg storemsg;
    EC_Errno err;
    EC_M_Fieldtype fieldtype;
    EC_M_Rectype rectype;

    if (!wallet || !msg) return EC_ERR_INTERNAL;

    /* Retrieve the message */
    storemsg = EC_W_wddb_get(wallet, stamp);
    if (!storemsg) {
	return EC_ERR_INTERNAL;
    }

    /* Make sure the first bit is a bank_encr, and transfer it */
    err = EC_M_examine_msg(&fieldtype, &rectype, storemsg);
    if (err) {
	EC_M_free_msg(storemsg);
	return EC_ERR_INTERNAL;
    }
    if (fieldtype != EC_M_FIELD_SOR || rectype != EC_M_REC_BANK_ENCR) {
	EC_M_free_msg(storemsg);
	return EC_ERR_INTERNAL;
    }
    err = EC_M_transfer_field(storemsg, msg);
    EC_M_free_msg(storemsg);

    if (err) return err;

    return EC_ERR_NONE;
}

EC_Errno EC_W_withdraw_2(EC_W_Wallet wallet, EC_M_Msg msg, UInt32 *pamount)
{
    EC_Errno err;
    EC_M_Bank_repl bank_repl = NULL;
    EC_M_Msg rmsg = NULL;
    EC_M_Error error = NULL;
    EC_M_Fieldtype fieldtype;
    EC_M_Rectype rectype;
    EC_M_Withdraw4 withdraw4 = NULL;
    time_t refstamp;
    UInt32 amt;
    UInt32 i;

    if (!wallet || !msg) return EC_ERR_INTERNAL;

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

    /* Handle the bank_repl */
    refstamp = bank_repl->reftime;
    err = EC_W_handle_bank_repl(wallet, bank_repl);
    EC_M_free_bank_repl(bank_repl);
    if (err) {
        EC_M_free_msg(rmsg);
        return err;
    }

    if (pamount) *pamount = 0;

    /* Look at the received message */
    while (!(err = EC_M_examine_msg(&fieldtype, &rectype, rmsg))) {
        if (fieldtype == EC_M_FIELD_NONE) {
            break;
        } else if (fieldtype != EC_M_FIELD_SOR) {
            /* This shouldn't be; ignore the field */
            err = EC_M_transfer_field(rmsg, NULL);
            if (err) break;
        } else if (rectype == EC_M_REC_WITHDRAW4) {
            /* Decompile the message */
            EC_M_free_withdraw4(withdraw4);
            err = EC_M_decompile_withdraw4(&withdraw4, rmsg);
            if (err) break;

            /* For each wdfin in the withdraw4, put the signed coins
               into the database. */
	    for (i=0;i<withdraw4->numwds;++i) {
		if (!err) err = EC_W_cashdb_finish(wallet,
		    wallet->userrec->bankID, wallet->userrec->currency,
		    withdraw4->wdfin[i], &amt);
		if (!err && pamount) *pamount += amt;
            }

            if (err) break;

            /* Remove the stored message from the wd database */
            err = EC_W_wddb_del(wallet, refstamp);
            if (err) break;

        } else {
            /* Handle the common messages */
            err = EC_W_handle_common(wallet, rmsg);
            if (err) break;
        }
    }

    EC_M_free_msg(rmsg);
    EC_M_free_withdraw4(withdraw4);

    if (err) {
        return err;
    }

    return EC_ERR_NONE;
}
