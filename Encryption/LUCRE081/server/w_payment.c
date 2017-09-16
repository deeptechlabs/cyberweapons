#include <time.h>
#include "lucre.h"
#include "sha.h"
#include "rand.h"

/*

Here's how to receive a payment request:

    EC_M_Msg       msg;			// the received msg will be put here
    EC_Errno       err;			// for checking errors
    EC_M_Payreq    payreq;		// the payment request will be put here

    msg = EC_M_new_msg();
    receive payreq into msg
    err = EC_M_decompile_payreq(&payreq, msg);
    // Now you can look at the fields of payreq, and decide whether to
    //   make the payment
    EC_M_free_payreq(payreq);
    EC_M_free_msg(msg);

Here's how to make a payment:

    EC_W_Wallet    wallet;		// your wallet
    EC_M_Msg       msg;			// the msg to be passed around
    EC_Errno       err;			// for error checking
    UInt32         seqno;		// the payment number

    // Fill these in before you start:
    char *	   walletid;		// The name of your wallet
    Int32          amount;		// The amount of the payment
    EC_M_Currency  currency;		// The currency for the payment
    char *         shop;		// The name of the shop
    UInt32	   shop_bankID;		// The shop's bank's ID
    char *         descr;		// The payment description

    wallet = EC_W_wallet_open(walletid);
    msg = EC_M_new_msg();
    err = EC_W_create_payment(wallet, amount, currency, shop, shop_bankID,
	    descr, &seqno);
    err = EC_W_make_payment(wallet, msg, seqno);
    // msg now contains the payment
    send msg
    EC_M_free_msg(msg);
    EC_W_wallet_close(wallet);

Here's how to make a payment request:

    EC_M_Msg       msg;			// the msg to be passed around
    EC_Errno       err;			// for error checking

    // Fill these in before you start:
    EC_M_Currency  currency;		// The currency for the payment
    UInt32	   amount;		// The amount of the payment
    UInt32         shop_bankID;		// The shop's bank's ID
    char *	   shop_accID;		// The shop's account ID
    char *	   descr;		// A description of the object
    char *         conn_host;		// Optionally, the host to connect
    					//   back to when making the payment
    					//   (use "" to leave it out)
    UInt32	   conn_port;		// As above, for the port number
    					//   (use 0 to leave it out)

    msg = EC_M_new_msg();
    err = EC_W_request_payment(msg, currency, amount, shop_bankID,
	shop_accID, descr, conn_host, conn_port);
    send the msg
    EC_M_free(msg);

One thing to note is that you should put a bit of randomness in the
descr field.  Otherwise, the bank can link together payments made
for the same object (the bank sees a hash of the descr field).

Here's how to accept a payment:

    EC_W_Wallet    wallet;		// your wallet
    EC_M_Msg       msg;			// the msg to be passed around
    EC_Errno       err;			// for error checking
    UInt32         seqno;		// the payment number
    EC_M_Payment   payment;		// the received payment
    UInt32         accepted, amount;	// the results of the payment

    // Fill this in before you start:
    char *	   walletid;		// The name of your wallet

    msg = EC_M_new_msg();
    receive the payment into msg
    err = EC_M_decompile_payment(&payment, msg);
    // here, you can examine the payment if you like
    wallet = EC_W_wallet_open(walletid);
    err = EC_W_recdb_put(wallet, payment, &seqno);
    EC_M_clear_msg(msg);
    err = EC_W_deposit_payment_1(wallet, msg, seqno);
    send msg to bank
    EC_M_clear_msg(msg);
    receive response into msg
    err = EC_W_deposit_payment_2(wallet, msg, seqno, &accepted, &amount);
    // accepted is now 1 or 0, according to whether or not the deposit
    //   was accepted; amount is the amount of the accepted deposit, or
    //   the error code for a rejected deposit
    EC_M_free_msg(msg);
    EC_W_wallet_close(wallet);

You should, of course, be checking the error return values.

*/

/* Create a payment and put it into the payments database.  Set *pseqno
   to the sequence number it was assigned. */
EC_Errno EC_W_create_payment(EC_W_Wallet wallet, UInt32 amount,
    EC_M_Currency currency, char *shop, UInt32 shop_bankID, char *descr,
    UInt32 *pseqno)
{
    EC_Errno err = EC_ERR_NONE;
    EC_W_Locktype oldlock;
    EC_M_Curr curr;
    EC_M_Payment payment;
    EC_M_Payment_hdr phdr;
    EC_M_Onl_coin *onl_coin;
    EC_M_Pcoins pcoins;
    EC_W_Tally tally;
    EC_M_Coindata coinlist, coinptr;
    UInt32 ncoins;
    UInt32 denom, budenom, buleft;
    UInt32 i, seqno;
    time_t stamp, expires;
    char *new_shop;
    char *comment;
    char *new_descr;
    Byte *payer_code;
    Byte *payer_hash;
    Byte *descr_hash;

    if (!wallet || !shop || !descr || !pseqno) return EC_ERR_INTERNAL;

    /* Get a temporary write lock on the wallet */
    err = EC_W_wallet_templock(wallet, EC_W_LOCK_WRITE, &oldlock);
    if (err) return EC_ERR_INTERNAL;

    /* Get the money tally */
    tally = EC_W_new_tally();
    if (!tally) {
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    err = EC_W_cashdb_tally(wallet, wallet->userrec->bankID, currency,
	0, EC_W_TALLY_MERGECVER|EC_W_TALLY_VERBOSE, tally);
    if (!err) err = EC_W_tally_inc(tally, 0, 0, EC_W_TALLY_MERGECVER);
    if (err) {
	EC_W_free_tally(tally);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Get the curr record */
    /* NOTE: this breaks if base_val changes with different keyversions! */
    curr = EC_W_curr_lookup(wallet, wallet->userrec->bankID, currency, 0);
    if (!curr) {
	EC_W_free_tally(tally);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }
    buleft = amount / curr->cinfo[0]->base_val;
    amount = buleft * curr->cinfo[0]->base_val;
    EC_M_free_curr(curr);

    /* Find an appropriate set of coins that add up to buleft base units */
    denom = tally->ver[0].ndenom-1;
    budenom = 1 << denom;
    coinlist = NULL;
    ncoins = 0;
    while(budenom && buleft) {
	EC_M_Coindata coindata = tally->ver[0].coindata[denom];
	while(coindata && budenom <= buleft) {
	    /* Grab this coin */
	    EC_M_Coindata newcoin = EC_M_clone_coindata(coindata);
	    if (!newcoin) {
		err = EC_ERR_INTERNAL;
		break;
	    }
	    newcoin->next = coinlist;
	    coinlist = newcoin;
	    buleft -= budenom;
	    coindata = coindata->next;
	    ncoins++;
	}
	if (err) break;
	if (denom == 0) break;
	--denom;
	budenom >>= 1;
    }
    EC_W_free_tally(tally);
    if (!err && buleft != 0) {
	/* We don't have the right change! */
	err = EC_ERR_INTERNAL;
    }

    if (err) {
	/* Free the coinlist */
	while (coinlist) {
	    EC_M_Coindata next = coinlist->next;
	    EC_M_free_coindata(coinlist);
	    coinlist = next;
	}
	EC_W_wallet_lock(wallet, oldlock);
	return err;
    }

    /* Create the pcoins message */
    onl_coin = ncoins ?
	(EC_M_Onl_coin *)EC_G_malloc(sizeof(EC_M_Onl_coin)*ncoins) : NULL;
    if (ncoins && !onl_coin) {
	while (coinlist) {
	    EC_M_Coindata next = coinlist->next;
	    EC_M_free_coindata(coinlist);
	    coinlist = next;
	}
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }
    coinptr = coinlist;
    for(i=0;i<ncoins;++i) onl_coin[i] = NULL;
    for(i=0; i<ncoins && coinptr; ++i, coinptr=coinptr->next) {
	BIGNUM *n = EC_M_clone_MPI(coinptr->n);
	BIGNUM *fn1h = EC_M_clone_MPI(coinptr->fn1h);
	if (!n || !fn1h) {
	    EC_M_free_MPI(n);
	    EC_M_free_MPI(fn1h);
	    err = EC_ERR_INTERNAL;
	    break;
	}
	onl_coin[i] = EC_M_new_onl_coin(coinptr->keyversion, n, fn1h,
	    1 << (coinptr->keyversion & EC_M_KEYVER_VALMASK));
	if (!onl_coin[i]) {
	    EC_M_free_MPI(n);
	    EC_M_free_MPI(fn1h);
	    err = EC_ERR_INTERNAL;
	    break;
	}
    }
    if (err) {
	for(i=0;i<ncoins;++i) EC_M_free_onl_coin(onl_coin[i]);
	if (onl_coin) EC_G_free(onl_coin);
	while (coinlist) {
	    EC_M_Coindata next = coinlist->next;
	    EC_M_free_coindata(coinlist);
	    coinlist = next;
	}
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }
    pcoins = EC_M_new_pcoins(ncoins, onl_coin);
    if (!pcoins) {
	for(i=0;i<ncoins;++i) EC_M_free_onl_coin(onl_coin[i]);
	if (onl_coin) EC_G_free(onl_coin);
	while (coinlist) {
	    EC_M_Coindata next = coinlist->next;
	    EC_M_free_coindata(coinlist);
	    coinlist = next;
	}
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Make the payment header */
    stamp = time(NULL);
    expires = stamp + EC_W_PAYMENT_EXPTIME;
    new_shop = EC_G_strdup(shop);
    comment = EC_G_strdup("");
    new_descr = EC_G_strdup(descr);
    payer_code = EC_G_malloc(SHA_DIGEST_LENGTH);
    payer_hash = EC_G_malloc(SHA_DIGEST_LENGTH);
    descr_hash = EC_G_malloc(SHA_DIGEST_LENGTH);
    if (!new_shop || !comment || !new_descr || !payer_code || !payer_hash
	|| !descr_hash) {
	if (new_shop) EC_G_free(new_shop);
	if (comment) EC_G_free(comment);
	if (new_descr) EC_G_free(new_descr);
	EC_M_free_data(payer_code);
	EC_M_free_data(payer_hash);
	EC_M_free_data(descr_hash);
	EC_M_free_pcoins(pcoins);
	while (coinlist) {
	    EC_M_Coindata next = coinlist->next;
	    EC_M_free_coindata(coinlist);
	    coinlist = next;
	}
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Pick a random payer_code */
    RAND_bytes(payer_code, SHA_DIGEST_LENGTH);

    /* Hash the payer code */
    SHA1(payer_code, SHA_DIGEST_LENGTH, payer_hash);

    /* Hash the description */
    SHA1(new_descr, strlen(new_descr), descr_hash);

    phdr = EC_M_new_payment_hdr(wallet->userrec->bankID,
	EC_M_PROT_ONLINE_COINS, amount, currency, ncoins, stamp, expires,
	shop_bankID, new_shop, payer_hash, SHA_DIGEST_LENGTH, descr_hash,
	SHA_DIGEST_LENGTH, 0x10, new_descr, comment, payer_code,
	SHA_DIGEST_LENGTH, 0, 0, 0);
    if (!phdr) {
	if (new_shop) EC_G_free(new_shop);
	if (comment) EC_G_free(comment);
	if (new_descr) EC_G_free(new_descr);
	EC_M_free_data(payer_code);
	EC_M_free_data(payer_hash);
	EC_M_free_data(descr_hash);
	EC_M_free_pcoins(pcoins);
	while (coinlist) {
	    EC_M_Coindata next = coinlist->next;
	    EC_M_free_coindata(coinlist);
	    coinlist = next;
	}
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Make the payment structure */
    payment = EC_M_new_payment(phdr, pcoins);
    if (!payment) {
	EC_M_free_payment_hdr(phdr);
	EC_M_free_pcoins(pcoins);
	while (coinlist) {
	    EC_M_Coindata next = coinlist->next;
	    EC_M_free_coindata(coinlist);
	    coinlist = next;
	}
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Put it into the payments database */
    err = EC_W_paydb_put(wallet, payment, &seqno);
    if (err) {
	EC_M_free_payment(payment);
	while (coinlist) {
	    EC_M_Coindata next = coinlist->next;
	    EC_M_free_coindata(coinlist);
	    coinlist = next;
	}
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Remove the coins we used from the cash database */
    err = EC_W_cashdb_del(wallet, wallet->userrec->bankID, currency, coinlist);
    while (coinlist) {
	EC_M_Coindata next = coinlist->next;
	EC_M_free_coindata(coinlist);
	coinlist = next;
    }
    EC_W_wallet_lock(wallet, oldlock);

    if (err) {
	return err;
    }

    if (pseqno) *pseqno = seqno;

    return EC_ERR_NONE;
}

/* Make a payment: extract and fill in a previously stored payment */
EC_Errno EC_W_make_payment(EC_W_Wallet wallet, EC_M_Msg msg, UInt32 seqno)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Payment payment;
    BIGNUM *xor;
    BN_CTX *ctx;
    EC_M_Bank_mkey bank_mkey;
    EC_M_Curr curr;
    UInt32 i;

    /* Extract the payment from the db */
    payment = EC_W_paydb_get(wallet, seqno);
    if (!payment) return EC_ERR_INTERNAL;

    /* Get the bank's keys */
    bank_mkey = EC_W_bankkeys_lookup(wallet, payment->payment_hdr->bankID, 0);
    if (!bank_mkey) {
	EC_M_free_payment(payment);
	return EC_ERR_INTERNAL;
    }

    /* We have to do that XOR thing and seal each coin. */

    /* Calculate the XOR factor */
    xor = EC_U_f(3, payment->payment_hdr->snapdata,
		    payment->payment_hdr->snaplen, bank_mkey->bank_n);
    EC_M_free_bank_mkey(bank_mkey);
    if (!xor) {
	EC_M_free_payment(payment);
	return EC_ERR_INTERNAL;
    }

    ctx = BN_CTX_new();
    if (!ctx) {
	EC_M_free_MPI(xor);
	EC_M_free_payment(payment);
	return EC_ERR_INTERNAL;
    }

    for(i=0;i<payment->pcoins->numcoins;++i) {
	/* Get the curr record for this coin */
	curr = EC_W_curr_lookup(wallet, payment->payment_hdr->bankID, 
	    payment->payment_hdr->currency,
	    payment->pcoins->onl_coin[i]->keyversion);
	if (!curr) {
	    err = EC_ERR_INTERNAL;
	    break;
	}
	err = EC_U_xor_MPI(payment->pcoins->onl_coin[i]->sig, xor);
	if (err) {
	    EC_M_free_curr(curr);
	    break;
	}
	if (!BN_mod_exp(payment->pcoins->onl_coin[i]->sig,
			payment->pcoins->onl_coin[i]->sig, 
			curr->onl_curr[0]->seal_e,
			curr->onl_curr[0]->seal_n,
			ctx)) {
	    EC_M_free_curr(curr);
	    break;
	}
	EC_M_free_curr(curr);
    }
    BN_CTX_free(ctx);
    EC_M_free_MPI(xor);
    if (err) {
	EC_M_free_payment(payment);
	return EC_ERR_INTERNAL;
    }

    /* Clean some fields in the payment */
    EC_M_free_data(payment->payment_hdr->payer_code);
    payment->payment_hdr->payer_code = NULL;
    payment->payment_hdr->payer_codelen = 0;
    payment->payment_hdr->seqno = 0;

    /* Now just compile the payment */
    err = EC_M_compile_payment(payment, msg);
    EC_M_free_payment(payment);

    return err;
}

EC_Errno EC_W_request_payment(EC_M_Msg msg, EC_M_Currency currency,
    UInt32 amount, UInt32 shop_bankID, char *shop_accID, char *descr,
    char *conn_host, UInt32 conn_port)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Payreq payreq;
    char *myshop_accID;
    char *mydescr;
    char *myconn_host;
    time_t timestamp;

    /* Get local copies of the strings */
    myshop_accID = EC_G_strdup( shop_accID ? shop_accID : "" );
    mydescr = EC_G_strdup( descr ? descr : "" );
    myconn_host = EC_G_strdup( conn_host ? conn_host : "" );

    if (!myshop_accID || !mydescr || !myconn_host) {
	if (myshop_accID) EC_G_free(myshop_accID);
	if (mydescr) EC_G_free(mydescr);
	if (myconn_host) EC_G_free(myconn_host);
	return EC_ERR_INTERNAL;
    }

    /* Construct the payment request */
    timestamp = time(NULL);
    payreq = EC_M_new_payreq(currency, amount, timestamp, shop_bankID,
	myshop_accID, mydescr, myconn_host, conn_port);
    if (!payreq) {
	EC_G_free(myshop_accID);
	EC_G_free(mydescr);
	EC_G_free(myconn_host);
	return EC_ERR_INTERNAL;
    }

    /* Compile it */
    err = EC_M_compile_payreq(payreq, msg);
    EC_M_free_payreq(payreq);
    if (err) {
	return err;
    }

    return EC_ERR_NONE;
}
