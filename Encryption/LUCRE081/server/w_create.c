#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include "lucre.h"

/*

Here's how to create a wallet:

    EC_W_Wallet    wallet;             // state variable
    EC_Errno       err;                // For checking return codes
    EC_M_Msg       msg;                // The msg to be passed around
    
    // You must give the following values before beginning
    char           walletid[];         // A name for your wallet
    char           passphrase[];       // The passphrase you want for
                                       //  your wallet
    void callback(int stage, int attempt); // A callback function, used during
					   // signature key generation
    char           accID[];            // Your account name
    EC_M_Currency  currency;           // Your account currency
    char           account_password[]; // Your account setup password
    BIGNUM *       setup_n;            // Bank's "setup" modulus
    BIGNUM *       setup_e;            // Bank's "setup" public exponent

    wallet = NULL;
    msg = EC_M_new_msg();
    err = EC_W_wallet_create_1(&wallet, msg, walletid, passphrase, callback);
    send msg
    EC_M_clear_msg(msg);
    receive the response into msg
    err = EC_W_wallet_create_2(&wallet, msg, accID, currency,
		account_password, setup_n, setup_e);
    send msg
    EC_M_clear_msg(msg);
    receive the response into msg
    err = EC_W_wallet_create_3(&wallet, msg);
    EC_M_free_msg(msg);

After this is done, it should be the case that each of wallet, msg,
and bank_mkey is NULL.

If you ever get an error from one of the functions (you should, of course,
check the return values) or if the protocol cannot be completed, call

    EC_W_wallet_create_abort(&wallet);

Also remember to free_msg() the msg either after create_3 or
after create_abort().

The wallet is locked for writing in create_1, and it stays that way until
it is unlocked (closed, actually) in either create_3 or create_abort.

*/

/* Step 1:
    Before:
	*pwallet is NULL
	msg is a newly-allocated message
	walletid is the name for the wallet
	passphrase is the desired passphrase for the wallet, or the
	    current one, if the wallet already exists
	callback is a function that is called periodically during
	    signature key generation
    After:
	pwallet points to an open wallet
	msg contains the SETUP_REQ message to be sent to the bank
*/
EC_Errno EC_W_wallet_create_1(EC_W_Wallet *pwallet, EC_M_Msg msg,
    char *walletid, char *passphrase, void (*callback)(int, int))
{
    char *walletname;
    char *lockfilename;
    EC_W_Wallet wallet;
    int uerr;
    EC_Errno err;
    int lockfd;
    time_t stamp;

    /* Here is where we specify the size for the user's signature key,
       and the value for e that we should use. */
    const Int16 keybits = 768;
    const UInt32 e_value = 3;

    if (!pwallet || !msg)
	return EC_ERR_INTERNAL;

    /* Make sure that wallet is NULL */
    *pwallet = NULL;

    walletname = EC_W_wallet_getname(walletid);
    if (!walletname) return EC_ERR_INTERNAL;
    /* Create the lockfile name */
    lockfilename = EC_W_wallet_mkfname(walletname, EC_W_LOCKFILE, "");
    if (!lockfilename) {
        /* Uh, oh. */
        EC_G_free(walletname);
        return EC_ERR_INTERNAL;
    }

    /* Create the directory for the wallet */
    uerr = mkdir(walletname, S_IRWXU);
    if (uerr) {
	if (errno == EEXIST) {
	    /* It's already there.  That's OK, as long as we own it
	       and its mode is S_IRWXU.  We check by trying to set
	       its mode. */
	   uerr = chmod(walletname, S_IRWXU);
	   if (uerr) {
	       /* No good. */
	       EC_G_free(walletname);
	       EC_G_free(lockfilename);
	       return EC_ERR_INTERNAL;
	   }
	} else {
	    /* Hmmm... Oh, well. */
	    EC_G_free(walletname);
	    EC_G_free(lockfilename);
	    return EC_ERR_INTERNAL;
        }
    }

    /* Create the lockfile */
    lockfd = creat(lockfilename, S_IRUSR|S_IWUSR);
    if (lockfd < 0) {
        /* Abort the creation! */
        rmdir(walletname);
        EC_G_free(walletname);
        EC_G_free(lockfilename);
        return EC_ERR_INTERNAL;
    }

    /* Now: we want to create the user file _before_ we open the wallet,
       but we really should lock the wallet first.  Therefore, we lock it
       here.  The lock will last until we close(lockfd).  Make sure to
       close lockfd _before_ trying to get another lock on the wallet! */
    EC_W_wallet_lockfd(lockfd, EC_W_LOCK_WRITE);

    /* Create the user file, if necessary.  Note that we need to pass
       the walletname, as the wallet is not yet open. */
    err = EC_W_user_create(walletname, passphrase, keybits, e_value, callback);
    if (err) {
	close(lockfd);
	EC_G_free(walletname);
	EC_G_free(lockfilename);
	return err;
    }

    close(lockfd);
    EC_G_free(walletname);
    EC_G_free(lockfilename);

    /* Now open the wallet */
    wallet = EC_W_wallet_open(walletid);
    if (!wallet) {
	/* Weird. */
	return EC_ERR_INTERNAL;
    }

    /* Lock the wallet so no one else can write to it */
    err = EC_W_wallet_lock(wallet, EC_W_LOCK_WRITE);
    if (err) {
	EC_W_wallet_close(wallet);
	return EC_ERR_INTERNAL;
    }

    /* Set the key for the wallet */
    err = EC_W_wallet_usephrase(wallet, passphrase);
    if (err) {
	EC_W_wallet_close(wallet);
	return EC_ERR_INTERNAL;
    }

    /* Get the next timestamp */
    stamp = EC_W_timestamp(wallet);
    if (!stamp) stamp = time(NULL);

    /* Get the first message (SETUP_REQ) ready */
    err = EC_P_create_setup_req(stamp, msg);
    if (err) {
	EC_W_wallet_close(wallet);
	return EC_ERR_INTERNAL;
    }

    /* Return the results */
    *pwallet = wallet;

    return EC_ERR_NONE;
}

/* Step 2:
    Before:
	pwallet points to an open wallet
	msg contains the received message (should be SETUP)
	accID, currency, account_password are the account details
	setup_n, setup_e is the "setup" public key of the bank
    After:
	pwallet points to the open wallet
	msg contains the OPENACC1 message to be sent
*/
EC_Errno EC_W_wallet_create_2(EC_W_Wallet *pwallet, EC_M_Msg msg,
    char *accID, EC_M_Currency currency, char *account_password,
    BIGNUM *setup_n, BIGNUM *setup_e)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Bank_mkey bank_mkey = NULL;
    char *bankname = NULL;
    EC_M_Protocols protocols = NULL;
    EC_M_Error error = NULL;
    EC_M_Userrec newuserrec = NULL;
    int found, i;
    time_t stamp;

    /* Make sure we have what we need */
    if (!pwallet || !*pwallet || !msg || !accID ||
	!account_password || !setup_n || !setup_e)
	return EC_ERR_INTERNAL;

    /* Parse the SETUP message */
    err = EC_P_parse_setup(msg, setup_n, setup_e, &bank_mkey,
	&bankname, &protocols, &error);
    if (err) {
	return EC_ERR_INTERNAL;
    }
    if (error) {
	/* An ERROR message was returned from the bank. */
	EC_W_handle_error(*pwallet, error);
	EC_M_free_error(error);
	return EC_ERR_INTERNAL;
    }

    /* We don't really care about the bankname; it's in the bank_mkey,
       anyway. */
    if (bankname) EC_G_free(bankname);

    /* Make sure we can understand the protocol, but otherwise ignore it. */
    found = 0;
    for(i=0;i<protocols->numprots;++i) {
	/* Look for the online coins protocol */
	if (protocols->prot_setup[i]->protocol == EC_M_PROT_ONLINE_COINS) {
	    found = 1;
	    break;
	}
    }
    EC_M_free_protocols(protocols);
    if (!found) {
	/* This bank doesn't speak online coins? */
	EC_M_free_bank_mkey(bank_mkey);
	return EC_ERR_INTERNAL;
    }

    /* The SETUP message was OK, and bank_mkey is now the bank's
       bank_mkey record.  Get the OPENACC1 message ready. */
    EC_M_clear_msg(msg);

    /* Get the next timestamp */
    stamp = EC_W_timestamp(*pwallet);
    if (!stamp) stamp = time(NULL);

    err = EC_P_create_openacc1(accID, currency,
	(*pwallet)->userrec->userkey->n, (*pwallet)->userrec->userkey->e,
	EC_M_PROT_ONLINE_COINS, account_password, bank_mkey, stamp, msg);
    if (err) {
	EC_M_free_bank_mkey(bank_mkey);
	return EC_ERR_INTERNAL;
    }

    /* Store the bank_mkey record in the wallet */
    err = EC_W_bankkeys_write(*pwallet, bank_mkey);
    if (err) {
	EC_M_free_bank_mkey(bank_mkey);
	return EC_ERR_INTERNAL;
    }

    /* Finally, store any info we've got in the wallet's userrec */
    newuserrec = EC_M_clone_userrec((*pwallet)->userrec);
    if (!newuserrec) {
	EC_M_free_bank_mkey(bank_mkey);
	return EC_ERR_INTERNAL;
    }
    newuserrec->bankID = bank_mkey->bankID;
    EC_M_free_bank_mkey(bank_mkey);
    newuserrec->currency = currency;
    if (newuserrec->username) EC_G_free(newuserrec->username);
    newuserrec->username = EC_G_strdup(accID);
    if (!newuserrec->username) {
	EC_M_free_userrec(newuserrec);
	return EC_ERR_INTERNAL;
    }
    EC_M_free_userrec((*pwallet)->userrec);
    (*pwallet)->userrec = newuserrec;

    err = EC_W_user_write(*pwallet);
    if (err) {
	return EC_ERR_INTERNAL;
    }

    return EC_ERR_NONE;
}

/* Step 3:
    Before:
	pwallet points to the open wallet
	msg contains the OPENACC2/CURR/etc. message received
    After:
	*pwallet is NULL
	msg is empty, and should be free_msg()'d
*/
EC_Errno EC_W_wallet_create_3(EC_W_Wallet *pwallet, EC_M_Msg msg)
{
    EC_Errno err;
    EC_M_Bank_repl bank_repl = NULL;
    EC_M_Msg rmsg = NULL;
    EC_M_Error error = NULL;
    EC_M_Fieldtype fieldtype;
    EC_M_Rectype rectype;
    EC_M_Openacc2 openacc2 = NULL;

    if (!pwallet || !*pwallet || !msg)
	return EC_ERR_INTERNAL;

    err = EC_P_parse_bankhdr(msg, EC_W_find_mkey, pwallet, &bank_repl,
	    &rmsg, &error);
    if (err) {
	return err;
    }
    if (error) {
	/* An ERROR message was returned from the bank. */
	EC_W_handle_error(*pwallet, error);
	EC_M_free_error(error);
	return EC_ERR_INTERNAL;
    }

    /* Now we get to look at the received message.  We expect
       OPENACC2, CURR, and maybe some misc. stuff. */
    while (!(err = EC_M_examine_msg(&fieldtype, &rectype, rmsg))) {
	if (fieldtype == EC_M_FIELD_NONE) {
	    break;
	} else if (fieldtype != EC_M_FIELD_SOR) {
	    /* This shouldn't be; ignore the field */
	    err = EC_M_transfer_field(rmsg, NULL);
	    if (err) break;
	} else if (rectype == EC_M_REC_OPENACC2) {
	    EC_M_free_openacc2(openacc2);
	    openacc2 = NULL;
	    err = EC_M_decompile_openacc2(&openacc2, rmsg);
	    if (err) break;

	    /* Handle the OPENACC2 */
	    /* Check that the protocol and public key are correct, and
	       that the userid matches that in the bank_repl
	       message. */
	    if (openacc2->userID != bank_repl->userID ||
		openacc2->protocol != EC_M_PROT_ONLINE_COINS ||
		(!BN_is_zero(openacc2->n) &&
		    BN_cmp(openacc2->n, (*pwallet)->userrec->userkey->n))) {
		/* Mismatch. */
		err = EC_ERR_INTERNAL;
		break;
	    }
	    /* Save the sequence number */
	    bank_repl->msg_seq = openacc2->msg_seq;
	    /* Store the userID in the userrec of the wallet */
	    (*pwallet)->userrec->userID = openacc2->userID;
	    err = EC_W_user_write(*pwallet);
	    if (err) break;
	} else {
	    /* Handle the common messages */
	    err = EC_W_handle_common(*pwallet, rmsg);
	    if (err) break;
	}
    }
    EC_M_free_msg(rmsg);
    EC_M_free_openacc2(openacc2);

    if (err) {
	EC_M_free_bank_repl(bank_repl);
	return err;
    }

    /* Handle the bank_repl; note that we've loaded the sequence number
       with that from the openacc2 message. */
    err = EC_W_handle_bank_repl(*pwallet, bank_repl);
    EC_M_free_bank_repl(bank_repl);
    if (err) return err;

    /* That should be everything; close up */
    EC_W_wallet_close(*pwallet);
    *pwallet = NULL;

    return EC_ERR_NONE;
}

void EC_W_wallet_create_abort(EC_W_Wallet *pwallet)

{
    /* Just close the wallet */
    EC_W_wallet_close(*pwallet);
    *pwallet = NULL;
}
