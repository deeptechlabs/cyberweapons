#include <unistd.h>
#include <time.h>
#include "lucre.h"

/* Handle the messages that may come from the bank at any time */
EC_Errno EC_W_handle_common(EC_W_Wallet wallet, EC_M_Msg msg)
{
    EC_Errno err;
    EC_M_Fieldtype fieldtype;
    EC_M_Rectype rectype;
    EC_M_Error error;
    EC_M_Curr curr;
    EC_M_Statement statement;
    char logstr[100];

    /* What kind of message is it? */
    err = EC_M_examine_msg(&fieldtype, &rectype, msg);
    if (err) return err;

    if (fieldtype != EC_M_FIELD_SOR) {
	/* Just dump the field */

	err = EC_M_transfer_field(msg, NULL);
	if (err) return err;

    } else {
	switch(rectype) {
	case EC_M_REC_WITHDRAW2:
	case EC_M_REC_QUIT:
	case EC_M_REC_DONE:
	    /* Silently ignore WITHDRAW2, QUIT, and DONE */
	    err = EC_M_transfer_field(msg, NULL);
	    if (err) return err;
	    break;

	case EC_M_REC_CURR:
	    /* Handle currency information */

	    err = EC_M_decompile_curr(&curr, msg);
	    if (err) return err;
	    err = EC_W_curr_write(wallet, wallet->userrec->bankID, curr);
	    EC_M_free_curr(curr);
	    if (err) return err;
	    break;

	case EC_M_REC_STATEMENT:
	    /* Handle STATEMENT records */

	    err = EC_M_decompile_statement(&statement, msg);
	    if (err) return err;
	    err = EC_W_statement_write(wallet, statement);
	    EC_M_free_statement(statement);
	    if (err) return err;
	    break;

	case EC_M_REC_ERROR:
	    /* Handle an error */

	    err = EC_M_decompile_error(&error, msg);
	    if (err) return err;
	    err = EC_W_handle_error(wallet, error);
	    EC_M_free_error(error);
	    if (err) return err;
	    break;

	default:
	    /* Everything else we ignore and log */

	    sprintf(logstr, "Record type %d encountered and ignored", rectype);
	    EC_G_log(EC_LOGLEVEL_NOTICE, logstr);
	    err = EC_M_transfer_field(msg, NULL);
	    if (err) return err;
	    break;
	}
    }

    return EC_ERR_NONE;
}

/* Handle an Error message */
EC_Errno EC_W_handle_error(EC_W_Wallet wallet, EC_M_Error error)
{
    /* Do nothing with it just yet */
    char logstr[100];

    sprintf(logstr, "Error message %d received from bank", error->errno);
    EC_G_log(EC_LOGLEVEL_NOTICE, logstr);
    return EC_ERR_NONE;
}

/* Handle a bank_repl */
EC_Errno EC_W_handle_bank_repl(EC_W_Wallet wallet, EC_M_Bank_repl bank_repl)
{
    EC_M_Status status;
    EC_Errno err = EC_ERR_NONE;

    /* Just make sure that the userid is OK, and then record the
	sequence number */
    if (!wallet || !bank_repl) return EC_ERR_INTERNAL;

    if (wallet->userrec->userID != bank_repl->userID) return EC_ERR_INTERNAL;

    if (bank_repl->msg_seq == 0) return EC_ERR_NONE;

    /* Update the sequence number in the wallet */
    status = EC_W_status_read(wallet);
    if (!status) return EC_ERR_INTERNAL;

    if (bank_repl->msg_seq > status->msg_seq) {
	status->msg_seq = bank_repl->msg_seq;
	err = EC_W_status_write(wallet, status);
    }
    EC_M_free_status(status);

    return err;
}

/* Handle a STATEMENT */
EC_Errno EC_W_statement_write(EC_W_Wallet wallet, EC_M_Statement statement)
{
    EC_M_Status status;
    EC_Errno err = EC_ERR_NONE;

    if (!wallet || !statement) return EC_ERR_INTERNAL;

    /* Update the statement in the wallet */
    status = EC_W_status_read(wallet);
    if (!status) return EC_ERR_INTERNAL;

    status->balance = statement->balance;
    err = EC_W_status_write(wallet, status);
    EC_M_free_status(status);

    return err;
}

/* Get the next timestamp */
time_t EC_W_timestamp(EC_W_Wallet wallet)
{
    EC_M_Status status;
    time_t stamp = time(NULL);

    if (!wallet) return 0;

    /* Get the lower bound on the next timestamp */
    status = EC_W_status_read(wallet);
    if (!status) return 0;

    if (stamp < status->nextstamp) stamp = status->nextstamp;

    /* Update the lower bound */
    status->nextstamp = stamp + 1;

    /* What if the write fails?  Cheat by sleeping for 2 seconds, thus
       guaranteeing that the next timestamp will be bigger... :-) */
    if (EC_W_status_write(wallet, status)) sleep(2);

    EC_M_free_status(status);
    return stamp;
}
