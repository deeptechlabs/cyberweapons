#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include "lucre.h"

/* Read the status file from a given wallet. */
EC_M_Status EC_W_status_read(EC_W_Wallet wallet)
{
    EC_Errno err;
    int statusfd;
    char *statusfname;
    EC_M_Msg statusmsg;
    EC_M_Status status;
    EC_M_Status defstatus;
    EC_W_Locktype oldlock;

    if (!wallet) return NULL;

    /* Make a default status */
    defstatus = EC_M_new_status(0, 0, 0, 0, 0);
    
    /* Get a read lock on the wallet */
    err = EC_W_wallet_templock(wallet, EC_W_LOCK_READ, &oldlock);
    if (err) {
        return defstatus;
    }

    /* Construct the statusfname */
    statusfname = EC_W_wallet_mkfname(wallet->name, EC_W_STATUSFNAME, "");
    if (!statusfname) {
	EC_W_wallet_lock(wallet, oldlock);
	return defstatus;
    }

    /* Try to create the file. */
    statusfd = open(statusfname, O_RDONLY);
    EC_G_free(statusfname);
    if (statusfd < 0) {
	EC_W_wallet_lock(wallet, oldlock);
	return defstatus;
    }

    /* Read the file into a msg */
    statusmsg = EC_M_new_msg();
    if (!statusmsg) {
	EC_W_wallet_lock(wallet, oldlock);
	return defstatus;
    }
    err = EC_M_BTE_decode(statusmsg, EC_G_read_in, &statusfd);
    close(statusfd);
    EC_W_wallet_lock(wallet, oldlock);
    if (err) {
	EC_M_free_msg(statusmsg);
	return defstatus;
    }

    /* Parse the msg as a status */
    err = EC_M_decompile_status(&status, statusmsg);
    EC_M_free_msg(statusmsg);
    if (err) {
	return defstatus;
    }

    /* Should be OK */
    EC_M_free_status(defstatus);
    return status;
}

/* Write a status to a wallet's status file. */
EC_Errno EC_W_status_write(EC_W_Wallet wallet, EC_M_Status status)
{
    char *statusfname, *newstatusfname;
    int statusfd;
    EC_M_Msg statusmsg;
    EC_Errno err;
    EC_W_Locktype oldlock;
    int uerr;

    if (!wallet || !status) return EC_ERR_INTERNAL;

    /* Compile the status record */
    statusmsg = EC_M_new_msg();
    if (!statusmsg) {
	return EC_ERR_INTERNAL;
    }
    err = EC_M_compile_status(status, statusmsg);
    if (err) {
	EC_M_free_msg(statusmsg);
	return EC_ERR_INTERNAL;
    }

    /* Get a write lock on the wallet */
    err = EC_W_wallet_templock(wallet, EC_W_LOCK_WRITE, &oldlock);
    if (err) {
        EC_M_free_msg(statusmsg);
        return EC_ERR_INTERNAL;
    }

    /* Open the status file */
    statusfname = EC_W_wallet_mkfname(wallet->name, EC_W_STATUSFNAME, "");
    newstatusfname = EC_W_wallet_mkfname(wallet->name, EC_W_STATUSFNAME,
	".new");
    if (!statusfname || !newstatusfname) {
	if (statusfname) EC_G_free(statusfname);
	if (newstatusfname) EC_G_free(newstatusfname);
	EC_W_wallet_lock(wallet, oldlock);
	EC_M_free_msg(statusmsg);
	return EC_ERR_INTERNAL;
    }

    /* Try to create the file. */
    statusfd = open(newstatusfname, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR);
    if (statusfd < 0) {
	EC_G_free(statusfname);
	EC_G_free(newstatusfname);
	EC_M_free_msg(statusmsg);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Write the record */
    err = EC_M_BTE_encode(statusmsg, EC_G_write_out, &statusfd);
    EC_M_free_msg(statusmsg);
    close(statusfd);
    if (err) {
	unlink(newstatusfname);
	EC_G_free(statusfname);
	EC_G_free(newstatusfname);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Rename the new file */
    uerr = rename(newstatusfname, statusfname);
    EC_W_wallet_lock(wallet, oldlock);
    if (uerr) {
	unlink(newstatusfname);
	EC_G_free(statusfname);
	EC_G_free(newstatusfname);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    EC_G_free(statusfname);
    EC_G_free(newstatusfname);
    return EC_ERR_NONE;
}
