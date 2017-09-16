#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "lucre.h"

/* Return the full wallet name associated with a wallet id */
char *EC_W_wallet_getname(char *walletid)
{
    char *walletbase;
    char *walletname;

    /* In Unix, the wallet id is simply the name of a directory.  If it
       does not start with '/', it is relative to $HOME.  If it is NULL
       or "", default to $ECWALLET, or to EC_W_WALLET_DEFNAME. */
    walletbase = walletid;
    if (!walletbase || !*walletbase) walletbase = getenv("ECWALLET");
    if (!walletbase || !*walletbase) walletbase = EC_W_WALLET_DEFNAME;

    /* Make a copy */
    walletbase = EC_G_strdup(walletbase);
    if (!walletbase) return NULL;

    if (walletbase[0] == '/') {
        walletname = EC_G_strdup(walletbase);
    } else {
        char *homedir = getenv("HOME");
        /* What do we want to do if there's no $HOME...? */
        if (!homedir) return NULL;

        /* Allocate the new name */
        walletname =
            (char *)EC_G_malloc(strlen(homedir)+1+strlen(walletbase)+1);
        if (!walletname) {
	    EC_G_free(walletbase);
	    return NULL;
	}

        /* Construct the wallet name */
        strcpy(walletname, homedir);
        strcat(walletname, "/");
        strcat(walletname, walletbase);
    }

    EC_G_free(walletbase);
    return walletname;
}

char *EC_W_wallet_mkfname(char *walletname, char *filename, char *ext)
{
    char *fname;

    if (!walletname || !filename) return NULL;
    fname = (char *)EC_G_malloc(strlen(walletname)+1+strlen(filename)
				    +strlen(ext)+1);
    if (!fname) return fname;

    strcpy(fname, walletname);
    strcat(fname, "/");
    strcat(fname, filename);
    strcat(fname, ext);

    return fname;
}

/* Open a wallet and return a wallet handle */
EC_W_Wallet EC_W_wallet_open(char *walletid)
{
    EC_W_Wallet newwallet;
    char *walletname = NULL;
    char *lockfilename = NULL;
    int lockfd = -1;
    EC_M_Userrec userrec;
    EC_Errno err;

    newwallet = (EC_W_Wallet)EC_G_malloc(sizeof(struct EC_W_Wallet_s));
    if (!newwallet) return newwallet;

    /* Construct the fields of the wallet */
    walletname = EC_W_wallet_getname(walletid);
    lockfilename = EC_W_wallet_mkfname(walletname, EC_W_LOCKFILE, "");
    if (lockfilename) lockfd = open(lockfilename, O_RDWR);
    EC_G_free(lockfilename);

    if (!walletname || lockfd < 0) {
        if (walletname) EC_G_free(walletname);
        if (lockfd >= 0) close(lockfd);
        return NULL;
    }

    /* Get the userrecord, but don't attempt to get the private key */
    /* Get a READ lock first */
    err = EC_W_wallet_lockfd(lockfd, EC_W_LOCK_READ);
    if (err) {
	EC_G_free(walletname);
	close(lockfd);
	return NULL;
    }

    userrec = EC_W_user_read(walletname);
    if (!userrec) {
	EC_G_free(walletname);
	close(lockfd);
	return NULL;
    }

    /* OK; unlock the wallet */
    err = EC_W_wallet_lockfd(lockfd, EC_W_LOCK_UNLOCK);
    if (err) {
	EC_M_free_userrec(userrec);
	EC_G_free(walletname);
	close(lockfd);
	return NULL;
    }

    newwallet->name = walletname;
    newwallet->lockfd = lockfd;
    newwallet->locktype = EC_W_LOCK_UNLOCK;
    newwallet->passphrase = NULL;
    newwallet->userrec = userrec;
    newwallet->userprivkey = NULL;
    newwallet->bkey_cache = NULL;
    newwallet->curr_cache = NULL;

    return newwallet;
}

/* Start using a given passphrase for an already open wallet */
EC_Errno EC_W_wallet_usephrase(EC_W_Wallet wallet, char *passphrase)
{
    Byte *newphrase;
    EC_Errno err;
    EC_M_Encrypt privkey;
    EC_M_Msg privmsg;
    EC_M_Userprivkey userprivkey;
    Byte *key;
    UInt32 keylen;

    if (!wallet) return EC_ERR_INTERNAL;

    if (passphrase) {
	newphrase = EC_G_strdup(passphrase);
	if (!newphrase) return EC_ERR_INTERNAL;
    } else {
	newphrase = EC_G_malloc(1);
	if (!newphrase) return EC_ERR_INTERNAL;
	newphrase[0] = '\0';
    }

    if (wallet->passphrase) EC_G_free(wallet->passphrase);
    wallet->passphrase = newphrase;

    /* Free any private key that happens to alrady be there */
    EC_M_free_userprivkey(wallet->userprivkey);
    wallet->userprivkey = NULL;

    /* Now try to decode the private key. */

    if (!wallet || !wallet->userrec || !wallet->userrec->userkey)
	return EC_ERR_INTERNAL;

    /* First grab a copy */
    privkey = EC_M_clone_encrypt(wallet->userrec->userkey->privkey);
    if (!privkey) {
	return EC_ERR_INTERNAL;
    }

    /* Convert the passphrase to a key */
    err = EC_U_pass2key(EC_W_USER_CRYPTALG, newphrase, &key, &keylen);
    if (err) {
	EC_M_free_encrypt(privkey);
	return err;
    }

    /* Try to decrypt it */
    privmsg = EC_U_decrypt_msg(key, keylen, privkey);
    EC_M_free_data(key);
    if (!privmsg) {
	EC_M_free_encrypt(privkey);
	return EC_ERR_INTERNAL;
    }

    /* Now see if we can parse the result as a userprivkey */
    err = EC_M_decompile_userprivkey(&userprivkey, privmsg);
    EC_M_free_msg(privmsg);
    if (err) {
	return err;
    }

    /* Success! */
    wallet->userprivkey = userprivkey;

    return EC_ERR_NONE;
}

/* Set a passphrase for an open wallet that knows its private key (that is,
   the correct passphrase has been set) */
EC_Errno EC_W_wallet_setphrase(EC_W_Wallet wallet, char *passphrase)
{
    Byte *key;
    char *newphrase;
    UInt32 keylen;
    EC_M_Msg userprivmsg;
    EC_M_Encrypt userprivcrypt;
    EC_M_Encrypt oldprivkey;
    EC_Errno err;

    if (!wallet || !wallet->userprivkey) return EC_ERR_INTERNAL;

    if (passphrase) {
	newphrase = EC_G_strdup(passphrase);
	if (!newphrase) return EC_ERR_INTERNAL;
    } else {
	newphrase = EC_G_malloc(1);
	if (!newphrase) return EC_ERR_INTERNAL;
	newphrase[0] = '\0';
    }

    /* Convert the passphrase to a key */
    err = EC_U_pass2key(EC_W_USER_CRYPTALG, newphrase, &key, &keylen);
    if (err) {
	return err;
    }

    /* Compile the userprivkey */
    userprivmsg = EC_M_new_msg();
    if (!userprivmsg) {
	EC_G_free(newphrase);
	EC_M_free_data(key);
	return EC_ERR_INTERNAL;
    }
    err = EC_M_compile_userprivkey(wallet->userprivkey, userprivmsg);
    if (err) {
	EC_M_free_msg(userprivmsg);
	EC_G_free(newphrase);
	EC_M_free_data(key);
	return EC_ERR_INTERNAL;
    }

    /* Encrypt the compiled message */
    userprivcrypt = EC_U_encrypt_msg(EC_W_USER_CRYPTALG, key, keylen,
	userprivmsg);
    EC_M_free_data(key);
    if (!userprivcrypt) {
	EC_M_free_msg(userprivmsg);
	EC_G_free(newphrase);
	return EC_ERR_INTERNAL;
    }

    oldprivkey = wallet->userrec->userkey->privkey;
    wallet->userrec->userkey->privkey = userprivcrypt;

    /* Write it out */
    err = EC_W_user_write(wallet);
    if (err) {
	wallet->userrec->userkey->privkey = oldprivkey;
	EC_M_free_encrypt(userprivcrypt);
	EC_G_free(newphrase);
	return err;
    }

    /* Success. */
    if (wallet->passphrase) EC_G_free(wallet->passphrase);
    wallet->passphrase = newphrase;

    EC_M_free_encrypt(oldprivkey);
    return EC_ERR_NONE;
}

/* Close a wallet */
void EC_W_wallet_close(EC_W_Wallet wallet)
{
    if (!wallet) return;

    /* Free the fields */
    if (wallet->name) EC_G_free(wallet->name);
    if (wallet->lockfd >= 0) close(wallet->lockfd);
    if (wallet->passphrase) EC_G_free(wallet->passphrase);
    EC_M_free_userrec(wallet->userrec);
    EC_M_free_userprivkey(wallet->userprivkey);
    EC_M_free_bank_mkey(wallet->bkey_cache);
    EC_M_free_curr(wallet->curr_cache);

    /* Free the wallet */
    EC_G_free(wallet);
}

/* Lock a file descriptor */
EC_Errno EC_W_wallet_lockfd(int lockfd, EC_W_Locktype locktype)
{
    struct flock lockstruct;
    int lockcmd;
    int err;

    /* Set up the lock structure */
    lockstruct.l_whence = SEEK_SET;
    lockstruct.l_start = 0;
    lockstruct.l_len = 0;
    if (locktype == EC_W_LOCK_WRITE || locktype == EC_W_LOCK_WRITE_NOWAIT) {
        lockstruct.l_type = F_WRLCK;
    } else if (locktype == EC_W_LOCK_READ
	    || locktype == EC_W_LOCK_READ_NOWAIT) {
        lockstruct.l_type = F_RDLCK;
    } else {
        lockstruct.l_type = F_UNLCK;
    }

    /* What type of lock? */
    if (locktype == EC_W_LOCK_READ_NOWAIT
	|| locktype == EC_W_LOCK_WRITE_NOWAIT) {
	lockcmd = F_SETLK;
    } else {
	lockcmd = F_SETLKW;
    }

    /* Call the lock */
    err = fcntl(lockfd, lockcmd, &lockstruct);

    if (err) return EC_ERR_INTERNAL;

    return EC_ERR_NONE;
}

/* Lock a wallet */
EC_Errno EC_W_wallet_lock(EC_W_Wallet wallet, EC_W_Locktype locktype)
{
    EC_Errno err = EC_ERR_NONE;

    if (!wallet) return EC_ERR_INTERNAL;

    /* Don't bother locking if the locktype doesn't change */
    if (locktype == wallet->locktype
      || (locktype == EC_W_LOCK_READ_NOWAIT
           && wallet->locktype == EC_W_LOCK_READ)
      || (locktype == EC_W_LOCK_WRITE_NOWAIT
           && wallet->locktype == EC_W_LOCK_WRITE))
	return EC_ERR_NONE;

    /* Do the lock */
    err = EC_W_wallet_lockfd(wallet->lockfd, locktype);
    if (err) return err;

    /* Save the new lock type */
    if (locktype == EC_W_LOCK_WRITE || locktype == EC_W_LOCK_WRITE_NOWAIT) {
        wallet->locktype = EC_W_LOCK_WRITE;
    } else if (locktype == EC_W_LOCK_READ
	    || locktype == EC_W_LOCK_READ_NOWAIT) {
        wallet->locktype = EC_W_LOCK_READ;
    } else {
        wallet->locktype = EC_W_LOCK_UNLOCK;
    }

    return EC_ERR_NONE;
}

/* Unlock a wallet */
EC_Errno EC_W_wallet_unlock(EC_W_Wallet wallet)
{
    return EC_W_wallet_lock(wallet, EC_W_LOCK_UNLOCK);
}

/* Return the type of lock _we_ have open on a wallet */
EC_W_Locktype EC_W_wallet_get_locktype(EC_W_Wallet wallet)
{
    if (!wallet) return EC_W_LOCK_UNLOCK;

    return wallet->locktype;
}

/* Make a temporary lock and return the old lock type */
EC_Errno EC_W_wallet_templock(EC_W_Wallet wallet, EC_W_Locktype locktype,
    EC_W_Locktype *oldlock)
{
    if (!wallet || !oldlock) return EC_ERR_INTERNAL;

    *oldlock = wallet->locktype;

    /* Only lock if the temp lock is "higher" than the current one. */
    if (*oldlock == EC_W_LOCK_WRITE) return EC_ERR_NONE;
    else if (*oldlock == EC_W_LOCK_READ) {
	if (locktype != EC_W_LOCK_WRITE && locktype != EC_W_LOCK_WRITE_NOWAIT)
	    return EC_ERR_NONE;
    }
    else {
	if (locktype != EC_W_LOCK_WRITE && locktype != EC_W_LOCK_WRITE_NOWAIT
	 && locktype != EC_W_LOCK_READ && locktype != EC_W_LOCK_READ_NOWAIT)
	    return EC_ERR_NONE;
    }

    return EC_W_wallet_lock(wallet, locktype);
}
