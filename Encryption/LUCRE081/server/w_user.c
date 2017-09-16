#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include "lucre.h"
#include "rsa.h"

/* Create a user file for a named wallet, if necessary.  If the file
   needs to be created, use the given key to encrypt the secret parts.
   Before you call this, make sure the wallet is locked for writing.
   The parameters keybits, e_value, and callback are passed to the
   RSA generation function. */
EC_Errno EC_W_user_create(char *walletname, char *passphrase,
    Int16 keybits, UInt32 e_value, void (*callback)(int, int))
{
    EC_Errno err;
    int userfd;
    char *userfname, *blankusername;
    EC_M_Userprivkey userprivkey;
    EC_M_Msg userprivmsg;
    EC_M_Encrypt userprivcrypt;
    EC_M_Userkey userkey;
    EC_M_Userrec userrec;
    EC_M_Msg userrecmsg;
    RSA *rsakey;
    BIGNUM *key_n;
    BIGNUM *key_e;
    BIGNUM *key_d;
    BIGNUM *key_p;
    BIGNUM *key_q;
    BIGNUM *key_iqmp;
    Byte *key;
    UInt32 keylen;

    if (!walletname) return EC_ERR_INTERNAL;

    /* Construct the userfname */
    userfname = EC_W_wallet_mkfname(walletname, EC_W_USERFNAME, "");
    if (!userfname) return EC_ERR_INTERNAL;

    /* Try to create the file.  Note: this is called from wallet_create(),
       so we know we have a write lock. */
    userfd = open(userfname, O_CREAT|O_EXCL|O_APPEND|O_WRONLY,
	S_IRUSR|S_IWUSR);
    if (userfd < 0 && errno != EEXIST) {
	/* We failed to create the file, and not because it already existed. */
	EC_G_free(userfname);
	return EC_ERR_INTERNAL;
    } else if (userfd < 0) {
	/* The file already exists.  That's fine. */
	EC_G_free(userfname);
	return EC_ERR_NONE;
    }

    /* We now have a fd open for writing to the user file, so create a
       user record.  We don't have much information yet, so this will
       be pretty sparse. */

    /* Create a userkey.  This is exciting.  Maybe change the NULL
       below, so the user can see something happening? */
    rsakey = RSA_generate_key((int)keybits, (unsigned long)e_value, callback);
    if (!rsakey) {
	close(userfd);
	unlink(userfname);
	EC_G_free(userfname);
	return EC_ERR_INTERNAL;
    }
    
    /* Make copies of the BIGNUMs */
    key_n = EC_M_clone_MPI(rsakey->n);
    key_e = EC_M_clone_MPI(rsakey->e);
    key_d = EC_M_clone_MPI(rsakey->d);
    key_p = EC_M_clone_MPI(rsakey->p);
    key_q = EC_M_clone_MPI(rsakey->q);
    key_iqmp = EC_M_clone_MPI(rsakey->iqmp);
    RSA_free(rsakey);
    if (!key_n || !key_e || !key_d || !key_p || !key_q || !key_iqmp) {
	EC_M_free_MPI(key_n);
	EC_M_free_MPI(key_e);
	EC_M_free_MPI(key_d);
	EC_M_free_MPI(key_p);
	EC_M_free_MPI(key_q);
	EC_M_free_MPI(key_iqmp);
	close(userfd);
	unlink(userfname);
	EC_G_free(userfname);
	return EC_ERR_INTERNAL;
    }

    /* Store the private key and compile it */
    userprivkey = EC_M_new_userprivkey(key_d, key_q, key_p, key_iqmp);
    if (!userprivkey) {
	EC_M_free_MPI(key_n);
	EC_M_free_MPI(key_e);
	EC_M_free_MPI(key_d);
	EC_M_free_MPI(key_p);
	EC_M_free_MPI(key_q);
	EC_M_free_MPI(key_iqmp);
	close(userfd);
	unlink(userfname);
	EC_G_free(userfname);
	return EC_ERR_INTERNAL;
    }
    userprivmsg = EC_M_new_msg();
    if (!userprivmsg) {
	EC_M_free_userprivkey(userprivkey);
	EC_M_free_MPI(key_n);
	EC_M_free_MPI(key_e);
	close(userfd);
	unlink(userfname);
	EC_G_free(userfname);
	return EC_ERR_INTERNAL;
    }

    err = EC_M_compile_userprivkey(userprivkey, userprivmsg);
    EC_M_free_userprivkey(userprivkey);
    if (err) {
	EC_M_free_msg(userprivmsg);
	EC_M_free_MPI(key_n);
	EC_M_free_MPI(key_e);
	close(userfd);
	unlink(userfname);
	EC_G_free(userfname);
	return EC_ERR_INTERNAL;
    }

    /* Generate the key from the pass phrase */
    err = EC_U_pass2key(EC_W_USER_CRYPTALG, passphrase, &key, &keylen);
    if (err) {
	EC_M_free_msg(userprivmsg);
	EC_M_free_MPI(key_n);
	EC_M_free_MPI(key_e);
	close(userfd);
	unlink(userfname);
	EC_G_free(userfname);
	return EC_ERR_INTERNAL;
    }

    /* Encrypt the compiled message */
    userprivcrypt = EC_U_encrypt_msg(EC_W_USER_CRYPTALG, key, keylen,
	    userprivmsg);
    if (key) EC_G_free(key);
    if (!userprivcrypt) {
	EC_M_free_msg(userprivmsg);
	EC_M_free_MPI(key_n);
	EC_M_free_MPI(key_e);
	close(userfd);
	unlink(userfname);
	EC_G_free(userfname);
	return EC_ERR_INTERNAL;
    }

    /* Create the user key record */
    userkey = EC_M_new_userkey(key_n, key_e, 1, userprivcrypt);
    if (!userkey) {
	EC_M_free_encrypt(userprivcrypt);
	EC_M_free_MPI(key_n);
	EC_M_free_MPI(key_e);
	close(userfd);
	unlink(userfname);
	EC_G_free(userfname);
	return EC_ERR_INTERNAL;
    }

    /* Create a blank username */
    blankusername = EC_G_malloc(1);
    if (!blankusername) {
	EC_M_free_userkey(userkey);
	close(userfd);
	unlink(userfname);
	EC_G_free(userfname);
	return EC_ERR_INTERNAL;
    }
    blankusername[0] = '\0';

    /* Create the user record */
    userrec = EC_M_new_userrec(0, userkey, 0, 0, blankusername);
    if (!userrec) {
	EC_G_free(blankusername);
	EC_M_free_userkey(userkey);
	close(userfd);
	unlink(userfname);
	EC_G_free(userfname);
	return EC_ERR_INTERNAL;
    }

    /* Compile the user record */
    userrecmsg = EC_M_new_msg();
    if (!userrecmsg) {
	EC_M_free_userrec(userrec);
	close(userfd);
	unlink(userfname);
	EC_G_free(userfname);
	return EC_ERR_INTERNAL;
    }
    err = EC_M_compile_userrec(userrec, userrecmsg);
    EC_M_free_userrec(userrec);
    if (err) {
	EC_M_free_msg(userrecmsg);
	close(userfd);
	unlink(userfname);
	EC_G_free(userfname);
	return EC_ERR_INTERNAL;
    }

    /* Finally, write the record */
    err = EC_M_BTE_encode(userrecmsg, EC_G_write_out, &userfd);
    EC_M_free_msg(userrecmsg);
    if (err) {
	close(userfd);
	unlink(userfname);
	EC_G_free(userfname);
	return EC_ERR_INTERNAL;
    }

    /* We're done! */

    close(userfd);
    EC_G_free(userfname);
    return EC_ERR_NONE;
}

/* Read the user file from a named wallet.  Do not extract the stuff inside
   it at this time. */
EC_M_Userrec EC_W_user_read(char *walletname)
{
    EC_Errno err;
    int userfd;
    char *userfname;
    EC_M_Msg usermsg;
    EC_M_Userrec userrec;

    if (!walletname) return NULL;

    /* Construct the userfname */
    userfname = EC_W_wallet_mkfname(walletname, EC_W_USERFNAME, "");
    if (!userfname) return NULL;

    /* Try to read the file.  Note: this is called from wallet_open(), so
       we know we have a read lock. */
    userfd = open(userfname, O_RDONLY);
    EC_G_free(userfname);
    if (userfd < 0) {
	return NULL;
    }

    /* Read the file into a msg */
    usermsg = EC_M_new_msg();
    if (!usermsg) {
	return NULL;
    }
    err = EC_M_BTE_decode(usermsg, EC_G_read_in, &userfd);
    close(userfd);
    if (err) {
	EC_M_free_msg(usermsg);
	return NULL;
    }

    /* Parse the msg as a userrec */
    err = EC_M_decompile_userrec(&userrec, usermsg);
    EC_M_free_msg(usermsg);
    if (err) {
	return NULL;
    }

    /* Should be OK */
    return userrec;
}

/* Write a wallet's userrec to its user file. */
EC_Errno EC_W_user_write(EC_W_Wallet wallet)
{
    char *userfname, *newuserfname;
    int userfd;
    EC_M_Msg userrecmsg;
    EC_Errno err;
    EC_W_Locktype oldlock;
    int uerr;

    if (!wallet || !wallet->userrec) return EC_ERR_INTERNAL;

    /* Compile the user record */
    userrecmsg = EC_M_new_msg();
    if (!userrecmsg) {
	return EC_ERR_INTERNAL;
    }
    err = EC_M_compile_userrec(wallet->userrec, userrecmsg);
    if (err) {
	EC_M_free_msg(userrecmsg);
	return err;
    }

    /* Get a write lock */
    err = EC_W_wallet_templock(wallet, EC_W_LOCK_WRITE, &oldlock);
    if (err) {
	EC_M_free_msg(userrecmsg);
	return err;
    }

    /* Open the user file */
    userfname = EC_W_wallet_mkfname(wallet->name, EC_W_USERFNAME, "");
    newuserfname = EC_W_wallet_mkfname(wallet->name, EC_W_USERFNAME, ".new");
    if (!userfname || !newuserfname) {
	if (userfname) EC_G_free(userfname);
	if (newuserfname) EC_G_free(newuserfname);
	EC_M_free_msg(userrecmsg);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Try to create the file.  Note: this is called from wallet_create(),
       so we know we have a write lock. */
    userfd = open(newuserfname, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR);
    if (userfd < 0) {
	EC_G_free(userfname);
	EC_G_free(newuserfname);
	EC_M_free_msg(userrecmsg);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Write the record */
    err = EC_M_BTE_encode(userrecmsg, EC_G_write_out, &userfd);
    EC_M_free_msg(userrecmsg);
    close(userfd);
    if (err) {
	unlink(newuserfname);
	EC_G_free(userfname);
	EC_G_free(newuserfname);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* Rename the new file */
    uerr = rename(newuserfname, userfname);
    if (uerr) {
	unlink(newuserfname);
	EC_G_free(userfname);
	EC_G_free(newuserfname);
	EC_W_wallet_lock(wallet, oldlock);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    EC_G_free(userfname);
    EC_G_free(newuserfname);
    EC_W_wallet_lock(wallet, oldlock);
    return EC_ERR_NONE;
}
