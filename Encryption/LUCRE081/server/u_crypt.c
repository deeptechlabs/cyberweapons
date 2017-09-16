/* Utilities for encrypting and decrypting data */

#include <string.h>
#include "lucre.h"
#include "bn.h"
#include "rand.h"
#include "des.h"

/* Encrypt a supplied message using a given algorithm.  The valid algorithms
   are as follows:

   0 : no encryption
   1 : 112-bit 3DES, "broken" mode

   The msg passed to this function is freed if the function returns
   successfully; clone it first if you need to keep an unencrypted copy. */
EC_M_Encrypt EC_U_encrypt_msg(EC_M_Cryptalg algorithm, Byte *key,
    UInt32 keylen, EC_M_Msg msg)
{
    EC_M_Encrypt encrypt;
    Byte *xdata;
    UInt32 xlen;

    /* Make sure we have data */
    if ((keylen && !key) || !msg) return NULL;

    /* Handle the trivial (no encryption) algorithm */
    if (algorithm == EC_M_CRYPTALG_NONE) {
	/* Check that the key length is 0 */
	if (keylen != 0) {
	    return NULL;
	}

	/* Create the encrypt srtuct */
	xlen = msg->end - msg->begin;
	xdata = EC_M_clone_data(msg->data + msg->begin, xlen);
	if (!xdata) {
	    return NULL;
	}
	encrypt = EC_M_new_encrypt(0, NULL, 0, xlen, xdata, xlen);
	if (!encrypt) {
	    EC_M_free_data(xdata);
	    return NULL;
	}
    }
    else if (algorithm == EC_M_CRYPTALG_112_3DES) {
	Byte padding[8];
	UInt32 padlen;
	UInt32 size;
	EC_Errno err;
	des_key_schedule keysched[2];
	des_cblock iv[2];
	Byte ivsave[16];
	Byte *ivdata;

	/* 112-bit 3DES; make sure the key length is right */
	if (keylen != 16) return NULL;

	/* Calculate the size of the message */
	size = msg->end - msg->begin;

	/* Create between 0 and 7 bytes of random padding, to bring the
	   length of the message to 1 byte less than a multiple of 8. */
	padlen = 7 - (size%8);
	if (padlen) RAND_bytes(padding, padlen);
	err = EC_M_append_msg(padding, padlen, msg);
	if (err) {
	    msg->end = msg->begin+size;
	    return NULL;
	}

	/* Append 1 more byte, which is a copy of the last byte in the msg
	   (including the recently-added padding) */
	err = EC_M_append_msg(msg->data+msg->end-1, 1, msg);
	if (err) {
	    msg->end = msg->begin+size;
	    return NULL;
	}

	/* The length of the encrypted data should now be a multiple of 8.
	   Get a copy of it. */
	xlen = msg->end - msg->begin;
	xdata = EC_M_clone_data(msg->data + msg->begin, xlen);
	msg->end = msg->begin+size;
	if (!xdata || (xlen % 8)) {
	    EC_M_free_data(xdata);
	    return NULL;
	}

	/* We're just about ready to encrypt; create the keyschedules */
	des_set_key((des_cblock *)key, keysched[0]);
	des_set_key((des_cblock *)(key+8), keysched[1]);

	/* Create two random initialization vectors and keep copies */
	RAND_bytes((Byte *)iv[0], 8);
	RAND_bytes((Byte *)iv[1], 8);
	memmove(ivsave, (Byte *)iv[0], 8);
	memmove(ivsave+8, (Byte *)iv[1], 8);

	/* Encrypt! */
	des_3cbc_encrypt((des_cblock *)xdata, (des_cblock *)xdata, xlen,
	    keysched[0], keysched[1], &(iv[0]), &(iv[1]), DES_ENCRYPT);

	/* Create the encrypt structure */
	ivdata = EC_M_clone_data(ivsave, 16);
	encrypt = EC_M_new_encrypt(algorithm, ivdata, 16, size, xdata, xlen);
	if (!encrypt) {
	    EC_M_free_data(ivdata);
	    EC_M_free_data(xdata);
	}
    }
    else {
	/* Unknown algorithm */
	return NULL;
    }

    /* Free the supplied msg, and return the encrypted version */
    EC_M_free_msg(msg);
    return encrypt;
}

/* RSA-encrypt a message using a specified underlying algorithm (as above).
   For 3DES-encryption, the RSA modulus must be at least 73 bytes (584 bits)
   long.
   As above, the supplied message is freed if this function returns
   successfully. */
EC_M_Bank_encr EC_U_rsa_encrypt_msg(EC_M_Cryptalg algorithm, UInt32 keyno,
    BIGNUM *n, BIGNUM *e, EC_M_Msg msg)
{
    EC_M_Bank_encr bank_encr;
    EC_M_Rsaenc rsaenc;
    EC_M_Encrypt encrypt;
    BIGNUM *rsakey;
    EC_M_Msg savemsg;

    /* Check the arguments */
    if (!msg) return NULL;

    /* Save a copy of the message to fiddle with */
    savemsg = EC_M_clone_msg(msg);
    if (!savemsg) return NULL;

    if (algorithm == EC_M_CRYPTALG_NONE) {
	/* No encryption */

	/* Construct a trivial RSA key */
	rsakey = BN_new();
	if (!rsakey) {
	    EC_M_free_msg(savemsg);
	    return NULL;
	}
	BN_zero(rsakey);
	rsaenc = EC_M_new_rsaenc(rsakey);
	if (!rsaenc) { 
	    EC_M_free_msg(savemsg);
	    BN_free(rsakey);
	    return NULL;
	}
	
	/* No encryption; just wrap the message in an encrypt structure */
	encrypt = EC_U_encrypt_msg(0, NULL, 0, savemsg);
	if (!encrypt) {
	    EC_M_free_msg(savemsg);
	    EC_M_free_rsaenc(rsaenc);
	    return NULL;
	}

	/* Create the bank_encr */
	bank_encr = EC_M_new_bank_encr(keyno, rsaenc, encrypt);
	if (!bank_encr) {
	    EC_M_free_rsaenc(rsaenc);
	    EC_M_free_encrypt(encrypt);
	    return NULL;
	}
    }
    else if (algorithm == EC_M_CRYPTALG_112_3DES) {
	/* 112-bit 3DES */
	UInt32 modlength;
	Byte deskey[16];
	Byte *randkey;
	BIGNUM *rsakey;
	BN_CTX *ctx;

	if (!n || !e) {
	    EC_M_free_msg(savemsg);
	    return NULL;
	}

	/* Check that the modulus is long enough */
	modlength = BN_num_bytes(n);
	if (modlength < 73) {
	    EC_M_free_msg(savemsg);
	    return NULL;
	}

	/* Create a buffer to hold the random RSA key */
	randkey = EC_G_malloc(modlength - 1);
	if (!randkey) {
	    EC_M_free_msg(savemsg);
	    return NULL;
	}

	/* Create a random RSA key */
	RAND_bytes(randkey, modlength - 1);

	/* Make sure it's the right length, and not too short */
	while(randkey[0] == 0) {
	    RAND_bytes(randkey, 1);
	}

	/* Extract a DES key from it */
	memmove(deskey, randkey+64, 8);
	memmove(deskey+8, randkey, 8);

	/* Turn the RSA key into a BIGNUM and free the buffer */
	rsakey = BN_bin2bn(randkey, modlength - 1, NULL);
	EC_G_free(randkey);
	if (!rsakey) {
	    EC_M_free_msg(savemsg);
	    return NULL;
	}

	/* Encrypt the RSA key */
	ctx = BN_CTX_new();
	if (!ctx) {
	    EC_M_free_msg(savemsg);
	    BN_free(rsakey);
	    return NULL;
	}
	if (!BN_mod_exp(rsakey, rsakey, e, n, ctx)) {
	    EC_M_free_msg(savemsg);
	    BN_free(rsakey);
	    BN_CTX_free(ctx);
	    return NULL;
	}
	BN_CTX_free(ctx);

	/* Construct the rsaenc structure */
	rsaenc = EC_M_new_rsaenc(rsakey);
	if (!rsaenc) {
	    EC_M_free_msg(savemsg);
	    BN_free(rsakey);
	    return NULL;
	}

	/* Encrypt the message */
	encrypt = EC_U_encrypt_msg(1, deskey, 16, savemsg);
	if (!encrypt) {
	    EC_M_free_msg(savemsg);
	    EC_M_free_rsaenc(rsaenc);
	    return NULL;
	}

	/* Create the bank_encr structure */
	bank_encr = EC_M_new_bank_encr(keyno, rsaenc, encrypt);
	if (!bank_encr) {
	    EC_M_free_rsaenc(rsaenc);
	    EC_M_free_encrypt(encrypt);
	    return NULL;
	}
    }
    else {
	/* Unknown algorithm */
	return NULL;
    }

    /* Free the msg and return the bank_encr */
    EC_M_free_msg(msg);
    return bank_encr;
}

/* Decrypt a supplied EC_M_Encrypt with a given key.  If successful, a
   newly-alocated EC_M_Msg is returned, and the EC_M_Encrypt is freed.
   Otherwise, NULL is returned. */
EC_M_Msg EC_U_decrypt_msg(Byte *key, UInt32 keylen, EC_M_Encrypt encrypt)
{
    EC_M_Msg clearmsg;
    EC_Errno err;

    /* Make sure we have data */
    if ((keylen && !key) || !encrypt || (encrypt->xlen && !encrypt->xdata)
	|| (encrypt->ivlen && !encrypt->ivdata))
	return NULL;

    /* What algorithm are we using? */
    if (encrypt->algorithm == EC_M_CRYPTALG_NONE) {
	/* Make sure we have enough data */
	if (encrypt->xlen < encrypt->size) return NULL;

	/* Create a new message */
	clearmsg = EC_M_new_msg();
	if (!clearmsg) return NULL;

	/* Get the data */
	err = EC_M_append_msg(encrypt->xdata, encrypt->size, clearmsg);
	if (err) {
	    EC_M_free_msg(clearmsg);
	    return NULL;
	}
    }
    else if (encrypt->algorithm == EC_M_CRYPTALG_112_3DES) {
	des_key_schedule keysched[2];
	des_cblock iv[2];
	Byte *xcopy;

	/* Make sure things are of the right lengths */
	if (keylen != 16 || encrypt->ivlen != 16 || (encrypt->xlen % 8)
	    || (encrypt->xlen < (encrypt->size + 1)))
	    return NULL;

	/* Set up the key schedules and the IVs */
	des_set_key((des_cblock *)key, keysched[0]);
	des_set_key((des_cblock *)(key+8), keysched[1]);
	memmove((Byte *)iv[0], encrypt->ivdata, 8);
	memmove((Byte *)iv[1], encrypt->ivdata+8, 8);

	/* Get a copy of the encrypted data */
	xcopy = EC_M_clone_data(encrypt->xdata, encrypt->xlen);
	if (!xcopy) return NULL;

	/* Decrypt it */
	des_3cbc_encrypt((des_cblock *)xcopy, (des_cblock *)xcopy,
	    encrypt->xlen, keysched[0], keysched[1], &(iv[0]), &(iv[1]),
	    DES_DECRYPT);

	/* Check that it decrypted OK */
	if (xcopy[encrypt->xlen-2] != xcopy[encrypt->xlen-1]) {
	    /* Nope; bad decryption! */
	    EC_M_free_data(xcopy);
	    return NULL;
	}

	/* It should be OK now; create a new message */
	clearmsg = EC_M_new_msg();
	if (!clearmsg) {
	    EC_M_free_data(xcopy);
	    return NULL;
	}

	/* Get the data */
	err = EC_M_append_msg(xcopy, encrypt->size, clearmsg);
	EC_M_free_data(xcopy);
	if (err) {
	    EC_M_free_msg(clearmsg);
	    return NULL;
	}
    }
    else {
	/* Unknown algorithm */
	return NULL;
    }

    /* free the encrypt structure and return the message */
    EC_M_free_encrypt(encrypt);
    return clearmsg;
}

/* RSA-decrypt a supplied EC_M_Bank_encr with a given key.  If
   successful, a newly-alocated EC_M_Msg is returned, and the
   EC_M_Bank_encr is freed.  Otherwise, NULL is returned.  The comments
   pertaining to EC_U_rsa_decrypt_msg(), above, apply here as well. */
EC_M_Msg EC_U_rsa_decrypt_msg(BIGNUM *n, BIGNUM *d, EC_M_Bank_encr bank_encr)
{
    EC_M_Msg msg;
    EC_M_Encrypt encrypt;
    Byte *key;
    UInt32 keylen;
    EC_Errno err;

    /* Check the arguments */
    if (!bank_encr || !bank_encr->encrypt) return NULL;

    /* Save a copy of the encrypt to pass to EC_U_decrypt_msg() */
    err = EC_M_examine_bank_encr(bank_encr, NULL, NULL, &encrypt);
    if (err) return NULL;

    /* Extract the key, depending on the algorithm */
    if (encrypt->algorithm == EC_M_CRYPTALG_NONE) {
	/* There's no key to get */
	key = NULL;
	keylen = 0;
    }
    else if (encrypt->algorithm == EC_M_CRYPTALG_112_3DES) {
	BIGNUM *result;
	BN_CTX *ctx;
	Byte *keybuf;
	UInt32 modlength;
	int i;

	if (!n || !d || !bank_encr->rsaenc || !bank_encr->rsaenc->key) {
	    EC_M_free_encrypt(encrypt);
	    return NULL;
	}

	/* Make sure the modulus is big enough */
	modlength = BN_num_bytes(n);
	if (modlength < 73) {
	    EC_M_free_encrypt(encrypt);
	    return NULL;
	}

	/* Allocate a buffer to hold the decrypted key */
	keybuf = (Byte *)EC_G_malloc(modlength);
	if (!keybuf) {
	    EC_M_free_encrypt(encrypt);
	    return NULL;
	}
	/* Zero the buffer */
	for (i=0;i<modlength;++i) keybuf[i] = 0;

	/* Try to decrypt the RSA key */
	ctx = BN_CTX_new();
	if (!ctx) {
	    EC_M_free_encrypt(encrypt);
	    EC_G_free(keybuf);
	    return NULL;
	}
	result = BN_new();
	if (!result) {
	    BN_CTX_free(ctx);
	    EC_M_free_encrypt(encrypt);
	    EC_G_free(keybuf);
	    return NULL;
	}
	if (!BN_mod_exp(result, bank_encr->rsaenc->key, d, n, ctx)) {
	    BN_free(result);
	    BN_CTX_free(ctx);
	    EC_M_free_encrypt(encrypt);
	    EC_G_free(keybuf);
	    return NULL;
	}
	BN_CTX_free(ctx);

	/* Put the decrypted number _right-aligned_ into the buffer
	   and free the result */
	BN_bn2bin(result, keybuf + modlength - BN_num_bytes(result));
	BN_free(result);

	/* Make sure the high byte is 0 */
	if (keybuf[0] != 0) {
	    /* We decrypted wrong */
	    EC_M_free_encrypt(encrypt);
	    EC_G_free(keybuf);
	    return NULL;
	}

	/* Extract the DES key from the buffer and free the buffer */
	key = EC_G_malloc(16);
	if (!key) {
	    EC_M_free_encrypt(encrypt);
	    EC_G_free(keybuf);
	    return NULL;
	}
	memmove(key, keybuf+65, 8);
	memmove(key+8, keybuf+1, 8);
	keylen = 16;
	EC_G_free(keybuf);

    }
    else {
	/* Unknown algorithm */
	return NULL;
    }

    /* At this point, the active variables are key, keylen, and encrypt */

    /* Decrypt the message */
    msg = EC_U_decrypt_msg(key, keylen, encrypt);
    if (key) EC_G_free(key);
    if (!msg) {
	/* The decryption failed! */
	EC_M_free_encrypt(encrypt);
	return NULL;
    }

    /* Success. */
    EC_M_free_bank_encr(bank_encr);
    return msg;
}

/* Convert a passphrase into a key */
EC_Errno EC_U_pass2key(EC_M_Cryptalg algorithm, char *passphrase,
    Byte **pkey, UInt32 *pkeylen)
{
    Byte *key;
    UInt32 keylen;

    if (!pkey || !pkeylen) return EC_ERR_INTERNAL;

    if (algorithm == EC_M_CRYPTALG_NONE) {
        /* No key for this algorithm */
        key = NULL;
        keylen = 0;
    }
    else if (algorithm == EC_M_CRYPTALG_112_3DES) {
        key = (Byte *)EC_G_malloc(16);
        if (!key) {
            return EC_ERR_INTERNAL;
        }
        keylen = 16;
	des_string_to_2keys(passphrase ? passphrase : "",
	    (des_cblock *)key, (des_cblock *)(key+8));
    }
    else {
        /* Unknown algorithm; just pass the pass phrase on as the key */
        key = (Byte *)EC_G_strdup(passphrase ? passphrase : "");
        if (!key) {
            return EC_ERR_INTERNAL;
        }
        keylen = strlen(key);
    }

    *pkey = key;
    *pkeylen = keylen;

    return EC_ERR_NONE;
}
