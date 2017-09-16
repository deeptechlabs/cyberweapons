#include "lucre.h"

/*
   bank_encr =
     [
        int	keyno
        rsaenc
        encrypt
     ]
 */

EC_M_Bank_encr EC_M_new_bank_encr(UInt32 keyno, EC_M_Rsaenc rsaenc,
    EC_M_Encrypt encrypt)
{
    EC_M_Bank_encr newbank_encr;

    if (!rsaenc || !encrypt) return NULL;
    newbank_encr = (EC_M_Bank_encr) EC_G_malloc(sizeof(struct EC_M_Bank_encr_s));
    if (!newbank_encr) return newbank_encr;

    newbank_encr->keyno = keyno;
    newbank_encr->rsaenc = rsaenc;
    newbank_encr->encrypt = encrypt;
    return newbank_encr;
}

EC_M_Bank_encr EC_M_clone_bank_encr(EC_M_Bank_encr bank_encr)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Bank_encr newbank_encr;
    UInt32 keyno;
    EC_M_Rsaenc rsaenc = NULL;
    EC_M_Encrypt encrypt = NULL;
    
    err = EC_M_examine_bank_encr(bank_encr, &keyno, &rsaenc, &encrypt);
    if (!err) {
	newbank_encr = EC_M_new_bank_encr(keyno, rsaenc, encrypt);
	if (newbank_encr) return newbank_encr;
    }

    EC_M_free_rsaenc(rsaenc);
    EC_M_free_encrypt(encrypt);
    return NULL;
}

EC_Errno EC_M_examine_bank_encr(EC_M_Bank_encr bank_encr, UInt32 *keyno,
    EC_M_Rsaenc *rsaenc, EC_M_Encrypt *encrypt)
{ 
    UInt32 mykeyno;
    EC_M_Rsaenc myrsaenc;
    EC_M_Encrypt myencrypt;

    if (!bank_encr) return EC_ERR_INTERNAL;

    mykeyno = bank_encr->keyno;
    myrsaenc = EC_M_clone_rsaenc(bank_encr->rsaenc);
    myencrypt = EC_M_clone_encrypt(bank_encr->encrypt);

    if (!myrsaenc || !myencrypt) {
	/* Didn't copy properly; abort */
	EC_M_free_rsaenc(myrsaenc);
	EC_M_free_encrypt(myencrypt);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    if (keyno) *keyno = mykeyno;
    if (rsaenc) *rsaenc = myrsaenc; else EC_M_free_rsaenc(myrsaenc);
    if (encrypt) *encrypt = myencrypt; else EC_M_free_encrypt(myencrypt);
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_bank_encr(EC_M_Bank_encr bank_encr1, EC_M_Bank_encr bank_encr2)
{
    if (!bank_encr1 || !bank_encr2) return 1;

    if (bank_encr1->keyno != bank_encr2->keyno
     || EC_M_cmp_rsaenc(bank_encr1->rsaenc, bank_encr2->rsaenc)
     || EC_M_cmp_encrypt(bank_encr1->encrypt, bank_encr2->encrypt))
	return 1;

    return 0;
}

void EC_M_free_bank_encr(EC_M_Bank_encr bank_encr)
{
    if (bank_encr) {
	EC_M_free_rsaenc(bank_encr->rsaenc);
	EC_M_free_encrypt(bank_encr->encrypt);
	EC_G_free(bank_encr);
    }
}

EC_Errno EC_M_compile_bank_encr(EC_M_Bank_encr bank_encr, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!bank_encr || !bank_encr->rsaenc || !bank_encr->encrypt || !msg)
	return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_BANK_ENCR, msg);
    if (!err) err = EC_M_compile_int(bank_encr->keyno, msg);
    if (!err) err = EC_M_compile_rsaenc(bank_encr->rsaenc, msg);
    if (!err) err = EC_M_compile_encrypt(bank_encr->encrypt, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_bank_encr(EC_M_Bank_encr *bank_encr, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    UInt32 keyno;
    EC_M_Rsaenc rsaenc = NULL;
    EC_M_Encrypt encrypt = NULL;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_BANK_ENCR, msg);
    if (!err) err = EC_M_decompile_int(&keyno, msg);
    if (!err) err = EC_M_decompile_rsaenc(&rsaenc, msg);
    if (!err) err = EC_M_decompile_encrypt(&encrypt, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && bank_encr) {
	*bank_encr = EC_M_new_bank_encr(keyno, rsaenc, encrypt);
	if (!*bank_encr) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    EC_M_free_rsaenc(rsaenc);
    EC_M_free_encrypt(encrypt);
    return err;
}
