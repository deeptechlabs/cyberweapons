#include "lucre.h"

/*
   encrypt =
     [
        int	algorithm
        data	ivdata
        int	size
        data	xdata
     ]
 */

EC_M_Encrypt EC_M_new_encrypt(EC_M_Cryptalg algorithm, Byte *ivdata,
    UInt32 ivlen, UInt32 size, Byte *xdata, UInt32 xlen)
{
    EC_M_Encrypt newencrypt;

    if ((ivlen && !ivdata) || (xlen && !xdata)) return NULL;
    newencrypt = (EC_M_Encrypt) EC_G_malloc(sizeof(struct EC_M_Encrypt_s));
    if (!newencrypt) return newencrypt;

    newencrypt->algorithm = algorithm;
    newencrypt->ivdata = ivdata;
    newencrypt->ivlen = ivlen;
    newencrypt->size = size;
    newencrypt->xdata = xdata;
    newencrypt->xlen = xlen;
    return newencrypt;
}

EC_M_Encrypt EC_M_clone_encrypt(EC_M_Encrypt encrypt)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Encrypt newencrypt;
    EC_M_Cryptalg algorithm;
    Byte *ivdata = NULL;
    UInt32 ivlen = 0;
    UInt32 size;
    Byte *xdata = NULL;
    UInt32 xlen = 0;
    
    err = EC_M_examine_encrypt(encrypt, &algorithm, &ivdata, &ivlen, &size,
	&xdata, &xlen);
    if (!err) {
	newencrypt = EC_M_new_encrypt(algorithm, ivdata, ivlen, size,
	    xdata, xlen);
	if (newencrypt) return newencrypt;
    }

    EC_M_free_data(ivdata);
    EC_M_free_data(xdata);
    return NULL;
}

EC_Errno EC_M_examine_encrypt(EC_M_Encrypt encrypt, EC_M_Cryptalg *algorithm,
    Byte **ivdata, UInt32 *ivlen, UInt32 *size, Byte **xdata, UInt32 *xlen)
{ 
    EC_M_Cryptalg myalgorithm;
    Byte *myivdata;
    UInt32 myivlen;
    UInt32 mysize;
    Byte *myxdata;
    UInt32 myxlen;

    if (!encrypt) return EC_ERR_INTERNAL;

    myalgorithm = encrypt->algorithm;
    myivdata = EC_M_clone_data(encrypt->ivdata, encrypt->ivlen);
    myivlen = encrypt->ivlen;
    mysize = encrypt->size;
    myxdata = EC_M_clone_data(encrypt->xdata, encrypt->xlen);
    myxlen = encrypt->xlen;

    if ((myivlen && !myivdata) || (myxlen && !myxdata)) {
	/* Didn't copy properly; abort */
	EC_M_free_data(myivdata);
	EC_M_free_data(myxdata);
	return EC_ERR_INTERNAL;
    }

    /* All OK */
    if (algorithm) *algorithm = myalgorithm;
    if (ivdata) *ivdata = myivdata; else EC_M_free_data(myivdata);
    if (ivlen) *ivlen = myivlen;
    if (size) *size = mysize;
    if (xdata) *xdata = myxdata; else EC_M_free_data(myxdata);
    if (xlen) *xlen = myxlen;
    return EC_ERR_NONE;
}

UInt32 EC_M_cmp_encrypt(EC_M_Encrypt encrypt1, EC_M_Encrypt encrypt2)
{
    if (!encrypt1 || !encrypt2) return 1;

    if (encrypt1->algorithm != encrypt2->algorithm
     || encrypt1->ivlen != encrypt2->ivlen
     || EC_M_cmp_data(encrypt1->ivdata, encrypt2->ivdata, encrypt1->ivlen)
     || encrypt1->size != encrypt2->size
     || encrypt1->xlen != encrypt2->xlen
     || EC_M_cmp_data(encrypt1->xdata, encrypt2->xdata, encrypt1->xlen))
	return 1;

    return 0;
}

void EC_M_free_encrypt(EC_M_Encrypt encrypt)
{
    if (encrypt) {
	EC_M_free_data(encrypt->ivdata);
	EC_M_free_data(encrypt->xdata);
	EC_G_free(encrypt);
    }
}

EC_Errno EC_M_compile_encrypt(EC_M_Encrypt encrypt, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;

    if (!encrypt || (encrypt->ivlen && !encrypt->ivdata)
	|| (encrypt->xlen && !encrypt->xdata) || !msg)
	return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_compile_sor(EC_M_REC_ENCRYPT, msg);
    if (!err) err = EC_M_compile_int(encrypt->algorithm, msg);
    if (!err) err = EC_M_compile_data(encrypt->ivdata, encrypt->ivlen, msg);
    if (!err) err = EC_M_compile_int(encrypt->size, msg);
    if (!err) err = EC_M_compile_data(encrypt->xdata, encrypt->xlen, msg);
    if (!err) err = EC_M_compile_eor(msg);

    if (!err) return EC_ERR_NONE;

    EC_M_seek_msg(msgpos, msg);
    return err;
}

EC_Errno EC_M_decompile_encrypt(EC_M_Encrypt *encrypt, EC_M_Msg msg)
{
    EC_Errno err = EC_ERR_NONE;
    EC_M_Msgpos msgpos;
    EC_M_Cryptalg algorithm;
    Byte *ivdata = NULL;
    UInt32 ivlen = 0;
    UInt32 size;
    Byte *xdata = NULL;
    UInt32 xlen = 0;

    if (!msg) return EC_ERR_INTERNAL;

    msgpos = EC_M_tell_msg(msg);

    if (!err) err = EC_M_decompile_sor(EC_M_REC_ENCRYPT, msg);
    if (!err) err = EC_M_decompile_int(&algorithm, msg);
    if (!err) err = EC_M_decompile_data(&ivdata, &ivlen, msg);
    if (!err) err = EC_M_decompile_int(&size, msg);
    if (!err) err = EC_M_decompile_data(&xdata, &xlen, msg);
    if (!err) err = EC_M_decompile_eor(msg);

    /* Did it work? */
    if (!err && encrypt) {
	*encrypt = EC_M_new_encrypt(algorithm, ivdata, ivlen, size,
	    xdata, xlen);
	if (!*encrypt) err = EC_ERR_INTERNAL;
	else return EC_ERR_NONE;
    }

    EC_M_seek_msg(msgpos, msg);
    EC_M_free_data(ivdata);
    EC_M_free_data(xdata);
    return err;
}
