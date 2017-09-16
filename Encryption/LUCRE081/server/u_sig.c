/* Utilities for creating and checking signatures */

#include "lucre.h"
#include "bn.h"
#include "sha.h"

static int ctoh(char c)
{
    if (c >= '0' && c <= '9') return(c-'0');
    if (c >= 'a' && c <= 'f') return(c-('a'-10));
    if (c >= 'A' && c <= 'F') return(c-('A'-10));
    return 0;
}

BIGNUM *EC_U_str2bn(const char *s, int len)
{
    int i,j;
    char binbuf[len/2];

    for(i=0,j=0;i<len;i+=2,++j) {
        binbuf[j] = ((ctoh(s[i]) << 4) | ctoh(s[i+1]));
    }

    return BN_bin2bn(binbuf, len/2, NULL);
}

BIGNUM *EC_U_f(Byte hashID, Byte *s, UInt32 len, BIGNUM *mod)
{
    int sofar;
    int size = BN_num_bytes(mod);
    unsigned char data[size+SHA_DIGEST_LENGTH+1];
    unsigned char data2[size+SHA_DIGEST_LENGTH+1];
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *f;

    SHA1(s,len,data2);
    memcpy(data, data2, SHA_DIGEST_LENGTH);
    data[SHA_DIGEST_LENGTH] = hashID;
    for(sofar=SHA_DIGEST_LENGTH+1; sofar<size; sofar+=SHA_DIGEST_LENGTH) {
        SHA1(data, sofar ,data2);
        memcpy(data+sofar, data2, SHA_DIGEST_LENGTH);
    }
    f = BN_bin2bn(data, size, NULL);
    if (f) BN_mod(f, f, mod, ctx);
    BN_CTX_free(ctx);
    return f;
}

Int32 EC_U_verify_sigmsg(EC_M_Sigmsg sigmsg, BIGNUM *n, BIGNUM *e)
{
    BIGNUM *f;
    BIGNUM *sigexp;
    BN_CTX *ctx;
    Int32 match;

    if (!sigmsg || !sigmsg->signature || !sigmsg->msg || !n || !e)
	return 0;

    if (sigmsg->algorithm != EC_M_SIGALG_SHA1) return 0;

    sigexp = BN_new();
    if (!sigexp) return 0;

    ctx = BN_CTX_new();
    if (!ctx) {
	BN_free(sigexp);
	return 0;
    }
    /* Calculate the hash */
    f = EC_U_f(1, sigmsg->msg->data + sigmsg->msg->begin,
	sigmsg->msg->end - sigmsg->msg->begin, n);
    if (!f) {
	BN_free(sigexp);
	BN_CTX_free(ctx);
	return 0;
    }

    /* Check the signature */
    if (!BN_mod_exp(sigexp, sigmsg->signature, e, n, ctx)) {
	BN_free(sigexp);
	BN_CTX_free(ctx);
	BN_free(f);
	return 0;
    }

    match = !BN_cmp(sigexp, f);

    BN_CTX_free(ctx);
    BN_free(sigexp);
    BN_free(f);

    return match;
}

EC_M_Sigmsg EC_U_sign_sigmsg(BIGNUM *n, BIGNUM *d, EC_M_Msg msg)
{
    BIGNUM *f;
    BIGNUM *sigexp;
    BN_CTX *ctx;
    EC_M_Sigmsg sigmsg;

    if (!n || !d || !msg) return NULL;

    sigexp = BN_new();
    if (!sigexp) return NULL;

    /* Calculate the hash */
    f = EC_U_f(1, msg->data + msg->begin, msg->end - msg->begin, n);
    if (!f) {
	BN_free(sigexp);
	return NULL;
    }

    /* Sign it */
    ctx = BN_CTX_new();
    if (!ctx) {
	BN_free(sigexp);
	BN_free(f);
	return NULL;
    }
    if (!BN_mod_exp(sigexp, f, d, n, ctx)) {
	BN_free(sigexp);
	BN_free(f);
	BN_CTX_free(ctx);
	return NULL;
    }
    BN_free(f);
    BN_CTX_free(ctx);
    /* Don't free sigexp, as it is included in the returned sigmsg */

    /* Create the sigmsg */
    sigmsg = EC_M_new_sigmsg(EC_M_SIGALG_SHA1, sigexp, msg);
    if (sigmsg) return sigmsg;

    BN_free(sigexp);
    return NULL;
}

/* XOR some of the bytes of n with the bytes of xor.
   I really don't know how this is supposed to work if n and xor are
   of different lengths... */
EC_Errno EC_U_xor_MPI(BIGNUM *n, BIGNUM *xor)
{
    Byte *nbin;
    Byte *xorbin;
    UInt32 nlen, xorlen;
    UInt32 i;

    /* Convert to data */

    nlen = BN_num_bytes(n);
    xorlen = BN_num_bytes(xor);

    nbin = EC_G_malloc(nlen);
    xorbin = EC_G_malloc(xorlen);
    if (!nbin || !xorbin) {
	EC_M_free_data(nbin);
	EC_M_free_data(xorbin);
	return EC_ERR_INTERNAL;
    }

    BN_bn2bin(n, nbin);
    BN_bn2bin(xor, xorbin);

    /* Do the XOR */
    for(i=8;i<nlen && i<xorlen;++i) {   /* Yes, that's 8 */
	nbin[i] ^= xorbin[i];
    }

    /* Convert back to MPI */
    if (BN_bin2bn(nbin, nlen, n) == NULL) {
	EC_M_free_data(nbin);
	EC_M_free_data(xorbin);
	return EC_ERR_INTERNAL;
    }

    EC_M_free_data(nbin);
    EC_M_free_data(xorbin);
    return EC_ERR_NONE;
}
