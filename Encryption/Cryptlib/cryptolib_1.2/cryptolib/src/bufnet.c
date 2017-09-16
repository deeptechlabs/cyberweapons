/*
 * This is version 1.2 of CryptoLib
 *
 * The authors of this software are Jack Lacy, Don Mitchell and Matt Blaze
 *              Copyright (c) 1991, 1992, 1993, 1994, 1995 by AT&T.
 * Permission to use, copy, and modify this software without fee
 * is hereby granted, provided that this entire notice is included in
 * all copies of any software which is or includes a copy or
 * modification of this software and in all copies of the supporting
 * documentation for such software.
 *
 * NOTE:
 * Some of the algorithms in cryptolib may be covered by patents.
 * It is the responsibility of the user to ensure that any required
 * licenses are obtained.
 *
 *
 * SOME PARTS OF CRYPTOLIB MAY BE RESTRICTED UNDER UNITED STATES EXPORT
 * REGULATIONS.
 *
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTY.  IN PARTICULAR, NEITHER THE AUTHORS NOR AT&T MAKE ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY
 * OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR PURPOSE.
 */

#include "libcrypt.h"

#ifdef K_AND_R
_TYPE( void )
bufPutBigInt(big, buffer)
  BigInt big;
  unsigned char **buffer;
#else
_TYPE( void )
bufPutBigInt(BigInt big, unsigned char **buffer)
#endif
{
	unsigned char *buf;
#ifdef DLLEXPORT
	HGLOBAL handle;
	handle = clib_malloc(LENGTH(big)*sizeof(NumType));
	buf = (unsigned char *)GlobalLock(handle);
#else
	buf = (unsigned char *)clib_malloc(LENGTH(big)*sizeof(NumType));
#endif
	
	bufPutInteger(SIGN(big), buffer, EXPLICIT);
	bufPutInteger(LENGTH(big), buffer, EXPLICIT);
	
	bigToBuf(big, LENGTH(big)*sizeof(NumType), buf);
	
	bufPutString(buf, LENGTH(big)*sizeof(NumType), buffer, EXPLICIT, OCTETSTRING);
#ifdef DLLEXPORT
	GlobalUnlock(handle);
	GlobalFree(handle);
#else
	free(buf);
#endif
}

#ifdef K_AND_R
_TYPE( BigInt )
bufGetBigInt(buffer)
  unsigned char **buffer;
#else
_TYPE( BigInt )
bufGetBigInt(unsigned char **buffer)
#endif
{
	unsigned char *buf;
	int length;
	BigInt big;
#ifdef DLLEXPORT
	HGLOBAL handle;
#endif
	
	big = bigInit(0);
	SIGN(big) = (Sign)bufGetInteger(buffer, EXPLICIT);
	length = (int)bufGetInteger(buffer, EXPLICIT);
	
#ifdef DLLEXPORT
	handle = clib_malloc(length*sizeof(NumType));
	buf = (unsigned char *)GlobalLock(handle);
#else
	buf = (unsigned char *)clib_malloc(length*sizeof(NumType));
#endif
	
	bufGetString(buf, length*sizeof(NumType), buffer, EXPLICIT);
	
	bufToBig(buf, length*sizeof(NumType), big);
#ifdef DLLEXPORT
	GlobalUnlock(handle);
	GlobalFree(handle);
#else
	free(buf);
#endif
	return big;
}

#ifdef K_AND_R
_TYPE( void )
bufPutTable(table, buffer)
  Table *table;
  unsigned char **buffer;
#else
_TYPE( void )
bufPutTable(Table *table, unsigned char **buffer)
#endif
{
	int i;
	
	bufPutInteger(table->length, buffer, EXPLICIT);
	
	for (i=0; i<(int)table->length; i++)
		bufPutBigInt(table->t[i], buffer);
	
}

#ifdef K_AND_R
_TYPE( Table *  )
bufGetTable(buffer)
  unsigned char **buffer;
#else
_TYPE( Table *  )
bufGetTable(unsigned char **buffer)
#endif
{
	Table *table;
	int i;
#ifdef DLLEXPORT
	HGLOBAL handle;
	
	handle = clib_malloc(sizeof(Table) + sizeof(Bignum)*(16-2));
	table = (Table *)GlobalLock(handle);
	table->tphandle = handle;
#else
	table = (Table *)clib_malloc(sizeof(Table) + sizeof(Bignum)*(16-2));
#endif
	table->length = (int)bufGetInteger(buffer, EXPLICIT);
	for (i=0; i<(int)table->length; i++)
		table->t[i] = bufGetBigInt(buffer);
	
	return table;
}

/* RSA net functions */

#ifdef K_AND_R
_TYPE( void )
bufPutRSAPublicKey(key, buffer)
  RSAPublicKey *key;
  unsigned char **buffer;
#else
_TYPE( void )
bufPutRSAPublicKey(RSAPublicKey *key, unsigned char **buffer)
#endif
{
	bufPutBigInt(key->publicExponent, buffer);
	bufPutBigInt(key->modulus, buffer);
}

#ifdef K_AND_R
_TYPE( RSAPublicKey *  )
bufGetRSAPublicKey(buffer)
  unsigned char **buffer;
#else
_TYPE( RSAPublicKey *  )
bufGetRSAPublicKey(unsigned char **buffer)
#endif
{
	RSAPublicKey *key;
#ifdef DLLEXPORT
	HGLOBAL handle;
	
	handle = clib_malloc(sizeof(RSAPublicKey));
	key = (RSAPublicKey *)GlobalLock(handle);
	key->pubkey_handle = handle;
#else
	key = (RSAPublicKey *)clib_malloc(sizeof(RSAPublicKey));
#endif
	key->publicExponent = bufGetBigInt(buffer);
	key->modulus = bufGetBigInt(buffer);
	
	return key;
}

#ifdef K_AND_R
_TYPE( void )
bufPutRSAPrivateKey(key, buffer)
  RSAPrivateKey *key;
  unsigned char **buffer;
#else
_TYPE( void )
bufPutRSAPrivateKey(RSAPrivateKey *key, unsigned char **buffer)
#endif
{
	bufPutBigInt(key->publicExponent, buffer);
	bufPutBigInt(key->privateExponent, buffer);
	bufPutBigInt(key->modulus, buffer);
	bufPutBigInt(key->crt->p, buffer);
	bufPutBigInt(key->crt->q, buffer);
	bufPutBigInt(key->crt->dp, buffer);
	bufPutBigInt(key->crt->dq, buffer);
	bufPutBigInt(key->crt->c12, buffer);
	
}

#ifdef K_AND_R
_TYPE( RSAPrivateKey * )
bufGetRSAPrivateKey(buffer)
  unsigned char **buffer;
#else
_TYPE( RSAPrivateKey * )
bufGetRSAPrivateKey(unsigned char **buffer)
#endif
{
	RSAPrivateKey *key;
#ifdef DLLEXPORT
	HGLOBAL handle;
	
	handle = clib_malloc(sizeof(RSAPrivateKey));
	key = (RSAPrivateKey *)GlobalLock(handle);
	key->privkey_handle = handle;
	handle = clib_malloc(sizeof(ChineseRemStruct));
	key->crt = (ChineseRemStruct *)GlobalLock(handle);
	key->crt->crt_handle = handle;
#else
	key = (RSAPrivateKey *)clib_malloc(sizeof(RSAPrivateKey));
	key->crt = (ChineseRemStruct *)clib_malloc(sizeof(ChineseRemStruct));
#endif
	key->publicExponent = bufGetBigInt(buffer);
	key->privateExponent = bufGetBigInt(buffer);
	key->modulus = bufGetBigInt(buffer);
	key->crt->p = bufGetBigInt(buffer);
	key->crt->q = bufGetBigInt(buffer);
	key->crt->dp = bufGetBigInt(buffer);
	key->crt->dq = bufGetBigInt(buffer);
	key->crt->c12 = bufGetBigInt(buffer);
	
	return key;
}

#ifdef K_AND_R
_TYPE( void )
bufPutRSASignature(sig, buffer)
  RSASignature *sig;
  unsigned char **buffer;
#else
_TYPE( void )
bufPutRSASignature(RSASignature *sig, unsigned char **buffer)
#endif
{
	bufPutBigInt((BigInt)sig, buffer);
}

#ifdef K_AND_R
_TYPE( RSASignature * )
bufGetRSASignature(buffer)
  unsigned char **buffer;
#else
_TYPE( RSASignature * )
bufGetRSASignature(unsigned char **buffer)
#endif
{
	RSASignature *sig;
	
	sig = (RSASignature *)bufGetBigInt(buffer);
	
	return sig;
}

/* El Gamal net functions */

#ifdef K_AND_R
_TYPE( void )
bufPutEGParams(params, buffer)
  EGParams *params;
  unsigned char **buffer;
#else
_TYPE( void )
bufPutEGParams(EGParams *params, unsigned char **buffer)
#endif
{
	bufPutBigInt(params->p, buffer);
	bufPutBigInt(params->q, buffer);
	bufPutBigInt(params->alpha, buffer);
}

#ifdef K_AND_R
_TYPE( EGParams * )
bufGetEGParams(buffer)
  unsigned char **buffer;
#else
_TYPE( EGParams * )
bufGetEGParams(unsigned char **buffer)
#endif
{
	EGParams *params;
#ifdef DLLEXPORT
	HGLOBAL handle;
	
	handle = clib_malloc(sizeof(EGParams));
	params = (EGParams *)GlobalLock(handle);
	params->handle = handle;
#else
	params = (EGParams *)clib_malloc(sizeof(EGParams));
#endif
	params->p = bufGetBigInt(buffer);
	params->q = bufGetBigInt(buffer);
	params->alpha = bufGetBigInt(buffer);
	
	return params;
}

#ifdef K_AND_R
_TYPE( void )
bufPutEGPublicKey(key, buffer)
  EGPublicKey *key;
  unsigned char **buffer;
#else
_TYPE( void )
bufPutEGPublicKey(EGPublicKey *key, unsigned char **buffer)
#endif
{
	bufPutBigInt(key->p, buffer);
	bufPutBigInt(key->q, buffer);
	bufPutBigInt(key->alpha, buffer);
	bufPutBigInt(key->publicKey, buffer);
	bufPutTable(key->g_table, buffer);
	bufPutTable(key->y_table, buffer);
}

#ifdef K_AND_R
_TYPE( EGPublicKey * )
bufGetEGPublicKey(buffer)
  unsigned char **buffer;
#else
_TYPE( EGPublicKey * )
bufGetEGPublicKey(unsigned char **buffer)
#endif
{
	EGPublicKey *key;
#ifdef DLLEXPORT
	HGLOBAL handle = clib_malloc(sizeof(EGPublicKey));
	key = (EGPublicKey *)GlobalLock(handle);
	key->handle = handle;
#else
	key = (EGPublicKey *)clib_malloc(sizeof(EGPublicKey));
#endif
	key->p = bufGetBigInt(buffer);
	key->q = bufGetBigInt(buffer);
	key->alpha = bufGetBigInt(buffer);
	key->publicKey = bufGetBigInt(buffer);
	key->g_table = bufGetTable(buffer);
	key->y_table = bufGetTable(buffer);
	
	return key;
}

#ifdef K_AND_R
_TYPE( void )
bufPutEGPrivateKey(key, buffer)
  EGPrivateKey *key;
  unsigned char **buffer;
#else
_TYPE( void )
bufPutEGPrivateKey(EGPrivateKey *key, unsigned char **buffer)
#endif
{
	bufPutBigInt(key->p, buffer);
	bufPutBigInt(key->q, buffer);
	bufPutBigInt(key->alpha, buffer);
	bufPutBigInt(key->publicKey, buffer);
	bufPutBigInt(key->secret, buffer);
	bufPutTable(key->g_table, buffer);
}

#ifdef K_AND_R
_TYPE( EGPrivateKey * )
bufGetEGPrivateKey(buffer)
  unsigned char **buffer;
#else
_TYPE( EGPrivateKey * )
bufGetEGPrivateKey(unsigned char **buffer)
#endif
{
	EGPrivateKey *key;
#ifdef DLLEXPORT
	HGLOBAL handle = clib_malloc(sizeof(EGPrivateKey));
	key = (EGPrivateKey *)GlobalLock(handle);
	key->handle = handle;
#else
	key = (EGPrivateKey *)clib_malloc(sizeof(EGPrivateKey));
#endif
	key->p = bufGetBigInt(buffer);
	key->q = bufGetBigInt(buffer);
	key->alpha = bufGetBigInt(buffer);
	key->publicKey = bufGetBigInt(buffer);
	key->secret = bufGetBigInt(buffer);
	key->g_table = bufGetTable(buffer);
	
	return key;
}

#ifdef K_AND_R
_TYPE( void ) bufPutEGSignature(sig, buffer)
  EGSignature *sig;
  unsigned char **buffer;
#else
_TYPE( void ) bufPutEGSignature(EGSignature *sig, unsigned char **buffer)
#endif
{
	bufPutBigInt(sig->r, buffer);
	bufPutBigInt(sig->s, buffer);
}

#ifdef K_AND_R
_TYPE( EGSignature * )
bufGetEGSignature(buffer)
  unsigned char **buffer;
#else
_TYPE( EGSignature * )
bufGetEGSignature(unsigned char **buffer)
#endif
{
	EGSignature *sig;
#ifdef DLLEXPORT
	HGLOBAL handle = clib_malloc(sizeof(EGPrivateKey));
	sig = (EGSignature *)GlobalLock(handle);
	sig->handle = handle;
#else
	sig = (EGSignature *)clib_malloc(sizeof(EGPrivateKey));
#endif
	sig->r = bufGetBigInt(buffer);
	sig->s = bufGetBigInt(buffer);
	
	return sig;
}

/* DSA net functions */

#ifdef K_AND_R
_TYPE( void ) bufPutDSASignature(sig, buffer)
  DSASignature *sig;
  unsigned char **buffer;
#else
_TYPE( void ) bufPutDSASignature(DSASignature *sig, unsigned char **buffer)
#endif
{
	bufPutBigInt(sig->r, buffer);
	bufPutBigInt(sig->s, buffer);
}

#ifdef K_AND_R
_TYPE( DSASignature * )
bufGetDSASignature(buffer)
  unsigned char **buffer;
#else
_TYPE( DSASignature * )
bufGetDSASignature(unsigned char **buffer)
#endif
{
	DSASignature *sig;
#ifdef DLLEXPORT
	HGLOBAL handle = clib_malloc(sizeof(DSASignature));
	sig = (DSASignature *)GlobalLock(handle);
	sig->handle = handle;
#else
	sig = (DSASignature *)clib_malloc(sizeof(DSASignature));
#endif
	sig->r = bufGetBigInt(buffer);
	sig->s = bufGetBigInt(buffer);
	
	return sig;
}

