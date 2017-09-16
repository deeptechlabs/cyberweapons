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
fputBigInt(big, stream)
  BigInt big;
  FILE *stream;
#else
_TYPE( void )
fputBigInt(BigInt big, FILE *stream)
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
	
	fputInteger(SIGN(big), stream, EXPLICIT);
	fputInteger(LENGTH(big), stream, EXPLICIT);
	
	bigToBuf(big, LENGTH(big)*sizeof(NumType), buf);
	
	fputString(buf, LENGTH(big)*sizeof(NumType), stream, EXPLICIT, OCTETSTRING);
#ifdef DLLEXPORT
	GlobalUnlock(handle);
	GlobalFree(handle);
#else
	free(buf);
#endif
}

#ifdef K_AND_R
_TYPE( BigInt )
fgetBigInt(stream)
  FILE *stream;
#else
_TYPE( BigInt )
fgetBigInt(FILE *stream)
#endif
{
	unsigned char *buf;
	int length;
	BigInt big;
#ifdef DLLEXPORT
	HGLOBAL handle;
#endif
	
	big = bigInit(0);
	SIGN(big) = (Sign)fgetInteger(stream, EXPLICIT);
	length = (int)fgetInteger(stream, EXPLICIT);
	
#ifdef DLLEXPORT
	handle = clib_malloc(length*sizeof(NumType));
	buf = (unsigned char *)GlobalLock(handle);
#else
	buf = (unsigned char *)clib_malloc(length*sizeof(NumType));
#endif
	
	fgetString(buf, length*sizeof(NumType), stream, EXPLICIT);
	
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
fputTable(table, stream)
  Table *table;
  FILE *stream;
#else
_TYPE( void )
fputTable(Table *table, FILE *stream)
#endif
{
	int i;
	
	fputInteger(table->length, stream, EXPLICIT);
	
	for (i=0; i<(int)table->length; i++)
		fputBigInt(table->t[i], stream);
	
}

#ifdef K_AND_R
_TYPE( Table *  )
fgetTable(stream)
  FILE *stream;
#else
_TYPE( Table *  )
fgetTable(FILE *stream)
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
	table->length = (int)fgetInteger(stream, EXPLICIT);
	for (i=0; i<(int)table->length; i++)
		table->t[i] = fgetBigInt(stream);
	
	return table;
}

/* RSA net functions */

#ifdef K_AND_R
_TYPE( void )
fputRSAPublicKey(key, stream)
  RSAPublicKey *key;
  FILE *stream;
#else
_TYPE( void )
fputRSAPublicKey(RSAPublicKey *key, FILE *stream)
#endif
{
	fputBigInt(key->publicExponent, stream);
	fputBigInt(key->modulus, stream);
}

#ifdef K_AND_R
_TYPE( RSAPublicKey *  )
fgetRSAPublicKey(stream)
  FILE *stream;
#else
_TYPE( RSAPublicKey *  )
fgetRSAPublicKey(FILE *stream)
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
	key->publicExponent = fgetBigInt(stream);
	key->modulus = fgetBigInt(stream);
	
	return key;
}

#ifdef K_AND_R
_TYPE( void )
fputRSAPrivateKey(key, stream)
  RSAPrivateKey *key;
  FILE *stream;
#else
_TYPE( void )
fputRSAPrivateKey(RSAPrivateKey *key, FILE *stream)
#endif
{
	fputBigInt(key->publicExponent, stream);
	fputBigInt(key->privateExponent, stream);
	fputBigInt(key->modulus, stream);
	fputBigInt(key->crt->p, stream);
	fputBigInt(key->crt->q, stream);
	fputBigInt(key->crt->dp, stream);
	fputBigInt(key->crt->dq, stream);
	fputBigInt(key->crt->c12, stream);
	
}

#ifdef K_AND_R
_TYPE( RSAPrivateKey * )
fgetRSAPrivateKey(stream)
  FILE *stream;
#else
_TYPE( RSAPrivateKey * )
fgetRSAPrivateKey(FILE *stream)
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
	key->publicExponent = fgetBigInt(stream);
	key->privateExponent = fgetBigInt(stream);
	key->modulus = fgetBigInt(stream);
	key->crt->p = fgetBigInt(stream);
	key->crt->q = fgetBigInt(stream);
	key->crt->dp = fgetBigInt(stream);
	key->crt->dq = fgetBigInt(stream);
	key->crt->c12 = fgetBigInt(stream);
	
	return key;
}

#ifdef K_AND_R
_TYPE( void )
fputRSASignature(sig, stream)
  RSASignature *sig;
  FILE *stream;
#else
_TYPE( void )
fputRSASignature(RSASignature *sig, FILE *stream)
#endif
{
	fputBigInt((BigInt)sig, stream);
}

#ifdef K_AND_R
_TYPE( RSASignature * )
fgetRSASignature(stream)
  FILE *stream;
#else
_TYPE( RSASignature * )
fgetRSASignature(FILE *stream)
#endif
{
	RSASignature *sig;
	
	sig = (RSASignature *)fgetBigInt(stream);
	
	return sig;
}

/* El Gamal net functions */

#ifdef K_AND_R
_TYPE( void )
fputEGParams(params, stream)
  EGParams *params;
  FILE *stream;
#else
_TYPE( void )
fputEGParams(EGParams *params, FILE *stream)
#endif
{
	fputBigInt(params->p, stream);
	fputBigInt(params->q, stream);
	fputBigInt(params->alpha, stream);
}

#ifdef K_AND_R
_TYPE( EGParams * )
fgetEGParams(stream)
  FILE *stream;
#else
_TYPE( EGParams * )
fgetEGParams(FILE *stream)
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
	params->p = fgetBigInt(stream);
	params->q = fgetBigInt(stream);
	params->alpha = fgetBigInt(stream);
	
	return params;
}

#ifdef K_AND_R
_TYPE( void )
fputEGPublicKey(key, stream)
  EGPublicKey *key;
  FILE *stream;
#else
_TYPE( void )
fputEGPublicKey(EGPublicKey *key, FILE *stream)
#endif
{
	fputBigInt(key->p, stream);
	fputBigInt(key->q, stream);
	fputBigInt(key->alpha, stream);
	fputBigInt(key->publicKey, stream);
	fputTable(key->g_table, stream);
	fputTable(key->y_table, stream);
}

#ifdef K_AND_R
_TYPE( EGPublicKey * )
fgetEGPublicKey(stream)
  FILE *stream;
#else
_TYPE( EGPublicKey * )
fgetEGPublicKey(FILE *stream)
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
	key->p = fgetBigInt(stream);
	key->q = fgetBigInt(stream);
	key->alpha = fgetBigInt(stream);
	key->publicKey = fgetBigInt(stream);
	key->g_table = fgetTable(stream);
	key->y_table = fgetTable(stream);
	
	return key;
}

#ifdef K_AND_R
_TYPE( void )
fputEGPrivateKey(key, stream)
  EGPrivateKey *key;
  FILE *stream;
#else
_TYPE( void )
fputEGPrivateKey(EGPrivateKey *key, FILE *stream)
#endif
{
	fputBigInt(key->p, stream);
	fputBigInt(key->q, stream);
	fputBigInt(key->alpha, stream);
	fputBigInt(key->publicKey, stream);
	fputBigInt(key->secret, stream);
	fputTable(key->g_table, stream);
}

#ifdef K_AND_R
_TYPE( EGPrivateKey * )
fgetEGPrivateKey(stream)
  FILE *stream;
#else
_TYPE( EGPrivateKey * )
fgetEGPrivateKey(FILE *stream)
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
	key->p = fgetBigInt(stream);
	key->q = fgetBigInt(stream);
	key->alpha = fgetBigInt(stream);
	key->publicKey = fgetBigInt(stream);
	key->secret = fgetBigInt(stream);
	key->g_table = fgetTable(stream);
	
	return key;
}

#ifdef K_AND_R
_TYPE( void ) fputEGSignature(sig, stream)
  EGSignature *sig;
  FILE *stream;
#else
_TYPE( void ) fputEGSignature(EGSignature *sig, FILE *stream)
#endif
{
	fputBigInt(sig->r, stream);
	fputBigInt(sig->s, stream);
}

#ifdef K_AND_R
_TYPE( EGSignature * )
fgetEGSignature(stream)
  FILE *stream;
#else
_TYPE( EGSignature * )
fgetEGSignature(FILE *stream)
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
	sig->r = fgetBigInt(stream);
	sig->s = fgetBigInt(stream);
	
	return sig;
}

/* DSA net functions */

#ifdef K_AND_R
_TYPE( void ) fputDSASignature(sig, stream)
  DSASignature *sig;
  FILE *stream;
#else
_TYPE( void ) fputDSASignature(DSASignature *sig, FILE *stream)
#endif
{
	fputBigInt(sig->r, stream);
	fputBigInt(sig->s, stream);
}

#ifdef K_AND_R
_TYPE( DSASignature * )
fgetDSASignature(stream)
  FILE *stream;
#else
_TYPE( DSASignature * )
fgetDSASignature(FILE *stream)
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
	sig->r = fgetBigInt(stream);
	sig->s = fgetBigInt(stream);
	
	return sig;
}

