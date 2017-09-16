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

/*
 *        Code for generating and manipulating El Gamal keys
 *        and doing encryption and decryption using El Gamal
 *        and generating and verifying digital signatures.
 *
 *        coded by Jack Lacy, December, 1991
 *
 *        Copyright (c) 1991 AT&T Bell Laboratories
 */
#include "libcrypt.h"

static EGPublicKey *buildEGPublicKey P((EGParams *, BigInt));
static EGPrivateKey *buildEGPrivateKey P((EGParams *, BigInt));

#ifdef K_AND_R
_TYPE( int )
randBytesNeededForEGParams (plen, qlen)
  int plen, qlen;
#else
_TYPE( int ) randBytesNeededForEGParams (int plen, int qlen)
#endif
{
	int bytes;

	bytes = ((2*plen + qlen)/8) + ((2*plen+qlen)%8?1:0);

	return bytes;
}

/*  Uses NIST's structure for keys. */
#ifdef K_AND_R
_TYPE( EGParams * )
genEGParams(primeLen, subprimelen, randomStart)
  int primeLen, subprimelen;
  BigInt randomStart;
#else
_TYPE( EGParams * ) genEGParams(int primeLen, int subprimelen, BigInt randomStart)
#endif
{
	EGParams *params;
	BigInt h, quotient, pminus1, ignore, p, q, alpha;
	BigInt root_randStart, randStart;
	int oldlen;
#ifdef DLLEXPORT
	HGLOBAL handle = clib_malloc(sizeof(EGParams));
	params = (EGParams *)GlobalLock(handle);
	params->handle = handle;
#else
	params = (EGParams *)clib_malloc(sizeof(EGParams));
#endif
	
	p                = bigInit(0);
	q                = bigInit(0);
	alpha        = bigInit(1);
	h                = bigInit(0);
	quotient        = bigInit(0);
	ignore        = bigInit(0);
	pminus1        = bigInit(0);
	root_randStart = NULL;
	randStart = NULL;
	if (randomStart != NULL) {
		root_randStart = bigInit(0);
		randStart = bigInit(0);
		bigCopy(randomStart, randStart);
		oldlen = LENGTH(randStart);
		LENGTH(randStart) = primeLen/32;
		bigCopy(randStart, root_randStart);
		LENGTH(randStart) = oldlen;
		bigRightShift(randStart, primeLen, randStart);
	}
	genStrongPrimeSet(primeLen, p, subprimelen, q, NIST, randStart);
	
	bigSubtract(p, one, pminus1);
	bigDivide(pminus1, q, quotient, ignore);
	while (bigCompare(alpha, one) == 0) {
		getRandBetween(pminus1, zero, h, PSEUDO, root_randStart);
		bigPow(h, quotient, p, alpha);
		if (randomStart != NULL)
			randomize(root_randStart);
	}
	
	freeBignum(h);
	freeBignum(quotient);
	freeBignum(pminus1);
	freeBignum(ignore);
	if (randomStart != NULL) {
		freeBignum(randStart);
		freeBignum(root_randStart);
	}
	
	params->p = p;
	params->q = q;
	params->alpha = alpha;
	
	return params;
}

#ifdef K_AND_R
static EGPublicKey *
buildEGPublicKey(params, x)
  EGParams *params;
  BigInt x;
#else
  static EGPublicKey *buildEGPublicKey(EGParams *params,
				       BigInt x)
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
	
	key->p = bigInit(0);
	bigCopy(params->p, key->p);
	key->q = bigInit(0);
	bigCopy(params->q, key->q);
	key->alpha = bigInit(0);
	bigCopy(params->alpha, key->alpha);
	key->publicKey = bigInit(0);
	bigPow(params->alpha, x, params->p, key->publicKey);
	key->g_table = g16_bigpow(key->alpha, key->p, 8*LENGTH(key->q));
	key->y_table = g16_bigpow(key->publicKey, key->p, 8*LENGTH(key->q));
	
	return key;
}


#ifdef K_AND_R
static EGPrivateKey *
buildEGPrivateKey(params, secret)
  EGParams *params;
  BigInt secret;
#else
  static EGPrivateKey *buildEGPrivateKey(EGParams *params,
					 BigInt secret)
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
	
	key->p = bigInit(0);
	bigCopy(params->p, key->p);
	key->q = bigInit(0);
	bigCopy(params->q, key->q);
	key->alpha = bigInit(0);
	bigCopy(params->alpha, key->alpha);
	key->secret = bigInit(0);
	bigCopy(secret, key->secret);
	key->publicKey = bigInit(0);
	bigPow(params->alpha, key->secret, params->p, key->publicKey);
	key->g_table = g16_bigpow(key->alpha, key->p, 8*LENGTH(key->q));
	
	return key;
}


#ifdef K_AND_R
_TYPE( EGPrivateKey * )
genEGPrivateKeyWithSeed(params, seed, seedlen)
  EGParams *params;
  char *seed;
  int seedlen;
#else
_TYPE( EGPrivateKey * ) genEGPrivateKeyWithSeed(EGParams *params,
						char *seed,
						int seedlen)
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
	
	key->secret = bigInit(0);
	seed_rng((unsigned char *)seed, seedlen);
	getRandBetween(params->q, one, key->secret, PSEUDO, NULL);
	if (EVEN(key->secret))
		bigAdd(key->secret, one, key->secret);
	
	key->p = bigInit(0);
	bigCopy(params->p, key->p);
	key->q = bigInit(0);
	bigCopy(params->q, key->q);
	key->alpha = bigInit(0);
	bigCopy(params->alpha, key->alpha);
	key->publicKey = bigInit(0);
	bigPow(params->alpha, key->secret, params->p, key->publicKey);
	key->g_table = g16_bigpow(key->alpha, key->p, 8*LENGTH(key->q));
		
	return key;
}


#ifdef K_AND_R
_TYPE( int )
randBytesNeededForEGKeySet (qlen)
  int qlen;
#else
_TYPE( int ) randBytesNeededForEGKeySet (int qlen)
#endif
{
	int bytes;

	bytes = (qlen/8) + (qlen%8?1:0);

	return bytes;
}

#ifdef K_AND_R
_TYPE( EGKeySet * )
genEGKeySet(params, plen, qlen, randomStart)
  EGParams *params;
  int plen, qlen;
  BigInt randomStart;
#else
_TYPE( EGKeySet * ) genEGKeySet(EGParams *params, int plen, int qlen, BigInt randomStart)
#endif
{
	EGKeySet *ks;
	BigInt secret;
	BigInt secret_randStart, randStart;
	int oldlen;
	int flag = 0;

#ifdef DLLEXPORT
	HGLOBAL handle = clib_malloc(sizeof(EGKeySet));
	ks = (EGKeySet *)GlobalLock(handle);
	ks->handle = handle;
#else
	ks = (EGKeySet *)clib_malloc(sizeof(EGKeySet));
#endif
	secret_randStart = NULL;
	if (randomStart != NULL) {
		randStart = bigInit(0);
		bigCopy(randomStart, randStart);
		secret_randStart = bigInit(0);
		oldlen = LENGTH(randStart);
		LENGTH(randStart) = qlen/32;
		bigCopy(randStart, secret_randStart);
		LENGTH(randStart) = oldlen;
		bigRightShift(randStart, qlen, randStart);
	}

	if (params == NULL) {
		params = genEGParams(plen, qlen, randStart);
		flag = 1;
	}

	secret = bigInit(0);
	getRandBetween(params->q, one, secret, PSEUDO, secret_randStart);
	if (EVEN(secret))
		bigAdd(secret, one, secret);
	
	ks->publicKey = buildEGPublicKey(params, secret);
	ks->privateKey = buildEGPrivateKey(params, secret);
	
	freeBignum(secret);
	if (flag == 1)
		freeEGParams(params);
	if (randomStart != NULL) {
		freeBignum(randStart);
		freeBignum(secret_randStart);
	}

	return ks;
	
}

#ifdef K_AND_R
_TYPE( BigInt  )
getEGPrime(key)
  EGPublicKey *key;
#else
_TYPE( BigInt ) getEGPrime(EGPublicKey *key)
#endif
{
	return key->p;
}

#ifdef K_AND_R
_TYPE( BigInt  )
getEGAlpha(key)
  EGPublicKey *key;
#else
_TYPE( BigInt ) getEGAlpha(EGPublicKey *key)
#endif
{
	return key->alpha;
}

#ifdef K_AND_R
_TYPE( int )
randBytesNeededForEGSign (qlen)
  int qlen;
#else
_TYPE( int ) randBytesNeededForEGSign (int qlen)
#endif
{
	int bytes;

	bytes = (qlen/8) + (qlen%8?1:0);

	return bytes;
}

#ifdef K_AND_R
_TYPE( EGSignature * )
EGSign(m, egKey, randomStart)
  BigInt m;
  EGPrivateKey *egKey;
  BigInt randomStart;
#else
_TYPE( EGSignature * ) EGSign(BigInt m,
			      EGPrivateKey *egKey,
			      BigInt randomStart)
#endif
{
	BigInt k, kinverse, r, s, pminus1, tmp;
	BigInt p, alpha, xgcd, ignore;
	EGSignature *sig;
#ifdef DLLEXPORT
	HGLOBAL handle = clib_malloc(sizeof(EGSignature));
	sig = (EGSignature *)GlobalLock(handle);
	sig->handle = handle;
#else
	sig = (EGSignature *)clib_malloc(sizeof(EGSignature));
#endif
	p = egKey->p;
	alpha = egKey->alpha;
	ignore = bigInit(0);
	pminus1 = bigInit(0);
	bigSubtract(p, one, pminus1);
	
	/* signature = (r,s) */
	/* get k */
	k = bigInit(0);
	getRandBetween(egKey->q, one, k, PSEUDO, randomStart);
	if (EVEN(k))
		bigAdd(k, one, k);
	
	kinverse = bigInit(0);
	xgcd = bigInit(0);
	extendedGcd(k, pminus1, kinverse, ignore, xgcd);
	while (bigCompare(xgcd, one) != 0) {
		bigSubtract(k, two, k);
		extendedGcd(k, pminus1, kinverse, ignore, xgcd);
	}
	
	/* get r */
	r = bigInit(0);
	brickell_bigpow(egKey->g_table, k, p, r);
/*
	bigPow(alpha, k, p, r);
*/	
	/* get s */
	s = bigInit(0);
	tmp = bigInit(0);
	bigMultiply(egKey->secret, r, tmp);
	bigMod(tmp, pminus1, tmp);
	bigSubtract(m, tmp, tmp);
	if (SIGN(tmp) == NEG)
		negate(tmp, pminus1, tmp);
	
	bigMultiply(kinverse, tmp, s);
	bigMod(s, pminus1, s);

	freeBignum(ignore);
	freeBignum(pminus1);
	freeBignum(k);
	freeBignum(kinverse);
	freeBignum(xgcd);
	freeBignum(tmp);
	
	sig->r = r;
	sig->s = s;
	return sig;
}


#ifdef K_AND_R
_TYPE( Boolean )
EGVerify(m, sig, key)
  BigInt m;
  EGSignature *sig;
  EGPublicKey *key;
#else
_TYPE( Boolean ) EGVerify(BigInt m,
			  EGSignature *sig,
			  EGPublicKey *key)
#endif
{
	BigInt alpha, p, y, tmp1, tmp2;
	Boolean retval;
	
	tmp1 = bigInit(0);
	tmp2 = bigInit(0);
	
	alpha = key->alpha;
	p = key->p;
	y = key->publicKey;
	
	brickell_bigpow(key->g_table, m, p, tmp1);
	double_bigPow(y, sig->r, sig->r, sig->s, p, tmp2);

	if (bigCompare(tmp1, tmp2) == 0)
		retval = TRUE;
	else
		retval = FALSE;
	
	freeBignum(tmp1);
	freeBignum(tmp2);
	
	return retval;
}

#ifdef K_AND_R
_TYPE( int )
randBytesNeededForEGEncrypt (qlen)
  int qlen;
#else
_TYPE( int ) randBytesNeededForEGEncrypt (int qlen)
#endif
{
	int bytes;

	bytes = (qlen/8) + (qlen%8?1:0);

	return bytes;
}

/* result = (c1 << bits(p) + c2) */
#ifdef K_AND_R
_TYPE( BigInt )
EGEncrypt(message, key, randomStart)
  BigInt message;
  EGPublicKey *key;
  BigInt randomStart;
#else
_TYPE( BigInt ) EGEncrypt(BigInt message,
			  EGPublicKey *key,
			  BigInt randomStart)
#endif
{
	BigInt x, K, c1, c2;
	BigInt result;
	
	x = bigInit(0);
	getRandBetween(key->q, one, x, PSEUDO, randomStart);
	if (EVEN(x))
		bigAdd(x, one, x);
	
	K = bigInit(0);
	brickell_bigpow(key->y_table, x, key->p, K);
	/*    bigPow(key->publicKey, x, key->p, K);*/
	
	result = bigInit(0);
	c1 = bigInit(0);
	c2 = bigInit(0);
	
	brickell_bigpow(key->g_table, x, key->p, c1);
	/*    bigPow(key->alpha, x, key->p, c1);*/
	
	/*
	   bigMultiply(message, K, c2);
	   bigMod(c2, key->p, c2);
	   */
	bigXor(message, K, c2);
	
	bigLeftShift(c1, (int)(LENGTH(key->p)*sizeof(Ulong)*CHARBITS), result);
	bigAdd(result, c2, result);
	
	freeBignum(x);
	freeBignum(c1);
	freeBignum(c2);
	freeBignum(K);
	
	return result;
	
}

#ifdef K_AND_R
_TYPE( BigInt  )
EGDecrypt(message, key)
  BigInt message;
  EGPrivateKey *key;
#else
_TYPE( BigInt  ) EGDecrypt(BigInt message,
			   EGPrivateKey *key)
#endif
{
	BigInt c1, c2, K, result;
	int shiftbits, oldlen;
	
	shiftbits = (int)(LENGTH(key->p)*sizeof(Ulong)*CHARBITS);
	c1 = bigInit(0);
	bigRightShift(message, shiftbits, c1);
	c2 = bigInit(0);
	oldlen = LENGTH(message);
	LENGTH(message) = LENGTH(key->p);
	bigCopy(message, c2);
	LENGTH(message) = (int)oldlen;
	
	K = bigInit(0);
	bigPow(c1, key->secret, key->p, K);
	
	result = bigInit(0);
	bigXor(c2, K, result);
	
	freeBignum(c1);
	freeBignum(c2);
	freeBignum(K);
	
	return result;
}

#ifdef K_AND_R
_TYPE( void )
freeEGPublicKey(pk)
  EGPublicKey *pk;
#else
_TYPE( void ) freeEGPublicKey(EGPublicKey *pk)
#endif
{
	freeBignum(pk->p);
	freeBignum(pk->q);
	freeBignum(pk->alpha);
	freeBignum(pk->publicKey);
	freeTable(pk->g_table);
	freeTable(pk->y_table);
#ifdef DLLEXPORT
	GlobalUnlock(pk->handle);
	GlobalFree(pk->handle);
#else
	free((char *)pk);
#endif
}

#ifdef K_AND_R
_TYPE( void )
freeEGPrivateKey(pk)
  EGPrivateKey *pk;
#else
_TYPE( void ) freeEGPrivateKey(EGPrivateKey *pk)
#endif
{
	freeBignum(pk->p);
	freeBignum(pk->q);
	freeBignum(pk->alpha);
	freeBignum(pk->publicKey);
	freeBignum(pk->secret);
	freeTable(pk->g_table);
#ifdef DLLEXPORT
	GlobalUnlock(pk->handle);
	GlobalFree(pk->handle);
#else
	free((char *)pk);
#endif
}

#ifdef K_AND_R
_TYPE( void )
freeEGKeys(ks)
  EGKeySet *ks;
#else
_TYPE( void ) freeEGKeys(EGKeySet *ks)
#endif
{
	freeEGPublicKey(ks->publicKey);
	freeEGPrivateKey(ks->privateKey);
#ifdef DLLEXPORT
	GlobalUnlock(ks->handle);
	GlobalFree(ks->handle);
#else
	free((char *)ks);
#endif
}

#ifdef K_AND_R
_TYPE( void )
freeEGSig(sig)
  EGSignature *sig;
#else
_TYPE( void ) freeEGSig(EGSignature *sig)
#endif
{
	freeBignum(sig->r);
	freeBignum(sig->s);
#ifdef DLLEXPORT
	GlobalUnlock(sig->handle);
	GlobalFree(sig->handle);
#else
	free((char *)sig);
#endif
}

#ifdef K_AND_R
_TYPE( void )
freeEGParams(params)
  EGParams *params;
#else
_TYPE( void ) freeEGParams(EGParams *params)
#endif
{
	freeBignum(params->p);
	freeBignum(params->q);
	freeBignum(params->alpha);
#ifdef DLLEXPORT
	GlobalUnlock(params->handle);
	GlobalFree(params->handle);
#else
	free((char *)params);
#endif
}


#ifdef K_AND_R
_TYPE( BigInt )quantized_EGDecrypt(m, key)
  BigInt m;
  EGPrivateKey *key;
#else
_TYPE( BigInt )quantized_EGDecrypt(BigInt m, EGPrivateKey *key)
#endif
{
	BigInt result;

	start_quantize(STD_QUANTUM);
	result = EGDecrypt(m, key);
	end_quantize();

	return result;
}

#ifdef K_AND_R
_TYPE( EGSignature *)quantized_EGSign(m, key, randomStart)
  BigInt m;
  EGPrivateKey *key;
  BigInt randomStart;
#else
_TYPE( EGSignature *)quantized_EGSign(BigInt m, EGPrivateKey *key, BigInt randomStart)
#endif
{
	EGSignature *sig;

	start_quantize(STD_QUANTUM);
	sig = EGSign(m, key, randomStart);
	end_quantize();

	return sig;
}

