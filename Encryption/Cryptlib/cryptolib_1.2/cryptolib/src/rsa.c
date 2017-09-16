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
 *        Code for generating and manipulating RSA keys
 *        and doing encryption and decryption using RSA.
 *        AT&T recognizes that RSA is patented
 *        (Rivest et. al. U.S. Patent 4,405,829, issued 9/20/83).
 *	  Use of this code assumes proper licensing.
 *
 *        coded by Jack Lacy, December, 1991
 *
 */
#include "libcrypt.h"

static Key_exps *genKeyExps P((BigInt, BigInt, BigInt, int, BigInt));
static void chineseRemTheorem P((BigInt , RSAPrivateKey *, BigInt));
static void genPrimesFor3 P((int, BigInt, BigInt, BigInt, BigInt));

#ifdef K_AND_R
static Key_exps *
genKeyExps(p, q, e, ebits, randomStart)
  BigInt p, q, e;
  int ebits;
  BigInt randomStart;
#else
  static Key_exps *genKeyExps(BigInt p,
			      BigInt q,
			      BigInt e,
			      int ebits,
			      BigInt randomStart)
#endif
{
	BigInt phi, p1, q1;
	BigInt u1, ngcd, ignore;
	Key_exps *exps;
	int ebytes;
#ifdef DLLEXPORT
	HGLOBAL handle = clib_malloc(sizeof(Key_exps));
	exps = (Key_exps *)GlobalLock(handle);
	exps->exp_handle = handle;
#else
	exps = (Key_exps *)clib_malloc(sizeof(Key_exps));
#endif
	p1 = bigInit(0);
	q1 = bigInit(0);
	phi = bigInit(0);
	u1  = bigInit(0);
	ngcd = bigInit(0);
	ignore = bigInit(0);
	if (e == NULL)
		e = bigInit(3);
	
	bigSubtract(p, one, p1);
	bigSubtract(q, one, q1);
	bigMultiply(p1, q1, phi);
	freeBignum(p1);
	freeBignum(q1);
	
	/* Get public exponent, relatively prime to modulus. */
	/* A by product of the extendedGcd calculation is the inverse
	   of e mod phi, which is d, the private exponent.
	   If e has been specified, skip this.
	 */
	if (ebits > 2) {
		ebytes = (ebits/8) + (ebits%8? 1: 0);
		if (randomStart == NULL) {
			bigRand(ebytes, e, PSEUDO);
		}
		else {
			bigCopy(randomStart, e);
		}
		if (EVEN(e))
			bigAdd(e, one, e);
	}

	extendedGcd(e, phi, u1, ignore, ngcd);
	while (bigCompare(ngcd, one) != 0) {
		bigAdd(e, two, e);
		extendedGcd(e, phi, u1, ignore, ngcd);
	}
	exps->d = u1;
	exps->e = e;
	
	freeBignum(phi);
	freeBignum(ngcd);
	freeBignum(ignore);
	
	return exps;
}

#ifdef K_AND_R
_TYPE( RSAPublicKey * )
buildRSAPublicKey(e, n)
  BigInt e, n;
#else
_TYPE( RSAPublicKey * ) buildRSAPublicKey(BigInt e,
					  BigInt n)
#endif
{
	RSAPublicKey *pk;
#ifdef DLLEXPORT
	HGLOBAL handle = clib_malloc(sizeof(RSAPublicKey));
	pk = (RSAPublicKey *)GlobalLock(handle);
	pk->pubkey_handle = handle;
#else
	pk = (RSAPublicKey *)clib_malloc(sizeof(RSAPublicKey));
#endif
	pk->publicExponent = e;
	pk->modulus = n;
	return pk;
}

#ifdef K_AND_R
_TYPE( RSAPrivateKey * )
buildRSAPrivateKey(e, d, p, q, dp, dq, c12)
  BigInt e, d, p, q, dp, dq, c12;
#else
_TYPE( RSAPrivateKey * ) buildRSAPrivateKey(BigInt e,
					    BigInt d,
					    BigInt p,
					    BigInt q,
					    BigInt dp,
					    BigInt dq,
					    BigInt c12)
#endif
{
	RSAPrivateKey *pk;
	ChineseRemStruct *crt;
#ifdef DLLEXPORT
	HGLOBAL crt_handle = clib_malloc(sizeof(ChineseRemStruct));
	HGLOBAL handle = clib_malloc(sizeof(RSAPrivateKey));
	crt = (ChineseRemStruct *)GlobalLock(crt_handle);
	crt->crt_handle = crt_handle;
	pk = (RSAPrivateKey *)GlobalLock(handle);
	pk->privkey_handle = handle;
#else
	crt = (ChineseRemStruct *)clib_malloc(sizeof(ChineseRemStruct));
	pk = (RSAPrivateKey *)clib_malloc(sizeof(RSAPrivateKey));
#endif
	
	pk->publicExponent = e;
	pk->privateExponent = d;
	pk->modulus = bigInit(0);
	bigMultiply(p, q, pk->modulus);
	
	pk->crt = crt;
	pk->crt->p = p;
	pk->crt->q = q;
	pk->crt->dp = dp;
	pk->crt->dq = dq;
	pk->crt->c12 = c12;
	
	return pk;
}

#ifdef K_AND_R
_TYPE( RSAKeySet * )
buildRSAKeySet(e, d, p, q)
  BigInt e, d, p, q;
#else
_TYPE( RSAKeySet * ) buildRSAKeySet(BigInt e,
				    BigInt d,
				    BigInt p,
				    BigInt q)
#endif
{
	BigInt pminus1, qminus1, n, dp, dq, c12;
	BigInt ecopy, dcopy;
	RSAKeySet *ks;
#ifdef DLLEXPORT
	HGLOBAL ks_handle = clib_malloc(sizeof(RSAKeySet));
	ks = (RSAKeySet *)GlobalLock(ks_handle);
	ks->keyset_handle = ks_handle;
#else
	ks = (RSAKeySet *)clib_malloc(sizeof(RSAKeySet));
#endif
	n = bigInit(0);
	bigMultiply(p, q, n);
	
	ecopy = bigInit(0);
	bigCopy(e, ecopy);
	ks->publicKey = buildRSAPublicKey(ecopy, n);
	
	pminus1 = bigInit(0);
	qminus1 = bigInit(0);
	bigSubtract(p, one, pminus1);
	bigSubtract(q, one, qminus1);
	
	dp = bigInit(0);
	dq = bigInit(0);
	bigMod(d, pminus1, dp);
	bigMod(d, qminus1, dq);
	
	c12 = bigInit(0);
	getInverse(q, p, c12);

	ecopy = bigInit(0);
	bigCopy(e, ecopy);
	dcopy = bigInit(0);
	bigCopy(d, dcopy);
	ks->privateKey = buildRSAPrivateKey(ecopy, dcopy, p, q,
					    dp, dq, c12);
	
	freeBignum(pminus1);
	freeBignum(qminus1);
	
	return ks;
}


#ifdef K_AND_R
static void
genPrimesFor3(nbits, p, q, r1, r2)
  int nbits;
  BigInt p, q, r1, r2;
#else
  static void genPrimesFor3(int nbits,
			    BigInt p,
			    BigInt q,
			    BigInt r1,
			    BigInt r2)
#endif
{
	BigInt ngcd, ignore, three, pminus1, qminus1;
	
	ignore = bigInit(0);
	three = bigInit(3);
	pminus1 = bigInit(0);
	qminus1 = bigInit(0);

	/* Gordon algorithm doesn't care about the p-1 factor size */
	genStrongPrimeSet(nbits/2, p, (int)NULL, ignore, GORDON, r1);
	bigSubtract(p, one, pminus1);
	ngcd = gcd(three, pminus1);
	while (bigCompare(ngcd, one) != 0) {
		if (r1 != NULL)
			randomize(r1);
		freeBignum(ngcd);
		genStrongPrimeSet(nbits/2, p, (int)NULL, ignore, GORDON, r1);
		bigSubtract(p, one, pminus1);
		ngcd = gcd(three, pminus1);
	}
	freeBignum(ngcd);
	
	genStrongPrimeSet(nbits/2, q, (int)NULL, ignore, GORDON, r2);
	bigSubtract(q, one, qminus1);
	ngcd = gcd(three, qminus1);
	while (bigCompare(ngcd, one) != 0) {
		if (r2 != NULL)
			randomize(r2);
		freeBignum(ngcd);
		genStrongPrimeSet(nbits/2, q, (int)NULL, ignore, GORDON, r2);
		bigSubtract(q, one, qminus1);
		ngcd = gcd(three, qminus1);
	}
	freeBignum(ngcd);
	freeBignum(pminus1);
	freeBignum(qminus1);
	freeBignum(ignore);
	freeBignum(three);
}


#ifdef K_AND_R
_TYPE( int )
randBytesNeededForRSA (modlen, ebits)
  int modlen, ebits;
#else
_TYPE( int ) randBytesNeededForRSA (int modlen, int ebits)
#endif
{
	int bytes;

	bytes = ((modlen + ebits)/8) + ((modlen+ebits)%8? 1: 0);

	return bytes;
}

#ifdef K_AND_R
_TYPE( RSAKeySet * )
genRSAKeySet(nbits, ebits, e, randomStart)
  Ulong nbits, ebits, randomStart;
  BigInt e;
#else
_TYPE( RSAKeySet * ) genRSAKeySet(int nbits,
				  int ebits,
				  BigInt e,
				  BigInt randomStart)
#endif
{
	BigInt p, q, ignore, r1, r2;
	Key_exps *exps;
	RSAKeySet *key_set;
	int oldlen;
	BigInt randStart;
	
	p = bigInit(0);
	q = bigInit(0);
	r1 = NULL;
	r2 = NULL;
	randStart = NULL;
	if (randomStart != NULL) {
		r1 = bigInit(0);
		r2 = bigInit(0);
		randStart = bigInit(0);
		bigCopy(randomStart, randStart);
		oldlen = LENGTH(randStart);
		LENGTH(randStart) = nbits/32/2;
		bigCopy(randStart, r1);
		LENGTH(randStart) = oldlen;
		bigRightShift(randStart, nbits/2, randStart);
		oldlen = LENGTH(randStart);
		LENGTH(randStart) = nbits/32/2;
		bigCopy(randStart, r2);
		LENGTH(randStart) = oldlen;
		bigRightShift(randStart, nbits/2, randStart);
	}
	if (ebits == 2)
		genPrimesFor3(nbits, p, q, r1, r2);
	
	else {
		ignore = bigInit(0);
		genStrongPrimeSet(nbits/2, p, (int)NULL, ignore, GORDON, r1);
		genStrongPrimeSet(nbits/2, q, (int)NULL, ignore, GORDON, r2);
		freeBignum(ignore);
	}
	exps = genKeyExps(p, q, e, ebits, randStart);
	key_set = buildRSAKeySet(exps->e, exps->d, p, q);
	freeBignum(exps->e);
	freeBignum(exps->d);
	if (r1 != NULL) {
		freeBignum(r1);
		freeBignum(r2);
		freeBignum(randStart);
	}
#ifdef DLLEXPORT
	GlobalUnlock(exps->exp_handle);
	GlobalFree(exps->exp_handle);
#else
	free((char *)exps);
#endif
	return key_set;
}


/*
   Chinese Remainder Theorem reconstruction of m^d mod n, using
   m^dp mod p and m^dq mod q with dp = d mod p-1, dq = d mod q-1.
   */
#ifdef K_AND_R
static void
chineseRemTheorem(m, key, em)
  BigInt m, em;
  RSAPrivateKey *key;
#else
  static void chineseRemTheorem(BigInt m,
				RSAPrivateKey *key,
				BigInt em)
#endif
{
	BigInt u1, u2;
	BigInt p, q, dp, dq, c12;
	
	p = key->crt->p;
	q = key->crt->q;
	dp = key->crt->dp;
	dq = key->crt->dq;
	c12 = key->crt->c12;
	
	u1 = bigInit(0);
	u2 = bigInit(0);

	bigPow(m, dp, p, u1);
	bigPow(m, dq, q, u2);
	
	crtCombine(u1, u2, p, q, c12, em);
	
	freeBignum(u1);
	freeBignum(u2);
	
}

#ifdef K_AND_R
_TYPE( void )
freeRSAPublicKey(pk)
  RSAPublicKey *pk;
#else
_TYPE( void ) freeRSAPublicKey(RSAPublicKey *pk)
#endif
{
	freeBignum(pk->publicExponent);
	freeBignum(pk->modulus);
#ifdef DLLEXPORT
	GlobalUnlock(pk->pubkey_handle);
	GlobalFree(pk->pubkey_handle);
#else
	free((char *)pk);
#endif
}

#ifdef K_AND_R
_TYPE( void )
freeRSAPrivateKey(pk)
  RSAPrivateKey *pk;
#else
_TYPE( void ) freeRSAPrivateKey(RSAPrivateKey *pk)
#endif
{
	freeBignum(pk->publicExponent);
	freeBignum(pk->privateExponent);
	freeBignum(pk->modulus);
	freeBignum(pk->crt->p);
	freeBignum(pk->crt->q);
	freeBignum(pk->crt->dp);
	freeBignum(pk->crt->dq);
	freeBignum(pk->crt->c12);
#ifdef DLLEXPORT
	GlobalUnlock(pk->crt->crt_handle);
	GlobalFree(pk->crt->crt_handle);
	GlobalUnlock(pk->privkey_handle);
	GlobalFree(pk->privkey_handle);
#else
	free((char *)pk->crt);
	free((char *)pk);
#endif	
}

#ifdef K_AND_R
_TYPE( void )
freeRSAKeys(ks)
  RSAKeySet *ks;
#else
_TYPE( void ) freeRSAKeys(RSAKeySet *ks)
#endif
{
	
	freeRSAPublicKey(ks->publicKey);
	freeRSAPrivateKey(ks->privateKey);
#ifdef DLLEXPORT
	GlobalUnlock(ks->keyset_handle);
	GlobalFree(ks->keyset_handle);
#else
	free((char *)ks);
#endif
}

#ifdef K_AND_R
_TYPE( BigInt )
RSAEncrypt(message, key)
  BigInt message;
  RSAPublicKey *key;
#else
_TYPE( BigInt ) RSAEncrypt(BigInt message,
			   RSAPublicKey *key)
#endif
{
	BigInt result;
	
	result = bigInit(3);
	if (bigCompare(key->publicExponent, result) == 0) {
		reset_big(result, 0);
		bigCube(message, key->modulus, result);
	}
	else {
		reset_big(result, 0);
		bigPow(message, key->publicExponent, key->modulus, result);
	}
	return result;
}

#ifdef K_AND_R
_TYPE( BigInt )
RSADecrypt(message, key)
  BigInt message;
  RSAPrivateKey *key;
#else
_TYPE( BigInt ) RSADecrypt(BigInt message,
			   RSAPrivateKey *key)
#endif
{
	BigInt result;
	
	result = bigInit(0);
	
	chineseRemTheorem(message, key, result);
	return result;
	
}


#ifdef K_AND_R
_TYPE( RSASignature * )
RSASign(message, key)
  BigInt message;
  RSAPrivateKey *key;
#else
_TYPE( RSASignature * ) RSASign(BigInt message,
				RSAPrivateKey *key)
#endif
{
	return (RSASignature *)RSADecrypt(message, key);
}


#ifdef K_AND_R
_TYPE( Boolean )
RSAVerify(message, sig, key)
  BigInt message;
  RSASignature *sig;
  RSAPublicKey *key;
#else
_TYPE( Boolean ) RSAVerify(BigInt message,
			   RSASignature *sig,
			   RSAPublicKey *key)
#endif
{
	Boolean retval;
	BigInt cmp;
	
	cmp = (BigInt)RSAEncrypt((BigInt)sig, key);
	
	if (bigCompare(message, cmp) == 0)
		retval = TRUE;
	else
		retval = FALSE;
	
	freeBignum(cmp);
	
	return retval;
}

#ifdef K_AND_R
_TYPE( void )
freeRSASig(sig)
  RSASignature *sig;
#else
_TYPE( void ) freeRSASig(RSASignature *sig)
#endif
{
	freeBignum((BigInt)sig);
}

#ifdef K_AND_R
_TYPE( void )
RSAPrivateKeyDesEncrypt(pk, deskey)
  RSAPrivateKey *pk;
  unsigned char *deskey;
#else
_TYPE( void )
RSAPrivateKeyDesEncrypt(RSAPrivateKey *pk, unsigned char *deskey)
#endif
{
	bignumDesEncrypt(pk->publicExponent, deskey);
	bignumDesEncrypt(pk->privateExponent, deskey);
	bignumDesEncrypt(pk->modulus, deskey);
	bignumDesEncrypt(pk->crt->p, deskey);
	bignumDesEncrypt(pk->crt->q, deskey);
	bignumDesEncrypt(pk->crt->dp, deskey);
	bignumDesEncrypt(pk->crt->dq, deskey);
	bignumDesEncrypt(pk->crt->c12, deskey);
}

#ifdef K_AND_R
_TYPE( void )
RSAPrivateKeyDesDecrypt(pk, deskey)
  RSAPrivateKey *pk;
  unsigned char *deskey;
#else
_TYPE( void )
RSAPrivateKeyDesDecrypt(RSAPrivateKey *pk, unsigned char *deskey)
#endif
{
	bignumDesDecrypt(pk->publicExponent, deskey);
	bignumDesDecrypt(pk->privateExponent, deskey);
	bignumDesDecrypt(pk->modulus, deskey);
	bignumDesDecrypt(pk->crt->p, deskey);
	bignumDesDecrypt(pk->crt->q, deskey);
	bignumDesDecrypt(pk->crt->dp, deskey);
	bignumDesDecrypt(pk->crt->dq, deskey);
	bignumDesDecrypt(pk->crt->c12, deskey);
}

#ifdef K_AND_R
_TYPE( BigInt )
quantized_RSADecrypt(m, key)
  BigInt m;
  RSAPrivateKey *key;
#else
_TYPE( BigInt )
quantized_RSADecrypt(BigInt m, RSAPrivateKey *key)
#endif
{
	BigInt result;

	start_quantize(STD_QUANTUM);
	result = RSADecrypt(m, key);
	end_quantize();

	return result;
}


#ifdef K_AND_R
_TYPE( RSASignature *)
quantized_RSASign(m, key)
  BigInt m;
  RSAPrivateKey *key;
#else
_TYPE( RSASignature *)
quantized_RSASign(BigInt m, RSAPrivateKey *key)
#endif
{
	return (RSASignature *)quantized_RSADecrypt(m, key);
}
