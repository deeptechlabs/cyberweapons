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
#include <stdlib.h>

/**************************************************
typedef struct {
	BigInt p, q, c12;
	BigInt modulus;
#ifdef DLLEXPORT
	HGLOBAL handle;
#endif
} RabinPrivateKey;

typedef struct {
	BigInt modulus;
#ifdef DLLEXPORT
	HGLOBAL handle;
#endif
} RabinPublicKey;

typedef struct {
	RabinPublicKey *publicKey;
	RabinPrivateKey *privateKey;
#ifdef DLLEXPORT
	HGLOBAL handle;
#endif
} RabinKeySet;

typedef Bignum RabinSignature;
***************************************************/


#ifdef K_AND_R
_TYPE( int )
randBytesNeededForRabinSet (modlen)
  int modlen;
#else
_TYPE( int ) randBytesNeededForRabinSet (int modlen)
#endif
{
	int bytes;

	bytes = (modlen/8) + (modlen%8? 1: 0);

	return bytes;
}

#ifdef K_AND_R
_TYPE( RabinKeySet *) genRabinKeySet (modbits, randomStart)
  int modbits;
  BigInt randomStart;
#else
_TYPE( RabinKeySet *) genRabinKeySet (int modbits, BigInt randomStart)
#endif
{
	RabinPrivateKey *privkey;
	RabinPublicKey *pubkey;
	RabinKeySet *ks;
	BigInt r1, r2, ignore;
	int oldlen;
#ifdef DLLEXPORT
	HGLOBAL handle;
#endif

#ifdef DLLEXPORT
	handle = clib_malloc(sizeof(RabinKeySet));
	ks = (RabinKeySet *)GlobalLock(handle);
	ks->handle = handle;

	handle = clib_malloc(sizeof(RabinPrivateKey));
	privkey = (RabinPrivateKey *)GlobalLock(handle);
	privkey->handle = handle;

	handle = clib_malloc(sizeof(RabinPublicKey));
	pubkey = (RabinPublicKey *)GlobalLock(handle);
	pubkey->handle = handle;
#else
	ks = (RabinKeySet *)clib_malloc(sizeof(RabinKeySet));
	privkey = (RabinPrivateKey *)clib_malloc(sizeof(RabinPrivateKey));
	pubkey = (RabinPublicKey *)clib_malloc(sizeof(RabinPublicKey));
#endif

	privkey->p = bigInit(0);
	privkey->q = bigInit(0);
	privkey->c12 = bigInit(0);
	privkey->modulus = bigInit(0);
	pubkey->modulus = bigInit(0);
	ignore = bigInit(0);

	r1 = NULL;
	r2 = NULL;
	if (randomStart != NULL) {
		r1 = bigInit(0);
		r2 = bigInit(0);
		oldlen = LENGTH(randomStart);
		LENGTH(randomStart) = modbits/32/2;
		bigCopy(randomStart, r1);
		LENGTH(randomStart) = oldlen;
		bigRightShift(randomStart, modbits/2, r2);
	}
	while ((privkey->p->num[0] & 3) != 3) {
		genStrongPrimeSet(modbits/2, privkey->p, (int)NULL, ignore, GORDON, r1);
		if (r1 != NULL)
			randomize(r1);
	}
	while ((privkey->q->num[0] & 3) != 3) {
		genStrongPrimeSet(modbits/2, privkey->q, (int)NULL, ignore, GORDON, r2);
		if (r2 != NULL)
			randomize(r2);
	}

	if (randomStart != NULL) {
		freeBignum(r1);
		freeBignum(r2);
	}
	getInverse(privkey->q, privkey->p, privkey->c12);
	bigMultiply(privkey->p, privkey->q, pubkey->modulus);
	bigCopy(pubkey->modulus, privkey->modulus);

	ks->publicKey = pubkey;
	ks->privateKey = privkey;

	freeBignum(ignore);

	return ks;
}

/* All Lengths are in bytes */
/* encrypted message format (from msb to lsb) =
 * [ pad | message | msglen (4 bytes) | digest (pad | message | msglen) ]
/* the digest is of everything beyond the digest including the pad and length field */

#ifdef K_AND_R
static BigInt prepare_enc_msg (message, modulus, digestType, digestLen, randomStart)
  BigInt message;
  BigInt modulus;
  int digestType;
  int digestLen;
  BigInt randomStart;
#else
static BigInt prepare_enc_msg (BigInt message,
			       BigInt modulus,
			       int digestType,
			       int digestLen,
			       BigInt randomStart)
#endif
{
	BigInt enc_message, digest;
	int msglen, modlen;

	digest = bigInit(0);
	enc_message = bigInit(0);
	modlen = LENGTH(modulus)*4;
	msglen = LENGTH(message)*4;

	if (msglen+digestLen+4 > modlen)
		handle_exception(CRITICAL, "Rabin Encrypt: message length too big\n");

	getRandBetween(zero, modulus, enc_message, PSEUDO, randomStart);

	bigCopy(message, enc_message);

	/* move message over 1 chunk for the length field */
	bigLeftShift(enc_message, 32, enc_message);

	/* insert the length */
	NUM(enc_message)[0] = msglen;

	bigLeftShift(enc_message, digestLen*8, enc_message);
	LENGTH(enc_message) = LENGTH(modulus);

	/* digest everything */
	bigMessageDigest((unsigned char *)NUM(enc_message)+digestLen, modlen-digestLen,
			 digest, digestType);

	/* insert the digest */
	bigCopy(digest, enc_message);
	LENGTH(enc_message) = LENGTH(modulus);

	/* message to be encrypted must be smaller than the modulus */

	freeBignum(digest);

	return enc_message;
}

#ifdef K_AND_R
static BigInt extract_message (roots, N, digestType, digestLen)
  BigInt roots[4];
  BigInt N;
  int digestType;
  int digestLen;
#else
static BigInt extract_message (BigInt roots[4],
			       BigInt N,
			       int digestType,
			       int digestLen)
#endif
{
	BigInt message, digest, r, cmp_digest;
	int modlen, msglen, i, rootlen;

	message = bigInit(0);
	modlen = LENGTH(N)*4;
	digest = bigInit(0);
	cmp_digest = bigInit(0);
	for (i=0; i<4; i++) {
		r = roots[i];
		rootlen = LENGTH(r);
		LENGTH(r) = digestLen/4;
		bigCopy(r, digest);
		LENGTH(r) = rootlen;
		bigRightShift(r, digestLen*8, r);
		bigMessageDigest((unsigned char *)NUM(r), modlen-digestLen,
				 cmp_digest, digestType);
		if (bigCompare(digest, cmp_digest) == 0) {
			bigCopy(r, message);
			break;
		}
	}
	freeBignum(digest);
	freeBignum(cmp_digest);

	if (i != 4) {
		msglen = (int)NUM(message)[0];
		bigRightShift(message, 32, message);
		LENGTH(message) = msglen/4;
	}
	
	return message;
		
}

#ifdef K_AND_R
_TYPE( int )
randBytesNeededForRabinEncrypt (modlen)
  int modlen;
#else
_TYPE( int ) randBytesNeededForRabinEncrypt (int modlen)
#endif
{
	int bytes;

	bytes = (modlen/8) + (modlen%8? 1: 0);

	return bytes;
}

#ifdef K_AND_R
_TYPE( BigInt ) RabinEncrypt (message, pubkey, digestType, digestLen, randomStart)
  BigInt message;
  RabinPublicKey *pubkey;
  int digestType;
  int digestLen;
  BigInt randomStart;
#else
_TYPE( BigInt ) RabinEncrypt (BigInt message,
			      RabinPublicKey *pubkey,
			      int digestType,
			      int digestLen,
			      BigInt randomStart)
#endif
{
	BigInt enc_message, tmp;

	enc_message = prepare_enc_msg(message, pubkey->modulus, digestType, digestLen, randomStart);

	/* encrypt */
	tmp = bigInit(0);
	bigMultiply(enc_message, enc_message, tmp);
	bigMod(tmp, pubkey->modulus, enc_message);

	freeBignum(tmp);

	return enc_message;
}

#ifdef K_AND_R
_TYPE( BigInt ) RabinDecrypt (enc_message, privkey, digestType, digestLen)
  BigInt enc_message;
  RabinPrivateKey *privkey;
  int digestType;
  int digestLen;
#else
_TYPE( BigInt ) RabinDecrypt (BigInt enc_message,
			      RabinPrivateKey *privkey,
			      int digestType,
			      int digestLen)
#endif
{
	BigInt message, r[4], N;

	N = privkey->modulus;
	r[0] = bigInit(0);
	r[1] = bigInit(0);
	r[2] = bigInit(0);
	r[3] = bigInit(0);

	compositeSquareRoot(enc_message, privkey->p, privkey->q, privkey->c12, r[0], r[1]);
	bigSubtract(N, r[0], r[2]);
	bigSubtract(N, r[1], r[3]);

	message = extract_message(r, N, digestType, digestLen);

	freeBignum(r[0]);
	freeBignum(r[1]);
	freeBignum(r[2]);
	freeBignum(r[3]);

	return message;
	
}

extern int bigNumsAllocated;
/*
 * signed message is [pad | digest(message)] such that the entire thing is
 * a quadratic residue mod p*q.
 */
#ifdef K_AND_R
static BigInt prepare_sig_msg (message, privkey, digestType, digestLen, randomStart)
  BigInt message;
  RabinPrivateKey *privkey;
  int digestType;
  int digestLen;
  BigInt randomStart;
#else
static BigInt prepare_sig_msg (BigInt message,
			       RabinPrivateKey *privkey,
			       int digestType,
			       int digestLen,
			       BigInt randomStart)
#endif
{
	BigInt digest, sig_msg, p, q, N;
	int modlen, msglen;

	p = privkey->p;
	q = privkey->q;
	N = privkey->modulus;
	modlen = LENGTH(N)*4;
	msglen = LENGTH(message)*4;
	digest = bigInit(0);
	sig_msg = bigInit(0);

	bigMessageDigest((unsigned char *)NUM(message), msglen, digest, digestType);
	getRandBetween(zero, N, sig_msg, PSEUDO, randomStart);
	bigCopy(digest, sig_msg);
	LENGTH(sig_msg) = modlen/4;
	while(bigIsQR(sig_msg, p, q) != TRUE) {
		if (randomStart != NULL)
			randomize(randomStart);
		getRandBetween(zero, N, sig_msg, PSEUDO, randomStart);
		bigCopy(digest, sig_msg);
		LENGTH(sig_msg) = modlen/4;

	}
	freeBignum(digest);

	return sig_msg;
}

#ifdef K_AND_R
_TYPE( int )
randBytesNeededForRabinSign (modlen)
  int modlen;
#else
_TYPE( int ) randBytesNeededForRabinSign (int modlen)
#endif
{
	int bytes;

	bytes = (modlen/8) + (modlen%8? 1: 0);

	return bytes;
}

/*
 * To sign a message digest, take the square root of the processed digest.
 */
#ifdef K_AND_R
_TYPE( RabinSignature * ) RabinSign (message, privkey, digestType, digestLen, randomStart)
  BigInt message;
  RabinPrivateKey *privkey;
  int digestType;
  int digestLen;
  BigInt randomStart;
#else
_TYPE( RabinSignature * ) RabinSign (BigInt message,
				     RabinPrivateKey *privkey,
				     int digestType,
				     int digestLen,
				     BigInt randomStart)
#endif
{
	BigInt sig_msg, r1;
	RabinSignature *sig;

	sig_msg = prepare_sig_msg(message, privkey, digestType, digestLen, randomStart);

	sig = (BigInt)bigInit(0);
	r1 = bigInit(0);
	compositeSquareRoot(sig_msg, privkey->p, privkey->q, privkey->c12, (BigInt)sig, r1);

	freeBignum(r1);
	freeBignum(sig_msg);

	return sig;

}

/*
 * Square the received signature, pick off the digest, compare to the digest of
 * the received message.
 */
#ifdef K_AND_R
_TYPE( Boolean ) RabinVerify (message, sig, pubkey, digestType, digestLen)
  BigInt message;
  RabinSignature *sig;
  RabinPublicKey *pubkey;
  int digestType;
  int digestLen;
#else
_TYPE( Boolean ) RabinVerify (BigInt message,
			      RabinSignature *sig,
			      RabinPublicKey *pubkey,
			      int digestType,
			      int digestLen)
#endif
{
	BigInt dec_sig, digest;
	Boolean retval;

	digest = bigInit(0);
	dec_sig = bigInit(0);
	bigMultiply(sig, sig, dec_sig);
	bigMod(dec_sig, pubkey->modulus, dec_sig);
	LENGTH(dec_sig) = digestLen/4;

	bigMessageDigest((unsigned char *)NUM(message), LENGTH(message)*4, digest, digestType);
	if (bigCompare(dec_sig, digest) != 0)
		retval = FALSE;
	else
		retval = TRUE;

	freeBignum(dec_sig);
	freeBignum(digest);

	return retval;

}

#ifdef K_AND_R
_TYPE( void ) freeRabinPublicKey (key)
  RabinPublicKey *key;
#else
_TYPE( void ) freeRabinPublicKey (RabinPublicKey *key)
#endif
{
	freeBignum(key->modulus);
#ifdef DLLEXPORT
	GlobalUnlock(key->handle);
	GlobalFree(key->handle);
#else
	free((char *)key);
#endif
}

#ifdef K_AND_R
_TYPE( void ) freeRabinPrivateKey (key)
  RabinPrivateKey *key;
#else
_TYPE( void ) freeRabinPrivateKey (RabinPrivateKey *key)
#endif
{
	freeBignum(key->p);
	freeBignum(key->q);
	freeBignum(key->c12);
	freeBignum(key->modulus);
#ifdef DLLEXPORT
	GlobalUnlock(key->handle);
	GlobalFree(key->handle);
#else
	free((char *)key);
#endif
}

#ifdef K_AND_R
_TYPE( void ) freeRabinKeySet (ks)
  RabinKeySet *ks;
#else
_TYPE( void ) freeRabinKeySet (RabinKeySet *ks)
#endif
{
	freeRabinPublicKey(ks->publicKey);
	freeRabinPrivateKey(ks->privateKey);
#ifdef DLLEXPORT
	GlobalUnlock(ks->handle);
	GlobalFree(ks->handle);
#else
	free((char *)ks);
#endif
}

#ifdef K_AND_R
_TYPE( void ) freeRabinSignature (sig)
  RabinSignature *sig;
#else
_TYPE( void ) freeRabinSignature (RabinSignature *sig)
#endif
{
	freeBignum(sig);
}

#ifdef K_AND_R
_TYPE( BigInt ) quantized_RabinDecrypt (enc_message, privkey, digestType, digestLen)
  BigInt enc_message;
  RabinPrivateKey *privkey;
  int digestType;
  int digestLen;
#else
_TYPE( BigInt ) quantized_RabinDecrypt (BigInt enc_message,
					RabinPrivateKey *privkey,
					int digestType,
					int digestLen)
#endif
{
	BigInt result;
	start_quantize(STD_QUANTUM);
	result = RabinDecrypt(enc_message, privkey, digestType, digestLen);
	end_quantize();
	return result;
}

#ifdef K_AND_R
_TYPE( RabinSignature * ) quantized_RabinSign (message, privkey, digestType, digestLen, randomStart)
  BigInt message;
  RabinPrivateKey *privkey;
  int digestType;
  int digestLen;
  BigInt randomStart;
#else
_TYPE( RabinSignature * ) quantized_RabinSign (BigInt message,
					       RabinPrivateKey *privkey,
					       int digestType,
					       int digestLen,
					       BigInt randomStart)
#endif
{
	RabinSignature *sig;
	start_quantize(STD_QUANTUM);
	sig = RabinSign(message, privkey, digestType, digestLen, randomStart);
	end_quantize();
	return sig;
}

