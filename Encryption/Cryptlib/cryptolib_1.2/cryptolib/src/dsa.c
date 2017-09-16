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
 *	Code for generating and manipulating keys
 *	and generating and verifying digital signatures
 *	according to NIST's digital signature standard (DSA)
 *	NIST, 1991
 *
 *	coded by Jack Lacy, December, 1991
 *
 *	Copyright (c) 1991 AT&T Bell Laboratories
 *
 *	9/14/93 Made compatible with El Gamal Keys (Actually
 *	made El Gamal Keys compatible with DSA).  The DSA
 *	signature looks just like the El Gamal signature (r,s).
 *	DSASignature is typdef'ed to EGSignature.
 *
 *	2/94 Included Ernie Brickell's speedup for constant base and prime.
 *	Increases size of key substantially but signing and verifying are
 *	roughly 3 times faster.
 */
#include "libcrypt.h"

#ifdef K_AND_R
_TYPE( int )
randBytesNeededForDSASign (qlen)
  int qlen;
#else
_TYPE( int ) randBytesNeededForDSASign (int qlen)
#endif
{
	int bytes;

	bytes = (qlen/8) + (qlen%8?1:0);

	return bytes;
}

#ifdef K_AND_R
_TYPE( DSASignature * )
DSASign(md, key, randomStart)
  BigInt md;
  EGPrivateKey *key;
  BigInt randomStart;
#else
_TYPE( DSASignature * ) DSASign(BigInt md,
				EGPrivateKey *key,
				BigInt randomStart)
#endif
{
	BigInt k, r, s, q, p, xr, tmp;
	BigInt kinverse;
	DSASignature *sig;
	Table *g_table;
	
#ifdef DLLEXPORT
	HGLOBAL handle = clib_malloc(sizeof(DSASignature));
	sig = (DSASignature *)GlobalLock(handle);
	sig->handle = handle;
#else
	sig = (DSASignature *)clib_malloc(sizeof(DSASignature));
#endif
	q = key->q;
	p = key->p;
	
	g_table = key->g_table;
	
	/* signature = (r,s) */
	/* get k -- relatively prime to q (gcd(k, q) = 1) */

#ifdef DSA_TEST
	k = atobig("79577ddcaafddc038b865b19f8eb1ada8a2838c6");
#else
	k = bigInit(0);
	getRandBetween(key->q, zero, k, PSEUDO, randomStart);
	if (EVEN(k))
		bigAdd(k, one, k);
#endif
	
	kinverse = bigInit(0);
	getInverse(k, q, kinverse);

	/* get r */
	r = bigInit(0);
/*	bigPow(key->alpha, k, p, r);*/
	brickell_bigpow(g_table, k, p, r);
	bigMod(r, q, r);
	
	/* get s */
	s = bigInit(0);
	tmp = bigInit(0);
	xr = bigInit(0);
	bigMultiply(key->secret, r, xr);
	bigAdd(md, xr, tmp);
	bigMultiply(kinverse, tmp, s);
	bigMod(s, q, s);
	
	freeBignum(k);
	freeBignum(kinverse);
	freeBignum(xr);
	freeBignum(tmp);
	
	sig->r = r;
	sig->s = s;
	return sig;
}


#ifdef K_AND_R
_TYPE( Boolean )
DSAVerify(md, sig, key)
  BigInt md;
  DSASignature *sig;
  EGPublicKey *key;
#else
_TYPE( Boolean )
  DSAVerify(BigInt md,
	    DSASignature *sig,
	    EGPublicKey *key)
#endif
{
	BigInt r, s, q, p, y, g;
	BigInt w, u1, u2, v;
	Boolean retval;
	Table *g_table, *y_table;
	
	s = sig->s;
	r = sig->r;
	q = key->q;
	p = key->p;

	w = bigInit(0);
	
	g_table = key->g_table;
	y_table = key->y_table;
	
	getInverse(s, q, w);

	u1 = bigInit(0);
	bigMultiply(md, w, u1);
	bigMod(u1, q, u1);
	
	u2 = bigInit(0);
	bigMultiply(r, w, u2);
	bigMod(u2, q, u2);
	
	g = key->alpha;
	y = key->publicKey;

	v = bigInit(0);

	double_brickell_bigpow(g_table, y_table, u1, u2, p, v);
/*	double_bigPow(g, y, u1, u2, p, v);*/
	bigMod(v, q, v);
	
	if (bigCompare(r, v) == 0)
		retval = TRUE;
	else
		retval = FALSE;
	
	freeBignum(w);
	freeBignum(u1);
	freeBignum(u2);
	freeBignum(v);
	
	return retval;
}

#ifdef K_AND_R
_TYPE( void ) freeDSASig(sig)
  DSASignature *sig;
#else
_TYPE( void ) freeDSASig(DSASignature *sig)
#endif
{
#ifdef DLLEXPORT
	GlobalUnlock(sig->handle);
	GlobalFree(sig->handle);
#else
	freeBignum(sig->r);
	freeBignum(sig->s);
	free((char *)sig);
#endif	
}


#ifdef K_AND_R
_TYPE( DSASignature * )quantized_DSASign(m, key, randomStart)
  BigInt m;
  DSAPrivateKey *key;
  BigInt randomStart;
#else
_TYPE( DSASignature * )quantized_DSASign(BigInt m, DSAPrivateKey *key, BigInt randomStart)
#endif
{
	DSASignature *sig;

	start_quantize(STD_QUANTUM);
	sig = DSASign(m, key, randomStart);
	end_quantize();

	return sig;
}
