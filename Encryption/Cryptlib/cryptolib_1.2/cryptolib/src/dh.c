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

/****************************
typedef struct {
	int qbits;
	BigInt alpha, p, q;
	Table *alphatab;
#ifdef DLLEXPORT
	HGLOBAL handle;
#endif
} DiffieHellmanSet;
****************************/

#ifdef K_AND_R
_TYPE( int )
randBytesNeededForDHSet (plen, qlen)
  int plen, qlen;
#else
_TYPE( int ) randBytesNeededForDHSet (int plen, int qlen)
#endif
{
	int bytes;

	bytes = ((2*plen + qlen)/8) + ((2*plen+qlen)%8?1:0);

	return bytes;
}

#ifdef K_AND_R
_TYPE( DiffieHellmanSet * )
GenDiffieHellmanSet(pbits, qbits, randomStart)
  int pbits, qbits;
  BigInt randomStart;
#else
_TYPE( DiffieHellmanSet * ) GenDiffieHellmanSet(int pbits, int qbits, BigInt randomStart)
#endif
{
	EGParams *params;
	DiffieHellmanSet *DHset;
#ifdef DLLEXPORT
	HGLOBAL handle;
#endif

#ifdef DLLEXPORT
	handle = clib_malloc(sizeof(DiffieHellmanSet));
	DHset = (DiffieHellmanSet *)GlobalLock(handle);
	DHset->handle = handle;
#else
	DHset = (DiffieHellmanSet *)clib_malloc(sizeof(DiffieHellmanSet));
#endif
	DHset->alpha = bigInit(0);
	DHset->p = bigInit(0);
	DHset->q = bigInit(0);
	
	params = genEGParams(pbits, qbits, randomStart);
	
	DHset->qbits = qbits;
	bigCopy(params->p, DHset->p);
	bigCopy(params->q, DHset->q);
	bigCopy(params->alpha, DHset->alpha);
	DHset->alphatab = g16_bigpow(DHset->alpha, DHset->p, 8*LENGTH(DHset->q));
	
	freeEGParams(params);

	return DHset;
}


#ifdef K_AND_R
_TYPE( int )
randBytesNeededForDHInit (qlen)
  int qlen;
#else
_TYPE( int ) randBytesNeededForDHInit (int qlen)
#endif
{
	int bytes;

	bytes = (qlen/8) + (qlen%8?1:0);

	return bytes;
}

#ifdef K_AND_R
_TYPE( void ) DiffieHellmanInit(myDHset, my_exponent, my_msg1, randomStart)
  DiffieHellmanSet *myDHset;
  BigInt my_exponent;
  BigInt my_msg1;
  BigInt randomStart;
#else
_TYPE( void ) DiffieHellmanInit(DiffieHellmanSet *myDHset,
				BigInt my_exponent,
				BigInt my_msg1,
				BigInt randomStart)
#endif
{
	if (ZERO(my_exponent)) {
		if (randomStart == NULL)
			bigRand(myDHset->qbits/8, my_exponent, PSEUDO);
		else
			bigCopy(randomStart, my_exponent);
	}

	brickell_bigpow(myDHset->alphatab, my_exponent, myDHset->p, my_msg1);
}

#ifdef K_AND_R
_TYPE( void ) DiffieHellmanGenKey(myDHset, recd_msg1, my_exponent, DH_key)
  DiffieHellmanSet *myDHset;
  BigInt recd_msg1;
  BigInt my_exponent;
  BigInt DH_key;
#else
_TYPE( void ) DiffieHellmanGenKey(DiffieHellmanSet *myDHset,
				  BigInt recd_msg1,
				  BigInt my_exponent,
				  BigInt DH_key)
#endif
{
	bigPow(recd_msg1, my_exponent, myDHset->p, DH_key);
}

#ifdef K_AND_R
_TYPE( void ) freeDiffieHellmanSet(DHset)
  DiffieHellmanSet *DHset;
#else
_TYPE( void ) freeDiffieHellmanSet(DiffieHellmanSet *DHset)
#endif
{
	freeBignum(DHset->alpha);
	freeBignum(DHset->p);
	freeBignum(DHset->q);
	freeTable(DHset->alphatab);
#ifdef DLLEXPORT
	GlobalUnlock(DHset->handle);
	GlobalFree(DHset->handle);
#else
	free((char *)DHset);
#endif
}

#ifdef K_AND_R
_TYPE( void ) quantized_DiffieHellmanInit(myDHset, my_exponent, my_msg1, randomStart)
  DiffieHellmanSet *myDHset;
  BigInt my_exponent;
  BigInt my_msg1;
  BigInt randomStart;
#else
_TYPE( void ) quantized_DiffieHellmanInit(DiffieHellmanSet *myDHset,
					  BigInt my_exponent,
					  BigInt my_msg1,
					  BigInt randomStart)
#endif
{
	start_quantize(STD_QUANTUM);
	DiffieHellmanInit(myDHset, my_exponent, my_msg1, randomStart);
	end_quantize();
}

#ifdef K_AND_R
_TYPE( void ) quantized_DiffieHellmanGenKey(myDHset, recd_msg1, my_exponent, DH_key)
  DiffieHellmanSet *myDHset;
  BigInt recd_msg1;
  BigInt my_exponent;
  BigInt DH_key;
#else
_TYPE( void ) quantized_DiffieHellmanGenKey(DiffieHellmanSet *myDHset,
					    BigInt recd_msg1,
					    BigInt my_exponent,
					    BigInt DH_key)
#endif
{
	start_quantize(STD_QUANTUM);
	DiffieHellmanGenKey(myDHset, recd_msg1, my_exponent, DH_key);
	end_quantize();
}


