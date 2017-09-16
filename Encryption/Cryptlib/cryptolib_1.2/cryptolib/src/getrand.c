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
 *        Pseudo random number generator and bignum interfaces
 *        to pseudo and true random number generators.
 *        by Jack Lacy and D.P. Mitchell December, 1991
 *
 *        Copyright (c) 1991 AT&T Bell Laboratories
 */
#include "libcrypt.h"
#include <stdlib.h>

static void pseudoRandBytes P((unsigned char *, int));
static void reallyRandomBytes P((unsigned char *, int));
static void bigPseudoRand P((int, BigInt));
static void bigReallyRand P((int, BigInt));
static unsigned long unix_random P((void));

#define pseudoRandom desRandom

#ifdef TRUERAND
#define truesource truerand
#else
#include <stdlib.h>
#include <time.h>
#define truesource unix_random

static unsigned long unix_random() {
	static int first_time = 1;
	Ulong num;
	
	if (first_time) {
		srand((unsigned int)time(0));
		first_time = 0;
	}
	num = (Ulong)rand();
	num = (num << 16) | (rand() & 0xffff);
	return num;
}
#endif

#ifdef K_AND_R
static void
reallyRandomBytes(buf, numbytes)
  unsigned char *buf;
  int numbytes;
#else
static void reallyRandomBytes(unsigned char *buf,
			      int numbytes)
#endif
{
	register int i;
	register unsigned char *bp;
	Ulong a, *aa;
	
	i = numbytes;
	bp = buf;
	for (i=0; i<numbytes; i++) {
		a = truesource();
		aa = shs((unsigned char *)&a, 4);
		bp[i] = (unsigned char)aa[0];
	}
}


#ifdef K_AND_R
static void
bigReallyRand(numbytes, num)
  int numbytes;
  BigInt num;
#else
static void bigReallyRand(int numbytes,
			  BigInt num)
#endif
{
	register unsigned char *buf;
	register int nunits;
	
	nunits = (numbytes/sizeof(Ulong));
	if (numbytes % sizeof(Ulong))
		nunits++;
	GUARANTEE(num, (int)nunits);
	LENGTH(num) = (int)nunits;
	
	buf = (unsigned char *)malloc(numbytes);
	reallyRandomBytes(buf, numbytes);
	bufToBig(buf, numbytes, num);
	free((char *)buf);
}

/* Get a random number between a and b. */
#ifdef K_AND_R
_TYPE( void )
getRandBetween(a, b, result, type, randomStart)
  BigInt a, b, result, randomStart;
  RandType type;
#else
_TYPE( void ) getRandBetween(BigInt a,
			     BigInt b,
			     BigInt result,
			     RandType type,
			     BigInt randomStart)
#endif
{
	BigInt T, slop, r, diff, p, q, one, two;
	int length;
	
	diff = bigInit(0);
	p    = bigInit(0);
	q    = bigInit(0);
	one  = bigInit(1);
	two  = bigInit(2);
	
	if (bigCompare(b, a) > 0) {
		bigCopy(a, p);
		bigCopy(b, q);
	}
	else {
		bigCopy(b, p);
		bigCopy(a, q);
	}
	
	bigSubtract(q, p, diff);
	freeBignum(q);
	
	if (bigCompare(diff, two) < 0) {
		handle_exception(CRITICAL, "getRandBetween Error: numbers must differ by at least 2\n");
	}
	
	/* generate a random number between 0 and diff */
	T = bigInit(0);
	slop = bigInit(0);
	bigLeftShift(one, bigBits(diff), T);
	length = (LENGTH(T)*sizeof(Ulong));
	
	bigMod(T, diff, slop);
	freeBignum(T);
	
	r = bigInit(0);
	if (randomStart == NULL) {
		do {
			bigRand(length, r, type);
		} while (bigCompare(r, slop) < 0);
	}
	else {
		bigCopy(randomStart, r);
		while (bigCompare(r, slop) < 0) {
			randomize(r);
		}
	}
	freeBignum(slop);
	
	bigMod(r, diff, result);
	freeBignum(r);
	freeBignum(diff);
	freeBignum(one);
	freeBignum(two);
	
	/* add smaller number back in */
	bigAdd(result, p, result);
	
	freeBignum(p);
}


#ifdef K_AND_R
static void
bigPseudoRand(numbytes, num)
  int  numbytes;
  BigInt num;
#else
  static void bigPseudoRand(int  numbytes,
			    BigInt num)
#endif
{
	register int nunits, i;
	BigData np;
	unsigned long mask;
	
	nunits = (numbytes/sizeof(Ulong));
	
	if (numbytes % sizeof(Ulong))
		nunits++;
	GUARANTEE(num, (int)nunits);
	LENGTH(num) = (int)nunits;
	
	i = numbytes%sizeof(Ulong);
	switch(i) {
	    case 3:
		mask = (unsigned long)0xffffff;
		break;
	    case 2:
		mask = (unsigned long)0xffff;
		break;
	    case 1:
		mask = (unsigned long)0xff;
		break;
	    case 0:
		mask = (unsigned long)0xffffffff;
		break;
	}
	
	np = NUM(num);
	for (i=0; i<LENGTH(num); i++)
		np[i] = pseudoRandom();
	
	np[i-1] &= mask;
}

#ifdef K_AND_R
static void
pseudoRandBytes(buf, numbytes)
  unsigned char *buf;
  int numbytes;
#else
  static void pseudoRandBytes(unsigned char *buf,
			      int numbytes)
#endif
{
	register int i;
	register unsigned char *bp;
	register unsigned long num;
	
	i = numbytes;
	bp = buf;
	bp -= (4 - (i&3));
	
	if (i&3)
		num = pseudoRandom();
	switch(i&3) {
	    case 3:
		bp[1] = (unsigned char)((num>>8) & 0xff);
	    case 2:
		bp[2] = (unsigned char)((num>>16) & 0xff);
	    case 1:
		bp[3] = (unsigned char)((num>>24) & 0xff);
	    case 0:
		bp += 4;
		i -= 4;
	}
	while (i >= 0) {
		num = pseudoRandom();
		bp[0] = (unsigned char)(num & 0xff);
		bp[1] = (unsigned char)((num>>8) & 0xff);
		bp[2] = (unsigned char)((num>>16) & 0xff);
		bp[3] = (unsigned char)((num>>24) & 0xff);
		bp += 4;
		i -= 4;
	}
}


#ifdef K_AND_R
_TYPE( void )
bigRand(numbytes, big, type)
  int numbytes;
  BigInt big;
  RandType type;
#else
_TYPE( void ) bigRand(int numbytes,
		      BigInt big,
		      RandType type)
#endif
{
	if (type == REALLY)
		bigReallyRand(numbytes, big);
	else
		bigPseudoRand(numbytes, big);
}

#ifdef K_AND_R
_TYPE( int ) randomBytes(buf, numbytes, type)
  unsigned char *buf;
  int numbytes;
  RandType type;
#else
_TYPE( int ) randomBytes(unsigned char *buf,
			 int numbytes,
			 RandType type)
#endif
{
	
	if (type == REALLY)
		reallyRandomBytes(buf, numbytes);
	else
		pseudoRandBytes(buf, numbytes);
	
	return 1;
}
/*
int _DLLAPI newRandomBytes(unsigned char *buf, int numbytes, int type)
{

	return randomBytes(buf, numbytes, type);
}
*/

#ifdef K_AND_R
_TYPE( void ) randomize(r)
  BigInt r;
#else
_TYPE( void ) randomize(BigInt r)
#endif
{
	DESState state;
	unsigned char *buf, icv[8], key[128];
	int length, oldlen;
#ifdef DLLEXPORT
	HGLOBAL handle;
#endif

	length = bigBytes(r);
	if (length%8)
		length = length + (8 - length%8);
	
#ifdef DLLEXPORT
	handle = clib_malloc(length);
	buf = (unsigned char *)GlobalLock(handle);
#else
	buf = (unsigned char *)clib_malloc(length);
#endif

	oldlen = LENGTH(r);
	LENGTH(r) = 2;
	bigToBuf(r, 8, icv);
	LENGTH(r) = oldlen;

	key_setup((unsigned char *)"randeyes", key);
	block_cipher(key, icv, 0);
	clib_memzero(buf, length);
	bigToBuf(r, length, buf);
	setupDESState(&state, "randeyes", icv, CBC);
	bufferEncrypt(buf, (int)length, &state);
	bufToBig(buf, bigBytes(r), r);
	
#ifdef DLLEXPORT
	clib_memzero(buf, length);
	GlobalUnlock(handle);
	GlobalFree(handle);
#else
	free(buf);
#endif

}
