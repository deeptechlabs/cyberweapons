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
 *  An implementation of Newton's method for deciding whether
 *  a modulus has a prime root.
 *
 *  Jack Lacy AT&T Bell Labs 1995
 */
#include "libcrypt.h"

static int first53primes[53] = {
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31,
        37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
        79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
        131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
        181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
        239, 241, 251,
};

static void nibpow P((BigInt, int, BigInt));

#ifdef K_AND_R
static Boolean divisibleBy8BitPrime(n)
  BigInt n;
#else
static Boolean divisibleBy8BitPrime(BigInt n)
#endif
{
	register BigData np;
	register int i, j;
	register int N;
	unsigned long m, divisor;
	Ushort m2;
	
	N = (int)LENGTH(n);
	np = NUM(n);
	i = 0;
	do {
		divisor = first53primes[i++];
		m = 0;
		for (j=N-1; j >= 0; j--) {
			m2 = (Ushort)(np[j]>>16) & 0xffff;
			m = ((m<<16) + m2)%divisor;
			m2 = (Ushort)(np[j] & 0xffff);
			m = ((m<<16) + m2)%divisor;
		}
		if (m == 0) {
			return(TRUE);
		}
	} while (i < 53);
	return(FALSE);
}


#ifdef K_AND_R
static void nibpow(x, nib, res)
  BigInt x;
  int nib;
  BigInt res;
#else
static void nibpow(BigInt x, int nib, BigInt res)
#endif
{
	BigInt t0, t1, t2;

	switch(nib) {
	    case 15:
		{
			t0 = bigInit(0);
			t1 = bigInit(0);

			bigMultiply(x, x, t0);
			bigMultiply(t0, t0, t1);
			bigMultiply(x, t1, t0);
			bigMultiply(t0, t0, t1);
			bigMultiply(t0, t1, res);

			freeBignum(t0);
			freeBignum(t1);

			return;
		}
	    case 14:
		{
			t0 = bigInit(0);
			t1 = bigInit(0);
			t2 = bigInit(0);

			bigMultiply(x, x, t0);
			bigMultiply(t0, t0, t1);
			bigMultiply(t0, t1, t2);
			bigMultiply(t1, t1, t0);
			bigMultiply(t0, t2, res);

			freeBignum(t0);
			freeBignum(t1);
			freeBignum(t2);

			return;
		}
	    case 13:
		{
			t0 = bigInit(0);
			t1 = bigInit(0);
			t2 = bigInit(0);

			bigMultiply(x, x, t0);
			bigMultiply(t0, t0, t1);
			bigMultiply(t1, t1, t0);
			bigMultiply(t0, t1, t2);
			bigMultiply(x, t2, res);

			freeBignum(t0);
			freeBignum(t1);
			freeBignum(t2);

			return;
		}
	    case 12:
		{
			t0 = bigInit(0);
			t1 = bigInit(0);

			bigMultiply(x, x, t0);
			bigMultiply(t0, t0, t1);
			bigMultiply(t1, t1, t0);
			bigMultiply(t0, t1, res);

			freeBignum(t0);
			freeBignum(t1);

			return;
		}
	    case 11:
		{
			t0 = bigInit(0);
			t1 = bigInit(0);

			bigMultiply(x, x, t0);
			bigMultiply(t0, t0, t1);
			bigMultiply(x, t1, t0);
			bigMultiply(t0, t0, t1);
			bigMultiply(x, t1, res);

			freeBignum(t0);
			freeBignum(t1);

			return;
		}
	    case 10:
		{
			t0 = bigInit(0);
			t1 = bigInit(0);

			bigMultiply(x, x, t0);
			bigMultiply(t0, t0, t1);
			bigMultiply(x, t1, t0);
			bigMultiply(t0, t0, res);

			freeBignum(t0);
			freeBignum(t1);

			return;
		}
	    case 9:
		{
			t0 = bigInit(0);
			t1 = bigInit(0);

			bigMultiply(x, x, t0);
			bigMultiply(t0, t0, t1);
			bigMultiply(t1, t1, t0);
			bigMultiply(x, t0, res);

			freeBignum(t0);
			freeBignum(t1);

			return;
		}
	    case 8:
		{
			t0 = bigInit(0);
			t1 = bigInit(0);

			bigMultiply(x, x, t0);
			bigMultiply(t0, t0, t1);
			bigMultiply(t1, t1, res);

			freeBignum(t0);
			freeBignum(t1);

			return;
		}
	    case 7:
		{
			t0 = bigInit(0);
			t1 = bigInit(0);

			bigMultiply(x, x, t0);
			bigMultiply(x, t0, t1);
			bigMultiply(t1, t1, t0);
			bigMultiply(x, t0, res);

			freeBignum(t0);
			freeBignum(t1);

			return;
		}
	    case 6:
		{
			t0 = bigInit(0);
			t1 = bigInit(0);

			bigMultiply(x, x, t0);
			bigMultiply(t0, t0, t1);
			bigMultiply(t0, t1, res);

			freeBignum(t0);
			freeBignum(t1);

			return;
		}
	    case 5:
		{
			t0 = bigInit(0);
			t1 = bigInit(0);

			bigMultiply(x, x, t0);
			bigMultiply(t0, t0, t1);
			bigMultiply(x, t1, res);

			freeBignum(t0);
			freeBignum(t1);

			return;
		}
	    case 4:
		{
			t0 = bigInit(0);

			bigMultiply(x, x, t0);
			bigMultiply(t0, t0, res);

			freeBignum(t0);

			return;
		}
	    case 3:
		{
			t0 = bigInit(0);

			bigMultiply(x, x, t0);
			bigMultiply(x, t0, res);

			freeBignum(t0);

			return;
		}
	    case 2:
		bigMultiply(x, x, res);
		return;

	    case 1:
		bigCopy(x, res);
		return;
	}
}

#define NIBBLE(B,N) (((NUM(B)[(N) >> 3] >> (((N) & 7) << 2)) & 15))
#define NIBSPERCHUNK 8

#ifdef K_AND_R
static BigInt bpow(x, p)
  BigInt x;
  unsigned long p;
#else
static BigInt bpow(BigInt x, unsigned long p)
#endif
{
	BigInt tmp, xp, bigp, tmp2;
	int i;
	int nib;

	bigp = bigInit(p);

	for (i = (int)(NIBSPERCHUNK*LENGTH(bigp) - 1); i >= 0; --i) {
		if (NIBBLE(bigp, i))
			break;
	}
	
	xp = bigInit(0);
	tmp = bigInit(1);
	tmp2 = bigInit(0);
	for (;;--i) {
		nib = (int)NIBBLE(bigp, i);
		if (nib) {
			nibpow(x, nib, tmp2);
			bigMultiply(tmp2, tmp, xp);
		}
			
		if (i == 0)
			break;

		bigMultiply(xp, xp, tmp);
		bigMultiply(tmp, tmp, xp);
		bigMultiply(xp, xp, tmp);
		bigMultiply(tmp, tmp, xp);
		bigCopy(xp, tmp);
	}
	freeBignum(tmp);
	freeBignum(tmp2);
	freeBignum(bigp);

	return xp;

}

#ifdef K_AND_R
static BigInt newx(x, N, p)
  BigInt x;
  BigInt N;
  int p;
#else
static BigInt newx(BigInt x, BigInt N, int p)
#endif
{
	BigInt nx, xp, xp1, tmp, bigp, rem;
	
	nx = bigInit(0);
	xp = bigInit(0);
	tmp = bigInit(0);
	bigp = bigInit(p);
	rem = bigInit(0);

	xp1 = bpow(x, p-1);
	bigMultiply(x, xp1, xp);

	bigSubtract(bigp, one, tmp);
	bigMultiply(tmp, x, nx);
	bigDivide(N, xp1, tmp, rem);
	bigAdd(tmp, nx, nx);
	bigDivide(nx, bigp, tmp, rem);
	bigCopy(tmp, nx);

	freeBignum(xp);
	freeBignum(xp1);
	freeBignum(tmp);
	freeBignum(bigp);
	freeBignum(rem);

	return(nx);
}


#ifdef K_AND_R
_TYPE( Boolean ) hasPthRoot(c, p)
  BigInt c;
  int p;
#else
_TYPE( Boolean ) hasPthRoot(BigInt c, int p)
#endif
{
	Boolean retval;
	BigInt nx, x, oldx;
	int bytes, bits, iterations;

	bytes = (((bigBits(c)+7)/8) + p - 1)/p;
	bits = (bigBits(c)+p-1)/p;

	oldx = bigInit(0);
	nx = bigInit(1);

    dorand:
	iterations = 0;

	bigRand(bytes, nx, PSEUDO);
	if (bigBits(nx) > bits)
		bigRightShift(nx, (bigBits(nx)-bits), nx);

	while (1) {
		x = newx(nx, c, p);
		/* If estimate leads to haywire behavior, get
		   new estimate.
		 */
		if (bigBits(x) >= 2*bigBits(nx)) {
			freeBignum(x);
			goto dorand;
		}
		if ((bigCompare(x, nx) == 0) ||
		    (bigCompare(oldx, x) == 0)) {	/* Stops toggle */
			break;
		}
		bigCopy(nx, oldx);
		bigCopy(x, nx);

		freeBignum(x);
	}
	freeBignum(x);
	x = bpow(nx, p);
	if (bigCompare(x, c) == 0) {
#ifdef NEWTON_DEBUG		
		printf("%d-th root = ", p); bigprint(x);
#endif
		retval = 1;
	}
	else {
#ifdef NEWTON_DEBUG		
		printf("no %d-th root\n ", p);
#endif
		retval = 0;
	}
	freeBignum(nx);
	freeBignum(x);
	freeBignum(oldx);

	return retval;

}

#ifdef K_AND_R
_TYPE( Boolean ) modulus_OK(c)
  BigInt c;
#else
_TYPE( Boolean ) modulus_OK(BigInt c)
#endif
{
	int i, p, limit;

	/* If modulus is even, return FALSE. */
	if (even(c))
		return FALSE;

	/* Is modulus divisible by one of the first 53 primes?
	   If so, return false.
	 */
	if (divisibleBy8BitPrime(c))
		return FALSE;

	/* If modulus is prime, return FALSE. */
	if (primeTest(c) == TRUE)
		return FALSE;


	/* Check for prime pth roots */
	p = 2;
	if (hasPthRoot(c, p))
		return FALSE;
	limit = bigBits(c)/8;
	for (i=0; i<53; i++) {
		p = first53primes[i];
		if (p > limit)
			return TRUE;
		if (hasPthRoot(c, p))
			return FALSE;
	}
	return TRUE;
}

#ifdef NEWTON_DEBUG
extern int bigNumsAllocated;

main() {
	BigInt a, b, c;
	int start;

	a = bigInit(0);
	getPrime(9, a);
	printf("root = "); bigprint(a);
	printf("bigs left = %d\n", bigNumsAllocated);

	c = bpow(a, (1024/9));
	printf("bigs left = %d\n", bigNumsAllocated);

	printf("cbits = %d  root^%d = ", bigBits(c), (1024/9)); bigprint(c);
	printf("\n\n");

	start = clock();
	if (modulus_OK(c))
		printf("Modulus OK.\n");
	else
		printf("Modulus NOT OK.\n");
	printf("time = %f\n", (clock()-start)/1000.0);
	printf("bigs left = %d\n", bigNumsAllocated);

	freeBignum(a);
	freeBignum(c);
}

#endif

