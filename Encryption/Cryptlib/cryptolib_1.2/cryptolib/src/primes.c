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
 *        Prime number generator and tests utilizing Rabin's
 *        compositeness test and Gordon's strong prime concept.
 *
 *        coded by Jack Lacy, December, 1991
 *
 *        Copyright (c) 1991 AT&T Bell Laboratories
 */
#include "libcrypt.h"

static int long_log P((int));
static int fakelog P((int));
static Boolean probPrimeTest P((BigInt));
static Boolean first53Test P((BigInt));
static Boolean genGordonPrimeSet P((int, BigInt, int, BigInt, BigInt, BigInt));
static Boolean genNISTPrimeSet P((int, BigInt, int, BigInt, BigInt, BigInt));

static int first_53_primes[53] = {
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31,
        37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
        79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
        131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
        181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
        239, 241, 251,
};

#define RLEN(a, i) ((a >= i) && (a < 2*i))

#ifdef K_AND_R
static int
long_log(n)
  int n;
#else
  static int long_log(int n)
#endif
{
	
	int i, j;
	
	i = 8192;
	j = 13;
	while(1) {
		if (RLEN(n, i))
			return j;
		else {
			j++;
			i *= 2;
		}
	}
}

#ifdef K_AND_R
static int
fakelog(n)
  int n;
#else
  static int fakelog(int n)
#endif
{
	
	switch(n) {
	    case 2:    return(1);
	    case 4:    return(2);
	    case 8:    return(3);
	    case 16:   return(4);
	    case 32:   return(5);
	    case 64:   return(6);
	    case 128:  return(7);
	    case 256:  return(8);
	    case 512:  return(9);
	    case 1024: return(10);
	    case 2048: return(11);
	    case 4096: return(12);
	    default:
		if (RLEN(n, 2))
			return fakelog(2);
		else if (RLEN(n, 4))
			return fakelog(4);
		else if (RLEN(n, 8))
			return fakelog(8);
		else if (RLEN(n, 16))
			return fakelog(16);
		else if (RLEN(n, 32))
			return fakelog(32);
		else if (RLEN(n, 64))
			return fakelog(64);
		else if (RLEN(n, 128))
			return fakelog(128);
		else if (RLEN(n, 256))
			return fakelog(256);
		else if (RLEN(n, 512))
			return fakelog(512);
		else if (RLEN(n, 1024))
			return fakelog(1024);
		else if (RLEN(n, 2048))
			return fakelog(2048);
		else
			return long_log(n);
	}
}

int primeTestAttempts = 5;

#ifdef K_AND_R
_TYPE( void )
setPrimeTestAttempts(i)
  int i;
#else
_TYPE( void ) setPrimeTestAttempts(int i)
#endif
{
	primeTestAttempts = i;
}

#ifdef K_AND_R
static Boolean
probPrimeTest(n)
  BigInt n;
#else
  static Boolean probPrimeTest(BigInt n)
#endif
{
	Boolean retval = FALSE;
	register int j, k = 0;
#ifndef DLLEXPORT
	static BigInt nminus1, x, y, q;
	static int first_time = 1;
	
	if (first_time) {
		first_time = 0;
		nminus1 = bigInit(0);
		q       = bigInit(0);
		x        = bigInit(0);
		y        = bigInit(0);
	}
#else
	BigInt nminus1, x, y, q;
	
	nminus1 = bigInit(0);
	q       = bigInit(0);
	x        = bigInit(0);
	y        = bigInit(0);
#endif
	bigsub(n, one, nminus1);
	bigCopy(nminus1, q);
	
	while (even(q)) {
		k++;
		bigRightShift(q, (int)1, q);
	}
	
	getRandBetween(one, n, x, PSEUDO, NULL);
	bigPow(x, q, n, y);
	
	j = 0;
	if (bigCompare(y, one) == 0) {
		retval = TRUE;
	}
	
	while ((j < k) && (retval == FALSE)) {
		if (bigCompare(y, nminus1) == 0) {
			retval = TRUE;
			break;
		}
		if (bigCompare(y, one) == 0) {
			retval = FALSE;
			break;
		}
		j++;
		bigMultiply(y, y, q);
		bigMod(q, n, y);
	}
#ifdef DLLEXPORT
	freeBignum(x);
	freeBignum(nminus1);
	freeBignum(q);
	freeBignum(y);
#endif
	return retval;
}


#ifdef K_AND_R
static Boolean
first53Test(n)
  BigInt n;
#else
static  Boolean first53Test(BigInt n)
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
		divisor = first_53_primes[i++];
		m = 0;
		for (j=N-1; j >= 0; j--) {
			m2 = (Ushort)(np[j]>>16) & 0xffff;
			m = ((m<<16) + m2)%divisor;
			m2 = (Ushort)(np[j] & 0xffff);
			m = ((m<<16) + m2)%divisor;
		}
		if (m == 0) {
			return(FALSE);
		}
	} while (i < 53);
	return(TRUE);
}


#ifdef K_AND_R
_TYPE( Boolean )
primeTest(n)
  BigInt n;
#else
_TYPE( Boolean ) primeTest(BigInt n)
#endif
{
	register int k;
	int accuracy;
	BigData np = NUM(n);
	
	if (LENGTH(n) == 1) {
		k = 0;
		do {
			if (np[0] == (Ulong)first_53_primes[k++])
				return(TRUE);
		} while (k < 53);
	}
	
	if (even(n))
		return(FALSE);
	
	if (first53Test(n) == FALSE)
		return(FALSE);
	
	accuracy = primeTestAttempts;
	while ((accuracy > 0) && probPrimeTest(n) == TRUE)
		accuracy--;
	
	if (accuracy == 0)
		return(TRUE);
	else
		return(FALSE);
}

#ifdef K_AND_R
_TYPE( int )
randBytesNeededForPrime (plen, qlen, type)
  int plen, qlen;
  PrimeType type;
#else
_TYPE( int ) randBytesNeededForPrime (int plen, int qlen, PrimeType type)
#endif
{
	int bytes;

	if (type == GORDON)
		bytes = (plen/8 + (plen%8? 1: 0));
	else
		bytes = ((plen + qlen)/8) + ((plen+qlen)%8?1:0);
	return bytes;
}

#ifdef K_AND_R
_TYPE( void )
getPrime(numbits, prime, randomStart)
  int numbits;
  BigInt prime, randomStart;
#else
_TYPE( void ) getPrime(int numbits,
		       BigInt prime,
		       BigInt randomStart)
#endif
{
	int numbytes;
	int shiftdiff;
	
	numbytes = (numbits/8);
	if (numbits%8 != 0)
		numbytes++;
	
	if (randomStart == NULL)
		bigRand(numbytes, prime, PSEUDO);
	else
		bigCopy(randomStart, prime);
	
	shiftdiff = (bigBits(prime) - numbits);
	if (shiftdiff > 0)
		bigRightShift(prime, (int)shiftdiff, prime);
	else if (shiftdiff < 0)
		bigLeftShift(prime, (int)(-shiftdiff), prime);
	
	if (EVEN(prime)) {
		NUM(prime)[0] |= 1;
	}
	
	while (1) {
		if (primeTest(prime) == TRUE)
			return;
		NUM(prime)[0] += 2;
	}
}

/*
   Generate strong primes using Gordon's method and
   Rabin's probabilistic primality test.  This function
   returns the strong prime p as well as r, a prime factor
   of p-1.
   */
#ifdef K_AND_R
static Boolean
genGordonPrimeSet(numbits, prime, factorbits, factor, r1, r2)
  int numbits, factorbits;
  BigInt prime, factor, r1, r2;
#else
  static Boolean genGordonPrimeSet(int numbits,
				   BigInt prime,
				   int factorbits,
				   BigInt factor,
				   BigInt r1,
				   BigInt r2)
#endif
{
	register BigInt r, pzero, twors;
	BigInt s, t, p, rs, ss, rr;
	BigInt rminus1, sminus1, twot;
	int pbits, tbits, rbits, sbits;
	Boolean found;
	
	/* the two return values */
	p = prime;
	r = factor;
	
	pbits = numbits;
	rbits = (pbits - fakelog(pbits) - 1);
	sbits = rbits/2;
	rbits = sbits;
	tbits = rbits - fakelog(rbits) - 1;
	
	s = bigInit(0);
	t = bigInit(0);
	getPrime(sbits, s, r1);
	getPrime(tbits, t, r2);
	
	/* find r -- r = 2Lt + 1 and is prime */
	twot = bigInit(0);
	bigLeftShift(t, 1, twot);
	
	reset_big(r, 1);
	bigAdd(r, twot, r);
	
	while (primeTest(r) == FALSE)
		bigAdd(r, twot, r);
	
	freeBignum(t);
	freeBignum(twot);
	
	/*
	   find p -- p = p0 + 2krs where:
	   p0 = u(r,s);        u(r,s) odd
	   p0 = u(r,s) + rs;   u(r,s) even
	   u(r,s) = (s^(r-1) - r^(s-1))mod rs.
	   */
	rs = bigInit(0);
	rminus1 = bigInit(0);
	sminus1 = bigInit(0);
	
	bigMultiply(r, s, rs);
	bigSubtract(r, one, rminus1);
	bigSubtract(s, one, sminus1);
	
	ss = bigInit(0);
	rr = bigInit(0);
	bigPow(s, rminus1, rs, ss);
	bigPow(r, sminus1, rs, rr);
	
	pzero = bigInit(0);
	bigSubtract(ss, rr, pzero);
	
	if (SIGN(pzero) == NEG) {
		negate(pzero, rs, pzero);
	}
	
	if (EVEN(pzero))
		bigAdd(pzero, rs, pzero);
	
	freeBignum(s);
	freeBignum(ss);
	freeBignum(rr);
	freeBignum(rminus1);
	freeBignum(sminus1);
	
	twors = bigInit(0);
	bigLeftShift(rs, 1, twors);
	freeBignum(rs);
	
	reset_big(p, (Ulong)0);
	bigAdd(pzero, p, p);
	
	while (bigBits(p) < pbits)
		bigAdd(p, twors, p);
	
	found = TRUE;
	
	while (primeTest(p) == FALSE) {
		bigAdd(p, twors, p);
		if (bigBits(p) > pbits) {
			found = FALSE;
			break;
		}
	}
	
	freeBignum(twors);
	
#ifndef NDEBUG
	if (found) {
		BigInt pminus1;
		/* verify that p and r are ok */
		pminus1 = bigInit(0);
		bigSubtract(p, one, pminus1);
		bigMod(pminus1, r, pzero);
		freeBignum(pminus1);
		
		if (bigCompare(pzero, zero) != 0)
			handle_exception(WARNING, "genGordonPrimeSet: DEBUG: pzero non-zero.\n");
	}
#endif
	
	freeBignum(pzero);
	
	return found;
}

#ifdef K_AND_R
static Boolean
genNISTPrimeSet(numbits, prime, facbits, factor, p_randomStart, q_randomStart)
  int numbits, facbits;
  BigInt prime, factor, p_randomStart, q_randomStart;
#else
  static Boolean genNISTPrimeSet(int numbits,
				 BigInt prime,
				 int facbits,
				 BigInt factor,
				 BigInt p_randomStart,
				 BigInt q_randomStart)
#endif
{
	int qlen;
	BigInt p, q, twoq, tmp, ignore, n;
	BigInt smallseed, bigseed;
	Boolean primeVal;
	
	p                = prime;
	q                = factor;
	twoq        = bigInit(0);
	tmp                = bigInit(0);
	ignore        = bigInit(0);
	n                = bigInit(0);
	smallseed        = bigInit(0);
	bigseed        = bigInit(0);
	
	qlen = facbits;
	getPrime(qlen, q, q_randomStart);
	bigLeftShift(q, (int)1, twoq);
	
	bigLeftShift(one, numbits, tmp);
	bigSubtract(tmp, one, tmp);
	bigDivide(tmp, twoq, bigseed, ignore);
	
	bigLeftShift(one, (int)(numbits-1), tmp);
	bigSubtract(tmp, one, tmp);
	bigDivide(tmp, twoq, smallseed, ignore);
	
	freeBignum(tmp);
	freeBignum(ignore);
	
	primeVal = FALSE;
	getRandBetween(bigseed, smallseed, n, PSEUDO, p_randomStart);
	bigSubtract(n, one, n);
	
	while (primeVal == FALSE) {
		bigAdd(n, one, n);
		bigMultiply(n, twoq, p);
		bigAdd(p, one, p);
		primeVal = primeTest(p);
	}
	freeBignum(smallseed);
	freeBignum(bigseed);
	freeBignum(twoq);
	freeBignum(n);
	
	return primeVal;
	
}


#ifdef K_AND_R
_TYPE( void )
genStrongPrimeSet(numbits, prime, facbits, factor, type, randomStart)
  int numbits, facbits;
  BigInt prime, factor, randomStart;
  PrimeType type;
#else
_TYPE( void ) genStrongPrimeSet(int numbits,
				BigInt prime,
				int facbits,
				BigInt factor,
				PrimeType type,
				BigInt randomStart)
#endif
{
	BigInt r1, r2;
	int oldlen;
	
	if (randomStart != NULL) {
		r1 = bigInit(0);
		r2 = bigInit(0);
	}
	else {
		r1 = NULL;
		r2 = NULL;
	}

	if (type == NIST) {
		if (randomStart != NULL) {
			oldlen = LENGTH(randomStart);
			LENGTH(randomStart) = facbits/32;
			bigCopy(randomStart, r1);
			LENGTH(randomStart) = oldlen;
			bigRightShift(randomStart, facbits, r2);
		}
		genNISTPrimeSet(numbits, prime, facbits, factor, r2, r1);
	}
	else if (type == GORDON) {
		if (randomStart != NULL) {
			oldlen = LENGTH(randomStart);
			LENGTH(randomStart) = numbits/32/2;
			bigCopy(randomStart, r1);
			LENGTH(randomStart) = oldlen;
			bigRightShift(randomStart, numbits/2, r2);
			LENGTH(r2) = numbits/32/2;
		}
		while (genGordonPrimeSet(numbits, prime, facbits, factor, r1, r2) == FALSE) {
			reset_big(prime, (Ulong)0);
			reset_big(factor, (Ulong)0);
			if (r1 != NULL) {
				randomize(r1);
				randomize(r2);
			}
		}
	}
	if (r1 != NULL) {
		freeBignum(r1);
		freeBignum(r2);
	}
}

#ifdef K_AND_R
_TYPE( void )
genStrongPrime(numbits, prime, randomStart)
  int numbits;
  BigInt prime, randomStart;
#else
_TYPE( void ) genStrongPrime(int numbits,
			     BigInt prime,
			     BigInt randomStart)
#endif
{
	BigInt factor;
	
	factor = bigInit(0);
	
	genStrongPrimeSet(numbits, prime, 160, factor, NIST, randomStart);
	
	freeBignum(factor);
}

#ifdef K_AND_R
_TYPE( int )
randBytesNeededForRoot (plen)
  int plen;
#else
_TYPE( int )randBytesNeededForRoot (int plen)
#endif
{
	int bytes;

	bytes = (plen/8 + (plen%8? 1: 0));

	return bytes;
}

/* f is a factor of p-1 */
#ifdef K_AND_R
_TYPE( void )
getPrimitiveElement(a, p, f, randomStart)
  BigInt a, p, f, randomStart;
#else
_TYPE( void ) getPrimitiveElement(BigInt a,
				  BigInt p,
				  BigInt f,
				  BigInt randomStart)
#endif
{
	BigInt pminus1, tmp, d;
	
	pminus1 = bigInit(0);
	tmp = bigInit(0);
	d = bigInit(0);
	
	bigSubtract(p, one, pminus1);
	bigDivide(pminus1, f, d, tmp);
	getRandBetween(p, one, a, PSEUDO, randomStart);

	bigPow(a, d, p, tmp);
	while (bigCompare(tmp, one) == 0) {
		bigAdd(a, one, a);
		bigPow(a, d, p, tmp);
	}
	
	freeBignum(pminus1);
	freeBignum(tmp);
	freeBignum(d);
}

