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
 *  Multiplication and squaring using Knuth's n^log3 algorithm
 *  in conjunction with n^2 multiplication and regular squaring
 *  speedups (bigmult and bigsquare) to terminate recursion.
 *  User function bigMultiply is made available here.
 *  If the multiplicands are equal (the same pointer) then
 *  squaring is done.
 *
 *  By D. P. Mitchell and Jack Lacy 11/91.
 *
 *  Copyright (c) 1991 AT&T Bell Laboratories
 */
#include "libcrypt.h"

static int get_recurse_len P((int));
static int bigCompareLongs P((BigData, BigData, int));
static void recursiveMultiply P((Ulong *, Ulong *, Ulong *, Ulong *, int));
static void recursiveSquare P((Ulong *, Ulong *, Ulong *, int));
static void fast_mult P((BigInt, BigInt, BigInt));
static void fast_square P((BigInt, BigInt));

#define ADDSTEP(i, C, A, B) { \
 suml = (A)[(i)] + (B)[(i)]; \
 sumh = ((Ulong)suml < (A)[(i)]); \
 (C)[(i)] = carry + suml; \
 carry = ((C)[(i)] < (Ulong)suml) + sumh; \
}

#define SUBSTEP(i, C, A, B) { \
 suml = ((long)(A)[(i)] - (long)(B)[(i)]); \
 sumh = - ((Ulong)suml > (A)[(i)]); \
 C[i] = suml + carry; \
 carry = (-((C)[(i)] > (Ulong)suml)) + sumh; \
}

#define ADD3STEP(i, T, C, A, B) { \
 (T)[(i)] = (A)[(i)] + (B)[(i)]; \
 sumh = ((T)[(i)] < (A)[(i)]); \
 suml = (T)[(i)] + carry; \
 sumh += ((Ulong)suml < (T)[(i)]); \
 (T)[(i)] = (unsigned long)suml + (C)[(i)]; \
 carry = sumh + ((T)[(i)] < (Ulong)suml); \
}


#ifdef NO_ASM /* If no assembly version of 32 bit mult, take full advantage of
		 Karatsuba and recurse to finish.
	       */
#define RECURSIONCUTOFF 2
#define SQRECCUTOFF 2
#else
#define RECURSIONCUTOFF 64
#define SQRECCUTOFF 64
#endif

#define RLEN(a, i) ((a >= i) && (a < 2*i))
#define MAXRECLEN 128  /* This sets the largest numbers that can be mulitplied together
			  to 64*4*8 = 2048 bytes giving an 4096 byte result.  If this
			  isn't large enough, change this parameter.
			*/
static Ulong tmp[MAXRECLEN];

#ifdef K_AND_R
static int
get_recurse_len(alen)
  int alen;
#else
  static int get_recurse_len(int alen)
#endif
{
	register int recurse_len;
	
	recurse_len = 2;
	
	while (1) {
		if (RLEN(alen, recurse_len))
			return recurse_len;
		else
			recurse_len *= 2;
	}
}


#define LESSTHAN(A,B,i) ((A[i-1] < B[i-1]) ? 1 : \
                         ((A[i-1] > B[i-1]) ? 0 : \
                          (bigCompareLongs(A,B,i) < 0)))

#ifdef K_AND_R
static int
bigCompareLongs(a, b, N)
  Ulong *a, *b;
  int N;
#else
  static int bigCompareLongs(Ulong *a,
			     Ulong *b,
			     int N)
#endif
{
	register int i;
	register Ulong *ap, *bp;
	
	i = (int)N-1;
	ap = a;
	bp = b;
	while ((i >= 0L) && (ap[i] == bp[i]))
		i--;
	
	if (i < 0)
		return 0;
	if (ap[i] < bp[i])
		return -1;
	else
		return 1;
	
}


/* MULTIPLICATION (not squaring) */
/* Recursive Karatsuba multiplication - for A, B length 2N
 * A = | a1 | a0 |
 * B = | b1 | b0 |
 * C = | c3 | c2 | c1 | c0 |
 * T = | t3 | t2 | t1 | t0 | (tmp scratch space)
 * each segment is Nover2 long and t1 and t3 are unused
 *      (and undeclared)
 * A*B = 2^2N(a1b1) + 2^N(a1b1 + (a1-a0)(b0-b1) + a0b0) + a0b0
 * Before the 3 recursive calls:
 * c = | (u1-u0) | (v0-v1) | --scratch N bits-- |
 * Afterwards:
 * c = | u1v1 (N bits) | u0v0 (N bits) |
 * t = | --scratch N bits-- | (u1-u0)*(v0-v1) (N bits) |
 */
#ifdef K_AND_R
static void
recursiveMultiply(a, b, c, t, N)
  Ulong a[], b[], c[], t[];
  long N;
#else
  static void recursiveMultiply(Ulong a[],	/* multiplicand */
				Ulong b[],	/* multiplier   */
				Ulong c[],	/* product      */
				Ulong t[],	/* N word tmp space */
				int N)
#endif
{
	register long sumh, suml, carry;
	register int i, Nover2;
	Ulong *a0, *a1, *b0, *b1, *c0, *c1, *c2, *c3;
	Ulong *u, *v, *t0, *t2;
	long signAdiff, signBdiff, carryABAB;
	
	if (N == RECURSIONCUTOFF) {
		Ulong_bigmultN(a, b, c, (int)N);
		return;
	}
	Nover2 = N >> 1;
	
	a0 = a; a1 = a0 + (int)Nover2;
	b0 = b; b1 = b0 + (int)Nover2;
	c0 = c; c1 = c0 + (int)Nover2; c2 = c1 + (int)Nover2; c3 = c2 + (int)Nover2;
	t0 = t; t2 = t0 + (int)N;
	
	u = a1; v = a0;
	signAdiff = 1;
	if (LESSTHAN(u, v, (int)Nover2) == 1) {
		u = a0; v = a1;
		signAdiff = 0;
	}
	carry = 0;
	for (i=0; i<Nover2; i++)
		SUBSTEP((int)i,c3,u,v);
	
	u = b0; v = b1;
	signBdiff = 1;
	if (LESSTHAN(u, v, (int)Nover2) == 1) {
		u = b1;	v = b0;
		signBdiff = 0;
	}
	carry = 0;
	for (i=0; i<Nover2; i++)
		SUBSTEP((int)i,c2,u,v);
	
	recursiveMultiply(c3, c2, t0, t2, (int)Nover2);
	recursiveMultiply(a0, b0, c0, t2, (int)Nover2);
	recursiveMultiply(a1, b1, c2, t2, (int)Nover2);
	
	carry = 0;
	for (i=0; i<N; i++)
		ADD3STEP(i,t2,c0,c1,c2);
	carryABAB = carry;
	
	carry = 0;
	if ((signAdiff ^ signBdiff) != 0) {
		for (i=0; i<N; i++)
			SUBSTEP(i,c1,t2,t0);
	}
	else {
		for (i=0; i<N; i++)
			ADDSTEP(i,c1,t2,t0);
	}
	
	carry += carryABAB;
	for (i=N; (i<N+Nover2) && (carry != 0); i++) {
		c1[i] += carry;
		carry = (c1[i] < (Ulong)carry);
	}
	
}


/* SQUARING */
/* Recursive Karatsuba squaring - for A length N
 * A = | a1 | a0 |
 * C = | c3 | c2 | c1 | c0 |
 * T = | t3 | t2 | t1 | t0 | (tmp scratch space)
 * each segment is Nover2 long and t1, t3 and c3 are unused
 *      (and undeclared)
 * A*B = (2^2N)*(a1a1) + (2^N)*(a1a1 + (a1-a0)(a0-a1) + a0a0) + a0a0
 * Before the 3 recursive calls:
 * c = | (a1-a0) (N/2 bits) | scratch (N bits) |
 * 
 * Afterwards:
 * c = | a1a1 (N bits) | a0a0 (N bits) |
 * t = | --scratch N bits-- | (a1-a0)^2 (Nbits) |
 */
#ifdef K_AND_R
static void
recursiveSquare(a, c, t, N)
  Ulong a[], c[], t[];
  int N;
#else
  static void recursiveSquare(Ulong a[],
			      Ulong c[],
			      Ulong t[],
			      int N)
#endif
{
	register long sumh, suml, carry;
	register int i, Nover2;
	Ulong *a0, *a1, *u, *v;
	Ulong *t0, *t2, *c0, *c1, *c2;
	long carryAA;
	
	if (N == SQRECCUTOFF) {
		Ulong_bigsquareN(a, c, N);
		return;
	}
	Nover2 = N >> 1;
	
	a0 = a; a1 = a0 + Nover2;
	c0 = c; c1 = c0 + Nover2; c2 = c1 + Nover2;
	t0 = t; t2 = t0 + N;
	
	u = a1; v = a0;
	if (LESSTHAN(u, v, Nover2) == 1) {
		u = a0; v = a1;
	}
	carry = 0;
	for (i=0; i<Nover2; i++)
		SUBSTEP(i,c2,u,v);
	
	recursiveSquare(c2, t0, t2, Nover2);
	recursiveSquare(a0, c0, t2, Nover2);
	recursiveSquare(a1, c2, t2, Nover2);
	
	carry = 0;
	for (i=0; i<N; i++)
		ADD3STEP(i,t2,c0,c1,c2);
	carryAA = carry;
	
	carry = 0;
	for (i=0; i<N; i++)
		SUBSTEP(i,c1,t2,t0);
	
	carry += carryAA;
	for (i=N; (i<N+Nover2) && (carry != 0); i++) {
		c1[i] += carry;
		carry = (c1[i] < (Ulong)carry);
	}
}


#ifdef K_AND_R
static void
cleanMult(a, b, c, L)
  BigInt a, b, c;
  int L;
#else
  static void cleanMult(BigInt a,
			BigInt b,
			BigInt c,
			int L)
#endif
{
	register int i, j, k;
	register int alen, blen;
	register BigData ap, bp;
	register Ulong m;
	
	alen = LENGTH(a);
	blen = LENGTH(b);
	
	/* A1 * B */
	ap = NUM(a)+L;
	j = (alen-L);
	k = L;
	for (i=0; i<j; i++) {
		m = ap[0];
		Ulong_bigmult(b, m, c, k);
		ap++;
		k++;
	}
	
	/* A0 * B1 */
	LENGTH(a) = L;
	bp = NUM(b)+L;
	j = blen-L;
	k = L;
	for (i=0; i<j; i++) {
		m = bp[0];
		Ulong_bigmult(a, m, c, k);
		bp++;
		k++;
	}
	LENGTH(a) = (int)alen;
	
}



#ifdef K_AND_R
static void
fast_mult(a, b, c)
  BigInt a, b, c;
#else
  static void fast_mult(BigInt a,
			BigInt b,
			BigInt c)
#endif
{
	register int alen, blen, recurse_len;
	
	alen = LENGTH(a);
	blen = LENGTH(b);
	
	if ((alen <= RECURSIONCUTOFF) || (blen <= RECURSIONCUTOFF) ||
	    (alen < 2*blen/3) || (blen < 2*alen/3)) {
		lbigmult(a, b, c);
		return;
	}
	GUARANTEE(c, (int)(alen+blen));
	
	if (alen > blen)
		alen = blen;
	
	recurse_len = get_recurse_len(alen);

	if (recurse_len*2 > MAXRECLEN) {
		handle_exception(CRITICAL, "fast_square: Number is too big for static tmp array.\n");
	}

	recursiveMultiply(NUM(a), NUM(b), NUM(c), tmp, recurse_len);
	
	LENGTH(c) = (int)(2*recurse_len);
	while ((NUM(c)[LENGTH(c)-1] == 0) && (LENGTH(c) > 1))
		LENGTH(c)--;
	
	if ((LENGTH(a) != (int)recurse_len) || (LENGTH(b) != (int)recurse_len))
		cleanMult(a, b, c, recurse_len);
	
}

#ifdef K_AND_R
static void
cleanSquare(a, c, L)
  BigInt a, c;
  int L;
#else
  static void cleanSquare(BigInt a,
			  BigInt c,
			  int L)
#endif
{
	register int i, j, k;
	register BigData ap;
	register int alen;
	register Ulong m;
	
	alen = LENGTH(a);
	
	/* A1 * A */
	j = alen-L;
	ap = NUM(a)+L;
	k = L;
	for (i=0; i<j; i++) {
		m = ap[0];
		Ulong_bigmult(a, m, c, k);
		ap++;
		k++;
	}
	
	/* A0 * A1 */
	ap = NUM(a)+L;
	LENGTH(a) = (int)L;
	k = L;
	for (i=0; i<j; i++) {
		m = ap[0];
		Ulong_bigmult(a, m, c, k);
		ap++;
		k++;
	}
	LENGTH(a) = (int)alen;
	
}

#ifdef K_AND_R
static void
fast_square(a, c)
  BigInt a, c;
#else
  static void fast_square(BigInt a,
			  BigInt c)
#endif
{
	register int alen, recurse_len;
	
	alen = LENGTH(a);
	
	if (alen <= SQRECCUTOFF) {
		bigsquare(a, c);
		return;
	}
	
	GUARANTEE(c, (int)(2*alen));
	recurse_len = get_recurse_len(alen);
	
	if (recurse_len*2 > MAXRECLEN)
		handle_exception(CRITICAL, "fast_square: Number is too big for static tmp array.\n");
	
	recursiveSquare(NUM(a), NUM(c), tmp, recurse_len);
	LENGTH(c) = (int)(2*recurse_len);
	while ((NUM(c)[LENGTH(c)-1] == 0) && (LENGTH(c) > 1))
		LENGTH(c)--;
	
	if (alen != recurse_len)
		cleanSquare(a, c, recurse_len);
}



#ifdef K_AND_R
_TYPE( void )
bigMultiply(a, b, result)
  BigInt a, b, result;
#else
_TYPE( void ) bigMultiply(BigInt a,
			  BigInt b,
			  BigInt result)
#endif
{
	
	if (a == b) {
		fast_square(a, result);
		SIGN(result) = POS;
	}
	else {
		fast_mult(a, b, result);
		SIGN(result) = (int)SIGN(a)*(int)SIGN(b);
	}
}
