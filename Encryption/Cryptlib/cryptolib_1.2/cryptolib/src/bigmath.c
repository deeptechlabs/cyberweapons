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
 *        Big Arithmetic routines
 *        coded by D. P. Mitchell and Jack Lacy December, 1991
 *
 *        Copyright (c) 1991 AT&T Bell Laboratories
 */
#include "libcrypt.h"

#define LO(x) ((Ushort) ((x) & UlongMask))
#define HI(x) (((x) >> 8) & UlongMask)
#define UHI(x) (((Ulong) (x)) >> (UlongBits/2))
#define lmult LMULT

static void bigleftshift P((BigInt, BigInt, int));
static void bl_shift P((BigInt, BigInt, int));
static void bigrightshift P((BigInt, BigInt, int));
static void br_shift P((BigInt, BigInt, int));

#define LONG_ADDSTEP(i, C, A, B) { \
 suml = (A)[(i)] + (B)[(i)]; \
 sumh = (suml < (A)[(i)]); \
 (C)[(i)] = carry + suml; \
 carry = ((C)[(i)] < suml) + sumh; \
}

#define CARRYSTEP(i) { \
 cp[(i)] = carry + ap[(i)]; \
 carry = (cp[(i)] < carry); \
}

#ifdef K_AND_R
_TYPE( void )
trim(big)
  BigInt big;
#else
_TYPE( void ) trim(BigInt big)
#endif
{
	while ((NUM(big)[LENGTH(big)-1] == 0) && LENGTH(big) > 1)
		LENGTH(big)--;
}

#ifdef K_AND_R
_TYPE( void )
bigaddition(a, b, c)
  BigInt a, b, c;
#else
_TYPE( void ) bigaddition(BigInt a,
			  BigInt b,
			  BigInt c)
#endif
{
	register Ulong carry, sumh, suml;
	register BigData ap, bp, cp;
	register int i;
	BigInt tmp;
	
	if (LENGTH(a) < LENGTH(b)) {
		tmp = a;
		a = b;
		b = tmp;
	}
	
	GUARANTEE(c, LENGTH(a) + 1);
	ap = NUM(a);
	bp = NUM(b);
	cp = NUM(c);
	i = LENGTH(b);
	carry = 0;
	ap -= 4 - (i&3);
	bp -= 4 - (i&3);
	cp -= 4 - (i&3);
	switch (i & 3) {
	    case 3:         LONG_ADDSTEP(1,cp,ap,bp);
	    case 2:         LONG_ADDSTEP(2,cp,ap,bp);
	    case 1:         LONG_ADDSTEP(3,cp,ap,bp);
	    case 0:
		ap += 4;
		bp += 4;
		cp += 4;
		i -= 4;
	}
	while (i >= 0) {
		LONG_ADDSTEP(0,cp,ap,bp);
		LONG_ADDSTEP(1,cp,ap,bp);
		LONG_ADDSTEP(2,cp,ap,bp);
		LONG_ADDSTEP(3,cp,ap,bp);
		ap += 4;
		bp += 4;
		cp += 4;
		i -= 4;
	}
	
	i = LENGTH(a) - LENGTH(b);
	ap -= 4 - (i&3);
	cp -= 4 - (i&3);
	switch (i & 3) {
	    case 3:         CARRYSTEP(1);
	    case 2:         CARRYSTEP(2);
	    case 1:         CARRYSTEP(3);
	    case 0:
		ap += 4;
		cp += 4;
		i -= 4;
	}
	while (i >= 0) {
		CARRYSTEP(0);
		CARRYSTEP(1);
		CARRYSTEP(2);
		CARRYSTEP(3);
		ap += 4;
		cp += 4;
		i -= 4;
	}
	
	if (carry) {
		*cp++ = carry;
		LENGTH(c) = LENGTH(a) + 1;
	} else
		LENGTH(c) = LENGTH(a);
	
	SIGN(c) = SIGN(a);
	trim(c);
}

#ifdef K_AND_R
_TYPE( void )
bigAdd(a, b, c)
  BigInt a, b, c;
#else
_TYPE( void ) bigAdd(BigInt a,
		     BigInt b,
		     BigInt c)
#endif
{
	if ((SIGN(a) == NEG) && (SIGN(b) == POS)) {
		if (bigCompare(b, a) > 0) {
			bigsub(b, a, c);
			SIGN(c) = POS;
		}
		else {
			bigsub(a, b, c);
			SIGN(c) = NEG;
		}
	}
	else if ((SIGN(b) == NEG) && (SIGN(a) == POS)) {
		if (bigCompare(a, b) > 0) {
			bigsub(a, b, c);
			SIGN(c) = POS;
		}
		else {
			bigsub(b, a, c);
			SIGN(c) = NEG;
		}
	}
	else {
		bigaddition(a, b, c);
		SIGN(c) = SIGN(a);
	}
}

#define LONG_SUBSTEP(i, C, A, B) { \
  suml = (long)((A)[(i)] - (B)[(i)]); \
  sumh = (long)(-((Ulong)suml > (A)[(i)])); \
  (C)[(i)] = (Ulong)((long)suml + carry);   \
  carry = (long)(-((C)[(i)] > (Ulong)suml)) + sumh; \
}

#define LONG_BORROWSTEP(i, C, A) { \
 (C)[(i)] = (Ulong)((long)(A)[(i)] + carry); \
 carry = (long)(-((C)[(i)] > (A)[(i)])); \
}

#ifdef K_AND_R
void
bigsub(a, b, c)
  BigInt a, b, c;
#else
void bigsub(BigInt a,
		     BigInt b,
		     BigInt c)
#endif
{
	register long sumh, suml, carry;
	register BigData ap, bp, cp;
	register int i;
	
	GUARANTEE(c, LENGTH(a));
	ap = NUM(a);
	bp = NUM(b);
	cp = NUM(c);
	i = LENGTH(b);
	sumh = carry = 0;
	ap -= 4 - (i&3);
	bp -= 4 - (i&3);
	cp -= 4 - (i&3);
	switch (i & 3) {
	    case 3:         LONG_SUBSTEP(1,cp,ap,bp);
	    case 2:         LONG_SUBSTEP(2,cp,ap,bp);
	    case 1:         LONG_SUBSTEP(3,cp,ap,bp);
	    case 0:
		ap += 4;
		bp += 4;
		cp += 4;
		i -= 4;
	}
	while (i >= 0) {
		LONG_SUBSTEP(0,cp,ap,bp);
		LONG_SUBSTEP(1,cp,ap,bp);
		LONG_SUBSTEP(2,cp,ap,bp);
		LONG_SUBSTEP(3,cp,ap,bp);
		ap += 4;
		bp += 4;
		cp += 4;
		i -= 4;
	}
	
	i = (int)(LENGTH(a) - LENGTH(b));
	ap -= 4 - (i&3);
	cp -= 4 - (i&3);
	switch (i & 3) {
	    case 3:         LONG_BORROWSTEP(1,cp,ap);
	    case 2:         LONG_BORROWSTEP(2,cp,ap);
	    case 1:         LONG_BORROWSTEP(3,cp,ap);
	    case 0:
		ap += 4;
		cp += 4;
		i -= 4;
	}
	while (i >= 0) {
		LONG_BORROWSTEP(0,cp,ap);
		LONG_BORROWSTEP(1,cp,ap);
		LONG_BORROWSTEP(2,cp,ap);
		LONG_BORROWSTEP(3,cp,ap);
		ap += 4;
		cp += 4;
		i -= 4;
	}
	
	LENGTH(c) = LENGTH(a);
	
	if (carry != 0)
		handle_exception(CRITICAL, "bigsub: carry is non zero when done\n");
	
	/*
	 *        Remove leading zero words.  This can only happen in
	 *        bigSubtract because all bignums are positive.
	 */
	trim(c);
}

#ifdef K_AND_R
_TYPE( void )
bigSubtract(a1, a2, ret)
  BigInt a1, a2, ret;
#else
_TYPE( void ) bigSubtract(BigInt a1,
			  BigInt a2,
			  BigInt ret)
#endif
{
	Sign sign1, sign2;
	
	sign1 = SIGN(a1);
	sign2 = SIGN(a2);
	
	if ((sign1 == POS) && (sign2 == POS)) {
		if (bigCompare(a1, a2) >= 0) {
			bigsub(a1, a2, ret);
			SIGN(ret) = POS;
			return;
		}
		else {
			bigsub(a2, a1, ret);
			SIGN(ret) = NEG;
			return;
		}
	}
	else if ((sign1 == POS) && (sign2 == NEG)) {
		bigaddition(a1, a2, ret);
		SIGN(ret) = POS;
		return;
	}
	else if ((sign1 == NEG) && (sign2 == NEG)) {
		if (bigCompare(a1, a2) >= 0) {
			bigsub(a1, a2, ret);
			SIGN(ret) = NEG;
			return;
		}
		else {
			bigsub(a2, a1, ret);
			SIGN(ret) = POS;
			return;
		}
	}
	else if ((sign1 == NEG) && (sign2 == POS)) {
		bigaddition(a1, a2, ret);
		SIGN(ret) = NEG;
		return;
	}
}
#define SHIFTSTEP(i) {bp[i] = ap[i];}

#ifdef K_AND_R
static void
bigleftshift(a, b, nwords)
  BigInt a, b;
  int nwords;
#else
  static void bigleftshift(BigInt a,
			   BigInt b,
			   int nwords)
#endif
{
	register BigData ap, bp;
	register int i;
	
	GUARANTEE(b, (int)(LENGTH(a) + nwords));
	i = LENGTH(a);
	LENGTH(b) = LENGTH(a) + (int)nwords;
	ap = NUM(a) + i;
	bp = NUM(b) + i + nwords;
	
	ap -= (i&3);
	bp -= (i&3);
	switch (i & 3) {
	    case 3:        SHIFTSTEP(2);
	    case 2:         SHIFTSTEP(1);
	    case 1:        SHIFTSTEP(0);
	    case 0:
		i -= 4;
	}
	while (i >= 0) {
		ap -= 4;
		bp -= 4;
		SHIFTSTEP(3);
		SHIFTSTEP(2);
		SHIFTSTEP(1);
		SHIFTSTEP(0);
		i -= 4;
	}
	
	i = nwords;
	bp -= i&3;
	switch (i&3) {
	    case 3:      bp[2] = 0;
	    case 2:      bp[1] = 0;
	    case 1:      bp[0] = 0;
	    case 0:
		i -= 4;
		bp -= 4;
	}
	while (i >= 0) {
		bp[3] = 0;
		bp[2] = 0;
		bp[1] = 0;
		bp[0] = 0;
		i -= 4;
		bp -= 4;
	}
	
	trim(b);
	
}

#define LSHIFT(i) { \
 el = ap[i]; \
 s = (Ulong)(el << n); \
 bp[i] = s + c; \
 c = (Ulong)(el >> (UlongBits-n)); \
}

#ifdef K_AND_R
static void
bl_shift(a, b, n)
  BigInt a, b;
  int n;
#else
  static void bl_shift(BigInt a,
		       BigInt b,
		       int n)
#endif
{
	register int i;
	register BigData ap, bp;
	register Ulong s, c;
	Ulong el;
	
	i = LENGTH(a);
	GUARANTEE(b, (int)(i + 1));
	
	c = 0;
	ap = NUM(a);
	bp = NUM(b);
	
	ap -= 4 - (i&3);
	bp -= 4 - (i&3);
	switch(i&3) {
	    case 3:        LSHIFT(1);
	    case 2:        LSHIFT(2);
	    case 1:        LSHIFT(3);
	    case 0:
		ap += 4;
		bp += 4;
		i -= 4;
	}
	while (i >= 0) {
		LSHIFT(0);
		LSHIFT(1);
		LSHIFT(2);
		LSHIFT(3);
		ap += 4;
		bp += 4;
		i -= 4;
	}
	
	*bp = c;
	LENGTH(b) = LENGTH(a)+1;
	
	trim(b);
	
}

#ifdef K_AND_R
_TYPE( void )
bigLeftShift(a, n, b)
  BigInt a, b;
  int n;
#else
_TYPE( void ) bigLeftShift(BigInt a,
			   int n,
			   BigInt b)
#endif
{
	register int i;
	
	if (n == 0) {
		if (a != b)
			bigCopy(a, b);
		return;
	}
	
	i = (n/UlongBits);
	GUARANTEE(b, LENGTH(a) + (int)(i+1));
	if (i > 0) {
		bigleftshift(a, b, i);
		if (n%UlongBits)
			bl_shift(b, b, n%UlongBits);
	}
	else
		bl_shift(a, b, n%UlongBits);
	
	trim(b);
}

#ifdef K_AND_R
static void 
bigrightshift(a, b, nwords)
  BigInt a, b;
  int nwords;
#else
  static void bigrightshift(BigInt a,
			    BigInt b,
			    int nwords)
#endif
{
	register int i, j, alen;
	BigData ap, oap;
	
	alen = LENGTH(a);
	if (a == b) {
		i = alen - nwords;
		if (i > 0) {
			LENGTH(a) = (int)i;
			ap = NUM(a) + nwords;
			oap = NUM(a);
			for (j=0; j<i; j++)
				oap[j]=ap[j];
		}
		else
			reset_big(a, (Ulong)0);
		return;
	}
	
	LENGTH(a) -= (int)nwords;
	if (LENGTH(a) > 0) {
		NUM(a) += nwords;
		bigCopy(a, b);
		NUM(a) -= nwords;
	}
	else {
		LENGTH(b) = 1;
		NUM(b)[0] = 0;
	}
	LENGTH(a) = (int)alen;
	
}


#define BITSHIFT(i) {\
 el = ap[i]; \
 s = el >> n; \
 bp[i] = s + c; \
 c = el << j; \
}

#ifdef K_AND_R
static void
br_shift(a, b, n)
  BigInt a, b;
  int n;
#else
  static void br_shift(BigInt a,
		       BigInt b,
		       int n)
#endif
{
	register BigData ap, bp;
	register int i,j;
	Ulong s, c;
	Ulong el;
	
	GUARANTEE(b, LENGTH(a));
	LENGTH(b) = LENGTH(a);
	i = LENGTH(a);
	ap = NUM(a);
	bp = NUM(b);
	j = UlongBits - n;
	c = 0;
	
	ap += i - (i&3);
	bp += i - (i&3);
	switch (i & 3) {
	    case 3:            BITSHIFT(2);
	    case 2:            BITSHIFT(1);
	    case 1:            BITSHIFT(0);
	    case 0:
		i -= 4;
		ap -= 4;
		bp -= 4;
	}
	while (i >= 0) {
		BITSHIFT(3);
		BITSHIFT(2);
		BITSHIFT(1);
		BITSHIFT(0);
		i -= 4;
		ap -= 4;
		bp -= 4;
	}
	
	trim(b);
}

#ifdef K_AND_R
_TYPE( void )
bigRightShift(a, n, b)
  BigInt a, b;
  int n;
#else
_TYPE( void ) bigRightShift(BigInt a,
			    int n,
			    BigInt b)
#endif
{
	
	bigrightshift(a, b, n/UlongBits);
	
	if (n%UlongBits)
		br_shift(b, b, n%UlongBits);
	
	trim(b);
}

#ifdef K_AND_R
_TYPE( void )
reset_big(a, u)
  BigInt a;
  Ulong u;
#else
_TYPE( void ) reset_big(BigInt a,
			Ulong u)
#endif
{
	BigData ap;
	
	clib_memzero((unsigned char *)NUM(a), sizeof(Ulong)*SPACE(a));
	ap = NUM(a);
	SIGN(a) = POS;
	LENGTH(a) = 1;
	ap[0] = u;
}


/* Basic n^2 multiplication */
#ifdef K_AND_R
void
lbigmult(a, b, c)
  BigInt a, b, c;
#else
void lbigmult(BigInt a,
	      BigInt b,
	      BigInt c)
#endif
{
	register int i;
	Ulong m;
	Ulong *bp = NUM(b);
	
	if ((c == b) || (c == a))
		handle_exception(CRITICAL, "lbigmult: product pointer cannot be the same as either \
                multiplicand.\n");
	
	reset_big(c, (Ulong)0);
	
	if ((ZERO(a) != 1) && (ZERO(b) != 1)) {
		GUARANTEE(c, LENGTH(a) + LENGTH(b));
		for (i = 0; i < LENGTH(b); i++) {
			m = bp[i];
			Ulong_bigmult(a, m, c, i);
		}
		SIGN(c) = SIGN(a) * SIGN(b);
	}
	trim(c);
}

#ifdef K_AND_R
void
bigsquare(a, c)
  BigInt a, c;
#else
void bigsquare(BigInt a,
	       BigInt c)
#endif
{
	
	if (a == c)
		handle_exception(CRITICAL, "bigsquare: product pointer cannot be the same as multiplicand.\n");
	
	GUARANTEE(c, 2*LENGTH(a));
	reset_big(c, (Ulong)0);
	Ulong_bigsquareN(NUM(a), NUM(c), LENGTH(a));
	LENGTH(c) = 2*LENGTH(a);
	trim(c);
	
}

#ifdef K_AND_R
_TYPE( int )
bigCompare(a, b)
  BigInt a, b;
#else
_TYPE( int ) bigCompare(BigInt a,
			BigInt b)
#endif
{
	register BigData ap, bp;
	register int i;
	
	trim(a);
	trim(b);
	
	if (LENGTH(a) != LENGTH(b))
		return (LENGTH(a) - LENGTH(b));
	i = LENGTH(a);
	ap = NUM(a) + i;
	bp = NUM(b) + i;
	while (--i >= 0 && *--ap == *--bp)
		;
	if (i < 0)
		return 0;
	if (*ap < *bp)
		return -1;
	else
		return 1;
}

#ifndef OLDMODREDUX

#ifdef K_AND_R
_TYPE( unsigned long )
longBigDivide(big, d)
  BigInt big;
  Ulong d;
#else
_TYPE( unsigned long ) longBigDivide(BigInt big,
				     Ulong d)
#endif
{
	Ushort dhi, q;
	Ulong r, s;
	static Bignum div, x, tmp;
	static Ulong divnum[2], xnum[2], tmpnum[3];
	static int first_time = 1;
	
	if (first_time) {
		div.num = divnum;
		div.space = 2;
		x.num = xnum;
		x.space = 2;
		tmp.num = tmpnum;
		tmp.space = 3;
		div.sign = x.sign = tmp.sign = POS;
		div.length = x.length = tmp.length = 1;
		first_time = 0;
	}
	bigCopy(big, &x);
	reset_big(&tmp, 0);

	dhi = (Ushort)(d>>16)&(Ushort)0xFFFF;

	divnum[1] = (unsigned long)dhi;
	divnum[0] = (d << 16);
	div.length = 2;
	
	r = 0;
	s = xnum[1];
	if (((s>>16)&0xFFFF) == (Ulong)dhi)
		q = (Ushort)0xFFFF;
	else
		q = (Ushort)(s/(Ulong)dhi);

	tmpnum[2] = LMULT(tmpnum, (Ulong)q, divnum, 2);
	/* tmpnum[2] = 0 always */
	tmp.length = 2;

	while (bigCompare(&tmp, &x) > 0) {
		q = q - (Ushort)1;
		bigSubtract(&tmp, &div, &tmp);
	}
	bigSubtract(&x, &tmp, &x);
	
	r = (unsigned long)((Ulong)q << 16);
	s = ((xnum[1]&0xFFFF)<<16) + (xnum[0]>>16);
	if ((xnum[1]&0xFFFF) == (Ulong)dhi)
		q = (Ushort)0xFFFF;
	else
		q = (Ushort)(s/(Ulong)dhi);
	
	reset_big(&tmp, 0);
	reset_big(&div, d);
	tmpnum[1] = LMULT(tmpnum, (Ulong)q, divnum, 1);
	tmp.length = 2;
	
	while (bigCompare(&tmp, &x) > 0) {
		q = q - 1;
		bigSubtract(&tmp, &div, &tmp);
	}
	r += (unsigned long)q;
	
	return r;
}


#ifdef K_AND_R
_TYPE( void )
bigMod(a, m, x)
  BigInt a, m, x;
#else
_TYPE( void ) bigMod(BigInt a,
		     BigInt m,
		     BigInt x)
#endif
{
	register BigData xp;
	int lendiff;
	Ulong q, ms;
	static BigInt div, tmp;
	static int first_time = 1;
	int i, l, k, changed, normbits, savesign;
	
	if (ZERO(m))
		handle_exception(CRITICAL, "bigMod: modulus is zero.\n");
	
	if (ONE(m)) {
		reset_big(x, 0);
		return;
	}
	
	if (a != x)
		bigCopy(a, x);
	
	savesign = SIGN(a);
	if (bigCompare(a, m) < 0L) {
		return;
	}
	
	SIGN(x) = POS;
	changed = 0;
	normbits = 0;
	/* Normalize the modulus, m and the dividend x to have msb = 1 */
	if (NUM(m)[LENGTH(m)-1] < (unsigned long)0x80000000) {
		normbits = (32-msb(NUM(m)[LENGTH(m)-1]));
		bigLeftShift(m, normbits, m);
		bigLeftShift(x, normbits, x);
		changed = 1;
	}
	
	l = LENGTH(x);
	k = LENGTH(m);
	lendiff = l - k;
	
	if (lendiff < 0)
		return;
	
	/* Init static working bignums */
	if (first_time) {
		tmp = bigInit(0);
		GUARANTEE(tmp, 4);
		div = bigInit(0);
		first_time = 0;
	}
	
	bigleftshift(m, div, lendiff);
	ms = NUM(m)[k-1]; /* most significant word of modulus */
	
	/* If dividend is bigger than divisor, subtract divisor */
	if (bigCompare(x, div) > 0)
		bigsub(x, div, x);
	
	/* In this loop, q is the estimated quotient */
	for (i=l-1; i>k-1; i--) {
		xp = NUM(x);
		bigrightshift(div, div, 1); /* shift right by 32 bits */
		if (xp[i] == ms)
			q = (unsigned long)0xFFFFFFFF;
		else {
			NUM(tmp)[1] = xp[i];
			NUM(tmp)[0] = xp[i-1];
			LENGTH(tmp) = 2;
			q = longBigDivide(tmp, ms);
		}
		reset_big(tmp, 0);
		Ulong_bigmult(div, q, tmp, 0);
		while (bigCompare(tmp, x) > 0) {
			bigSubtract(tmp, div, tmp);
			q--;
		}

		bigSubtract(x, tmp, x);
	}
	
	if (changed) {
		bigRightShift(m, normbits, m);
		bigRightShift(x, normbits, x);
	}
	SIGN(x) = savesign;
	
}

#ifdef K_AND_R
_TYPE( void )
bigDivide(a, m, qu, x )
  BigInt a, m, qu, x;
#else
_TYPE( void ) bigDivide(BigInt a,
			BigInt m,
			BigInt qu,
			BigInt x)
#endif
{
	register BigData xp;
	static BigInt div, tmp;
	static int first_time = 1;
	Ulong q, ms;
	int i, j, l, k, lendiff,changed, normbits, asavesign, msavesign;
	
	if (first_time) {
		tmp = bigInit(0);
		GUARANTEE(tmp, 4);
		div = bigInit(0);
		first_time = 0;
	}

	if (ZERO(m))
		handle_exception(CRITICAL, "bigDivide: divisor is zero.\n");
	
	SIGN(qu) = SIGN(a) * SIGN(m);
	
	if (a != x)
		bigCopy(a, x);
	
	reset_big(qu, 0);
	i = bigCompare(a, m);
	if (i < 0) {
		return;
	}
	if (i == 0) {
		reset_big(qu, 1);
		reset_big(x, 0);
		return;
	}
	if (ONE(m)) {
		bigCopy(a, qu);
		reset_big(x, (Ulong)0);
		return;
	}
	
	asavesign = SIGN(a);
	msavesign = SIGN(m);
	
	SIGN(x) = POS;
	SIGN(m) = POS;
	changed = 0;
	normbits = 0;

	if (NUM(m)[LENGTH(m)-1] < (unsigned long)0x80000000) {
		normbits = (32-msb(NUM(m)[LENGTH(m)-1]));
		bigLeftShift(m, normbits, div);
		bigLeftShift(x, normbits, x);
		changed = 1;
	}
	else
		bigCopy(m, div);

	l = LENGTH(x);
	k = LENGTH(div);
	lendiff = l - k;
	ms = NUM(div)[k-1];
	
	GUARANTEE(qu, (int)(l-k+1));
	bigleftshift(div, div, lendiff);
	
	if (bigCompare(x, div) > 0) {
		bigsub(x, div, x);
		NUM(qu)[l-k] = 1;
		LENGTH(qu) = l-k+1;
	}
	else
		LENGTH(qu) = l-k;

	j = l-k-1;
	
	for (i=l-1; i>k-1; i--) {
		xp = NUM(x);
		bigrightshift(div, div, 1);

		if (xp[i] == ms) {
			q = (unsigned long)0xFFFFFFFF;
		}
		else {

			NUM(tmp)[1] = xp[i];
			NUM(tmp)[0] = xp[i-1];
			LENGTH(tmp) = 2;
			q = longBigDivide(tmp, ms);

		}

		reset_big(tmp, 0);
		Ulong_bigmult(div, q, tmp, 0);
		while (bigCompare(tmp, x) > 0) {
			bigSubtract(tmp, div, tmp);
			q--;
		}
		bigSubtract(x, tmp, x);
		NUM(qu)[j--] = q;
	}
	
	if (changed) {
		bigRightShift(x, normbits, x);
	}
	SIGN(x) = asavesign;
	SIGN(m) = msavesign;
	
}

#else

#ifdef K_AND_R
_TYPE( void )
bigMod(a, m, result)
  BigInt a, m, result;
#else
_TYPE( void ) bigMod(BigInt a,
		     BigInt m,
		     BigInt result)
#endif
{
	register BigInt r;
	register int k, resbits, rbits;
	
	if (ZERO(m))
		handle_exception(CRITICAL, "bigMod: modulus is zero.\n");
	
	GUARANTEE(result, LENGTH(a));
	
	SIGN(result) = SIGN(a);
	if (a != result)
		bigCopy(a, result);
	
	k = (int)(bigBits(result) - bigBits(m));
	if (k < 0)
		return;
	
	r = bigInit(0);
	bigLeftShift(m, k, r);
	rbits = (int)bigBits(r);
	
	while (bigCompare(result, m) > 0) {
		while (bigCompare(r, result) > 0) {
			br_shift(r, r, (int)1);
			rbits--;
		}
		bigsub(result, r, result);
		
		resbits = (int)bigBits(result);
		k = rbits - resbits;
		if (k > 0) {
			bigRightShift(r, k, r);
			rbits = resbits;
		}
	}
	if (bigCompare(result, m) == 0)
		reset_big(result, (Ulong)0);
	
	freeBignum(r);
}


#ifdef K_AND_R
_TYPE( void )
bigDivide(a, divisor, quotient, remainder)
  BigInt a, divisor, quotient, remainder;
#else
_TYPE( void ) bigDivide(BigInt a,
			BigInt divisor,
			BigInt quotient,
			BigInt remainder)
#endif
{
	register int k, L, rembits, divbits, rbits;
	register BigInt x0, r, one;
	
	if (ZERO(divisor))
		handle_exception(CRITICAL, "bigDivide: divisor is zero.\n");
	
	SIGN(quotient) = SIGN(a) * SIGN(divisor);
	
	bigCopy(a, remainder);
	reset_big(quotient, (Ulong)0);
	
	if (bigCompare(a, divisor) < 0) {
		return;
	}
	if (ONE(divisor)) {
		bigCopy(a, quotient);
		reset_big(remainder, (Ulong)0);
		return;
	}
	r = bigInit(0);
	x0 = bigInit(0);
	one = bigInit(1);
	
	rembits = (int)bigBits(remainder);
	divbits = (int)bigBits(divisor);
	L = rembits - divbits;
	
	bigLeftShift(divisor, L, r);
	rbits = (int)bigBits(r);
	
	while (bigCompare(remainder, divisor) > 0) {
		while (bigCompare(r, remainder) > 0) {
			br_shift(r, r, 1);
			rbits--;
			L--;
		}
		bigsub(remainder, r, remainder);
		
		rembits = (int)bigBits(remainder);
		k = rbits - rembits;
		if (k > 0) {
			bigRightShift(r, k, r);
			rbits = rembits;
		}
		bigLeftShift(one, L, x0);
		bigAdd(quotient, x0, quotient);
		L = rbits - divbits;
	}
	if (bigCompare(divisor, remainder) == 0) {
		bigAdd(quotient, one, quotient);
		reset_big(remainder, (Ulong)0);
	}
	freeBignum(one);
	freeBignum(r);
	freeBignum(x0);
	
}
#endif

#ifdef K_AND_R
_TYPE( void )
bigCopy(a, b)
  BigInt a, b;
#else
_TYPE( void ) bigCopy(BigInt a,
		      BigInt b)
#endif
{
	register BigData ap, bp;
	register i;
	
	GUARANTEE(b, LENGTH(a));
	i = LENGTH(a);
	LENGTH(b) = LENGTH(a);
	SIGN(b) = SIGN(a);
	ap = NUM(a) + i;
	bp = NUM(b) + i;
	
	ap -= (i&3);
	bp -= (i&3);
	switch (i&3) {
	    case 3:  bp[2] = ap[2];
	    case 2:  bp[1] = ap[1];
	    case 1:  bp[0] = ap[0];
	    case 0:
		i -= 4;
	}
	while (i >= 0) {
		ap -= 4;
		bp -= 4;
		bp[3] = ap[3];
		bp[2] = ap[2];
		bp[1] = ap[1];
		bp[0] = ap[0];
		i -= 4;
	}
}

#ifdef K_AND_R
_TYPE( void )
bigAnd(a, b, c)
  BigInt a, b, c;
#else
_TYPE( void ) bigAnd(BigInt a,
		     BigInt b,
		     BigInt c)
#endif
{
	register BigData ap, bp, cp;
	register int i;
	
	if (LENGTH(a) > LENGTH(b))
		i = LENGTH(b);
	else
		i = LENGTH(a);
	GUARANTEE(c, (int)i);
	LENGTH(c) = (int)i;
	SIGN(c) = SIGN(a);
	ap = NUM(a);
	bp = NUM(b);
	cp = NUM(c);
	
	ap -= 4 - (i&3);
	bp -= 4 - (i&3);
	cp -= 4 - (i&3);
	switch (i&3) {
	    case 3:  cp[1] = ap[1] & bp[1];
	    case 2:  cp[2] = ap[2] & bp[2];
	    case 1:  cp[3] = ap[3] & bp[3];
	    case 0:
		ap += 4;
		bp += 4;
		cp += 4;
		i -= 4;
	};
	while (i >= 0) {
		cp[0] = ap[0] & bp[0];
		cp[1] = ap[1] & bp[1];
		cp[2] = ap[2] & bp[2];
		cp[3] = ap[3] & bp[3];
		ap += 4;
		bp += 4;
		cp += 4;
		i -= 4;
	}
}

#ifdef K_AND_R
_TYPE( void )
bigOr(a, b, c)
  BigInt a, b, c;
#else
_TYPE( void ) bigOr(BigInt a,
		    BigInt b,
		    BigInt c)
#endif
{
	register BigData ap, bp, cp, maxp;
	register i, maxlen, minlen;
	
	if (LENGTH(a) > LENGTH(b)) {
		maxlen = LENGTH(a);
		minlen = LENGTH(b);
		maxp = NUM(a) + minlen;
	}
	else {
		maxlen = LENGTH(b);
		minlen = LENGTH(a);
		maxp = NUM(b) + minlen;
	}
	GUARANTEE(c, (int)maxlen);
	LENGTH(c) = (int)maxlen;
	
	SIGN(c) = SIGN(a);
	ap = NUM(a);
	bp = NUM(b);
	cp = NUM(c);
	i = minlen;    
	ap -= 4 - (i&3);
	bp -= 4 - (i&3);
	cp -= 4 - (i&3);
	
	switch (i&3) {
	    case 3:  cp[1] = ap[1] | bp[1];
	    case 2:  cp[2] = ap[2] | bp[2];
	    case 1:  cp[3] = ap[3] | bp[3];
	    case 0:
		ap += 4;
		bp += 4;
		cp += 4;
		i -= 4;
	}
	while (i >= 0) {
		cp[0] = ap[0] | bp[0];
		cp[1] = ap[1] | bp[1];
		cp[2] = ap[2] | bp[2];
		cp[3] = ap[3] | bp[3];
		ap += 4;
		bp += 4;
		cp += 4;
		i -= 4;
	}
	i = maxlen-minlen;
	while (i--)
		*cp++ = *maxp++;
	trim(c);
}

#ifdef K_AND_R
_TYPE( void )
bigXor(a, b, c)
  BigInt a, b, c;
#else
_TYPE( void ) bigXor(BigInt a,
		     BigInt b,
		     BigInt c)
#endif
{
	register BigData ap, bp, cp, maxp;
	register i, maxlen, minlen;
	
	if (LENGTH(a) > LENGTH(b)) {
		maxlen = LENGTH(a);
		minlen = LENGTH(b);
		maxp = NUM(a) + minlen;
	}
	else {
		maxlen = LENGTH(b);
		minlen = LENGTH(a);
		maxp = NUM(b) + minlen;
	}
	GUARANTEE(c, (int)maxlen);
	LENGTH(c) = (int)maxlen;
	
	SIGN(c) = SIGN(a);
	ap = NUM(a);
	bp = NUM(b);
	cp = NUM(c);
	i = minlen;    
	ap -= 4 - (i&3);
	bp -= 4 - (i&3);
	cp -= 4 - (i&3);
	
	switch (i&3) {
	    case 3:  cp[1] = ap[1] ^ bp[1];
	    case 2:  cp[2] = ap[2] ^ bp[2];
	    case 1:  cp[3] = ap[3] ^ bp[3];
	    case 0:
		ap += 4;
		bp += 4;
		cp += 4;
		i -= 4;
	}
	while (i >= 0) {
		cp[0] = ap[0] ^ bp[0];
		cp[1] = ap[1] ^ bp[1];
		cp[2] = ap[2] ^ bp[2];
		cp[3] = ap[3] ^ bp[3];
		ap += 4;
		bp += 4;
		cp += 4;
		i -= 4;
	}
	i = maxlen-minlen;
	while (i--)
		*cp++ = *maxp++;
	trim(c);
}

#ifdef K_AND_R
_TYPE( void )
negate(a, p, result)
  BigInt a, p, result;
#else
_TYPE( void ) negate(BigInt a,
		     BigInt p,
		     BigInt result)
#endif
{
	BigInt minus1, tmp, one;
	
	if ((bigCompare(p, a) > 0) && (SIGN(a) == POS)) {
		bigSubtract(p, a, result);
	}
	else {
		minus1 = bigInit(0);
		tmp = bigInit(0);
		one = bigInit(1);
		
		bigSubtract(p, one, minus1);
		bigMultiply(a, minus1, tmp);
		
		bigMod(tmp, p, result);
		
		SIGN(result) = POS;
		
		freeBignum(minus1);
		freeBignum(tmp);
		freeBignum(one);
	}
}

#ifdef K_AND_R
_TYPE( void )
crtCombine(a, b, p, q, c12, result)
  BigInt a, b, p, q, c12, result;
#else
_TYPE( void ) crtCombine(BigInt a,
			 BigInt b,
			 BigInt p,
			 BigInt q,
			 BigInt c12,
			 BigInt result)
#endif
{
	BigInt u1, u2, tmp, tmp1;
	
	u1 = bigInit(0);
	u2 = bigInit(0);
	tmp = bigInit(0);
	tmp1 = bigInit(0);
	
	bigCopy(a, u1);
	bigCopy(b, u2);
	
	if (bigCompare(u1, u2) >= 0)
		bigSubtract(u1, u2, tmp1);
	else {
		bigSubtract(u2, u1, tmp1);
		bigSubtract(p, tmp1, tmp1);
	}
	bigMultiply(c12, tmp1, tmp);
	bigMod(tmp, p, tmp);
	bigMultiply(tmp, q, result);
	bigAdd(result, u2, result);
	if (SIGN(result) == NEG) {
		bigMultiply(p, q, tmp);
		negate(result, tmp, result);
	}
	
	freeBignum(u1);
	freeBignum(u2);
	freeBignum(tmp);
	freeBignum(tmp1);
}


