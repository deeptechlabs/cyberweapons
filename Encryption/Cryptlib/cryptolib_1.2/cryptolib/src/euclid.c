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
 *        Euclid's extended gcd algorithm from Knuth Vol 2.
 *
 *        coded by Jack Lacy, December, 1991
 *
 *        Copyright (c) 1991 AT&T Bell Laboratories
 */
#include "libcrypt.h"

#ifdef K_AND_R
_TYPE( void )
extendedGcd(u, v, up, vp, gcd)
  BigInt u, v, up, vp, gcd;
#else
_TYPE( void ) extendedGcd(BigInt u,
			  BigInt v,
			  BigInt up,
			  BigInt vp,
			  BigInt gcd)
#endif
{
	BigInt u1, u2, u3, v1, v2, v3, t1, t2, t3;
	BigInt q, u1save, u2save, u3save;
	
	if (ZERO(u) || ZERO(v))  {
		reset_big(gcd, (Ulong)0);
		return;
	}
	
	q = bigInit(0);
	
	u1 = bigInit(1);
	u2 = bigInit(0);
	u3 = bigInit(0);
	bigCopy(u, u3);
	
	v1 = bigInit(0);
	v2 = bigInit(1);
	v3 = bigInit(0);
	bigCopy(v, v3);
	
	t1 = bigInit(0);
	t2 = bigInit(0);
	t3 = bigInit(0);
	
	while (!ZERO(v3)) {
		bigDivide(u3, v3, q, t3);
		
		bigMultiply(v1, q, t1);
		bigMultiply(v2, q, t2);
		
		bigSubtract(u1, t1, t1);
		bigSubtract(u2, t2, t2);
		
		u1save = u1;
		u2save = u2;
		u3save = u3;
		
		u1 = v1;
		u2 = v2;
		u3 = v3;
		
		v1 = t1;
		v2 = t2;
		v3 = t3;
		
		t1 = u1save;
		t2 = u2save;
		t3 = u3save;
	}
	
	bigCopy(u1, up);
	if (SIGN(up) == NEG)
		negate(up, v, up);
	bigCopy(u2, vp);
	if (SIGN(vp) == NEG)
		negate(vp, u, vp);
	bigCopy(u3, gcd);
	
	freeBignum(u1);
	freeBignum(u2);
	freeBignum(u3);
	freeBignum(v1);
	freeBignum(v2);
	freeBignum(v3);
	freeBignum(t1);
	freeBignum(t2);
	freeBignum(t3);
	freeBignum(q);
}

#ifdef K_AND_R
_TYPE( void )
getInverse(u, v, up)
  BigInt u, v, up;
#else
_TYPE( void ) getInverse(BigInt u,
			 BigInt v,
			 BigInt up)
#endif
{
	BigInt u1, u3, v1, v3, t1, t3;
	BigInt q, u1save, u3save;
	
	q = bigInit(0);
	
	u1 = bigInit(1);
	u3 = bigInit(0);
	bigCopy(u, u3);
	
	v1 = bigInit(0);
	v3 = bigInit(0);
	bigCopy(v, v3);
	
	t1 = bigInit(0);
	t3 = bigInit(0);
	
	while (!ZERO(v3)) {

		bigDivide(u3, v3, q, t3);

		bigMultiply(v1, q, t1);
		bigSubtract(u1, t1, t1);

		u1save = u1;
		u3save = u3;
		
		u1 = v1;
		u3 = v3;
		
		v1 = t1;
		v3 = t3;
		
		t1 = u1save;
		t3 = u3save;
	}
	
	bigCopy(u1, up);
	if (SIGN(up) == NEG)
		negate(up, v, up);
	
	freeBignum(u1);
	freeBignum(u3);
	freeBignum(v1);
	freeBignum(v3);
	freeBignum(t1);
	freeBignum(t3);
	freeBignum(q);
}


#ifdef K_AND_R
_TYPE( void )
ogetInverse(u, v, up)
  BigInt u, v, up;
#else
_TYPE( void ) ogetInverse(BigInt u,
			 BigInt v,
			 BigInt up)
#endif
{
	BigInt u1, u3, v1, v3, t1, t3;
	BigInt q, rem, u1save, u3save;
	
	q = bigInit(0);
	rem = bigInit(0);
	
	u1 = bigInit(1);
	u3 = bigInit(0);
	bigCopy(u, u3);
	
	v1 = bigInit(0);
	v3 = bigInit(0);
	bigCopy(v, v3);
	
	t1 = bigInit(0);
	t3 = bigInit(0);
	
	while (!ZERO(v3)) {
		
		bigDivide(u3, v3, q, rem);
		
		bigMultiply(v1, q, t1);
		bigMultiply(v3, q, t3);
		
		bigSubtract(u1, t1, t1);
		bigSubtract(u3, t3, t3);

		u1save = u1;
		u3save = u3;
		
		u1 = v1;
		u3 = v3;
		
		v1 = t1;
		v3 = t3;
		
		t1 = u1save;
		t3 = u3save;
	}
	
	bigCopy(u1, up);
	if (SIGN(up) == NEG)
		negate(up, v, up);
	
	freeBignum(u1);
	freeBignum(u3);
	freeBignum(v1);
	freeBignum(v3);
	freeBignum(t1);
	freeBignum(t3);
	freeBignum(q);
	freeBignum(rem);
}




#ifdef K_AND_R
_TYPE( BigInt )
gcd(a, b)
  BigInt a, b;
#else
_TYPE( BigInt ) gcd(BigInt a,
		    BigInt b)
#endif
{
	BigInt aa, bb, gcd;
	
	aa = bigInit(0);
	bb = bigInit(0);
	gcd = bigInit(0);
	
	extendedGcd(a, b, aa, bb, gcd);
	
	freeBignum(aa);
	freeBignum(bb);
	
	return gcd;
	
}
