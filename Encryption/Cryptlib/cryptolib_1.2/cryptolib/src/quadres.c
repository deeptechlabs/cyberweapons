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
 *	Code for determining quadratic residues and square roots
 *	modulo a prime and a product of 2 primes.
 *	By Jack Lacy
 *	Copyright (c) 1993 AT&T Bell Labs.
 */
#include "libcrypt.h"

/* a is a quad residue if x^2 mod n = a has a soln x.
 * if n is prime, a is a quadratic residue mod n if
 * a ^ (n-1)/2 mod n = 1 (for n prime)
 */

#ifdef K_AND_R
_TYPE( Boolean )
quadResidue(a, n)
  BigInt a, n;
#else
_TYPE( Boolean ) quadResidue(BigInt a,
			     BigInt n)
#endif
{
	BigInt d, q;
	Boolean retval;
	
	d = bigInit(0);
	q = bigInit(0);
	
	bigSubtract(n, one, q);
	bigRightShift(q, (int)1, q);
	bigPow(a, q, n, d);
	
	if (bigCompare(d, one) == 0)
		retval = TRUE;
	else
		retval = FALSE;
	
	freeBignum(d);
	freeBignum(q);
	
	return retval;
}

#ifdef K_AND_R
_TYPE( Boolean )
compositeQuadResidue(a, p, q)
  BigInt a, p, q;
#else
_TYPE( Boolean ) compositeQuadResidue(BigInt a,
				      BigInt p,
				      BigInt q)
#endif
{
	if (quadResidue(a, p) == FALSE)
		return FALSE;
	else
		return quadResidue(a, q);
}

/* squareRoot() assumes a is a quadratic residue mod p and
 * that p is a prime of the form p = 4k + 3.  result is one
 * of the roots of a.  The other is (p-1)*result mod p.
 */
#ifdef K_AND_R
_TYPE( void )
squareRoot(a, p, result)
  BigInt a, p, result;
#else
_TYPE( void ) squareRoot(BigInt a,
			 BigInt p,
			 BigInt result)
#endif
{
	BigInt k;
	
	if ((p->num[0]&3) != 3)
		handle_exception(WARNING, "squareRoot: Prime must be of form, p mod 4 == 3.\n");
	
	k = bigInit(0);
	
	bigRightShift(p, (int)2, k);
	bigAdd(k, one, k);
	
	bigPow(a, k, p, result);
	
	freeBignum(k);
}

#ifdef K_AND_R
_TYPE( Boolean )
valid_sqroot(res, a, n)
  BigInt res, a, n;
#else
_TYPE( Boolean ) valid_sqroot(BigInt res,
			      BigInt a,
			      BigInt n)
#endif
{
	BigInt tmp;
	Boolean retval;
	
	tmp = bigInit(0);
	bigMultiply(res, res, tmp);
	bigMod(tmp, n, tmp);
	
	if (bigCompare(tmp, a) == 0)
		retval = TRUE;
	else
		retval = FALSE;
	
	freeBignum(tmp);
	
	return retval;
}

#ifdef K_AND_R
_TYPE( void )
compositeSquareRoot(a, p, q, c12, r1, r2)
  BigInt a, p, q, r1, r2, c12;
#else
_TYPE( void ) compositeSquareRoot(BigInt a,
				  BigInt p,
				  BigInt q,
				  BigInt c12,
				  BigInt r1,
				  BigInt r2)
#endif
{
	BigInt srp, srq, nsrp, nsrq;
	
	srp = bigInit(0);
	srq = bigInit(0);
	nsrp = bigInit(0);
	nsrq = bigInit(0);

	squareRoot(a, p, srp);
	squareRoot(a, q, srq);
	
	negate(srp, p, nsrp);
	/*    negate(srq, q, nsrq);*/
	
	crtCombine(srp, srq, p, q, c12, r1);
	crtCombine(nsrp, srq, p, q, c12, r2);
	
	freeBignum(srp);
	freeBignum(srq);
	freeBignum(nsrp);
	freeBignum(nsrq);
}
