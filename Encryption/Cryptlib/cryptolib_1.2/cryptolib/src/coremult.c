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
 *	Core multiplication routines.
 *	Implemented by Jack Lacy.
 *	Copyright AT&T 1994.
 *
 */
#include "libcrypt.h"

/*
   These utilities must run as efficiently as possible.
   They all make use of inner core multiplication utilities
   in longmult.c.
   Ulong_bigmultN()        : utility used by recursiveMultiply() (fastmult.c)
   Assumes a and b have the same length, N.
   Ulong_bigsquareN()        : utility used by bigsquare() (bigmath.c)
   and recursiveSquare() (fastmult.c)
   Ulong_bigmult()        : utility used by lbigmult() (bigmath.c)
*/

#ifdef K_AND_R
void
Ulong_bigmultN(a, b, c, N)
  unsigned long *a, *b, *c;
  int N;
#else
void Ulong_bigmultN(unsigned long *a,
		    unsigned long *b,
		    unsigned long *c,
		    int N)
#endif
{
	register unsigned long *ap, *bp, *cp;
	register unsigned long carry, m;
	register int i;
	
	ap = a;
	bp = b;
	cp = c;
	
	for (i=0; i<N; i++)
		cp[i] = (Ulong)0;
	
	carry = 0;
	i = 0;
	do {
		m = ap[i];
		carry = LMULT(cp, m, bp, N);
		cp[N] = carry;
		cp++;
		i++;
	} while (i<N);
}


#ifdef K_AND_R
void
Ulong_bigsquareN(a, c, N)
  unsigned long *a, *c;
  int N;
#else
void Ulong_bigsquareN(unsigned long *a,
		      unsigned long *c,
		      int N)
#endif
{
	register unsigned long *ap, *cp, m;
	register int i, j;
	
	ap = a;
	cp = c;

	BUILDDIAG(cp, ap, N);
	if (N == 1) return;
	
	ap = a;
	cp = c-1;
	i = 0;
	j = 1;
	do {
/*		cp += 2;*/
		cp = &c[2*i + 1];
		m = ap[i];
		SQUAREINNERLOOP(cp, m, ap, j, N);
		i++; j++;
	} while (i<N-1);
}



#ifdef K_AND_R
void
Ulong_bigmult(a, sb, c, offset)
  BigInt a, c;
  unsigned long sb;
  int offset;
#else
void Ulong_bigmult(BigInt a,
		   unsigned long sb,
		   BigInt c,
		   int offset)
#endif
{
	unsigned long m, carry;
	unsigned long *ap, *cp;
	int gap, i;

	i = LENGTH(a) + offset;
	GUARANTEE(c, (int)(i + 2));

	gap = LENGTH(c) - i;

	if (gap < 0) {
		i = -gap;
		cp = NUM(c) + LENGTH(c);
		do {
			*cp++ = (unsigned long)0;
		} while (--i >= 0);
	}

	ap = NUM(a);
	m = sb;
	cp = NUM(c) + offset;
	carry = LMULT(cp, m, ap, (int)LENGTH(a));
	cp += LENGTH(a);

	if ((i=gap) > 0) {
		do {
			cp[0] = cp[0] + carry;
			carry = (cp[0] < carry);
			cp++;
		} while ((carry != 0) && (--i > 0));
	}
	else
		LENGTH(c) = (int)(offset + LENGTH(a));

	if (carry) {
		*cp++ = carry;
		LENGTH(c)++;
	}
	trim(c);

	
}




