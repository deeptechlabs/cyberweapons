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
 *        Routines for calculating Jacoby symbols both for 
 *	  ints and BigInts.
 *        coded by Jack Lacy and Tom London
 *
 *        Copyright (c) 1995 AT&T Bell Laboratories
 */
#include "libcrypt.h"

int tab2[] = {0, 1, 0, -1, 0, -1, 0, 1};

#ifdef K_AND_R
_TYPE( int ) bigJacobi(a, b)
  BigInt a;
  BigInt b;
#else
_TYPE( int ) bigJacobi(BigInt a, BigInt b)
#endif
{
	static BigInt aa, bb, r;
	static int first_time = 1;
	int v, k;
	
	if (first_time) {
		aa = bigInit(0);
		bb = bigInit(0);
		r = bigInit(0);
		first_time = 0;
	}
	
	if (ZERO(b)) {
		if ((bigCompare(a, one) == 0))
			return 1;
		else
			return 0;
	}
	
	if (EVEN(a) && EVEN(b))
		return 0;
	
	bigCopy(a, aa);
	bigCopy(b, bb);
	
	v = 0;
	while (EVEN(bb)) {
		v++;
		bigRightShift(bb, 1, bb);
	}
	if ((v & 1) == 0)
		k = 1;
	else
		k = tab2[NUM(aa)[0]&7];
	
	if (SIGN(bb) == NEG) {
		SIGN(bb) = POS;
		if (SIGN(aa) == NEG)
			k = -k;
	}
	
	while(1) {
		if (ZERO(aa)) {
			v = bigCompare(bb, one);
			if (v>0)
				return 0;
			else if (v == 0) {
				return k;
			}
		}
		v = 0;
		while (EVEN(aa)) {
			v++;
			bigRightShift(aa, 1, aa);
		}
		if (v & 1)
			k = k*tab2[NUM(bb)[0]&7];
		
		if ((NUM(aa)[0])&(NUM(bb)[0])&2)
			k = -k;
		bigCopy(aa, r);
		bigMod(bb, r, aa);
		bigCopy(r, bb);
	}
}

#ifdef K_AND_R
_TYPE( int )
jacobi(a, b)
  int a, b;
#else
_TYPE( int )
jacobi(int a, int b)
#endif
{
	int v;
	int k;
	int r;
	
	if( b==0 ) {
		if( a==1 || a==-1 )
			return(1);
		else
			return(0);
	}
	
	if( ((a & 1) == 0) && ((b & 1) == 0) )
		return(0);
	v = 0;
	while( (b & 1) == 0 ) {
		v++;
		b /= 2;
	}
	if( (v & 1) == 0 ) 
		k = 1;
	else
		k = tab2[a&7];
	
	if( b<0 ) {
		b = -b;
		if( a<0 )
		        k = -k;
        }
	
	while( 1 ) {
		if( a==0 ) {
			if( b>1 ) return(0);
			if( b==1 ) return(k);
		}
		v = 0;
		while( (a & 1) == 0 ) {
			v++;
			a /= 2;
		}
		if( v&1 )
			k = k*tab2[b&7];
		
		if(a&b&2) k = -k;
		r = abs(a);
		a = b % r;
		b = r;
	}
}

#ifdef K_AND_R
_TYPE( int )	
isQR(a, p, q)
  int a, p, q;
#else
_TYPE( int )	
isQR(int a, int p, int q)
#endif
{
	if( jacobi(a, p)==1 && jacobi(a, q)==1 )
		return(1);
	else return(0);
}

#ifdef K_AND_R
_TYPE( int )
bigIsQR(a, p, q)
  BigInt a, p, q;
#else
_TYPE( int )
bigIsQR(BigInt a, BigInt p, BigInt q)
#endif
{
	int retval;
	
	retval = bigJacobi(a, p);
	if (retval != 1)
		return 0;
	retval = bigJacobi(a, q);
	if (retval != 1)
		return 0;
		
	return TRUE;
}

