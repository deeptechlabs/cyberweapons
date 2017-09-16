/*
 *	loki89.c - library routines for a 64 bit LOKI89 implementation
 *
 *  Author:	Lawrence Brown <lpb@csadfa.oz>		Aug 1989
 *		Computer Science, UC UNSW, ADFA, Canberra, ACT 2600, Australia.
 *
 *  Modifications:
 *		v1.0 - original set of code (based on des64.c v4.0) 9/89 lpb
 *		v2.0 - include conditionals for various speed/sizes 4/90 lpb
 *		v2.1 - use RCS system for production control	5/90 lpb
 *		v3.0 - support both LOKI89 & LOKI91 versions   10/92 lpb
 *
 *  Copyright 1989 by Lawrence Brown and UNSW. All rights reserved.
 *      This program may not be sold or used as inducement to buy a
 *      product without the written permission of the author.
 *
 *	nb: if this program is compiled on a little-endian machine (eg Vax)
 *		#define LITTLE_ENDIAN
 *		in order to enable the byte swapping  routines 
 *
 *	    if a detailed trace of LOKI89 function f is required for debugging
 *		#define TRACE=n		n=1 print blocks, n=2 print fn f also
 *                                      n=3 print individual S-box calcs also
 *
 *	    these routines assume that the 8-byte char arrays used to pass
 *		the 64-bit blocks fall on a word boundary, so that the blocks
 *		may be read as longwords for efficiency reasons. If this is
 *		not true, the load & save of the parameters will need changing.
 */
#include <stdio.h>
#include "loki.h"	/* include Interface Specification header file       */
#include "loki.i"	/* include LOKI89 Permutation, Subs & Key tables*/

/*
 *	string specifying version and copyright message
 */
char	*loki_lib_ver = "LOKI89 library v3.0, Copyright (C) 1990 Lawrence Brown & UNSW";

static Long	f();	/* declare LOKI89 function f		     */
static short	s();	/* declare LOKI89 s-box routine (for small ver) */

/*
 *	lokikey - the 64-bit key for the LOKI89 library routines
 */
Long	lokikey[2] = {0, 0};


/*
 *	ROL12(b) - macro to rotate 32-bit block b left  by 12 bits
 *	ROR12(b) - macro to rotate 32-bit block b right by 12 bits
 */
#define ROL12(b) b = ((b << 12) | (b >> 20));
#define ROR12(b) b = ((b >> 12) | (b << 20));

/*
 *      bswap(b) - exchanged bytes in each longword of a 64-bit data block
 *                      on little-endian machines where byte order is reversed
 */
#ifdef  LITTLE_ENDIAN
#define bswap(cb) {                             \
        register char   c;                      \
        c = cb[0]; cb[0] = cb[3]; cb[3] = c;    \
        c = cb[1]; cb[1] = cb[2]; cb[2] = c;    \
        c = cb[4]; cb[4] = cb[7]; cb[7] = c;    \
        c = cb[5]; cb[5] = cb[6]; cb[6] = c;    \
}
#endif

/*
 *	setlokikey(key) - save 64-bit key for use in encryptions & decryptions
 */

void
setlokikey(key)
char	key[LOKIBLK];		/* Key to use, stored as an array of Longs    */
{
#ifdef LITTLE_ENDIAN
	bswap(key);			/* swap bytes round if little-endian */
#endif

	lokikey[0] = ((Long *)key)[0];
	lokikey[1] = ((Long *)key)[1];

#if	TRACE >= 1
	fprintf(stderr,"  keyinit(%08lx, %08lx)\n", lokikey[0], lokikey[1]);
#endif

#ifdef LITTLE_ENDIAN
	bswap(key);			/* swap bytes back if little-endian */
#endif
}


/*
 *	enloki(b) - main LOKI89 encryption routine, this routine encrypts one 
 *		64-bit block b using the LOKI89 algorithm with lokikey
 *
 *		The encryption operation involves XOR'ing the input block with
 *		the key, applying a LOKI89 round sixteen times
 *		(which ensures the output is a complex function of the input,
 *		and the key), and finally XOR'ing the input block with the key
 *
 *		Each round performs the following calculation using a 48-bit
 *		subkeys:
 *			L(i) = R(i-1)
 *			R(i) = L(i-1) XOR f(R(i-1), K(i))
 *
 *		To save swapping, alternate calls to f use L & R respectively
 *
 *		nb: The 64-bit block is passed as two longwords. For the
 *			purposes of the LOKI89 algorithm, the bits are numbered:
 *			    [63 62 .. 33 32] [31 30 ... 1 0]
 *			The L (left) half is b[0], the R (right) half is b[1]
 *
 */
void
enloki(b)
char	b[LOKIBLK];
{
	register Long	L, R;			/* left & right data halves  */
	register Long	KL, KR;			/* left & right key  halves  */

#ifdef LITTLE_ENDIAN
	bswap(b);			/* swap bytes round if little-endian */
#endif

#if	TRACE >= 1
	fprintf(stderr,"  enloki(%08lx, %08lx)\n", ((Long *)b)[0], ((Long *)b)[1]);
#endif

	KL = lokikey[0];			/* load keys in register vars */
	KR = lokikey[1];

	L = ((Long *)b)[0] ^ KL;		/* LR = X XOR K */
	R = ((Long *)b)[1] ^ KR;

	/* Perform the 16 rounds using sub-keys in usual order               */
	L ^= f(R, KL);	ROL12(KL);		
	R ^= f(L, KR);	ROL12(KR);
	L ^= f(R, KL);	ROL12(KL);		
	R ^= f(L, KR);	ROL12(KR);
	L ^= f(R, KL);	ROL12(KL);		
	R ^= f(L, KR);	ROL12(KR);
	L ^= f(R, KL);	ROL12(KL);		
	R ^= f(L, KR);	ROL12(KR);
	L ^= f(R, KL);	ROL12(KL);		
	R ^= f(L, KR);	ROL12(KR);
	L ^= f(R, KL);	ROL12(KL);		
	R ^= f(L, KR);	ROL12(KR);
	L ^= f(R, KL);	ROL12(KL);		
	R ^= f(L, KR);	ROL12(KR);
	L ^= f(R, KL);	ROL12(KL);		
	R ^= f(L, KR);	ROL12(KR);

	((Long *)b)[0] = R ^ KR;		/* Y = swap(LR) XOR K */
	((Long *)b)[1] = L ^ KL;

#if	TRACE >= 1
	fprintf(stderr,"  enloki returns %08lx, %08lx\n", ((Long *)b)[0], ((Long *)b)[1]);
#endif

#ifdef LITTLE_ENDIAN
	bswap(b);			/* swap bytes round if little-endian */
#endif
}


/*
 *	deloki(b) - main LOKI89 decryption routine, this routine decrypts one 
 *		64-bit block b using the LOKI89 algorithm with lokikey
 *
 *		Decryption uses the same algorithm as encryption, except that
 *		the subkeys are used in reverse order.
 */
void
deloki(b)
char	b[LOKIBLK];
{
	register Long	L, R;			/* left & right data halves  */
	register Long	KL, KR;			/* left & right key  halves  */

#ifdef LITTLE_ENDIAN
	bswap(b);			/* swap bytes round if little-endian */
#endif

#if	TRACE >= 1
	fprintf(stderr,"  deloki(%08lx, %08lx)\n", ((Long *)b)[0], ((Long *)b)[1]);
#endif

	KL = lokikey[0];			/* load keys in register vars */
	KR = lokikey[1];

	L = ((Long *)b)[0] ^ KR;		/* LR = X XOR K */
	R = ((Long *)b)[1] ^ KL;

	/* Perform the 16 rounds using sub-keys in usual order               */
	ROR12(KR);	L ^= f(R, KR);
	ROR12(KL);	R ^= f(L, KL);
	ROR12(KR);	L ^= f(R, KR);
	ROR12(KL);	R ^= f(L, KL);
	ROR12(KR);	L ^= f(R, KR);
	ROR12(KL);	R ^= f(L, KL);
	ROR12(KR);	L ^= f(R, KR);
	ROR12(KL);	R ^= f(L, KL);
	ROR12(KR);	L ^= f(R, KR);
	ROR12(KL);	R ^= f(L, KL);
	ROR12(KR);	L ^= f(R, KR);
	ROR12(KL);	R ^= f(L, KL);
	ROR12(KR);	L ^= f(R, KR);
	ROR12(KL);	R ^= f(L, KL);
	ROR12(KR);	L ^= f(R, KR);
	ROR12(KL);	R ^= f(L, KL);

	((Long *)b)[0] = R ^ KL;		/* Y = LR XOR K */
	((Long *)b)[1] = L ^ KR;

#if	TRACE >= 1
	fprintf(stderr,"  deloki returns %08lx, %08lx\n", ((Long *)b)[0], ((Long *)b)[1]);
#endif

#ifdef LITTLE_ENDIAN
	bswap(b);			/* swap bytes round if little-endian */
#endif
}


/*
 *	f(r, k) - is the complex non-linear LOKI89 function, whose output
 *		is a complex function of both input data and sub-key.
 *		The input data R(i-1) is:
 *			added modulo 2 to the key K(i)
 *			expanded to 48-bits via expansion fn E
 *			substituted into the S-boxes
 *			permuted by P.
 *		ie the calculation is:
 *			A = E(R(i-1) XOR K(i))		(a 48-bit value)
 *			B = S(A)			(a 32-bit value)
 *			f = P(B)			(a 32-bit value)
 *
 *	nb: the 12-bit S-box input value [x x x x 11 10 9 ... 3 2 1 0]
 *	    is interpreted as:
 *		bits [11 10 1 0] select 1 of 16 rows within each box,
 *		bits [9 8 ... 3 2] then select a column within that row
 */

#define MASK12	0x0fff			/* 12 bit mask for expansion E */

static Long
f(r, k)
register Long	r;	/* Data value R(i-1) */
Long		k;	/* Key     K(i)   */
{
	Long	a, b, c;		/* 32 bit S-box output, & P output */

	a = r ^ k;			/* A = R(i-1) XOR K(i) */

	/* want to use slow speed/small size version */
	b = ((Long)s((a         & MASK12))      ) | /* B = S(E(R(i-1))^K(i)) */
	    ((Long)s(((a >>  8) & MASK12)) <<  8) |
	    ((Long)s(((a >> 16) & MASK12)) << 16) |
	    ((Long)s((((a >> 24) | (a << 8)) & MASK12)) << 24);

	perm32(&c, &b, P);		/* C = P(S( E(R(i-1)) XOR K(i))) */

#if	TRACE >= 2	/* If Tracing, dump A, K(i), and f(R(i-1),K(i)) */
	fprintf(stderr,"  f(%08lx, %08lx) = P.S(%08lx) = P(%08lx) = %08lx\n",
		r, k, a, b, c);
#endif

	return(c);			/* f returns the result C */
}


/*
 *	s(i) - return S-box value for input i
 */
static short s(i)
register Long i;	/* return S-box value for input i */
{
	register short	r, c, v, t;
	short	exp8();		/* exponentiation routine for GF(2^8) */
	
	r = ((i>>8) & 0xc) | (i & 0x3);		/* row value */
	c = (i>>2) & 0xff;			/* column value */
	t = c ^ r;				/* base value for Sfn */
	v = exp8(t, sfn[r].exp, sfn[r].gen);	/* Sfn[r] = t ^ exp mod gen */
#if TRACE >= 3
	fprintf(stderr, "   s(%lx=[%d,%d]) = %x sup %d mod %d = %x\n",
			i, r, c, t, sfn[r].exp, sfn[r].gen, v);
#endif
	return(v);
}

/*
 *	perm32(out, in, perm) is the general permutation of a 32-bit input
 *		block to a 32-bit output block, under the control of a 
 *		permutation array perm. Each element of perm specifies which
 *		input bit is to be permuted to the output bit with the same
 *		index as the array element.
 *
 *	nb: to set bits in the output word, as mask with a single 1 in it is
 *		used. On each step, the 1 is shifted into the next location
 */

#define	MSB	0x80000000L		/* MSB of 32-bit word */

perm32(out, in , perm)
Long	*out;		/* Output 32-bit block to be permuted                */
Long	*in;		/* Input  32-bit block after permutation             */
char	perm[32]; 	/* Permutation array                                 */
{
	Long	mask = MSB;		/* mask used to set bit in output    */
	register int	i, o, b;	/* input bit no, output bit no, value */
	register char	*p = perm;	/* ptr to permutation array  */

	*out = 0;			/* clear output block */
	for (o=0; o<32; o++) {		/* For each output bit position o */	
		i =(int)*p++;		/* get input bit permuted to output o */
		b = (*in >> i) & 01;	/* value of input bit i */
		if (b)			/* If the input bit i is set */
			*out |= mask;		/*  OR in mask to output i */
		mask >>= 1;			/* Shift mask to next bit    */
	}
}

/*
 *	mult8(a, b, gen) - returns the product of two binary
 *		strings a and b using the generator gen as the modulus
 *			mult = a * b mod gen
 *		gen generates a suitable Galois field in GF(2^8)
 */

#define SIZE 256		/* 256 elements in GF(2^8) */

short mult8(a, b, gen)
short	a, b;		/* operands for multiply */
short	gen;		/* irreducible polynomial generating Galois Field */
{
	short	product = 0;		/* result of multiplication */

	while(b != 0) {			/* while multiplier is non-zero */
		if (b & 01)
			product ^= a;	/*   add multiplicand if LSB of b set */
		a <<= 1;		/*   shift multiplicand one place */
		if (a >= SIZE)
			a ^= gen;	/*   and modulo reduce if needed */
		b >>= 1;		/*   shift multiplier one place  */
	}
	return(product);
}

/*
 *	exp8(base, exponent, gen) - returns the result of
 *		exponentiation given the base, exponent, generator of GF,
 *			exp = base ^ exp mod gen
 */

short exp8(base, exponent, gen)
short	base;		/* base of exponentiation 	*/
short	exponent;	/* exponent			*/
short	gen;		/* irreducible polynomial generating Galois Field */
{
	short	accum = base;	/* superincreasing sequence of base */
	short	result = 1;	/* result of exponentiation	    */

	if (base == 0)		/* if zero base specified then      */
		return(0);	/* the result is "0" if base = 0    */

	while (exponent != 0) {	/* repeat while exponent non-zero */
		if (( exponent & 0x0001) == 0x0001)	/* multiply if exp 1 */
			result = mult8(result, accum, gen);
		exponent >>= 1;		/* shift exponent to next digit */
		accum = mult8(accum, accum, gen);	/* & square  */
	}
	return(result);
}
