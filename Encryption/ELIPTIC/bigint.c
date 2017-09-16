/************************************************************************
*                                                                       *
*       Routines to implement optimal normal basis multiplication.      *
*  See Mullin, Onyszchuk, Vanstone, Wilson, "Optimal Normal Bases in    *
*  GF(p^n)", Discrete Applied Math, V22, 1988, p149                     *
*   Ash, Blake, Vanstone, "Low Complexity Normal Bases", Discrete       *
*   Applied Math, V25, 1989, p191                                       *
* Agnew, Mullin, Onyszchuk, Vanstone, "An Implementation for a Fast     *
*  Public-Key Cryptosystem", Jour. Cryptology, 1991, V3, p 63           *
* "Elliptic Curve Public Key Cryptosystems", A. Menezes, Kluwer, 1993   *
*  pages 83-86.                                                         *
*                                                                       *
*                       Jan. 22, 1995                                   *
*                                                                       *
************************************************************************/

#include <stdio.h>
#include "bigint.h"
#include "eliptic.h"

/*  global structure for all multiply routines.  compute once at begining
to save disk space.  */

INDEX  Lambda[field_prime];   /*  for multiply  */
ELEMENT mask_table[WORDSIZE];   /*  was for shift_index, now in eliptic.c  */

/*  shift routines assume bigendian structure.  operate in place */

void shift_left(a)
BIGINT *a;
{
        register INDEX i;
        register ELEMENT bit,temp;

        bit = 0;
        for (i=LONGPOS; i>=STRTPOS; i--) {
           temp = ( a->b[i] << 1) | bit;
           bit = (a->b[i] & SUBMASK) ? 1L : 0L;
           a->b[i] = temp;
        }
        a->b[STRTPOS] &= UPRMASK;
}

void shift_right(a)
BIGINT *a;
{
        register INDEX i;
        register ELEMENT bit,temp;

        bit = (a->b[STRTPOS] & 1) ? SUBMASK : 0;
        for (i=STRTPOS; i< MAXLONG; i++) {
           temp = ( a->b[i] >> 1) | bit;
           bit = (a->b[i] & 1) ? SUBMASK : 0;
           a->b[i] = temp;
        }
}

/* an entirely different way to do the same thing */
void rot_left(a)
BIGINT *a;
{
        register INDEX i;
        register ELEMENT bit,temp;

        bit = (a->b[STRTPOS] & UPRBIT) ? 1L : 0L;
        for (i=LONGPOS; i>=STRTPOS; i--) {
           temp = (a->b[i] & SUBMASK) ? 1L : 0L;
           a->b[i] = ( a->b[i] << 1) | bit;
           bit = temp;
        }
        a->b[STRTPOS] &= UPRMASK;
}

void rot_right(a)
BIGINT *a;
{
        register INDEX i;
        register ELEMENT bit,temp;

        bit = (a->b[LONGPOS] & 1) ? UPRBIT : 0L;
        for (i=STRTPOS; i< MAXLONG; i++) {
           temp = ( a->b[i] >> 1)  | bit;
           bit = (a->b[i] & 1) ? SUBMASK : 0L;
           a->b[i] = temp;
        }
        a->b[STRTPOS] &= UPRMASK;
}

void null(a)
BIGINT *a;
{
        register INDEX i;

        for (i=0; i<MAXLONG; i++)  a->b[i] = 0;
}

void copy (a,b)
BIGINT *a,*b;
{
        register INDEX i;

        for (i=0; i<MAXLONG; i++)  b->b[i] = a->b[i];
}

/* create Lambda [i,j] table.  indexed by j, each entry contains the
value of i which satisfies 2^i + 2^j = 1 || 0 mod field_prime.  There are
two 16 bit entries per index j except for zero.  See references for
details.  Since 2^0 = 1 and 2^2n = 1, 2^n = -1 and the first entry would
be 2^0 + 2^n = 0.  Multiplying both sides by 2, it stays congruent to
zero.  So Half the table is unnecessary since multiplying exponents by
2 is the same as squaring is the same as rotation once.  Lambda[0] stores
n = (field_prime - 1)/2.  The terms congruent to one must be found via
lookup in the log table.  Since every entry for (i,j) also generates an
entry for (j,i), the whole 1D table can be built quickly.
*/

void genlambda()
{
        INDEX i,logof,n,index;
        INDEX log2[field_prime],twoexp;

        for (i=0; i<field_prime; i++) log2[i] = -1;

/*  build antilog table first  */

        twoexp = 1;
        for (i=0; i<field_prime; i++) {
          log2[twoexp] = i;
          twoexp = (twoexp << 1) % field_prime;
        }

/*  compute n for easy reference */

        n = (field_prime - 1)/2;
        Lambda[0] = n;
        Lambda[1] = n;
        Lambda[n] = 1;

/*  loop over result space.  Since we want 2^i + 2^j = 1 mod field_prime
        it's a ton easier to loop on 2^i and look up i then solve the silly
        equations.  Think about it, make a table, and it'll be obvious.  */

        for (i=2; i<=n; i++) {
          index = log2[i];
          logof = log2[field_prime - i + 1];
          Lambda[index] = logof;
          Lambda[logof] = index;
        }
/*  last term, it's the only one which equals itself.  See references.  */

        Lambda[log2[n+1]] = log2[n+1];
}

/*  Bit chunk mover needs mask table, which should be built during
        initialization.
*/

void initmask()
{
        register INDEX i;

        mask_table[0] = -1L;
        for (i=1; i<WORDSIZE; i++) mask_table[i] = (ELEMENT)~(-1L << i);
}

/*  Normal Basis Multiplication.  Assumes Lambda vector already initialized
        for type 1 normal basis.  See above references for details
                Output = c = a*b over GF(2^NUMBITS)
*/

void opt_mul(a,b,c)
BIGINT *a,*b,*c;
{
	register INDEX i,j;
	INDEX k, zero_index, one_index;
	ELEMENT bit, temp;
        BIGINT amatrix[NUMBITS] ,bcopy;

        null(c);
        copy(b,&bcopy);

/*  for each rotation of B vector there are at most two rotations of A vector
in a type 1 normal basis.  Lambda is lookup table of A rotations from 2^i +
2^j = 1 mod field_prime.  For 2^i + 2^j = 0, need only one master shift and
single rotations thereafter.  The Lambda table is uniformly scrambled and
shows why this is an efficient bit mixing algorithm.
*/

/*  create the a matrix.  does a copy and rotate right by one for each index  */

	copy (a, &amatrix[0]);
	k = 0;
	for (i=1; i<NUMBITS; i++) {
	  bit = (amatrix[k].b[LONGPOS] & 1) ? UPRBIT : 0L;
	  SUMLOOP(j) {
	    temp = amatrix[k].b[j];
	    amatrix[i].b[j] = (temp>>1) | bit;
	    bit = (temp & 1) ? SUBMASK : 0L;
	  }
	  amatrix[i].b[STRTPOS] &= UPRMASK;
	  k = i;
	}

	zero_index = Lambda[0];
	SUMLOOP (i)
	     c->b[i] = bcopy.b[i] & amatrix[zero_index].b[i];

/*  main loop, two lookups for every position */

        for (j=1; j<NUMBITS; j++) {
           rot_right(&bcopy);
	   one_index = Lambda[j];
	   zero_index = (zero_index+1) % NUMBITS;
	   SUMLOOP (i) c->b[i] ^= bcopy.b[i] & 
		(amatrix[zero_index].b[i] ^ amatrix[one_index].b[i]);
        }
}

/*  opt_inv computes the inverse of a normal basis, GF(2^n) "number".
        Enter with pointers to source number, destination storage.
Leaves source alone and puts its inverse into destination.  
The algorithm is based on the explanation given in Menezes book.
It can be formalized as follows:
for GF(2^m), exponent of -1 = 2^m - 2 = 2(2^(m-1) -1).

Write m-1 = sum ( m_k * 2^k)  where m_k = {0,1}, k = 0,1,...,l
Let
	r_i = sum ( m_(k+i) * 2^k) k = 0,1,..,l-i

Then each step in the exponent expansion can be written as

	2^r_s - 1 = 2^m_s * (2^m_(s+1) - 1) * (2^m_(s+1) + 1) + m_s

When bit m_s = 0 the last multiply and squaring are absent.  Starting
with r_l, work up the chain until s=0 and square the final result.

To speed things up a bit, implement specific bit lengths and use a
single expansion for multiplication when m_s = 1.  A very special
multiply routine is included to compute x^2^j * x.
Seems pretty cool to this programmer!
*/

/*  this routine used by opt_inv to multiply a number by a specified
shifted amount.  Enter with pointer to number, pointer to result,
and index shift amount.
*/

void index_mul(a, c, shift)
BIGINT *a, *c;
INDEX shift;
{
	register INDEX i,j;
	INDEX k;
	INDEX zero_index, one_index;
	BIGINT amatrix[NUMBITS], bcopy;
	ELEMENT bit, temp;

	null(c);

/*  create the a matrix.  does a copy and rotate right by one for each index  */

	copy (a, &amatrix[0]);
	k = 0;
	for (i=1; i<NUMBITS; i++) {
	  bit = (amatrix[k].b[LONGPOS] & 1) ? UPRBIT : 0L;
	  SUMLOOP(j) {
	    temp = amatrix[k].b[j];
	    amatrix[i].b[j] = (temp>>1) | bit;
	    bit = (temp & 1) ? SUBMASK : 0L;
	  }
	  amatrix[i].b[STRTPOS] &= UPRMASK;
	  k = i;
	}
	copy (&amatrix[NUMBITS - shift], &bcopy);
	zero_index = Lambda[0];
	SUMLOOP (i)
	     c->b[i] = bcopy.b[i] & amatrix[zero_index].b[i];

/*  main loop, two lookups for every position */

        for (j=1; j<NUMBITS; j++) {
           rot_right(&bcopy);
	   one_index = Lambda[j];
	   zero_index = (zero_index+1) % NUMBITS;
	   SUMLOOP (i) c->b[i] ^= bcopy.b[i] & 
		(amatrix[zero_index].b[i] ^ amatrix[one_index].b[i]);
        }
}

void opt_inv(src,dst)
BIGINT *src, *dst;
{
	register INDEX i,j;
	INDEX zero_index, one_index, k;
        BIGINT amatrix[NUMBITS], a_0, a_1, a_2;
	ELEMENT	bit, temp;

        copy(src, &amatrix[0]);
        null(dst);

/*  expand src into local matrix, will be used for several steps  */

	k = 0;
	for (i=1; i<NUMBITS; i++) {
	  bit = (amatrix[k].b[LONGPOS] & 1) ? UPRBIT : 0L;
	  SUMLOOP(j) {
	    temp = amatrix[k].b[j];
	    amatrix[i].b[j] = (temp>>1) | bit;
	    bit = (temp & 1) ? SUBMASK : 0L;
	  }
	  amatrix[i].b[STRTPOS] &= UPRMASK;
	  k = i;
	}

/*  begin working up chain of multiplies.  NUMBITS = 148 assumed here. */
/*  Fancy coders, use contditionals to build this for arbitrary NUMBITS. */

/* 2^2 - 1  */

	copy (&amatrix[NUMBITS - 1], &a_0);
	zero_index = Lambda[0];
	SUMLOOP (i)
	     a_1.b[i] = a_0.b[i] & amatrix[zero_index].b[i];

/*  main loop, two lookups for every position */

        for (j=1; j<NUMBITS; j++) {
           rot_right(&a_0);
	   one_index = Lambda[j];
	   zero_index = (zero_index+1) % NUMBITS;
	   SUMLOOP (i) a_1.b[i] ^= a_0.b[i] & 
		(amatrix[zero_index].b[i] ^ amatrix[one_index].b[i]);
        }

/*  2^4 - 1  */

	index_mul( &a_1, &a_2, 2);

/*  2^9 - 1 */

	index_mul( &a_2, &a_0, 4);
	rot_left(&a_0);

	zero_index = Lambda[0];
	SUMLOOP (i)
	     a_1.b[i] = a_0.b[i] & amatrix[zero_index].b[i];

/*  main loop, two lookups for every position */

        for (j=1; j<NUMBITS; j++) {
           rot_right(&a_0);
	   one_index = Lambda[j];
	   zero_index = (zero_index+1) % NUMBITS;
	   SUMLOOP (i) a_1.b[i] ^= a_0.b[i] & 
		(amatrix[zero_index].b[i] ^ amatrix[one_index].b[i]);
        }

/*  2^18 - 1 */

	index_mul (&a_1, &a_2, 9);

/*  2^36 - 1 */

	index_mul (&a_2, &a_0, 18);

/*  2^73 - 1 */

	index_mul (&a_0, &a_1, 36);
	rot_left (&a_1);
	zero_index = Lambda[0];
	SUMLOOP (i)
	     a_2.b[i] = a_1.b[i] & amatrix[zero_index].b[i];

/*  main loop, two lookups for every position */

        for (j=1; j<NUMBITS; j++) {
           rot_right(&a_1);
	   one_index = Lambda[j];
	   zero_index = (zero_index+1) % NUMBITS;
	   SUMLOOP (i) a_2.b[i] ^= a_1.b[i] & 
		(amatrix[zero_index].b[i] ^ amatrix[one_index].b[i]);
        }

/*  2^147 - 1 */

	index_mul( &a_2, &a_0, 73);
	rot_left(&a_0);
	zero_index = Lambda[0];
	SUMLOOP (i)
	     dst->b[i] = a_0.b[i] & amatrix[zero_index].b[i];

/*  main loop, two lookups for every position */

        for (j=1; j<NUMBITS; j++) {
           rot_right(&a_0);
	   one_index = Lambda[j];
	   zero_index = (zero_index+1) % NUMBITS;
	   SUMLOOP (i) dst->b[i] ^= a_0.b[i] & 
		(amatrix[zero_index].b[i] ^ amatrix[one_index].b[i]);
        }

        rot_left( dst); /* final squaring */
}

void init_opt_math()
{

        initmask();             /*  create shift_index mask table  */
        genlambda();            /*  create Lambda pointer table    */
}
}
