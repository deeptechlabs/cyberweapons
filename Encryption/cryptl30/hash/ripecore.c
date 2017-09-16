/****************************************************************************
*																			*
*						 RIPEMD-160 Core Transformation 					*
*						Copyright Peter Gutmann 1992-1997					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
#else
  #include "crypt.h"
#endif /* Compiler-specific includes */

/* The RIPEMD-160 f()-functions.  The f1 function can be optimized to save
   one boolean operation each - thanks to Rich Schroeppel
   <rcs@cs.arizona.edu> for discovering this.  The f2 function can be
   optimized to eliminate one boolean operation - thanks for Wei Dai for
   discovering this */

#define f1(x,y,z)	( x ^ y ^ z )						/* Rounds  0-15 */
/*#define f2(x,y,z)	( ( x & y ) | ( ~x & z ) )			// Rounds 16-31 */
#define f2(x,y,z)	( z ^ ( x & ( y ^ z ) ) )			/* Rounds 16-31 */
#define f3(x,y,z)	( ( x | ~y ) ^ z )					/* Rounds 32-47 */
/*#define f4(x,y,z)	( ( x & z ) | ( y & ~z ) )			// Rounds 48-63 */
#define	f4(x,y,z)	( y ^ ( z & ( x ^ y ) ) )			/* Rounds 48-63 */
#define f5(x,y,z)	( x ^ ( y | ~z ) )					/* Rounds 64-79 */

/* The RIPEMD-160 Mysterious Constants */

#define K1A		0x00000000UL
#define K1B		0x50A28BE6UL							/* Rounds  0-15 */
#define K2A		0x5A827999UL
#define K2B 	0x5C4DD124UL							/* Rounds 16-31 */
#define K3A		0x6ED9EBA1UL
#define K3B		0x6D703EF3UL							/* Rounds 32-47 */
#define K4A		0x8F1BBCDCUL
#define K4B		0x7A6D76E9UL							/* Rounds 48-63 */
#define K5A		0xA953FD4EUL
#define K5B		0x00000000UL							/* Rounds 64-79 */

/* Note that it may be necessary to add parentheses to these macros if they
   are to be called with expressions as arguments */

/* 32-bit rotate left - kludged with shifts */

#define ROTL(n,X)  ( ( ( X ) << n ) | ( ( X ) >> ( 32 - n ) ) )

/* The prototype RIPE-MD160 sub-round.  The fundamental sub-round is:

		a' = ROTL( a + f( b, c, d ) + data + k, s ) + e;
		b' = a;
		c' = ROTL( 10, c );
		d' = c;
		e' = d;

   but this is implemented by unrolling the loop 5 times and renaming the
   variables ( e, a, b, c, d ) = ( a', b', c', d', e' ) each iteration.
   This code is then replicated 16 times for each of the 5 functions */

#define subRound( a, b, c, d, e, f, s, k, data ) \
	a += f( b, c, d ) + data + k; \
	a = MASK32( ROTL( s, MASK32( a ) ) + e ); \
	c = MASK32( ROTL( 10, c ) )

/* Perform the RIPEMD-160 transformation.  This performs a parellel
   transformation of the hX values (hXl and hXr) and then combines the
   results back into hX at the end */

void RIPEMD160Transform( LONG *digest, LONG *data )
	{
	LONG h1l, h2l, h3l, h4l, h5l, h1r, h2r, h3r, h4r, h5r;

	h1l = h1r = digest[ 0 ];
	h2l = h2r = digest[ 1 ];
	h3l = h3r = digest[ 2 ];
	h4l = h4r = digest[ 3 ];
	h5l = h5r = digest[ 4 ];

	subRound( h1l, h2l, h3l, h4l, h5l, f1, 11, K1A, data[  0 ] );
	subRound( h5l, h1l, h2l, h3l, h4l, f1, 14, K1A, data[  1 ] );
	subRound( h4l, h5l, h1l, h2l, h3l, f1, 15, K1A, data[  2 ] );
	subRound( h3l, h4l, h5l, h1l, h2l, f1, 12, K1A, data[  3 ] );
	subRound( h2l, h3l, h4l, h5l, h1l, f1,  5, K1A, data[  4 ] );
	subRound( h1l, h2l, h3l, h4l, h5l, f1,  8, K1A, data[  5 ] );
	subRound( h5l, h1l, h2l, h3l, h4l, f1,  7, K1A, data[  6 ] );
	subRound( h4l, h5l, h1l, h2l, h3l, f1,  9, K1A, data[  7 ] );
	subRound( h3l, h4l, h5l, h1l, h2l, f1, 11, K1A, data[  8 ] );
	subRound( h2l, h3l, h4l, h5l, h1l, f1, 13, K1A, data[  9 ] );
	subRound( h1l, h2l, h3l, h4l, h5l, f1, 14, K1A, data[ 10 ] );
	subRound( h5l, h1l, h2l, h3l, h4l, f1, 15, K1A, data[ 11 ] );
	subRound( h4l, h5l, h1l, h2l, h3l, f1,  6, K1A, data[ 12 ] );
	subRound( h3l, h4l, h5l, h1l, h2l, f1,  7, K1A, data[ 13 ] );
	subRound( h2l, h3l, h4l, h5l, h1l, f1,  9, K1A, data[ 14 ] );
	subRound( h1l, h2l, h3l, h4l, h5l, f1,  8, K1A, data[ 15 ] );

	subRound( h5l, h1l, h2l, h3l, h4l, f2,  7, K2A, data[  7 ] );
	subRound( h4l, h5l, h1l, h2l, h3l, f2,  6, K2A, data[  4 ] );
	subRound( h3l, h4l, h5l, h1l, h2l, f2,  8, K2A, data[ 13 ] );
	subRound( h2l, h3l, h4l, h5l, h1l, f2, 13, K2A, data[  1 ] );
	subRound( h1l, h2l, h3l, h4l, h5l, f2, 11, K2A, data[ 10 ] );
	subRound( h5l, h1l, h2l, h3l, h4l, f2,  9, K2A, data[  6 ] );
	subRound( h4l, h5l, h1l, h2l, h3l, f2,  7, K2A, data[ 15 ] );
	subRound( h3l, h4l, h5l, h1l, h2l, f2, 15, K2A, data[  3 ] );
	subRound( h2l, h3l, h4l, h5l, h1l, f2,  7, K2A, data[ 12 ] );
	subRound( h1l, h2l, h3l, h4l, h5l, f2, 12, K2A, data[  0 ] );
	subRound( h5l, h1l, h2l, h3l, h4l, f2, 15, K2A, data[  9 ] );
	subRound( h4l, h5l, h1l, h2l, h3l, f2,  9, K2A, data[  5 ] );
	subRound( h3l, h4l, h5l, h1l, h2l, f2, 11, K2A, data[  2 ] );
	subRound( h2l, h3l, h4l, h5l, h1l, f2,  7, K2A, data[ 14 ] );
	subRound( h1l, h2l, h3l, h4l, h5l, f2, 13, K2A, data[ 11 ] );
	subRound( h5l, h1l, h2l, h3l, h4l, f2, 12, K2A, data[  8 ] );

	subRound( h4l, h5l, h1l, h2l, h3l, f3, 11, K3A, data[  3 ] );
	subRound( h3l, h4l, h5l, h1l, h2l, f3, 13, K3A, data[ 10 ] );
	subRound( h2l, h3l, h4l, h5l, h1l, f3,  6, K3A, data[ 14 ] );
	subRound( h1l, h2l, h3l, h4l, h5l, f3,  7, K3A, data[  4 ] );
	subRound( h5l, h1l, h2l, h3l, h4l, f3, 14, K3A, data[  9 ] );
	subRound( h4l, h5l, h1l, h2l, h3l, f3,  9, K3A, data[ 15 ] );
	subRound( h3l, h4l, h5l, h1l, h2l, f3, 13, K3A, data[  8 ] );
	subRound( h2l, h3l, h4l, h5l, h1l, f3, 15, K3A, data[  1 ] );
	subRound( h1l, h2l, h3l, h4l, h5l, f3, 14, K3A, data[  2 ] );
	subRound( h5l, h1l, h2l, h3l, h4l, f3,  8, K3A, data[  7 ] );
	subRound( h4l, h5l, h1l, h2l, h3l, f3, 13, K3A, data[  0 ] );
	subRound( h3l, h4l, h5l, h1l, h2l, f3,  6, K3A, data[  6 ] );
	subRound( h2l, h3l, h4l, h5l, h1l, f3,  5, K3A, data[ 13 ] );
	subRound( h1l, h2l, h3l, h4l, h5l, f3, 12, K3A, data[ 11 ] );
	subRound( h5l, h1l, h2l, h3l, h4l, f3,  7, K3A, data[  5 ] );
	subRound( h4l, h5l, h1l, h2l, h3l, f3,  5, K3A, data[ 12 ] );

	subRound( h3l, h4l, h5l, h1l, h2l, f4, 11, K4A, data[  1 ] );
	subRound( h2l, h3l, h4l, h5l, h1l, f4, 12, K4A, data[  9 ] );
	subRound( h1l, h2l, h3l, h4l, h5l, f4, 14, K4A, data[ 11 ] );
	subRound( h5l, h1l, h2l, h3l, h4l, f4, 15, K4A, data[ 10 ] );
	subRound( h4l, h5l, h1l, h2l, h3l, f4, 14, K4A, data[  0 ] );
	subRound( h3l, h4l, h5l, h1l, h2l, f4, 15, K4A, data[  8 ] );
	subRound( h2l, h3l, h4l, h5l, h1l, f4,  9, K4A, data[ 12 ] );
	subRound( h1l, h2l, h3l, h4l, h5l, f4,  8, K4A, data[  4 ] );
	subRound( h5l, h1l, h2l, h3l, h4l, f4,  9, K4A, data[ 13 ] );
	subRound( h4l, h5l, h1l, h2l, h3l, f4, 14, K4A, data[  3 ] );
	subRound( h3l, h4l, h5l, h1l, h2l, f4,  5, K4A, data[  7 ] );
	subRound( h2l, h3l, h4l, h5l, h1l, f4,  6, K4A, data[ 15 ] );
	subRound( h1l, h2l, h3l, h4l, h5l, f4,  8, K4A, data[ 14 ] );
	subRound( h5l, h1l, h2l, h3l, h4l, f4,  6, K4A, data[  5 ] );
	subRound( h4l, h5l, h1l, h2l, h3l, f4,  5, K4A, data[  6 ] );
	subRound( h3l, h4l, h5l, h1l, h2l, f4, 12, K4A, data[  2 ] );

	subRound( h2l, h3l, h4l, h5l, h1l, f5,  9, K5A, data[  4 ] );
	subRound( h1l, h2l, h3l, h4l, h5l, f5, 15, K5A, data[  0 ] );
	subRound( h5l, h1l, h2l, h3l, h4l, f5,  5, K5A, data[  5 ] );
	subRound( h4l, h5l, h1l, h2l, h3l, f5, 11, K5A, data[  9 ] );
	subRound( h3l, h4l, h5l, h1l, h2l, f5,  6, K5A, data[  7 ] );
	subRound( h2l, h3l, h4l, h5l, h1l, f5,  8, K5A, data[ 12 ] );
	subRound( h1l, h2l, h3l, h4l, h5l, f5, 13, K5A, data[  2 ] );
	subRound( h5l, h1l, h2l, h3l, h4l, f5, 12, K5A, data[ 10 ] );
	subRound( h4l, h5l, h1l, h2l, h3l, f5,  5, K5A, data[ 14 ] );
	subRound( h3l, h4l, h5l, h1l, h2l, f5, 12, K5A, data[  1 ] );
	subRound( h2l, h3l, h4l, h5l, h1l, f5, 13, K5A, data[  3 ] );
	subRound( h1l, h2l, h3l, h4l, h5l, f5, 14, K5A, data[  8 ] );
	subRound( h5l, h1l, h2l, h3l, h4l, f5, 11, K5A, data[ 11 ] );
	subRound( h4l, h5l, h1l, h2l, h3l, f5,  8, K5A, data[  6 ] );
	subRound( h3l, h4l, h5l, h1l, h2l, f5,  5, K5A, data[ 15 ] );
	subRound( h2l, h3l, h4l, h5l, h1l, f5,  6, K5A, data[ 13 ] );

	subRound( h1r, h2r, h3r, h4r, h5r, f5,  8, K1B, data[  5 ] );
	subRound( h5r, h1r, h2r, h3r, h4r, f5,  9, K1B, data[ 14 ] );
	subRound( h4r, h5r, h1r, h2r, h3r, f5,  9, K1B, data[  7 ] );
	subRound( h3r, h4r, h5r, h1r, h2r, f5, 11, K1B, data[  0 ] );
	subRound( h2r, h3r, h4r, h5r, h1r, f5, 13, K1B, data[  9 ] );
	subRound( h1r, h2r, h3r, h4r, h5r, f5, 15, K1B, data[  2 ] );
	subRound( h5r, h1r, h2r, h3r, h4r, f5, 15, K1B, data[ 11 ] );
	subRound( h4r, h5r, h1r, h2r, h3r, f5,  5, K1B, data[  4 ] );
	subRound( h3r, h4r, h5r, h1r, h2r, f5,  7, K1B, data[ 13 ] );
	subRound( h2r, h3r, h4r, h5r, h1r, f5,  7, K1B, data[  6 ] );
	subRound( h1r, h2r, h3r, h4r, h5r, f5,  8, K1B, data[ 15 ] );
	subRound( h5r, h1r, h2r, h3r, h4r, f5, 11, K1B, data[  8 ] );
	subRound( h4r, h5r, h1r, h2r, h3r, f5, 14, K1B, data[  1 ] );
	subRound( h3r, h4r, h5r, h1r, h2r, f5, 14, K1B, data[ 10 ] );
	subRound( h2r, h3r, h4r, h5r, h1r, f5, 12, K1B, data[  3 ] );
	subRound( h1r, h2r, h3r, h4r, h5r, f5,  6, K1B, data[ 12 ] );

	subRound( h5r, h1r, h2r, h3r, h4r, f4,  9, K2B, data[  6 ] );
	subRound( h4r, h5r, h1r, h2r, h3r, f4, 13, K2B, data[ 11 ] );
	subRound( h3r, h4r, h5r, h1r, h2r, f4, 15, K2B, data[  3 ] );
	subRound( h2r, h3r, h4r, h5r, h1r, f4,  7, K2B, data[  7 ] );
	subRound( h1r, h2r, h3r, h4r, h5r, f4, 12, K2B, data[  0 ] );
	subRound( h5r, h1r, h2r, h3r, h4r, f4,  8, K2B, data[ 13 ] );
	subRound( h4r, h5r, h1r, h2r, h3r, f4,  9, K2B, data[  5 ] );
	subRound( h3r, h4r, h5r, h1r, h2r, f4, 11, K2B, data[ 10 ] );
	subRound( h2r, h3r, h4r, h5r, h1r, f4,  7, K2B, data[ 14 ] );
	subRound( h1r, h2r, h3r, h4r, h5r, f4,  7, K2B, data[ 15 ] );
	subRound( h5r, h1r, h2r, h3r, h4r, f4, 12, K2B, data[  8 ] );
	subRound( h4r, h5r, h1r, h2r, h3r, f4,  7, K2B, data[ 12 ] );
	subRound( h3r, h4r, h5r, h1r, h2r, f4,  6, K2B, data[  4 ] );
	subRound( h2r, h3r, h4r, h5r, h1r, f4, 15, K2B, data[  9 ] );
	subRound( h1r, h2r, h3r, h4r, h5r, f4, 13, K2B, data[  1 ] );
	subRound( h5r, h1r, h2r, h3r, h4r, f4, 11, K2B, data[  2 ] );

	subRound( h4r, h5r, h1r, h2r, h3r, f3,  9, K3B, data[ 15 ] );
	subRound( h3r, h4r, h5r, h1r, h2r, f3,  7, K3B, data[  5 ] );
	subRound( h2r, h3r, h4r, h5r, h1r, f3, 15, K3B, data[  1 ] );
	subRound( h1r, h2r, h3r, h4r, h5r, f3, 11, K3B, data[  3 ] );
	subRound( h5r, h1r, h2r, h3r, h4r, f3,  8, K3B, data[  7 ] );
	subRound( h4r, h5r, h1r, h2r, h3r, f3,  6, K3B, data[ 14 ] );
	subRound( h3r, h4r, h5r, h1r, h2r, f3,  6, K3B, data[  6 ] );
	subRound( h2r, h3r, h4r, h5r, h1r, f3, 14, K3B, data[  9 ] );
	subRound( h1r, h2r, h3r, h4r, h5r, f3, 12, K3B, data[ 11 ] );
	subRound( h5r, h1r, h2r, h3r, h4r, f3, 13, K3B, data[  8 ] );
	subRound( h4r, h5r, h1r, h2r, h3r, f3,  5, K3B, data[ 12 ] );
	subRound( h3r, h4r, h5r, h1r, h2r, f3, 14, K3B, data[  2 ] );
	subRound( h2r, h3r, h4r, h5r, h1r, f3, 13, K3B, data[ 10 ] );
	subRound( h1r, h2r, h3r, h4r, h5r, f3, 13, K3B, data[  0 ] );
	subRound( h5r, h1r, h2r, h3r, h4r, f3,  7, K3B, data[  4 ] );
	subRound( h4r, h5r, h1r, h2r, h3r, f3,  5, K3B, data[ 13 ] );

	subRound( h3r, h4r, h5r, h1r, h2r, f2, 15, K4B, data[  8 ] );
	subRound( h2r, h3r, h4r, h5r, h1r, f2,  5, K4B, data[  6 ] );
	subRound( h1r, h2r, h3r, h4r, h5r, f2,  8, K4B, data[  4 ] );
	subRound( h5r, h1r, h2r, h3r, h4r, f2, 11, K4B, data[  1 ] );
	subRound( h4r, h5r, h1r, h2r, h3r, f2, 14, K4B, data[  3 ] );
	subRound( h3r, h4r, h5r, h1r, h2r, f2, 14, K4B, data[ 11 ] );
	subRound( h2r, h3r, h4r, h5r, h1r, f2,  6, K4B, data[ 15 ] );
	subRound( h1r, h2r, h3r, h4r, h5r, f2, 14, K4B, data[  0 ] );
	subRound( h5r, h1r, h2r, h3r, h4r, f2,  6, K4B, data[  5 ] );
	subRound( h4r, h5r, h1r, h2r, h3r, f2,  9, K4B, data[ 12 ] );
	subRound( h3r, h4r, h5r, h1r, h2r, f2, 12, K4B, data[  2 ] );
	subRound( h2r, h3r, h4r, h5r, h1r, f2,  9, K4B, data[ 13 ] );
	subRound( h1r, h2r, h3r, h4r, h5r, f2, 12, K4B, data[  9 ] );
	subRound( h5r, h1r, h2r, h3r, h4r, f2,  5, K4B, data[  7 ] );
	subRound( h4r, h5r, h1r, h2r, h3r, f2, 15, K4B, data[ 10 ] );
	subRound( h3r, h4r, h5r, h1r, h2r, f2,  8, K4B, data[ 14 ] );

	subRound( h2r, h3r, h4r, h5r, h1r, f1,  8, K5B, data[ 12 ] );
	subRound( h1r, h2r, h3r, h4r, h5r, f1,  5, K5B, data[ 15 ] );
	subRound( h5r, h1r, h2r, h3r, h4r, f1, 12, K5B, data[ 10 ] );
	subRound( h4r, h5r, h1r, h2r, h3r, f1,  9, K5B, data[  4 ] );
	subRound( h3r, h4r, h5r, h1r, h2r, f1, 12, K5B, data[  1 ] );
	subRound( h2r, h3r, h4r, h5r, h1r, f1,  5, K5B, data[  5 ] );
	subRound( h1r, h2r, h3r, h4r, h5r, f1, 14, K5B, data[  8 ] );
	subRound( h5r, h1r, h2r, h3r, h4r, f1,  6, K5B, data[  7 ] );
	subRound( h4r, h5r, h1r, h2r, h3r, f1,  8, K5B, data[  6 ] );
	subRound( h3r, h4r, h5r, h1r, h2r, f1, 13, K5B, data[  2 ] );
	subRound( h2r, h3r, h4r, h5r, h1r, f1,  6, K5B, data[ 13 ] );
	subRound( h1r, h2r, h3r, h4r, h5r, f1,  5, K5B, data[ 14 ] );
	subRound( h5r, h1r, h2r, h3r, h4r, f1, 15, K5B, data[  0 ] );
	subRound( h4r, h5r, h1r, h2r, h3r, f1, 13, K5B, data[  3 ] );
	subRound( h3r, h4r, h5r, h1r, h2r, f1, 11, K5B, data[  9 ] );
	subRound( h2r, h3r, h4r, h5r, h1r, f1, 11, K5B, data[ 11 ] );

	h3l = digest[ 1 ] + h3l + h4r;
	digest[ 1 ] = MASK32( digest[ 2 ] + h4l + h5r );
	digest[ 2 ] = MASK32( digest[ 3 ] + h5l + h1r );
	digest[ 3 ] = MASK32( digest[ 4 ] + h1l + h2r );
	digest[ 4 ] = MASK32( digest[ 0 ] + h2l + h3r );
	digest[ 0 ] = MASK32( h3l );
	}
