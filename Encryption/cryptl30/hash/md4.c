/****************************************************************************
*																			*
*						  MD4 Message Digest Algorithm 						*
*						Copyright Peter Gutmann 1992-1996					*
*																			*
****************************************************************************/

#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "md4.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "md4.h"
#else
  #include "crypt.h"
  #include "hash/md4.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*							The MD4 Transformation							*
*																			*
****************************************************************************/

/* MD4 magic numbers. C2 and C3 are from Knuth, Table 2, p.660, "The Art of
   Programming", Volume 2 (Seminumerical Algorithms), Table 2, p.660.
   Second Edition (1981), Addison-Wesley */

#define I0  0x67452301L      /* Initial values for MD buffer */
#define I1  0xEFCDAB89L
#define I2  0x98BADCFEL
#define I3  0x10325476L
#define C2  013240474631L    /* Round 2 constant: sqrt( 2 ) in octal */
#define C3  015666365641L    /* Round 3 constant: sqrt( 3 ) in octal */

/* Round 1 shift amounts */

#define FS1  3
#define FS2  7
#define FS3 11
#define FS4 19

/* Round 2 shift amounts */

#define GS1  3
#define GS2  5
#define GS3  9
#define GS4 13

/* Round 3 shift amounts */

#define HS1  3
#define HS2  9
#define HS3 11
#define HS4 15

/* F, G, and H are basic MD4 functions */

#define	F(X,Y,Z)	( ( X & Y ) | ( ( ~X ) & Z ) )
#define	G(X,Y,Z)	( ( X & Y ) | ( X & Z ) | ( Y & Z ) )
#define H(X,Y,Z)	( X ^ Y ^ Z )

/* ROTATE_LEFT rotates x left n bits */

#define ROTATE_LEFT(x,n)	( ( x << n ) | ( x >> ( 32 - n ) ) )

/* FF, GG, HH, and II transformations for rounds 1, 2, and 3 */

#define FF(A,B,C,D,X,shiftAmt) \
	A += F( B, C, D ) + X; \
	A = MASK32( ROTATE_LEFT( MASK32( A ), shiftAmt ) )

#define GG(A,B,C,D,X,shiftAmt) \
	A += G( B, C,D ) + X + C2; \
	A = MASK32( ROTATE_LEFT( MASK32( A ), shiftAmt ) )

#define HH(A,B,C,D,X,shiftAmt) \
	A += H( B, C,D ) + X + C3; \
	A = MASK32( ROTATE_LEFT( MASK32( A ), shiftAmt ) )

/* Basic MD4 step. Transforms digest based on data */

void MD4Transform( LONG *digest, LONG *data )
	{
	LONG A, B, C, D;

	/* Set up local data */
	A = digest[ 0 ];
	B = digest[ 1 ];
	C = digest[ 2 ];
	D = digest[ 3 ];

	/* Round 1 */
	FF( A, B, C, D, data[  0 ], FS1 );
	FF( D, A, B, C, data[  1 ], FS2 );
	FF( C, D, A, B, data[  2 ], FS3 );
	FF( B, C, D, A, data[  3 ], FS4 );
	FF( A, B, C, D, data[  4 ], FS1 );
	FF( D, A, B, C, data[  5 ], FS2 );
	FF( C, D, A, B, data[  6 ], FS3 );
	FF( B, C, D, A, data[  7 ], FS4 );
	FF( A, B, C, D, data[  8 ], FS1 );
	FF( D, A, B, C, data[  9 ], FS2 );
	FF( C, D, A, B, data[ 10 ], FS3 );
	FF( B, C, D, A, data[ 11 ], FS4 );
	FF( A, B, C, D, data[ 12 ], FS1 );
	FF( D, A, B, C, data[ 13 ], FS2 );
	FF( C, D, A, B, data[ 14 ], FS3 );
	FF( B, C, D, A, data[ 15 ], FS4 );

	/* Round 2 */
	GG( A, B, C, D, data[  0 ], GS1 );
	GG( D, A, B, C, data[  4 ], GS2 );
	GG( C, D, A, B, data[  8 ], GS3 );
	GG( B, C, D, A, data[ 12 ], GS4 );
	GG( A, B, C, D, data[  1 ], GS1 );
	GG( D, A, B, C, data[  5 ], GS2 );
	GG( C, D, A, B, data[  9 ], GS3 );
	GG( B, C, D, A, data[ 13 ], GS4 );
	GG( A, B, C, D, data[  2 ], GS1 );
	GG( D, A, B, C, data[  6 ], GS2 );
	GG( C, D, A, B, data[ 10 ], GS3 );
	GG( B, C, D, A, data[ 14 ], GS4 );
	GG( A, B, C, D, data[  3 ], GS1 );
	GG( D, A, B, C, data[  7 ], GS2 );
	GG( C, D, A, B, data[ 11 ], GS3 );
	GG( B, C, D, A, data[ 15 ], GS4 );

	/* Round 3 */
	HH( A, B, C, D, data[  0 ], HS1 );
	HH( D, A, B, C, data[  8 ], HS2 );
	HH( C, D, A, B, data[  4 ], HS3 );
	HH( B, C, D, A, data[ 12 ], HS4 );
	HH( A, B, C, D, data[  2 ], HS1 );
	HH( D, A, B, C, data[ 10 ], HS2 );
	HH( C, D, A, B, data[  6 ], HS3 );
	HH( B, C, D, A, data[ 14 ], HS4 );
	HH( A, B, C, D, data[  1 ], HS1 );
	HH( D, A, B, C, data[  9 ], HS2 );
	HH( C, D, A, B, data[  5 ], HS3 );
	HH( B, C, D, A, data[ 13 ], HS4 );
	HH( A, B, C, D, data[  3 ], HS1 );
	HH( D, A, B, C, data[ 11 ], HS2 );
	HH( C, D, A, B, data[  7 ], HS3 );
	HH( B, C, D, A, data[ 15 ], HS4 );

	/* Build message digest */
	digest[ 0 ] = MASK32( digest[ 0 ] + A );
	digest[ 1 ] = MASK32( digest[ 1 ] + B );
	digest[ 2 ] = MASK32( digest[ 2 ] + C );
	digest[ 3 ] = MASK32( digest[ 3 ] + D );
	}

/****************************************************************************
*																			*
*							MD4 Support Routines							*
*																			*
****************************************************************************/

/* The routine md4Initial initializes the message-digest context md4Info */

void md4Initial( MD4_INFO *md4Info )
	{
	/* Clear all fields */
	memset( md4Info, 0, sizeof( MD4_INFO ) );

	/* Load magic initialization constants */
	md4Info->digest[ 0 ] = I0;
	md4Info->digest[ 1 ] = I1;
	md4Info->digest[ 2 ] = I2;
	md4Info->digest[ 3 ] = I3;

	/* Initialise bit count */
	md4Info->countLo = md4Info->countHi = 0L;
	}

/* The routine MD4Update updates the message-digest context to account for
   the presence of each of the characters buffer[ 0 .. count-1 ] in the
   message whose digest is being computed */

void md4Update( MD4_INFO *md4Info, BYTE *buffer, int count )
	{
	LONG tmp;
	int dataCount;

	/* Update bitcount */
	tmp = md4Info->countLo;
	if ( ( md4Info->countLo = tmp + ( ( LONG ) count << 3 ) ) < tmp )
		md4Info->countHi++;				/* Carry from low to high */
	md4Info->countHi += count >> 29;

	/* Get count of bytes already in data */
	dataCount = ( int ) ( tmp >> 3 ) & 0x3F;

	/* Handle any leading odd-sized chunks */
	if( dataCount )
		{
#ifdef _BIG_WORDS
		BYTE *p = md4Info->dataBuffer + dataCount;
#else
		BYTE *p = ( BYTE * ) md4Info->data + dataCount;
#endif /* _BIG_WORDS */

		dataCount = MD4_DATASIZE - dataCount;
		if( count < dataCount )
			{
			memcpy( p, buffer, count );
			return;
			}
		memcpy( p, buffer, dataCount );
#ifdef _BIG_WORDS
		copyToLLong( md4Info->data, md4Info->dataBuffer, MD4_DATASIZE );
#else
		littleToBigLong( md4Info->data, MD4_DATASIZE );
#endif /* _BIG_WORDS */
		MD4Transform( md4Info->digest, md4Info->data );
		buffer += dataCount;
		count -= dataCount;
		}

	/* Process data in MD4_DATASIZE chunks */
	while( count >= MD4_DATASIZE )
		{
#if defined( _BIG_WORDS )
		memcpy( md4Info->dataBuffer, buffer, MD4_DATASIZE );
		copyToLLong( md4Info->data, md4Info->dataBuffer, MD4_DATASIZE );
		MD4Transform( md4Info->digest, md4Info->data );
#elif defined( DATA_BIGENDIAN )
		memcpy( md4Info->data, buffer, MD4_DATASIZE );
		littleToBigLong( md4Info->data, MD4_DATASIZE );
		MD4Transform( md4Info->digest, md4Info->data );
#else
		MD4Transform( md4Info->digest, ( LONG * ) buffer );
#endif /* Endianness and word-size dependant data moves */
		buffer += MD4_DATASIZE;
		count -= MD4_DATASIZE;
		}

	/* Handle any remaining bytes of data. */
#ifdef _BIG_WORDS
	memcpy( md4Info->dataBuffer, buffer, count );
#else
	memcpy( md4Info->data, buffer, count );
#endif /* _BIG_WORDS */
	}

/* Final wrapup - pad to MD4_DATASIZE-byte boundary with the bit pattern
   1 0* (64-bit count of bits processed, MSB-first) */

void md4Final( MD4_INFO *md4Info )
	{
	int count;
	BYTE *dataPtr;

	/* Compute number of bytes mod 64 */
	count = ( int ) md4Info->countLo;
	count = ( count >> 3 ) & 0x3F;

	/* Set the first char of padding to 0x80.  This is safe since there is
	   always at least one byte free */
#ifdef _BIG_WORDS
	dataPtr = md4Info->dataBuffer + count;
#else
	dataPtr = ( BYTE * ) md4Info->data + count;
#endif /* _BIG_WORDS */
	*dataPtr++ = 0x80;

	/* Bytes of padding needed to make 64 bytes */
	count = MD4_DATASIZE - 1 - count;

	/* Pad out to 56 mod 64 */
	if( count < 8 )
		{
		/* Two lots of padding:  Pad the first block to 64 bytes */
		memset( dataPtr, 0, count );
#ifdef _BIG_WORDS
		copyToLLong( md4Info->data, md4Info->dataBuffer, MD4_DATASIZE );
#else
		littleToBigLong( md4Info->data, MD4_DATASIZE );
#endif /* _BIG_WORDS */
		MD4Transform( md4Info->digest, md4Info->data );

		/* Now fill the next block with 56 bytes */
#ifdef _BIG_WORDS
		memset( md4Info->dataBuffer, 0, MD4_DATASIZE - 8 );
#else
		memset( md4Info->data, 0, MD4_DATASIZE - 8 );
#endif /* _BIG_WORDS */
		}
	else
		/* Pad block to 56 bytes */
		memset( dataPtr, 0, count - 8 );
#ifdef _BIG_WORDS
	copyToLLong( md4Info->data, md4Info->dataBuffer, MD4_DATASIZE );
#endif /* _BIG_WORDS */

	/* Append length in bits and transform */
	md4Info->data[ 14 ] = md4Info->countLo;
	md4Info->data[ 15 ] = md4Info->countHi;

#ifndef _BIG_WORDS
	littleToBigLong( md4Info->data, MD4_DATASIZE - 8 );
#endif /* _BIG_WORDS */
	MD4Transform( md4Info->digest, md4Info->data );

	md4Info->done = TRUE;
	}
