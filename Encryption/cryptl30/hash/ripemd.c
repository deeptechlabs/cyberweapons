/****************************************************************************
*																			*
*					   RIPEMD-160 Message Digest Algorithm 					*
*						Copyright Peter Gutmann 1992-1996					*
*																			*
****************************************************************************/

#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "clink.h"
  #include "ripemd.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "clink.h"
  #include "ripemd.h"
#else
  #include "crypt.h"
  #include "hash/clink.h"
  #include "hash/ripemd.h"
#endif /* Compiler-specific includes */

/* RIPEMD-160 initial values */

#define h0init	0x67452301UL
#define h1init	0xEFCDAB89UL
#define h2init	0x98BADCFEUL
#define h3init	0x10325476UL
#define h4init	0xC3D2E1F0UL

/****************************************************************************
*																			*
*						RIPEMD-160 Support Routines							*
*																			*
****************************************************************************/

/* Initialize the RIP#60 values */

void ripemd160Initial( RIPEMD160_INFO *ripemd160Info )
	{
	/* Clear all fields */
	memset( ripemd160Info, 0, sizeof( RIPEMD160_INFO ) );

	/* Set the h-vars to their initial values */
	ripemd160Info->digest[ 0 ] = h0init;
	ripemd160Info->digest[ 1 ] = h1init;
	ripemd160Info->digest[ 2 ] = h2init;
	ripemd160Info->digest[ 3 ] = h3init;
	ripemd160Info->digest[ 4 ] = h4init;
	}

/* Update RIPEMD160 for a block of data */

void ripemd160Update( RIPEMD160_INFO *ripemd160Info, BYTE *buffer, int count )
	{
	LONG tmp;
	int dataCount;

	/* Update bitcount */
	tmp = ripemd160Info->countLo;
	if ( ( ripemd160Info->countLo = tmp + ( ( LONG ) count << 3 ) ) < tmp )
		ripemd160Info->countHi++;				/* Carry from low to high */
	ripemd160Info->countHi += count >> 29;

	/* Get count of bytes already in data */
	dataCount = ( int ) ( tmp >> 3 ) & 0x3F;

	/* Handle any leading odd-sized chunks */
	if( dataCount )
		{
#ifdef _BIG_WORDS
		BYTE *p = ripemd160Info->dataBuffer + dataCount;
#else
		BYTE *p = ( BYTE * ) ripemd160Info->data + dataCount;
#endif /* _BIG_WORDS */

		dataCount = RIPEMD160_DATASIZE - dataCount;
		if( count < dataCount )
			{
			memcpy( p, buffer, count );
			return;
			}
		memcpy( p, buffer, dataCount );
#ifdef _BIG_WORDS
		copyToLLong( ripemd160Info->data, ripemd160Info->dataBuffer, RIPEMD160_DATASIZE );
#else
		littleToBigLong( ripemd160Info->data, RIPEMD160_DATASIZE );
#endif /* _BIG_WORDS */
		RIPEMD160Transform( ripemd160Info->digest, ripemd160Info->data );
		buffer += dataCount;
		count -= dataCount;
		}

	/* Process data in RIPEMD160_DATASIZE chunks */
	while( count >= RIPEMD160_DATASIZE )
		{
#if defined( _BIG_WORDS )
		memcpy( ripemd160Info->dataBuffer, buffer, RIPEMD160_DATASIZE );
		copyToLLong( ripemd160Info->data, ripemd160Info->dataBuffer, RIPEMD160_DATASIZE );
		RIPEMD160Transform( ripemd160Info->digest, ripemd160Info->data );
#elif defined( DATA_BIGENDIAN )
		memcpy( ripemd160Info->data, buffer, RIPEMD160_DATASIZE );
		littleToBigLong( ripemd160Info->data, RIPEMD160_DATASIZE );
		RIPEMD160Transform( ripemd160Info->digest, ripemd160Info->data );
#else
		RIPEMD160Transform( ripemd160Info->digest, ( LONG * ) buffer );
#endif /* Endianness and word-size dependant data moves */
		buffer += RIPEMD160_DATASIZE;
		count -= RIPEMD160_DATASIZE;
		}

	/* Handle any remaining bytes of data. */
#ifdef _BIG_WORDS
	memcpy( ripemd160Info->dataBuffer, buffer, count );
#else
	memcpy( ripemd160Info->data, buffer, count );
#endif /* _BIG_WORDS */
	}

/* Final wrapup - pad to RIPEMD160_DATASIZE-byte boundary with the bit
   pattern 1 0* (64-bit count of bits processed, MSB-first) */

void ripemd160Final( RIPEMD160_INFO *ripemd160Info )
	{
	int count;
	BYTE *dataPtr;

	/* Compute number of bytes mod 64 */
	count = ( int ) ripemd160Info->countLo;
	count = ( count >> 3 ) & 0x3F;

	/* Set the first char of padding to 0x80.  This is safe since there is
	   always at least one byte free */
#ifdef _BIG_WORDS
	dataPtr = ripemd160Info->dataBuffer + count;
#else
	dataPtr = ( BYTE * ) ripemd160Info->data + count;
#endif /* _BIG_WORDS */
	*dataPtr++ = 0x80;

	/* Bytes of padding needed to make 64 bytes */
	count = RIPEMD160_DATASIZE - 1 - count;

	/* Pad out to 56 mod 64 */
	if( count < 8 )
		{
		/* Two lots of padding:  Pad the first block to 64 bytes */
		memset( dataPtr, 0, count );
#ifdef _BIG_WORDS
		copyToLLong( ripemd160Info->data, ripemd160Info->dataBuffer, RIPEMD160_DATASIZE );
#else
		littleToBigLong( ripemd160Info->data, RIPEMD160_DATASIZE );
#endif /* _BIG_WORDS */
		RIPEMD160Transform( ripemd160Info->digest, ripemd160Info->data );

		/* Now fill the next block with 56 bytes */
#ifdef _BIG_WORDS
		memset( ripemd160Info->dataBuffer, 0, RIPEMD160_DATASIZE - 8 );
#else
		memset( ripemd160Info->data, 0, RIPEMD160_DATASIZE - 8 );
#endif /* _BIG_WORDS */
		}
	else
		/* Pad block to 56 bytes */
		memset( dataPtr, 0, count - 8 );
#ifdef _BIG_WORDS
	copyToLLong( ripemd160Info->data, ripemd160Info->dataBuffer, RIPEMD160_DATASIZE );
#endif /* _BIG_WORDS */

	/* Append length in bits and transform */
	ripemd160Info->data[ 14 ] = ripemd160Info->countLo;
	ripemd160Info->data[ 15 ] = ripemd160Info->countHi;

#ifndef _BIG_WORDS
	littleToBigLong( ripemd160Info->data, RIPEMD160_DATASIZE - 8 );
#endif /* _BIG_WORDS */
	RIPEMD160Transform( ripemd160Info->digest, ripemd160Info->data );

	ripemd160Info->done = TRUE;
	}
