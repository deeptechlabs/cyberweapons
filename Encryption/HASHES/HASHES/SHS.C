#include <stdio.h>
#include <stdlib.h>
#include <time.h>
 
/* --------------------------------- SHS.H ------------------------------- */
 
/* NIST proposed Secure Hash Standard.
 
   Written 2 September 1992, Peter C. Gutmann.
   This implementation placed in the public domain.

   Modified 1 June 1993, Colin Plumb.
   These modifications placed in the public domain.
 
   Comments to pgut1@cs.aukuni.ac.nz */
 
/* Useful defines/typedefs */
 
typedef unsigned char	BYTE;

/* Since 64-bit machines are the wave of the future, we may as well
   support them directly. */

#ifdef FORCE32

#undef HAVE64

#else	/* !FORCE32 */

#if __alpha	/* Or other machines? */
#define HAVE64 1
typedef unsigned long WORD64;
#endif

#if __GNUC__
#define HAVE64 1
typedef unsigned long long WORD64;
#endif

#endif	/* !FORCE32 */

#ifdef HAVE64
typedef unsigned int WORD32;
#else
typedef unsigned long WORD32;
#endif
 
/* The SHS block size and message digest sizes, in bytes */
 
#define SHS_BLOCKSIZE	64
#define SHS_DIGESTSIZE	20
 
/* The structure for storing SHS info
   data[] is placed first in case offsets of 0 are faster
   for some reason; it's the most often accessed field. */
 
typedef struct {
	WORD32 data[ 16 ];		/* SHS data buffer */
	WORD32 digest[ 5 ];		/* Message digest */
#ifdef HAVE64
	WORD64 count;
#else
	WORD32 countHi, countLo;	/* 64-bit bit count */
#endif
} SHS_INFO;
 
/* Whether the machine is little-endian or not */
 
#undef LITTLE_ENDIAN
 
/* --------------------------------- SHS.C ------------------------------- */
 
/* NIST proposed Secure Hash Standard.
 
   Written 2 September 1992, Peter C. Gutmann.
   This implementation placed in the public domain.

   Modified 1 June 1993, Colin Plumb.
   These modifications placed in the public domain.
 
   Comments to pgut1@cs.aukuni.ac.nz */
 
#include <string.h>
 
/* The SHS f()-functions.  The f1 and f3 functions can be optimized to
   save one boolean operation each - thanks to Rich Schroeppel,
   rcs@cs.arizona.edu for discovering this */
 
/*#define f1(x,y,z)	( (x & y) | (~x & z) )		// Rounds  0-19 */
#define f1(x,y,z)	( z ^ (x & (y ^ z) ) )		/* Rounds  0-19 */
#define f2(x,y,z)	( x ^ y ^ z )			/* Rounds 20-39 */
/*#define f3(x,y,z)	( (x & y) | (x & z) | (y & z) )	// Rounds 40-59 */
#define f3(x,y,z)	( (x & y) | (z & (x | y) ) )	/* Rounds 40-59 */
#define f4(x,y,z)	( x ^ y ^ z )			/* Rounds 60-79 */
 
/* The SHS Mysterious Constants */
 
#define K1	0x5A827999L	/* Rounds  0-19 */
#define K2	0x6ED9EBA1L	/* Rounds 20-39 */
#define K3	0x8F1BBCDCL	/* Rounds 40-59 */
#define K4	0xCA62C1D6L	/* Rounds 60-79 */
 
/* SHS initial values */
 
#define h0init	0x67452301L
#define h1init	0xEFCDAB89L
#define h2init	0x98BADCFEL
#define h3init	0x10325476L
#define h4init	0xC3D2E1F0L

/* Note that it may be necessary to add parentheses to these macros
   if they are to be called with expressions as arguments. */
 
/* 32-bit rotate left - kludged with shifts */
 
#define ROTL(n,X)  ( (X << n) | ( X >> (32-n) ) )
 
/* The initial expanding function */
/* The hash function is defined over an 80-word expanded input array W,
   where the first 16 are copies of the input data, and the remaining 64
   are defined by W[i] = W[i-16] ^ W[i-14] ^ W[i-8] ^ W[i-3].  This
   implementation generates these values on the fly in a circular buffer. */
 
#define expand(W,i) ( W[i & 15] ^= W[i-14 & 15] ^ W[i-8 & 15] ^ W[i-3 & 15] )
 
/* The prototype SHS sub-round */
/* The fundamental sub-round is
   a' = e + ROTL(5,a) + f(b, c, d) + k + data;
   b' = a;
   c' = ROTL(30,b);
   d' = c;
   e' = d;
   ... but this is implemented by unrolling the loop 5 times and renaming
   the variables (e,a,b,c,d) = (a',b',c',d',e') each iteration. */
 
#define subRound(a, b, c, d, e, f, k, data) \
	( e += ROTL(5,a) + f(b, c, d) + k + data, b = ROTL(30, b) )

/* The above code is replicated 20 times for each of the 4 functions,
   using the next 20 values from the W[] array each time. */

/* Initialize the SHS values */
 
void shsInit( SHS_INFO *shsInfo )
{
	/* Set the h-vars to their initial values */
	shsInfo->digest[ 0 ] = h0init;
	shsInfo->digest[ 1 ] = h1init;
	shsInfo->digest[ 2 ] = h2init;
	shsInfo->digest[ 3 ] = h3init;
	shsInfo->digest[ 4 ] = h4init;

	/* Initialise bit count */
#ifdef HAVE64
	shsInfo->count = 0;
#else
	shsInfo->countLo = shsInfo->countHi = 0;
#endif
}
 
/* Perform the SHS transformation.  Note that this code, like MD5, seems to
   break some optimizing compilers due to the complexity of the expressions
   and the size of the basic block.  It may be necessary to split it into
   sections, e.g. based on the four subrounds

   Note that this corrupts the shsInfo->data area */

#ifndef ASM
 
void shsTransform( SHS_INFO *shsInfo )
{
	register WORD32 A, B, C, D, E;

	/* Set up first buffer */
	A = shsInfo->digest[ 0 ];
	B = shsInfo->digest[ 1 ];
	C = shsInfo->digest[ 2 ];
	D = shsInfo->digest[ 3 ];
	E = shsInfo->digest[ 4 ];

	/* Heavy mangling, in 4 sub-rounds of 20 interations each. */
	subRound( A, B, C, D, E, f1, K1, shsInfo->data[ 0] );
	subRound( E, A, B, C, D, f1, K1, shsInfo->data[ 1] );
	subRound( D, E, A, B, C, f1, K1, shsInfo->data[ 2] );
	subRound( C, D, E, A, B, f1, K1, shsInfo->data[ 3] );
	subRound( B, C, D, E, A, f1, K1, shsInfo->data[ 4] );
	subRound( A, B, C, D, E, f1, K1, shsInfo->data[ 5] );
	subRound( E, A, B, C, D, f1, K1, shsInfo->data[ 6] );
	subRound( D, E, A, B, C, f1, K1, shsInfo->data[ 7] );
	subRound( C, D, E, A, B, f1, K1, shsInfo->data[ 8] );
	subRound( B, C, D, E, A, f1, K1, shsInfo->data[ 9] );
	subRound( A, B, C, D, E, f1, K1, shsInfo->data[10] );
	subRound( E, A, B, C, D, f1, K1, shsInfo->data[11] );
	subRound( D, E, A, B, C, f1, K1, shsInfo->data[12] );
	subRound( C, D, E, A, B, f1, K1, shsInfo->data[13] );
	subRound( B, C, D, E, A, f1, K1, shsInfo->data[14] );
	subRound( A, B, C, D, E, f1, K1, shsInfo->data[15] );
	subRound( E, A, B, C, D, f1, K1, expand(shsInfo->data, 16) );
	subRound( D, E, A, B, C, f1, K1, expand(shsInfo->data, 17) );
	subRound( C, D, E, A, B, f1, K1, expand(shsInfo->data, 18) );
	subRound( B, C, D, E, A, f1, K1, expand(shsInfo->data, 19) );

	subRound( A, B, C, D, E, f2, K2, expand(shsInfo->data, 20) );
	subRound( E, A, B, C, D, f2, K2, expand(shsInfo->data, 21) );
	subRound( D, E, A, B, C, f2, K2, expand(shsInfo->data, 22) );
	subRound( C, D, E, A, B, f2, K2, expand(shsInfo->data, 23) );
	subRound( B, C, D, E, A, f2, K2, expand(shsInfo->data, 24) );
	subRound( A, B, C, D, E, f2, K2, expand(shsInfo->data, 25) );
	subRound( E, A, B, C, D, f2, K2, expand(shsInfo->data, 26) );
	subRound( D, E, A, B, C, f2, K2, expand(shsInfo->data, 27) );
	subRound( C, D, E, A, B, f2, K2, expand(shsInfo->data, 28) );
	subRound( B, C, D, E, A, f2, K2, expand(shsInfo->data, 29) );
	subRound( A, B, C, D, E, f2, K2, expand(shsInfo->data, 30) );
	subRound( E, A, B, C, D, f2, K2, expand(shsInfo->data, 31) );
	subRound( D, E, A, B, C, f2, K2, expand(shsInfo->data, 32) );
	subRound( C, D, E, A, B, f2, K2, expand(shsInfo->data, 33) );
	subRound( B, C, D, E, A, f2, K2, expand(shsInfo->data, 34) );
	subRound( A, B, C, D, E, f2, K2, expand(shsInfo->data, 35) );
	subRound( E, A, B, C, D, f2, K2, expand(shsInfo->data, 36) );
	subRound( D, E, A, B, C, f2, K2, expand(shsInfo->data, 37) );
	subRound( C, D, E, A, B, f2, K2, expand(shsInfo->data, 38) );
	subRound( B, C, D, E, A, f2, K2, expand(shsInfo->data, 39) );

	subRound( A, B, C, D, E, f3, K3, expand(shsInfo->data, 40) );
	subRound( E, A, B, C, D, f3, K3, expand(shsInfo->data, 41) );
	subRound( D, E, A, B, C, f3, K3, expand(shsInfo->data, 42) );
	subRound( C, D, E, A, B, f3, K3, expand(shsInfo->data, 43) );
	subRound( B, C, D, E, A, f3, K3, expand(shsInfo->data, 44) );
	subRound( A, B, C, D, E, f3, K3, expand(shsInfo->data, 45) );
	subRound( E, A, B, C, D, f3, K3, expand(shsInfo->data, 46) );
	subRound( D, E, A, B, C, f3, K3, expand(shsInfo->data, 47) );
	subRound( C, D, E, A, B, f3, K3, expand(shsInfo->data, 48) );
	subRound( B, C, D, E, A, f3, K3, expand(shsInfo->data, 49) );
	subRound( A, B, C, D, E, f3, K3, expand(shsInfo->data, 50) );
	subRound( E, A, B, C, D, f3, K3, expand(shsInfo->data, 51) );
	subRound( D, E, A, B, C, f3, K3, expand(shsInfo->data, 52) );
	subRound( C, D, E, A, B, f3, K3, expand(shsInfo->data, 53) );
	subRound( B, C, D, E, A, f3, K3, expand(shsInfo->data, 54) );
	subRound( A, B, C, D, E, f3, K3, expand(shsInfo->data, 55) );
	subRound( E, A, B, C, D, f3, K3, expand(shsInfo->data, 56) );
	subRound( D, E, A, B, C, f3, K3, expand(shsInfo->data, 57) );
	subRound( C, D, E, A, B, f3, K3, expand(shsInfo->data, 58) );
	subRound( B, C, D, E, A, f3, K3, expand(shsInfo->data, 59) );

	subRound( A, B, C, D, E, f4, K4, expand(shsInfo->data, 60) );
	subRound( E, A, B, C, D, f4, K4, expand(shsInfo->data, 61) );
	subRound( D, E, A, B, C, f4, K4, expand(shsInfo->data, 62) );
	subRound( C, D, E, A, B, f4, K4, expand(shsInfo->data, 63) );
	subRound( B, C, D, E, A, f4, K4, expand(shsInfo->data, 64) );
	subRound( A, B, C, D, E, f4, K4, expand(shsInfo->data, 65) );
	subRound( E, A, B, C, D, f4, K4, expand(shsInfo->data, 66) );
	subRound( D, E, A, B, C, f4, K4, expand(shsInfo->data, 67) );
	subRound( C, D, E, A, B, f4, K4, expand(shsInfo->data, 68) );
	subRound( B, C, D, E, A, f4, K4, expand(shsInfo->data, 69) );
	subRound( A, B, C, D, E, f4, K4, expand(shsInfo->data, 70) );
	subRound( E, A, B, C, D, f4, K4, expand(shsInfo->data, 71) );
	subRound( D, E, A, B, C, f4, K4, expand(shsInfo->data, 72) );
	subRound( C, D, E, A, B, f4, K4, expand(shsInfo->data, 73) );
	subRound( B, C, D, E, A, f4, K4, expand(shsInfo->data, 74) );
	subRound( A, B, C, D, E, f4, K4, expand(shsInfo->data, 75) );
	subRound( E, A, B, C, D, f4, K4, expand(shsInfo->data, 76) );
	subRound( D, E, A, B, C, f4, K4, expand(shsInfo->data, 77) );
	subRound( C, D, E, A, B, f4, K4, expand(shsInfo->data, 78) );
	subRound( B, C, D, E, A, f4, K4, expand(shsInfo->data, 79) );

	/* Build message digest */
	shsInfo->digest[ 0 ] += A;
	shsInfo->digest[ 1 ] += B;
	shsInfo->digest[ 2 ] += C;
	shsInfo->digest[ 3 ] += D;
	shsInfo->digest[ 4 ] += E;
}

#endif /* !ASM */

/* When run on a little-endian CPU we need to perform byte reversal on an
   array of longwords.  It is possible to make the code endianness-
   independant by fiddling around with data at the byte level, but this
   makes for very slow code, so we rely on the user to sort out endianness
   at compile time */

#ifdef LITTLE_ENDIAN
 
static void byteReverse( WORD32 *buffer, unsigned byteCount )
{
	WORD32 value;

	byteCount /= sizeof(WORD32);
	while ( byteCount-- ) {
		value = *buffer;
		value = ( value & 0xFF00FF00L ) >> 8  | \
		        ( value & 0x00FF00FFL ) << 8;
		*buffer++ = value << 16  |  value >> 16 ;
	}
}

#else /* !LITTLE_ENDIAN */

#define byteReverse(buf, count)	/* nothing */

#endif /* !LITTLE_ENDIAN */
 
/* Update SHS for a block of data. */
 
void shsUpdate( SHS_INFO *shsInfo, BYTE const *buffer, unsigned count )
{
	WORD32 t;

	/* Update bitcount */

#ifdef HAVE64
	t = ( (WORD32)shsInfo->count >> 3) & 0x3f;
	shsInfo->count += (WORD64)count << 3;
#else
	t = shsInfo->countLo;
	if ( ( shsInfo->countLo = t + ( (WORD32)count << 3) ) < t )
		shsInfo->countHi++;	/* Carry from low to high */
	shsInfo->countHi += count >> 29;

	t = (t >> 3) & 0x3f;	/* Bytes already in shsInfo->data */
#endif

	/* Handle any leading odd-sized chunks */

	if ( t ) {
		BYTE *p = (BYTE *)shsInfo->data + t;

		t = 64-t;
		if (count < t) {
			memcpy( p, buffer, count );
			return;
		}
		memcpy( p, buffer, t );
		byteReverse( shsInfo->data, SHS_BLOCKSIZE );
		shsTransform( shsInfo );
		buffer += t;
		count -= t;
	}

	/* Process data in SHS_BLOCKSIZE chunks */

	while( count >= SHS_BLOCKSIZE ) {
		memcpy( shsInfo->data, buffer, SHS_BLOCKSIZE );
		byteReverse( shsInfo->data, SHS_BLOCKSIZE );
		shsTransform( shsInfo );
		buffer += SHS_BLOCKSIZE;
		count -= SHS_BLOCKSIZE;
	}

	/* Handle any remaining bytes of data. */

	memcpy( shsInfo->data, buffer, count );
}

/* Final wrapup - pad to 64-byte boundary with the bit pattern 
   1 0* (64-bit count of bits processed, MSB-first) */
 
void shsFinal( SHS_INFO *shsInfo )
{
	int count;
	BYTE *p;

	/* Compute number of bytes mod 64 */
#ifdef HAVE64
	count = (int)shsInfo->count;
#else
	count = (int)shsInfo->countLo;
#endif
	count = ( count >> 3 ) & 0x3F;

	/* Set the first char of padding to 0x80.  This is safe since there is
	   always at least one byte free */
	p = (BYTE *)shsInfo->data + count;
	*p++ = 0x80;

	/* Bytes of padding needed to make 64 bytes */
	count = SHS_BLOCKSIZE - 1 - count;

	/* Pad out to 56 mod 64 */
	if( count < 8 ) {
		/* Two lots of padding:  Pad the first block to 64 bytes */
		memset( p, 0, count );
		byteReverse( shsInfo->data, SHS_BLOCKSIZE );
		shsTransform( shsInfo );

		/* Now fill the next block with 56 bytes */
		memset( shsInfo->data, 0, SHS_BLOCKSIZE - 8 );
	} else {
		/* Pad block to 56 bytes */
		memset( p, 0, count - 8 );
	}
	byteReverse( shsInfo->data, SHS_BLOCKSIZE-8 );

	/* Append length in bits and transform */
#if HAVE64
	shsInfo->data[ 14 ] = (WORD32)( shsInfo->count >> 32 );
	shsInfo->data[ 15 ] = (WORD32)shsInfo->count;
#else
	shsInfo->data[ 14 ] = shsInfo->countHi;
	shsInfo->data[ 15 ] = shsInfo->countLo;
#endif

	shsTransform( shsInfo );
}
 
/* ----------------------------- SHS Test code --------------------------- */
 
/* Size of buffer for SHS speed test data */
 
#define TEST_BLOCK_SIZE	( SHS_DIGESTSIZE * 100 )
 
/* Number of bytes of test data to process */
 
#define TEST_BYTES	10000000L
#define TEST_BLOCKS	( TEST_BYTES / TEST_BLOCK_SIZE )
 
void main( void )
{
	SHS_INFO shsInfo;
	BYTE data[ TEST_BLOCK_SIZE ];
	time_t endTime, startTime;
	long i;

	/* Test output data (this is the only test data given in the SHS
	   document, but chances are if it works for this it'll work for
	   anything) */
	shsInit( &shsInfo );
	shsUpdate( &shsInfo, (BYTE *)"abc", 3 );
	shsFinal( &shsInfo );
	if( shsInfo.digest[ 0 ] != 0x0164B8A9L || \
	    shsInfo.digest[ 1 ] != 0x14CD2A5EL || \
	    shsInfo.digest[ 2 ] != 0x74C4F7FFL || \
	    shsInfo.digest[ 3 ] != 0x082C4D97L || \
	    shsInfo.digest[ 4 ] != 0xF1EDF880L )
	{
		puts( "Error in SHS implementation: Test 1 failed" );
		exit( -1 );
	}
	puts("Test 1 passed");

	shsInit( &shsInfo );
	shsUpdate( &shsInfo, (BYTE *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56 );
	shsFinal( &shsInfo );
	if( shsInfo.digest[ 0 ] != 0xD2516EE1L || \
	    shsInfo.digest[ 1 ] != 0xACFA5BAFL || \
	    shsInfo.digest[ 2 ] != 0x33DFC1C4L || \
	    shsInfo.digest[ 3 ] != 0x71E43844L || \
	    shsInfo.digest[ 4 ] != 0x9EF134C8L )
	{
		puts( "Error in SHS implementation: Test 2 failed" );
		exit( -1 );
	}
	puts("Test 2 passed");

	shsInit( &shsInfo );
	for( i = 0; i < 15625; i++ )
		shsUpdate( &shsInfo, (BYTE *)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 64 );
	shsFinal( &shsInfo );
	if( shsInfo.digest[ 0 ] != 0x3232AFFAL || \
	    shsInfo.digest[ 1 ] != 0x48628A26L || \
	    shsInfo.digest[ 2 ] != 0x653B5AAAL || \
	    shsInfo.digest[ 3 ] != 0x44541FD9L || \
	    shsInfo.digest[ 4 ] != 0x0D690603L )
	{
		puts( "Error in SHS implementation: Test 3 failed" );
		exit( -1 );
	}
	puts("Test 3 passed");

	shsInit( &shsInfo );
	for( i = 0; i < 40000; i++ )
		shsUpdate( &shsInfo, (BYTE *)"aaaaaaaaaaaaaaaaaaaaaaaaa", 25 );
	shsFinal( &shsInfo );
	if( shsInfo.digest[ 0 ] != 0x3232AFFAL || \
	    shsInfo.digest[ 1 ] != 0x48628A26L || \
	    shsInfo.digest[ 2 ] != 0x653B5AAAL || \
	    shsInfo.digest[ 3 ] != 0x44541FD9L || \
	    shsInfo.digest[ 4 ] != 0x0D690603L )
	{
		puts( "Error in SHS implementation: Test 4 failed" );
		exit( -1 );
	}
	puts("Test 4 passed");

	shsInit( &shsInfo );
	for( i = 0; i < 8000; i++ )
		shsUpdate( &shsInfo, (BYTE *)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 125 );
	shsFinal( &shsInfo );
	if( shsInfo.digest[ 0 ] != 0x3232AFFAL || \
	    shsInfo.digest[ 1 ] != 0x48628A26L || \
	    shsInfo.digest[ 2 ] != 0x653B5AAAL || \
	    shsInfo.digest[ 3 ] != 0x44541FD9L || \
	    shsInfo.digest[ 4 ] != 0x0D690603L )
	{
		puts( "Error in SHS implementation: Test 5 failed" );
		exit( -1 );
	}
	puts("Test 5 passed");

	/* Now perform time trial, generating MD for 10MB of data.  First,
	   initialize the test data */
	memset( data, 0, TEST_BLOCK_SIZE );

	/* Get start time */
	printf( "SHS time trial.  Processing %ld characters...\n", TEST_BYTES );
	time( &startTime );

	/* Calculate SHS message digest in TEST_BLOCK_SIZE byte blocks */
	shsInit( &shsInfo );
	for( i = TEST_BLOCKS; i > 0; i-- )
		shsUpdate( &shsInfo, data, TEST_BLOCK_SIZE );
	shsFinal( &shsInfo );

	/* Get finish time and time difference */
	time( &endTime );
	printf( "Seconds to process test input: %ld\n", endTime - startTime );
	printf( "Characters processed per second: %ld\n", TEST_BYTES / ( endTime - startTime ) );
}
