/****************************************************************************
*																			*
*						cryptlib Randomness Management Code					*
*						 Copyright Peter Gutmann 1995-1999					*
*																			*
****************************************************************************/

/* This module and the misc/rnd*.c modules represent the cryptlib
   continuously seeded pseudorandom number generator (CSPRNG) as described in
   my 1998 Usenix Security Symposium paper "The generation of random numbers
   for cryptographic purposes".

   The CSPRNG code is copyright Peter Gutmann (and various others) 1996,
   1997, 1998, 1999, all rights reserved.  Redistribution of the CSPRNG
   modules and use in source and binary forms, with or without modification,
   are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice
	  and this permission notice in its entirety.

   2. Redistributions in binary form must reproduce the copyright notice in
	  the documentation and/or other materials provided with the distribution.

  3. A copy of any bugfixes or enhancements made must be provided to the
	 author, <pgut001@cs.auckland.ac.nz> to allow them to be added to the
	 baseline version of the code.

  ALTERNATIVELY, the code may be distributed under the terms of the GNU
  General Public License, version 2 or any later version published by the
  Free Software Foundation, in which case the provisions of the GNU GPL are
  required INSTEAD OF the above restrictions.

  Although not required under the terms of the GPL, it would still be nice if
  you could make any changes available to the author to allow a consistent
  code base to be maintained */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "bn.h"
  #include "sha.h"
  #include "random.h"
#else
  #include "bn/bn.h"
  #include "hash/sha.h"
  #include "misc/random.h"
#endif /* Compiler-specific includes */

/* The EAY SHA code doesn't make the SHA compression function externally
   accessible, so we use RIPEMD-160 for now */

#define SHA1Transform( hash, data )	RIPEMD160Transform( hash, data )
#ifdef __WIN32__
  void __cdecl RIPEMD160Transform( LONG *H, const LONG *X );
#else
  void RIPEMD160Transform( LONG *H, const LONG *X );
#endif /* __WIN32__ */

/* If we don't have a defined randomness interface, complain */

#if !( defined( __MSDOS__ ) || defined( __WIN16__ ) || defined( __WIN32__ ) || \
	   defined( __OS2__ ) || defined( __BEOS__ ) || defined( __UNIX__ ) || \
	   defined( __MAC__ ) || defined( __TANDEM__ ) )
  #error You need to create OS-specific randomness-gathering functions in misc/rnd<os_name>.c
#endif /* Various OS-specific defines */

/* The allocated size if the randomness pool, which allows for the overflow
   created by the fact that the SHA blocksize isn't any useful multiple of a
   power of 2 */

#define RANDOMPOOL_ALLOCSIZE	( ( RANDOMPOOL_SIZE + SHA_DIGEST_LENGTH - 1 ) / \
									SHA_DIGEST_LENGTH ) * SHA_DIGEST_LENGTH

/* The random data information */

RANDOM_INFO randomInfo;

/* Since the slow poll executes in the background, it can cause
   synchronisation problems when a background slow poll is in progress while
   other threads access the random data pool.  We therefore use locking
   variables to serialise access to the random pool */

DECLARE_LOCKING_VARS( randPool )
DECLARE_LOCKING_VARS( randGen )

/****************************************************************************
*																			*
*						Random Pool Management Routines						*
*																			*
****************************************************************************/

/* Initialise a random pool */

static void initRandomPool( RANDOM_INFO *randomInfo, BYTE *randomPool )
	{
	memset( randomInfo, 0, sizeof( RANDOM_INFO ) );
	randomInfo->randomPool = randomPool;
	randomInfo->randomWritePos = randomInfo->randomReadPos = 0;
	randomInfo->randomStatus = CRYPT_NORANDOM;
	}

/* Stir up the data in the random buffer.  Given a circular buffer of length
   n bytes, we use SHA to hash the 20 bytes at n with the 64 bytes at
   n - 20...n - 1 and n + 20...n + 64 as the input data block.  Then we move
   on to the next 20 bytes until the entire buffer has been mixed.  We don't
   bother with SHA data endianess-adjustment since we're not really
   interested in the final output values, as long as they're well-mixed */

void mixRandomPool( RANDOM_INFO *randomPool )
	{
#ifdef _BIG_WORDS
	LONG dataBuffer[ SHA_CBLOCK / 4 ];
#else
	BYTE dataBuffer[ SHA_CBLOCK ];
#endif /* BIG_WORDS */
	int hashIndex;

	/* If we're modifying the global pool, lock the resource while we modify
	   it */
	if( randomPool == &randomInfo )
		lockGlobalResource( randPool );

	/* Stir up the entire pool */
#ifdef _BIG_WORDS
	for( hashIndex = 0; hashIndex < RANDOMPOOL_SIZE; hashIndex += SHA_DIGEST_LENGTH )
		{
		LONG digestLong[ SHA_DIGEST_LENGTH / 4 ];
		BYTE *digestPtr;
		int dataBufIndex, poolIndex = hashIndex - SHA_DIGEST_LENGTH, i;

		/* If we're at the start of the pool, the first block we hash is at
		   the end of the pool */
		if( !hashIndex )
			poolIndex = RANDOMPOOL_SIZE - SHA_DIGEST_LENGTH;

		/* Copy SHA_DIGEST_LENGTH bytes from position n - 19...n - 1 in the
		   circular pool into the hash data buffer */
		for( dataBufIndex = 0; dataBufIndex < SHA_DIGEST_LENGTH; dataBufIndex += 4 )
			dataBuffer[ dataBufIndex / 4 ] = \
				( ( LONG ) randomPool->randomPool[ poolIndex++ % RANDOMPOOL_SIZE ] << 24 ) | \
				( ( LONG ) randomPool->randomPool[ poolIndex++ % RANDOMPOOL_SIZE ] << 16 ) | \
				( ( LONG ) randomPool->randomPool[ poolIndex++ % RANDOMPOOL_SIZE ] << 8 ) | \
				( ( LONG ) randomPool->randomPool[ poolIndex++ % RANDOMPOOL_SIZE ] );

		/* Copy SHA_CBLOCK - SHA_DIGEST_LENGTH bytes from position n + 20...
		   n + 64 from the circular pool into the hash data buffer */
		poolIndex = ( hashIndex + SHA_DIGEST_LENGTH ) % RANDOMPOOL_SIZE;
		while( dataBufIndex < SHA_CBLOCK )
			{
			dataBuffer[ dataBufIndex / 4 ] = \
				( ( LONG ) randomPool->randomPool[ poolIndex++ % RANDOMPOOL_SIZE ] << 24 ) | \
				( ( LONG ) randomPool->randomPool[ poolIndex++ % RANDOMPOOL_SIZE ] << 16 ) | \
				( ( LONG ) randomPool->randomPool[ poolIndex++ % RANDOMPOOL_SIZE ] << 8 ) | \
				( ( LONG ) randomPool->randomPool[ poolIndex++ % RANDOMPOOL_SIZE ] );
			dataBufIndex += 4;
			}

		/* Hash the data at position n...n + 19 in the circular pool using
		   the surrounding data extracted previously */
		digestPtr = randomPool->randomPool + hashIndex;
		for( i = 0; i < SHA_DIGEST_LENGTH / 4; i++ )
			{
			digestLong[ i ] = mgetBLong( digestPtr );
			}
		SHA1Transform( digestLong, dataBuffer );
		digestPtr = randomPool->randomPool + hashIndex;
		for( i = 0; i < SHA_DIGEST_LENGTH / 4; i++ )
			{
			mputBLong( digestPtr, digestLong[ i ] );
			}
		}
#else
	for( hashIndex = 0; hashIndex < RANDOMPOOL_SIZE; hashIndex += SHA_DIGEST_LENGTH )
		{
		int dataBufIndex, poolIndex = hashIndex - SHA_DIGEST_LENGTH;

		/* If we're at the start of the pool, the first block we hash is at
		   the end of the pool */
		if( !hashIndex )
			poolIndex = RANDOMPOOL_SIZE - SHA_DIGEST_LENGTH;

		/* Copy SHA_DIGEST_LENGTH bytes from position n - 19...n - 1 in the
		   circular pool into the hash data buffer */
		for( dataBufIndex = 0; dataBufIndex < SHA_DIGEST_LENGTH; dataBufIndex++ )
			dataBuffer[ dataBufIndex ] = \
						randomPool->randomPool[ poolIndex++ % RANDOMPOOL_SIZE ];

		/* Copy SHA_CBLOCK - SHA_DIGEST_LENGTH bytes from position n + 20...
		   n + 64 from the circular pool into the hash data buffer */
		poolIndex = ( hashIndex + SHA_DIGEST_LENGTH ) % RANDOMPOOL_SIZE;
		while( dataBufIndex < SHA_CBLOCK )
			dataBuffer[ dataBufIndex++ ] = \
						randomPool->randomPool[ poolIndex++ % RANDOMPOOL_SIZE ];

		/* Hash the data at position n...n + 19 in the circular pool using
		   the surrounding data extracted previously */
		SHA1Transform( ( LONG * ) ( randomPool->randomPool + hashIndex ),
					   ( LONG * ) dataBuffer );
		}
#endif /* _BIG_WORDS */
	zeroise( dataBuffer, sizeof( dataBuffer ) );

	/* We're back to reading and writing from the start of the pool */
	randomPool->randomReadPos = randomPool->randomWritePos = 0;

	/* If we're modifying the global pool, unlock the resource to let other
	   threads at it */
	if( randomPool == &randomInfo )
		unlockGlobalResource( randPool );
	}

/* Add a block of data to the random buffer */

void addRandomBuffer( BYTE *buffer, int count )
	{
	lockGlobalResource( randPool );
	while( count-- )
		addRandomByte( *buffer++ );
	unlockGlobalResource( randPool );
	}

/* Extract random data from the randomness pool in such a way that compromise
   of the data doesn't compromise the pool, and vice versa.  This is done by
   performing the (one-way) pool mixing operation on the pool, and on a
   transformed version of the pool which becomes the key.  No pool data ever
   leaves the pool */

static void getKeyFromPool( BYTE *buffer, const int bufSize )
	{
	RANDOM_INFO keyRandomInfo;
	BYTE keyPool[ RANDOMPOOL_ALLOCSIZE ];
	long *keyPoolLong = ( long * ) keyPool;
	int i;

	/* From now on we need exlusive access to the random pool, so we lock the
	   resource.  Note that the function calls which follow lock the pool
	   again so the locking capability must be reentrant */
	lockGlobalResource( randPool );

	/* Prepare to get data from the randomness pool.  Before we do this, we
	   perform a final quick poll of the system to get any last bit of
	   entropy, and mix the entire pool */
	fastPoll();
	mixRandomPool( &randomInfo );

	/* Initialise the copy of the random pool being used to generate the key
	   and copy the main pool information across */
	initRandomPool( &keyRandomInfo, keyPool );
	memcpy( keyRandomInfo.randomPool, randomInfo.randomPool, RANDOMPOOL_ALLOCSIZE );

	/* Change the key pool data */
	for( i = 0; i < RANDOMPOOL_SIZE / sizeof( long ); i++ )
		keyPoolLong[ i ] ^= ~1UL;

	/* Mix the original and key pools so neither can be recovered from the
	   other */
	mixRandomPool( &randomInfo );
	mixRandomPool( &keyRandomInfo );

	/* We've finished with the random pool, unlock the resource again */
	unlockGlobalResource( randPool );

	/* Copy the transformed data to the output buffer and zeroise the key
	   pool */
	memcpy( buffer, keyRandomInfo.randomPool, bufSize );
	zeroise( keyPool, sizeof( RANDOMPOOL_ALLOCSIZE ) );
	zeroise( &keyRandomInfo, sizeof( RANDOM_INFO ) );
	}

/****************************************************************************
*																			*
*							Random Pool External Interface					*
*																			*
****************************************************************************/

/* Add random data to the random pool.  We don't try to estimate the amount
   of entroy which we're adding due to the difficulty in doing this - if this
   sort of thing is required it's up to the user to look after it */

CRET cryptAddRandom( const void CPTR randomData, const int randomDataLength )
	{
	BYTE *randomDataPtr = ( BYTE * ) randomData;

	/* Perform basic error checking */
	if( randomData == NULL )
		{
		if( randomDataLength != CRYPT_RANDOM_FASTPOLL && \
			randomDataLength != CRYPT_RANDOM_SLOWPOLL )
			return( CRYPT_BADPARM1 );
		}
	else
		{
		if( randomDataLength <= 0 )
			return( CRYPT_BADPARM2 );
		if( checkBadPtrRead( randomData, randomDataLength ) )
			return( CRYPT_BADPARM1 );
		}

	/* If we're adding data to the pool, add it now and exit */
	if( randomData != NULL )
		{
		addRandomBuffer( randomDataPtr, randomDataLength );

		/* We assume that the externally-added randomness is strong enough to
		   satisfy the requirements for good random data.  Presumably anyone
		   who bothers to use this call will ensure that they're using
		   appropriate data such as the output of a hardware source and not
		   just a call to time() */
		randomInfo.randomStatus = CRYPT_OK;

		return( CRYPT_OK );
		}

	/* Perform either a fast or slow poll for random system data */
	if( randomDataLength == CRYPT_RANDOM_FASTPOLL )
		fastPoll();
	else
		slowPoll();

	return( CRYPT_OK );
	}

/* Force a flush of the polling subsystem before extracting data from the
   randomness pool */

static int flushRandomPoll( void )
	{
	/* Perform a failsafe check - this should only ever be called once per
	   app, because after the first blocking poll the programmer of the
	   calling app will make sure there's a slow poll done earlier on */
	if( cryptStatusError( randomInfo.randomStatus ) )
		cryptAddRandom( NULL, CRYPT_RANDOM_SLOWPOLL );

	/* Make sure any background randomness-gathering process has finished */
	waitforRandomCompletion();

	/* If we still can't get any random information, let the user know */
	if( cryptStatusError( randomInfo.randomStatus ) )
		return( randomInfo.randomStatus );

	return( CRYPT_OK );
	}

/* Generate a block of random data.  This is a low-grade (well, lower-grade
   than the internal high-grade one) generator intended as something more
   secure than rand() but not really suitable for key generation or other
   jobs which are traditionally managed by the library.  The generator works
   by using 32 bytes (256 bits) from the internal generator to key RC4, and
   returning the RC4 output as "random" data.  Because of a number of
   recently-discovered problems in RC4 regarding correlation of initial
   output and key bits, we crank the generator for 128 bytes after keying
   before producing any output bytes */

static unsigned int *rc4state = NULL;
static int rc4x, rc4y;

CRET cryptGetRandom( void CPTR randomData, const int randomDataLength )
	{
	BYTE *randomDataPtr = ( BYTE * ) randomData;
	unsigned int sx, sy;
	int count;

	/* Perform basic error checking */
	if( randomDataLength <= 0 )
		return( CRYPT_BADPARM2 );
	if( checkBadPtrWrite( randomData, randomDataLength ) )
		return( CRYPT_BADPARM1 );

	/* Lock the resource while we modify it */
	lockGlobalResource( randGen );

	/* Allocate the state buffer and initialize the RC4-based generator if
	   necessary */
	if( rc4state == NULL )
		{
		int x, keypos = 0, status;
		unsigned int y = 0;
		BYTE key[ 32 ];

		/* Check that the randomness pool is established so we can use it to
		   initialise the RC4-based generator.  If nothing is set up yet, the
		   following call will start a slow poll which will block until we get
		   enough randomness or the polling fails with a CRYPT_NORANDOM */
		status = flushRandomPoll();
		if( cryptStatusOK( status ) )
			/* Allocate the RC4 state buffer */
			status = krnlMemalloc( ( void ** ) &rc4state, 256 * sizeof( int ) );
		if( cryptStatusError( status ) )
			{
			unlockGlobalResource( randGen );
			return( status );
			}

		/* Get 32 random bytes for the RC4 key */
		getKeyFromPool( key, 32 );

		/* Perform the RC4 key schedule */
		rc4x = rc4y = 0;
		for( x = 0; x < 256; x++ )
			rc4state[ x ] = x;
		for( x = 0; x < 256; x++ )
			{
			sx = rc4state[ x ];
			y += sx + key[ keypos ];
			y &= 0xFF;
			rc4state[ x ] = rc4state[ y ];
			rc4state[ y ] = sx;
			if( ++keypos == 32 )
				keypos = 0;
			}

		/* Initialise the generator and scrub the random key.  This is
		   necessary because the initial RC4 output bytes may contain
		   correlations with the key.  We therefore call ourselves
		   recursively to generate 128 bytes of output, which are also used
		   to zap the random key */
		cryptGetRandom( key, 32 );
		cryptGetRandom( key, 32 );
		cryptGetRandom( key, 32 );
		cryptGetRandom( key, 32 );
		}

	/* Now that the key is set up, run the RC4 generator to produce the
	   required amount of output */
	for( count = 0; count < randomDataLength; count++ )
		{
		rc4x++;
		rc4x &= 0xFF;
		sx = rc4state[ rc4x ];
		rc4y += sx;
		rc4y &= 0xFF;
		sy = rc4state[ rc4y ];
		rc4state[ rc4y ] = sx;
		rc4state[ rc4x ] = sy;
		*randomDataPtr++ = rc4state[ ( unsigned char ) ( sx+sy ) ];
		}

	/* Unlock the resource to let other threads at it */
	unlockGlobalResource( randGen );

	return( CRYPT_OK );
	}

/* Get a block of random data */

int getRandomData( BYTE *buffer, const int length )
	{
	int status;

	/* Make sure the random pool is big enough to return this much data (this
	   is more of a sanity check than anything else) */
	if( length > RANDOMPOOL_SIZE )
		return( CRYPT_BADPARM2 );

	/* Prepare the randomness pool for access */
	status = flushRandomPoll();
	if( cryptStatusError( status ) )
		return( status );

	/* Get the data from the pool */
	getKeyFromPool( buffer, length );

	return( CRYPT_OK );
	}

/* Get a block of nonzero random data.  This somewhat peculiar function is
   required for PKCS #1 padding */

int getNonzeroRandomData( BYTE *buffer, const int length )
	{
	BYTE poolBuffer[ RANDOMPOOL_SIZE ];
	int count = length, status;

	/* Prepare the randomness pool for access */
	status = flushRandomPoll();
	if( cryptStatusError( status ) )
		return( status );

	/* The extraction of data is a little complex, both because the amount of
	   data required can be larger than the pool size and because we don't
	   know how much data we'll need (as a rule of thumb it'll be size +
	   ( size / 256 ) bytes, but in a worst-case situation we could need to
	   draw out megabytes of data), so we copy out an entire pools worth at a
	   time and keep going until we've filled the output requirements */
	while( count )
		{
		int i;

		/* Copy as much as we can from the randomness pool */
		getKeyFromPool( poolBuffer, RANDOMPOOL_SIZE );
		for( i = 0; count && i < RANDOMPOOL_SIZE; i++ )
			if( poolBuffer[ i ] )
				{
				*buffer++ = poolBuffer[ i ];
				count--;
				}
		}
	zeroise( poolBuffer, RANDOMPOOL_SIZE );

	return( CRYPT_OK );
	}

/* Generate a bignum of a specified length, with the given high and low 8
   bits.  'high' is merged into the high 8 bits of the number (set it to 0x80
   to ensure that the number is exactly 'bits' bits long, i.e. 2^(bits-1) <=
   bn < 2^bits), 'low' is merged into the low 8 bits (set it to 1 to ensure
   that the number is odd).  In almost all cases used in cryptlib, 'high' is
   set to 0xC0 and low is set to 0x01.

   We don't need to pagelock the bignum buffer we're using because it's being
   accessed continuously while there's data in it, so there's little chance
   it'll be swapped unless the system is already thrashing */

int generateBignum( BIGNUM *bn, const int noBits, const BYTE high,
					const BYTE low )
	{
	BYTE buffer[ CRYPT_MAX_PKCSIZE ];
	int byteCount = bitsToBytes( noBits ), index = 0, status;
	int noBytes = byteCount;

	/* Clear the return value */
	BN_zero( bn );

	/* Prepare the randomness pool for access */
	status = flushRandomPoll();
	if( cryptStatusError( status ) )
		return( status );

	/* The extraction of data gets a little complicated since the larger
	   bignums are bigger than the randomness pool, so we have to extract
	   data in chunks when generating bignums of more than 2048 bits */
	while( byteCount )
		{
		int randomCount = min( byteCount, RANDOMPOOL_SIZE );

		/* Copy as much as we can from the randomness pool */
		getKeyFromPool( buffer + index, randomCount );
		index += randomCount;
		byteCount -= randomCount;
		}

	/* Merge in the specified low bits, mask off any excess high bits, and
	   merge in the specified high bits.  This is a bit more complex than
	   just masking in the byte values because the bignum may not be a
	   multiple of 8 bytes long */
	buffer[ noBytes - 1 ] |= low;
	buffer[ 0 ] &= 255 >> ( -noBits & 7 );
	buffer[ 0 ] |= high >> ( -noBits & 7 );
	if( noBytes > 1 && ( noBits & 7 ) )
		buffer[ 1 ] |= high << ( noBits & 7 );

	/* Turn the contents of the buffer into a bignum and zeroise the buffer */
	status = ( BN_bin2bn( buffer, noBytes, bn ) == NULL ) ? \
			 CRYPT_NOMEM : CRYPT_OK;
	zeroise( buffer, noBytes );

	return( status );
	}

/* Get a random (but not necessarily unpredictable) nonce.  It doesn't matter
   much what it is, as long as it's completely different for each call.  This
   uses the same mixing mechanism as the main generator, but without the
   entropy gathering phase which makes the main generator unpredictable */

void getNonce( void *nonce, int nonceLength )
	{
	static RANDOM_INFO nonceRandomInfo;
	static BYTE noncePool[ RANDOMPOOL_ALLOCSIZE ];
	static BOOLEAN isInitialised = FALSE;
	BYTE *noncePtr = nonce;

	if( !isInitialised )
		{
		/* Seed the nonce pool with a value which is guaranteed to be
		   different each time (unless the entire program is rerun more than
		   twice a second, which is doubtful) */
		time( ( time_t * ) noncePool );
		isInitialised = TRUE;
		initRandomPool( &nonceRandomInfo, noncePool );
		}

	/* Shuffle the pool and copy it to the output buffer until it's full */
	while( nonceLength > 0 )
		{
		int count = ( nonceLength > RANDOMPOOL_SIZE ) ? \
					RANDOMPOOL_SIZE : nonceLength;

		/* Mix the pool and copy the appropriate amount of data to the output
		   buffer */
		mixRandomPool( &nonceRandomInfo );
		memcpy( noncePtr, nonceRandomInfo.randomPool, count );

		/* Move on to the next block of the output buffer */
		noncePtr += RANDOMPOOL_SIZE;
		nonceLength -= RANDOMPOOL_SIZE;
		}
	}

/* Initialise and shut down the randomness routines */

int initRandom( void )
	{
	BYTE *randomPool;
	int status;

	/* Create the random data pool */
	if( ( status = krnlMemalloc( ( void ** ) &randomPool,
								 RANDOMPOOL_ALLOCSIZE ) ) != CRYPT_OK )
		return( status );
	initRandomPool( &randomInfo, randomPool );

	/* Create any required thread synchronization variables */
	initGlobalResourceLock( randPool );
	initGlobalResourceLock( randGen );

	/* Call any special-case startup functions */
	initRandomPolling();

	return( CRYPT_OK );
	}

void endRandom( void )
	{
	/* Call any special-case shutdown functions */
	endRandomPolling();

	/* Delete thread synchronization vars and random data buffers */
	deleteGlobalResourceLock( randPool );
	deleteGlobalResourceLock( randGen );
	if( rc4state != NULL )
		{
		krnlMemfree( ( void ** ) &rc4state );
		rc4x = rc4y = 0;
		}
	if( randomInfo.randomPool != NULL )
		{
		krnlMemfree( ( void ** ) &randomInfo.randomPool );
		zeroise( &randomInfo, sizeof( RANDOM_INFO ) );
		}
	}
