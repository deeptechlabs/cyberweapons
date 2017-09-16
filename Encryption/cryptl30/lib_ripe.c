/****************************************************************************
*																			*
*						cryptlib RIPEMD-160 Hash Routines					*
*						  Copyright Peter Gutmann 1996						*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypt.h"
#include "cryptctx.h"
#ifdef INC_ALL
  #include "ripemd.h"
#else
  #include "hash/ripemd.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								RIPEMD160 Self-test Routines						*
*																			*
****************************************************************************/

/* Test the RIPEMD160 output against the test vectors given in the RIPEMD-160
   paper */

void ripemd160HashBuffer( void *hashInfo, BYTE *outBuffer, BYTE *inBuffer,
						  int length, const HASH_STATE hashState );

static const struct {
	const char *data;							/* Data to hash */
	const int length;							/* Length of data */
	const BYTE digest[ RIPEMD160_DIGESTSIZE ];	/* Digest of data */
	} digestValues[] = {
	{ "", 0,
	  { 0x9C, 0x11, 0x85, 0xA5, 0xC5, 0xE9, 0xFC, 0x54,
		0x61, 0x28, 0x08, 0x97, 0x7E, 0xE8, 0xF5, 0x48,
		0xB2, 0x25, 0x8D, 0x31 } },
	{ "a", 1,
	  { 0x0B, 0xDC, 0x9D, 0x2D, 0x25, 0x6B, 0x3E, 0xE9,
		0xDA, 0xAE, 0x34, 0x7B, 0xE6, 0xF4, 0xDC, 0x83,
		0x5A, 0x46, 0x7F, 0xFE } },
	{ "abc", 3,
	  { 0x8E, 0xB2, 0x08, 0xF7, 0xE0, 0x5D, 0x98, 0x7A,
		0x9B, 0x04, 0x4A, 0x8E, 0x98, 0xC6, 0xB0, 0x87,
		0xF1, 0x5A, 0x0B, 0xFC } },
	{ "message digest", 14,
	  { 0x5D, 0x06, 0x89, 0xEF, 0x49, 0xD2, 0xFA, 0xE5,
		0x72, 0xB8, 0x81, 0xB1, 0x23, 0xA8, 0x5F, 0xFA,
		0x21, 0x59, 0x5F, 0x36 } },
	{ "abcdefghijklmnopqrstuvwxyz", 26,
	  { 0xF7, 0x1C, 0x27, 0x10, 0x9C, 0x69, 0x2C, 0x1B,
		0x56, 0xBB, 0xDC, 0xEB, 0x5B, 0x9D, 0x28, 0x65,
		0xB3, 0x70, 0x8D, 0xBC } },
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
	  { 0x12, 0xA0, 0x53, 0x38, 0x4A, 0x9C, 0x0C, 0x88,
		0xE4, 0x05, 0xA0, 0x6C, 0x27, 0xDC, 0xF4, 0x9A,
		0xDA, 0x62, 0xEB, 0x2B } },
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62,
	  { 0xB0, 0xE2, 0x0B, 0x6E, 0x31, 0x16, 0x64, 0x02,
		0x86, 0xED, 0x3A, 0x87, 0xA5, 0x71, 0x30, 0x79,
		0xB2, 0x1F, 0x51, 0x89 } },
	{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80,
	  { 0x9B, 0x75, 0x2E, 0x45, 0x57, 0x3D, 0x4B, 0x39,
		0xF4, 0xDB, 0xD3, 0x32, 0x3C, 0xAB, 0x82, 0xBF,
		0x63, 0x32, 0x6B, 0xFB } },
	{ NULL, 0, { 0 } }
	};

int ripemd160SelfTest( void )
	{
	BYTE digest[ RIPEMD160_DIGESTSIZE ];
	int i;

	/* Test RIPEMD160 against the test vectors from the RIPEMD-160 paper */
	for( i = 0; digestValues[ i ].data != NULL; i++ )
		{
		ripemd160HashBuffer( NULL, digest, ( BYTE * ) digestValues[ i ].data,
							 digestValues[ i ].length, HASH_ALL );
		if( memcmp( digest, digestValues[ i ].digest, RIPEMD160_DIGESTSIZE ) )
			return( CRYPT_ERROR );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Routines							*
*																			*
****************************************************************************/

/* Perform auxiliary init and shutdown actions on an encryption context */

int ripemd160Init( CRYPT_INFO *cryptInfo )
	{
	int status;

	/* Allocate memory for the RIPEMD160 context within the encryption context.
	   Since hash contexts can be reset by deleting the hash values, this may 
	   already have been allocated previously so we only perform the alloc
	   if it's actually required */
	if( cryptInfo->ctxHash.hashInfo == NULL && \
		( status = krnlMemalloc( &cryptInfo->ctxHash.hashInfo,
								 sizeof( RIPEMD160_INFO ) ) ) != CRYPT_OK )
		return( status );
	ripemd160Initial( ( RIPEMD160_INFO * ) cryptInfo->ctxHash.hashInfo );

	return( CRYPT_OK );
	}

int ripemd160End( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	krnlMemfree( &cryptInfo->ctxHash.hashInfo );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							RIPEMD160 Hash Routines							*
*																			*
****************************************************************************/

/* Hash data using RIPEMD160 */

int ripemd160Hash( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RIPEMD160_INFO *ripemd160Info = ( RIPEMD160_INFO * ) cryptInfo->ctxHash.hashInfo;

	/* If we've already called ripemd160Final(), we can't continue */
	if( cryptInfo->ctxHash.done )
		return( CRYPT_ERROR_COMPLETE );

	if( !noBytes )
		{
		BYTE *bufPtr = cryptInfo->ctxHash.hash;
		int i;

		ripemd160Final( ripemd160Info );

		/* Extract the digest into the hash buffer */
		for( i = 0; i < RIPEMD160_DIGESTSIZE / 4; i++ )
			{
			mputLLong( bufPtr, ripemd160Info->digest[ i ] );
			}
		cryptInfo->ctxHash.done = TRUE;
		}
	else
		ripemd160Update( ripemd160Info, buffer, noBytes );

	return( CRYPT_OK );
	}

/* Internal API: Hash a single block of memory without the overhead of
   creating an encryption context */

void ripemd160HashBuffer( void *hashInfo, BYTE *outBuffer, BYTE *inBuffer,
						  int length, const HASH_STATE hashState )
	{
	RIPEMD160_INFO *ripemd160Info = ( RIPEMD160_INFO * ) hashInfo, ripemd160InfoBuffer;
	int i;

	/* If the user has left it up to us to allocate the hash context buffer,
	   use the internal buffer */
	if( ripemd160Info == NULL )
		ripemd160Info = &ripemd160InfoBuffer;

	if( hashState == HASH_ALL )
		{
		ripemd160Initial( ripemd160Info );
		ripemd160Update( ripemd160Info, inBuffer, length );
		ripemd160Final( ripemd160Info );
		for( i = 0; i < RIPEMD160_DIGESTSIZE / 4; i++ )
			{
			mputLLong( outBuffer, ripemd160Info->digest[ i ] );
			}
		}
	else
		switch( hashState )
			{
			case HASH_START:
				ripemd160Initial( ripemd160Info );
				/* Drop through */

			case HASH_CONTINUE:
				ripemd160Update( ripemd160Info, inBuffer, length );
				break;

			case HASH_END:
				if( inBuffer != NULL )
					ripemd160Update( ripemd160Info, inBuffer, length );
				ripemd160Final( ripemd160Info );
				for( i = 0; i < RIPEMD160_DIGESTSIZE / 4; i++ )
					{
					mputLLong( outBuffer, ripemd160Info->digest[ i ] );
					}
			}

	/* Clean up */
	zeroise( &ripemd160InfoBuffer, sizeof( RIPEMD160_INFO ) );
	}
