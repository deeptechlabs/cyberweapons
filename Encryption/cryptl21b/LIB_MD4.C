/****************************************************************************
*																			*
*							cryptlib MD4 Hash Routines						*
*						Copyright Peter Gutmann 1992-1996					*
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
  #include "md4.h"
#else
  #include "hash/md4.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								MD4 Self-test Routines						*
*																			*
****************************************************************************/

/* Test the MD4 output against the test vectors given in RFC 1320 */

void md4HashBuffer( void *hashInfo, BYTE *outBuffer, BYTE *inBuffer,
					int length, const HASH_STATE hashState );

static struct {
	char *data;						/* Data to hash */
	int length;						/* Length of data */
	BYTE digest[ MD4_DIGESTSIZE ];	/* Digest of data */
	} digestValues[] = {
	{ "", 0,
	  { 0x31, 0xD6, 0xCF, 0xE0, 0xD1, 0x6A, 0xE9, 0x31,
		0xB7, 0x3C, 0x59, 0xD7, 0xE0, 0xC0, 0x89, 0xC0 } },
	{ "a", 1,
	  { 0xBD, 0xE5, 0x2C, 0xB3, 0x1D, 0xE3, 0x3E, 0x46,
		0x24, 0x5E, 0x05, 0xFB, 0xDB, 0xD6, 0xFB, 0x24 } },
	{ "abc", 3,
	  { 0xA4, 0x48, 0x01, 0x7A, 0xAF, 0x21, 0xD8, 0x52,
		0x5F, 0xC1, 0x0A, 0xE8, 0x7A, 0xA6, 0x72, 0x9D } },
	{ "message digest", 14,
	  { 0xD9, 0x13, 0x0A, 0x81, 0x64, 0x54, 0x9F, 0xE8,
		0x18, 0x87, 0x48, 0x06, 0xE1, 0xC7, 0x01, 0x4B } },
	{ "abcdefghijklmnopqrstuvwxyz", 26,
	  { 0xD7, 0x9E, 0x1C, 0x30, 0x8A, 0xA5, 0xBB, 0xCD,
		0xEE, 0xA8, 0xED, 0x63, 0xDF, 0x41, 0x2D, 0xA9 } },
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62,
	  { 0x04, 0x3F, 0x85, 0x82, 0xF2, 0x41, 0xDB, 0x35,
		0x1C, 0xE6, 0x27, 0xE1, 0x53, 0xE7, 0xF0, 0xE4 } },
	{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80,
	  { 0xE3, 0x3B, 0x4D, 0xDC, 0x9C, 0x38, 0xF2, 0x19,
		0x9C, 0x3E, 0x7B, 0x16, 0x4F, 0xCC, 0x05, 0x36 } },
	{ NULL, 0, { 0 } }
	};

int md4SelfTest( void )
	{
	BYTE digest[ MD4_DIGESTSIZE ];
	int i;

	/* Test MD4 against the test vectors given in RFC 1320 */
	for( i = 0; digestValues[ i ].data != NULL; i++ )
		{
		md4HashBuffer( NULL, digest, ( BYTE * ) digestValues[ i ].data,
					   digestValues[ i ].length, HASH_ALL );
		if( memcmp( digest, digestValues[ i ].digest, MD4_DIGESTSIZE ) )
			return( CRYPT_SELFTEST );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Routines							*
*																			*
****************************************************************************/

/* Perform auxiliary init and shutdown actions on an encryption context */

int md4Init( CRYPT_INFO *cryptInfo, const void *cryptInfoEx )
	{
	int status;

	UNUSED( cryptInfoEx );

	/* Allocate memory for the MD4 context within the encryption context */
	if( cryptInfo->ctxHash.hashInfo != NULL )
		return( CRYPT_INITED );
	if( ( status = krnlMemalloc( &cryptInfo->ctxHash.hashInfo,
								 sizeof( MD4_INFO ) ) ) != CRYPT_OK )
		return( status );
	md4Initial( ( MD4_INFO * ) cryptInfo->ctxHash.hashInfo );

	return( CRYPT_OK );
	}

int md4End( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	krnlMemfree( &cryptInfo->ctxHash.hashInfo );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								MD4 Hash Routines							*
*																			*
****************************************************************************/

/* Hash data using MD4 */

int md4Hash( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	MD4_INFO *md4Info = ( MD4_INFO * ) cryptInfo->ctxHash.hashInfo;

	/* If we've already called md4Final(), we can't continue */
	if( cryptInfo->ctxHash.done )
		return( CRYPT_COMPLETE );

	if( !noBytes )
		{
		BYTE *bufPtr = cryptInfo->ctxHash.hash;
		int i;

		md4Final( md4Info );
		for( i = 0; i < MD4_DIGESTSIZE / 4; i++ )
			{
			mputLLong( bufPtr, md4Info->digest[ i ] );
			}
		cryptInfo->ctxHash.done = TRUE;
		}
	else
		md4Update( md4Info, buffer, noBytes );

	return( CRYPT_OK );
	}

/* Internal API: Hash a single block of memory without the overhead of
   creating an encryption context */

void md4HashBuffer( void *hashInfo, BYTE *outBuffer, BYTE *inBuffer,
					int length, const HASH_STATE hashState )
	{
	MD4_INFO *md4Info = ( MD4_INFO * ) hashInfo, md4InfoBuffer;
	int i;

	/* If the user has left it up to us to allocate the hash context buffer,
	   use the internal buffer */
	if( md4Info == NULL )
		md4Info = &md4InfoBuffer;

	if( hashState == HASH_ALL )
		{
		md4Initial( md4Info );
		md4Update( md4Info, inBuffer, length );
		md4Final( md4Info );
		for( i = 0; i < MD4_DIGESTSIZE / 4; i++ )
			{
			mputLLong( outBuffer, md4Info->digest[ i ] );
			}
		}
	else
		switch( hashState )
			{
			case HASH_START:
				md4Initial( md4Info );
				/* Drop through */

			case HASH_CONTINUE:
				md4Update( md4Info, inBuffer, length );
				break;

			case HASH_END:
				md4Update( md4Info, inBuffer, length );
				md4Final( md4Info );
				for( i = 0; i < MD4_DIGESTSIZE / 4; i++ )
					{
					mputLLong( outBuffer, md4Info->digest[ i ] );
					}
			}

	/* Clean up */
	zeroise( &md4InfoBuffer, sizeof( MD4_INFO ) );
	}
