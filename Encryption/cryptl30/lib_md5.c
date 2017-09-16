/****************************************************************************
*																			*
*							cryptlib MD5 Hash Routines						*
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
  #include "md5.h"
#else
  #include "hash/md5.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								MD5 Self-test Routines						*
*																			*
****************************************************************************/

/* Test the MD5 output against the test vectors given in RFC 1321 */

void md5HashBuffer( void *hashInfo, BYTE *outBuffer, BYTE *inBuffer,
					int length, const HASH_STATE hashState );

static const struct {
	const char *data;						/* Data to hash */
	const int length;						/* Length of data */
	const BYTE digest[ MD5_DIGEST_LENGTH ];	/* Digest of data */
	} digestValues[] = {
	{ "", 0,
	  { 0xD4, 0x1D, 0x8C, 0xD9, 0x8F, 0x00, 0xB2, 0x04,
		0xE9, 0x80, 0x09, 0x98, 0xEC, 0xF8, 0x42, 0x7E } },
	{ "a", 1,
	  { 0x0C, 0xC1, 0x75, 0xB9, 0xC0, 0xF1, 0xB6, 0xA8,
		0x31, 0xC3, 0x99, 0xE2, 0x69, 0x77, 0x26, 0x61 } },
	{ "abc", 3,
	  { 0x90, 0x01, 0x50, 0x98, 0x3C, 0xD2, 0x4F, 0xB0,
		0xD6, 0x96, 0x3F, 0x7D, 0x28, 0xE1, 0x7F, 0x72 } },
	{ "message digest", 14,
	  { 0xF9, 0x6B, 0x69, 0x7D, 0x7C, 0xB7, 0x93, 0x8D,
		0x52, 0x5A, 0x2F, 0x31, 0xAA, 0xF1, 0x61, 0xD0 } },
	{ "abcdefghijklmnopqrstuvwxyz", 26,
	  { 0xC3, 0xFC, 0xD3, 0xD7, 0x61, 0x92, 0xE4, 0x00,
		0x7D, 0xFB, 0x49, 0x6C, 0xCA, 0x67, 0xE1, 0x3B } },
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62,
	  { 0xD1, 0x74, 0xAB, 0x98, 0xD2, 0x77, 0xD9, 0xF5,
		0xA5, 0x61, 0x1C, 0x2C, 0x9F, 0x41, 0x9D, 0x9F } },
	{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80,
	  { 0x57, 0xED, 0xF4, 0xA2, 0x2B, 0xE3, 0xC9, 0x55,
		0xAC, 0x49, 0xDA, 0x2E, 0x21, 0x07, 0xB6, 0x7A } },
	{ NULL, 0, { 0 } }
	};

int md5SelfTest( void )
	{
	BYTE digest[ MD5_DIGEST_LENGTH ];
	int i;

	/* Test MD5 against the test vectors given in RFC 1320 */
	for( i = 0; digestValues[ i ].data != NULL; i++ )
		{
		md5HashBuffer( NULL, digest, ( BYTE * ) digestValues[ i ].data,
					   digestValues[ i ].length, HASH_ALL );
		if( memcmp( digest, digestValues[ i ].digest, MD5_DIGEST_LENGTH ) )
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

int md5Init( CRYPT_INFO *cryptInfo )
	{
	int status;

	/* Allocate memory for the MD5 context within the encryption context.
	   Since hash contexts can be reset by deleting the hash values, this may 
	   already have been allocated previously so we only perform the alloc
	   if it's actually required */
	if( cryptInfo->ctxHash.hashInfo == NULL && \
		( status = krnlMemalloc( &cryptInfo->ctxHash.hashInfo,
								 sizeof( MD5_CTX ) ) ) != CRYPT_OK )
		return( status );
	MD5_Init( ( MD5_CTX * ) cryptInfo->ctxHash.hashInfo );

	return( CRYPT_OK );
	}

int md5End( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	krnlMemfree( &cryptInfo->ctxHash.hashInfo );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								MD5 Hash Routines							*
*																			*
****************************************************************************/

/* Hash data using MD5 */

int md5Hash( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	MD5_CTX *md5Info = ( MD5_CTX * ) cryptInfo->ctxHash.hashInfo;

	/* If we've already called MD5_Final(), we can't continue */
	if( cryptInfo->ctxHash.done )
		return( CRYPT_ERROR_COMPLETE );

	if( !noBytes )
		{
		MD5_Final( cryptInfo->ctxHash.hash, md5Info );
		cryptInfo->ctxHash.done = TRUE;
		}
	else
		MD5_Update( md5Info, buffer, noBytes );

	return( CRYPT_OK );
	}

/* Internal API: Hash a single block of memory without the overhead of
   creating an encryption context */

void md5HashBuffer( void *hashInfo, BYTE *outBuffer, BYTE *inBuffer,
					int length, const HASH_STATE hashState )
	{
	MD5_CTX *md5Info = ( MD5_CTX * ) hashInfo, md5InfoBuffer;

	/* If the user has left it up to us to allocate the hash context buffer,
	   use the internal buffer */
	if( md5Info == NULL )
		md5Info = &md5InfoBuffer;

	if( hashState == HASH_ALL )
		{
		MD5_Init( md5Info );
		MD5_Update( md5Info, inBuffer, length );
		MD5_Final( outBuffer, md5Info );
		}
	else
		switch( hashState )
			{
			case HASH_START:
				MD5_Init( md5Info );
				/* Drop through */

			case HASH_CONTINUE:
				MD5_Update( md5Info, inBuffer, length );
				break;

			case HASH_END:
				if( inBuffer != NULL )
					MD5_Update( md5Info, inBuffer, length );
				MD5_Final( outBuffer, md5Info );
			}

	/* Clean up */
	zeroise( &md5InfoBuffer, sizeof( MD5_CTX ) );
	}
