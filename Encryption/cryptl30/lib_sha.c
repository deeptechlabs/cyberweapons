/****************************************************************************
*																			*
*							cryptlib SHA Hash Routines						*
*						Copyright Peter Gutmann 1992-1997					*
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
  #include "sha.h"
#else
  #include "hash/sha.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								SHA Self-test Routines						*
*																			*
****************************************************************************/

/* Test the SHA output against the test vectors given in FIPS 180 and FIPS
   180-1 (the first three values are the SHA results, the second three are
   the SHA1 results).

   We skip the third test since this takes several seconds to execute, which
   leads to an unacceptable delay in the library startup time */

void shaHashBuffer( void *hashInfo, BYTE *outBuffer, BYTE *inBuffer,
					int length, const HASH_STATE hashState );

static const struct {
	const char *data;						/* Data to hash */
	const int length;						/* Length of data */
	const BYTE digest[ SHA_DIGEST_LENGTH ];	/* Digest of data */
	} digestValues[] = {
	{ "abc", 3,
	  { 0x01, 0x64, 0xB8, 0xA9, 0x14, 0xCD, 0x2A, 0x5E,
		0x74, 0xC4, 0xF7, 0xFF, 0x08, 0x2C, 0x4D, 0x97,
		0xF1, 0xED, 0xF8, 0x80 } },
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
	  { 0xD2, 0x51, 0x6E, 0xE1, 0xAC, 0xFA, 0x5B, 0xAF,
		0x33, 0xDF, 0xC1, 0xC4, 0x71, 0xE4, 0x38, 0x44,
		0x9E, 0xF1, 0x34, 0xC8 } },
/*	{ "aaaaa...", 1000000L,
	  { 0x32, 0x32, 0xAF, 0xFA, 0x48, 0x62, 0x8A, 0x26,
		0x65, 0x3B, 0x5A, 0xAA, 0x44, 0x54, 0x1F, 0xD9,
		0x0D, 0x69, 0x06, 0x03 } }, */
	{ "abc", 3,
	  { 0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A,
		0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C,
		0x9C, 0xD0, 0xD8, 0x9D } },
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
	  { 0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E,
		0xBA, 0xAE, 0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5,
		0xE5, 0x46, 0x70, 0xF1 } },
/*	{ "aaaaa...", 1000000L,
	  { 0x34, 0xAA, 0x97, 0x3C, 0xD4, 0xC4, 0xDA, 0xA4,
		0xF6, 0x1E, 0xEB, 0x2B, 0xDB, 0xAD, 0x27, 0x31,
		0x65, 0x34, 0x01, 0x6F } }, */
	{ NULL, 0, { 0 } }
	};

int shaSelfTest( void )
	{
	SHA_CTX shaInfo;
	BYTE digest[ SHA_DIGEST_LENGTH ];
	int i;

	/* Test SHA against the test vectors given in FIPS 180.  We can't use the
	   internal shaHashBuffer() API for this since it defaults to SHA-1, so
	   we duplicate the functionality of shaHashBuffer() here */
	SHA_Init( &shaInfo );
	SHA_Update( &shaInfo, ( BYTE * ) digestValues[ 0 ].data,
			   digestValues[ 0 ].length );
	SHA_Final( digest, &shaInfo );
	if( memcmp( digest, digestValues[ 0 ].digest, SHA_DIGEST_LENGTH ) )
		return( CRYPT_ERROR );
	SHA_Init( &shaInfo );
	SHA_Update( &shaInfo, ( BYTE * ) digestValues[ 1 ].data,
			   digestValues[ 1 ].length );
	SHA_Final( digest, &shaInfo );
	if( memcmp( digest, digestValues[ 1 ].digest, SHA_DIGEST_LENGTH ) )
		return( CRYPT_ERROR );

	/* Test SHA against values given in FIPS 180-1 */
	for( i = 2; digestValues[ i ].data != NULL; i++ )
		{
		shaHashBuffer( NULL, digest, ( BYTE * ) digestValues[ i ].data,
					   digestValues[ i ].length, HASH_ALL );
		if( memcmp( digest, digestValues[ i ].digest, SHA_DIGEST_LENGTH ) )
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

int shaInit( CRYPT_INFO *cryptInfo )
	{
	int status;

	/* Allocate memory for the SHA context within the encryption context.
	   Since hash contexts can be reset by deleting the hash values, this may 
	   already have been allocated previously so we only perform the alloc
	   if it's actually required */
	if( cryptInfo->ctxHash.hashInfo == NULL && \
		( status = krnlMemalloc( &cryptInfo->ctxHash.hashInfo,
								 sizeof( SHA_CTX ) ) ) != CRYPT_OK )
		return( status );
	SHA1_Init( ( SHA_CTX * ) cryptInfo->ctxHash.hashInfo );

	return( CRYPT_OK );
	}

int shaEnd( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	krnlMemfree( &cryptInfo->ctxHash.hashInfo );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								SHA Hash Routines							*
*																			*
****************************************************************************/

/* Hash data using SHA */

int shaHash( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	SHA_CTX *shaInfo = ( SHA_CTX * ) cryptInfo->ctxHash.hashInfo;

	/* If we've already called shaFinal(), we can't continue */
	if( cryptInfo->ctxHash.done )
		return( CRYPT_ERROR_COMPLETE );

	if( !noBytes )
		{
		SHA1_Final( cryptInfo->ctxHash.hash, shaInfo );
		cryptInfo->ctxHash.done = TRUE;
		}
	else
		SHA1_Update( shaInfo, buffer, noBytes );

	return( CRYPT_OK );
	}

/* Internal API: Hash a single block of memory without the overhead of
   creating an encryption context.  This always uses SHA1 */

void shaHashBuffer( void *hashInfo, BYTE *outBuffer, BYTE *inBuffer,
					int length, const HASH_STATE hashState )
	{
	SHA_CTX *shaInfo = ( SHA_CTX * ) hashInfo, shaInfoBuffer;

	/* If the user has left it up to us to allocate the hash context buffer,
	   use the internal buffer */
	if( shaInfo == NULL )
		shaInfo = &shaInfoBuffer;

	if( hashState == HASH_ALL )
		{
		SHA1_Init( shaInfo );
		SHA1_Update( shaInfo, inBuffer, length );
		SHA1_Final( outBuffer, shaInfo );
		}
	else
		switch( hashState )
			{
			case HASH_START:
				SHA1_Init( shaInfo );
				/* Drop through */

			case HASH_CONTINUE:
				SHA1_Update( shaInfo, inBuffer, length );
				break;

			case HASH_END:
				if( inBuffer != NULL )
					SHA1_Update( shaInfo, inBuffer, length );
				SHA1_Final( outBuffer, shaInfo );
			}

	/* Clean up */
	zeroise( &shaInfoBuffer, sizeof( SHA_CTX ) );
	}
