/****************************************************************************
*																			*
*							cryptlib MD2 Hash Routines						*
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
  #include "md2.h"
#else
  #include "hash/md2.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								MD2 Self-test Routines						*
*																			*
****************************************************************************/

/* Test the MD2 output against the test vectors given in RFC 1319 */

void md2HashBuffer( void *hashInfo, BYTE *outBuffer, BYTE *inBuffer,
					int length, const HASH_STATE hashState );

static struct {
	char *data;						/* Data to hash */
	int length;						/* Length of data */
	BYTE digest[ MD2_DIGESTSIZE ];	/* Digest of data */
	} digestValues[] = {
	{ "", 0,
	  { 0x83, 0x50, 0xE5, 0xA3, 0xE2, 0x4C, 0x15, 0x3D,
		0xF2, 0x27, 0x5C, 0x9F, 0x80, 0x69, 0x27, 0x73 } },
	{ "a", 1,
	  { 0x32, 0xEC, 0x01, 0xEC, 0x4A, 0x6D, 0xAC, 0x72,
		0xC0, 0xAB, 0x96, 0xFB, 0x34, 0xC0, 0xB5, 0xD1 } },
	{ "abc", 3,
	  { 0xDA, 0x85, 0x3B, 0x0D, 0x3F, 0x88, 0xD9, 0x9B,
		0x30, 0x28, 0x3A, 0x69, 0xE6, 0xDE, 0xD6, 0xBB } },
	{ "message digest", 14,
	  { 0xAB, 0x4F, 0x49, 0x6B, 0xFB, 0x2A, 0x53, 0x0B,
		0x21, 0x9F, 0xF3, 0x30, 0x31, 0xFE, 0x06, 0xB0 } },
	{ "abcdefghijklmnopqrstuvwxyz", 26,
	  { 0x4E, 0x8D, 0xDF, 0xF3, 0x65, 0x02, 0x92, 0xAB,
		0x5A, 0x41, 0x08, 0xC3, 0xAA, 0x47, 0x94, 0x0B } },
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62,
	  { 0xDA, 0x33, 0xDE, 0xF2, 0xA4, 0x2D, 0xF1, 0x39,
		0x75, 0x35, 0x28, 0x46, 0xC3, 0x03, 0x38, 0xCD } },
	{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80,
	  { 0xD5, 0x97, 0x6F, 0x79, 0xD8, 0x3D, 0x3A, 0x0D,
		0xC9, 0x80, 0x6C, 0x3C, 0x66, 0xF3, 0xEF, 0xD8 } },
	{ NULL, 0, { 0 } }
	};

int md2SelfTest( void )
	{
	BYTE digest[ MD2_DIGESTSIZE ];
	int i;

	/* Test MD2 against the test vectors given in RFC 1319 */
	for( i = 0; digestValues[ i ].data != NULL; i++ )
		{
		md2HashBuffer( NULL, digest, ( BYTE * ) digestValues[ i ].data,
					   digestValues[ i ].length, HASH_ALL );
		if( memcmp( digest, digestValues[ i ].digest, MD2_DIGESTSIZE ) )
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

int md2Init( CRYPT_INFO *cryptInfo, const void *cryptInfoEx )
	{
	int status;

	UNUSED( cryptInfoEx );

	/* Allocate memory for the MD2 context within the encryption context */
	if( cryptInfo->ctxHash.hashInfo != NULL )
		return( CRYPT_INITED );
	if( ( status = krnlMemalloc( &cryptInfo->ctxHash.hashInfo,
								 sizeof( MD2_INFO ) ) ) != CRYPT_OK )
		return( status );
	md2Initial( ( MD2_INFO * ) cryptInfo->ctxHash.hashInfo );

	return( CRYPT_OK );
	}

int md2End( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	krnlMemfree( &cryptInfo->ctxHash.hashInfo );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								MD2 Hash Routines							*
*																			*
****************************************************************************/

/* Hash data using MD2 */

int md2Hash( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	MD2_INFO *md2Info = ( MD2_INFO * ) cryptInfo->ctxHash.hashInfo;

	/* If we've already called md2Final(), we can't continue */
	if( cryptInfo->ctxHash.done )
		return( CRYPT_COMPLETE );

	if( !noBytes )
		{
		md2Final( md2Info );
		memcpy( cryptInfo->ctxHash.hash, md2Info->state, MD2_DIGESTSIZE );
		cryptInfo->ctxHash.done = TRUE;
		}
	else
		md2Update( md2Info, buffer, noBytes );

	return( CRYPT_OK );
	}

/* Internal API: Hash a single block of memory without the overhead of
   creating an encryption context */

void md2HashBuffer( void *hashInfo, BYTE *outBuffer, BYTE *inBuffer,
					int length, const HASH_STATE hashState )
	{
	MD2_INFO *md2Info = ( MD2_INFO * ) hashInfo, md2InfoBuffer;

	/* If the user has left it up to us to allocate the hash context buffer,
	   use the internal buffer */
	if( md2Info == NULL )
		md2Info = &md2InfoBuffer;

	if( hashState == HASH_ALL )
		{
		md2Initial( md2Info );
		md2Update( md2Info, inBuffer, length );
		md2Final( md2Info );
		memcpy( outBuffer, md2Info->state, MD2_DIGESTSIZE );
		}
	else
		switch( hashState )
			{
			case HASH_START:
				md2Initial( md2Info );
				/* Drop through */

			case HASH_CONTINUE:
				md2Update( md2Info, inBuffer, length );
				break;

			case HASH_END:
				md2Update( md2Info, inBuffer, length );
				md2Final( md2Info );
				memcpy( outBuffer, md2Info->state, MD2_DIGESTSIZE );
			}

	/* Clean up */
	zeroise( &md2InfoBuffer, sizeof( MD2_INFO ) );
	}
