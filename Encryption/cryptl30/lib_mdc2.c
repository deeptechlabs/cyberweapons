/****************************************************************************
*																			*
*							cryptlib MDC2 Hash Routines						*
*						Copyright Peter Gutmann 1992-1998					*
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
  #include "mdc2.h"
#else
  #include "hash/mdc2.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								MDC2 Self-test Routines						*
*																			*
****************************************************************************/

/* Test the MDC2 output against (???) test vectors */

void mdc2HashBuffer( void *hashInfo, BYTE *outBuffer, BYTE *inBuffer,
					 int length, const HASH_STATE hashState );

static const struct {
	const char *data;							/* Data to hash */
	const int length;							/* Length of data */
	const BYTE digest[ MDC2_DIGEST_LENGTH ];	/* Digest of data */
	} digestValues[] = {
	{ "Now is the time for all ", 24,
	  { 0x42, 0xE5, 0x0C, 0xD2, 0x24, 0xBA, 0xCE, 0xBA,
		0x76, 0x0B, 0xDD, 0x2B, 0xD4, 0x09, 0x28, 0x1A } },
	{ NULL, 0, { 0 } }
	};

int mdc2SelfTest( void )
	{
	MDC2_CTX mdc2Info;
	BYTE digest[ MDC2_DIGEST_LENGTH ];
	int i;

	/* Test MDC2 against the test vectors given in ??? */
	for( i = 0; digestValues[ i ].data != NULL; i++ )
		{
		MDC2_Init( &mdc2Info );
		MDC2_Update( &mdc2Info, ( BYTE * ) digestValues[ i ].data, 
					 digestValues[ i ].length );
		MDC2_Final( digest, &mdc2Info );
		if( memcmp( digest, digestValues[ i ].digest, MDC2_DIGEST_LENGTH ) )
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

int mdc2Init( CRYPT_INFO *cryptInfo )
	{
	int status;

	/* Allocate memory for the MDC2 context within the encryption context.
	   Since MAC contexts can be reset by deleting the MAC values, this may 
	   already have been allocated previously so we only perform the alloc
	   if it's actually required */
	if( cryptInfo->ctxHash.hashInfo == NULL && \
		( status = krnlMemalloc( &cryptInfo->ctxHash.hashInfo,
								 sizeof( MDC2_CTX ) ) ) != CRYPT_OK )
		return( status );
	MDC2_Init( ( MDC2_CTX * ) cryptInfo->ctxHash.hashInfo );

	return( CRYPT_OK );
	}

int mdc2End( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	krnlMemfree( &cryptInfo->ctxHash.hashInfo );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								MDC2 Hash Routines							*
*																			*
****************************************************************************/

/* Hash data using MDC2 */

int mdc2Hash( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	MDC2_CTX *mdc2Info = ( MDC2_CTX * ) cryptInfo->ctxHash.hashInfo;

	/* If we've already called MDC2_Final(), we can't continue */
	if( cryptInfo->ctxHash.done )
		return( CRYPT_ERROR_COMPLETE );

	if( !noBytes )
		{
		MDC2_Final( cryptInfo->ctxHash.hash, mdc2Info );
		cryptInfo->ctxHash.done = TRUE;
		}
	else
		MDC2_Update( mdc2Info, buffer, noBytes );

	return( CRYPT_OK );
	}
