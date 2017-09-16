/****************************************************************************
*																			*
*					cryptlib HMAC-RIPEMD-160 Hash Routines					*
*						 Copyright Peter Gutmann 1997						*
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
*						HMAC-RIPEMD-160 Self-test Routines					*
*																			*
****************************************************************************/

/* Test the HMAC-RIPEMD-160 output against the test vectors given in RFC
   ???? */

int hmacRIPEMD160InitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int hmacRIPEMD160Hash( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes );

static const struct {
	const char *key;							/* HMAC key */
	const int keyLength;						/* Length of key */
	const char *data;							/* Data to hash */
	const int length;							/* Length of data */
	const BYTE digest[ RIPEMD160_DIGESTSIZE ];	/* Digest of data */
	} hmacValues[] = {
	/* No published test vectors yet */
	{ "", 0, NULL, 0, { 0 } }
	};

int hmacRIPEMD160SelfTest( void )
	{
	CRYPT_INFO cryptInfo;
	RIPEMD160_INFO ripemdInfo;
	int i;

	/* Set up the dummy cryptInfo structure */
	memset( &cryptInfo, 0, sizeof( CRYPT_INFO ) );
	cryptInfo.ctxMAC.macInfo = &ripemdInfo;

	/* Test HMAC-RIPEMD-160 against the test vectors given in RFC ???? */
	for( i = 0; hmacValues[ i ].data != NULL; i++ )
		{
		/* Initialise the encryption context with enough information to test
		   the HMAC functionality */
		cryptInfo.ctxMAC.done = FALSE;
		ripemd160Initial( ( RIPEMD160_INFO * ) cryptInfo.ctxMAC.macInfo );

		/* Load the HMAC key and perform the hashing */
		hmacRIPEMD160InitKey( &cryptInfo, hmacValues[ i ].key,
							  hmacValues[ i ].keyLength );
		hmacRIPEMD160Hash( &cryptInfo, ( BYTE * ) hmacValues[ i ].data,
						   hmacValues[ i ].length );
		hmacRIPEMD160Hash( &cryptInfo, NULL, 0 );

		/* Retrieve the hash and make sure it matches the expected value */
		if( memcmp( cryptInfo.ctxMAC.mac, hmacValues[ i ].digest,
					RIPEMD160_DIGESTSIZE ) )
			break;
		}

	return( ( hmacValues[ i ].data == NULL ) ? \
			CRYPT_OK : CRYPT_ERROR );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Routines							*
*																			*
****************************************************************************/

/* Perform auxiliary init and shutdown actions on an encryption context */

int hmacRIPEMD160Init( CRYPT_INFO *cryptInfo )
	{
	int status;

	/* Allocate memory for the RIPEMD-160 context within the encryption
	   context.  Since MAC contexts can be reset by deleting the MAC values, 
	   this may already have been allocated previously so we only perform the 
	   alloc if it's actually required */
	if( cryptInfo->ctxMAC.macInfo == NULL && \
		( status = krnlMemalloc( &cryptInfo->ctxMAC.macInfo,
								 sizeof( RIPEMD160_INFO ) ) ) != CRYPT_OK )
		return( status );
	ripemd160Initial( ( RIPEMD160_INFO * ) cryptInfo->ctxMAC.macInfo );

	return( CRYPT_OK );
	}

int hmacRIPEMD160End( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	krnlMemfree( &cryptInfo->ctxMAC.macInfo );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							HMAC-RIPEMD-160 Hash Routines					*
*																			*
****************************************************************************/

/* Retrieve the hash value */

static int hmacRIPEMD160GetData( CRYPT_INFO *cryptInfo, BYTE *buffer )
	{
	RIPEMD160_INFO *ripemdInfo = ( RIPEMD160_INFO * ) cryptInfo->ctxMAC.macInfo;
	int i;

	/* Extract the digest into the memory buffer */
	for( i = 0; i < RIPEMD160_DIGESTSIZE / 4; i++ )
		{
		mputBLong( buffer, ripemdInfo->digest[ i ] );
		}

	return( ( ripemdInfo->done ) ? CRYPT_OK : CRYPT_ERROR_INCOMPLETE );
	}

/* Hash data using HMAC-RIPEMD-160 */

int hmacRIPEMD160Hash( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RIPEMD160_INFO *ripemdInfo = ( RIPEMD160_INFO * ) cryptInfo->ctxMAC.macInfo;

	/* If we've already called ripemd160Final(), we can't continue */
	if( cryptInfo->ctxMAC.done )
		return( CRYPT_ERROR_COMPLETE );

	if( !noBytes )
		{
		BYTE hashBuffer[ RIPEMD160_DATASIZE ], digestBuffer[ RIPEMD160_DIGESTSIZE ];
		int i;

		/* Complete the inner hash and extract the digest */
		ripemd160Final( ripemdInfo );
		hmacRIPEMD160GetData( cryptInfo, digestBuffer );

		/* Perform the of the outer hash using the zero-padded key XOR'd
		   with the opad value followed by the digest from the inner hash */
		memset( hashBuffer, HMAC_OPAD, RIPEMD160_DATASIZE );
		memcpy( hashBuffer, cryptInfo->ctxMAC.userKey,
				cryptInfo->ctxMAC.userKeyLength );
		for( i = 0; i < cryptInfo->ctxMAC.userKeyLength; i++ )
			hashBuffer[ i ] ^= HMAC_OPAD;
		ripemd160Initial( ripemdInfo );
		ripemd160Update( ripemdInfo, hashBuffer, RIPEMD160_DATASIZE );
		memset( hashBuffer, 0, RIPEMD160_DATASIZE );
		ripemd160Update( ripemdInfo, digestBuffer, RIPEMD160_DIGESTSIZE );
		memset( digestBuffer, 0, RIPEMD160_DIGESTSIZE );
		ripemd160Final( ripemdInfo );
		hmacRIPEMD160GetData( cryptInfo, cryptInfo->ctxMAC.mac );
		cryptInfo->ctxMAC.done = TRUE;
		}
	else
		ripemd160Update( ripemdInfo, buffer, noBytes );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						HMAC-RIPEMD-160 Key Management Routines				*
*																			*
****************************************************************************/

/* Set up an HMAC-RIPEMD-160 key */

int hmacRIPEMD160InitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength )
	{
	RIPEMD160_INFO *ripemdInfo = ( RIPEMD160_INFO * ) cryptInfo->ctxMAC.macInfo;
	BYTE hashBuffer[ RIPEMD160_DATASIZE ];
	int i;

	/* If the key size is larger than tha RIPEMD-160 data size, reduce it to
	   the RIPEMD-160 hash size before processing it (yuck.  You're required
	   to do this though) */
	if( keyLength > RIPEMD160_DATASIZE )
		{
		/* Hash the user key down to the hash size (ripemd160Initial() has
		   already been called when the context was created) */
		ripemd160Update( ripemdInfo, ( BYTE * ) key, keyLength );
		ripemd160Final( ripemdInfo );
		hmacRIPEMD160GetData( cryptInfo, cryptInfo->ctxMAC.userKey );
		cryptInfo->ctxMAC.userKeyLength = RIPEMD160_DIGESTSIZE;

		/* Reset the RIPEMD-160 state */
		ripemd160Initial( ripemdInfo );
		}
	else
		{
		/* Copy the key to internal storage */
		memcpy( cryptInfo->ctxMAC.userKey, key, keyLength );
		cryptInfo->ctxMAC.userKeyLength = keyLength;
		}

	/* Perform the start of the inner hash using the zero-padded key XOR'd
	   with the ipad value */
	memset( hashBuffer, HMAC_IPAD, RIPEMD160_DATASIZE );
	memcpy( hashBuffer, cryptInfo->ctxMAC.userKey,
			cryptInfo->ctxMAC.userKeyLength );
	for( i = 0; i < cryptInfo->ctxMAC.userKeyLength; i++ )
		hashBuffer[ i ] ^= HMAC_IPAD;
	ripemd160Update( ripemdInfo, hashBuffer, RIPEMD160_DATASIZE );
	memset( hashBuffer, 0, RIPEMD160_DATASIZE );

	return( CRYPT_OK );
	}
