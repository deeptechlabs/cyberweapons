/****************************************************************************
*																			*
*						cryptlib HMAC-SHA Hash Routines						*
*						  Copyright Peter Gutmann 1997						*
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
*							HMAC-SHA Self-test Routines						*
*																			*
****************************************************************************/

/* Test the HMAC-SHA output against the test vectors given in RFC ???? */

int hmacSHAInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int hmacSHAHash( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes );

static const struct {
	const char *key;						/* HMAC key */
	const int keyLength;					/* Length of key */
	const char *data;						/* Data to hash */
	const int length;						/* Length of data */
	const BYTE digest[ SHA_DIGEST_LENGTH ];	/* Digest of data */
	} hmacValues[] = {
	{ "\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B"
	  "\x0B\x0B\x0B\x0B", 20,
	  "Hi There", 8,
	  { 0xB6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64,
		0xE2, 0x8B, 0xC0, 0xB6, 0xFB, 0x37, 0x8C, 0x8E,
		0xF1, 0x46, 0xBE, 0x00 } },
	{ "Jefe", 4,
		"what do ya want for nothing?", 28,
	  { 0xEF, 0xFC, 0xDF, 0x6A, 0xE5, 0xEB, 0x2F, 0xA2,
		0xD2, 0x74, 0x16, 0xD5, 0xF1, 0x84, 0xDF, 0x9C,
		0x25, 0x9A, 0x7C, 0x79 } },
	{ "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA", 20,
	  "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
	  "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
	  "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
	  "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD"
	  "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD", 50,
	  { 0x12, 0x5D, 0x73, 0x42, 0xB9, 0xAC, 0x11, 0xCD,
		0x91, 0xA3, 0x9A, 0xF4, 0x8A, 0xA1, 0x7B, 0x4F,
		0x63, 0xF1, 0x75, 0xD3 } },
	{ "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10"
	  "\x11\x12\x13\x14\x15\x16\x17\x18\x19", 25,
	  "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
	  "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
	  "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
	  "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD"
	  "\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD\xCD", 50,
	  { 0x4C, 0x90, 0x07, 0xF4, 0x02, 0x62, 0x50, 0xC6,
		0xBC, 0x84, 0x14, 0xF9, 0xBF, 0x50, 0xC8, 0x6C,
		0x2D, 0x72, 0x35, 0xDA } },
#if 0	/* Should be trunc.to 96 bits - we don't do truncation */
	{ "\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C"
	  "\x0C\x0C\x0C\x0C", 20,
	  "Test With Truncation", 20,
	  { 0x4C, 0x1A, 0x03, 0x42, 0x4B, 0x55, 0xE0, 0x7F,
		0xE7, 0xF2, 0x7B, 0xE1, 0xD5, 0x8B, 0xB9, 0x32,
		0x4A, 0x9A, 0x5A, 0x04 } },
#endif /* 0 */
	{ "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA", 80,
	  "Test Using Larger Than Block-Size Key - Hash Key First", 54,
	  { 0xAA, 0x4A, 0xE5, 0xE1, 0x52, 0x72, 0xD0, 0x0E,
		0x95, 0x70, 0x56, 0x37, 0xCE, 0x8A, 0x3B, 0x55,
		0xED, 0x40, 0x21, 0x12 } },
	{ "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
	  "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA", 80,
	  "Test Using Larger Than Block-Size Key and Larger Than One "
	  "Block-Size Data", 73,
	  { 0xE8, 0xE9, 0x9D, 0x0F, 0x45, 0x23, 0x7D, 0x78,
		0x6D, 0x6B, 0xBA, 0xA7, 0x96, 0x5C, 0x78, 0x08,
		0xBB, 0xFF, 0x1A, 0x91 } },
	{ "", 0, NULL, 0, { 0 } }
	};

int hmacSHASelfTest( void )
	{
	CRYPT_INFO cryptInfo;
	SHA_CTX shaInfo;
	int i;

	/* Set up the dummy cryptInfo structure */
	memset( &cryptInfo, 0, sizeof( CRYPT_INFO ) );
	cryptInfo.ctxMAC.macInfo = &shaInfo;

	/* Test HMAC-SHA against the test vectors given in RFC ???? */
	for( i = 0; hmacValues[ i ].data != NULL; i++ )
		{
		/* Initialise the encryption context with enough information to test
		   the HMAC functionality */
		cryptInfo.ctxMAC.done = FALSE;
		SHA1_Init( ( SHA_CTX * ) cryptInfo.ctxMAC.macInfo );

		/* Load the HMAC key and perform the hashing */
		hmacSHAInitKey( &cryptInfo, hmacValues[ i ].key,
						hmacValues[ i ].keyLength );
		hmacSHAHash( &cryptInfo, ( BYTE * ) hmacValues[ i ].data,
					 hmacValues[ i ].length );
		hmacSHAHash( &cryptInfo, NULL, 0 );

		/* Retrieve the hash and make sure it matches the expected value */
		if( memcmp( cryptInfo.ctxMAC.mac, hmacValues[ i ].digest,
					SHA_DIGEST_LENGTH ) )
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

int hmacSHAInit( CRYPT_INFO *cryptInfo )
	{
	int status;

	/* Allocate memory for the SHA context within the encryption context.
	   Since MAC contexts can be reset by deleting the MAC values, this may 
	   already have been allocated previously so we only perform the alloc
	   if it's actually required */
	if( cryptInfo->ctxMAC.macInfo == NULL && \
		( status = krnlMemalloc( &cryptInfo->ctxMAC.macInfo,
								 sizeof( SHA_CTX ) ) ) != CRYPT_OK )
		return( status );
	SHA1_Init( ( SHA_CTX * ) cryptInfo->ctxMAC.macInfo );

	return( CRYPT_OK );
	}

int hmacSHAEnd( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	krnlMemfree( &cryptInfo->ctxMAC.macInfo );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							HMAC-SHA Hash Routines							*
*																			*
****************************************************************************/

/* Hash data using HMAC-SHA */

int hmacSHAHash( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	SHA_CTX *shaInfo = ( SHA_CTX * ) cryptInfo->ctxMAC.macInfo;

	/* If we've already called SHA1_Final(), we can't continue */
	if( cryptInfo->ctxMAC.done )
		return( CRYPT_ERROR_COMPLETE );

	if( !noBytes )
		{
		BYTE hashBuffer[ SHA_CBLOCK ], digestBuffer[ SHA_DIGEST_LENGTH ];
		int i;

		/* Complete the inner hash and extract the digest */
		SHA1_Final( digestBuffer, shaInfo );

		/* Perform the of the outer hash using the zero-padded key XOR'd
		   with the opad value followed by the digest from the inner hash */
		memset( hashBuffer, HMAC_OPAD, SHA_CBLOCK );
		memcpy( hashBuffer, cryptInfo->ctxMAC.userKey,
				cryptInfo->ctxMAC.userKeyLength );
		for( i = 0; i < cryptInfo->ctxMAC.userKeyLength; i++ )
			hashBuffer[ i ] ^= HMAC_OPAD;
		SHA1_Init( shaInfo );
		SHA1_Update( shaInfo, hashBuffer, SHA_CBLOCK );
		memset( hashBuffer, 0, SHA_CBLOCK );
		SHA1_Update( shaInfo, digestBuffer, SHA_DIGEST_LENGTH );
		memset( digestBuffer, 0, SHA_DIGEST_LENGTH );
		SHA1_Final( cryptInfo->ctxMAC.mac, shaInfo );
		cryptInfo->ctxMAC.done = TRUE;
		}
	else
		SHA1_Update( shaInfo, buffer, noBytes );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							HMAC-SHA Key Management Routines				*
*																			*
****************************************************************************/

/* Set up an HMAC-SHA key */

int hmacSHAInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength )
	{
	SHA_CTX *shaInfo = ( SHA_CTX * ) cryptInfo->ctxMAC.macInfo;
	BYTE hashBuffer[ SHA_CBLOCK ];
	int i;

	/* If the key size is larger than tha SHA data size, reduce it to the
	   SHA hash size before processing it (yuck.  You're required to do this
	   though) */
	if( keyLength > SHA_CBLOCK )
		{
		/* Hash the user key down to the hash size (SHA1_Init() has already
		   been called when the context was created) and use the hashed form
		   of the key */
		SHA1_Update( shaInfo, ( void * ) key, keyLength );
		SHA1_Final( cryptInfo->ctxMAC.userKey, shaInfo );
		cryptInfo->ctxMAC.userKeyLength = SHA_DIGEST_LENGTH;

		/* Reset the SHA state */
		SHA1_Init( shaInfo );
		}
	else
		{
		/* Copy the key to internal storage */
		memcpy( cryptInfo->ctxMAC.userKey, key, keyLength );
		cryptInfo->ctxMAC.userKeyLength = keyLength;
		}

	/* Perform the start of the inner hash using the zero-padded key XOR'd
	   with the ipad value */
	memset( hashBuffer, HMAC_IPAD, SHA_CBLOCK );
	memcpy( hashBuffer, cryptInfo->ctxMAC.userKey,
			cryptInfo->ctxMAC.userKeyLength );
	for( i = 0; i < cryptInfo->ctxMAC.userKeyLength; i++ )
		hashBuffer[ i ] ^= HMAC_IPAD;
	SHA1_Update( shaInfo, hashBuffer, SHA_CBLOCK );
	memset( hashBuffer, 0, SHA_CBLOCK );

	return( CRYPT_OK );
	}
