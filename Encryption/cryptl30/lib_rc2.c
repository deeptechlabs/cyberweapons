/****************************************************************************
*																			*
*						cryptlib RC2 Encryption Routines					*
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
  #include "rc2.h"
#else
  #include "crypt/rc2.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								RC2 Self-test Routines						*
*																			*
****************************************************************************/

/* RC2 test vectors from RFC 2268 */

static const struct RC2_TEST {
	const BYTE key[ 16 ];
	const BYTE plainText[ 8 ];
	const BYTE cipherText[ 8 ];
	} testRC2[] = {
	{ { 0x88, 0xBC, 0xA9, 0x0E, 0x90, 0x87, 0x5A, 0x7F,
		0x0F, 0x79, 0xC3, 0x84, 0x62, 0x7B, 0xAF, 0xB2 },
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x22, 0x69, 0x55, 0x2A, 0xB0, 0xF8, 0x5C, 0xA6 } }
	};

/* Test the RC2 code against the RC2 test vectors */

int rc2SelfTest( void )
	{
	BYTE temp[ RC2_BLOCKSIZE ];
	RC2_KEY key;
	int i;

	for( i = 0; i < sizeof( testRC2 ) / sizeof( struct RC2_TEST ); i++ )
		{
		memcpy( temp, testRC2[ i ].plainText, RC2_BLOCKSIZE );
		rc2keyInit( &key, testRC2[ i ].key, 16 );
		rc2encrypt( &key, temp );
		if( memcmp( testRC2[ i ].cipherText, temp, RC2_BLOCKSIZE ) )
			return( CRYPT_ERROR );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Routines							*
*																			*
****************************************************************************/

/* Perform init and shutdown actions on an encryption context */

int rc2Init( CRYPT_INFO *cryptInfo )
	{
	int status;

	/* Allocate memory for the key and the algorithm-specific data within
	   the crypt context and set up any pointers we need */
	if( ( status = krnlMemalloc( &cryptInfo->ctxConv.key, sizeof( RC2_KEY ) ) ) != CRYPT_OK )
		return( status );
	cryptInfo->ctxConv.keyLength = sizeof( RC2_KEY );

	return( CRYPT_OK );
	}

int rc2End( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	krnlMemfree( &cryptInfo->ctxConv.key );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							RC2 En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt/decrypt data in ECB mode */

int rc2EncryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RC2_KEY *rc2Key = ( RC2_KEY * ) cryptInfo->ctxConv.key;
	int blockCount = noBytes / RC2_BLOCKSIZE;

	while( blockCount-- )
		{
		/* Encrypt a block of data */
		rc2encrypt( rc2Key, buffer );

		/* Move on to next block of data */
		buffer += RC2_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int rc2DecryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RC2_KEY *rc2Key = ( RC2_KEY * ) cryptInfo->ctxConv.key;
	int blockCount = noBytes / RC2_BLOCKSIZE;

	while( blockCount-- )
		{
		/* Decrypt a block of data */
		rc2decrypt( rc2Key, buffer );

		/* Move on to next block of data */
		buffer += RC2_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CBC mode */

int rc2EncryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RC2_KEY *rc2Key = ( RC2_KEY * ) cryptInfo->ctxConv.key;
	int blockCount = noBytes / RC2_BLOCKSIZE;

	while( blockCount-- )
		{
		int i;

		/* XOR the buffer contents with the IV */
		for( i = 0; i < RC2_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Encrypt a block of data */
		rc2encrypt( rc2Key, buffer );

		/* Shift ciphertext into IV */
		memcpy( cryptInfo->ctxConv.currentIV, buffer, RC2_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += RC2_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int rc2DecryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RC2_KEY *rc2Key = ( RC2_KEY * ) cryptInfo->ctxConv.key;
	BYTE temp[ RC2_BLOCKSIZE ];
	int blockCount = noBytes / RC2_BLOCKSIZE;

	while( blockCount-- )
		{
		int i;

		/* Save the ciphertext */
		memcpy( temp, buffer, RC2_BLOCKSIZE );

		/* Decrypt a block of data */
		rc2decrypt( rc2Key, buffer );

		/* XOR the buffer contents with the IV */
		for( i = 0; i < RC2_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( cryptInfo->ctxConv.currentIV, temp, RC2_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += RC2_BLOCKSIZE;
		}

	/* Clear the temporary buffer */
	zeroise( temp, RC2_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CFB mode */

int rc2EncryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RC2_KEY *rc2Key = ( RC2_KEY * ) cryptInfo->ctxConv.key;
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = RC2_BLOCKSIZE - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Encrypt the data */
		for( i = 0; i < bytesToUse; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i + ivCount ];
		memcpy( cryptInfo->ctxConv.currentIV + ivCount, buffer, bytesToUse );

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes )
		{
		ivCount = ( noBytes > RC2_BLOCKSIZE ) ? RC2_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		rc2encrypt( rc2Key, cryptInfo->ctxConv.currentIV );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( cryptInfo->ctxConv.currentIV, buffer, ivCount );

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ctxConv.ivCount = ( ivCount % RC2_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in CFB mode.  Note that the transformation can be made
   faster (but less clear) with temp = buffer, buffer ^= iv, iv = temp
   all in one loop */

int rc2DecryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RC2_KEY *rc2Key = ( RC2_KEY * ) cryptInfo->ctxConv.key;
	BYTE temp[ RC2_BLOCKSIZE ];
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = RC2_BLOCKSIZE - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Decrypt the data */
		memcpy( temp, buffer, bytesToUse );
		for( i = 0; i < bytesToUse; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i + ivCount ];
		memcpy( cryptInfo->ctxConv.currentIV + ivCount, temp, bytesToUse );

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes )
		{
		ivCount = ( noBytes > RC2_BLOCKSIZE ) ? RC2_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		rc2encrypt( rc2Key, cryptInfo->ctxConv.currentIV );

		/* Save the ciphertext */
		memcpy( temp, buffer, ivCount );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( cryptInfo->ctxConv.currentIV, temp, ivCount );

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ctxConv.ivCount = ( ivCount % RC2_BLOCKSIZE );

	/* Clear the temporary buffer */
	zeroise( temp, RC2_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in OFB mode */

int rc2EncryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RC2_KEY *rc2Key = ( RC2_KEY * ) cryptInfo->ctxConv.key;
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = RC2_BLOCKSIZE - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Encrypt the data */
		for( i = 0; i < bytesToUse; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i + ivCount ];

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes )
		{
		ivCount = ( noBytes > RC2_BLOCKSIZE ) ? RC2_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		rc2encrypt( rc2Key, cryptInfo->ctxConv.currentIV );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ctxConv.ivCount = ( ivCount % RC2_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in OFB mode */

int rc2DecryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RC2_KEY *rc2Key = ( RC2_KEY * ) cryptInfo->ctxConv.key;
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = RC2_BLOCKSIZE - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;

		/* Decrypt the data */
		for( i = 0; i < bytesToUse; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i + ivCount ];

		/* Adjust the byte count and buffer position */
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		ivCount += bytesToUse;
		}

	while( noBytes )
		{
		ivCount = ( noBytes > RC2_BLOCKSIZE ) ? RC2_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		rc2encrypt( rc2Key, cryptInfo->ctxConv.currentIV );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ctxConv.ivCount = ( ivCount % RC2_BLOCKSIZE );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							RC2 Key Management Routines						*
*																			*
****************************************************************************/

/* Key schedule an RC2 key */

int rc2InitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength )
	{
	RC2_KEY *rc2Key = ( RC2_KEY * ) cryptInfo->ctxConv.key;

	/* Copy the key to internal storage */
	if( cryptInfo->ctxConv.userKey != key )
		memcpy( cryptInfo->ctxConv.userKey, key, keyLength );
	cryptInfo->ctxConv.userKeyLength = keyLength;

	rc2keyInit( rc2Key, key, keyLength );
	return( CRYPT_OK );
	}
