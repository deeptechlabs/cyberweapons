/****************************************************************************
*																			*
*						cryptlib RC5 Encryption Routines					*
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
  #include "rc5.h"
#else
  #include "crypt/rc5.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								RC5 Self-test Routines						*
*																			*
****************************************************************************/

/* RC5 test vectors from RC5 specification */

static const struct RC5_TEST {
	const BYTE key[ 16 ];
	const BYTE plainText[ 8 ];
	const BYTE cipherText[ 8 ];
	} testRC5[] = {
	{ { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x21, 0xA5, 0xDB, 0xEE, 0x15, 0x4B, 0x8F, 0x6D } },
	{ { 0x91, 0x5F, 0x46, 0x19, 0xBE, 0x41, 0xB2, 0x51,
		0x63, 0x55, 0xA5, 0x01, 0x10, 0xA9, 0xCE, 0x91 },
	  { 0x21, 0xA5, 0xDB, 0xEE, 0x15, 0x4B, 0x8F, 0x6D },
	  { 0xF7, 0xC0, 0x13, 0xAC, 0x5B, 0x2B, 0x89, 0x52 } },
	{ { 0x78, 0x33, 0x48, 0xE7, 0x5A, 0xEB, 0x0F, 0x2F,
		0xD7, 0xB1, 0x69, 0xBB, 0x8D, 0xC1, 0x67, 0x87 },
	  { 0xF7, 0xC0, 0x13, 0xAC, 0x5B, 0x2B, 0x89, 0x52 },
	  { 0x2F, 0x42, 0xB3, 0xB7, 0x03, 0x69, 0xFC, 0x92 } },
	{ { 0xDC, 0x49, 0xDB, 0x13, 0x75, 0xA5, 0x58, 0x4F,
		0x64, 0x85, 0xB4, 0x13, 0xB5, 0xF1, 0x2B, 0xAF },
	  { 0x2F, 0x42, 0xB3, 0xB7, 0x03, 0x69, 0xFC, 0x92 },
	  { 0x65, 0xC1, 0x78, 0xB2, 0x84, 0xD1, 0x97, 0xCC } },
	{ { 0x52, 0x69, 0xF1, 0x49, 0xD4, 0x1B, 0xA0, 0x15,
		0x24, 0x97, 0x57, 0x4D, 0x7F, 0x15, 0x31, 0x25 },
	  { 0x65, 0xC1, 0x78, 0xB2, 0x84, 0xD1, 0x97, 0xCC },
	  { 0xEB, 0x44, 0xE4, 0x15, 0xDA, 0x31, 0x98, 0x24 } }
	};

/* Test the RC5 code against the RC5 test vectors */

int rc5SelfTest( void )
	{
	BYTE temp[ RC5_BLOCKSIZE ];
	RC5_KEY key;
	int i;

	for( i = 0; i < sizeof( testRC5 ) / sizeof( struct RC5_TEST ); i++ )
		{
		key.noRounds = 12;
		memcpy( temp, testRC5[ i ].plainText, RC5_BLOCKSIZE );
			rc5keyInit( &key, testRC5[ i ].key, 16 );
		rc5encrypt( &key, temp );
		if( memcmp( testRC5[ i ].cipherText, temp, RC5_BLOCKSIZE ) )
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

int rc5Init( CRYPT_INFO *cryptInfo, void *cryptInfoEx )
	{
	CRYPT_INFO_RC5 *cryptInfoExPtr = ( CRYPT_INFO_RC5 * ) cryptInfoEx;
	int status;

	/* Allocate memory for the key within the crypt context and set up any
	   pointers we need.  We don't process cryptInfoExPtr->noRounds at this
	   point since we set things up when we perform the rc5InitKey()
	   function, as the number of rounds is key-dependant */
	if( cryptInfo->ctxConv.key != NULL )
		return( CRYPT_INITED );
	if( ( status = krnlMemalloc( &cryptInfo->ctxConv.key, sizeof( RC5_KEY ) ) ) != CRYPT_OK )
		return( status );
	if( cryptInfoExPtr == NULL )
		setRC5info( cryptInfo, CRYPT_USE_DEFAULT );
	else
		setRC5info( cryptInfo, cryptInfoExPtr->rounds );
	cryptInfo->ctxConv.keyLength = sizeof( RC5_KEY );

	return( CRYPT_OK );
	}

int rc5End( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	krnlMemfree( &cryptInfo->ctxConv.key );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							RC5 En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt/decrypt data in ECB mode */

int rc5EncryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RC5_KEY *rc5Key = ( RC5_KEY * ) cryptInfo->ctxConv.key;
	int blockCount = noBytes / RC5_BLOCKSIZE;

	while( blockCount-- )
		{
		/* Encrypt a block of data */
		rc5encrypt( rc5Key, buffer );

		/* Move on to next block of data */
		buffer += RC5_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int rc5DecryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RC5_KEY *rc5Key = ( RC5_KEY * ) cryptInfo->ctxConv.key;
	int blockCount = noBytes / RC5_BLOCKSIZE;

	while( blockCount-- )
		{
		/* Decrypt a block of data */
		rc5decrypt( rc5Key, buffer );

		/* Move on to next block of data */
		buffer += RC5_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CBC mode */

int rc5EncryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RC5_KEY *rc5Key = ( RC5_KEY * ) cryptInfo->ctxConv.key;
	int blockCount = noBytes / RC5_BLOCKSIZE;

	while( blockCount-- )
		{
		int i;

		/* XOR the buffer contents with the IV */
		for( i = 0; i < RC5_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Encrypt a block of data */
		rc5encrypt( rc5Key, buffer );

		/* Shift ciphertext into IV */
		memcpy( cryptInfo->ctxConv.currentIV, buffer, RC5_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += RC5_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int rc5DecryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RC5_KEY *rc5Key = ( RC5_KEY * ) cryptInfo->ctxConv.key;
	BYTE temp[ RC5_BLOCKSIZE ];
	int blockCount = noBytes / RC5_BLOCKSIZE;

	while( blockCount-- )
		{
		int i;

		/* Save the ciphertext */
		memcpy( temp, buffer, RC5_BLOCKSIZE );

		/* Decrypt a block of data */
		rc5decrypt( rc5Key, buffer );

		/* XOR the buffer contents with the IV */
		for( i = 0; i < RC5_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( cryptInfo->ctxConv.currentIV, temp, RC5_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += RC5_BLOCKSIZE;
		}

	/* Clear the temporary buffer */
	zeroise( temp, RC5_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CFB mode */

int rc5EncryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RC5_KEY *rc5Key = ( RC5_KEY * ) cryptInfo->ctxConv.key;
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = RC5_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > RC5_BLOCKSIZE ) ? RC5_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		rc5encrypt( rc5Key, cryptInfo->ctxConv.currentIV );

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
	cryptInfo->ctxConv.ivCount = ( ivCount % RC5_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in CFB mode.  Note that the transformation can be made
   faster (but less clear) with temp = buffer, buffer ^= iv, iv = temp
   all in one loop */

int rc5DecryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RC5_KEY *rc5Key = ( RC5_KEY * ) cryptInfo->ctxConv.key;
	BYTE temp[ RC5_BLOCKSIZE ];
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = RC5_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > RC5_BLOCKSIZE ) ? RC5_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		rc5encrypt( rc5Key, cryptInfo->ctxConv.currentIV );

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
	cryptInfo->ctxConv.ivCount = ( ivCount % RC5_BLOCKSIZE );

	/* Clear the temporary buffer */
	zeroise( temp, RC5_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in OFB mode */

int rc5EncryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RC5_KEY *rc5Key = ( RC5_KEY * ) cryptInfo->ctxConv.key;
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = RC5_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > RC5_BLOCKSIZE ) ? RC5_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		rc5encrypt( rc5Key, cryptInfo->ctxConv.currentIV );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ctxConv.ivCount = ( ivCount % RC5_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in OFB mode */

int rc5DecryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	RC5_KEY *rc5Key = ( RC5_KEY * ) cryptInfo->ctxConv.key;
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = RC5_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > RC5_BLOCKSIZE ) ? RC5_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		rc5encrypt( rc5Key, cryptInfo->ctxConv.currentIV );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ctxConv.ivCount = ( ivCount % RC5_BLOCKSIZE );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							RC5 Key Management Routines						*
*																			*
****************************************************************************/

/* Get/set algorithm-specific parameters */

int getRC5info( const CRYPT_INFO *cryptInfo )
	{
	return( cryptInfo->ctxConv.algorithmParam1 );
	}

void setRC5info( CRYPT_INFO *cryptInfo, const int rounds )
	{
	cryptInfo->ctxConv.algorithmParam1 = rounds;
	if( rounds != CRYPT_USE_DEFAULT && rounds != RC5_DEFAULT_ROUNDS )
		cryptInfo->ctxConv.nonDefaultValues = TRUE;
	}

/* Key schedule a RC5 key */

int rc5InitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength )
	{
	RC5_KEY *rc5Key = ( RC5_KEY * ) cryptInfo->ctxConv.key;

	/* Copy the key to internal storage */
	if( cryptInfo->ctxConv.userKey != key )
		memcpy( cryptInfo->ctxConv.userKey, key, keyLength );
	cryptInfo->ctxConv.userKeyLength = keyLength;

	/* If the number of rounds has been preset, use this value */
	rc5Key->noRounds = ( cryptInfo->ctxConv.algorithmParam1 != CRYPT_USE_DEFAULT ) ? \
					cryptInfo->ctxConv.algorithmParam1 : RC5_DEFAULT_ROUNDS;

	rc5keyInit( rc5Key, key, keyLength );
	return( CRYPT_OK );
	}
