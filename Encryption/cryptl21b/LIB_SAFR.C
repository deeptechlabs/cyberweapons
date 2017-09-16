/****************************************************************************
*																			*
*						cryptlib Safer Encryption Routines					*
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
  #include "safer.h"
#else
  #include "crypt/safer.h"
#endif /* Compiler-specific includes */

/* The size of the expanded SAFER keys */

#define SAFER_EXPANDED_KEYSIZE		SAFER_KEYLEN

/****************************************************************************
*																			*
*							SAFER Self-test Routines						*
*																			*
****************************************************************************/

/* SAFER-SK64 and SAFER_SK128 test vectors, from the ETH reference
   implementation */

/* The data structure for the ( key, plaintext, ciphertext ) triplets */

typedef struct {
	const int rounds;
	const BYTE key[ SAFER_KEYSIZE ];
	const BYTE plaintext[ SAFER_BLOCKSIZE ];
	const BYTE ciphertext[ SAFER_BLOCKSIZE ];
	} SAFER_TEST;

static const SAFER_TEST testSafer[] = {
	{ SAFER_K64_ROUNDS,
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
	  { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
	  { 0x15, 0x1B, 0xFF, 0x02, 0xAD, 0x11, 0xBF, 0x2D } },
	{ SAFER_K64_ROUNDS,
	  { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
	  { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
	  { 0x5F, 0xCE, 0x9B, 0xA2, 0x05, 0x84, 0x38, 0xC7 } },
	{ SAFER_K128_ROUNDS,
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
	  { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
	  { 0x41, 0x4C, 0x54, 0x5A, 0xB6, 0x99, 0x4A, 0xF7 } },
	{ SAFER_K128_ROUNDS,
	  { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
	  { 0xFF, 0x78, 0x11, 0xE4, 0xB3, 0xA7, 0x2E, 0x71 } },
	{ SAFER_K128_ROUNDS,
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
	  { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
	  { 0x49, 0xC9, 0x9D, 0x98, 0xA5, 0xBC, 0x59, 0x08 } },
	};

/* Test the SAFER-SK code against the test vectors from the ETH reference
   implementation */

int saferSelfTest( void )
	{
	BYTE temp[ SAFER_BLOCKSIZE ];
	BYTE key128[ SAFER_KEYSIZE ], key[ SAFER_EXPANDED_KEYSIZE ];
	int i;

	for( i = 0; i < sizeof( testSafer ) / sizeof( SAFER_TEST ); i++ )
		{
		/* We always do a 128-bit key schedule internally so if we're
		   using a 64-bit key we mirror the first 64 bits into the second
		   64 bits */
		memcpy( key128, testSafer[ i ].key, bitsToBytes( 128 ) );
		if( testSafer[ i ].rounds == SAFER_K64_ROUNDS )
			memcpy( key128 + bitsToBytes( 64 ),
					testSafer[ i ].key, bitsToBytes( 64 ) );

		memcpy( temp, testSafer[ i ].plaintext, SAFER_BLOCKSIZE );
		saferExpandKey( key, key128, testSafer[ i ].rounds, TRUE );
		saferEncryptBlock( temp, key );
		if( memcmp( testSafer[ i ].ciphertext, temp, SAFER_BLOCKSIZE ) )
			return( CRYPT_ERROR );
		saferDecryptBlock( temp, key );
		if( memcmp( testSafer[ i ].plaintext, temp, SAFER_BLOCKSIZE ) )
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

int saferInit( CRYPT_INFO *cryptInfo, void *cryptInfoEx )
	{
	CRYPT_INFO_SAFER *cryptInfoExPtr = ( CRYPT_INFO_SAFER * ) cryptInfoEx;
	int status;

	/* Allocate memory for the key within the crypt context and set up any
	   pointers we need.  We don't process
	   cryptInfoExPtr->rounds at this point since we set things up when we
	   perform the saferInitKey() function, as the number of rounds is key-
	   dependant.  Because the number of rounds is keysize dependant, we
	   can't check whether a user-specified number of rounds is the same as
	   the default number at this point because we don't yet know how big the
	   key will be, so we always set the nonDefaultValues flag if we're given
	   a number of rounds which isn't CRYPT_USE_DEFAULT */
	if( cryptInfo->ctxConv.key != NULL )
		return( CRYPT_INITED );
	if( ( status = krnlMemalloc( &cryptInfo->ctxConv.key, SAFER_EXPANDED_KEYSIZE ) ) != CRYPT_OK )
		return( status );
	if( cryptInfoExPtr == NULL )
		setSaferInfo( cryptInfo, CRYPT_USE_DEFAULT, CRYPT_USE_DEFAULT );
	else
		if( cryptInfoExPtr->useSaferSK == CRYPT_USE_DEFAULT )
			setSaferInfo( cryptInfo, TRUE, cryptInfoExPtr->rounds );
		else
			setSaferInfo( cryptInfo, ( BOOLEAN ) cryptInfoExPtr->useSaferSK,
						  cryptInfoExPtr->rounds );
	cryptInfo->ctxConv.keyLength = SAFER_EXPANDED_KEYSIZE;

	return( CRYPT_OK );
	}

int saferEnd( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	krnlMemfree( &cryptInfo->ctxConv.key );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							SAFER En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt/decrypt data in ECB mode */

int saferEncryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BYTE *saferKey = ( BYTE * ) cryptInfo->ctxConv.key;
	int blockCount = noBytes / SAFER_BLOCKSIZE;

	while( blockCount-- )
		{
		/* Encrypt a block of data */
		saferEncryptBlock( buffer, saferKey );

		/* Move on to next block of data */
		buffer += SAFER_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int saferDecryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BYTE *saferKey = ( BYTE * ) cryptInfo->ctxConv.key;
	int blockCount = noBytes / SAFER_BLOCKSIZE;

	while( blockCount-- )
		{
		/* Decrypt a block of data */
		saferDecryptBlock( buffer, saferKey );

		/* Move on to next block of data */
		buffer += SAFER_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CBC mode */

int saferEncryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BYTE *saferKey = ( BYTE * ) cryptInfo->ctxConv.key;
	int blockCount = noBytes / SAFER_BLOCKSIZE;

	while( blockCount-- )
		{
		int i;

		/* XOR the buffer contents with the IV */
		for( i = 0; i < SAFER_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Encrypt a block of data */
		saferEncryptBlock( buffer, saferKey );

		/* Shift ciphertext into IV */
		memcpy( cryptInfo->ctxConv.currentIV, buffer, SAFER_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += SAFER_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int saferDecryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BYTE *saferKey = ( BYTE * ) cryptInfo->ctxConv.key;
	BYTE temp[ SAFER_BLOCKSIZE ];
	int blockCount = noBytes / SAFER_BLOCKSIZE;

	while( blockCount-- )
		{
		int i;

		/* Save the ciphertext */
		memcpy( temp, buffer, SAFER_BLOCKSIZE );

		/* Decrypt a block of data */
		saferDecryptBlock( buffer, saferKey );

		/* XOR the buffer contents with the IV */
		for( i = 0; i < SAFER_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( cryptInfo->ctxConv.currentIV, temp, SAFER_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += SAFER_BLOCKSIZE;
		}

	/* Clear the temporary buffer */
	zeroise( temp, SAFER_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CFB mode */

int saferEncryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BYTE *saferKey = ( BYTE * ) cryptInfo->ctxConv.key;
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = SAFER_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > SAFER_BLOCKSIZE ) ? SAFER_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		saferEncryptBlock( cryptInfo->ctxConv.currentIV, saferKey );

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
	cryptInfo->ctxConv.ivCount = ( ivCount % SAFER_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in CFB mode.  Note that the transformation can be made
   faster (but less clear) with temp = buffer, buffer ^= iv, iv = temp
   all in one loop */

int saferDecryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BYTE *saferKey = ( BYTE * ) cryptInfo->ctxConv.key;
	BYTE temp[ SAFER_BLOCKSIZE ];
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = SAFER_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > SAFER_BLOCKSIZE ) ? SAFER_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		saferEncryptBlock( cryptInfo->ctxConv.currentIV, saferKey );

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
	cryptInfo->ctxConv.ivCount = ( ivCount % SAFER_BLOCKSIZE );

	/* Clear the temporary buffer */
	zeroise( temp, SAFER_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in OFB mode */

int saferEncryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BYTE *saferKey = ( BYTE * ) cryptInfo->ctxConv.key;
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = SAFER_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > SAFER_BLOCKSIZE ) ? SAFER_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		saferEncryptBlock( cryptInfo->ctxConv.currentIV, saferKey );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ctxConv.ivCount = ( ivCount % SAFER_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in OFB mode */

int saferDecryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BYTE *saferKey = ( BYTE * ) cryptInfo->ctxConv.key;
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = SAFER_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > SAFER_BLOCKSIZE ) ? SAFER_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		saferEncryptBlock( cryptInfo->ctxConv.currentIV, saferKey );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ctxConv.ivCount = ( ivCount % SAFER_BLOCKSIZE );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							SAFER Key Management Routines					*
*																			*
****************************************************************************/

/* Get/set algorithm-specific parameters */

int getSaferInfo( const CRYPT_INFO *cryptInfo, BOOLEAN *useSaferSK )
	{
	*useSaferSK = ( BOOLEAN ) cryptInfo->ctxConv.algorithmParam1;
	return( cryptInfo->ctxConv.algorithmParam2 );
	}

void setSaferInfo( CRYPT_INFO *cryptInfo, const BOOLEAN useSaferSK,
				   const int rounds )
	{
	cryptInfo->ctxConv.algorithmParam1 = ( int ) useSaferSK;
	cryptInfo->ctxConv.algorithmParam2 = rounds;
	if( useSaferSK == FALSE || rounds != CRYPT_USE_DEFAULT )
		cryptInfo->ctxConv.nonDefaultValues = TRUE;
	}

int saferGetKeysize( CRYPT_INFO *cryptInfo )
	{
	/* This is tricky, since we dynamically adjust the key type to 64 or 128
	   bits depending on how much keying data we've been passed by the user,
	   but we can't tell in advance how much this will be.  We get around
	   this by taking advantage of the fact that when the library queries the
	   key size for an encryption context with no key loaded, it always wants
	   to know the maximum amount of data it can use for a key, so we just
	   return the maximum value */
	if( cryptInfo->ctxConv.userKeyLength == 0 )
		return( bitsToBytes( 128 ) );

	/* If the key has already been set up, just return the type of key we're
	   using */
	return( ( cryptInfo->ctxConv.userKeyLength <= bitsToBytes( 64 ) ) ? \
			bitsToBytes( 64 ) : bitsToBytes( 128 ) );
	}

/* Key schedule a SAFER key */

int saferInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength )
	{
	BYTE *saferKey = ( BYTE * ) cryptInfo->ctxConv.key;
	BOOLEAN shortKey = keyLength <= bitsToBytes( 64 );
	int currentRounds;

	/* Copy the key to internal storage */
	if( cryptInfo->ctxConv.userKey != key )
		memcpy( cryptInfo->ctxConv.userKey, key, keyLength );
	cryptInfo->ctxConv.userKeyLength = keyLength;

	/* If the number of rounds has been preset, use this value */
	if( cryptInfo->ctxConv.algorithmParam2 != CRYPT_USE_DEFAULT )
		currentRounds = cryptInfo->ctxConv.algorithmParam2;
	else
		/* Determine the number of rounds to use based on the key size */
		if( cryptInfo->ctxConv.algorithmParam1 )
			currentRounds = ( shortKey ) ? SAFER_SK64_ROUNDS : SAFER_SK128_ROUNDS;
		else
			currentRounds = ( shortKey ) ? SAFER_K64_ROUNDS : SAFER_K128_ROUNDS;

	/* Generate an expanded SAFER key */
	if( shortKey )
		/* We always do a 128-bit key schedule internally so if we're using a
		   64-bit key we mirror the first 64 bits into the second 64 bits */
		memcpy( cryptInfo->ctxConv.userKey + bitsToBytes( 64 ), cryptInfo->ctxConv.userKey,
				bitsToBytes( 64 ) );
	saferExpandKey(	saferKey, cryptInfo->ctxConv.userKey, currentRounds,
					( BOOLEAN ) cryptInfo->ctxConv.algorithmParam1 );

	return( CRYPT_OK );
	}
