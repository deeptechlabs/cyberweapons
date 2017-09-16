/****************************************************************************
*																			*
*					  cryptlib Skipjack Encryption Routines					*
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

/* Size of the Skipjack block and key size */

#define SKIPJACK_KEYSIZE	10
#define SKIPJACK_BLOCKSIZE	8

/* Prototypes for functions in crypt/skipjack.c */

void skipjackMakeKey( BYTE key[ SKIPJACK_KEYSIZE ],
					  BYTE tab[ SKIPJACK_KEYSIZE ][ 256 ]);
void skipjackEncrypt( BYTE tab[ SKIPJACK_KEYSIZE ][ 256 ],
					  BYTE in[ SKIPJACK_BLOCKSIZE ],
					  BYTE out[ SKIPJACK_BLOCKSIZE ] );
void skipjackDecrypt( BYTE tab[ SKIPJACK_KEYSIZE ][ 256 ],
					  BYTE in[ SKIPJACK_BLOCKSIZE ],
					  BYTE out[ SKIPJACK_BLOCKSIZE ] );

/****************************************************************************
*																			*
*							Skipjack Self-test Routines						*
*																			*
****************************************************************************/

/* Skipjack test vectors from the NSA Skipjack specification */

static const struct SKIPJACK_TEST {
	const BYTE key[ 10 ];
	const BYTE plainText[ 8 ];
	const BYTE cipherText[ 8 ];
	} testSkipjack[] = {
	{ { 0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 },
	  { 0x33, 0x22, 0x11, 0x00, 0xDD, 0xCC, 0xBB, 0xAA },
	  { 0x25, 0x87, 0xCA, 0xE2, 0x7A, 0x12, 0xD3, 0x00 } }
	};

/* Test the Skipjack code against the Skipjack test vectors */

int skipjackSelfTest( void )
	{
	BYTE temp[ SKIPJACK_BLOCKSIZE ];
	BYTE sjKey[ 10 ][ 256 ];
	int i;

	for( i = 0; i < sizeof( testSkipjack ) / sizeof( struct SKIPJACK_TEST ); i++ )
		{
		memcpy( temp, testSkipjack[ i ].plainText, SKIPJACK_BLOCKSIZE );
		skipjackMakeKey( ( BYTE * ) testSkipjack[ i ].key, sjKey );
		skipjackEncrypt( sjKey, temp, temp );
		if( memcmp( testSkipjack[ i ].cipherText, temp, SKIPJACK_BLOCKSIZE ) )
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

int skipjackInit( CRYPT_INFO *cryptInfo )
	{
	int status;

	/* Allocate memory for the key within the crypt context and set up any
	   pointers we need */
	if( ( status = krnlMemalloc( &cryptInfo->ctxConv.key, SKIPJACK_KEYSIZE * 256 ) ) != CRYPT_OK )
		return( status );
	cryptInfo->ctxConv.keyLength = SKIPJACK_KEYSIZE * 256;

	return( CRYPT_OK );
	}

int skipjackEnd( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	krnlMemfree( &cryptInfo->ctxConv.key );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Skipjack En/Decryption Routines					*
*																			*
****************************************************************************/

/* Encrypt/decrypt data in ECB mode */

int skipjackEncryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	int blockCount = noBytes / SKIPJACK_BLOCKSIZE;

	while( blockCount-- )
		{
		/* Encrypt a block of data */
		skipjackEncrypt( cryptInfo->ctxConv.key, buffer, buffer );

		/* Move on to next block of data */
		buffer += SKIPJACK_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int skipjackDecryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	int blockCount = noBytes / SKIPJACK_BLOCKSIZE;

	while( blockCount-- )
		{
		/* Decrypt a block of data */
		skipjackDecrypt( cryptInfo->ctxConv.key, buffer, buffer );

		/* Move on to next block of data */
		buffer += SKIPJACK_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CBC mode */

int skipjackEncryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	int blockCount = noBytes / SKIPJACK_BLOCKSIZE;

	while( blockCount-- )
		{
		int i;

		/* XOR the buffer contents with the IV */
		for( i = 0; i < SKIPJACK_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Encrypt a block of data */
		skipjackEncrypt( cryptInfo->ctxConv.key, buffer, buffer );

		/* Shift ciphertext into IV */
		memcpy( cryptInfo->ctxConv.currentIV, buffer, SKIPJACK_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += SKIPJACK_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int skipjackDecryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BYTE temp[ SKIPJACK_BLOCKSIZE ];
	int blockCount = noBytes / SKIPJACK_BLOCKSIZE;

	while( blockCount-- )
		{
		int i;

		/* Save the ciphertext */
		memcpy( temp, buffer, SKIPJACK_BLOCKSIZE );

		/* Decrypt a block of data */
		skipjackDecrypt( cryptInfo->ctxConv.key, buffer, buffer );

		/* XOR the buffer contents with the IV */
		for( i = 0; i < SKIPJACK_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( cryptInfo->ctxConv.currentIV, temp, SKIPJACK_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += SKIPJACK_BLOCKSIZE;
		}

	/* Clear the temporary buffer */
	zeroise( temp, SKIPJACK_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CFB mode */

int skipjackEncryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = SKIPJACK_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > SKIPJACK_BLOCKSIZE ) ? SKIPJACK_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		skipjackEncrypt( cryptInfo->ctxConv.key, cryptInfo->ctxConv.currentIV,
						 cryptInfo->ctxConv.currentIV );

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
	cryptInfo->ctxConv.ivCount = ( ivCount % SKIPJACK_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in CFB mode.  Note that the transformation can be made
   faster (but less clear) with temp = buffer, buffer ^= iv, iv = temp
   all in one loop */

int skipjackDecryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BYTE temp[ SKIPJACK_BLOCKSIZE ];
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = SKIPJACK_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > SKIPJACK_BLOCKSIZE ) ? SKIPJACK_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		skipjackEncrypt( cryptInfo->ctxConv.key, cryptInfo->ctxConv.currentIV,
						 cryptInfo->ctxConv.currentIV );

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
	cryptInfo->ctxConv.ivCount = ( ivCount % SKIPJACK_BLOCKSIZE );

	/* Clear the temporary buffer */
	zeroise( temp, SKIPJACK_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in OFB mode */

int skipjackEncryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = SKIPJACK_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > SKIPJACK_BLOCKSIZE ) ? SKIPJACK_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		skipjackEncrypt( cryptInfo->ctxConv.key, cryptInfo->ctxConv.currentIV,
						 cryptInfo->ctxConv.currentIV );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ctxConv.ivCount = ( ivCount % SKIPJACK_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in OFB mode */

int skipjackDecryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = SKIPJACK_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > SKIPJACK_BLOCKSIZE ) ? SKIPJACK_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		skipjackEncrypt( cryptInfo->ctxConv.key, cryptInfo->ctxConv.currentIV,
						 cryptInfo->ctxConv.currentIV );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ctxConv.ivCount = ( ivCount % SKIPJACK_BLOCKSIZE );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Skipjack Key Management Routines				*
*																			*
****************************************************************************/

/* Key schedule a Skipjack key */

int skipjackInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength )
	{
	/* Copy the key to internal storage */
	if( cryptInfo->ctxConv.userKey != key )
		memcpy( cryptInfo->ctxConv.userKey, key, keyLength );
	cryptInfo->ctxConv.userKeyLength = keyLength;

	/* In theory Skipjack doesn't require a key schedule so we could just
	   copy the user key across, however the optimised version preprocesses
	   the keying data to save an XOR on each F-table access */
	skipjackMakeKey( ( BYTE * ) key, cryptInfo->ctxConv.key );
	return( CRYPT_OK );
	}
