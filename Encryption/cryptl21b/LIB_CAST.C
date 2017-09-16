/****************************************************************************
*																			*
*					  cryptlib CAST-128 Encryption Routines					*
*						Copyright Peter Gutmann 1996-1997					*
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
  #include "cast.h"
#else
  #include "crypt/cast.h"
#endif /* Compiler-specific includes */

/* Defines to map from EAY to native naming */

#define CAST_BLOCKSIZE		CAST_BLOCK

/* The size of the keyscheduled CAST key */

#define CAST_EXPANDED_KEYSIZE	sizeof( CAST_KEY )

/****************************************************************************
*																			*
*								CAST Self-test Routines						*
*																			*
****************************************************************************/

/* CAST test vectors from CAST specification */

static struct CAST_TEST {
	BYTE key[ CAST_KEY_LENGTH ];
	BYTE plainText[ CAST_BLOCKSIZE ];
	BYTE cipherText[ CAST_BLOCKSIZE ];
	} testCAST[] = {
	{ { 0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78,
		0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A },
	  { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF },
	  { 0x23, 0x8B, 0x4F, 0xE5, 0x84, 0x7E, 0x44, 0xB2 } }
	};

/* Test the CAST code against the CAST test vectors */

int castSelfTest( void )
	{
	BYTE temp[ CAST_BLOCKSIZE ];
	CAST_KEY castKey;
	int i;

	for( i = 0; i < sizeof( testCAST ) / sizeof( struct CAST_TEST ); i++ )
		{
		memcpy( temp, testCAST[ i ].plainText, CAST_BLOCKSIZE );
		CAST_set_key( &castKey, CAST_KEY_LENGTH, testCAST[ i ].key );
		CAST_ecb_encrypt( temp, temp, &castKey, CAST_ENCRYPT );
		if( memcmp( testCAST[ i ].cipherText, temp, CAST_BLOCKSIZE ) )
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

int castInit( CRYPT_INFO *cryptInfo, void *cryptInfoEx )
	{
	int status;

	UNUSED( cryptInfoEx );

	/* Allocate memory for the key and the algorithm-specific data within
	   the crypt context and set up any pointers we need */
	if( cryptInfo->ctxConv.key != NULL )
		return( CRYPT_INITED );
	if( ( status = krnlMemalloc( &cryptInfo->ctxConv.key, CAST_EXPANDED_KEYSIZE ) ) != CRYPT_OK )
		return( status );
	cryptInfo->ctxConv.keyLength = CAST_EXPANDED_KEYSIZE;

	return( CRYPT_OK );
	}

int castEnd( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	krnlMemfree( &cryptInfo->ctxConv.key );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							CAST En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt/decrypt data in ECB mode */

int castEncryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	int blockCount = noBytes / CAST_BLOCKSIZE;

	while( blockCount-- )
		{
		/* Encrypt a block of data */
		CAST_ecb_encrypt( buffer, buffer, cryptInfo->ctxConv.key, CAST_ENCRYPT );

		/* Move on to next block of data */
		buffer += CAST_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int castDecryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	int blockCount = noBytes / CAST_BLOCKSIZE;

	while( blockCount-- )
		{
		/* Decrypt a block of data */
		CAST_ecb_encrypt( buffer, buffer, cryptInfo->ctxConv.key, CAST_DECRYPT );

		/* Move on to next block of data */
		buffer += CAST_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CBC mode */

int castEncryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
#if 0
#ifdef ASM_X86
	if( noBytes )	/* CAST asm code doesn't like 0-length blocks */
		castEncryptCBC86( buffer, buffer, noBytes, cryptInfo->ctxConv.key,
						  cryptInfo->ctxConv.currentIV );
#else
	int blockCount = noBytes / CAST_BLOCKSIZE;

	while( blockCount-- )
		{
		int i;

		/* XOR the buffer contents with the IV */
		for( i = 0; i < CAST_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Encrypt a block of data */
		CAST_ecb_encrypt( buffer, buffer, cryptInfo->ctxConv.key, CAST_ENCRYPT );

		/* Shift ciphertext into IV */
		memcpy( cryptInfo->ctxConv.currentIV, buffer, CAST_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += CAST_BLOCKSIZE;
		}
#endif /* ASM_X86 */
#endif
	CAST_cbc_encrypt( buffer, buffer, noBytes, cryptInfo->ctxConv.key,
					  cryptInfo->ctxConv.currentIV, CAST_ENCRYPT );

	return( CRYPT_OK );
	}

int castDecryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
#if 0
#ifdef ASM_X86
	if( noBytes )	/* CAST asm code doesn't like 0-length blocks */
		castDecryptCBC86( buffer, buffer, noBytes, cryptInfo->ctxConv.key,
						  cryptInfo->ctxConv.currentIV );
#else
	BYTE temp[ CAST_BLOCKSIZE ];
	int blockCount = noBytes / CAST_BLOCKSIZE;

	while( blockCount-- )
		{
		int i;

		/* Save the ciphertext */
		memcpy( temp, buffer, CAST_BLOCKSIZE );

		/* Decrypt a block of data */
		CAST_ecb_encrypt( buffer, buffer, cryptInfo->ctxConv.key, CAST_DECRYPT );

		/* XOR the buffer contents with the IV */
		for( i = 0; i < CAST_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( cryptInfo->ctxConv.currentIV, temp, CAST_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += CAST_BLOCKSIZE;
		}

	/* Clear the temporary buffer */
	zeroise( temp, CAST_BLOCKSIZE );
#endif /* ASM_X86 */
#endif
	CAST_cbc_encrypt( buffer, buffer, noBytes, cryptInfo->ctxConv.key,
					  cryptInfo->ctxConv.currentIV, CAST_DECRYPT );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CFB mode */

int castEncryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = CAST_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > CAST_BLOCKSIZE ) ? CAST_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		CAST_ecb_encrypt( cryptInfo->ctxConv.currentIV,
						  cryptInfo->ctxConv.currentIV,
						  cryptInfo->ctxConv.key,
						  CAST_ENCRYPT );

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
	cryptInfo->ctxConv.ivCount = ( ivCount % CAST_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in CFB mode.  Note that the transformation can be made
   faster (but less clear) with temp = buffer, buffer ^= iv, iv = temp
   all in one loop */

int castDecryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BYTE temp[ CAST_BLOCKSIZE ];
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = CAST_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > CAST_BLOCKSIZE ) ? CAST_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		CAST_ecb_encrypt( cryptInfo->ctxConv.currentIV,
						  cryptInfo->ctxConv.currentIV,
						  cryptInfo->ctxConv.key, CAST_ENCRYPT );

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
	cryptInfo->ctxConv.ivCount = ( ivCount % CAST_BLOCKSIZE );

	/* Clear the temporary buffer */
	zeroise( temp, CAST_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in OFB mode */

int castEncryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = CAST_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > CAST_BLOCKSIZE ) ? CAST_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		CAST_ecb_encrypt( cryptInfo->ctxConv.currentIV,
						  cryptInfo->ctxConv.currentIV,
						  cryptInfo->ctxConv.key, CAST_ENCRYPT );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ctxConv.ivCount = ( ivCount % CAST_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Decrypt data in OFB mode */

int castDecryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = CAST_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > CAST_BLOCKSIZE ) ? CAST_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		CAST_ecb_encrypt( cryptInfo->ctxConv.currentIV,
						  cryptInfo->ctxConv.currentIV,
						  cryptInfo->ctxConv.key, CAST_ENCRYPT );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ctxConv.ivCount = ( ivCount % CAST_BLOCKSIZE );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							CAST Key Management Routines					*
*																			*
****************************************************************************/

/* Key schedule an CAST key */

int castInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength )
	{
	/* Copy the key to internal storage */
	if( cryptInfo->ctxConv.userKey != key )
		memcpy( cryptInfo->ctxConv.userKey, key, keyLength );
	cryptInfo->ctxConv.userKeyLength = keyLength;

	CAST_set_key( cryptInfo->ctxConv.key, CAST_KEY_LENGTH, ( BYTE * ) key );
	return( CRYPT_OK );
	}
