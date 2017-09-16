/****************************************************************************
*																			*
*						cryptlib DES Encryption Routines					*
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
  #include "des.h"
#else
  #include "crypt/des.h"
#endif /* Compiler-specific includes */

/* The DES block size */

#define DES_BLOCKSIZE			8

#ifdef INC_ALL
  #include "testdes.h"
#else
  #include "crypt/testdes.h"
#endif /* Compiler-specific includes */

/* The scheduled DES key and size of the keyscheduled DES key */

#define DES_KEY					Key_schedule
#define DES_KEYSIZE				sizeof( Key_schedule )

/****************************************************************************
*																			*
*							DES Self-test Routines							*
*																			*
****************************************************************************/

/* Test the DES implementation against the test vectors given in NBS Special
   Publication 500-20, 1980 */

static int desTestLoop( DES_TEST *testData, int iterations, int operation )
	{
	BYTE temp[ DES_BLOCKSIZE ];
	BYTE key[ DES_KEYSIZE ];
	int i;

	for( i = 0; i < iterations; i++ )
		{
		memcpy( temp, testData[ i ].plaintext, DES_BLOCKSIZE );
		key_sched( ( C_Block * ) testData[ i ].key,
				   *( ( Key_schedule * ) key ) );
		des_ecb_encrypt( ( C_Block * ) temp, ( C_Block * ) temp,
						 *( ( Key_schedule * ) key ), operation );
		if( memcmp( testData[ i ].ciphertext, temp, DES_BLOCKSIZE ) )
			return( CRYPT_ERROR );
		}

	return( CRYPT_OK );
	}

int desSelfTest( void )
	{
	int status = CRYPT_OK;

	/* Since the self-test uses weak keys, we have to turn off the checking
	   for key parity errors and weak keys until it's completed */
	des_check_key = FALSE;

	/* Check the DES test vectors */
	if( ( desTestLoop( testIP, sizeof( testIP ) / sizeof( DES_TEST ),
					   DES_ENCRYPT ) != CRYPT_OK ) || \
		( desTestLoop( testVP, sizeof( testVP ) / sizeof( DES_TEST ),
					   DES_ENCRYPT ) != CRYPT_OK ) || \
		( desTestLoop( testKP, sizeof( testKP ) / sizeof( DES_TEST ),
					   DES_ENCRYPT ) != CRYPT_OK ) || \
		( desTestLoop( testRS, sizeof( testRS ) / sizeof( DES_TEST ),
					   DES_DECRYPT ) != CRYPT_OK ) || \
		( desTestLoop( testDP, sizeof( testDP ) / sizeof( DES_TEST ),
					   DES_ENCRYPT ) != CRYPT_OK ) || \
		( desTestLoop( testSB, sizeof( testSB ) / sizeof( DES_TEST ),
					   DES_ENCRYPT ) != CRYPT_OK ) )
		status = CRYPT_ERROR;

	/* Reenable checking for key parity errors and weak keys */
	des_check_key = TRUE;

	return( status );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Routines							*
*																			*
****************************************************************************/

/* Perform init and shutdown actions on an encryption context */

int desInit( CRYPT_INFO *cryptInfo )
	{
	int status;

	/* Allocate memory for the keyscheduled key */
	if( ( status = krnlMemalloc( &cryptInfo->ctxConv.key, DES_KEYSIZE ) ) != CRYPT_OK )
		return( status );
	cryptInfo->ctxConv.keyLength = DES_KEYSIZE;

	return( CRYPT_OK );
	}

int desEnd( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	krnlMemfree( &cryptInfo->ctxConv.key );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							DES En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt/decrypt data in ECB mode */

int desEncryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	int blockCount = noBytes / DES_BLOCKSIZE;

	while( blockCount-- )
		{
		/* Encrypt a block of data */
		des_ecb_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer, 
						 *( DES_KEY * ) cryptInfo->ctxConv.key, DES_ENCRYPT );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int desDecryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	int blockCount = noBytes / DES_BLOCKSIZE;

	while( blockCount-- )
		{
		/* Decrypt a block of data */
		des_ecb_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer, 
						 *( DES_KEY * ) cryptInfo->ctxConv.key, DES_DECRYPT );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CBC mode */

int desEncryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	/* Encrypt the buffer of data */
	des_ncbc_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer, noBytes,
					  *( DES_KEY * ) cryptInfo->ctxConv.key,
					  ( C_Block * ) cryptInfo->ctxConv.currentIV, DES_ENCRYPT );

	return( CRYPT_OK );
	}

int desDecryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	/* Encrypt the buffer of data */
	des_ncbc_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer, noBytes,
					  *( DES_KEY * ) cryptInfo->ctxConv.key,
					  ( C_Block * ) cryptInfo->ctxConv.currentIV, DES_DECRYPT );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CFB mode */

int desEncryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = DES_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > DES_BLOCKSIZE ) ? DES_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		des_ecb_encrypt( ( C_Block * ) cryptInfo->ctxConv.currentIV,
						 ( C_Block * ) cryptInfo->ctxConv.currentIV,
						 *( DES_KEY * ) cryptInfo->ctxConv.key, DES_ENCRYPT );

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
	cryptInfo->ctxConv.ivCount = ( ivCount % DES_BLOCKSIZE );

	return( CRYPT_OK );
	}

int desDecryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BYTE temp[ DES_BLOCKSIZE ];
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = DES_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > DES_BLOCKSIZE ) ? DES_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		des_ecb_encrypt( ( C_Block * ) cryptInfo->ctxConv.currentIV,
						 ( C_Block * ) cryptInfo->ctxConv.currentIV,
						 *( DES_KEY * ) cryptInfo->ctxConv.key, DES_ENCRYPT );

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
	cryptInfo->ctxConv.ivCount = ( ivCount % DES_BLOCKSIZE );

	/* Clear the temporary buffer */
	zeroise( temp, DES_BLOCKSIZE );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in OFB mode */

int desEncryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = DES_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > DES_BLOCKSIZE ) ? DES_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		des_ecb_encrypt( ( C_Block * ) cryptInfo->ctxConv.currentIV,
						 ( C_Block * ) cryptInfo->ctxConv.currentIV,
						 *( DES_KEY * ) cryptInfo->ctxConv.key, DES_ENCRYPT );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ctxConv.ivCount = ( ivCount % DES_BLOCKSIZE );

	return( CRYPT_OK );
	}

int desDecryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	int i, ivCount = cryptInfo->ctxConv.ivCount;

	/* If there's any encrypted material left in the IV, use it now */
	if( ivCount )
		{
		int bytesToUse;

		/* Find out how much material left in the encrypted IV we can use */
		bytesToUse = DES_BLOCKSIZE - ivCount;
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
		ivCount = ( noBytes > DES_BLOCKSIZE ) ? DES_BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		des_ecb_encrypt( ( C_Block * ) cryptInfo->ctxConv.currentIV,
						 ( C_Block * ) cryptInfo->ctxConv.currentIV,
						 *( DES_KEY * ) cryptInfo->ctxConv.key, DES_ENCRYPT );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= cryptInfo->ctxConv.currentIV[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}

	/* Remember how much of the IV is still available for use */
	cryptInfo->ctxConv.ivCount = ( ivCount % DES_BLOCKSIZE );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							DES Key Management Routines						*
*																			*
****************************************************************************/

/* Key schedule a DES key */

int desInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength )
	{
	/* Copy the key to internal storage */
	if( cryptInfo->ctxConv.userKey != key )
		memcpy( cryptInfo->ctxConv.userKey, key, keyLength );
	cryptInfo->ctxConv.userKeyLength = keyLength;

	/* Call the libdes key schedule code.  Returns with -1 if the key parity
	   is wrong (which never occurs since we force the correct parity) or -2
	   if a weak key is used */
	des_set_odd_parity( ( C_Block * ) cryptInfo->ctxConv.userKey );
	if( key_sched( ( C_Block * ) cryptInfo->ctxConv.userKey, 
				   *( DES_KEY * ) cryptInfo->ctxConv.key ) )
		return( CRYPT_ARGERROR_STR1 );

	return( CRYPT_OK );
	}
