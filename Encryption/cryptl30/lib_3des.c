/****************************************************************************
*																			*
*					cryptlib Triple DES Encryption Routines					*
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

#define DES_BLOCKSIZE	8

#ifdef INC_ALL
  #include "testdes.h"
#else
  #include "crypt/testdes.h"
#endif /* Compiler-specific includes */

/* A structure to hold the keyscheduled DES keys */

typedef struct {
	Key_schedule desKey1;			/* The first DES key */
	Key_schedule desKey2;			/* The second DES key */
	Key_schedule desKey3;			/* The third DES key */
	} DES3_KEY;

/* The size of the keyscheduled DES and 3DES keys */

#define DES_KEYSIZE		sizeof( Key_schedule )
#define DES3_KEYSIZE	sizeof( DES3_KEY )

/****************************************************************************
*																			*
*								3DES Self-test Routines						*
*																			*
****************************************************************************/

/* Test the DES implementation against the test vectors given in NBS Special
   Publication 800-20, 1999 (which are actually the same as 500-20, 1980,
   since they require that K1 = K2 = K3, but we do it anyway so we can claim
   compliance) */

static int des3TestLoop( DES_TEST *testData, int iterations )
	{
	BYTE temp[ DES_BLOCKSIZE ];
	BYTE key1[ DES_KEYSIZE ], key2[ DES_KEYSIZE ], key3[ DES_KEYSIZE ];
	int i;

	for( i = 0; i < iterations; i++ )
		{
		memcpy( temp, testData[ i ].plaintext, DES_BLOCKSIZE );

		key_sched( ( C_Block * ) testData[ i ].key,
				   *( ( Key_schedule * ) key1 ) );
		key_sched( ( C_Block * ) testData[ i ].key,
				   *( ( Key_schedule * ) key2 ) );
		key_sched( ( C_Block * ) testData[ i ].key,
				   *( ( Key_schedule * ) key3 ) );
		des_ecb3_encrypt( ( C_Block * ) temp, ( C_Block * ) temp,
						  *( ( Key_schedule * ) key1 ), 
						  *( ( Key_schedule * ) key2 ), 
						  *( ( Key_schedule * ) key3 ), DES_ENCRYPT );
		if( memcmp( testData[ i ].ciphertext, temp, DES_BLOCKSIZE ) )
			return( CRYPT_ERROR );
		}

	return( CRYPT_OK );
	}

int des3SelfTest( void )
	{
	int status = CRYPT_OK;

	/* Since the self-test uses weak keys, we have to turn off the checking
	   for key parity errors and weak keys until it's completed */
	des_check_key = FALSE;

	/* Check the 3DES test vectors */
	if( ( des3TestLoop( testIP, sizeof( testIP ) / sizeof( DES_TEST ) ) != CRYPT_OK ) || \
		( des3TestLoop( testVP, sizeof( testVP ) / sizeof( DES_TEST ) ) != CRYPT_OK ) || \
		( des3TestLoop( testKP, sizeof( testKP ) / sizeof( DES_TEST ) ) != CRYPT_OK ) || \
		( des3TestLoop( testRS, sizeof( testRS ) / sizeof( DES_TEST ) ) != CRYPT_OK ) || \
		( des3TestLoop( testDP, sizeof( testDP ) / sizeof( DES_TEST ) ) != CRYPT_OK ) || \
		( des3TestLoop( testSB, sizeof( testSB ) / sizeof( DES_TEST ) ) != CRYPT_OK ) )
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

int des3Init( CRYPT_INFO *cryptInfo )
	{
	int status;

	/* Allocate memory for the keyscheduled keys */
	if( ( status = krnlMemalloc( &cryptInfo->ctxConv.key, DES3_KEYSIZE ) ) != CRYPT_OK )
		return( status );
	cryptInfo->ctxConv.keyLength = DES3_KEYSIZE;

	return( CRYPT_OK );
	}

int des3End( CRYPT_INFO *cryptInfo )
	{
	/* Free any allocated memory */
	krnlMemfree( &cryptInfo->ctxConv.key );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							3DES En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt/decrypt data in ECB mode */

int des3EncryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->ctxConv.key;
	int blockCount = noBytes / DES_BLOCKSIZE;

	while( blockCount-- )
		{
		/* Encrypt a block of data */
		des_ecb3_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer,
						  des3Key->desKey1, des3Key->desKey2,
						  des3Key->desKey3, DES_ENCRYPT );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

int des3DecryptECB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->ctxConv.key;
	int blockCount = noBytes / DES_BLOCKSIZE;

	while( blockCount-- )
		{
		/* Decrypt a block of data */
		des_ecb3_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer,
						  des3Key->desKey1, des3Key->desKey2,
						  des3Key->desKey3, DES_DECRYPT );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CBC mode */

int des3EncryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->ctxConv.key;
#if 0
	int blockCount = noBytes / DES_BLOCKSIZE;

	while( blockCount-- )
		{
		int i;

		/* XOR the buffer contents with the IV */
		for( i = 0; i < DES_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Encrypt a block of data */
		des_ecb3_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer,
						  des3Key->desKey1, des3Key->desKey2,
						  des3Key->desKey3, DES_ENCRYPT );

		/* Shift ciphertext into IV */
		memcpy( cryptInfo->currentIV, buffer, DES_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}
#endif
	/* Encrypt the buffer of data */
	des_ede3_cbc_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer, noBytes,
						  des3Key->desKey1, des3Key->desKey2, des3Key->desKey3,
						  ( C_Block * ) cryptInfo->ctxConv.currentIV,
						  DES_ENCRYPT );

	return( CRYPT_OK );
	}

int des3DecryptCBC( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->ctxConv.key;
#if 0
	BYTE temp[ DES_BLOCKSIZE ];
	int blockCount = noBytes / DES_BLOCKSIZE;

	while( blockCount-- )
		{
		int i;

		/* Save the ciphertext */
		memcpy( temp, buffer, DES_BLOCKSIZE );

		/* Decrypt a block of data */
		des_ecb3_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer,
						  des3Key->desKey1, des3Key->desKey2,
						  des3Key->desKey3, DES_DECRYPT );

		/* XOR the buffer contents with the IV */
		for( i = 0; i < DES_BLOCKSIZE; i++ )
			buffer[ i ] ^= cryptInfo->currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( cryptInfo->currentIV, temp, DES_BLOCKSIZE );

		/* Move on to next block of data */
		buffer += DES_BLOCKSIZE;
		}

	/* Clear the temporary buffer */
	zeroise( temp, DES_BLOCKSIZE );
#endif
	/* Encrypt the buffer of data */
	des_ede3_cbc_encrypt( ( C_Block * ) buffer, ( C_Block * ) buffer, noBytes,
						  des3Key->desKey1, des3Key->desKey2, des3Key->desKey3,
						  ( C_Block * ) cryptInfo->ctxConv.currentIV,
						  DES_DECRYPT );

	return( CRYPT_OK );
	}

/* Encrypt/decrypt data in CFB mode */

int des3EncryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->ctxConv.key;
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
		des_ecb3_encrypt( ( C_Block * ) cryptInfo->ctxConv.currentIV,
						  ( C_Block * ) cryptInfo->ctxConv.currentIV,
						  des3Key->desKey1, des3Key->desKey2,
						  des3Key->desKey3, DES_ENCRYPT );

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

/* Decrypt data in CFB mode.  Note that the transformation can be made
   faster (but less clear) with temp = buffer, buffer ^= iv, iv = temp
   all in one loop */

int des3DecryptCFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->ctxConv.key;
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
		des_ecb3_encrypt( ( C_Block * ) cryptInfo->ctxConv.currentIV,
						  ( C_Block * ) cryptInfo->ctxConv.currentIV,
						  des3Key->desKey1, des3Key->desKey2,
						  des3Key->desKey3, DES_ENCRYPT );

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

int des3EncryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->ctxConv.key;
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
		des_ecb3_encrypt( ( C_Block * ) cryptInfo->ctxConv.currentIV,
						  ( C_Block * ) cryptInfo->ctxConv.currentIV,
						  des3Key->desKey1, des3Key->desKey2,
						  des3Key->desKey3, DES_ENCRYPT );

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

/* Decrypt data in OFB mode */

int des3DecryptOFB( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->ctxConv.key;
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
		des_ecb3_encrypt( ( C_Block * ) cryptInfo->ctxConv.currentIV,
						  ( C_Block * ) cryptInfo->ctxConv.currentIV,
						  des3Key->desKey1, des3Key->desKey2,
						  des3Key->desKey3, DES_ENCRYPT );

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
*							3DES Key Management Routines						*
*																			*
****************************************************************************/

/* Key schedule two/three DES keys */

int des3InitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength )
	{
	DES3_KEY *des3Key = ( DES3_KEY * ) cryptInfo->ctxConv.key;
	BOOLEAN useEDE = FALSE;

	/* Copy the key to internal storage */
	if( cryptInfo->ctxConv.userKey != key )
		memcpy( cryptInfo->ctxConv.userKey, key, keyLength );
	cryptInfo->ctxConv.userKeyLength = keyLength;

	/* Check the key size.  This gets a bit complicated because although we
	   follow X9.52 and default to three-key triple DES, we'll often be
	   passed a 128 (112)-bit key which was common in older designs.  If this
	   happens we take the 112-bit key and repeat the first 56 bits to create
	   a 168-bit key.  X9.52 says that if the caller wants EDE behaviour they
	   have to set it up themselves using a full 168-bit key, but this will
	   cause problems for people using the high-level functions which don't
	   allow this level of control, so if we're passed a 112-bit key we just
	   expand it out to 168 bits to get two-key EDE */
	if( keyLength <= bitsToBytes( 64 * 2 ) )
		useEDE = TRUE;	/* Only 112 bits of key, force EDE mode */

	/* Call the libdes key schedule code.  Returns with -1 if the key parity
	   is wrong (which never occurs since we force the correct parity) or -2
	   if a weak key is used */
	des_set_odd_parity( ( C_Block * ) cryptInfo->ctxConv.userKey );
	if( key_sched( ( des_cblock * ) cryptInfo->ctxConv.userKey,
				   des3Key->desKey1 ) )
		return( CRYPT_ARGERROR_STR1 );
	des_set_odd_parity( ( C_Block * ) ( ( BYTE * ) cryptInfo->ctxConv.userKey + bitsToBytes( 64 ) ) );
	if( key_sched( ( des_cblock * ) ( ( BYTE * ) cryptInfo->ctxConv.userKey + bitsToBytes( 64 ) ),
				   des3Key->desKey2 ) )
		return( CRYPT_ARGERROR_STR1 );
	if( useEDE )
		/* Rather than performing another key schedule, we just copy the first
		   scheduled key into the third one */
		memcpy( des3Key->desKey3, des3Key->desKey1, DES_KEYSIZE );
	else
		{
		des_set_odd_parity( ( C_Block * ) ( ( BYTE * ) cryptInfo->ctxConv.userKey + bitsToBytes( 128 ) ) );
		if( key_sched( ( des_cblock * ) ( ( BYTE * ) cryptInfo->ctxConv.userKey + bitsToBytes( 128 ) ),
					   des3Key->desKey3 ) )
			return( CRYPT_ARGERROR_STR1 );
		}

	return( CRYPT_OK );
	}
