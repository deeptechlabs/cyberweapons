/* Compile options:

   -DTEST_VERSION compiles the test version, which encrypts sample data/keys.
   -DTIME_TRIAL compiles a version which encrypts 10MB of data in CFB mode
				for timing tests.
   -DSETUP_TRIAL compiles a version which performs the password/S-box setup
				 repeatedly for brute-force crack timing tests.
   -DUSE_CBC compiles a simple encryption program using CBC mode.
   (no define) compiles a simple encryption program using CFB mode.

   -DSHOW_SBOXES displays the S-Boxes for each key.

   -DASM_ENCRYPT includes extra code for the 80x86 16-bit fast encrypt()
				 routine.
   -DASM_ENCRYPT32 includes extra code for the 80x86 32-bit even faster
				   encrypt() routine.
	Note that these asm routines are meant to be used in CFB mode, and
	neither have the code for CBC handling, however this is very simple to
	add */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "nsea.h"

/* The S-Box variables */

BYTE *tempKey;				/* The temporary key used to set up the S-Boxes */
#if defined( ASM_ENCRYPT ) || defined( ASM_ENCRYPT_32 )
  WORD sBoxBase;			/* S-Box segment address */
  LONG *sBoxAddress;		/* Non-adjusted S-Box address */
#else
  LONG *sBoxes1, *sBoxes2;	/* The S-Boxes themselves */
#endif /* ASM_ENCRYPT || ASM_ENCRYPT_32 */

/* Macros to handle rotation of 64-bit quantities */

LONG rotTemp;		/* Temporary value for rotations */

#define rotl(A,B)	rotTemp = A >> 24; \
					A = ( A << 8 ) | ( B >> 24 ); \
					B = ( B << 8 ) | rotTemp;
#define rotr(A,B)	rotTemp = B << 24; \
					B = ( B >> 8 ) | ( A << 24 ); \
					A = ( A >> 8 ) | rotTemp;

/* Define the following for CBC mode.  Note that CBC should not be defined
   if CFB mode is being used since the CFB encryption works as:

   buffer ^= e( CFB-iv ), CFB-iv = buffer

   which means that the CBC-iv's are simply the unencrypted buffer xor'd
   with the previous contents of the encrypted buffer.  When there are
   repeated blocks of data and the two are xor'd as part of the CBC process
   the original plaintext is recovered... */

#ifdef TEST_VERSION	/* If we're running test code, we need to use CBC mode */
  #define USE_CBC
#endif /* TEST_VERSION */

/* The values used for cipher block chaining (since we are overlapping
   encrypts and decrypts we need two left and right values, one for
   encryption and one for decryption; in practice only one set of values
   is necessary) */

#ifdef USE_CBC
  LONG ivLLeft1, ivRLeft1, ivLRight1, ivRRight1;
  LONG ivLLeft2, ivRLeft2, ivLRight2, ivRRight2;
#endif /* USE_CBC */

/* Information needed in CFB mode:  The IV, the encrypted IV, and the count
   of bytes already processed in the current block */

BYTE iv[ BLOCKSIZE ];			/* CFB initialization vector */
BYTE temp[ BLOCKSIZE ];			/* Encrypted IV */
int ivCount;					/* Count of bytes used in block */

/* Define the following to perform two rounds of encryption for each data
   block.  This may be desirable since for one-round encryption each step of
   the process is affected by a single byte of plaintext, so it would be
   possible to work backwards from the last byte of plaintext encrypted to
   reverse-engineer the contents of the S-Boxes.

   A further enhancement to this scheme is to use multiple sets of S-Boxes,
   one set for each round of encryption (you could go to three, four, five
   etc rounds) */

#define TWO_ROUNDS

/****************************************************************************
*																			*
*				NSEA Key Generation and Encryption Routines					*
*																			*
****************************************************************************/

/* The initial, standardised S-boxes are generated using a linear
   congruential random number generator (LCRNG).  These can be set to any
   pseudorandom value, as long as they are always the same.  An LCRNG is used
   since it's a well-known method.  The values used in the LCRNG have been
   chosen for their pessimality to avoid the use of shortcut forms, forcing
   the use of a multiply and divide to slow down the generation of numbers.
   The generator itself is initialised to a random value (salt) based on the
   key (to avoid the possibility of speeding up a brute-force attack by using
   precalculated S-boxes) and a 32-bit pseudorandom value (to make sure the
   encrypted data is different each time and thus avoid traffic analysis).

   From the standard set of S-boxes, a new set is generated with a far better
   pseudo-random number generator, namely NSEA encrypting the encryption key
   using the initial S-boxes.  The output from the NSEA pseudo-random number
   generator is then used to build a new set of S-boxes which are dependant
   on the encryption key used.  These replace the first set as the working
   S-boxes

   This method of key setup makes encryption fast and brute-force attacks
   slow and painful.  Once the S-boxes are set up, en/decryption proceeds at
   a fairly rapid pace, however if the key is changed constantly (as it
   would be for a brute-force attack) a lot of time is spent in rebuilding
   the S-boxes after each key change.  The key setup has in fact been
   pessimized to perform badly even on high-performance systems, since it is
   non-parallelizable (each S-box permutation operation depends on all
   preceding permutation operations), and due to the constant memory
   accesses as the S-boxes are set up will run slowly even on normally fast
   RISC systems.

   When we generate random data by encrypting the key, we prepend the key
   length in big-endian form to the seed value (ie the user key) to make sure
   the algorithm is sensitive to the length of the key */

#define initRnd(salt)	lcrngNumber = salt;		/* Initialise LCRNG */

WORD lcrngNumber;

WORD rnd( void );

#if !defined( ASM_ENCRYPT ) && !defined( ASM_ENCRYPT_32 )

#ifdef SHOW_SBOXES

/* Show the S-Boxes */

static void showSBoxes( void )
	{
	int i, j;

	putchar( '\n' );
	for( i = 0; i < 64; i++ )
		{
		for( j = 0; j < 4; j++ )
			printf( "%08lX%08lX ", \
					sBoxes1[ ( i * 4 ) + j ], sBoxes2[ ( i * 4 ) + j ] );
		putchar( '\n' );
		}
	}

#endif /* SHOW_SBOXES */

/* Set up the S-Boxes */

static WORD rnd( void )
	{
	/*				(	   X      *    a     + c ) mod m	*/
	lcrngNumber = ( ( lcrngNumber * 23311L ) + 1 ) % 65533U;

	return( lcrngNumber );
	}

/* Set up initial S-Box to be n columns of 0..255 */

static void setInitialSBox( BYTE *sBox )
	{
	int i, j, index = 0;

	for( i = 0; i < 256; i++ )
		for( j = 0; j < sizeof( LONG ); j++ )
			sBox[ index++ ] = i;
	}

/* Set up the initial tempKey */

static void initTempKey( BYTE *key, int keyLength, WORD salt, BYTE *tempKeyPtr )
	{
	int i;

	/* Generate the salt and initialise the LCRNG */
	while( keyLength-- )
		salt = ( salt << 1 ) ^ *key++;
	initRnd( salt );

	/* Initialize tempKey with pseudorandom values */
	for( i = 0; i < SBOX_SIZE; i++ )
		*tempKeyPtr++ = ( BYTE ) ( rnd() >> 8 );
	}

/* Permute an sBox based on the values in tempKey */

static void permuteSBox( BYTE *sBox, int tempKeyIndex )
	{
	static int columnTable[] = { 0, 256, 512, 768 };
	int srcIndex, destIndex;
	BYTE temp;

	for( srcIndex = 0; srcIndex < SBOX_SIZE; srcIndex++ )
		{
		destIndex = tempKey[ tempKeyIndex++ ] + columnTable[ srcIndex & 3 ];

		temp = sBox[ srcIndex ];
		sBox[ srcIndex ] = sBox[ destIndex ];
		sBox[ destIndex ] = temp;
		}
	}

void initSBoxes( BYTE *key, int keyLength, const LONG salt )
	{
	BYTE *sBoxByte1 = ( BYTE * ) sBoxes1, *sBoxByte2 = ( BYTE * ) sBoxes2;
#ifdef USE_CBC
	int i;
#endif /* USE_CBC */

	/* Set up initial sBoxes */
	setInitialSBox( sBoxByte1 );
	setInitialSBox( sBoxByte2 );

	/* Generate the initial tempKey, mixing in the 32-bit salt */
	initTempKey( key, keyLength, ( WORD ) salt, tempKey );
	initTempKey( key, keyLength, ( WORD ) ( salt >> 16 ), tempKey + SBOX_SIZE );

	/* Permute the S-Boxes in a pseudo-random manner */
	permuteSBox( sBoxByte1, 0 );
	permuteSBox( sBoxByte2, SBOX_SIZE );

#ifdef SHOW_SBOXES
	showSBoxes();
#endif /* SHOW_SBOXES */

	/* Encrypt the key using the standard S-Boxes */
	initIV( salt );
	tempKey[ 0 ] = ( BYTE ) ( keyLength >> 8 );
	tempKey[ 1 ] = ( BYTE ) keyLength;
	memcpy( tempKey + 2, key, keyLength );
	memset( tempKey + 2 + keyLength, 0, ( SBOX_SIZE * 2 ) - ( keyLength + 2 ) );
#ifdef USE_CBC
	for( i = 0; i < 256 * sizeof( LONG ) * 2; i += BLOCKSIZE )
		encrypt( tempKey + i, tempKey + i );
#else
	encryptCFB( tempKey, 256 * sizeof( LONG ) * 2 );
#endif /* USE_CBC */

	/* Reset the initial sBoxes */
	setInitialSBox( sBoxByte1 );
	setInitialSBox( sBoxByte2 );

	/* Permute the sBoxes using the encrypted key as our source of random numbers */
	permuteSBox( sBoxByte1, 0 );
	permuteSBox( sBoxByte2, SBOX_SIZE );

#ifdef SHOW_SBOXES
	showSBoxes();
#endif /* SHOW_SBOXES */
	}
#endif /* !( ASM_ENCRYPT || ASM_ENCRYPT_32 ) */

/* Initialise the encryption system */

void initNSEA( void )
	{
	/* Allocate the S-Boxes and temporary key space */
#if !defined( ASM_ENCRYPT ) && !defined( ASM_ENCRYPT_32 )
	if( ( sBoxes1 = ( LONG * ) malloc( SBOX_SIZE ) ) == NULL || \
		( sBoxes2 = ( LONG * ) malloc( SBOX_SIZE ) ) == NULL || \
		( tempKey = ( BYTE * ) malloc( SBOX_SIZE * 2 ) ) == NULL )
		{
		/* Make sure we dont try and scrub the sBoxes if they aren't set
		   up yet */
		sBoxes1 = NULL;
		puts( "Out of memory" );
		exit( ERROR );
		}
#else
	if( ( sBoxAddress = ( LONG * ) malloc( ( SBOX_SIZE * 2 ) + 16 ) ) == NULL || \
		( tempKey = ( BYTE * ) malloc( SBOX_SIZE * 2 ) ) == NULL )
		{
		/* Make sure we dont try and scrub the sBoxes if they aren't set
		   up yet */
		sBoxAddress = NULL;
		puts( "Out of memory" );
		exit( ERROR );
		}

	/* Fiddle addresses to segment-align them */
	sBoxBase = FP_SEG( sBoxAddress ) + 1;
#endif /* !( ASM_ENCRYPT || ASM_ENCRYPT_32 ) */
	}

/* Shut down the encryption system */

void endNSEA( void )
	{
	/* Scrub the temporary key, sBoxes, and IV and encrypted IV so other
	   users can't find them by examining core after the program has run.
	   We have to check whether sBoxes has been set up since we may be
	   calling this from an error handler which may have been called before
	   initCrypt() has been called */
#if defined( ASM_ENCRYPT ) || defined( ASM_ENCRYPT_32 )
	if( sBoxAddress != NULL )
		{
		memset( sBoxAddress, 0, SBOX_SIZE * 2 );
		memset( tempKey, 0, SBOX_SIZE * 2 );
		free( sBoxAddress );
		free( tempKey );
		}
#else
	if( sBoxes1 != NULL )
		{
		memset( sBoxes1, 0, SBOX_SIZE );
		memset( sBoxes2, 0, SBOX_SIZE );
		memset( tempKey, 0, SBOX_SIZE * 2 );
		free( sBoxes1 );
		free( sBoxes2 );
		free( tempKey );
		}
#endif /* ASM_ENCRYPT || ASM_ENCRYPT_32 */

	memset( iv, 0, BLOCKSIZE );
	memset( temp, 0, BLOCKSIZE );
	}

/* Save and restore the current states of the encryption */

static BYTE savedIV[ BLOCKSIZE ], savedTemp[ BLOCKSIZE ];
static int savedIvCount;

#ifdef USE_CBC
  static LONG savedIvLLeft1, savedIvRLeft1, savedIvLRight1, savedIvRRight1;
  static LONG savedIvLLeft2, savedIvRLeft2, savedIvLRight2, savedIvRRight2;
#endif /* USE_CBC */

void saveCryptState( void )
	{
	memcpy( savedIV, iv, BLOCKSIZE );
	memcpy( savedTemp, temp, BLOCKSIZE );
	savedIvCount = ivCount;
#ifdef USE_CBC
	savedIvLLeft1 = ivLLeft1;
	savedIvRLeft1 = ivRLeft1;
	savedIvLRight1 = ivLRight1;
	savedIvRRight1 = ivRRight1;
	savedIvLLeft2 = ivLLeft2;
	savedIvRLeft2 = ivRLeft2;
	savedIvLRight2 = ivLRight2;
	savedIvRRight2 = ivRRight2;
#endif /* USE_CBC */
	}

void restoreCryptState( void )
	{
	memcpy( iv, savedIV, BLOCKSIZE );
	memcpy( temp, savedTemp, BLOCKSIZE );
	ivCount = savedIvCount;
#ifdef USE_CBC
	ivLLeft1 = savedIvLLeft1;
	ivRLeft1 = savedIvRLeft1;
	ivLRight1 = savedIvLRight1;
	ivRRight1 = savedIvRRight1;
	ivLLeft2 = savedIvLLeft2;
	ivRLeft2 = savedIvRLeft2;
	ivLRight2 = savedIvLRight2;
	ivRRight2 = savedIvRRight2;
#endif /* USE_CBC */
	}

/* Return a random LONG for the IV.  It doesn't matter much what it is, as
   long as it's completely different for each call */

LONG getRandomLong( void )
	{
	static BOOLEAN initialised = FALSE;
	static LONG randomLong;

	if( !initialised )
		{
		/* Seed the data with a value which is guaranteed to be different
		   each time (unless the entire program is rerun more than twice a
		   second, which is doubtful) */
		time( ( time_t * ) &randomLong );
		initialised = TRUE;
		}

	/* Now shuffle the bits.  It would be nice to use NSEA to do this, but
	   it hasn't been set up yet */
	initRnd( ( WORD ) randomLong ^ ( WORD ) ( randomLong >> 16 ) );
	randomLong = ( ( LONG ) rnd() << 16 ) | rnd();
	return( randomLong );
	}

/****************************************************************************
*																			*
*					The NSEA Encryption/Decryption Routines					*
*																			*
****************************************************************************/

#if !defined( ASM_ENCRYPT ) && !defined( ASM_ENCRYPT_32 )

/* This is the core routine used by NSEA, and is a fairly standard method
   used by, for example, the DES.  The input data is broken into two halves
   and each half is alternately used to encrypt the other half */

void encrypt( BYTE *inData, BYTE *outData )
	{
	LONG lLeft = *( ( LONG * ) inData );
	LONG rLeft = *( ( LONG * ) inData + 1 );
	LONG lRight = *( ( LONG * ) inData + 2 );
	LONG rRight = *( ( LONG * ) inData + 3 );

#ifdef USE_CBC
	lLeft ^= ivLLeft1;
	rLeft ^= ivRLeft1;
	lRight ^= ivLRight1;
	rRight ^= ivRRight1;
#endif /* USE_CBC */

	lLeft ^= sBoxes1[ ( BYTE ) lRight ];	/* 1,1 */
	rLeft ^= sBoxes2[ ( BYTE ) rRight ];
	rotl( lRight, rRight );
	lRight ^= sBoxes1[ ( BYTE ) lLeft ];	/* 1, 2 */
	rRight ^= sBoxes2[ ( BYTE ) rLeft ];
	rotl( lLeft, rLeft );
	lLeft ^= sBoxes1[ ( BYTE ) lRight ];	/* 1, 3 */
	rLeft ^= sBoxes2[ ( BYTE ) rRight ];
	rotl( lRight, rRight );
	lRight ^= sBoxes1[ ( BYTE ) lLeft ];	/* 1, 4 */
	rRight ^= sBoxes2[ ( BYTE ) rLeft ];
	rotl( lLeft, rLeft );
	lLeft ^= sBoxes1[ ( BYTE ) lRight ];	/* 1, 5 */
	rLeft ^= sBoxes2[ ( BYTE ) rRight ];
	rotl( lRight, rRight );
	lRight ^= sBoxes1[ ( BYTE ) lLeft ];	/* 1, 6 */
	rRight ^= sBoxes2[ ( BYTE ) rLeft ];
	rotl( lLeft, rLeft );
	lLeft ^= sBoxes1[ ( BYTE ) lRight ];	/* 1, 7 */
	rLeft ^= sBoxes2[ ( BYTE ) rRight ];
	rotl( lRight, rRight );
	lRight ^= sBoxes1[ ( BYTE ) lLeft ];	/* 1, 8 */
	rRight ^= sBoxes2[ ( BYTE ) rLeft ];
	rotl( lLeft, rLeft );
#ifdef TWO_ROUNDS
	lLeft ^= sBoxes1[ ( BYTE ) lRight ];	/* 2, 1 */
	rLeft ^= sBoxes2[ ( BYTE ) rRight ];
	rotl( lRight, rRight );
	lRight ^= sBoxes1[ ( BYTE ) lLeft ];	/* 2, 2 */
	rRight ^= sBoxes2[ ( BYTE ) rLeft ];
	rotl( lLeft, rLeft );
	lLeft ^= sBoxes1[ ( BYTE ) lRight ];	/* 2, 3 */
	rLeft ^= sBoxes2[ ( BYTE ) rRight ];
	rotl( lRight, rRight );
	lRight ^= sBoxes1[ ( BYTE ) lLeft ];	/* 2, 4 */
	rRight ^= sBoxes2[ ( BYTE ) rLeft ];
	rotl( lLeft, rLeft );
	lLeft ^= sBoxes1[ ( BYTE ) lRight ];	/* 2, 5 */
	rLeft ^= sBoxes2[ ( BYTE ) rRight ];
	rotl( lRight, rRight );
	lRight ^= sBoxes1[ ( BYTE ) lLeft ];	/* 2, 6 */
	rRight ^= sBoxes2[ ( BYTE ) rLeft ];
	rotl( lLeft, rLeft );
	lLeft ^= sBoxes1[ ( BYTE ) lRight ];	/* 2, 7 */
	rLeft ^= sBoxes2[ ( BYTE ) rRight ];
	rotl( lRight, rRight );
	lRight ^= sBoxes1[ ( BYTE ) lLeft ];	/* 2, 8 */
	rRight ^= sBoxes2[ ( BYTE ) rLeft ];
	rotl( lLeft, rLeft );
#endif /* TWO_ROUNDS */

#ifdef USE_CBC
	ivLLeft1 = lLeft;
	ivRLeft1 = rLeft;
	ivLRight1 = lRight;
	ivRRight1 = rRight;
#endif /* USE_CBC */

	*( ( LONG * ) outData ) = lLeft;
	*( ( LONG * ) outData + 1 ) = rLeft;
	*( ( LONG * ) outData + 2 ) = lRight;
	*( ( LONG * ) outData + 3 ) = rRight;
	}

#endif /* !( ASM_ENCRYPT || ASM_ENCRYPT_32 ) */

#ifdef USE_CBC

/* Perform the decryption */

void decrypt( BYTE *inData, BYTE *outData )
	{
	LONG lLeft = *( ( LONG * ) inData );
	LONG rLeft = *( ( LONG * ) inData + 1 );
	LONG lRight = *( ( LONG * ) inData + 2 );
	LONG rRight = *( ( LONG * ) inData + 3 );

#ifdef TWO_ROUNDS
	rotr( lLeft, rLeft );					/* 1, 1 */
	lRight ^= sBoxes1[ ( BYTE ) lLeft ];
	rRight ^= sBoxes2[ ( BYTE ) rLeft ];
	rotr( lRight, rRight );					/* 1, 2 */
	lLeft ^= sBoxes1[ ( BYTE ) lRight ];
	rLeft ^= sBoxes2[ ( BYTE ) rRight ];
	rotr( lLeft, rLeft );					/* 1, 3 */
	lRight ^= sBoxes1[ ( BYTE ) lLeft ];
	rRight ^= sBoxes2[ ( BYTE ) rLeft ];
	rotr( lRight, rRight );					/* 1, 4 */
	lLeft ^= sBoxes1[ ( BYTE ) lRight ];
	rLeft ^= sBoxes2[ ( BYTE ) rRight ];
	rotr( lLeft, rLeft );					/* 1, 5 */
	lRight ^= sBoxes1[ ( BYTE ) lLeft ];
	rRight ^= sBoxes2[ ( BYTE ) rLeft ];
	rotr( lRight, rRight );					/* 1, 6 */
	lLeft ^= sBoxes1[ ( BYTE ) lRight ];
	rLeft ^= sBoxes2[ ( BYTE ) rRight ];
	rotr( lLeft, rLeft );					/* 1, 7 */
	lRight ^= sBoxes1[ ( BYTE ) lLeft ];
	rRight ^= sBoxes2[ ( BYTE ) rLeft ];
	rotr( lRight, rRight );					/* 1, 8 */
	lLeft ^= sBoxes1[ ( BYTE ) lRight ];
	rLeft ^= sBoxes2[ ( BYTE ) rRight ];
#endif /* TWO_ROUNDS */
	rotr( lLeft, rLeft );					/* 2, 1 */
	lRight ^= sBoxes1[ ( BYTE ) lLeft ];
	rRight ^= sBoxes2[ ( BYTE ) rLeft ];
	rotr( lRight, rRight );					/* 2, 2 */
	lLeft ^= sBoxes1[ ( BYTE ) lRight ];
	rLeft ^= sBoxes2[ ( BYTE ) rRight ];
	rotr( lLeft, rLeft );					/* 2, 3 */
	lRight ^= sBoxes1[ ( BYTE ) lLeft ];
	rRight ^= sBoxes2[ ( BYTE ) rLeft ];
	rotr( lRight, rRight );					/* 2, 4 */
	lLeft ^= sBoxes1[ ( BYTE ) lRight ];
	rLeft ^= sBoxes2[ ( BYTE ) rRight ];
	rotr( lLeft, rLeft );					/* 2, 5 */
	lRight ^= sBoxes1[ ( BYTE ) lLeft ];
	rRight ^= sBoxes2[ ( BYTE ) rLeft ];
	rotr( lRight, rRight );					/* 2, 6 */
	lLeft ^= sBoxes1[ ( BYTE ) lRight ];
	rLeft ^= sBoxes2[ ( BYTE ) rRight ];
	rotr( lLeft, rLeft );					/* 2, 7 */
	lRight ^= sBoxes1[ ( BYTE ) lLeft ];
	rRight ^= sBoxes2[ ( BYTE ) rLeft ];
	rotr( lRight, rRight );					/* 2, 8 */
	lLeft ^= sBoxes1[ ( BYTE ) lRight ];
	rLeft ^= sBoxes2[ ( BYTE ) rRight ];

	lLeft ^= ivLLeft2;
	rLeft ^= ivRLeft2;
	lRight ^= ivLRight2;
	rRight ^= ivRRight2;

	ivLLeft2 = *( ( LONG * ) inData );
	ivRLeft2 = *( ( LONG * ) inData + 1 );
	ivLRight2 = *( ( LONG * ) inData + 2 );
	ivRRight2 = *( ( LONG * ) inData + 3 );

	*( ( LONG * ) outData ) = lLeft;
	*( ( LONG * ) outData + 1 ) = rLeft;
	*( ( LONG * ) outData + 2 ) = lRight;
	*( ( LONG * ) outData + 3 ) = rRight;
	}
#endif /* USE_CBC */

/****************************************************************************
*																			*
*					Cipher Block Chaining Mode Routines						*
*																			*
****************************************************************************/

#ifdef USE_CBC

/* Initialise the IV */

void initIV( const LONG salt )
	{
	BYTE iv[ BLOCKSIZE ];

	/* Copy the salt into the IV and encrypt it */
	iv[ 0 ] = ( BYTE ) ( salt >> 24 );
	iv[ 1 ] = ( BYTE ) ( salt >> 16 );
	iv[ 2 ] = ( BYTE ) ( salt >> 8 );
	iv[ 3 ] = ( BYTE ) salt;
	memset( iv + sizeof( LONG ), 0, BLOCKSIZE - sizeof( LONG ) );
	encrypt( iv, iv );

	/* Copy across to the IV variables */
	ivLLeft1 = ivLLeft2 = * ( ( LONG * ) iv );
	ivRLeft1 = ivRLeft2 = * ( ( LONG * ) iv + 1 );
	ivLRight1 = ivLRight2 = * ( ( LONG * ) iv + 2 );
	ivRRight1 = ivRRight2 = * ( ( LONG * ) iv + 3 );
	}
#endif /* USE_CBC */

/****************************************************************************
*																			*
*						Cipher Feedback Mode Routines						*
*																			*
****************************************************************************/

#ifndef USE_CBC

/* Initialise the IV */

void initIV( const LONG salt )
	{
	/* Copy the salt into the IV and encrypt it */
	iv[ 0 ] = ( BYTE ) ( salt >> 24 );
	iv[ 1 ] = ( BYTE ) ( salt >> 16 );
	iv[ 2 ] = ( BYTE ) ( salt >> 8 );
	iv[ 3 ] = ( BYTE ) salt;
	memset( iv + sizeof( LONG ), 0, BLOCKSIZE - sizeof( LONG ) );
	encrypt( iv, iv );

	ivCount = 0;
	}

/* Encrypt data in CFB mode */

void encryptCFB( BYTE *buffer, int noBytes )
	{
	int bytesToUse, i;

	if( ivCount )
		{
		/* Use any material left in the encrypted IV */
		bytesToUse = BLOCKSIZE - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;
		for( i = 0; i < bytesToUse; i++ )
			buffer[ i ] ^= temp[ i + ivCount ];
		memcpy( iv + ivCount, buffer, bytesToUse );
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		}

	while( noBytes )
		{
		ivCount = ( noBytes > BLOCKSIZE ) ? BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		encrypt( iv, temp );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= temp[ i ];

		/* Shift ciphertext into IV */
		memcpy( iv, buffer, ivCount );

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}
	}

/* Decrypt data in CFB mode */

void decryptCFB( BYTE *buffer, int noBytes )
	{
	int bytesToUse, i;

	if( ivCount )
		{
		/* Use any material left in the encrypted IV */
		bytesToUse = BLOCKSIZE - ivCount;
		if( noBytes < bytesToUse )
			bytesToUse = noBytes;
		memcpy( iv + ivCount, buffer, bytesToUse );
		for( i = 0; i < bytesToUse; i++ )
			buffer[ i ] ^= temp[ i + ivCount ];
		noBytes -= bytesToUse;
		buffer += bytesToUse;
		}

	while( noBytes )
		{
		ivCount = ( noBytes > BLOCKSIZE ) ? BLOCKSIZE : noBytes;

		/* Encrypt the IV */
		encrypt( iv, temp );

		/* Shift ciphertext into IV */
		memcpy( iv, buffer, ivCount );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= temp[ i ];

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}
	}
#endif /* !USE_CBC */