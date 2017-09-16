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

/* The encryption password lengths.  A minimum length of 8 bytes provides a
   reasonable level of security, as well as ensuring that the salt used to
   initialise the LFSR used to generate the S-boxes covers the full possible
   range of values */

#define MIN_KEYLENGTH	8
#define MAX_KEYLENGTH	80		/* Any reasonable value will do */

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

/****************************************************************************
*																			*
*		Sample Program:  File Encryption/Decryption using CFB mode			*
*																			*
****************************************************************************/

#ifndef USE_CBC

#define NSEA_ID		"NSEA"

void main( const int argc, const char *argv[] )
	{
#if !defined( TIME_TRIAL ) && !defined( SETUP_TRIAL )
	FILE *inFilePtr, *outFilePtr;
#endif /* !( TIME_TRIAL || SETUP_TRIAL ) */
#ifndef SETUP_TRIAL
	BYTE buffer[ 512 ];
#endif /* !SETUP_TRIAL */
	char key[ MAX_KEYLENGTH + 1 ];
	int count = 1;
	LONG salt = getRandomLong();

#if !defined( TIME_TRIAL ) && !defined( SETUP_TRIAL )
	if( argc == 4 )
		{
		if( ( inFilePtr = fopen( argv[ 2 ], "rb" ) ) == NULL )
			{
			perror( argv[ 1 ] );
			exit( ERROR );
			}
		if( ( outFilePtr = fopen( argv[ 3 ], "wb" ) ) == NULL )
			{
			perror( argv[ 2 ] );
			exit( ERROR );
			}
		}
	else
		{
		puts( "Usage: nsea e|d <infile> <outfile>" );
		puts( "            e to encrypt data" );
		puts( "            d to decrypt data" );
		exit( ERROR );
		}
#endif /* !( TIME_TRIAL || SETUP_TRIAL ) */

	initNSEA();

#if !defined( TIME_TRIAL ) && !defined( SETUP_TRIAL )
	/* Read/write the header information */
	if( *argv[ 1 ] == 'e' )
		{
		fwrite( NSEA_ID, 1, 4, outFilePtr );
		fputc( ( BYTE ) ( salt >> 24 ), outFilePtr );
		fputc( ( BYTE ) ( salt >> 16 ), outFilePtr );
		fputc( ( BYTE ) ( salt >> 8 ), outFilePtr );
		fputc( ( BYTE ) salt, outFilePtr );
		}
	else
		{
		if( fread( buffer, 1, 8, inFilePtr ) != 8 || \
			memcmp( buffer, NSEA_ID, 4 ) )
			{
			puts( "Not an NSEA-encrypted file" );
			exit( ERROR );
			}
		salt = ( ( LONG ) buffer[ 4 ] << 24 ) | \
			   ( ( LONG ) buffer[ 5 ] << 16 ) | \
			   ( ( LONG ) buffer[ 6 ] << 8 ) | \
						  buffer[ 7 ];
		}
#endif /* !( TIME_TRIAL || SETUP_TRIAL ) */

	/* Set up the S-Boxes */
#if defined( TIME_TRIAL ) || defined( SETUP_TRIAL )
	strcpy( key, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" );
#else
	*key = '\0';
	while( strlen( key ) < MIN_KEYLENGTH )
		{
		printf( "Key (%d-%d chars): ", MIN_KEYLENGTH, MAX_KEYLENGTH );
		fgets( key, MAX_KEYLENGTH, stdin );	/* Should use something better */
		key[ strlen( key ) - 1 ] = '\0';	/* Stomp '\n' */
		putchar( '\n' );
		}
#endif /* TIME_TRIAL || SETUP_TRIAL */
#ifdef SETUP_TRIAL
	puts( "Performing 1000 key setup operations" );
	for( count = 0; count < 1000; count++ )
		{
		initSBoxes( ( BYTE * ) key, strlen( key ), salt );
		initIV( DEFAULT_SALT );
		}
	puts( "Done" );
#else
	initSBoxes( ( BYTE * ) key, strlen( key ), salt );
	initIV( DEFAULT_SALT );
#endif /* SETUP_TRIAL */

	/* We're done with the key, zap it */
	memset( key, 0, MAX_KEYLENGTH + 1 );

#if defined( TIME_TRIAL )
	/* Encrypt 1MB of data in 512-byte blocks */
	memset( buffer, 0, 512 );
	puts( "Encrypting 20480 x 512-byte blocks (10MB)..." );
	for( count = 0; count < 20480; count++ )
		encryptCFB( buffer, 512 );
	puts( "Done" );
#elif !defined( SETUP_TRIAL )

	/* Grovel through a file en/decrypting it */
	while( count )
		{
		/* Read in a block of chars */
		count = fread( buffer, 1, 512, inFilePtr );

		/* Encrypt/decrypt data block */
		if( *argv[ 1 ] == 'e' )
			encryptCFB( buffer, count );
		else
			decryptCFB( buffer, count );

		/* Write out block and reset counter */
		fwrite( buffer, 1, count, outFilePtr );
		}

	fclose( inFilePtr );
	fclose( outFilePtr );
#endif /* TIME_TRIAL */

	endNSEA();
	}
#endif /* !USE_CBC */

/****************************************************************************
*																			*
*			Sample Program:  File En/Decryption using CBC Mode				*
*																			*
****************************************************************************/

#if !defined( TEST_VERSION ) && defined( USE_CBC )

#define NSEA_ID		"NSEA"

/* Grossly inefficient CBC file en/decryption program */

void main( const int argc, const char *argv[] )
	{
	FILE *inFilePtr, *outFilePtr;
	BYTE dataIn[ BLOCKSIZE ], dataOut[ BLOCKSIZE ];
	char key[ MAX_KEYLENGTH + 1 ];
	int count = 0, ch;
	LONG salt = getRandomLong();

	if( argc == 4 )
		{
		if( ( inFilePtr = fopen( argv[ 2 ], "rb" ) ) == NULL )
			{
			perror( argv[ 1 ] );
			exit( ERROR );
			}
		if( ( outFilePtr = fopen( argv[ 3 ], "wb" ) ) == NULL )
			{
			perror( argv[ 2 ] );
			exit( ERROR );
			}
		}
	else
		{
		puts( "Usage: nsea e|d <infile> <outfile>" );
		puts( "            e to encrypt data" );
		puts( "            d to decrypt data" );
		exit( ERROR );
		}

	initNSEA();

	/* Read/write the header information */
	if( *argv[ 1 ] == 'e' )
		{
		fwrite( NSEA_ID, 1, 4, outFilePtr );
		fputc( ( BYTE ) ( salt >> 24 ), outFilePtr );
		fputc( ( BYTE ) ( salt >> 16 ), outFilePtr );
		fputc( ( BYTE ) ( salt >> 8 ), outFilePtr );
		fputc( ( BYTE ) salt, outFilePtr );
		}
	else
		{
		if( fread( dataIn, 1, 8, inFilePtr ) != 8 || \
			memcmp( dataIn, NSEA_ID, 4 ) )
			{
			puts( "Not an NSEA-encrypted file" );
			exit( ERROR );
			}
		salt = ( ( LONG ) dataIn[ 4 ] << 24 ) | \
			   ( ( LONG ) dataIn[ 5 ] << 16 ) | \
			   ( ( LONG ) dataIn[ 6 ] << 8 ) | \
						  dataIn[ 7 ];
		}

	/* Set up the S-Boxes */
	*key = '\0';
	while( strlen( key ) < MIN_KEYLENGTH )
		{
		printf( "Key (%d-%d chars): ", MIN_KEYLENGTH, MAX_KEYLENGTH );
		fgets( key, MAX_KEYLENGTH, stdin ); /* Should use something better */
		key[ strlen( key ) - 1 ] = '\0';    /* Stomp '\n' */
		putchar( '\n' );
		}

	initSBoxes( ( BYTE * ) key, strlen( key ), salt );
	initIV( DEFAULT_SALT );

	/* We're done with the key, zap it */
	memset( key, 0, MAX_KEYLENGTH + 1 );

	/* Grovel through a file en/decrypting it */
	memset( dataIn, 0, BLOCKSIZE );
	while( !feof( inFilePtr ) )
		{
		/* Read in a block of chars */
		while( count < BLOCKSIZE )
			{
			if( ( ch = getc( inFilePtr ) ) == EOF && count == 1 )
				/* File is a multiple of blocksize, exit now */
				goto endLoop;
			dataIn[ count++ ] = ( ch == EOF ) ? 0 : ch;
			}

		/* Encrypt/decrypt data block */
		if( *argv[ 1 ] == 'e' )
			encrypt( dataIn, dataOut );
		else
			decrypt( dataIn, dataOut );

		/* Write out block and reset counter */
		for( count = 0; count < BLOCKSIZE; count++ )
			fputc( dataOut[ count ], outFilePtr );
		count = 0;
		}

endLoop:
	fclose( inFilePtr );
	fclose( outFilePtr );

	endNSEA();
	}

#endif /* !TEST_VERSION */

/****************************************************************************
*																			*
*				Sample Program:  Perform Test En/Decryptions				*
*																			*
****************************************************************************/

#ifdef TEST_VERSION

/* Sample code to encrypt/decrypt 128-bit values.  Note that the sample
   keys are possibly somewhat shorter than what would normally be used
   (128 bits vs MIN_KEYLENGTH...MAX_KEYLENGTH bytes) */

typedef struct {
			   BYTE key[ BLOCKSIZE ];		/* Sample key */
			   BYTE data[ BLOCKSIZE ];		/* Sample data */
			   } SAMPLE_VALUE;

SAMPLE_VALUE testValues[] = {
					{
						{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
						{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
					}, {
						{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
						  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
						{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
						  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
					}, {
						{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
						{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
					}, {
						{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
						{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
					}, {
						{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
						{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
					}, {
						{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
						{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
					}, {
						{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
						  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
						{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
					}, {
						{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
						{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
						  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
					}, {
						{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
						  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
						{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
					}, {
						{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
						{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
						  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
					}, {
						{ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
						  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
						{ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
						  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
					}, {
						{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
						  0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 },
						{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
						  0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 },
					}, {
						{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
						  0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 },
						{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                          0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 },
					}, {
						{ 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
						  0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF },
						{ 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
						  0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF }
					}
				};

#define NO_TEST_VALUES		14

/* Code to generate test encryption values */

void printData( BYTE *data )
	{
	int i = 0;

	while( i < BLOCKSIZE )
		printf( "%02X", data[ i++ ] );
	}

void main( void )
	{
	BYTE cipherText[ BLOCKSIZE ], result[ BLOCKSIZE ];
	int i, j;

	puts( "Beginning test run..." );

	initNSEA();

	for( i = 0; i < NO_TEST_VALUES; i++ )
		{
		/* Set up the key */
		initSBoxes( testValues[ i ].key, BLOCKSIZE, DEFAULT_SALT );
		initIV( DEFAULT_SALT );

		printf( "Key " );
		printData( testValues[ i ].key );
		printf( ", data " );
		printData( testValues[ i ].data );
		printf( ":\n    " );

		for( j = 0; j < 4; j++ )
			{
  #ifdef ASM_ENCRYPT_32
			encrypt32( testValues[ i ].data, cipherText );
  #else
			encrypt( testValues[ i ].data, cipherText );
  #endif /* ASM_ENCRYPT_32 */
			decrypt( cipherText, result );
			printData( cipherText );
			putchar( ' ' );
			if( memcmp( testValues[ i ].data, result, BLOCKSIZE ) )
				{
				printf( "\nDecrypted to " );
				printData( result );
				putchar( '\n' );
				}
			if( j == 1 )
				printf( "\n    " );
			}
		putchar( '\n' );
		}

	endNSEA();
	}
#endif /* !TEST_VERSION && USE_CBC */
