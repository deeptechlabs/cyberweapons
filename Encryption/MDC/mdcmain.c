/****************************************************************************
*									    *
*			    MDCMAIN.C - MDC driver code			    *
*									    *
*	Written by Peter Gutmann, pgut1@cs.aukuni.ac.nz, September 1992	    *
*		    You can use this code in any way you want,		    *
*	although it'd be nice if you kept my name + contact address on it   *
*									    *
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "mdc.h"

/* The encryption password lengths.  A minimum length of 8 bytes provides a
   reasonable level of security */

#define MIN_KEYLENGTH	8
#define MAX_KEYLENGTH	80	/* Any reasonable value will do */

/* The buffer used by the MDC version of MD5 */

BYTE cryptBuffer[ 2048 ];

/****************************************************************************
*									    *
*	Sample Program:	 File Encryption/Decryption using CFB mode	    *
*									    *
****************************************************************************/

#ifndef TEST_VERSION

#define MDC_ID	    "MDC "

void main( const int argc, const char *argv[] )
    {
#if !defined( TIME_TRIAL ) && !defined( SETUP_TRIAL )
    FILE *inFilePtr, *outFilePtr;
#endif /* !( TIME_TRIAL || SETUP_TRIAL ) */
#if defined( TIME_TRIAL ) || defined( SETUP_TRIAL )
    time_t startTime, endTime;
#endif /* TIME_TRIAL || SETUP_TRIAL */
#ifndef SETUP_TRIAL
    BYTE buffer[ 512 ];
#endif /* !SETUP_TRIAL */
    char key[ MAX_KEYLENGTH + 1 ];
    int count = 1;
    BYTE *iv;

#if !defined( TIME_TRIAL ) && !defined( SETUP_TRIAL )
    if( argc == 4 )
	{
	if( ( inFilePtr = fopen( argv[ 2 ], "rb" ) ) == NULL )
	    {
	    perror( argv[ 2 ] );
	    exit( ERROR );
	    }
	if( ( outFilePtr = fopen( argv[ 3 ], "r" ) ) != NULL )
	    {
	    fclose( outFilePtr );
	    printf( "Won't overwrite existing file %s\n", argv[ 3 ] );
	    exit( ERROR );
	    }
	if( ( outFilePtr = fopen( argv[ 3 ], "wb" ) ) == NULL )
	    {
	    perror( argv[ 3 ] );
	    exit( ERROR );
	    }
	}
    else
	{
	puts( "Usage: mdc e|d <infile> <outfile>" );
	puts( "		  e to encrypt data" );
	puts( "		  d to decrypt data" );
	exit( ERROR );
	}
#endif /* !( TIME_TRIAL || SETUP_TRIAL ) */

#if !defined( TIME_TRIAL ) && !defined( SETUP_TRIAL )
    /* Read/write the header information */
    if( *argv[ 1 ] == 'e' )
	{
	iv = getIV();
	fwrite( MDC_ID, 1, 4, outFilePtr );
	fwrite( iv, 1, IV_SIZE, outFilePtr );
	}
    else
	{
	if( fread( buffer, 1, 4 + IV_SIZE, inFilePtr ) != 4 + IV_SIZE || \
	    memcmp( buffer, MDC_ID, 4 ) )
	    {
	    puts( "Not an MDC-encrypted file" );
	    exit( ERROR );
	    }
	memcpy( iv, buffer + 4, IV_SIZE );
	}
#endif /* !( TIME_TRIAL || SETUP_TRIAL ) */

    /* Set up the S-Boxes */
#if defined( TIME_TRIAL ) || defined( SETUP_TRIAL )
    strcpy( key, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" );
    iv = getIV();
#else
    *key = '\0';
    while( strlen( key ) < MIN_KEYLENGTH )
	{
	printf( "Key (%d-%d chars): ", MIN_KEYLENGTH, MAX_KEYLENGTH );
	fgets( key, MAX_KEYLENGTH, stdin ); /* Should use something better */
	key[ strlen( key ) - 1 ] = '\0';    /* Stomp '\n' */
	putchar( '\n' );
	}
#endif /* TIME_TRIAL || SETUP_TRIAL */
#ifdef SETUP_TRIAL
    puts( "Performing 100 key setup operations" );
    time( &startTime );
    for( count = 0; count < 100; count++ )
	initKey( ( BYTE * ) key, strlen( key ), iv );
    time( &endTime );
    printf( "Seconds to 100 perform key setup operations: %ld\n", \
	    ( long ) ( endTime - startTime ) );
    printf( "Setups per second: %ld\n", \
	    100 / ( endTime - startTime ) );	/* Should really use FP */
    puts( "Done" );
#else
    initKey( ( BYTE * ) key, strlen( key ), iv );
#endif /* SETUP_TRIAL */

    /* We're done with the key, zap it */
    memset( key, 0, MAX_KEYLENGTH + 1 );

#if defined( TIME_TRIAL )
    /* Encrypt 1MB of data in 512-byte blocks */
    memset( buffer, 0, 512 );
    puts( "Encrypting 20480 x 512-byte blocks (10MB)..." );
    time( &startTime );
    for( count = 0; count < 20480; count++ )
	encryptCFB( buffer, 512 );
    time( &endTime );
    printf( "Seconds to encrypt: %ld\n", ( long ) ( endTime - startTime ) );
    printf( "Bytes per second: %ld\n", 10000000L / ( endTime - startTime ) );
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
    }

#endif /* !TEST_VERSION */

/****************************************************************************
*									    *
*		Sample Program:	 Perform Test En/Decryptions		    *
*									    *
****************************************************************************/

#ifdef TEST_VERSION

/* Sample code to encrypt/decrypt 128-bit values.  Note that the sample
   keys are possibly somewhat shorter than what would normally be used
   (128 bits vs MIN_KEYLENGTH...MAX_KEYLENGTH bytes).  Note that the
   following code only exercises the basic MDC transformation, not the
   CFB-mode encryption, since this is stream-oriented */

typedef struct {
	       BYTE key[ BLOCKSIZE ];	    /* Sample key */
	       BYTE data[ BLOCKSIZE ];	    /* Sample data */
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

#define NO_TEST_VALUES	    14

/* Things internal to MDC which we normally don't need to know about but
   which are used by this test code */

void longReverse( LONG *buffer, int byteCount );
extern BYTE auxKey[ MD5_BLOCKSIZE ];

/* Code to generate test encryption values */

void printData( BYTE *data )
    {
    int i = 0;

    while( i < BLOCKSIZE )
	printf( "%02X", data[ i++ ] );
    }

void main( void )
    {
    BYTE cipherText[ BLOCKSIZE ];
    int i;

    puts( "Beginning test run..." );

    for( i = 0; i < NO_TEST_VALUES; i++ )
	{
	/* Set up the key */
	initKey( testValues[ i ].key, BLOCKSIZE, DEFAULT_IV );

	printf( "Key " );
	printData( testValues[ i ].key );
	printf( ", data " );
	printData( testValues[ i ].data );
	printf( ":\n	" );

	/* Perform test encryptions.  Note that we can't test this by
	   decrypting it like an ECB/CBC mode cipher since it's a one-way
	   transformation */
	memcpy( cipherText, testValues[ i ].data, BLOCKSIZE );
	mdcTransform( cipherText );
	printData( cipherText );
	putchar( '\n' );
	}
    }
#endif /* TEST_VERSION */
#endif /* TEST_VERSION */
