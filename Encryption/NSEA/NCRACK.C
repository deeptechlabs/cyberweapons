#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nsea.h"

/* The encryption password lengths.  A minimum length of 8 bytes provides a
   reasonable level of security, as well as ensuring that the salt used to
   initialise the LFSR used to generate the S-boxes covers the full possible
   range of values */

#define MIN_KEYLENGTH	8
#define MAX_KEYLENGTH	80		/* Any reasonable value will do */

/****************************************************************************
*																			*
*							NSEA Dictionary Cracker							*
*																			*
****************************************************************************/

/* This code isn't meant for interactive use - it's something you compile
   and then put on some machine to grind away at it in the background.  Thus
   a lot of stuff is hardwired in a compile time */

#define KNOWN_PLAINTEXT		/*"abcdefg"*/ "/* Compile"
#define KNOWN_PLAINTEXT_LEN	sizeof( KNOWN_PLAINTEXT ) - 1

#define NSEA_ID		"NSEA"

void main( const int argc, const char *argv[] )
	{
	FILE *inFilePtr, *dictFilePtr;
	BYTE cipherText[ BLOCKSIZE ], buffer[ BLOCKSIZE ];
	char key[ MAX_KEYLENGTH + 1 ];
	int count, keyLength;
	LONG salt;

	if( argc == 3 )
		{
		if( ( inFilePtr = fopen( argv[ 1 ], "rb" ) ) == NULL )
			{
			perror( argv[ 1 ] );
			exit( ERROR );
			}
		if( ( dictFilePtr = fopen( argv[ 2 ], "r" ) ) == NULL )
			{
			perror( argv[ 2 ] );
			exit( ERROR );
			}
		}
	else
		{
		puts( "Usage: ncrack <data file> <dictionary file>" );
		exit( ERROR );
		}

	initNSEA();

	/* Read in salt */
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

	/* Read in up to BLOCKSIZE bytes of input file */
	if( ( count = fread( cipherText, 1, BLOCKSIZE, inFilePtr ) ) < BLOCKSIZE )
		{
		puts( "Can't read input data" );
		exit( ERROR );
		}
	fclose( inFilePtr );

	while( TRUE )
		{
		/* Read in and initialize key */
		if( fgets( key, MAX_KEYLENGTH, dictFilePtr ) == NULL )
			{
			puts( "ncrack: Exhausted dictionary" );
			break;
			}
		if( ( keyLength = strlen( key ) - 1 ) < MIN_KEYLENGTH )
			/* Don't bother with too-short keys */
			continue;
		initSBoxes( ( BYTE * ) key, keyLength, salt );
		initIV( DEFAULT_SALT );

		/* Decrypt data and check if we have a match with the plaintext */
		memcpy( buffer, cipherText, count );
		decryptCFB( buffer, count );
		if( !memcmp( buffer, KNOWN_PLAINTEXT, KNOWN_PLAINTEXT_LEN ) )
			{
			printf( "ncrack: Found key: %s", key );
			break;
			}
		}

	fclose( dictFilePtr );

	endNSEA();
	}
