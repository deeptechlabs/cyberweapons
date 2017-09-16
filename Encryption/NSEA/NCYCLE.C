#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "nsea.h"

/* OS-specific stuff */

#ifdef OS2
  #include <os2task.h>
#endif /* OS2 */

/****************************************************************************
*																			*
*						Block Cipher Cycling Routines						*
*																			*
****************************************************************************/

/* The following code is based on a version kindly provided by Robert Ames
   (mirage1@gpu.utcs.utoronto.ca) which in turn was based on Phil Karn's
   DESCYCLE, with a few changes made to speed execution and much creeping 
   featurism added by myself */

void get8( FILE *stream, BYTE *strPtr )
	{
	int i, value;

	for( i = 0; i < 8; i++ )
		{
		fscanf( stream, "%2x", &value );
		*strPtr++ = value;
		}
	}

void put8( FILE *stream, BYTE *strPtr )
	{
	int i;

	for( i = 0; i < 8; i++ )
		fprintf( stream, "%02x ", *strPtr++ );
	putc( '\n', stream );
	}

void get16( FILE *stream, BYTE *strPtr )
	{
	int i, value;

	for( i = 0; i < 16; i++ )
		{
		fscanf( stream, "%2x", &value );
		*strPtr++ = value;
		}
	}

void put16( FILE *stream, BYTE *strPtr )
	{
    int i;

	for( i = 0; i < 16; i++ )
		fprintf( stream, "%02x ", *strPtr++ );
	putc( '\n', stream );
	}

/* Print a report on ncycle's progress */

clock_t startTime;

void report( FILE *stream, const BOOLEAN cycleFound, const long count )
	{
	if( cycleFound )
		fprintf( stream, "Cycle found after %ld iterations\n", count );
	else
		fprintf( stream, "No cycle found after %ld iterations\n", count );
#ifdef __MSDOS__
	fprintf( stream, "Runtime = %ld seconds\n", ( ( clock() - startTime ) * 10 ) / 182 );
#else
	fprintf( stream, "Runtime = %ld seconds\n", ( clock() - startTime ) / CLK_TCK );
#endif /* __MSDOS__ */
	}

/* The main NSEA cycling program */

void main( const int argc, const char *argv[] )
	{
	BYTE key[ 8 ], initialData[ BLOCKSIZE ], workingData[ BLOCKSIZE ];
	BOOLEAN verbose = FALSE, defParam = FALSE, backGround = FALSE;
	BOOLEAN showBits = FALSE;
	unsigned int iterationCount = 0, updateInterval;
	long noIterations, totalIterations = 0;
	FILE *dataFile;
	long dataFilePos;
	int i, j;
	BYTE mask;
#ifdef OS2
	char choice;
#endif /* OS2 */

	/* Do an arg check */
	if( !strcmp( argv[ 1 ], "-?" ) )
		{
		puts( "Usage: ncycle {-v|-d|-b|-s}" );
		puts( "                 -v = Verbose mode" );
		puts( "                 -d = Use default parameters" );
		puts( "	                -b = Background mode" );
		puts( "                 -s = Show bit patterns" );
		exit( ERROR );
		}

	*argv++;
	while( *argv != NULL )
		{
		verbose |= !strcmp( *argv, "-v" );		/* Verbose mode */
		defParam |= !strcmp( *argv, "-d" );		/* Use default parameters */
		backGround |= !strcmp( *argv, "-b" );	/* Background mode */
		showBits |= !strcmp( *argv, "-s" );		/* Show bit patterns */
		*argv++;
		}

	/* Try and open the output file */
	if( backGround && ( dataFile = fopen( "ncycle.out", "w" ) ) == NULL )
		{
		perror( "ncycle.out" );
		exit( ERROR );
		}

	initNSEA();

	/* Set up the encryption parameters */
	if( defParam )
		{
		/* Use default parameters: all-0 key and data, report every 50000
		   steps, run 1 billion interations */
		memset( key, 0, 8 );
		memset( initialData, 0, BLOCKSIZE );
		updateInterval = 50000U;
		noIterations = 1000000000L;
		}
	else
		{
		/* Get key from user */
		printf( "Enter key (hex): " );
		get8( stdin, key );
		printf( "Setting key: " );
		put8( stdout, key );

		/* Get start value from user */
		printf( "Enter starting value (16 hex bytes): " );
		get16( stdin, initialData );
		printf( "Starting value: " );
		put16( stdout, initialData );

		/* Get update interval and iteration count from user */
		printf( "Update interval: " );
		scanf( "%u", &updateInterval );
		printf( "No.iterations: " );
		scanf( "%ld", &noIterations );
#ifdef OS2
		printf( "Low priority [y/n]? " );
		choice = toupper( getche() );
		if( choice == 'Y' )
			DosSetPrty( 0, 1, 0, 0 );		/* Idle task */
#endif /* OS2 */
		putchar( '\n' );
		}

	/* Write setup info to data file if necessary */
	if( backGround )
		{
		put8( dataFile, key );
		put16( dataFile, initialData );
		fprintf( dataFile, "%u\n", updateInterval );
		fprintf( dataFile, "%ld\n", noIterations );
		fflush( dataFile );
		dataFilePos = ftell( dataFile );
		}

	/* Set up working data and start value */
	memcpy( workingData, initialData, BLOCKSIZE );
	initSBoxes( key, 8, DEFAULT_SALT );
	initIV( DEFAULT_SALT );

	startTime = clock();
	while( noIterations-- )
		{
#ifdef ASM_ENCRYPT_32
		encrypt32( workingData, workingData );
#else
		encrypt( workingData, workingData );
#endif /* ASM_ENCRYPT_32 */

		if( showBits )
			{
			for( i = 0; i < BLOCKSIZE; i++ )
				{
				mask = 0x80;
				for( j = 0; j < 8; j++ )
					{
					putchar( ( workingData[ i ] & mask ) ? '1' : '0' );
					mask >>= 1;
					}
				putchar( ' ' );
				}
			putchar( '\n' );
			}

		if( ++iterationCount == updateInterval )
			{
			/* Reached the update interval, report status */
			totalIterations += iterationCount;
			iterationCount = 0;
			if( backGround )
				{
				/* Write checkpoint data */
				fseek( dataFile, dataFilePos, SEEK_SET );
				put16( dataFile, workingData );
				fprintf( dataFile, "%ld\n", totalIterations );
				fflush( dataFile );
				}
			else
				{
				if( verbose )
					{
					printf( "%ld ", totalIterations );
					put16( stdout, workingData );
					}
				else
					printf( "\r%ld", totalIterations );
				fflush( stdout );
				}
			}

		/* If we've come back to the start value, we've got a cycle */
		if( !memcmp( workingData, initialData, BLOCKSIZE ) )
			{
			totalIterations += iterationCount;
			if( backGround )
				{
				/* Write the log file */
				report( dataFile, TRUE, totalIterations );
				fclose( dataFile );
				}
			else
				report( stdout, TRUE, totalIterations );

			exit( ERROR );
			}
		}

	totalIterations += iterationCount;
	if( backGround )
		{
		/* Write the log file */
		fseek( dataFile, dataFilePos, SEEK_SET );
		report( dataFile, FALSE, totalIterations );
		fclose( dataFile );
		}
	else
		{
		if( !verbose )
			putchar( '\n' );
		report( stdout, FALSE, totalIterations );
		}

	endNSEA();
	exit( OK );
	}
