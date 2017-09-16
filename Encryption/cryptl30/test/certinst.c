/****************************************************************************
*																			*
*					  cryptlib Certificate Installation Utility 			*
*						Copyright Peter Gutmann 1997-1999					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _MSC_VER
  #include "../capi.h"
  #include "test.h"
#else
  #include "capi.h"
  #include "test/test.h"
#endif /* Braindamaged MSC include handling */

/* Generic I/O buffer size.  This has to be of a reasonable size so we can
   handle cert chains */

#if defined( __MSDOS__ ) && defined( __TURBOC__ )
  #define BUFFER_SIZE		3072
#else
  #define BUFFER_SIZE		8192
#endif /* __MSDOS__ && __TURBOC__ */

/* Various useful types */

#define BOOLEAN	int
#define BYTE	unsigned char
#ifndef TRUE
  #define FALSE	0
  #define TRUE	!FALSE
#endif /* TRUE */

/* There are a few OS's broken enough not to define the standard exit codes
   (SunOS springs to mind) so we define some sort of equivalent here just
   in case */

#ifndef EXIT_SUCCESS
  #define EXIT_SUCCESS	0
  #define EXIT_FAILURE	!EXIT_SUCCESS
#endif /* EXIT_SUCCESS */

/* It's useful to know if we're running under Windows to enable Windows-
   specific processing */

#ifdef _MSC_VER
  #define __WINDOWS__
#endif /* _MSC_VER */

/* Generic I/O buffer size.  This has to be of a reasonable size so we can
   handle cert chains */

#if defined( __MSDOS__ ) && defined( __TURBOC__ )
  #define BUFFER_SIZE		3072
#else
  #define BUFFER_SIZE		8192
#endif /* __MSDOS__ && __TURBOC__ */

BYTE buffer[ BUFFER_SIZE ];

/* A special status code to indicate that cert.trust information was updated */

#define STATUS_TRUST_UPDATED	1000

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Print information on a cert-handling error */

static void printCertError( const CRYPT_CERTIFICATE certificate,
							const char *functionName, const int errorCode,
							const int lineNumber )
	{
	int errorType, errorLocus;
	int status;

	printf( "%s failed with error code %d, line %d\n", functionName,
			errorCode, lineNumber );
	status = cryptGetErrorInfo( certificate, &errorType, NULL, &errorLocus );
	if( cryptStatusOK( status ) && errorType != CRYPT_CERTERROR_NONE )
		printf( "cryptGetCertError() reports locus %d, type %d.\n",
				errorLocus, errorType );
	}

/* Add a cert to a keyset */

static int addCertificate( const CRYPT_KEYSET cryptKeyset,
						   const CRYPT_CERTIFICATE certificate,
						   const BOOLEAN makeTrusted )
	{
	char buffer[ CRYPT_MAX_TEXTSIZE + 1 ];
	int length, status;

	/* Display some info on what we're doing */
	status = cryptGetCertComponentString( certificate,
						CRYPT_CERTINFO_COMMONNAME, buffer, &length );
	if( cryptStatusError( status ) )
		status = cryptGetCertComponentString( certificate,
						CRYPT_CERTINFO_ORGANISATIONALUNITNAME, buffer, &length );
	if( cryptStatusError( status ) )
		status = cryptGetCertComponentString( certificate,
						CRYPT_CERTINFO_ORGANISATIONNAME, buffer, &length );
	if( cryptStatusOK( status ) )
		{
		buffer[ length ] = '\0';
		printf( "Adding certificate for %s...", buffer );
		}
	else
		printf( "Adding certificate..." );

#ifndef __MSDOS__
	/* Add the certificate to the keyset */
	status = cryptAddPublicKey( cryptKeyset, certificate );
	if( status == CRYPT_DATA_DUPLICATE )
		puts( "\nThis certificate is already present in the keyset." );
	else
		if( cryptStatusError( status ) )
			{
			char errorMessage[ 512 ];
			int errorCode, errorMessageLength;

			printf( "\ncryptAddPublicKey() failed with error code %d, line "
					"%d\n",
					status, __LINE__ );
			status = cryptGetErrorInfo( cryptKeyset, &errorCode, errorMessage,
										&errorMessageLength );
			if( cryptStatusError( status ) )
				printf( "cryptGetErrorInfo() failed with error code %d, line "
						"%d\n", status, __LINE__ );
			else
				{
				errorMessage[ errorMessageLength ] = '\0';
				printf( "Extended error code = %d, error message = %s.\n",
						errorCode, errorMessage );
				}

			return( status );
			}
		else
#else
	if( cryptKeyset );		/* Get rid of compiler warning */
#endif /* !__MSDOS__ */
			puts( "done." );

	/* Make the certificate trusted if necessary */
	if( makeTrusted )
		{
		int trusted;

		status = cryptGetCertComponentNumeric( certificate,
											   CRYPT_CERTINFO_TRUSTED, &trusted );
		if( cryptStatusOK( status ) && trusted )
			puts( "This certificate is already trusted." );
		else
			{
			printf( "Making certificate implicitly trusted..." );
			status = cryptAddCertComponentNumeric( certificate,
												   CRYPT_CERTINFO_TRUSTED, TRUE );
			if( cryptStatusError( status ) )
				{
				puts( "\nCouldn't make the certificate trusted." );
				printCertError( CRYPT_ERROR, "cryptAddCertComponentNumeric",
								status, __LINE__ );
				return( status );
				}
			puts( "done." );

			/* Remember that we've changed the trust information */
			status = STATUS_TRUST_UPDATED;
			}
		}

	return( status );
	}

/****************************************************************************
*																			*
*								Standalone main()							*
*																			*
****************************************************************************/

/* Windoze defines ERROR_FILE_EXISTS somewhere even though it's not
   documented */

#undef ERROR_FILE_EXISTS

/* Error codes.  cryptlib return codes are converted to a positive value
   (some OS's don't like negative status codes), application-specific codes
   unrelated to cryptlib are given below */

#define ERROR_BADARG		500		/* Bad argument */
#define ERROR_FILE_EXISTS	501		/* Output file already exists */
#define ERROR_FILE_INPUT	502		/* Error opening input file */
#define ERROR_FILE_OUTPUT	503		/* Error opening/creating output file */

/* Display the help info */

static void showHelp( void )
	{
	puts( "Usage: certinst -it -k<number> -n<name> -u<name> -p<password> <infile>" );
	puts( "       -i = install CA root certs 'cacert01..cacertnn'" );
	puts( "       -k = key database type (CRYPT_KEYSET_xxx numeric values)" );
	puts( "       -n = key database name" );
	puts( "       -p = password for key database access" );
	puts( "       -t = make the certificate implicitly trusted" );
	puts( "       -u = user name for key database access" );
	puts( "" );
	puts( "Examples:" );
	puts( "  certinst -inPublicKeys         : Install CA certs into 'PublicKeys' keyset" );
	puts( "  certinst -tinPublicKeys        : As above, make CA certs implicitly trusted" );
	puts( "  certinst -nPublicKeys cert.der : Install cert.der into keyset" );
	puts( "" );
	puts( "It is strongly recommended that you use 'certinst -it <other "
		  "necessary\noptions>' to install the default CA certificates and "
		  "make them trusted\nbefore you use cryptlibs certificate "
		  "management routines, since this will\nset up the required CA "
		  "trust infrastructure.\n" );
	}

/* The main program */

int main( int argc, char **argv )
	{
	CRYPT_CERTIFICATE certificate;
#ifdef __WINDOWS__
	CRYPT_KEYSET_TYPE cryptKeysetType = CRYPT_KEYSET_ODBC;
#else
	CRYPT_KEYSET_TYPE cryptKeysetType = CRYPT_KEYSET_MYSQL;
#endif /* OS-specific default keyset */
	CRYPT_KEYSET cryptKeyset;
	FILE *inFile = NULL;
	BOOLEAN doInstallDefaultCerts = FALSE, doMakeTrusted = FALSE;
	BOOLEAN trustInfoUpdated = FALSE;
	char *keysetName = NULL, *userName = NULL, *password = NULL;
	int status;

	/* Process the input parameters */
	puts( "Certificate install utility for cryptlib 2.1.  Copyright Peter Gutmann 1999." );
	puts( "" );
	if( argc < 2 )
		{
		showHelp();
		return( ERROR_BADARG );
		}

	/* VisualAge C++ doesn't set the TZ correctly */
#if defined( __IBMC__ ) || defined( __IBMCPP__ )
	tzset();
#endif /* VisualAge C++ */

	/* Initialise cryptlib */
	status = cryptInit();
	if( cryptStatusError( status ) )
		{
		printf( "cryptlib initialisation failed with error code %d.\n",
				status );
		return( -status );
		}
	atexit( (void(*)(void)) cryptEnd );		/* Auto cleanup on exit */

	/* Check for arguments */
	while( argc > 1 && *argv[ 1 ] == '-' )
		{
		char *argPtr = argv[ 1 ] + 1;

		while( *argPtr )
			{
			switch( toupper( *argPtr ) )
				{
				case 'I':
					doInstallDefaultCerts = TRUE;
					argPtr++;
					break;

				case 'K':
					cryptKeysetType = atoi( argPtr + 1 );
					argPtr += ( cryptKeysetType > 10 ) ? 3 : 2;
					if( cryptKeysetType < CRYPT_KEYSET_ODBC )
						{
						puts( "Keyset type must specify a key database." );
						return( ERROR_BADARG );
						}
					break;

				case 'N':
					keysetName = argPtr + 1;
					argPtr += strlen( argPtr );
					break;

				case 'P':
					password = argPtr + 1;
					argPtr += strlen( argPtr );
					break;

				case 'T':
					doMakeTrusted = TRUE;
					argPtr++;
					break;

				case 'U':
					userName = argPtr + 1;
					argPtr += strlen( argPtr );
					break;

				default:
					printf( "Unknown option '%c'.\n", *argPtr );
					return( ERROR_BADARG );
				}
			}

		argc--;
		argv++;
		}

	/* Make sure the args are consistent */
	if( !doInstallDefaultCerts && argc <= 1 )
		{
		puts( "You must specify either the installation of the default "
			  "certs or the\ninstallation of a cert from a user-defined "
			  "file." );
		return( ERROR_BADARG );
		}
	if( keysetName == NULL )
		{
		puts( "You must specify a keyset to install the certs into." );
		return( ERROR_BADARG );
		}

	/* If we're installing a user-defined cert, try and import it */
	if( argc > 1 )
		{
		int count;

		if( doInstallDefaultCerts )
			{
			puts( "You can't install both the default CA certs and a "
				  "user-defined cert at the\nsame time." );
			return( ERROR_BADARG );
			}

		if( ( inFile = fopen( argv[ 1 ], "rb" ) ) == NULL )
			{
			perror( argv[ 1 ] );
			return( ERROR_FILE_INPUT );
			}

		/* Import the cert object from the file */
		count = fread( buffer, 1, BUFFER_SIZE, inFile );
		fclose( inFile );
		if( count == BUFFER_SIZE )	/* Item too large for buffer */
			{
			printf( "Certificate object in file '%s' is too large for the "
					"internal buffer.\n", argv[ 1 ] );
			return( ERROR_FILE_INPUT );
			}
		status = cryptImportCert( buffer, count, &certificate );
		if( cryptStatusError( status ) )
			{
			printCertError( CRYPT_ERROR, "cryptImportCert", status, __LINE__ );
			return( -status );
			}
		}

#ifndef __MSDOS__
	/* Open the keyset to add the cert to.  Since it may not exist yet, we
	   first try to create it, if it already exists this will return a
	   duplicate data error so we retry the open with no flags to open the
	   existing database keyset for write access */
	if( userName == NULL && password == NULL )
		{
		status = cryptKeysetOpen( &cryptKeyset, cryptKeysetType, keysetName,
								  CRYPT_KEYOPT_CREATE );
		if( status == CRYPT_DATA_DUPLICATE )
			status = cryptKeysetOpen( &cryptKeyset, cryptKeysetType,
									  keysetName, CRYPT_KEYOPT_NONE );
		}
	else
		{
		status = cryptKeysetOpenEx( &cryptKeyset, cryptKeysetType,
									keysetName, NULL, userName, password,
									CRYPT_KEYOPT_CREATE );
		if( status == CRYPT_DATA_DUPLICATE )
			status = cryptKeysetOpenEx( &cryptKeyset, cryptKeysetType,
										keysetName, NULL, userName, password,
										CRYPT_KEYOPT_NONE );
		}
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't open the certificate database '%s', type %d,\n"
				"error code %d.\n", keysetName, cryptKeysetType, status );
		return( -status );
		}
#else
	/* DOS doesn't have a database interface */
	if( userName || password );		/* Get rid of compiler warning */
	cryptKeyset = CRYPT_ERROR;
#endif /* !__MSDOS__ */

	/* Install the certs as required */
	if( doInstallDefaultCerts )
		{
		BOOLEAN certFound = FALSE;
		char fileNameBuffer[ 64 ];
		int startLetter;

		for( startLetter = 'a'; startLetter <= 'z'; startLetter++ )
			{
			int count = 1;

			do
				{
				int length;

				/* Read the next cert from the standard cert collection */
				sprintf( fileNameBuffer, "test/certs/%ccert%02d.der",
						 startLetter, count++ );
				if( ( inFile = fopen( fileNameBuffer, "rb" ) ) == NULL )
					break;
				length = fread( buffer, 1, BUFFER_SIZE, inFile );
				fclose( inFile );
				certFound = TRUE;

				/* Import the certificate */
				status = cryptImportCert( buffer, length, &certificate );
				if( cryptStatusError( status ) )
					printCertError( CRYPT_ERROR, "cryptImportCert", status,
									__LINE__ );
				else
					{
					/* Add the cert to the keyset */
					status = addCertificate( cryptKeyset, certificate,
											 doMakeTrusted );
					cryptDestroyCert( certificate );

					/* If the trust info was changed, remember that we have
					   to flush it later on */
					if( status == STATUS_TRUST_UPDATED )
						{
						trustInfoUpdated = TRUE;
						status = CRYPT_OK;
						}
					}
				}
			while( cryptStatusOK( status ) );
			}

		if( !certFound )
			puts( "No certificate files found.  You must run this program "
				  "from the cryptlib\ndirectory so that it can read the "
				  "certificate files from the 'test/certs/'\nsubdirectory." );
		}
	else
		{
		/* Add the user-defined cert */
		status = addCertificate( cryptKeyset, certificate, doMakeTrusted );
		cryptDestroyCert( certificate );

		/* If the trust info was changed, remember that we have to flush it
		   later on */
		if( status == STATUS_TRUST_UPDATED )
			trustInfoUpdated = TRUE;
		}

	/* Clean up */
	cryptKeysetClose( cryptKeyset );
	if( inFile != NULL )
		fclose( inFile );
	if( cryptStatusError( status ) )
		{
		printf( "Certificate processing failed with error code %d\n",
				status );
		return( -status );
		}

	/* Flush the updated trust information if necessary */
	if( trustInfoUpdated )
		cryptWriteOptions();

	return( EXIT_SUCCESS );
	}
