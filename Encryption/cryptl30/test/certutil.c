/****************************************************************************
*																			*
*					  cryptlib Certificate Utility Routines					*
*						Copyright Peter Gutmann 1997-1998					*
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

/* Define the following to build a standalone cert utility program.  Note 
   that the code for the standalone version exists only as a debugging tool
   which is intended for use during cryptlib development.  It isn't kept in
   sync with every new code release, and its use is not supported */

/*#define STANDALONE_PROGRAM	/**/

/* Define the following to wrap the main() function in the standalone program
   with a simple wrapper which tests various options */

/*#define WRAP_STANDALONE		/**/

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

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Import a certificate object */

int importCertFile( CRYPT_CERTIFICATE *cryptCert, const char *fileName )
	{
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int count;

	if( ( filePtr = fopen( fileName, "rb" ) ) == NULL )
		return( CRYPT_DATA_OPEN );
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
    if( count == BUFFER_SIZE )	/* Item too large for buffer */
		return( CRYPT_ERROR_OVERFLOW );

	/* Import the certificate */
	return( cryptImportCert( buffer, count, cryptCert ) );
	}

/* Get a line of text from the user */

static void getText( char *input, const char *prompt )
	{
	printf( "Enter %s: ", prompt );
	fflush( stdout );
	fgets( input, CRYPT_MAX_TEXTSIZE - 1, stdin );
	putchar( '\n' );
	}

/* Read a key from a private key file */

int getPrivateKey( CRYPT_CONTEXT *cryptContext, const char *keysetName,
				   const char *keyName, const char *password )
	{
	CRYPT_KEYSET cryptKeyset;
	int status;

	/* Read the key from the keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE, keysetName,
							  CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		return( status );
	status = cryptGetPrivateKey( cryptKeyset, cryptContext, CRYPT_KEYID_NAME, 
								 keyName, password );
	if( status == CRYPT_ERROR_WRONGKEY )
		{
		char passwordBuffer[ CRYPT_MAX_TEXTSIZE ];

		/* We need a password for this private key, get it from the user and
		   get the key again */
		getText( passwordBuffer, "private key password" );
		status = cryptGetPrivateKey( cryptKeyset, cryptContext,
									 CRYPT_KEYID_NAME, keyName,
									 passwordBuffer );
		}
	cryptKeysetClose( cryptKeyset );
	return( status );
	}

/* Print extended certificate error information */

void printCertErrorInfo( const CRYPT_CERTIFICATE certificate )
	{
	int errorType, errorLocus;
	int status;

	status = cryptGetErrorInfo( certificate, &errorType, NULL, &errorLocus );
	if( cryptStatusOK( status ) && errorType != CRYPT_CERTERROR_NONE )
		printf( "cryptGetCertError() reports locus %d, type %d.\n",
				errorLocus, errorType );
	}

/* Add a collection of fields to a certificate */

int addCertFields( const CRYPT_CERTIFICATE certificate,
				   const CERT_DATA *certData )
	{
	int i;

	for( i = 0; certData[ i ].type != CRYPT_ATTRIBUTE_NONE; i++ )
		{
		int status;

		if( certData[ i ].componentType == IS_NUMERIC )
			{
			status = cryptAddCertComponentNumeric( certificate,
						certData[ i ].type, certData[ i ].numericValue );
			if( cryptStatusError( status ) )
				printf( "cryptAddCertComponentNumeric() for field ID %d, "
						"value %d, failed with error code %d, line %d\n",
						certData[ i ].type, certData[ i ].numericValue,
						status, __LINE__ );
			}
		else
			if( certData[ i ].componentType == IS_STRING )
				{
				status = cryptAddCertComponentString( certificate,
							certData[ i ].type, certData[ i ].stringValue,
							strlen( certData[ i ].stringValue ) );
				if( cryptStatusError( status ) )
					printf( "cryptAddCertComponentString() for field ID %d,\n"
							"value '%s', failed with error code %d, line %d\n",
							certData[ i ].type, certData[ i ].stringValue,
							status, __LINE__ );
				}
			else
				{
				status = cryptAddCertComponentString( certificate,
							certData[ i ].type, &certData[ i ].timeValue,
							sizeof( time_t ) );
				if( cryptStatusError( status ) )
					printf( "cryptAddCertComponentString() for field ID %d,\n"
							"value '%ld', failed with error code %d, line %d\n",
							certData[ i ].type, certData[ i ].timeValue,
							status, __LINE__ );
				}
		if( cryptStatusError( status ) )
			{
			printCertErrorInfo( certificate );
			return( FALSE );
			}
		}

	return( TRUE );
	}

/* Populate a key database with the contents of a directory.  This is a
   rather OS-specific utility function for setting up test databases which
   only works under Win32 */

#if defined( _MSC_VER ) && defined( _WIN32 )

void loadCertificates( void )
	{
	WIN32_FIND_DATA findData;
	HANDLE searchHandle;

	searchHandle = FindFirstFile( "d:/tmp/certs/*.der", &findData );
	if( searchHandle == INVALID_HANDLE_VALUE )
		return;
	do
		{
		CRYPT_CERTIFICATE cryptCert;
		int status;

		printf( "Adding cert %s.\n", findData.cFileName );
		status = importCertFile( &cryptCert, findData.cFileName );
		if( cryptStatusOK( status ) )
			{
			cryptDestroyCert( cryptCert );
			}
		}
	while( FindNextFile( searchHandle, &findData ) );
	FindClose( searchHandle );
	}
#endif /* Win32 */

/* Write an object to a file for debugging purposes */

void debugDump( const char *fileName, const void *data, const int dataLength )
	{
	FILE *filePtr;
	char fileNameBuffer[ 128 ];

#if defined( _MSC_VER ) 
	strcpy( fileNameBuffer, "d:/tmp/" );
#elif defined( __UNIX__ )
	strcpy( fileNameBuffer, "/tmp/" );
#else
	fileNameBuffer[ 0 ] = '\0';
#endif /* OS-specific paths */
	strcat( fileNameBuffer, fileName );
	strcat( fileNameBuffer, ".der" );

#if defined( __VMCMS__ )
	{
	char formatBuffer[ 32 ];

	sprintf( formatBuffer, "wb, recfm=F, lrecl=%d, noseek", dataLength );
	filePtr = fopen( fileNameBuffer, formatBuffer );
	}
	if( filePtr == NULL )
#else
	if( ( filePtr = fopen( fileNameBuffer, "wb" ) ) == NULL )
#endif /* __VMCMS__ */
		return;
	fwrite( data, dataLength, 1, filePtr );
	fclose( filePtr );
	}

/****************************************************************************
*																			*
*							Certificate Dump Routines						*
*																			*
****************************************************************************/

/* Print a DN */

static void printDN( const CRYPT_CERTIFICATE certificate )
	{
	char buffer[ CRYPT_MAX_TEXTSIZE + 1 ];
	int length, status;

	status = cryptGetCertComponentString( certificate,
						CRYPT_CERTINFO_COUNTRYNAME, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  C = %s.\n", buffer ); }
	status = cryptGetCertComponentString( certificate,
						CRYPT_CERTINFO_STATEORPROVINCENAME, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  S = %s.\n", buffer ); }
	status = cryptGetCertComponentString( certificate,
						CRYPT_CERTINFO_LOCALITYNAME, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  L = %s.\n", buffer ); }
	status = cryptGetCertComponentString( certificate,
						CRYPT_CERTINFO_ORGANIZATIONNAME, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  O = %s.\n", buffer ); }
	status = cryptGetCertComponentString( certificate,
						CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  OU = %s.\n", buffer ); }
	status = cryptGetCertComponentString( certificate,
						CRYPT_CERTINFO_COMMONNAME, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  CN = %s.\n", buffer ); }
	}

/* Print an altName */

static void printAltName( const CRYPT_CERTIFICATE certificate )
	{
	char buffer[ CRYPT_MAX_TEXTSIZE + 1 ];
	int length, status;

	status = cryptGetCertComponentString( certificate,
						CRYPT_CERTINFO_RFC822NAME, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  Email = %s.\n", buffer ); }
	status = cryptGetCertComponentString( certificate,
						CRYPT_CERTINFO_DNSNAME, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  DNSName = %s.\n", buffer ); }
	status = cryptGetCertComponentString( certificate,
						CRYPT_CERTINFO_EDIPARTYNAME_NAMEASSIGNER, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  EDI Nameassigner = %s.\n", buffer ); }
	status = cryptGetCertComponentString( certificate,
						CRYPT_CERTINFO_EDIPARTYNAME_PARTYNAME, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  EDI Partyname = %s.\n", buffer ); }
	status = cryptGetCertComponentString( certificate,
						CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  URL = %s.\n", buffer ); }
	status = cryptGetCertComponentString( certificate,
						CRYPT_CERTINFO_IPADDRESS, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  IP = %s.\n", buffer ); }
	status = cryptGetCertComponentString( certificate,
						CRYPT_CERTINFO_REGISTEREDID, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  Registered ID = %s.\n", buffer ); }
	}

/* Print information on a certificate */

void printCertInfo( const CRYPT_CERTIFICATE certificate )
	{
	CRYPT_CERTTYPE_TYPE certType;
	BOOLEAN hasExtensions = FALSE;
	char buffer[ CRYPT_MAX_TEXTSIZE + 1 ];
	int length, value, status;

	cryptGetCertComponentNumeric( certificate, CRYPT_CERTINFO_CERTTYPE,
								  &value );
	certType = value;

	/* Display the issuer and subject DN */
	if( certType != CRYPT_CERTTYPE_CERTREQUEST && \
		certType != CRYPT_CERTTYPE_CMS_ATTRIBUTES )
		{
		puts( "Certificate object issuer name is:" );
		cryptAddCertComponentNumeric( certificate, CRYPT_CERTINFO_ISSUERNAME,
									  CRYPT_UNUSED );
		printDN( certificate );
		cryptAddCertComponentNumeric( certificate, CRYPT_CERTINFO_ISSUERALTNAME,
									  CRYPT_UNUSED );
		printAltName( certificate );
		}
	if( certType != CRYPT_CERTTYPE_CRL && \
		certType != CRYPT_CERTTYPE_CMS_ATTRIBUTES )
		{
		puts( "Certificate object subject name is:" );
		cryptAddCertComponentNumeric( certificate, CRYPT_CERTINFO_SUBJECTNAME,
									  CRYPT_UNUSED );
		printDN( certificate );
		cryptAddCertComponentNumeric( certificate, CRYPT_CERTINFO_SUBJECTALTNAME,
									  CRYPT_UNUSED );
		printAltName( certificate );
		}

	/* Display the validity information */
	if( certType == CRYPT_CERTTYPE_CERTCHAIN ||
		certType == CRYPT_CERTTYPE_CERTIFICATE || \
		certType == CRYPT_CERTTYPE_ATTRIBUTE_CERT )
		{
		time_t validFrom, validTo;
		char buffer[ 50 ];

		cryptGetCertComponentString( certificate, CRYPT_CERTINFO_VALIDFROM,
									 &validFrom, &length );
		cryptGetCertComponentString( certificate, CRYPT_CERTINFO_VALIDTO,
									 &validTo, &length );
		strcpy( buffer, ctime( &validFrom ) );
		buffer[ strlen( buffer ) - 1 ] = '\0';	/* Stomp '\n' */
		printf( "Certificate is valid from %s to %s", buffer,
				ctime( &validTo ) );
		}
	if( certType == CRYPT_CERTTYPE_CRL )
		{
		char tuBuffer[ 50 ], nuBuffer[ 50 ];
		time_t timeStamp;
		int noEntries = 0;

		cryptGetCertComponentString( certificate, CRYPT_CERTINFO_THISUPDATE,
									 &timeStamp, &length );
		strcpy( tuBuffer, ctime( &timeStamp ) );
		tuBuffer[ strlen( tuBuffer ) - 1 ] = '\0';		/* Stomp '\n' */
		status = cryptGetCertComponentString( certificate, CRYPT_CERTINFO_NEXTUPDATE,
											  &timeStamp, &length );
		if( cryptStatusOK( status ) )
			{
			strcpy( nuBuffer, ctime( &timeStamp ) );
			nuBuffer[ strlen( nuBuffer ) - 1 ] = '\0';	/* Stomp '\n' */
			}
		cryptGetCertComponentString( certificate, CRYPT_CERTINFO_REVOCATIONDATE,
									 &timeStamp, &length );
			/* The revocation date is actually the date for the first revoked
			   cert, there can be more than one of these, accessible via the
			   cursor functions */
		if( cryptStatusOK( status ) )
			printf( "CRL time %s, next update %s,\n  revocation date %s",
					tuBuffer, nuBuffer, ctime( &timeStamp ) );
		else
			printf( "CRL time %s, revocation date %s", tuBuffer,
					ctime( &timeStamp ) );

		/* Count the entries */
		if( cryptAddCertComponentNumeric( certificate, CRYPT_CERTINFO_CURRENT_CERTIFICATE,
										  CRYPT_CURSOR_FIRST ) == CRYPT_OK )
			do
				{
				noEntries++;
				}
			while( cryptAddCertComponentNumeric( certificate,
										CRYPT_CERTINFO_CURRENT_CERTIFICATE,
										CRYPT_CURSOR_NEXT ) == CRYPT_OK );
		printf( "CRL has %d entr%s.\n", noEntries,
				( noEntries == 1 ) ? "y" : "ies" );
		}

	/* Display the self-signed status and fingerprint */
	if( cryptStatusOK( cryptGetCertComponentNumeric( certificate,
									CRYPT_CERTINFO_SELFSIGNED, &value ) ) )
		printf( "Certificate object is %sself-signed.\n",
				value ? "" : "not " );
	if( certType == CRYPT_CERTTYPE_CERTIFICATE || \
		certType == CRYPT_CERTTYPE_CERTCHAIN )
		{
		BYTE fingerPrint[ CRYPT_MAX_HASHSIZE ];
		int fingerPrintSize, i;

		cryptGetCertComponentString( certificate, CRYPT_CERTINFO_FINGERPRINT,
									 fingerPrint, &fingerPrintSize );
		printf( "Certificate fingerprint = " );
		for( i = 0; i < fingerPrintSize; i++ )
			printf( "%02X ", fingerPrint[ i ] );
		putchar( '\n' );
		}

	/* List the attribute types */
	puts( "Certificate extension/attribute types present (by cryptlib ID) "
		  "are:" );
	if( cryptAddCertComponentNumeric( certificate, CRYPT_CERTINFO_CURRENT_EXTENSION,
									  CRYPT_CURSOR_FIRST ) == CRYPT_OK )
		do
			{
			hasExtensions = TRUE;
			cryptGetCertComponentNumeric( certificate, CRYPT_CERTINFO_CURRENT_EXTENSION,
										  &value );
			printf( "  Extension type = %d.\n", value );
			}
	while( cryptAddCertComponentNumeric( certificate, CRYPT_CERTINFO_CURRENT_EXTENSION,
										 CRYPT_CURSOR_NEXT ) == CRYPT_OK );

	/* Display common attributes */
	if( !hasExtensions )
		{
		puts( "  (No extensions/attributes)." );
		return;
		}
	puts( "Some of the common extensions/attributes are:" );
	if( certType != CRYPT_CERTTYPE_CMS_ATTRIBUTES )
		{
		status = cryptGetCertComponentNumeric( certificate,
								CRYPT_CERTINFO_KEYUSAGE, &value );
		if( cryptStatusOK( status ) && value )
			printf( "  keyUsage = %04X.\n", value );
		status = cryptGetCertComponentNumeric( certificate,
								CRYPT_CERTINFO_CA, &value );
		if( cryptStatusOK( status ) && value )
			printf( "  basicConstraints.cA = %s.\n", value ? "True" : "False" );
		status = cryptGetCertComponentNumeric( certificate,
								CRYPT_CERTINFO_PATHLENCONSTRAINT, &value );
		if( cryptStatusOK( status ) && value )
			printf( "  basicConstraints.pathLenConstraint = %d.\n", value );
		status = cryptGetCertComponentString( certificate,
								CRYPT_CERTINFO_CERTPOLICYID, buffer, &length );
		if( cryptStatusOK( status ) )
			{
			buffer[ length ] = '\0';
			printf( "  certificatePolicies.policyInformation.policyIdentifier = "
					"%s.\n", buffer );
			}
		}
	else
		{
		time_t signingTime;

		cryptGetCertComponentString( certificate, CRYPT_CERTINFO_CMS_SIGNINGTIME,
									 &signingTime, &length );
		printf( "Signing time %s", ctime( &signingTime ) );
		}
	}

void printCertChainInfo( const CRYPT_CERTIFICATE certChain )
	{
	int value, count;

	/* Make sure it really is a cert chain */
	cryptGetCertComponentNumeric( certChain, CRYPT_CERTINFO_CERTTYPE,
								  &value );
	if( value != CRYPT_CERTTYPE_CERTCHAIN )
		{
		printCertInfo( certChain );
		return;
		}

	/* Display info on each cert in the chain.  This uses the cursor
	   mechanism to select successive certs in the chain from the leaf up to
	   the root */
	count = 0;
	cryptAddCertComponentNumeric( certChain, CRYPT_CERTINFO_CURRENT_CERTIFICATE,
								  CRYPT_CURSOR_FIRST );
	do
		{
		printf( "Certificate %d\n-------------\n", count++ );
		printCertInfo( certChain );
		putchar( '\n' );
		}
	while( cryptAddCertComponentNumeric( certChain,
			CRYPT_CERTINFO_CURRENT_CERTIFICATE, CRYPT_CURSOR_NEXT ) == CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Standalone main()							*
*																			*
****************************************************************************/

#ifdef STANDALONE_PROGRAM

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

/* Stucture to store DN components passed in by the caller */

typedef struct {
	const CRYPT_CERTINFO_TYPE type;
	const char *name;
	char *value;
	} DN_INFO;

/* Check whether a file already exists */

static int checkFileExists( const char *fileName,
							const BOOLEAN overwriteFile )
	{
	FILE *filePtr;

	/* Make sure the output file doesn't already exist */
	if( fileName == NULL || ( filePtr = fopen( fileName, "rb" ) ) == NULL )
		return( CRYPT_OK );
	fclose( filePtr );
	if( !overwriteFile )
		{
		printf( "Output file %s already exists.\n", fileName );
		return( ERROR_FILE_EXISTS );
		}
	return( CRYPT_OK );
	}

/* Break up a DN into its components */

static int parseDN( DN_INFO *dnInfo, char *dn )
	{
	char *dnPtr = dn;

	while( *dnPtr )
		{
		int i;

		/* Find the info on the current DN component */
		for( i = 0; dnInfo[ i ].type != SENTINEL; i++ )
			if( !strnicmp( dnPtr, dnInfo[ i ].name, 
						   strlen( dnInfo[ i ].name ) ) )
				break;
		if( dnInfo[ i ].type == SENTINEL )
			{
			printf( "Bad DN format '%s'.\n", dn );
			return( ERROR_BADARG );
			}
		if( dnInfo[ i ].value != NULL )
			{
			printf( "Duplicate component in DN '%s'.\n", dn );
			return( ERROR_BADARG );
			}
		dnPtr += strlen( dnInfo[ i ].name );
		if( *dnPtr++ != '=' )
			{
			printf( "Missing '=' in DN '%s'.\n", dn );
			return( ERROR_BADARG );
			}

		dnInfo[ i ].value = dnPtr;
		for( i = 0; dnPtr[ i ] != ',' && dnPtr[ i ]; i++ );
		if( dnPtr[ i ] )
			{
			/* There's more to follow, add a terminator and point to the rest
			   of the string */
			dnPtr[ i ] = '\0';
			dnPtr++;
			}
		dnPtr += i;
		}

	return( CRYPT_OK );
	}

/* Generate a new key + cert request/self-signed cert */

static int generateKey( const char *keysetName, const char *password,
						const char *label, const DN_INFO *dnInfo, 
						const BOOLEAN createSelfSigned )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT cryptContext;
	const char *keyLabel = ( label == NULL ) ? "Private key" : label;
	int status;

	/* Create a new RSA key */
	cryptCreateContext( &cryptContext, CRYPT_ALGO_RSA, CRYPT_MODE_PKC );
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL, keyLabel,
							 strlen( keyLabel ) );
	status = cryptGenerateKey( cryptContext );
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( cryptContext );
		printf( "Key generation failed with error %d.\n", status );
		return( status );
		}

	/* Write the key to the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  keysetName, CRYPT_KEYOPT_CREATE );
	if( cryptStatusOK( status ) )
		{
		status = cryptAddPrivateKey( cryptKeyset, cryptContext, password );
		cryptKeysetClose( cryptKeyset );
		}
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( cryptContext );
		printf( "Private keyset save failed with error code %d\n", status );
		return( status );
		}

	/* Create the certification request/certificate */
	cryptCreateCert( &cryptCert, createSelfSigned ? \
					 CRYPT_CERTTYPE_CERTIFICATE : CRYPT_CERTTYPE_CERTREQUEST );
	status = cryptAddCertComponentNumeric( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
	if( cryptStatusOK( status ) )
		{
		int i;

		/* Add each of the DN components */
		for( i = 0; dnInfo[ i ].type != SENTINEL; i++ )
			if( dnInfo[ i ].value != NULL )
				{
				status = cryptAddCertComponentString( cryptCert, dnInfo[ i ].type,
							dnInfo[ i ].value, strlen( dnInfo[ i ].value ) );
				if( cryptStatusError( status ) )
					break;
				}
		}
	if( cryptStatusOK( status ) && createSelfSigned )
		{
		/* Make it a self-signed CA cert */
		status = cryptAddCertComponentNumeric( cryptCert,
					CRYPT_CERTINFO_SELFSIGNED, TRUE );
		if( cryptStatusOK( status ) )
			status = cryptAddCertComponentNumeric( cryptCert,
					CRYPT_CERTINFO_KEYUSAGE,
					CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN );
		if( cryptStatusOK( status ) )
			status = cryptAddCertComponentNumeric( cryptCert,
					CRYPT_CERTINFO_CA, TRUE );
		}
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCert, cryptContext );
	cryptDestroyContext( cryptContext );
	if( cryptStatusError( status ) )
		{
		printf( "Certificate creation failed with error code %d.\n",
				status );
		printCertErrorInfo( cryptCert );
		cryptDestroyCert( cryptCert );
		return( status );
		}

	/* Update the private key keyset with the cert request/certificate */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  keysetName, CRYPT_KEYOPT_NONE );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetPrivateKey( cryptKeyset, NULL, CRYPT_KEYID_NONE,
									 NULL, password );
		if( cryptStatusOK( status ) )
			status = cryptAddPrivateKey( cryptKeyset, cryptCert, NULL );
		cryptKeysetClose( cryptKeyset );
		}

	/* Clean up */
	cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		printf( "Private key update failed with error code %d\n", status );
	return( status );
	}

/* Create a certificate from a cert request */

static int createCertificate( CRYPT_CERTIFICATE *certificate,
							  const CRYPT_CERTTYPE_TYPE certType,
							  const CRYPT_CERTIFICATE certRequest,
							  const CRYPT_CONTEXT caKeyContext )
	{
	int status;

	/* Verify the certification request */
	status = cryptCheckCert( certRequest, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( status );

	/* Create the certificate */
	status = cryptCreateCert( certificate, certType );
	if( cryptStatusError( status ) )
		return( status );
	status = cryptAddCertComponentNumeric( *certificate,
					CRYPT_CERTINFO_CERTREQUEST, certRequest );
	if( cryptStatusOK( status ) )
		status = cryptSignCert( *certificate, caKeyContext );

	return( status );
	}

/* Display the help info */

static void showHelp( void )
	{
	puts( "Usage: certutil -d<DN> -v -k{s} -s{c} -o -f<private key> -l<key label>" );
	puts( "                -p<password> <infile> <outfile>" );
	puts( "       -k = generate new key and create cert request" );
	puts( "       -ks = create self-signed CA root instead of cert request" );
	puts( "       -s = sign a cert request and create cert" );
	puts( "       -sc = create cert chain instead of cert" );
	puts( "       -u = update a private key with a cert object" );
	puts( "       -v = view/check cert object" );
	puts( "       -x = extract cert object from private key" );
	puts( "" );
	puts( "       -d = specify DN (components = C, SP, L, O, OU, CN, Email, URI)" );
	puts( "       -f = specify private key file" );
	puts( "       -o = overwrite output file" );
	puts( "       -p = specify password" );
	puts( "" );
	puts( "Examples:" );
	puts( "certutil -k -l\"My key\" keyfile         - Generate private key + cert.request" );
	puts( "certutil -k -d\"C=US,O=Foo Corp,CN=John Doe,Email=doe@foo.com\" keyfile   - DN" );
	puts( "certutil -ks keyfile            - Generate private key + self-signed CA cert" );
	puts( "certutil -s -pcakey infile outfile                       - Sign cert request" );
	puts( "certutil -u -puserkey infile  - Update users private key with cert in infile" );
	puts( "certutil -x -pkeyfile outfile      - Extract certificate object from keyfile" );
	puts( "certutil -v infile             - Display certificate object(s), verify sigs." );
	puts( "" );
	puts( "Long example: Create self-signed CA root, certify a cert.request:" );
	puts( "certutil -ks -l\"CA key\" -d<DN> cakey - Generate CA key + self-signed CA root" );
	puts( "certutil -k -l\"User key\" -d<DN> userkey - Generate user key and cert request" );
	puts( "certutil -x -puserkey certreq           - Extract cert request from user key" );
	puts( "certutil -s -pcakey certreq cert            - Sign cert request with CA root" );
	puts( "certutil -u -puserkey cert                   - Update user key with new cert" );
	}

/* The main program.  If we're not calling this from a test wrapper, use it 
   as our main() */

#ifndef WRAP_STANDALONE
  #define wrappedMain	main
#endif /* WRAP_STANDALONE */

int wrappedMain( int argc, char **argv )

	{
	CRYPT_CERTIFICATE certificate;
	DN_INFO dnInfo[] = {
		{ CRYPT_CERTINFO_COMMONNAME, "CN", NULL },
		{ CRYPT_CERTINFO_COUNTRYNAME, "C", NULL },
		{ CRYPT_CERTINFO_RFC822NAME, "Email", NULL },
		{ CRYPT_CERTINFO_LOCALITYNAME, "L", NULL },
		{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, "OU", NULL },
		{ CRYPT_CERTINFO_ORGANIZATIONNAME, "O", NULL },
		{ CRYPT_CERTINFO_STATEORPROVINCENAME, "SP", NULL },
		{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, "URI", NULL },
		{ SENTINEL, NULL, NULL }
		};
	char *keyFileName = NULL, *password = NULL, *label = NULL;
	char dnBuffer[ CRYPT_MAX_TEXTSIZE * 8 ];
	BOOLEAN doView = FALSE, doExtract = FALSE, doOverwriteOutput = FALSE;
	BOOLEAN doSign = FALSE, doUpdate = FALSE, doKeygen = FALSE;
	BOOLEAN optionFlag = FALSE;
	int status;

	/* Process the input parameters */
	puts( "Certificate utility for cryptlib 3.0beta.  Copyright Peter Gutmann 1998, 1999." );
	puts( "Warning: This is a debugging tool, not a user program!" );
	puts( "" );
	if( argc < 3 )
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
				case 'D':
					argPtr++;
					if( strlen( argPtr ) > CRYPT_MAX_TEXTSIZE * 8 )
						{
						puts( "DN too long" );
						return( ERROR_BADARG );
						}
					strcpy( dnBuffer, argPtr );
					argPtr += strlen( argPtr );
					status = parseDN( dnInfo, dnBuffer );
					if( cryptStatusError( status ) )
						return( status );
					break;

				case 'F':
					keyFileName = argPtr + 1;
					argPtr += strlen( argPtr );
					break;

				case 'K':
					doKeygen = TRUE;
					if( argPtr[ 1 ] )
						{
						if( toupper( argPtr[ 1 ] ) != 'S' )
							{
							puts( "Unknown key generation parameter." );
							return( ERROR_BADARG );
							}
						optionFlag = TRUE;
						argPtr++;
						}
					argPtr++;
					break;

				case 'L':
					label = argPtr + 1;
					argPtr += strlen( argPtr );
					break;

				case 'O':
					doOverwriteOutput = TRUE;
					argPtr++;
					break;

				case 'P':
					password = argPtr + 1;
					argPtr += strlen( argPtr );
					break;

				case 'S':
					doSign = TRUE;
					if( argPtr[ 1 ] )
						{
						if( toupper( argPtr[ 1 ] ) != 'C' )
							{
							puts( "Unknown output format parameter." );
							return( ERROR_BADARG );
							}
						optionFlag = TRUE;
						argPtr++;
						}
					argPtr++;
					break;

				case 'U':
					doUpdate = TRUE;
					argPtr++;
					break;

				case 'V':
					doView = TRUE;
					argPtr++;
					break;

				case 'X':
					doExtract = TRUE;
					argPtr++;
					break;

				default:
					printf( "Unknown option '%c'.\n", *argPtr );
					return( ERROR_BADARG );
				}
			}

		argc--;
		argv++;
		}

	/* Make sure we aren't trying to do too many things at once */
	status = 0;
	if( doView ) status++;
	if( doExtract ) status++;
	if( doKeygen ) status++;
	if( doSign ) status++;
	if( doUpdate ) status++;
	if( !status )
		{
		puts( "Nothing to do, you need to specify a command option." );
		return( ERROR_BADARG );
		}
	if( status > 1 )
		{
		puts( "You can't perform that many types of operation at once." );
		return( ERROR_BADARG );
		}

	/* Generate a key */
	if( doKeygen )
		{
		/* Make sure the file arg is in order */
		if( argc <= 1 )
			{
			puts( "You need to specify an output file for the key to be "
				  "generated into." );
			return( ERROR_BADARG );
			}
		status = checkFileExists( argv[ 1 ], doOverwriteOutput );
		if( status != CRYPT_OK )
			return( status );

		/* Generate the key + cert request/cert */
		status = generateKey( argv[ 1 ], password, label, dnInfo, optionFlag );
		}

	/* Extract a key from a private key file */
	if( doExtract )
		{
		CRYPT_KEYSET cryptKeyset;
		CRYPT_HANDLE cryptHandle;
		FILE *outFile;
		BYTE buffer[ BUFFER_SIZE ];
		int size;

		/* Make sure the files are right */
		if( keyFileName == NULL )
			{
			puts( "You must specify a keyfile to export the cert object from." );
			return( ERROR_BADARG );
			}
		if( argc <= 1 )
			{
			puts( "You need to specify an output file to export the cert "
				  "object into." );
			return( ERROR_BADARG );
			}
		status = checkFileExists( argv[ 1 ], doOverwriteOutput );
		if( status != CRYPT_OK )
			return( status );
		if( ( outFile = fopen( argv[ 1 ], "wb" ) ) == NULL )
			{
			perror( argv[ 1 ] );
			return( ERROR_FILE_INPUT );
			}

		/* Get the public key (with attached cert info) from the private key
		   keyset */
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
								  keyFileName, CRYPT_KEYOPT_READONLY );
		if( cryptStatusOK( status ) )
			{
			status = cryptGetPublicKey( cryptKeyset, &cryptHandle,
										CRYPT_KEYID_NONE, NULL );
			cryptKeysetClose( cryptKeyset );
			}
		if( cryptStatusError( status ) )
			{
			fclose( outFile );
			printf( "Couldn't read certificate object from private key "
					"file, error code %d.\n", status );
			return( -status );
			}

		/* Export the certificate object to the output file */
		status = cryptExportCert( buffer, &size,
							CRYPT_CERTFORMAT_CERTIFICATE, cryptHandle );
		if( cryptStatusOK( status ) )
			fwrite( buffer, 1, size, outFile );
		cryptDestroyObject( cryptHandle );
		if( cryptStatusError( status ) )
			printf( "Couldn't extract certificate object, error code %d.\n",
					status );

		/* Clean up */
		fclose( outFile );
		}

	/* Display/check a cert object */
	if( doView )
		{
		FILE *inFile;
		BYTE buffer[ BUFFER_SIZE ];
		int count;

		if( argc <= 1 )
			{
			puts( "You need to specify an input file to read the cert "
				  "object from." );
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
			printf( "Certificate object in file %s is too large for the "
					"internal buffer.\n", argv[ 1 ] );
			return( ERROR_FILE_INPUT );
			}
		status = cryptImportCert( buffer, &certificate );

		/* Display it */
		if( cryptStatusOK( status ) )
			printCertInfo( certificate );
		}

	/* Sign a cert request */
	if( doSign )
		{
		CRYPT_CONTEXT signContext;
		CRYPT_CERTIFICATE certificate, certRequest;
		FILE *outFile;
		BYTE buffer[ BUFFER_SIZE ];
		int count;

		/* Make sure the files are right */
		if( keyFileName == NULL )
			{
			puts( "You must specify a keyfile to sign the cert object with." );
			return( ERROR_BADARG );
			}
		if( argc <= 2 )
			{
			puts( "You need to specify an input file for the cert request "
				  "and and output file for the cert." );
			return( ERROR_BADARG );
			}

		/* Get the private key and cert request */
		status = getPrivateKey( &signContext, keyFileName, NULL );
		if( cryptStatusError( status ) )
			{
			printf( "Couldn't get private key, error code = %d.\n", status );
			return( -status );
			}
		status = importCertFile( &certRequest, argv[ 1 ] );
		if( cryptStatusError( status ) )
			{
			cryptDestroyContext( signContext );
			printf( "Couldn't import cert request, error code = %d.\n",
					status );
			return( -status );
			}

		/* Create the certificate from the cert request */
		status = createCertificate( &certificate, optionFlag ? \
					CRYPT_CERTTYPE_CERTCHAIN : CRYPT_CERTTYPE_CERTIFICATE,
					certRequest, signContext );
		cryptDestroyContext( signContext );
		cryptDestroyCert( certRequest );
		if( cryptStatusError( status ) )
			{
			printf( "Couldn't create certificate from cert request, error "
					"code = %d.\n", status );
			return( -status );
			}

		/* Export the cert and write it to the output file */
		cryptExportCert( buffer, &count, optionFlag ? \
					CRYPT_CERTFORMAT_CERTCHAIN : CRYPT_CERTFORMAT_CERTIFICATE,
					certificate );
		cryptDestroyCert( certificate );
		if( ( outFile = fopen( argv[ 2 ], "wb" ) ) == NULL )
			{
			perror( argv[ 2 ] );
			return( ERROR_FILE_INPUT );
			}
		fwrite( buffer, 1, count, outFile );
		fclose( outFile );
		}

	/* Update a private key with a cert object */
	if( doUpdate )
		{
		CRYPT_KEYSET cryptKeyset;
		CRYPT_CERTIFICATE certificate;

		/* Make sure the files are right */
		if( keyFileName == NULL )
			{
			puts( "You must specify a keyfile to upate." );
			return( ERROR_BADARG );
			}
		if( argc <= 1 )
			{
			puts( "You need to specify an input file to read the cert "
				  "object from." );
			return( ERROR_BADARG );
			}

		/* Import the cert object */
		status = importCertFile( &certificate, argv[ 1 ] );
		if( cryptStatusError( status ) )
			{
			printf( "Couldn't import cert object, error code = %d.\n",
					status );
			return( -status );
			}

		/* Update the private key keyset with the cert object */
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
								  keyFileName, CRYPT_KEYOPT_NONE );
		if( cryptStatusOK( status ) )
			{
			status = cryptGetPrivateKey( cryptKeyset, NULL, CRYPT_KEYID_NONE,
										 NULL, password );
			if( cryptStatusOK( status ) )
				status = cryptAddPrivateKey( cryptKeyset, certificate, NULL );
			cryptKeysetClose( cryptKeyset );
			}
		if( cryptStatusError( status ) )
			printf( "Couldn't update keyset with certificate object, error "
					"code %d.\n", status );
		}

	/* Clean up.  The cryptlib cleanup is handled by the atexit() function */
	if( cryptStatusError( status ) )
		{
		printf( "Certificate processing failed with error code %d\n",
				status );
		return( -status );
		}
	return( EXIT_SUCCESS );
	}

#ifdef WRAP_STANDALONE

int main( int argc, char **argv )
	{
	char *args1[] = {
		"", "-ks", 
		"-dC=US,O=Certificates R US,OU=Test CA,CN=John Doe,Email=doe@certsrus.com",
		"c:/temp/cakey.der"
		};
	char *args2[] = {
		"", "-k",
		"-dC=US,O=Foo Bar and Grill,OU=Hamburgers,CN=Burger Bob",
		"c:/temp/userkey.der"
		};
	char *args3[] = {
		"", "-x", "-fc:/temp/userkey.der", "c:/temp/certreq.der"
		};
	char *args4[] = {
		"", "-sc", "-fc:/temp/cakey.der", "c:/temp/certreq.der", "c:/temp/certchain.der"
		};
	char *args5[] = {
		"", "-u", "-fc:/temp/userkey.der", "c:/temp/certchain.der"
		};

	/* Generate self-signed CA root */
	wrappedMain( 4, args1 );

	/* Generate user key and cert request */
	wrappedMain( 4, args2 );

	/* Extract cert request from user key */
	wrappedMain( 4, args3 );

	/* Sign cert request with CA root to give cert chain */
	wrappedMain( 5, args4 );

	/* Update user key with new cert chain */
	wrappedMain( 4, args5 );
	}
#endif /* WRAP_STANDALONE */

#endif /* STANDALONE_PROGRAM */
