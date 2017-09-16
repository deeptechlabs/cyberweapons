/****************************************************************************
*																			*
*						cryptlib Enveloping Test Routines					*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _MSC_VER
  #include "../capi.h"
  #include "../test/test.h"
#else
  #include "capi.h"
  #include "test/test.h"
#endif /* Braindamaged MSC include handling */

/* Generic buffer size and dynamically-allocated file I/O buffer size.  The 
   generic buffer has to be of a reasonable size so we can handle S/MIME 
   signature chains, the file buffer should be less than the 16-bit INT_MAX 
   for testing on 16-bit machines */

#if defined( __MSDOS__ ) && defined( __TURBOC__ )
  #define BUFFER_SIZE		/*6144/**/3072/**/
  #define FILEBUFFER_SIZE	12000
#else
  #define BUFFER_SIZE		16384
  #define FILEBUFFER_SIZE	16384
#endif /* __MSDOS__ && __TURBOC__ */

/* Test data to use for the self-test */

#define ENVELOPE_TESTDATA		( ( BYTE * ) "Some test data" )
#define ENVELOPE_TESTDATA_SIZE	15

/* External flag which indicates that the key read routines work OK.  This is
   set by earlier self-test code, if it isn't set some of the enveloping
   tests are disabled */

extern int keyReadOK;

/****************************************************************************
*																			*
*								Utility Routines 							*
*																			*
****************************************************************************/

BYTE FAR_BSS buffer[ BUFFER_SIZE ];

/* Common routines to create an envelope, add enveloping information, push
   data, pop data, and destroy an envelope */

static int createEnvelope( CRYPT_ENVELOPE *envelope, const BOOLEAN isCMS )
	{
	int status;

	/* Create the envelope */
	status = cryptCreateEnvelopeEx( envelope, isCMS ? \
									CRYPT_FORMAT_CMS : CRYPT_FORMAT_CRYPTLIB,
									CRYPT_USE_DEFAULT );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateEnvelope() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

static int createDeenvelope( CRYPT_ENVELOPE *envelope )
	{
	int status;

	/* Create the envelope */
	status = cryptCreateDeenvelope( envelope );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateDeevelope() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

static int addEnvInfoString( const CRYPT_ENVELOPE envelope,
							 const CRYPT_ATTRIBUTE_TYPE type,
							 const void *envInfo, const int envInfoLen )
	{
	int status;

	status = cryptAddEnvComponentString( envelope, type, envInfo, envInfoLen );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddEnvelopeInfoString() failed with error code %d, "
				"line %d\n", status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

static int addEnvInfoNumeric( const CRYPT_ENVELOPE envelope,
							  const CRYPT_ATTRIBUTE_TYPE type,
							  const int envInfo )
	{
	int status;

	status = cryptAddEnvComponentNumeric( envelope, type, envInfo );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddEnvelopeInfoNumeric() failed with error code %d, "
				"line %d\n", status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

static int pushData( const CRYPT_ENVELOPE envelope, const BYTE *buffer,
					 const int length, const void *stringEnvInfo,
					 const int numericEnvInfo )
	{
	int status, bytesIn;

	/* Push in the data */
	status = cryptPushData( envelope, buffer, length, &bytesIn );
	if( status == CRYPT_ENVELOPE_RESOURCE )
		{
		int cryptEnvInfo;

		/* Add the appropriate enveloping information we need to continue */
		cryptAddEnvComponentNumeric( envelope,
					CRYPT_ENVINFO_CURRENT_COMPONENT, CRYPT_CURSOR_FIRST );
		do
			{
			char label[ CRYPT_MAX_TEXTSIZE + 1 ];
			int labelLength;

			status = cryptGetEnvComponentNumeric( envelope,
						CRYPT_ENVINFO_CURRENT_COMPONENT, &cryptEnvInfo );
			if( cryptStatusError( status ) )
				{
				printf( "cryptGetEnvComponentNumeric() failed with error code "
						"%d, line %d\n", status, __LINE__ );
				return( status );
				}

			switch( cryptEnvInfo )
				{
				case CRYPT_ATTRIBUTE_NONE:
					/* The required information was supplied via other means
					   (in practice this means there's a crypto device 
					   available and that was used for the decrypt), there's 
					   nothing left to do */
					puts( "(Decryption key was recovered using crypto device "
						  "or non-password-protected\n private key)." );
					break;

				case CRYPT_ENVINFO_PRIVATEKEY:
					/* Private key is present, need password to decrypt */
					status = cryptGetAttributeString( envelope, 
									CRYPT_ENVINFO_PRIVATEKEY_LABEL, 
									label, &labelLength );
					if( cryptStatusError( status ) )
						{
						printf( "Private key label read failed with error "
								"code %d, line %d\n", status, __LINE__ );
						return( status );
						}
					label[ labelLength ] = '\0';
					printf( "Need password to decrypt private key '%s'.\n", 
							label );
					if( !addEnvInfoString( envelope, CRYPT_ENVINFO_PASSWORD,
								stringEnvInfo, strlen( stringEnvInfo ) ) )
						return( SENTINEL );
					break;

				case CRYPT_ENVINFO_PASSWORD:
					puts( "Need user password." );
					if( !addEnvInfoString( envelope, CRYPT_ENVINFO_PASSWORD,
								stringEnvInfo, strlen( stringEnvInfo ) ) )
						return( SENTINEL );
					break;

				case CRYPT_ENVINFO_SESSIONKEY:
					puts( "Need session key." );
					if( !addEnvInfoNumeric( envelope, CRYPT_ENVINFO_SESSIONKEY,
											numericEnvInfo ) )
						return( SENTINEL );
					break;

				case CRYPT_ENVINFO_KEY:
					puts( "Need conventional encryption key." );
					break;

				case CRYPT_ENVINFO_SIGNATURE:
					/* If we've processed the entire data block in one go,
					   we may end up with only signature information
					   available, in which case we defer processing them
					   until after we've finished with the deenveloped data */
					break;

				default:
					printf( "Need unknown enveloping information type %d.\n",
							cryptEnvInfo );
					return( SENTINEL );
				}
			}
		while( cryptAddEnvComponentNumeric( envelope,
			CRYPT_ENVINFO_CURRENT_COMPONENT, CRYPT_CURSOR_NEXT ) == CRYPT_OK );

		/* If we're using some form of encrypted enveloping, report the 
		   algorithm and keysize used */
		if( cryptEnvInfo == CRYPT_ATTRIBUTE_NONE || \
			cryptEnvInfo == CRYPT_ENVINFO_PRIVATEKEY || \
			cryptEnvInfo == CRYPT_ENVINFO_PASSWORD )
			{
			int cryptAlgo, keySize;

			status = cryptGetAttribute( envelope, CRYPT_CTXINFO_ALGO, 
										&cryptAlgo );
			if( cryptStatusOK( status ) )
				status = cryptGetAttribute( envelope, CRYPT_CTXINFO_KEYSIZE, 
											&keySize );
			if( cryptStatusError( status ) )
				{
				printf( "Couldn't query encryption algorithm and keysize "
						"used in envelope, status %d, line %d.\n", status, 
						__LINE__ );
				return( status );
				}
			printf( "Data is protected using algorithm %d with %d bit key.\n",
					cryptAlgo, keySize * 8 );
			}
		}
	else
		if( cryptStatusError( status ) )
			{
			printf( "cryptPushData() failed with error code %d, line %d.\n",
					status, __LINE__ );
			return( status );
			}
	if( bytesIn != length )
		{
		printf( "cryptPushData() only copied %d of %d bytes, line %d\n",
				bytesIn, length, __LINE__ );
		return( SENTINEL );
		}

	/* Flush the data */
	status = cryptPushData( envelope, NULL, 0, NULL );
	if( cryptStatusError( status ) && status != CRYPT_ERROR_COMPLETE )
		{
		printf( "cryptPushData() (flush) failed with error code %d, line "
				"%d\n", status, __LINE__ );
		return( status );
		}

	return( bytesIn );
	}

static int popData( CRYPT_ENVELOPE envelope, BYTE *buffer, int bufferSize )
	{
	int status, bytesOut;

	status = cryptPopData( envelope, buffer, bufferSize, &bytesOut );
	if( cryptStatusError( status ) )
		{
		printf( "cryptPopData() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( status );
		}

	return( bytesOut );
	}

static int destroyEnvelope( CRYPT_ENVELOPE envelope )
	{
	int status;

	/* Destroy the envelope */
	status = cryptDestroyEnvelope( envelope );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyEnvelope() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

/****************************************************************************
*																			*
*							Enveloping Test Routines 						*
*																			*
****************************************************************************/

/* Test various parts of the enveloping code */

static int envelopeData( const BOOLEAN useDatasize, 
						 const BOOLEAN useLargeBuffer )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	BYTE *inBufPtr = ENVELOPE_TESTDATA, *outBufPtr = buffer;
	const int length = useLargeBuffer ? \
							( ( INT_MAX <= 32768L ) ? 16384 : 1048576 ) : \
							ENVELOPE_TESTDATA_SIZE;
	const int bufSize = length + 128;
	int count;

	if( useLargeBuffer )
		{
		int i;

		puts( "Testing enveloping of large data quantity..." );

		/* Allocate a large buffer and fill it with a known value */
		if( ( inBufPtr = malloc( bufSize ) ) == NULL )
			{
			printf( "Couldn't allocate buffer of %d bytes, skipping large "
					"buffer enveloping test.\n", length );
			return( TRUE );
			}
		outBufPtr = inBufPtr;
		for( i = 0; i < length; i++ )
			inBufPtr[ i ] = i & 0xFF;
		}
	else

		if( useDatasize )
			puts( "Testing plain data enveloping with datasize hint..." );
		else
			puts( "Testing plain data enveloping..." );

	/* Create the envelope, push in the data, pop the enveloped result, and
	   destroy the envelope */
	if( !createEnvelope( &cryptEnvelope, FALSE ) )
		return( FALSE );
	if( useDatasize )
		cryptAddEnvComponentNumeric( cryptEnvelope, CRYPT_ENVINFO_DATASIZE,
									 length );
	if( useLargeBuffer )
		cryptAddEnvComponentNumeric( cryptEnvelope, CRYPT_ATTRIBUTE_BUFFERSIZE,
									 length + 1024 );
	count = pushData( cryptEnvelope, inBufPtr, length, NULL, 0 );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, outBufPtr, bufSize );
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Tell them what happened */
	printf( "Enveloped data has size %d bytes.\n", count );
	if( !useLargeBuffer )
		debugDump( ( useDatasize ) ? "env_dat" : "env_datn", outBufPtr, 
				   count );

	/* Create the envelope, push in the data, pop the de-enveloped result,
	   and destroy the envelope */
	if( !createDeenvelope( &cryptEnvelope ) )
		return( FALSE );
	if( useLargeBuffer )
		cryptAddEnvComponentNumeric( cryptEnvelope, CRYPT_ATTRIBUTE_BUFFERSIZE,
									 length + 1024 );
	count = pushData( cryptEnvelope, outBufPtr, count, NULL, 0 );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, outBufPtr, bufSize );
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Make sure the result matches what we pushed */
	if( count != length )
		{
		puts( "De-enveloped data length != original length." );
		return( FALSE );
		}
	if( useLargeBuffer )
		{
		int i;

		for( i = 0; i < length; i++ )
			if( outBufPtr[ i ] != ( i & 0xFF ) )
			{
			printf( "De-enveloped data != original data at byte %d.\n", i );
			return( FALSE );
			}
		}
	else
		if( memcmp( outBufPtr, ENVELOPE_TESTDATA, length ) )
			{
			puts( "De-enveloped data != original data." );
			return( FALSE );
			}

	/* Clean up */
	if( useLargeBuffer )
		free( inBufPtr );
	puts( "Enveloping of plain data succeeded.\n" );
	return( TRUE );
	}

int testEnvelopeData( void )
	{
	if( !envelopeData( FALSE, FALSE ) )
		return( FALSE );
	return( envelopeData( TRUE, FALSE ) );
	}

int testLargeBufferEnvelopeData( void )
	{
	return( envelopeData( TRUE, TRUE ) );
	}

static int envelopeCompress( const BOOLEAN useDatasize )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	FILE *inFile;
	BYTE *buffer, *envelopedBuffer;
	int dataCount = 0, count;

	if( useDatasize )
		puts( "Testing compressed data enveloping with datasize hint..." );
	else
		puts( "Testing compressed data enveloping..." );

	/* Since this needs a nontrivial amount of data for the compression, we 
	   read it from an external file into dynamically-allocated buffers */
	if( ( ( buffer = malloc( FILEBUFFER_SIZE ) ) == NULL ) || \
		( ( envelopedBuffer = malloc( FILEBUFFER_SIZE ) ) == NULL ) )
		{
		if( buffer != NULL )
			free( buffer );
		puts( "Couldn't allocate test buffers." );
		return( FALSE );
		}
	inFile = fopen( COMPRESS_FILE, "rb" );
	if( inFile != NULL )
		{
		dataCount = fread( buffer, 1, FILEBUFFER_SIZE, inFile );
		fclose( inFile );
		}
	if( dataCount < 1000 || dataCount == FILEBUFFER_SIZE )
		{
		free( buffer );
		free( envelopedBuffer );
		puts( "Couldn't read test file for compression." );
		return( FALSE );
		}

	/* Create the envelope, push in the data, pop the enveloped result, and
	   destroy the envelope */
	if( !createEnvelope( &cryptEnvelope, FALSE ) )
		return( FALSE );
	cryptAddEnvComponentNumeric( cryptEnvelope, CRYPT_ENVINFO_COMPRESSION,
								 CRYPT_USE_DEFAULT );
	if( useDatasize )
		cryptAddEnvComponentNumeric( cryptEnvelope, CRYPT_ENVINFO_DATASIZE,
									 dataCount );
	count = pushData( cryptEnvelope, buffer, dataCount, NULL, 0 );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, envelopedBuffer, FILEBUFFER_SIZE );
	if( count > dataCount - 1000 )
		{
		puts( "Compression of data failed." );
		return( FALSE );
		}
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Tell them what happened */
	printf( "Enveloped data has size %d bytes.\n", count );
	debugDump( ( useDatasize ) ? "env_cpr" : "env_cprn", envelopedBuffer, 
			   count );

	/* Create the envelope, push in the data, pop the de-enveloped result,
	   and destroy the envelope */
	if( !createDeenvelope( &cryptEnvelope ) )
		return( FALSE );
	count = pushData( cryptEnvelope, envelopedBuffer, count, NULL, 0 );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, envelopedBuffer, FILEBUFFER_SIZE );
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Make sure the result matches what we pushed */
	if( count != dataCount || memcmp( buffer, envelopedBuffer, dataCount ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}

	/* Clean up */
	free( buffer );
	free( envelopedBuffer );
	puts( "Enveloping of compressed data succeeded.\n" );
	return( TRUE );
	}

int testEnvelopeCompress( void )
	{
	/* In practice these two produce identical output since we always have to
	   use the indefinite-length encoding internally because we don't know in
	   advance how large the compressed data will be */
	if( !envelopeCompress( FALSE ) )
		return( FALSE );
	return( envelopeCompress( TRUE ) );
	}

static int envelopeSessionCrypt( const BOOLEAN useDatasize )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	CRYPT_CONTEXT cryptContext;
	CRYPT_ALGO cryptAlgo = selectCipher( CRYPT_ALGO_CAST );
	int count;

	if( useDatasize )
		puts( "Testing raw-session-key encrypted enveloping with datasize hint..." );
	else
		puts( "Testing raw-session-key encrypted enveloping..." );

	/* If this version has been built without support for CAST-128, the self-
	   test will fall back to the (always available) Blowfish, however this
	   doesn't have an OID defined so we need to convert the choice to 3DES */
	if( cryptAlgo == CRYPT_ALGO_BLOWFISH )
		cryptAlgo = CRYPT_ALGO_3DES;

	/* Create the session key context.  We don't check for errors here since
	   this code will already have been tested earlier */
	cryptCreateContext( &cryptContext, cryptAlgo, CRYPT_MODE_CBC );
	cryptLoadKey( cryptContext, "0123456789ABCDEF", 16 );

	/* Create the envelope, push in a password and the data, pop the
	   enveloped result, and destroy the envelope */
	if( !createEnvelope( &cryptEnvelope, FALSE ) || \
		!addEnvInfoNumeric( cryptEnvelope, CRYPT_ENVINFO_SESSIONKEY,
							cryptContext ) )
		return( FALSE );
	if( useDatasize )
		cryptAddEnvComponentNumeric( cryptEnvelope, CRYPT_ENVINFO_DATASIZE,
									 ENVELOPE_TESTDATA_SIZE );
	count = pushData( cryptEnvelope, ENVELOPE_TESTDATA,
					  ENVELOPE_TESTDATA_SIZE, NULL, 0 );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Tell them what happened */
	printf( "Enveloped data has size %d bytes.\n", count );
	debugDump( ( useDatasize ) ? "env_ses" : "env_sesn", buffer, count );

	/* Create the envelope, push in the data, pop the de-enveloped result,
	   and destroy the envelope */
	if( !createDeenvelope( &cryptEnvelope ) )
		return( FALSE );
	count = pushData( cryptEnvelope, buffer, count, NULL, cryptContext );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Make sure the result matches what we pushed */
	if( count != ENVELOPE_TESTDATA_SIZE || \
		memcmp( buffer, ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyContext( cryptContext );
	puts( "Enveloping of raw-session-key-encrypted data succeeded.\n" );
	return( TRUE );
	}

int testEnvelopeSessionCrypt( void )
	{
	if( !envelopeSessionCrypt( FALSE ) )
		return( FALSE );
	return( envelopeSessionCrypt( TRUE ) );
	}

static int envelopeCrypt( const BOOLEAN useDatasize )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	int count;

	if( useDatasize )
		puts( "Testing password-encrypted enveloping with datasize hint..." );
	else
		puts( "Testing password-encrypted enveloping..." );

	/* Create the envelope, push in a password and the data, pop the
	   enveloped result, and destroy the envelope */
	if( !createEnvelope( &cryptEnvelope, FALSE ) || \
		!addEnvInfoString( cryptEnvelope, CRYPT_ENVINFO_PASSWORD, "Password", 8 ) )
		return( FALSE );
	if( useDatasize )
		cryptAddEnvComponentNumeric( cryptEnvelope, CRYPT_ENVINFO_DATASIZE,
									 ENVELOPE_TESTDATA_SIZE );
	count = pushData( cryptEnvelope, ENVELOPE_TESTDATA,
					  ENVELOPE_TESTDATA_SIZE, NULL, 0 );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Tell them what happened */
	printf( "Enveloped data has size %d bytes.\n", count );
	debugDump( ( useDatasize ) ? "env_pas" : "env_pasn", buffer, count );

	/* Create the envelope, push in the data, pop the de-enveloped result,
	   and destroy the envelope */
	if( !createDeenvelope( &cryptEnvelope ) )
		return( FALSE );
	count = pushData( cryptEnvelope, buffer, count, "Password", 8 );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Make sure the result matches what we pushed */
	if( count != ENVELOPE_TESTDATA_SIZE || \
		memcmp( buffer, ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}

	/* Clean up */
	puts( "Enveloping of password-encrypted data succeeded.\n" );
	return( TRUE );
	}

int testEnvelopeCrypt( void )
	{
	if( !envelopeCrypt( FALSE ) )
		return( FALSE );
	return( envelopeCrypt( TRUE ) );
	}

static int envelopePKCCrypt( const BOOLEAN useDatasize,
							 const BOOLEAN useRawKey,
							 const BOOLEAN useRecipient )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	CRYPT_KEYSET cryptKeyset;
	CRYPT_HANDLE cryptKey;
	int count, status;

	if( !keyReadOK )
		{
		puts( "Couldn't find key files, skipping test of public-key "
			  "encrypted enveloping..." );
		return( TRUE );
		}
	printf( "Testing public-key encrypted enveloping" );
	if( useDatasize )
		printf( " with datasize hint" );
	printf( ( useRawKey ) ? " using raw public key" : " using X.509 cert" );
	if( useRecipient )
		printf( " and recipient info" );
	puts( "..." );

	/* Open the keyset and either get the public key the hard (to make sure 
	   this version works) or leave the keyset open to allow it to be added
	   to the envelope */
	if( useRawKey )
		{
		/* Raw RSA key read from PGP keyring */
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
								  PGP_PUBKEY_FILE, CRYPT_KEYOPT_READONLY );
		if( cryptStatusOK( status ) )
			status = cryptGetPublicKey( cryptKeyset, &cryptKey,
										CRYPT_KEYID_NAME, "test" );
		cryptKeysetClose( cryptKeyset );
		if( cryptStatusError( status ) )
			{
			puts( "Read of public key from PGP keyring failed." );
			return( FALSE );
			}
		}
	else
		{
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
								  USER_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
		if( !useRecipient )
			{
			/* Certificate read from private key file */
			if( cryptStatusOK( status ) )
				status = cryptGetPublicKey( cryptKeyset, &cryptKey,
											CRYPT_KEYID_NAME, 
											USER_PRIVKEY_LABEL );
			cryptKeysetClose( cryptKeyset );
			if( cryptStatusError( status ) )
				{
				puts( "Read of public key from PGP keyring failed." );
				return( FALSE );
				}
			}
		}

	/* Create the envelope, push in the recipient info or public key and data, 
	   pop the enveloped result, and destroy the envelope */
	if( !createEnvelope( &cryptEnvelope, FALSE ) )
		return( FALSE );
	if( useRecipient )
		{
		/* Add recipient information to the envelope.  Since we can't 
		   guarantee that we have a real public-key keyset available at this 
		   time (it's created by a different part of the self-test code which
		   may not have run yet) we're actually reading the public key from 
		   the private-key keyset.  Normally we couldn't do this, however 
		   since PKCS #15 doesn't store email addresses as key ID's (there's
		   no need to), the code will drop back to trying for a match on the 
		   key label.  Because of this we specify the private key label 
		   instead of a real recipient email address.  Note that this trick 
		   only works because of a coincidence of two or three factors and
		   wouldn't normally be used, it's only used here because we can't
		   assume that a real public-key keyset is available for use */
		if( !addEnvInfoNumeric( cryptEnvelope, CRYPT_ENVINFO_KEYSET_ENCRYPT,
								cryptKeyset ) || \
			!addEnvInfoString( cryptEnvelope, CRYPT_ENVINFO_RECIPIENT,
							   USER_PRIVKEY_LABEL, strlen( USER_PRIVKEY_LABEL ) ) )
			return( FALSE );
		cryptKeysetClose( cryptKeyset );
		}
	else
		{
		if( !addEnvInfoNumeric( cryptEnvelope, CRYPT_ENVINFO_PUBLICKEY,
								cryptKey ) )
			return( FALSE );
		cryptDestroyObject( cryptKey );
		}
	if( useDatasize )
		cryptAddEnvComponentNumeric( cryptEnvelope, CRYPT_ENVINFO_DATASIZE,
									 ENVELOPE_TESTDATA_SIZE );
	count = pushData( cryptEnvelope, ENVELOPE_TESTDATA,
					  ENVELOPE_TESTDATA_SIZE, NULL, 0 );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Tell them what happened */
	printf( "Enveloped data has size %d bytes.\n", count );
	debugDump( ( useDatasize ) ? ( ( useRawKey ) ? "env_pkc" : "env_crt" ) : \
			   ( ( useRawKey ) ? "env_pkcn" : "env_crtn" ), buffer, count );

	/* Create the envelope and push in the decryption keyset */
	if( !createDeenvelope( &cryptEnvelope ) )
		return( FALSE );
	if( useRawKey )
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
								  PGP_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	else
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
								  USER_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		status = addEnvInfoNumeric( cryptEnvelope,
								CRYPT_ENVINFO_KEYSET_DECRYPT, cryptKeyset );
	cryptKeysetClose( cryptKeyset );
	if( !status )
		return( FALSE );

	/* Push in the data */
	count = pushData( cryptEnvelope, buffer, count, useRawKey ? \
					  "test10" : USER_PRIVKEY_PASSWORD, 0 );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Make sure the result matches what we pushed */
	if( count != ENVELOPE_TESTDATA_SIZE || \
		memcmp( buffer, ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}

	/* Clean up */
	puts( "Enveloping of public-key encrypted data succeeded.\n" );
	return( TRUE );
	}

int testEnvelopePKCCrypt( void )
	{
	if( cryptQueryCapability( CRYPT_ALGO_IDEA, NULL ) == CRYPT_ERROR_NOTAVAIL )
		puts( "Skipping raw public-key based enveloping, which requires the "
			  "IDEA cipher to\nbe enabled.\n" );
	else
		{
		if( !envelopePKCCrypt( FALSE, TRUE, FALSE ) )
			return( FALSE );
		if( !envelopePKCCrypt( TRUE, TRUE, FALSE ) )
			return( FALSE );
		}
	if( !envelopePKCCrypt( FALSE, FALSE, FALSE ) )
		return( FALSE );
	if( !envelopePKCCrypt( TRUE, FALSE, FALSE ) )
		return( FALSE );
	return( envelopePKCCrypt( TRUE, FALSE, TRUE ) );
	}

static int envelopeSign( const void *data, const int dataLength,
						 const BOOLEAN useDatasize, const BOOLEAN useRawKey )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int value, count, status;

	if( !keyReadOK )
		{
		puts( "Couldn't find key files, skipping test of signed "
			  "enveloping..." );
		return( TRUE );
		}
	printf( "Testing signed enveloping" );
	if( useDatasize )
		printf( " with datasize hint" );
	printf( ( useRawKey ) ? " using raw public key" : " using X.509 cert" );
	puts( "..." );

	/* Get the private key */
	if( useRawKey )
		{
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
								  PGP_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
		if( cryptStatusOK( status ) )
			{
			status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
										CRYPT_KEYID_NAME, "test", "test10" );
			cryptKeysetClose( cryptKeyset );
			}
		}
	else
		status = getPrivateKey( &cryptContext, USER_PRIVKEY_FILE,
								USER_PRIVKEY_LABEL, USER_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		puts( "Read of private key from key file failed, cannot test "
			  "enveloping." );
		return( FALSE );
		}

	/* Create the envelope, push in the signing key and data, pop the
	   enveloped result, and destroy the envelope */
	if( !createEnvelope( &cryptEnvelope, FALSE ) || \
		!addEnvInfoNumeric( cryptEnvelope, CRYPT_ENVINFO_SIGNATURE,
							cryptContext ) )
		return( FALSE );
	cryptDestroyContext( cryptContext );
	if( useDatasize )
		cryptAddEnvComponentNumeric( cryptEnvelope, CRYPT_ENVINFO_DATASIZE,
									 dataLength );
	count = pushData( cryptEnvelope, data, dataLength, NULL, 0 );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Tell them what happened */
	printf( "Enveloped data has size %d bytes.\n", count );
	debugDump( ( useDatasize ) ? ( ( useRawKey ) ? "env_sig" : "env_csg" ) : \
			   ( ( useRawKey ) ? "env_sign" : "env_csgn" ), buffer, count );

	/* Create the envelope and push in the sig.check keyset */
	if( !createDeenvelope( &cryptEnvelope ) )
		return( FALSE );
	if( useRawKey )
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
								  PGP_PUBKEY_FILE, CRYPT_KEYOPT_READONLY );
	else
		status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
								  USER_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		status = addEnvInfoNumeric( cryptEnvelope,
							CRYPT_ENVINFO_KEYSET_SIGCHECK, cryptKeyset );
	cryptKeysetClose( cryptKeyset );
	if( !status )
		return( FALSE );

	/* Push in the data */
	count = pushData( cryptEnvelope, buffer, count, NULL, 0 );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( cryptStatusError( count ) )
		return( FALSE );

	/* Determine the result of the signature check */
	cryptGetEnvComponentNumeric( cryptEnvelope,
								 CRYPT_ENVINFO_CURRENT_COMPONENT, &value );
	if( value != CRYPT_ENVINFO_SIGNATURE )
		{
		printf( "Envelope requires unexpected enveloping information type "
				"%d.\n", value );
		return( FALSE );
		}
	status = cryptGetEnvComponentNumeric( cryptEnvelope,
								CRYPT_ENVINFO_SIGNATURE_RESULT, &value );
	switch( value )
		{
		case CRYPT_OK:
			puts( "Signature is valid." );
			break;

		case CRYPT_DATA_NOTFOUND:
			puts( "Cannot find key to check signature." );
			break;

		case CRYPT_ERROR_SIGNATURE:
			puts( "Signature is invalid." );
			break;

		default:
			printf( "Signature check returned status %d.\n", status );
		}
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Make sure the result matches what we pushed */
	if( count != dataLength || memcmp( buffer, data, dataLength ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}

	/* Clean up */
	puts( "Enveloping of signed data succeeded.\n" );
	return( TRUE );
	}

int testEnvelopeSign( void )
	{
	if( cryptQueryCapability( CRYPT_ALGO_IDEA, NULL ) == CRYPT_ERROR_NOTAVAIL )
		puts( "Skipping raw public-key based signing, which requires the "
			  "IDEA cipher to\nbe enabled.\n" );
	else
		{
		if( !envelopeSign( ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE, 
						   FALSE, TRUE ) )
			return( FALSE );
		if( !envelopeSign( ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE, 
						   TRUE, TRUE ) )
			return( FALSE );
		}
	if( !envelopeSign( ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE, 
					   FALSE, FALSE ) )
		return( FALSE );
	return( envelopeSign( ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE, 
						  TRUE, FALSE ) );
	}

/****************************************************************************
*																			*
*							CMS Enveloping Test Routines 					*
*																			*
****************************************************************************/

/* Test CMS signature generation/checking */

static int cmsEnvelopeSigCheck( const void *signedData,
								const int signedDataLength,
								const BOOLEAN detachedSig,
								const BOOLEAN checkData )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	CRYPT_CERTIFICATE signerInfo;
	BOOLEAN sigStatus = FALSE;
	int value, count, status;

	/* Create the envelope and push in the data.  Since this is a CMS
	   signature which carries its certs with it, there's no need to push in
	   a sig.check keyset.  If it has a detached sig, we need to push two
	   lots of data, first the signature to set the envelope state, then the
	   data.  In addition if it's a detached sig, there's nothing to be
	   unwrapped so we don't pop any data */
	if( !createDeenvelope( &cryptEnvelope ) )
		return( FALSE );
	count = pushData( cryptEnvelope, signedData, signedDataLength, NULL, 0 );
	if( !cryptStatusError( count ) )
		if( detachedSig )
			count = pushData( cryptEnvelope, ENVELOPE_TESTDATA,
						  ENVELOPE_TESTDATA_SIZE, NULL, 0 );
		else
			count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( cryptStatusError( count ) )
		return( FALSE );

	/* Determine the result of the signature check */
	cryptGetEnvComponentNumeric( cryptEnvelope,
								 CRYPT_ENVINFO_CURRENT_COMPONENT, &value );
	if( value != CRYPT_ENVINFO_SIGNATURE )
		{
		printf( "Envelope requires unexpected enveloping information type "
				"%d.\n", value );
		return( FALSE );
		}
	status = cryptGetEnvComponentNumeric( cryptEnvelope,
								CRYPT_ENVINFO_SIGNATURE_RESULT, &value );
	switch( value )
		{
		case CRYPT_OK:
			puts( "Signature is valid." );
			sigStatus = TRUE;
			break;

		case CRYPT_DATA_NOTFOUND:
			puts( "Cannot find key to check signature." );
			break;

		case CRYPT_ERROR_SIGNATURE:
			puts( "Signature is invalid." );
			break;

		default:
			printf( "Signature check returned status %d.\n", status );
		}

	/* Report on the signer and signature info.  We continue even if the sig
	   status is bad since we can still try and display signing info even if
	   the check fails */
	status = cryptGetEnvComponentNumeric( cryptEnvelope,
							CRYPT_ENVINFO_SIGNATURE, &signerInfo );
	if( cryptStatusError( status ) && sigStatus )
		{
		printf( "Cannot retrieve signer information from CMS signature, "
				"status = %d.\n", status );
		return( FALSE );
		}
	if( cryptStatusOK( status ) )
		{
		puts( "Signer information is:" );
		printCertInfo( signerInfo );
		cryptDestroyCert( signerInfo );
		}
	status = cryptGetEnvComponentNumeric( cryptEnvelope,
							CRYPT_ENVINFO_SIGNATURE_EXTRADATA, &signerInfo );
	if( cryptStatusError( status ) && sigStatus && \
		status != CRYPT_DATA_NOTFOUND )
		{
		printf( "Cannot retrieve signature information from CMS signature, "
				"status = %d.\n", status );
		return( FALSE );
		}
	if( cryptStatusOK( status ) )
		{
		puts( "Signature information is:" );
		printCertInfo( signerInfo );
		cryptDestroyCert( signerInfo );
		}

	/* Make sure the result matches what we pushed */
	if( !detachedSig && checkData && ( count != ENVELOPE_TESTDATA_SIZE || \
		memcmp( buffer, ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE ) ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}

	/* Clean up */
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );
	return( sigStatus );
	}

static int cmsEnvelopeSign( const BOOLEAN useDatasize,
				const BOOLEAN useAttributes, const BOOLEAN useExtAttributes, 
				const BOOLEAN detachedSig, 
				const CRYPT_CONTEXT externalSignContext )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	CRYPT_CONTEXT cryptContext;
	int count, status;

	if( !keyReadOK )
		{
		puts( "Couldn't find key files, skipping test of CMS signed "
			  "enveloping..." );
		return( TRUE );
		}
	printf( "Testing CMS %s%s", ( useExtAttributes ) ? "extended " : "",
			( detachedSig ) ? "detached signature" : "signed enveloping" );
	if( !useAttributes )
		printf( " without signing attributes" );
	if( useDatasize )
		printf( " with datasize hint" );
	puts( "..." );

	/* Get the private key */
	if( externalSignContext != CRYPT_UNUSED )
		cryptContext = externalSignContext;
	else
		{
		status = getPrivateKey( &cryptContext, USER_PRIVKEY_FILE,
								USER_PRIVKEY_LABEL, USER_PRIVKEY_PASSWORD );
		if( cryptStatusError( status ) )
			{
			puts( "Read of private key from key file failed, cannot test "
				  "CMS enveloping." );
			return( FALSE );
			}
		}

	/* Create the CMS envelope, push in the signing key and data, pop the
	   enveloped result, and destroy the envelope */
	if( !createEnvelope( &cryptEnvelope, TRUE ) || \
		!addEnvInfoNumeric( cryptEnvelope, CRYPT_ENVINFO_SIGNATURE,
							cryptContext ) )
		return( FALSE );
	if( externalSignContext == CRYPT_UNUSED )
		cryptDestroyContext( cryptContext );
#if 0	/* Test non-data content type w.automatic attribute handling */
	cryptAddEnvComponentNumeric( cryptEnvelope, CRYPT_ENVINFO_CONTENTTYPE,
								 CRYPT_CONTENT_SIGNEDDATA );
#endif /* 1 */
	if( useDatasize )
		cryptAddEnvComponentNumeric( cryptEnvelope, CRYPT_ENVINFO_DATASIZE,
									 ENVELOPE_TESTDATA_SIZE );
	if( useExtAttributes )
		{
		CRYPT_CERTIFICATE cmsAttributes;

		/* Add an ESS security label as signing attributes */
		cryptCreateCert( &cmsAttributes, CRYPT_CERTTYPE_CMS_ATTRIBUTES );
		cryptAddCertComponentString( cmsAttributes,
						CRYPT_CERTINFO_CMS_SECLABEL_POLICY,
						"1 3 6 1 4 1 9999 1", 18 );
		cryptAddCertComponentNumeric( cmsAttributes,
						CRYPT_CERTINFO_CMS_SECLABEL_CLASSIFICATION,
						CRYPT_CLASSIFICATION_SECRET );
		status = cryptAddEnvComponentNumeric( cryptEnvelope,
						CRYPT_ENVINFO_SIGNATURE_EXTRADATA, cmsAttributes );
		cryptDestroyCert( cmsAttributes );
		if( cryptStatusError( status ) )
			{
			printf( "cryptAddEnvComponentNumeric() failed with error code "
					"%d, line %d\n", status, __LINE__ );
			return( FALSE );
			}
		}
	if( detachedSig )
		cryptAddEnvComponentNumeric( cryptEnvelope,
									 CRYPT_ENVINFO_DETACHEDSIGNATURE, TRUE );
	if( !useAttributes )
		cryptSetOptionNumeric( CRYPT_OPTION_CMS_DEFAULTATTRIBUTES, FALSE );
	count = pushData( cryptEnvelope, ENVELOPE_TESTDATA,
					  ENVELOPE_TESTDATA_SIZE, NULL, 0 );
	if( !useAttributes )
		cryptSetOptionNumeric( CRYPT_OPTION_CMS_DEFAULTATTRIBUTES, TRUE );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Tell them what happened */
	printf( "CMS %s has size %d bytes.\n", ( detachedSig ) ? \
			"detached signature" : "signed data", count );
	debugDump( ( detachedSig ) ? "smi_dsig" : ( useExtAttributes ) ? \
			   ( useDatasize ) ? "smi_esg" : "smi_esgn" : \
			   ( useDatasize ) ? "smi_sig" : "smi_sign", buffer, count );

	/* Make sure the signature is valid */
	status = cmsEnvelopeSigCheck( buffer, count, detachedSig, TRUE );
	if( !status )
		return( FALSE );

	if( detachedSig )
		printf( "Creation of CMS %sdetached signature succeeded.\n\n",
				( useExtAttributes ) ? "extended " : "" );
	else
		printf( "Enveloping of CMS %ssigned data succeeded.\n\n",
				( useExtAttributes ) ? "extended " : "" );
	return( TRUE );
	}

int testCMSEnvelopeSign( void )
	{
	if( !cmsEnvelopeSign( FALSE, FALSE, FALSE, FALSE, CRYPT_UNUSED ) )
		return( FALSE );
	if( !cmsEnvelopeSign( FALSE, TRUE, FALSE, FALSE, CRYPT_UNUSED ) )
		return( FALSE );
	if( !cmsEnvelopeSign( TRUE, TRUE, FALSE, FALSE, CRYPT_UNUSED ) )
		return( FALSE );
	if( !cmsEnvelopeSign( FALSE, TRUE, TRUE, FALSE, CRYPT_UNUSED ) )
		return( FALSE );
	return( cmsEnvelopeSign( TRUE, TRUE, TRUE, FALSE, CRYPT_UNUSED ) );
	}

int testCMSEnvelopeDetachedSig( void )
	{
	return( cmsEnvelopeSign( FALSE, TRUE, FALSE, TRUE, CRYPT_UNUSED ) );
	}

int testCMSEnvelopeSignExt( const CRYPT_CONTEXT signContext )
	{
	return( cmsEnvelopeSign( TRUE, TRUE, FALSE, FALSE, signContext ) );
	}

int testCMSImportSignedData( void )
	{
	FILE *filePtr;
	int count;

#if 1
	if( ( filePtr = fopen( SMIME_SIGNED_FILE, "rb" ) ) == NULL )
#else
	puts( "Kludging read" );
	if( ( filePtr = fopen( "c:/temp/smimesi.p7s", "rb" ) ) == NULL )
#endif
		{
		puts( "Couldn't find S/MIME SignedData file, skipping test of "
			  "SignedData import..." );
		return( TRUE );
		}
	puts( "Testing S/MIME SignedData import..." );
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
	if( count == BUFFER_SIZE )
		{
		puts( "The data buffer size is too small for the signed data.  To "
			  "fix this,\nincrease the BUFFER_SIZE value in " __FILE__
			  " and recompile the code." );
		return( TRUE );		/* Skip this test and continue */
		}
	printf( "SignedData has size %d bytes.\n", count );

	/* Check the signature on the data */
	if( !cmsEnvelopeSigCheck( buffer, count, FALSE, FALSE ) )
		return( FALSE );

	/* Clean up */
	puts( "Import of S/MIME SignedData succeeded.\n" );
	return( TRUE );
	}

/* Test CMS enveloping/de-enveloping */

static int cmsEnvelopeDecrypt( const void *envelopedData,
							   const int envelopedDataLength,
							   const CRYPT_HANDLE externalKeyset, 
							   const char *externalPassword )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	int count, status;

	/* Create the envelope and push in the decryption keyset */
	if( !createDeenvelope( &cryptEnvelope ) )
		return( FALSE );
	if( externalKeyset != CRYPT_UNUSED )
		status = addEnvInfoNumeric( cryptEnvelope,
								CRYPT_ENVINFO_KEYSET_DECRYPT, externalKeyset );
	else
		{
		CRYPT_KEYSET cryptKeyset;

		status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
								  USER_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
		if( cryptStatusOK( status ) )
			status = addEnvInfoNumeric( cryptEnvelope,
								CRYPT_ENVINFO_KEYSET_DECRYPT, cryptKeyset );
		cryptKeysetClose( cryptKeyset );
		}
	if( !status )
		return( FALSE );

	/* Push in the data */
	count = pushData( cryptEnvelope, envelopedData, envelopedDataLength,
					  ( externalPassword == NULL ) ? USER_PRIVKEY_PASSWORD : 
					  externalPassword, 0 );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Make sure the result matches what we pushed */
	if( count != ENVELOPE_TESTDATA_SIZE || \
		memcmp( buffer, ENVELOPE_TESTDATA, ENVELOPE_TESTDATA_SIZE ) )
		{
		puts( "De-enveloped data != original data." );
		return( FALSE );
		}

	return( TRUE );
	}

static int cmsEnvelopeCrypt( const BOOLEAN useDatasize, 
							 const CRYPT_HANDLE externalCryptContext,
							 const CRYPT_HANDLE externalKeyset,
							 const char *externalPassword )
	{
	CRYPT_ENVELOPE cryptEnvelope;
	CRYPT_HANDLE cryptKey;
	BOOLEAN isKeyAgreementKey = FALSE;
	int count, status;

	if( !keyReadOK )
		{
		puts( "Couldn't find key files, skipping test of CMS encrypted "
			  "enveloping..." );
		return( TRUE );
		}
	printf( "Testing CMS public-key encrypted enveloping" );
	if( useDatasize )
		printf( " with datasize hint" );
	puts( "..." );

	/* Get the public key.  We do it the hard way rather than just adding the
	   recipient info to make sure this version works */
	if( externalCryptContext != CRYPT_UNUSED )
		{
		int cryptAlgo;

		status = cryptGetAttribute( externalCryptContext, CRYPT_CTXINFO_ALGO, 
									&cryptAlgo );
		if( cryptStatusError( status ) )
			{
			puts( "Couldn't determine algorithm for public key, cannot test "
				  "CMS enveloping." );
			return( FALSE );
			}
		if( cryptAlgo == CRYPT_ALGO_KEA )
			isKeyAgreementKey = TRUE;
		cryptKey = externalCryptContext;
		}
	else
		{
		CRYPT_KEYSET cryptKeyset;

		status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
								  USER_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
		if( cryptStatusOK( status ) )
			status = cryptGetPublicKey( cryptKeyset, &cryptKey,
										CRYPT_KEYID_NAME, USER_PRIVKEY_LABEL );
		if( cryptStatusOK( status ) )
			status = cryptKeysetClose( cryptKeyset );
		if( cryptStatusError( status ) )
			{
			puts( "Read of public key from key file failed, cannot test "
				  "CMS enveloping." );
			return( FALSE );
			}
		}

	/* Create the envelope, add the public key and originator key if 
	   necessary, push in the data, pop the enveloped result, and destroy 
	   the envelope */
	if( !createEnvelope( &cryptEnvelope, TRUE ) || \
		!addEnvInfoNumeric( cryptEnvelope, CRYPT_ENVINFO_PUBLICKEY,
							cryptKey ) )
		return( FALSE );
	if( isKeyAgreementKey && \
		!addEnvInfoNumeric( cryptEnvelope, CRYPT_ENVINFO_ORIGINATOR,
							cryptKey ) )
		return( FALSE );
	if( externalCryptContext == CRYPT_UNUSED )
		cryptDestroyObject( cryptKey );
	if( useDatasize )
		cryptAddEnvComponentNumeric( cryptEnvelope, CRYPT_ENVINFO_DATASIZE,
									 ENVELOPE_TESTDATA_SIZE );
	count = pushData( cryptEnvelope, ENVELOPE_TESTDATA,
					  ENVELOPE_TESTDATA_SIZE, NULL, 0 );
	if( cryptStatusError( count ) )
		return( FALSE );
	count = popData( cryptEnvelope, buffer, BUFFER_SIZE );
	if( cryptStatusError( count ) )
		return( FALSE );
	if( !destroyEnvelope( cryptEnvelope ) )
		return( FALSE );

	/* Tell them what happened */
	printf( "Enveloped data has size %d bytes.\n", count );
	debugDump( ( useDatasize ) ? "smi_pkc" : "smi_pkcn", buffer, count );

	/* Make sure the enveloped data is valid */
	status = cmsEnvelopeDecrypt( buffer, count, externalKeyset, 
								 externalPassword );
	if( !status )
		return( FALSE );

	/* Clean up */
	puts( "Enveloping of CMS public-key encrypted data succeeded.\n" );
	return( TRUE );
	}

int testCMSEnvelopePKCCrypt( void )
	{
	if( !cmsEnvelopeCrypt( FALSE, CRYPT_UNUSED, CRYPT_UNUSED, NULL ) )
		return( FALSE );
	return( cmsEnvelopeCrypt( TRUE, CRYPT_UNUSED, CRYPT_UNUSED, NULL ) );
	}

int testCMSEnvelopePKCCryptEx( const CRYPT_HANDLE encryptContext,
							   const CRYPT_HANDLE decryptKeyset, 
							   const char *password )
	{
	return( cmsEnvelopeCrypt( TRUE, encryptContext, decryptKeyset, 
							  password ) );
	}

#if 0	/* This function doesn't currently serve any purpose since there's no
		   third-party enveloped data present to test */

int testCMSImportEnvelopedData( void )
	{
	FILE *filePtr;
	int count;

	if( ( filePtr = fopen( SMIME_ENVELOPED_FILE, "rb" ) ) == NULL )
		{
		puts( "Couldn't find S/MIME EnvelopedData file, skipping test of "
			  "EnvelopedData import..." );
		return( TRUE );
		}
	puts( "Testing S/MIME EnvelopedData import..." );
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
	if( count == BUFFER_SIZE )
		{
		puts( "The data buffer size is too small for the enveloped data.  To "
			  "fix this,\nincrease the BUFFER_SIZE value in " __FILE__
			  " and recompile the code." );
		return( TRUE );		/* Skip this test and continue */
		}
	printf( "EnvelopedData has size %d bytes.\n", count );

	/* Decrypt the data */
	if( !cmsEnvelopeDecrypt( buffer, count ) )
		return( FALSE );

	/* Clean up */
	puts( "Import of S/MIME EnvelopedData succeeded.\n" );
	return( TRUE );
	}
#endif /* 0 */
