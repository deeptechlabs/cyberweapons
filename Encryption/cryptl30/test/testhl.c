/****************************************************************************
*																			*
*					cryptlib Mid and High-Level Test Routines				*
*						Copyright Peter Gutmann 1995-1999					*
*																			*
****************************************************************************/

#include <limits.h>		/* To determine max.buffer size we can encrypt */
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

/* Generic I/O buffer size.  This has to be of a reasonable size so we can
   handle signatures with large keys and sizeable test certificates */

#ifdef __MSDOS__
  #define BUFFER_SIZE		1024
#else
  #define BUFFER_SIZE		4096
#endif /* Memory-starved environments */

/* Prototypes for functions in testlib.c */

int testLowlevel( const CRYPT_DEVICE cryptDevice, const CRYPT_ALGO cryptAlgo,
				  const CRYPT_MODE cryptMode, const BOOLEAN checkOnly );

/* Prototypes for functions in testenv.c */

int testCMSEnvelopeSignExt( const CRYPT_CONTEXT signContext );
int testCMSEnvelopePKCCryptEx( const CRYPT_HANDLE encryptContext,
							   const CRYPT_HANDLE decryptKeyset, 
							   const char *password );

/****************************************************************************
*																			*
*							Mid-level Routines Test							*
*																			*
****************************************************************************/

#if defined( TEST_MIDLEVEL ) || defined( TEST_DEVICE ) || \
	defined( TEST_HIGHLEVEL )

/* Test whether two session keys are identical */

static int compareSessionKeys( const CRYPT_CONTEXT cryptContext1,
							   const CRYPT_CONTEXT cryptContext2 )
	{
	BYTE buffer[ 8 ];
	int status;

	cryptLoadIV( cryptContext1, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 );
	cryptLoadIV( cryptContext2, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 );
	memcpy( buffer, "12345678", 8 );
	status = cryptEncrypt( cryptContext1, buffer, 8 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptEncrypt() with first key failed with error "
				"code %d, line %d\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptDecrypt( cryptContext2, buffer, 8 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDecrypt() with second key failed with error "
				"code %d, line %d\n", status, __LINE__ );
		return( FALSE );
		}
	if( memcmp( buffer, "12345678", 8 ) )
		{
		puts( "Data decrypted with key2 != plaintext encrypted with key1." );
		return( FALSE );
		}
	return( TRUE );
	}

#endif /* TEST_MIDLEVEL || TEST_DEVICE || TEST_HIGHLEVEL */

#if defined( TEST_MIDLEVEL ) || defined( TEST_DEVICE ) 

/* General-purpose routines to perform a key exchange and sign and sig 
   check data */

static int signData( const char *algoName, const CRYPT_ALGO algorithm,
					 const CRYPT_CONTEXT externalSignContext,
					 const CRYPT_CONTEXT externalCheckContext )
	{
	CRYPT_OBJECT_INFO cryptObjectInfo;
	CRYPT_CONTEXT signContext, checkContext;
	CRYPT_CONTEXT hashContext;
	BYTE *buffer, hashBuffer[] = "abcdefghijklmnopqrstuvwxyz";
	int status, length;

	printf( "Testing %s digital signature...\n", algoName );

	/* Create an SHA hash context and hash the test buffer */
	cryptCreateContext( &hashContext, CRYPT_ALGO_SHA, CRYPT_MODE_NONE );
	cryptEncrypt( hashContext, hashBuffer, 26 );
	cryptEncrypt( hashContext, hashBuffer, 0 );

	/* Create the appropriate en/decryption contexts */
	if( externalSignContext != CRYPT_UNUSED )
		{
		signContext = externalSignContext;
		checkContext = externalCheckContext;
		}
	else
		{
		if( algorithm == CRYPT_ALGO_DSA )
			status = loadDSAContexts( CRYPT_UNUSED, &signContext, 
									  &checkContext );
		else
			if( algorithm == CRYPT_ALGO_ELGAMAL )
				status = loadElgamalContexts( &checkContext, &signContext );
			else
				status = loadRSAContexts( CRYPT_UNUSED, &checkContext, 
										  &signContext );
		if( !status )
			return( FALSE );
		}

	/* Find out how big the signature will be */
	status = cryptCreateSignature( NULL, &length, signContext, hashContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateSignature() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "cryptCreateSignature() reports signature object will be %d "
			"bytes long\n", length );
	if( ( buffer = malloc( length ) ) == NULL )
		return( FALSE );

	/* Sign the hashed data */
	status = cryptCreateSignature( buffer, &length, signContext, hashContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateSignature() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}

	/* Query the signed object */
	status = cryptQueryObject( buffer, &cryptObjectInfo );
	if( cryptStatusError( status ) )
		{
		printf( "cryptQueryObject() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}
	printf( "cryptQueryObject() reports object type %d, algorithm %d, mode "
			"%d.\n", cryptObjectInfo.objectType, cryptObjectInfo.cryptAlgo,
			cryptObjectInfo.cryptMode );
	memset( &cryptObjectInfo, 0, sizeof( CRYPT_OBJECT_INFO ) );
	debugDump( "signature", buffer, length );

	/* Check the signature on the hash */
	status = cryptCheckSignature( buffer, checkContext, hashContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCheckSignature() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyContext( hashContext );
	if( externalSignContext == CRYPT_UNUSED )
		destroyContexts( CRYPT_UNUSED, checkContext, signContext );
	printf( "Generation and checking of %s digital signature via %d-bit "
			"data block\n  succeeded.\n", algoName, PKC_KEYSIZE );
	free( buffer );
	return( TRUE );
	}

static int keyExportImport( const char *algoName, const CRYPT_ALGO algorithm,
							const CRYPT_CONTEXT externalCryptContext,
							const CRYPT_CONTEXT externalDecryptContext )
	{
	CRYPT_OBJECT_INFO cryptObjectInfo;
	CRYPT_CONTEXT cryptContext, decryptContext;
	CRYPT_CONTEXT sessionKeyContext1, sessionKeyContext2;
	BYTE *buffer;
	int status, length;

	printf( "Testing %s public-key export/import...\n", algoName );

	/* Create RC2 encryption contexts for the session key */
	cryptCreateContext( &sessionKeyContext1, selectCipher( CRYPT_ALGO_RC2 ),
						CRYPT_MODE_OFB );
	cryptGenerateKey( sessionKeyContext1 );
	cryptCreateContext( &sessionKeyContext2, selectCipher( CRYPT_ALGO_RC2 ),
						CRYPT_MODE_OFB );

	/* Create the appropriate en/decryption contexts */
	if( externalCryptContext != CRYPT_UNUSED )
		{
		cryptContext = externalCryptContext;
		decryptContext = externalDecryptContext;
		}
	else
		{
		if( algorithm == CRYPT_ALGO_ELGAMAL )
			status = loadElgamalContexts( &cryptContext, &decryptContext );
		else
			status = loadRSAContexts( CRYPT_UNUSED, &cryptContext, &decryptContext );
		if( !status )
			return( FALSE );
		}

	/* Find out how big the exported key will be */
	status = cryptExportKey( NULL, &length, cryptContext, sessionKeyContext1 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptExportKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "cryptExportKey() reports exported key object will be %d bytes "
			"long\n", length );
	if( ( buffer = malloc( length ) ) == NULL )
		return( FALSE );

	/* Export the session key */
	status = cryptExportKey( buffer, &length, cryptContext, sessionKeyContext1 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptExportKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}

	/* Query the encrypted key object */
	status = cryptQueryObject( buffer, &cryptObjectInfo );
	if( cryptStatusError( status ) )
		{
		printf( "cryptQueryObject() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}
	printf( "cryptQueryObject() reports object type %d, algorithm %d, mode "
			"%d.\n", cryptObjectInfo.objectType, cryptObjectInfo.cryptAlgo,
			cryptObjectInfo.cryptMode );
	memset( &cryptObjectInfo, 0, sizeof( CRYPT_OBJECT_INFO ) );
	debugDump( "keytrans", buffer, length );

	/* Recreate the session key by importing the encrypted key */
	status = cryptImportKey( buffer, decryptContext, sessionKeyContext2 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}

	/* Make sure the two keys match */
	if( !compareSessionKeys( sessionKeyContext1, sessionKeyContext2 ) )
		return( FALSE );

	/* Clean up */
	destroyContexts( CRYPT_UNUSED, sessionKeyContext1, sessionKeyContext2 );
	if( externalCryptContext == CRYPT_UNUSED )
		destroyContexts( CRYPT_UNUSED, cryptContext, decryptContext );
	printf( "Export/import of session key via %d-bit %s-encrypted data "
			"block succeeded.\n\n", PKC_KEYSIZE, algoName );
	free( buffer );
	return( TRUE );
	}

#endif /* TEST_MIDLEVEL || TEST_DEVICE */

#ifdef TEST_RANDOM

/* Test the randomness gathering routines */

int testRandomRoutines( void )
	{
	CRYPT_CONTEXT cryptContext;
	int status;

	puts( "Testing randomness routines.  This may take a few seconds..." );

	/* Create an encryption context to generate a key into */
	cryptCreateContext( &cryptContext, CRYPT_ALGO_DES, CRYPT_MODE_ECB );
	status = cryptGenerateKey( cryptContext );
	cryptDestroyContext( cryptContext );

	/* Check whether we got enough randomness */
	if( status == CRYPT_ERROR_RANDOM )
		{
		puts( "The randomness-gathering routines in the library can't acquire enough" );
		puts( "random information to allow key generation and public-key encryption to" );
		puts( "function.  You will need to change lib_rand.c or reconfigure your system" );
		puts( "to allow the randomness-gathering routines to function.  The code to" );
		puts( "change can be found in misc/rndXXXX.c\n" );
		return( FALSE );
		}

	puts( "Randomness-gathering self-test succeeded.\n" );
	return( TRUE );
	}

#endif /* TEST_RANDOM */

#ifdef TEST_MIDLEVEL

/* Test the ability to encrypt a large amount of data */

int testLargeBufferEncrypt( void )
	{
	CRYPT_CONTEXT cryptContext;
	BYTE *buffer;
	const size_t length = ( INT_MAX <= 32768L ) ? 16384 : 1048576;
	int i, status;

	puts( "Testing encryption of large data quantity..." );

	/* Allocate a large buffer and fill it with a known value */
	if( ( buffer = malloc( length ) ) == NULL )
		{
		printf( "Couldn't allocate buffer of %d bytes, skipping large buffer "
				"encryption test.\n", length );
		return( TRUE );
		}
	memset( buffer, '*', length );

	/* Encrypt the buffer */
	cryptCreateContext( &cryptContext, CRYPT_ALGO_DES, CRYPT_MODE_CBC );
	cryptLoadKey( cryptContext, "12345678", 8 );
	cryptLoadIV( cryptContext, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 );
	status = cryptEncrypt( cryptContext, buffer, length );
	if( cryptStatusError( status ) )
		{
		printf( "cryptEncrypt() of large data quantity failed with error "
				"code %d, line %d\n", status, __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* Decrypt the buffer */
	cryptCreateContext( &cryptContext, CRYPT_ALGO_DES, CRYPT_MODE_CBC );
	cryptLoadKey( cryptContext, "12345678", 8 );
	cryptLoadIV( cryptContext, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 );
	status = cryptDecrypt( cryptContext, buffer, length );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDecrypt() of large data quantity failed with error "
				"code %d, line %d\n", status, __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* Make sure it went OK */
	for( i = 0; i < ( int ) length; i++ )
		if( buffer[ i ] != '*' )
			{
			printf( "Decrypted data != original plaintext at position %d.\n",
					i );
			return( FALSE );
			}

	/* Clean up */
	free( buffer );
	printf( "Encryption of %d bytes of data succeeded.\n\n", length );
	return( TRUE );
	}

/* Test the code to derive a fixed-length encryption key from a variable-
   length user key */

int testDeriveKey( void )
	{
	CRYPT_CONTEXT cryptContext, decryptContext;
	BYTE *userKey = ( BYTE * ) "This is a long user key for cryptDeriveKey()";
	BYTE buffer[ 8 ];
	int userKeyLength = strlen( ( char * ) userKey ), status;

	puts( "Testing key derivation..." );

	/* Create IDEA/CBC encryption and decryption contexts and load them with
	   identical salt values for the key derivation (this is easier than
	   reading the salt from one and writing it to the other) */
	cryptCreateContext( &cryptContext, selectCipher( CRYPT_ALGO_IDEA ), 
						CRYPT_MODE_CBC );
	cryptCreateContext( &decryptContext, selectCipher( CRYPT_ALGO_IDEA ), 
						CRYPT_MODE_CBC );
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_KEYING_SALT,
							 "\x12\x34\x56\x78\x78\x56\x34\x12", 8 );
	cryptSetAttributeString( decryptContext, CRYPT_CTXINFO_KEYING_SALT,
							 "\x12\x34\x56\x78\x78\x56\x34\x12", 8 );

	/* Load an IDEA key derived from a user key into both contexts */
	status = cryptDeriveKey( cryptContext, userKey, userKeyLength );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDeriveKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptDeriveKey( decryptContext, userKey, userKeyLength );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDeriveKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure the two derived keys match */
	if( !compareSessionKeys( cryptContext, decryptContext ) )
		return( FALSE );

	/* Clean up */
	destroyContexts( CRYPT_UNUSED, cryptContext, decryptContext );

	/* Test the derivation process using fixed test data: password = 
	   "password", salt = 0x12345678, iterations = 5 */
	cryptCreateContext( &cryptContext, CRYPT_ALGO_DES, CRYPT_MODE_ECB );
	cryptSetAttribute( cryptContext, CRYPT_CTXINFO_MODE, CRYPT_MODE_ECB );
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_KEYING_SALT,
							 "\x12\x34\x56\x78", 4 );
	cryptSetAttribute( cryptContext, CRYPT_CTXINFO_KEYING_ITERATIONS, 5 );
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_KEYING_VALUE,
							 "password", 8 );
	memset( buffer, 0, 8 );
	cryptEncrypt( cryptContext, buffer, 8 );
	cryptDestroyContext( cryptContext );
	if( memcmp( buffer, "\x75\xFF\x21\x71\x25\x30\x46\x8C", 8 ) )
		{
		puts( "Derived key value doesn't match predefined test value." );
		return( FALSE );
		}

	puts( "Generation of key via cryptDeriveKey() succeeded.\n" );
	return( TRUE );
	}

/* Test the code to export/import an encrypted key via conventional
   encryption.  This demonstrates the ability to use one context type to
   export another - we export a triple DES key using Blowfish.  We're not as
   picky with error-checking here since most of the functions have just
   executed successfully */

int testConventionalExportImport( void )
	{
	CRYPT_OBJECT_INFO cryptObjectInfo;
	CRYPT_CONTEXT cryptContext, decryptContext;
	CRYPT_CONTEXT sessionKeyContext1, sessionKeyContext2;
	char *userKey = ( BYTE * ) "All n-entities must communicate with other "
							   "n-entities via n-1 entiteeheehees";
	BYTE *buffer;
	int userKeyLength = strlen( userKey );
	int status, length;

	puts( "Testing conventional key export/import..." );

	/* Create triple-DES encryption contexts for the session key */
	cryptCreateContext( &sessionKeyContext1, CRYPT_ALGO_3DES, CRYPT_MODE_CFB );
	cryptSetAttribute( sessionKeyContext1, CRYPT_CTXINFO_MODE, CRYPT_MODE_CFB );
	cryptGenerateKey( sessionKeyContext1 );
	cryptCreateContext( &sessionKeyContext2, CRYPT_ALGO_3DES, CRYPT_MODE_CFB );
	cryptSetAttribute( sessionKeyContext2, CRYPT_CTXINFO_MODE, CRYPT_MODE_CFB );

	/* Create a Blowfish encryption context to export the session key */
	cryptCreateContext( &cryptContext, CRYPT_ALGO_BLOWFISH, CRYPT_MODE_CBC );
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_KEYING_SALT,
							 "\x12\x34\x56\x78\x78\x56\x34\x12", 8 );
	cryptDeriveKey( cryptContext, userKey, userKeyLength );

	/* Find out how big the exported key will be */
	status = cryptExportKey( NULL, &length, cryptContext, sessionKeyContext1 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptExportKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "cryptExportKey() reports exported key object will be %d bytes "
			"long\n", length );
	if( ( buffer = malloc( length ) ) == NULL )
		return( FALSE );

	/* Export the session information */
	status = cryptExportKey( buffer, &length, cryptContext, sessionKeyContext1 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptExportKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}

	/* Query the encrypted key object */
	status = cryptQueryObject( buffer, &cryptObjectInfo );
	if( cryptStatusError( status ) )
		{
		printf( "cryptQueryObject() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}
	printf( "cryptQueryObject() reports object type %d, algorithm %d, mode "
			"%d.\n", cryptObjectInfo.objectType, cryptObjectInfo.cryptAlgo,
			cryptObjectInfo.cryptMode );
	debugDump( "kek", buffer, length );

	/* Recreate the session key by importing the encrypted key */
	status = cryptCreateContextEx( &decryptContext,
								   cryptObjectInfo.cryptAlgo,
								   cryptObjectInfo.cryptMode,
								   cryptObjectInfo.cryptContextExInfo );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateContext() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}
	cryptSetAttributeString( decryptContext, CRYPT_CTXINFO_KEYING_SALT,
							 cryptObjectInfo.salt, cryptObjectInfo.saltSize );
	cryptDeriveKey( decryptContext, userKey, userKeyLength );

	status = cryptImportKey( buffer, decryptContext, sessionKeyContext2 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}

	/* Make sure the two keys match */
	if( !compareSessionKeys( sessionKeyContext1, sessionKeyContext2 ) )
		return( FALSE );

	/* Clean up */
	destroyContexts( CRYPT_UNUSED, sessionKeyContext1, sessionKeyContext2 );
	destroyContexts( CRYPT_UNUSED, cryptContext, decryptContext );
	printf( "Export/import of Blowfish key via user-key-based triple DES "
			"conventional\n  encryption succeeded.\n\n" );
	free( buffer );
	return( TRUE );
	}

int testMACExportImport( void )
	{
	CRYPT_OBJECT_INFO cryptObjectInfo;
	CRYPT_CONTEXT cryptContext, decryptContext;
	CRYPT_CONTEXT macContext1, macContext2;
	BYTE mac1[ CRYPT_MAX_HASHSIZE ], mac2[ CRYPT_MAX_HASHSIZE ];
	BYTE *userKey = ( BYTE * ) "This is a long user key for cryptDeriveKey()";
	BYTE *buffer;
	int userKeyLength = strlen( ( char * ) userKey );
	int status, length1, length2;

	puts( "Testing MAC key export/import..." );

	/* Create HMAC-SHA1 contexts for the MAC key */
	cryptCreateContext( &macContext1, CRYPT_ALGO_HMAC_SHA, CRYPT_MODE_NONE );
	cryptGenerateKey( macContext1 );
	cryptCreateContext( &macContext2, CRYPT_ALGO_HMAC_SHA, CRYPT_MODE_NONE );

	/* Create a 3DES encryption context to export the MAC key */
	cryptCreateContext( &cryptContext, CRYPT_ALGO_3DES, CRYPT_MODE_CBC );
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_KEYING_SALT,
							 "\x12\x34\x56\x78\x78\x56\x34\x12", 8 );
	cryptDeriveKey( cryptContext, userKey, userKeyLength );

	/* Find out how big the exported key will be */
	status = cryptExportKey( NULL, &length1, cryptContext, macContext1 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptExportKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "cryptExportKey() reports exported key object will be %d bytes "
			"long\n", length1 );
	if( ( buffer = malloc( length1 ) ) == NULL )
		return( FALSE );

	/* Export the MAC information */
	status = cryptExportKey( buffer, &length1, cryptContext, macContext1 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptExportKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}

	/* Query the encrypted key object */
	status = cryptQueryObject( buffer, &cryptObjectInfo );
	if( cryptStatusError( status ) )
		{
		printf( "cryptQueryObject() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}
	printf( "cryptQueryObject() reports object type %d, algorithm %d, mode "
			"%d.\n", cryptObjectInfo.objectType, cryptObjectInfo.cryptAlgo,
			cryptObjectInfo.cryptMode );
	debugDump( "kek_mac", buffer, length1 );

	/* Recreate the MAC key by importing the encrypted key */
	status = cryptCreateContextEx( &decryptContext,
								   cryptObjectInfo.cryptAlgo,
								   cryptObjectInfo.cryptMode,
								   cryptObjectInfo.cryptContextExInfo );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateContext() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}
	cryptSetAttributeString( decryptContext, CRYPT_CTXINFO_KEYING_SALT,
							 cryptObjectInfo.salt, cryptObjectInfo.saltSize );
	cryptDeriveKey( decryptContext, userKey, userKeyLength );

	status = cryptImportKey( buffer, decryptContext, macContext2 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}

	/* Make sure the two MAC keys match */
	cryptEncrypt( macContext1, "1234", 4 );
	cryptEncrypt( macContext1, NULL, 0 );
	cryptEncrypt( macContext2, "1234", 4 );
	cryptEncrypt( macContext2, NULL, 0 );
	cryptGetAttributeString( macContext1, CRYPT_CTXINFO_HASHVALUE, 
							 mac1, &length1 );
	cryptGetAttributeString( macContext2, CRYPT_CTXINFO_HASHVALUE, 
							 mac2, &length2 );
	if( ( length1 != length2 ) || memcmp( mac1, mac2, length1 ) || \
		!memcmp( mac1, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 ) || \
		!memcmp( mac2, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 ) )
		{
		puts( "Data MAC'd with key1 != data MAC'd with key2." );
		return( FALSE );
		}

	/* Clean up */
	destroyContexts( CRYPT_UNUSED, macContext1, macContext2 );
	destroyContexts( CRYPT_UNUSED, cryptContext, decryptContext );
	printf( "Export/import of MAC key via user-key-based triple DES "
			"conventional\n  encryption succeeded.\n\n" );
	free( buffer );
	return( TRUE );
	}

/* Test the code to export/import an encrypted key.  We're not as picky with
   error-checking here since most of the functions have just executed
   successfully */

int testKeyExportImport( void )
	{
	int status;

	status = keyExportImport( "RSA", CRYPT_ALGO_RSA, CRYPT_UNUSED, 
							  CRYPT_UNUSED );
	if( status )
		status = keyExportImport( "Elgamal", CRYPT_ALGO_ELGAMAL, 
								  CRYPT_UNUSED, CRYPT_UNUSED );
	putchar( '\n' );
	return( status );
	}

/* Test the code to sign data.  We're not as picky with error-checking here
   since most of the functions have just executed successfully.  We check two
   algorithm types since there are different code paths for DLP and non-DLP
   based PKC's */

int testSignData( void )
	{
	int status;

	status = signData( "RSA", CRYPT_ALGO_RSA, CRYPT_UNUSED, CRYPT_UNUSED );
	if( status == TRUE )
		status = signData( "DSA", CRYPT_ALGO_DSA, CRYPT_UNUSED, CRYPT_UNUSED );
	if( status == TRUE )
		status = signData( "Elgamal", CRYPT_ALGO_ELGAMAL, CRYPT_UNUSED, CRYPT_UNUSED );
	putchar( '\n' );
	return( status );
	}

/* Test the code to exchange a session key via Diffie-Hellman.  We're not as
   picky with error-checking here since most of the functions have just
   executed successfully */

int testKeyAgreement( void )
	{
	CRYPT_OBJECT_INFO cryptObjectInfo;
	CRYPT_CONTEXT cryptContext1, cryptContext2;
	CRYPT_CONTEXT sessionKeyContext1, sessionKeyContext2;
	BYTE *buffer;
	int length, status;

	puts( "Testing key agreement..." );

	/* Create the DH encryption contexts, one with a key loaded and the
	   other as a blank template for the import from the first one */
	if( !loadDHContexts( &cryptContext1, NULL, PKC_KEYSIZE ) )
		return( FALSE );
	cryptCreateContext( &cryptContext2, CRYPT_ALGO_DH, CRYPT_MODE_PKC );

	/* Create the session key templates */
	cryptCreateContext( &sessionKeyContext1, selectCipher( CRYPT_ALGO_RC5 ),
						CRYPT_MODE_CBC );
	cryptCreateContext( &sessionKeyContext2, selectCipher( CRYPT_ALGO_RC5 ),
						CRYPT_MODE_CBC );

	/* Find out how big the exported key will be */
	status = cryptExportKey( NULL, &length, cryptContext1, sessionKeyContext1 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptExportKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "cryptExportKey() reports exported key object will be %d bytes "
			"long\n", length );
	if( ( buffer = malloc( length ) ) == NULL )
		return( FALSE );

	/* Perform phase 1 of the exchange */
	status = cryptExportKey( buffer, &length, cryptContext1, sessionKeyContext1 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptExportKey() #1 failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}
	status = cryptImportKey( buffer, cryptContext2, sessionKeyContext2 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportKey() #1 failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}

	/* Query the encrypted key object */
	status = cryptQueryObject( buffer, &cryptObjectInfo );
	if( cryptStatusError( status ) )
		{
		printf( "cryptQueryObject() failed with error code %d, line %d\n",
				status );
		free( buffer );
		return( FALSE );
		}
	printf( "cryptQueryObject() reports object type %d, algorithm %d, mode "
			"%d.\n", cryptObjectInfo.objectType, cryptObjectInfo.cryptAlgo,
			cryptObjectInfo.cryptMode );
	memset( &cryptObjectInfo, 0, sizeof( CRYPT_OBJECT_INFO ) );
	debugDump( "keyagree", buffer, length );

	/* Perform phase 2 of the exchange */
	status = cryptExportKey( buffer, &length, cryptContext2, sessionKeyContext2 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptExportKey() #2 failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}
	status = cryptImportKey( buffer, cryptContext1, sessionKeyContext1 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportKey() #2 failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}

	/* Make sure the two keys match */
	if( !compareSessionKeys( sessionKeyContext1, sessionKeyContext2 ) )
		return( FALSE );

	/* Clean up */
	destroyContexts( CRYPT_UNUSED, sessionKeyContext1, sessionKeyContext2 );
	destroyContexts( CRYPT_UNUSED, cryptContext1, cryptContext2 );
	printf( "Exchange of session key via %d-bit Diffie-Hellman succeeded.\n\n",
			PKC_KEYSIZE );
	free( buffer );
	return( TRUE );
	}

/* Test normal and asynchronous public-key generation */

static int keygen( const CRYPT_ALGO cryptAlgo, const char *algoName )
	{
	CRYPT_CONTEXT cryptContext;
	BYTE buffer[ BUFFER_SIZE ];
	int length, status;

	printf( "Testing %s key generation...\n", algoName );

	/* Create an encryption context and generate a (short) key into it.
	   Generating a minimal-length 512 bit key is faster than the default
	   1-2K bit keys */
	cryptCreateContext( &cryptContext, cryptAlgo, CRYPT_MODE_PKC );
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL, 
							 "Private key", 11 );
	status = cryptGenerateKeyEx( cryptContext, 64 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGenerateKey() failed with error code %d, line %d\n",
				status );
		return( FALSE );
		}

	/* Perform a test operation to check the new key */
	if( cryptAlgo == CRYPT_ALGO_RSA || cryptAlgo == CRYPT_ALGO_DSA )
		{
		CRYPT_CONTEXT hashContext;
		BYTE hashBuffer[] = "abcdefghijklmnopqrstuvwxyz";

		/* Create an SHA hash context and hash the test buffer */
		cryptCreateContext( &hashContext, CRYPT_ALGO_SHA, CRYPT_MODE_NONE );
		cryptEncrypt( hashContext, hashBuffer, 26 );
		cryptEncrypt( hashContext, hashBuffer, 0 );

		/* Sign the hashed data and check the signature */
		status = cryptCreateSignature( buffer, &length, cryptContext, hashContext );
		if( cryptStatusOK( status ) )
			status = cryptCheckSignature( buffer, cryptContext, hashContext );

		/* Clean up */
		cryptDestroyContext( hashContext );
		cryptDestroyContext( cryptContext );
		if( cryptStatusError( status ) )
			{
			printf( "Sign/signature check with generated key failed with "
					"error code %d, line %d\n", status, __LINE__ );
			return( FALSE );
			}
		}
	else
	if( cryptAlgo == CRYPT_ALGO_ELGAMAL )
		{
		CRYPT_CONTEXT sessionKeyContext1, sessionKeyContext2;

		/* Test the key exchange */
		cryptCreateContext( &sessionKeyContext1, CRYPT_ALGO_DES, CRYPT_MODE_CBC );
		cryptCreateContext( &sessionKeyContext2, CRYPT_ALGO_DES, CRYPT_MODE_CBC );
		cryptGenerateKey( sessionKeyContext1 );
		status = cryptExportKey( buffer, &length, cryptContext,
								  sessionKeyContext1 );
		if( cryptStatusOK( status ) )
			status = cryptImportKey( buffer, cryptContext,
									 sessionKeyContext2 );
		cryptDestroyContext( cryptContext );
		if( cryptStatusError( status ) )
			{
			destroyContexts( CRYPT_UNUSED, sessionKeyContext1, 
							 sessionKeyContext2 );
			printf( "Key exchange with generated key failed with error code "
					"%d, line %d\n", status, __LINE__ );
			return( FALSE );
			}

		/* Make sure the two keys match */
		if( !compareSessionKeys( sessionKeyContext1, sessionKeyContext2 ) )
			return( FALSE );

		/* Clean up */
		destroyContexts( CRYPT_UNUSED, sessionKeyContext1, 
						 sessionKeyContext2 );
		}
	else
	if( cryptAlgo == CRYPT_ALGO_DH )
		{
		CRYPT_CONTEXT dhContext;
		CRYPT_CONTEXT sessionKeyContext1, sessionKeyContext2;

KLUDGE_WARN( "DH test because of absence of DH key exchange mechanism" );
cryptDestroyContext( cryptContext );
return( TRUE );

		/* Test the key exchange */
		cryptCreateContext( &sessionKeyContext1, CRYPT_ALGO_DES, CRYPT_MODE_CBC );
		cryptCreateContext( &sessionKeyContext2, CRYPT_ALGO_DES, CRYPT_MODE_CBC );
		cryptCreateContext( &dhContext, CRYPT_ALGO_DH, CRYPT_MODE_PKC );
		status = cryptExportKey( buffer, &length, cryptContext,
								  sessionKeyContext1 );
		if( cryptStatusOK( status ) )
			status = cryptImportKey( buffer, dhContext,
									 sessionKeyContext2 );
		if( cryptStatusOK( status ) )
			status = cryptExportKey( buffer, &length, dhContext,
									 sessionKeyContext2 );
		if( cryptStatusOK( status ) )
			status = cryptImportKey( buffer, cryptContext,
									 sessionKeyContext1 );
		cryptDestroyContext( cryptContext );
		cryptDestroyContext( dhContext );
		if( cryptStatusError( status ) )
			{
			destroyContexts( CRYPT_UNUSED, sessionKeyContext1, 
							 sessionKeyContext2 );
			printf( "Key exchange with generated key failed with error code "
					"%d, line %d\n", status, __LINE__ );
			return( FALSE );
			}

		/* Make sure the two keys match */
		if( !compareSessionKeys( sessionKeyContext1, sessionKeyContext2 ) )
			return( FALSE );

		/* Clean up */
		destroyContexts( CRYPT_UNUSED, sessionKeyContext1, 
						 sessionKeyContext2 );
		}
	else
		{
		printf( "Unexpected encryption algorithm %d found.\n", cryptAlgo );
		return( FALSE );
		}

	printf( "%s key generation succeeded.\n", algoName );
	return( TRUE );
	}


int testKeygen( void )
	{
	if( !keygen( CRYPT_ALGO_RSA, "RSA" ) )
		return( FALSE );
	if( !keygen( CRYPT_ALGO_DSA, "DSA" ) )
		return( FALSE );
	if( !keygen( CRYPT_ALGO_ELGAMAL, "Elgamal" ) )
		return( FALSE );
	if( !keygen( CRYPT_ALGO_DH, "DH" ) )
		return( FALSE );
	putchar( '\n' );
	return( TRUE );
	}

int testKeygenAsync( void )
	{
	/* Async keygen requires threading support which is currently only
	   handled under Win32 or OS/2 (actually it's present under many versions
	   of Unix as well but it's a bit tricky to determine automatically
	   without the cryptlib-internal configuration tricks which ones support
	   it */
#if !defined( WIN32 ) && !defined( _WIN32 ) && \
	( !( defined( __IBMC__ ) || defined( __IBMCPP__ ) ) || \
	  defined( __VMCMS__ ) || defined( __OS400__ ) )
	return( TRUE );
#else
	CRYPT_CONTEXT cryptContext;
	int status;

	puts( "Testing asynchronous key generation..." );

	/* Create an encryption context and generate a longish (2K bit) key
	   into it (this ensures that we can see the async operation in
	   action, anything smaller and it's done almost immediately) */
	cryptCreateContext( &cryptContext, CRYPT_ALGO_RSA, CRYPT_MODE_PKC );
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL, 
							 "Private key", 11 );
	status = cryptGenerateKeyAsyncEx( cryptContext, 256 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGenerateKeyAsync() failed with error code %d, line "
				"%d\n", status );
		return( FALSE );
		}

	/* Hang around a bit to allow things to start.  This value is a bit of a
	   difficult quantity to get right since VC++ can spend longer than the
	   startup time thrashing the drive doing nothing so it has to be high,
	   but on faster PC's even a 2K bit key can be generated in a few
	   seconds, so it can't be too high or the keygen will have finished.
	   The following value is safe for a 400MHz PII, presumably the next step
	   will be to move to 3K bit keys (3072 bits, 384 in the above keygen
	   call) but this may cause problems with some external implementations
	   which cap the keysize at 2K bits */
	printf( "Delaying 2s to allow keygen to start..." );
	Sleep( 2000 );
	puts( "done." );

	/* Check that the async keygen is still in progress */
	status = cryptAsyncQuery( cryptContext );
	if( status == CRYPT_ERROR_BUSY )
		puts( "Async keygen in progress." );
	else
		{
		/* If the machine's really fast, the keygen could have completed
		   already */
		if( status == CRYPT_OK )
			{
			printf( "The async keygen has completed before the rest of the "
					"test code could run.\nTo fix this, either decrease "
					"the startup delay on line %d\nof " __FILE__ " or "
					"increase the size of the key being generated to slow\n"
					"down the generation process.\n\n", __LINE__ - 15 );
			cryptDestroyContext( cryptContext );

			return( TRUE );
			}

		printf( "Async keygen failed with error code %d, line %d\n", status,
				__LINE__ );
		return( FALSE );
		}

	/* Cancel the async keygen */
	status = cryptAsyncCancel( cryptContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAsyncCancel() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "Cancelling async operation..." );
	while( cryptAsyncQuery( cryptContext ) == CRYPT_ERROR_BUSY )
		Sleep( 1000 );	/* Wait for the cancel to take effect */
	puts( "done." );

	/* Clean up */
	cryptDestroyContext( cryptContext );
	puts( "Asynchronous key generation succeeded.\n" );
	return( TRUE );
#endif /* Win32 */
	}

#endif /* TEST_MIDLEVEL */

/****************************************************************************
*																			*
*							Crypto Device Routines Test						*
*																			*
****************************************************************************/

#ifdef TEST_DEVICE

/* Device information tables for PKCS #11 device types.  This lists all the 
   devices we know about and can check for.  If you have a PKCS #11 device
   which isn't listed below, you need to add an entry with its name and a 
   password and key object label usable for testing to the table, and also 
   add the name of the driver as a CRYPT_OPTION_DEVICE_PKCS11_DVRxx entry so 
   cryptlib can load the appropriate driver for it.  To add this, use the
   updateConfig() function in testlib.c, see the code comments there for more
   details.

   The SEIS EID cards name their private key objects slightly differently 
   from the name used in the software-only eID driver, if you're using a 
   card-based version you need to switch the commented lines below to the 
   alternate name.
   
   The iD2 driver implements multiple virtual slots, one for each key type,
   so the entry is given in the extended driver::slot name format to tell 
   cryptlib which slot to use */

typedef struct {
	const char *name;
	const char *password;
	const char *keyLabel;
	} DEVICE_INFO;

static const DEVICE_INFO pkcs11DeviceInfo[] = {
	{ "ActivCard Cryptoki Library", "test", "Test user key" },
	{ "CryptoFlex", "ABCD1234", "012345678901234567890123456789ME" },
	{ "Cryptoki for eID", "1234", "Private key" },	/* PKCS #12 token */
	{ "Cryptoki for eID", "1234", "eID private nonrepudiation key" }, /* Smart card key */
	{ "Cryptoki for eID", "1234", "eID private key encipherment key" }, /* Smart card key */
	{ "Datakey Cryptoki DLL - NETSCAPE", "test", "Test user key" },
	{ "Eracom Cryptoki", "test", "Test user key" },
	{ "ERACOM Software Only", "0000", "Test user key" },
	{ "GemSAFE", "test", "Test user key" },
	{ "iButton", "test", "Test user key" },
	{ "iD2 Cryptographic Library::iD2 Smart Card (PIN1)", "1234", "Digital Signature" },
	{ "iD2 Cryptographic Library::iD2 Smart Card (PIN2)", "5678", "Non Repudiation" },
	{ "Rainbow iKey", "test", "Test user key" },
	{ "SignLite security module", "test", "Test user key" },
	{ "Spyrus Rosetta", "test", "Test user key" },
	{ "Spyrus Lynks", "test", "Test user key" },
	{ "TrustCenter PKCS#11 Library", "12345678", "Test user key" },
	{ NULL, NULL, NULL }
	};

/* Uncomment the following to test cryptlib's CAW functionality.  Note that 
   this will zeroise the card being tested as a part of the process, all data
   contained in it will be destroyed.  In addition to uncommenting the 
   following, you also need to set the zeroise and default SSO PIN's below */

/* #define TEST_CAW_FUNCTIONALITY */

/* Device information for Fortezza cards */

#define FORTEZZA_ZEROISE_PIN		"XXXXXXXXXXXX"
#define FORTEZZA_SSO_DEFAULT_PIN	"XXXXXX"
#define FORTEZZA_SSO_PIN			"0000"
#define FORTEZZA_USER_PIN			"0000"

static const DEVICE_INFO fortezzaDeviceInfo = \
	{ "", FORTEZZA_USER_PIN, "Test user key" };

/* Data used to create certs in the device */

static const CERT_DATA paaCertData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Honest Dave's PAA" },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, "Certification Policy Division" }, 
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave the PAA" },

	/* Self-signed X.509v3 CA certificate */
	{ CRYPT_CERTINFO_SELFSIGNED, IS_NUMERIC, TRUE },
	{ CRYPT_CERTINFO_CA, IS_NUMERIC, TRUE },
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC,
	  CRYPT_KEYUSAGE_KEYCERTSIGN },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

static const CERT_DATA cACertData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Dave's Wetaburgers and CA" },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, "Certification Division" }, 
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave Himself" },

	/* Self-signed X.509v3 CA certificate */
	{ CRYPT_CERTINFO_SELFSIGNED, IS_NUMERIC, TRUE },
	{ CRYPT_CERTINFO_CA, IS_NUMERIC, TRUE },
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC,
	  CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

static const CERT_DATA userCertData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Dave's Wetaburgers" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave's key" },

	/* X.509v3 general-purpose certificate */
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC, 
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE | CRYPT_KEYUSAGE_KEYENCIPHERMENT },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

static const CERT_DATA userSigOnlyCertData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Dave's Wetaburgers" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave's signing key" },

	/* X.509v3 signature-only certificate */
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC, CRYPT_KEYUSAGE_DIGITALSIGNATURE },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

static const CERT_DATA userKeyAgreeCertData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Dave's Wetaburgers" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave's key agreement key" },

	/* X.509v3 key agreement certificate */
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC, CRYPT_KEYUSAGE_KEYAGREEMENT },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

/* Delete leftover keys created during testing */

static void deleteTestKey( const CRYPT_DEVICE cryptDevice, 
						   const char *keyName, const char *keyDescription )
	{
	if( cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME, keyName ) == CRYPT_OK )
		printf( "(Deleted a %s key object, presumably a leftover from a "
				"previous run).\n", keyDescription );
	}

/* Test the general capabilities of a device */

static BOOLEAN testDeviceCapabilities( const CRYPT_DEVICE cryptDevice, 
									   const char *deviceName, 
									   const BOOLEAN isWriteProtected )
	{
	CRYPT_ALGO cryptAlgo;
	BOOLEAN testResult = FALSE;

	printf( "Checking %s capabilities...\n", deviceName );
	for( cryptAlgo = CRYPT_ALGO_FIRST_CONVENTIONAL;
		 cryptAlgo <= CRYPT_ALGO_LAST; cryptAlgo++ )
		if( cryptStatusOK( cryptDeviceQueryCapability( cryptDevice,
													   cryptAlgo, NULL ) ) )
			{
			CRYPT_MODE cryptMode;

			for( cryptMode = CRYPT_MODE_FIRST_CONVENTIONAL;
				 cryptMode <= CRYPT_MODE_LAST; cryptMode++ )
				if( cryptStatusOK( cryptDeviceQueryCapability( cryptDevice,
															   cryptAlgo, NULL ) ) )
				{
				testResult = testLowlevel( cryptDevice, cryptAlgo, 
										   cryptMode, isWriteProtected );
				if( !testResult )
					return( FALSE );
				}
			}
	if( isWriteProtected )
		puts( "No tests were performed since the device is write-protected." );
	else
		puts( "Device capabilities test succeeded." );
	
	return( TRUE );
	}

/* Create a key and certificate in a device */

static BOOLEAN createKey( const CRYPT_DEVICE cryptDevice,
						  const CRYPT_ALGO cryptAlgo,
						  const char *description, const char *dumpName,
						  const CRYPT_CONTEXT signingKey )
	{
	CRYPT_CONTEXT cryptContext;
	CRYPT_CERTIFICATE cryptCert;
	BYTE certBuffer[ BUFFER_SIZE ], labelBuffer[ CRYPT_MAX_TEXTSIZE ];
	const BOOLEAN isCA = ( signingKey == CRYPT_UNUSED ) ? TRUE : FALSE;
	const CERT_DATA *certData = ( isCA ) ? cACertData : \
			( cryptAlgo == CRYPT_ALGO_RSA ) ? userCertData : \
			( cryptAlgo == CRYPT_ALGO_DSA ) ? userSigOnlyCertData : \
			userKeyAgreeCertData;
	int certificateLength, status;

	sprintf( labelBuffer, "Test %s key", description );

	/* Generate a key in the device */
	printf( "Generating a %s key in the device...", description );
	status = cryptDeviceCreateContext( cryptDevice, &cryptContext, 
									   cryptAlgo, CRYPT_MODE_PKC );
	if( cryptStatusError( status ) )
		{
		printf( "\ncryptDeviceCreateContext() failed with error code %d, "
				"line %d\n", status, __LINE__ );
		return( FALSE );
		}
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL, labelBuffer, 
							 strlen( labelBuffer ) );
	status = cryptGenerateKey( cryptContext );
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( cryptContext );
		printf( "\ncryptGenerateKey() failed with error code %d, line %d\n", 
				status, __LINE__ );
		return( FALSE );
		}
	puts( " succeeded." );

	/* Create a certificate for the key */
	printf( "Generating a certificate for the key..." );
	cryptCreateCert( &cryptCert, ( isCA ) ? \
					 CRYPT_CERTTYPE_CERTIFICATE : CRYPT_CERTTYPE_CERTCHAIN );
	status = cryptAddCertComponentNumeric( cryptCert, 
						CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptCert, certData ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCert, isCA ? cryptContext : signingKey );
	cryptDestroyContext( cryptContext );
	if( cryptStatusError( status ) )
		{
		cryptDestroyCert( cryptCert );
		printf( "\nCreation of certificate failed with error code %d, "
				"line %d\n", status, __LINE__ );
		return( FALSE );
		}
	puts( " succeeded." );

	/* Dump the resulting cert for debugging */
	if( dumpName != NULL )
		{
		status = cryptExportCert( certBuffer, &certificateLength, isCA ? \
					CRYPT_CERTFORMAT_CERTIFICATE : CRYPT_CERTFORMAT_CERTCHAIN,
					cryptCert );
		if( cryptStatusOK( status ) )
			debugDump( dumpName, certBuffer, certificateLength );
		}

	/* Update the key with the cert */
	printf( "Updating device with certificate..." );
	status = cryptAddPublicKey( cryptDevice, cryptCert );
	cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "\ncryptAddPublicKey() failed with error code %d, line %d\n", 
				status, __LINE__ );
		return( FALSE );
		}
	puts( " succeeded." );

	return( TRUE );
	}

/* Test the high-level functionality provided by a device */

static BOOLEAN testDeviceHighlevel( const CRYPT_DEVICE cryptDevice, 
									const CRYPT_DEVICE_TYPE deviceType,
									const char *keyLabel,
									const char *password,
									const BOOLEAN isWriteProtected )
	{
	CRYPT_CONTEXT pubKeyContext, privKeyContext, sigKeyContext;
	int status;

	if( !isWriteProtected )
		{
		const CRYPT_ALGO cryptAlgo = ( deviceType == CRYPT_DEVICE_PKCS11 ) ? \
									 CRYPT_ALGO_RSA : CRYPT_ALGO_DSA;

		/* Create a CA key in the device */
		if( !createKey( cryptDevice, cryptAlgo, "CA", 
						( deviceType == CRYPT_DEVICE_PKCS11 ) ? \
						"dp_cacert" : "df_cacert", CRYPT_UNUSED ) )
			return( FALSE );

		/* Read back the CA key for use in generating end entity certs */
		status = cryptGetPrivateKey( cryptDevice, &sigKeyContext, 
									 CRYPT_KEYID_NAME, "Test CA key", 
									 NULL );
		if( cryptStatusError( status ) )
			{
			printf( "\nRead of CA key failed with error code %d, line %d\n", 
					status, __LINE__ );
			return( FALSE );
			}

		/* Create end-entity certificate(s) for keys using the previously-
		   generated CA key.  If it's a Fortezza card we have to generate two
		   sets of keys/certs, one for signing and one for encryption */
		status = createKey( cryptDevice, cryptAlgo, "user", 
							( deviceType == CRYPT_DEVICE_PKCS11 ) ? \
							"dp_usrcert" : "df_usrcert", sigKeyContext );
		if( status && deviceType == CRYPT_DEVICE_FORTEZZA )
			status = createKey( cryptDevice, CRYPT_ALGO_KEA, "KEA", 
								"df_keacert", sigKeyContext );
		cryptDestroyContext( sigKeyContext );
		if( !status )
			return( FALSE );
		}

	/* See whether there are any existing keys or certs - some tokens have 
	   these built in and don't allow anything new to be created, after this 
	   point the handling is somewhat special-case but we can at least report 
	   their presence.  Although generally we can reuse a private key context
	   for both public and private operations, some devices or drivers (and 
	   by extension the cryptlib kernel) don't allow public-key ops with 
	   private keys so we have to eplicitly handle public and private keys.
	   This gets somewhat messy because some devices don't have public keys 
	   but allow public-key ops with their private keys, while others 
	   separate public and private keys and don't allow the private key to do
	   public-key ops */
	status = cryptGetPublicKey( cryptDevice, &pubKeyContext, 
								CRYPT_KEYID_NAME, keyLabel );
	if( cryptStatusOK( status ) )
		{
		puts( "Found a public key in the device, details follow..." );
		printCertChainInfo( pubKeyContext );
		}
	else
		pubKeyContext = CRYPT_UNUSED;
	status = cryptGetPrivateKey( cryptDevice, &privKeyContext, 
								 CRYPT_KEYID_NAME, keyLabel, NULL );
	if( cryptStatusOK( status ) )
		{
		puts( "Found a private key in the device, details follow..." );
		printCertChainInfo( privKeyContext );
		if( pubKeyContext == CRYPT_UNUSED )
			{
			/* No explicit public key found, try using the private key for
			   both key types */
			puts( "No public key found, attempting to continue using the "
				  "private key as both a\npublic and a private key." );
			pubKeyContext = privKeyContext;
			}
		}
	else
		privKeyContext = CRYPT_UNUSED;
	sigKeyContext = privKeyContext;
	if( deviceType == CRYPT_DEVICE_FORTEZZA )
		{
		cryptDestroyContext( pubKeyContext );	/* pubK is sig.only */
		status = cryptGetPrivateKey( cryptDevice, &privKeyContext, 
									 CRYPT_KEYID_NAME, "Test KEA key", NULL );
		if( cryptStatusOK( status ) )
			{
			puts( "Found a key agreement key in the device, details follow..." );
			printCertChainInfo( privKeyContext );
			pubKeyContext = privKeyContext;		/* Fortezza allows both uses */
			}
		else
			{
			pubKeyContext = CRYPT_UNUSED;
			privKeyContext = CRYPT_UNUSED;
			}
		}

	/* If we got something, try some simple operations with it */
	if( pubKeyContext != CRYPT_UNUSED )
		testCMSEnvelopePKCCryptEx( pubKeyContext, cryptDevice, password );
	if( sigKeyContext != CRYPT_UNUSED )
		testCMSEnvelopeSignExt( sigKeyContext );

	/* Clean up */
	if( privKeyContext != CRYPT_UNUSED )
		{
		cryptDestroyContext( privKeyContext );
		if( privKeyContext != sigKeyContext )
			cryptDestroyContext( sigKeyContext );
		}
	if( pubKeyContext != CRYPT_UNUSED && pubKeyContext != privKeyContext )
		cryptDestroyContext( pubKeyContext );
	return( TRUE );
	}

/* Test cryptlib's CAW functionality with a Fortezza card.  Note that these
   operations have to be done in a more or less continuous sequence (ie
   without an intervening device open call) because it's not possible to
   escape from some of the states if the card is closed and reopened in
   between */

static int testCAW( void )
	{
	CRYPT_DEVICE cryptDevice;
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT signContext;
	int status;

	puts( "Testing Certificate Authority Workstation (CAW) functionality..." );
	status = cryptDeviceOpen( &cryptDevice, CRYPT_DEVICE_FORTEZZA, NULL );
	if( status == CRYPT_BADPARM2 )
		{
		puts( "Support for Fortezza cards isn't enabled in this build of "
			  "cryptlib." );
		return( CRYPT_ERROR_NOTAVAIL );	/* Device access not available */
		}
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_PARAM3 )
			puts( "Fortezza card not detected, skipping test." );
		else
			printf( "cryptDeviceOpen() failed with error code %d, line %d\n",
					status, __LINE__ );
		return( FALSE );
		}

	/* Zeroise the card prior to initialising it */
	printf( "Zeroising device... " );
	status = cryptDeviceControl( cryptDevice, 
					CRYPT_DEVICECONTROL_ZEROISE, FORTEZZA_ZEROISE_PIN, 
					strlen( FORTEZZA_ZEROISE_PIN ) );
	if( cryptStatusError( status ) )
		{
		printf( "\ncryptDeviceControl() failed with error code %d, line %d\n", 
				status, __LINE__ );
		return( FALSE );
		}
	puts( "succeeded." );

	/* Initialise the card */
	printf( "Initialising device... " );
	status = cryptDeviceControl( cryptDevice, 
					CRYPT_DEVINFO_INITIALISE, FORTEZZA_SSO_DEFAULT_PIN, 
					strlen( FORTEZZA_SSO_DEFAULT_PIN ) );
	if( cryptStatusError( status ) )
		{
		printf( "\ncryptDeviceControl() failed with error code %d, line %d\n", 
				status, __LINE__ );
		return( FALSE );
		}
	puts( "succeeded." );

	/* Set the SSO PIN */
	printf( "Setting SSO PIN... " );
	status = cryptDeviceControlEx( cryptDevice, 
					CRYPT_DEVINFO_SET_AUTHENT_SUPERVISOR,
					FORTEZZA_SSO_DEFAULT_PIN, strlen( FORTEZZA_SSO_DEFAULT_PIN ),
					FORTEZZA_SSO_PIN, strlen( FORTEZZA_SSO_PIN ) );
	if( cryptStatusError( status ) )
		{
		printf( "\ncryptDeviceControl() failed with error code %d, line %d\n", 
				status, __LINE__ );
		return( FALSE );
		}
	puts( "set to " FORTEZZA_SSO_PIN "." );

	/* Create a CA root key and install its cert.  We can't use the card to 
	   do this because cert slot 0 is a data-only slot (that is, it can't
	   correspond to a key held on the card), so we create a dummy external
	   cert and use that */
	printf( "Loading PAA certificate... " );
	if( !loadDSAContexts( CRYPT_UNUSED, &signContext, NULL ) )
		return( FALSE );
	cryptCreateCert( &cryptCert, CRYPT_CERTTYPE_CERTIFICATE );
	status = cryptAddCertComponentNumeric( cryptCert, 
						CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, signContext );
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptCert, paaCertData ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCert, signContext );
	cryptDestroyContext( signContext );
	if( cryptStatusError( status ) )
		{
		cryptDestroyCert( cryptCert );
		printf( "\nCreation of certificate failed with error code %d, "
				"line %d\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPublicKey( cryptDevice, cryptCert );
	cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "\ncryptAddPublicKey() failed with error code %d, line %d\n", 
				status, __LINE__ );
		return( FALSE );
		}
	puts( "succeeded." );

	/* Set the user PIN */
	printf( "Setting user PIN... " );
	status = cryptDeviceControlEx( cryptDevice, 
					CRYPT_DEVINFO_SET_AUTHENT_USER,
					FORTEZZA_USER_PIN, strlen( FORTEZZA_USER_PIN ),
					FORTEZZA_USER_PIN, strlen( FORTEZZA_USER_PIN ) );
	if( cryptStatusError( status ) )
		{
		printf( "\ncryptDeviceControl() failed with error code %d, line %d\n", 
				status, __LINE__ );
		return( FALSE );
		}
	puts( "set to " FORTEZZA_USER_PIN "." );

	/* Clean up */
	cryptDeviceClose( cryptDevice );
	return( TRUE );
	}

/* General device test routine */

static int testCryptoDevice( const CRYPT_DEVICE_TYPE deviceType,
							 const char *deviceName,
							 const DEVICE_INFO *deviceInfo )
	{
	CRYPT_DEVICE cryptDevice;
	BOOLEAN isWriteProtected = FALSE;
	BOOLEAN testResult = FALSE, partialSuccess = FALSE;
	int status;

	/* Open a connection to the device */
	if( deviceType == CRYPT_DEVICE_PKCS11 )
		{
		printf( "\nTesting %s %s...\n", deviceInfo->name, deviceName );
		status = cryptDeviceOpen( &cryptDevice, deviceType, deviceInfo->name );
		}
	else
		{
		printf( "\nTesting %s...\n", deviceName );
		status = cryptDeviceOpen( &cryptDevice, deviceType, deviceName );
		}
	if( status == CRYPT_BADPARM2 )
		{
		puts( "Support for this device type isn't enabled in this build of "
			  "cryptlib." );
		return( CRYPT_ERROR_NOTAVAIL );	/* Device access not available */
		}
	if( cryptStatusError( status ) )
		{
		if( status == CRYPT_ERROR_PARAM3 )
			puts( "Crypto device not detected, skipping test." );
		else
			printf( "cryptDeviceOpen() failed with error code %d, line %d\n",
					status, __LINE__ );
		return( FALSE );
		}

	/* If it's one of the smarter classes of device, authenticate ourselves to 
	   the device, which is usually required in order to allow it to be used
	   fully.  Since devices don't require a login or handle their login via 
	   non-PKCS #11 mechanisms (eg card readers with keypads, biometrics) and 
	   will return CRYPT_ERROR_INITED if we try to log in to them so we 
	   report this case to the user */
	if( deviceType == CRYPT_DEVICE_PKCS11 || deviceType == CRYPT_DEVICE_FORTEZZA )
		{
		printf( "Logging on to the device..." );
		status = cryptDeviceControl( cryptDevice, CRYPT_DEVICECONTROL_AUTH_USER,
									 deviceInfo->password, 
									 strlen( deviceInfo->password ) );
		if( status == CRYPT_NOTINITED && deviceType == CRYPT_DEVICE_PKCS11 )
			{
			/* It's an uninitialised PKCS #11 device, try initialising it.  
			   Testing CAW functionality is somewhat more complex than a 
			   straight init and is handled separately */
			puts( " device needs to be initialised." );
			printf( "Initialising device..." );
			status = cryptDeviceControl( cryptDevice, CRYPT_DEVICECONTROL_INITIALISE,
										 deviceInfo->password, 
										 strlen( deviceInfo->password ) );
			if( cryptStatusOK( status ) )
				{
				/* After the init we're logged on as SSO, to perform any 
				   useful testing we have to re-log on as a user since most
				   devices which actually enforce SSO vs user roles won't 
				   allow standard operations to be performed while the SSO 
				   role is in effect.  Since the initialisation sets the user 
				   PIN to the same value as the SSO PIN, we can just re-
				   authenticate ourselves using the same PIN (in the real 
				   world and if SSO vs user roles are being enforced, the SSO 
				   would change the user PIN before handing the device over 
				   to the user) */
				printf( " succeeded.\nLogging on to the device..." );
				status = cryptDeviceControl( cryptDevice, 
							CRYPT_DEVICECONTROL_AUTH_USER,
							deviceInfo->password, strlen( deviceInfo->password ) );
				}
			}
		if( cryptStatusError( status ) )
			{
			if( status == CRYPT_INITED )
				puts( " no login required to use this device." );
			else
				{
				printf( "\ncryptDeviceControl() failed with error code %d, "
						"line %d\n", status, __LINE__ );
				return( FALSE );
				}
			}
		else
			puts( " succeeded." );
		}

	/* Write-protected devices won't allow contexts to be created in them, 
	   before we try the general device capabilities test we make sure we
	   can actually perform the operation */
	if( deviceType == CRYPT_DEVICE_PKCS11 )
		{
		CRYPT_CONTEXT cryptContext;

		/* Try and create a DES object.  The following check for read-only
		   devices always works because the device object ACL is applied at
		   a much higher level than any device capability checking, the
		   device will never even see the create object message if it's
		   write-protected so all we have to do is make sure that whatever 
		   we create is ephemeral */
		status = cryptDeviceCreateContext( cryptDevice, &cryptContext,
										   CRYPT_ALGO_DES, CRYPT_MODE_ECB );
		if( cryptStatusOK( status ) )
			cryptDestroyContext( cryptContext );
		if( status == CRYPT_ERROR_PERMISSION )
			isWriteProtected = TRUE;
		}

	/* To force the code not to try to create keys and certs in a writeable
	   device, uncomment the following line of code.  This requires that keys/
	   certs of the required type are already present in the device */
	KLUDGE_WARN( "write-protect status" );
	isWriteProtected = TRUE;				/**/

	/* There may be test keys lying around from an earlier run, in which case
	   we try to delete them to make sure they won't interfere with the 
	   current one */
	if( !isWriteProtected )
		{
		deleteTestKey( cryptDevice, "Test CA key", "CA" );
		deleteTestKey( cryptDevice, deviceInfo->keyLabel, "user" );
		if( deviceType == CRYPT_DEVICE_PKCS11 )
			{
			deleteTestKey( cryptDevice, RSA_PUBKEY_LABEL, "RSA public" );
			deleteTestKey( cryptDevice, RSA_PRIVKEY_LABEL, "RSA private" );
			deleteTestKey( cryptDevice, DSA_PUBKEY_LABEL, "DSA public" );
			deleteTestKey( cryptDevice, DSA_PRIVKEY_LABEL, "DSA private" );
			}
		if( deviceType == CRYPT_DEVICE_FORTEZZA )
			deleteTestKey( cryptDevice, "Test KEA key", "KEA" );
		}

	/* Report what the device can do.  This is intended mostly for simple 
	   crypto accelerators and may fail with for devices which work only
	   with the higher-level functions centered around certificates, 
	   signatures,and key wrapping, so we skip the tests for devices which 
	   allow only high-level access */
	if( deviceType != CRYPT_DEVICE_FORTEZZA )
		testResult = testDeviceCapabilities( cryptDevice, deviceName, 
											 isWriteProtected );

	/* If it's a smart device, try various device-specific operations */
	if( deviceType == CRYPT_DEVICE_FORTEZZA || \
		deviceType == CRYPT_DEVICE_PKCS11 )
		partialSuccess = testDeviceHighlevel( cryptDevice, deviceType,
							deviceInfo->keyLabel, deviceInfo->password, 
							isWriteProtected );

	/* Clean up */
	status = cryptDeviceClose( cryptDevice );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDeviceClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	if( !testResult )
		{
		if( !partialSuccess )
			return( FALSE );
		printf( "Some %s tests succeeded.\n\n", deviceName );
		}
	else
		printf( "%s tests succeeded.\n\n", deviceName );
	return( TRUE );
	}

int testDevices( void )
	{
	int i, status;

#ifdef TEST_DEVICE_FORTEZZA
  #ifdef TEST_CAW_FUNCTIONALITY
	/* If testing of CAW functionality is enabled, test the full card 
	   initialisation process */
	status = testCAW();
	if( cryptStatusError( status ) && status != CRYPT_ERROR_NOTAVAIL )
		return( status );
  #else
	puts( "Skipping CAW functionality test (uncomment the "
		  "TEST_CAW_FUNCTIONALITY #define\n  in " __FILE__ " to enable 
		  this)." );
  #endif /* TEST_CAW_FUNCTIONALITY */
	status = testCryptoDevice( CRYPT_DEVICE_FORTEZZA, "Fortezza card", 
							   &fortezzaDeviceInfo );
	if( cryptStatusError( status ) && status != CRYPT_ERROR_NOTAVAIL )
		return( status );
#endif /* TEST_DEVICE_FORTEZZA */
	for( i = 0; pkcs11DeviceInfo[ i ].name != NULL; i++ )
		{
		status = testCryptoDevice( CRYPT_DEVICE_PKCS11, "PKCS #11 crypto token", 
								   &pkcs11DeviceInfo[ i ] );
		if( cryptStatusError( status ) && status != CRYPT_ERROR_NOTAVAIL )
			return( status );
		}
	return( TRUE );
	}
#endif /* TEST_DEVICE */

/****************************************************************************
*																			*
*							High-level Routines Test						*
*																			*
****************************************************************************/

#ifdef TEST_HIGHLEVEL

/* Test the code to export/import a CMS key */

int testKeyExportImportCMS( void )
	{
	CRYPT_OBJECT_INFO cryptObjectInfo;
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	CRYPT_CONTEXT sessionKeyContext1, sessionKeyContext2;
	BYTE *buffer;
	int status, length;

	puts( "Testing CMS public-key export/import..." );

	/* Get a private key with a cert chain attached */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  USER_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
									 CRYPT_KEYID_NAME, USER_PRIVKEY_LABEL, 
									 USER_PRIVKEY_PASSWORD );
		cryptKeysetClose( cryptKeyset );
		}
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't read private key, status %d, line %d.\n", status,
				__LINE__ );
		return( FALSE );
		}

	/* Create triple-DES encryption contexts for the exported and imported
	   session keys */
	cryptCreateContext( &sessionKeyContext1, CRYPT_ALGO_3DES, CRYPT_MODE_CBC );
	cryptGenerateKey( sessionKeyContext1 );
	cryptCreateContext( &sessionKeyContext2, CRYPT_ALGO_3DES, CRYPT_MODE_CBC );

	/* Find out how big the exported key will be */
	status = cryptExportKeyEx( NULL, &length, CRYPT_FORMAT_SMIME,
							   cryptContext, sessionKeyContext1 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptExportKeyEx() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "cryptExportKeyEx() reports CMS exported key will be %d bytes "
			"long\n", length );
	if( ( buffer = malloc( length ) ) == NULL )
		return( FALSE );

	/* Export the key */
	status = cryptExportKeyEx( buffer, &length, CRYPT_FORMAT_SMIME,
							   cryptContext, sessionKeyContext1 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptExportKeyEx() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}

	/* Query the encrypted key object */
	status = cryptQueryObject( buffer, &cryptObjectInfo );
	if( cryptStatusError( status ) )
		{
		printf( "cryptQueryObject() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}
	printf( "cryptQueryObject() reports object type %d, algorithm %d, mode "
			"%d.\n", cryptObjectInfo.objectType, cryptObjectInfo.cryptAlgo,
			cryptObjectInfo.cryptMode );
	memset( &cryptObjectInfo, 0, sizeof( CRYPT_OBJECT_INFO ) );
	debugDump( "cms_ri", buffer, length );

	/* Import the encrypted key and load it into the session key context */
	status = cryptImportKeyEx( buffer, cryptContext, sessionKeyContext2 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportKeyEx() failed with error code %d, line %d\n",
				status, __LINE__ );
		free( buffer );
		return( FALSE );
		}

	/* Make sure the two keys match */
	if( !compareSessionKeys( sessionKeyContext1, sessionKeyContext2 ) )
		return( FALSE );

	/* Clean up */
	destroyContexts( CRYPT_UNUSED, sessionKeyContext1, sessionKeyContext2 );
	cryptDestroyContext( cryptContext );
	puts( "Export/import of CMS session key succeeded.\n" );
	free( buffer );
	return( TRUE );
	}

/* Test the code to create an CMS signature */

static const CERT_DATA cmsAttributeData[] = {
	/* Content type */
	{ CRYPT_CERTINFO_CMS_CONTENTTYPE, IS_NUMERIC, CRYPT_CONTENT_SPCINDIRECTDATACONTEXT },

	/* Odds and ends */
	{ CRYPT_CERTINFO_CMS_SPCOPUSINFO, IS_NUMERIC, CRYPT_UNUSED },
	{ CRYPT_CERTINFO_CMS_SPCSTMT_COMMERCIALCODESIGNING, IS_NUMERIC, CRYPT_UNUSED },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

static int signDataCMS( const char *description,
						const CRYPT_CERTIFICATE signingAttributes )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cmsAttributes = signingAttributes;
	CRYPT_CONTEXT signContext, hashContext;
	BYTE *buffer, hashBuffer[] = "abcdefghijklmnopqrstuvwxyz";
	int status, length;

	printf( "Testing %s...\n", description );

	/* Create an SHA hash context and hash the test buffer */
	cryptCreateContext( &hashContext, CRYPT_ALGO_SHA, CRYPT_MODE_NONE );
	cryptEncrypt( hashContext, hashBuffer, 26 );
	cryptEncrypt( hashContext, hashBuffer, 0 );

	/* Get a private key with a cert chain attached */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  USER_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetPrivateKey( cryptKeyset, &signContext,
									 CRYPT_KEYID_NAME, USER_PRIVKEY_LABEL, 
									 USER_PRIVKEY_PASSWORD );
		cryptKeysetClose( cryptKeyset );
		}
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't read private key, status %d, line %d.\n", status,
				__LINE__ );
		return( FALSE );
		}

	/* Find out how big the signature will be */
	status = cryptCreateSignatureEx( NULL, &length, CRYPT_FORMAT_SMIME,
									 signContext, hashContext, cmsAttributes );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateSignatureEx() failed with error code %d, line "
				"%d\n", status, __LINE__ );
		return( FALSE );
		}
	printf( "cryptCreateSignatureEx() reports CMS signature will be %d "
			"bytes long\n", length );
	if( ( buffer = malloc( length ) ) == NULL )
		return( FALSE );

	/* Sign the hashed data */
	status = cryptCreateSignatureEx( buffer, &length, CRYPT_FORMAT_SMIME,
									 signContext, hashContext, cmsAttributes );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateSignatureEx() failed with error code %d, line "
				"%d\n", status, __LINE__ );
		free( buffer );
		return( FALSE );
		}
	debugDump( ( signingAttributes == CRYPT_USE_DEFAULT ) ? \
			   "cms_sigd" : "cms_sig", buffer, length );

	/* Check the signature on the hash */
	status = cryptCheckSignatureEx( buffer, signContext, hashContext,
			( cmsAttributes == CRYPT_USE_DEFAULT ) ? NULL : &cmsAttributes );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCheckSignatureEx() failed with error code %d, line "
				"%d\n", status, __LINE__ );
		free( buffer );
		return( FALSE );
		}
	
	/* Display the signing attributes */
	if( cmsAttributes != CRYPT_USE_DEFAULT )
		printCertInfo( cmsAttributes );

	/* Clean up */
	cryptDestroyContext( hashContext );
	cryptDestroyContext( signContext );
	cryptDestroyCert( cmsAttributes );
	printf( "Generation and checking of %s succeeded.\n\n", description );
	free( buffer );
	return( TRUE );
	}

int testSignDataCMS( void )
	{
	CRYPT_CERTIFICATE cmsAttributes;
	int status;

	/* First test the basic CMS signature with default attributes (content
	   type, signing time, and message digest) */
	if( !signDataCMS( "CMS signature", CRYPT_USE_DEFAULT ) )
		return( FALSE );

	/* Create some CMS attributes and sign the data with the user-defined
	   attributes */
	status = cryptCreateCert( &cmsAttributes, CRYPT_CERTTYPE_CMS_ATTRIBUTES );
	if( cryptStatusError( status ) || \
		!addCertFields( cmsAttributes, cmsAttributeData ) )
		return( FALSE );
	status = signDataCMS( "complex CMS signature", cmsAttributes );
	cryptDestroyCert( cmsAttributes );

	return( status );
	}

#endif /* TEST_HIGHLEVEL */
