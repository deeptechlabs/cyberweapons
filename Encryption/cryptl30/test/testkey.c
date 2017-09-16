/****************************************************************************
*																			*
*						  cryptlib Keyset Test Routines						*
*						Copyright Peter Gutmann 1995-1999					*
*																			*
****************************************************************************/

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

/* External flag which indicates that the key read routines work OK.  This is
   set by earlier self-test code, if it isn't set some of the enveloping
   tests are disabled */

extern int keyReadOK;

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Print extended error info from a keyset */

static void printKeysetError( const CRYPT_KEYSET cryptKeyset,
							  const char *functionName, 
							  const int functionStatus )
	{
	char errorMessage[ 512 ];
	int errorCode, errorMessageLength, status;

	printf( "%s() failed with error code %d, line %d\n", functionName,
			functionStatus, __LINE__ );
	status = cryptGetErrorInfo( cryptKeyset, &errorCode, errorMessage,
								&errorMessageLength );
	if( cryptStatusError( status ) )
		printf( "cryptGetErrorInfo() failed with error code %d, line %d\n",
				status, __LINE__ );
	else
		{
		errorMessage[ errorMessageLength ] = '\0';
		printf( "Extended error code = %d, error message =\n%s", errorCode,
				errorMessage );
		}
	}

/****************************************************************************
*																			*
*							Keyset Access Routines Test						*
*																			*
****************************************************************************/

/* Get a public key from a PGP keyring */

int testGetPGPPublicKey( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	FILE *filePtr;
	int status;

	/* Check that the file actually exists so we can return an appropriate
	   error message */
	if( ( filePtr = fopen( PGP_PUBKEY_FILE, "rb" ) ) == NULL )
		return( CRYPT_ERROR_FAILED );
	fclose( filePtr );
	keyReadOK = FALSE;

	puts( "Testing PGP public key read..." );

	/* Try and open the keyset and try to read the required key */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  PGP_PUBKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Get the key */
	status = cryptGetPublicKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NAME,
								"test" );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetPublicKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	puts( "Read of public key from PGP keyring succeeded.\n" );
	return( TRUE );
	}

/* Get a private key from a PGP keyring */

int testGetPGPPrivateKey( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	FILE *filePtr;
	int status;

	/* Check that the file actually exists so we can return an appropriate
	   error message */
	if( ( filePtr = fopen( PGP_PRIVKEY_FILE, "rb" ) ) == NULL )
		return( CRYPT_ERROR_FAILED );
	fclose( filePtr );

	puts( "Testing PGP private key read..." );

	/* Try and open the keyset and try to read the required key */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  PGP_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Get the key.  First we try it without a password, if that fails we
	   retry it with the password - this tests a lot of the private-key get
	   functionality including things like key cacheing */
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NAME,
 								 "test10", NULL );
	if( status == CRYPT_ERROR_WRONGKEY )
		{
		/* We need a password for this private key, get it from the user and
		   get the key again */
		status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
									 CRYPT_KEYID_NAME, "test10", "test10" );
		}
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetPrivateKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Both key reads worked, remember this for later */
	keyReadOK = TRUE;

	puts( "Read of private key from PGP keyring succeeded.\n" );
	return( TRUE );
	}

/* Get a key from a PKCS #12 file.  Because of the security problems 
   associated with this format, the code only checks the data format but
   doesn't try to read or use the keys.  If anyone wants this, they'll
   have to add the code themselves.  Your security warranty is void if you 
   implement this */

int testGetBorkenKey( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	FILE *filePtr;
	int status;

	/* Check that the file actually exists so we can return an appropriate
	   error message */
	if( ( filePtr = fopen( PKCS12_FILE, "rb" ) ) == NULL )
		return( CRYPT_ERROR_FAILED );
	fclose( filePtr );

/*	puts( "Testing PKCS #12 key read..." ); */

	/* Try and open the keyset and try to read the required key */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE, PKCS12_FILE, 
							  CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Get the key  - this is currently hardwired to CRYPT_ERROR_FAILED after 
	   unwrapping the first dozen or so layers of PKCS #12 bloat */
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NAME,
 								 "test", NULL );
/*	if( cryptStatusError( status ) )
		{
		printf( "cryptGetPrivateKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext ); */

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

/*	puts( "Read of key from PKCS #12 file succeeded.\n" ); */
	return( TRUE );
	}

/* Read/write a private key from a file */

static int readFileKey( const BOOLEAN useRSA )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int status;

	printf( "Testing %s private key read from key file...\n", useRSA ? "RSA" : "DSA" );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Read the key from the file */
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
								 CRYPT_KEYID_NAME, 
								 useRSA ? RSA_PRIVKEY_LABEL : DSA_PRIVKEY_LABEL,
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetPrivateKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	cryptDestroyContext( cryptContext );

	printf( "Read of %s private key from key file succeeded.\n\n",
			useRSA ? "RSA" : "DSA" );
	return( TRUE );
	}

static int writeFileKey( const BOOLEAN useRSA )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT privateKeyContext;
	int status;

	printf( "Testing %s private key write to key file...\n", useRSA ? "RSA" : "DSA" );

	/* Create the private key context */
	if( useRSA )
		{
		if( !loadRSAContexts( CRYPT_UNUSED, NULL, &privateKeyContext ) )
			return( FALSE );
		}
	else
		if( !loadDSAContexts( CRYPT_UNUSED, &privateKeyContext, NULL ) )
			return( FALSE );

	/* Create/open the file keyset.  For the first call (with RSA) we create 
	   a new keyset, for subsequent calls we update the existing keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, 
							  useRSA ? CRYPT_KEYOPT_CREATE : CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Write the key to the file */
	status = cryptAddPrivateKey( cryptKeyset, privateKeyContext, 
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddPrivateKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyContext( privateKeyContext );
	printf( "Write of %s private key to key file succeeded.\n\n",
			useRSA ? "RSA" : "DSA" );
	return( TRUE );
	}

int testReadWriteFileKey( void )
	{
	int status;

	status = writeFileKey( TRUE );
	if( status )
		status = readFileKey( TRUE );
	if( status )
		status = writeFileKey( FALSE );
	if( status )
		status = readFileKey( FALSE );
	return( status );
	}

/* Read only the public key/cert/cert chain portion of a keyset */

int testReadFilePublicKey( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int cryptAlgo, status;

	puts( "Testing public key read from key file..." );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Read the public key from the file and make sure it really is a public-
	   key context */
	status = cryptGetPublicKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NAME,
								RSA_PRIVKEY_LABEL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetPublicKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptGetAttribute( cryptContext, CRYPT_CTXINFO_ALGO, &cryptAlgo );
	if( cryptStatusError( status ) || \
		cryptAlgo < CRYPT_ALGO_FIRST_PKC || cryptAlgo > CRYPT_ALGO_LAST_PKC )
		{
		puts( "Returned object isn't a public-key context." );
		return( FALSE );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	cryptDestroyContext( cryptContext );

	puts( "Read of public key from key file succeeded.\n" );
	return( TRUE );
	}

static int readCert( const char *certTypeName,
					 const CRYPT_CERTTYPE_TYPE certType )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCert;
	int value, status;

	printf( "Testing %s read from key file...\n", certTypeName );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Read the certificate from the file and make sure it really is a cert */
	status = cryptGetPublicKey( cryptKeyset, &cryptCert, CRYPT_KEYID_NAME,
								( certType == CRYPT_CERTTYPE_CERTIFICATE ) ? \
								RSA_PRIVKEY_LABEL : USER_PRIVKEY_LABEL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetPublicKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptGetCertComponentNumeric( cryptCert, CRYPT_CERTINFO_CERTTYPE,
										   &value );
	if( cryptStatusError( status ) || value != certType )
		{
		printf( "Returned object isn't a %s.\n", certTypeName );
		return( FALSE );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	cryptDestroyCert( cryptCert );

	printf( "Read of %s from key file succeeded.\n\n", certTypeName );
	return( TRUE );
	}

int testReadFileCert( void )
	{
	return( readCert( "certificate", CRYPT_CERTTYPE_CERTIFICATE ) );
	}
int testReadFileCertChain( void )
	{
	return( readCert( "cert chain", CRYPT_CERTTYPE_CERTCHAIN ) );
	}

/* Update a keyset to contain a certificate */

int testAddTrustedCert( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE trustedCert;
	int status;

	puts( "Testing trusted certificate add to key file ..." );

	/* Read the CA root cert and make it trusted */
	status = importCertFile( &trustedCert, CERT_FILE );
	if( cryptStatusError( status ) )
		{
		puts( "Couldn't read certificate from file, skipping test of trusted "
			  "cert write..." );
		return( TRUE );
		}
	cryptSetAttribute( trustedCert, CRYPT_CERTINFO_TRUSTED_IMPLICIT, TRUE );

	/* Open the keyset, update it with the trusted certificate, and close it */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPublicKey( cryptKeyset, trustedCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddPublicKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	cryptDestroyCert( trustedCert );
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	puts( "Trusted certificate add to key file succeeded.\n" );
	return( TRUE );
	}

static const CERT_DATA cACertData[] = {
	/* Identification information.  Note the non-heirarchical order of the
	   components to test the automatic arranging of the DN */
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Dave's Wetaburgers and CA" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave Himself" },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, "Certification Division" },
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },

	/* Self-signed X.509v3 certificate */
	{ CRYPT_CERTINFO_SELFSIGNED, IS_NUMERIC, TRUE },

	/* CA extensions.  Policies are very much CA-specific and currently
	   undefined, so we use a dummy OID for a nonexistant private org for
	   now */
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC,
	  CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN },
	{ CRYPT_CERTINFO_CA, IS_NUMERIC, TRUE },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

int testUpdateFileCert( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT publicKeyContext, privateKeyContext;
	int status;

	puts( "Testing certificate update to key file ..." );

	/* Create a self-signed CA certificate using the in-memory key (which is
	   the same as the one in the keyset) */
	if( !loadRSAContexts( CRYPT_UNUSED, &publicKeyContext, &privateKeyContext ) )
		return( FALSE );
	status = cryptCreateCert( &cryptCert, CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d.\n", status );
		return( FALSE );
		}
	status = cryptAddCertComponentNumeric( cryptCert,
						CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, publicKeyContext );
	if( cryptStatusOK( status ) && !addCertFields( cryptCert, cACertData ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCert, privateKeyContext );
	destroyContexts( CRYPT_UNUSED, publicKeyContext, privateKeyContext );
	if( cryptStatusError( status ) )
		{
		printf( "Certificate creation failed with error code %d.\n", status );
		cryptDestroyCert( status );
		return( FALSE );
		}

	/* Open the keyset, update it with the certificate, and close it */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPublicKey( cryptKeyset, cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddPublicKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	cryptDestroyCert( cryptCert );
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	puts( "Certificate update to key file succeeded.\n" );
	return( TRUE );
	}

/* Update a keyset to contain a cert chain */

static const CERT_DATA certRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Dave's Wetaburgers" },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, "Procurement" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave Smith" },
	{ CRYPT_CERTINFO_EMAIL, IS_STRING, 0, "dave@wetaburgers.com" },

	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

int testWriteFileCertChain( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCertChain;
	CRYPT_CONTEXT cryptCAKey, cryptKey;
	int status;

	puts( "Testing cert chain write to key file ..." );

	/* Generate a key to certify.  We can't just reuse the built-in test key
	   because this has already been used as the CA key and the keyset code
	   won't allow it to be added to a keyset as both a CA key and user key,
	   so we have to generate a new one */
	status = cryptCreateContext( &cryptKey, CRYPT_ALGO_RSA, CRYPT_MODE_PKC );
	if( cryptStatusOK( status ) )
		status = cryptSetAttributeString( cryptKey, CRYPT_CTXINFO_LABEL,
										  USER_PRIVKEY_LABEL, 
										  strlen( USER_PRIVKEY_LABEL ) );
	if( cryptStatusOK( status ) )
		status = cryptGenerateKeyEx( cryptKey, bitsToBytes( 512 ) );
	if( cryptStatusError( status ) )
		{
		printf( "Test key generation failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Get the CA's key */
	status = getPrivateKey( &cryptCAKey, CA_PRIVKEY_FILE,
							CA_PRIVKEY_LABEL, CA_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "CA private key read failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Create the keyset and cert chain containing the new key */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCreateCert( &cryptCertChain, CRYPT_CERTTYPE_CERTCHAIN );
	if( cryptStatusOK( status ) )
		status = cryptAddCertComponentNumeric( cryptCertChain,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptKey );
	cryptDestroyContext( cryptKey );
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptCertChain, certRequestData ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCertChain, cryptCAKey );
	cryptDestroyContext( cryptCAKey );
	if( cryptStatusError( status ) )
		{
		printf( "Cert chain creation failed with error code %d, line %d\n",
				status, __LINE__ );
		printCertErrorInfo( cryptCertChain );
		return( FALSE );
		}

	/* Write the cert chain to the file */
	status = cryptAddPrivateKey( cryptKeyset, cryptCertChain, 
								 USER_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddPublicKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	cryptDestroyCert( cryptCertChain );
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	puts( "Cert chain write to key file succeeded.\n" );
	return( TRUE );
	}

/* Delete a key from a file */

int testDeleteFileKey( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int status;

	puts( "Testing delete from key file..." );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Delete the key from the file.  Since we don't need the DSA key any 
	   more we use it as the key to delete */
	status = cryptDeleteKey( cryptKeyset, CRYPT_KEYID_NAME, 
							 DSA_PRIVKEY_LABEL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDeleteKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptGetPublicKey( cryptKeyset, &cryptContext, CRYPT_KEYID_NAME, 
								DSA_PRIVKEY_LABEL );
	if( cryptStatusOK( status ) )
		{
		cryptDestroyContext( cryptContext );
		puts( "cryptDeleteKey() claimed the key was deleted but it's still "
			  "present." );
		return( FALSE );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	puts( "Delete from key file succeeded.\n" );
	return( TRUE );
	}

/* Change the password for a key in a file */

int testChangeFileKeyPassword( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int status;

	puts( "Testing change of key password for key file..." );

	/* Open the file keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Read the key using the old password, delete it, and write it back
	   using the new password.  To keep things simple we just use the same
	   password (since the key will be used again later), the test of the
	   delete function earlier on has already confirmed that the old key 
	   and password will be deleted so there's no chance of a false positive */
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
								 CRYPT_KEYID_NAME, RSA_PRIVKEY_LABEL,
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusOK( status ) )
		status = cryptDeleteKey( cryptKeyset, CRYPT_KEYID_NAME, 
								 RSA_PRIVKEY_LABEL );
	if( cryptStatusOK( status ) )
		status = cryptAddPrivateKey( cryptKeyset, cryptContext,
									 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "Password change failed with error code %d, line %d\n", 
				status, __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	puts( "Password change for key in key file succeeded.\n" );
	return( TRUE );
	}

/* Write a key and cert to a file in a single operation */

int testSingleStepFileCert( void )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT cryptContext;
	int status;

	puts( "Testing single-step key+cert write to key file ..." );

	/* Create a self-signed CA certificate */
	if( !loadRSAContexts( CRYPT_UNUSED, NULL, &cryptContext ) )
		return( FALSE );
	status = cryptCreateCert( &cryptCert, CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d.\n", status );
		return( FALSE );
		}
	status = cryptAddCertComponentNumeric( cryptCert,
						CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
	if( cryptStatusOK( status ) && !addCertFields( cryptCert, cACertData ) )
		return( FALSE );
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCert, cryptContext );
	if( cryptStatusError( status ) )
		{
		printf( "Certificate creation failed with error code %d.\n", status );
		cryptDestroyCert( status );
		return( FALSE );
		}

	/* Open the keyset, write the key and certificate, and close it */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_FILE,
							  TEST_PRIVKEY_FILE, CRYPT_KEYOPT_CREATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPrivateKey( cryptKeyset, cryptContext,
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddPrivateKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptAddPublicKey( cryptKeyset, cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddPrivateKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	cryptDestroyContext( cryptContext );
	cryptDestroyCert( cryptCert );
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Try and read the key+cert back.  We use the generic RSA key label to
	   read it since this isn't a real user key */
	status = getPrivateKey( &cryptContext, TEST_PRIVKEY_FILE,
							RSA_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	cryptDestroyContext( cryptContext );
	if( cryptStatusError( status ) )
		{
		printf( "Private key read failed with error code %d, line %d\n", 
				status, __LINE__ );
		return( FALSE );
		}

	puts( "Single-step key+cert write to key file succeeded.\n" );
	return( TRUE );
	}

/* Read/write a private key from a smart card */

static int gemplusOK = FALSE, towitokoOK = FALSE;

int readCardKey( const char *readerName )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT cryptContext;
	int status;

	printf( "Testing smart card key read with %s reader...", readerName );

	/* Open the smart card keyset, with a check to make sure this access
	   method exists so we can return an appropriate error message */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_SMARTCARD,
							  readerName, CRYPT_KEYOPT_READONLY );
	if( status == CRYPT_BADPARM2 )	/* Smart card access not available */
		return( CRYPT_ERROR_NOTAVAIL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Read the key from the file */
	status = cryptGetPrivateKey( cryptKeyset, &cryptContext,
								 CRYPT_KEYID_NAME, RSA_PRIVKEY_LABEL, 
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		printf( "cryptGetPrivateKey() failed with error code %d, line %d\n",
				status, __LINE__ );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );

	cryptDestroyContext( cryptContext );

	puts( "Key read from smart card succeeded.\n" );
	return( TRUE );
	}

int testReadCardKey( void )
	{
	if( gemplusOK && !readCardKey( "Gemplus" ) )
		return( FALSE );
	if( towitokoOK && !readCardKey( "Towitoko" ) )
		return( FALSE );
	return( TRUE );
	}

static int writeCardKey( const char *readerName )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CONTEXT privKeyContext;
	int status;

	printf( "Testing smart card key write with %s reader...\n", 
			readerName );

	/* Create the RSA encryption context */
	if( !loadRSAContexts( CRYPT_UNUSED, NULL, &privKeyContext ) )
		return( FALSE );

	/* Create the smart card keyset, with a check to make sure this access
	   method exists so we can return an appropriate error message */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_KEYSET_SMARTCARD,
							  readerName, CRYPT_KEYOPT_CREATE );
	if( status == CRYPT_BADPARM2 )	/* Smart card access not available */
		return( CRYPT_ERROR_NOTAVAIL );
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( privKeyContext );
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		if( status == CRYPT_BADPARM3 )	/* Reader type not available */
			{
			printf( "This may be because you haven't plugged in or enabled "
					"the reader.\n" );
			return( CRYPT_ERROR_NOTAVAIL );
			}
		return( FALSE );
		}

	/* Write the key to the card */
	status = cryptAddPrivateKey( cryptKeyset, privKeyContext, 
								 TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddPrivateKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	cryptDestroyContext( privKeyContext );

	puts( "Key write to smart card succeeded.\n" );
	return( TRUE );
	}

int testWriteCardKey( void )
	{
	int status;

	status = writeCardKey( "Gemplus" );
	if( status == TRUE )
		gemplusOK = TRUE;
	if( !status )
		return( FALSE );
	status = writeCardKey( "Towitoko" );
	if( status == TRUE )
		towitokoOK = TRUE;
	return( status );
	}

/* Read/write a certificate from a public-key keyset.  Returns 
   CRYPT_ERROR_NOTAVAIL if this keyset type isn't available from this 
   cryptlib build, CRYPT_ERROR_FAILED if the keyset/data source access 
   failed */

static int testKeysetRead( const CRYPT_KEYSET_TYPE keysetType,
						   const char *keysetName,
						   const char *keyName, 
						   const CRYPT_CERTTYPE_TYPE type )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCert;
	int value, status;

	/* Open the keyset with a check to make sure this access method exists 
	   so we can return an appropriate error message */
	status = cryptKeysetOpen( &cryptKeyset, keysetType, keysetName,
							  CRYPT_KEYOPT_READONLY );
	if( status == CRYPT_BADPARM2 )	/* Database keyset access not available */
		return( CRYPT_ERROR_NOTAVAIL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( CRYPT_ERROR_FAILED );
		}

	/* Read the certificate from the keyset */
	status = cryptGetPublicKey( cryptKeyset, &cryptCert, CRYPT_KEYID_NAME,
								keyName );
	if( cryptStatusError( status ) )
		{
		/* The access to network-accessible keysets can be rather 
		   temperamental and can fail at this point even though it's not a
		   fatal error.  The calling code knows this and will continue the
		   self-test with an appropriate warning, so we explicitly clean up 
		   after ourselves to make sure we don't get a CRYPT_ORPHAN on
		   shutdown */
		cryptKeysetClose( cryptKeyset );
		printf( "cryptGetPublicKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure we got what we were expecting */
	cryptGetCertComponentNumeric( cryptCert, CRYPT_CERTINFO_CERTTYPE, &value );
	if( value != type )
		{
		printf( "Expecting certificate object type %d, got %d.", type, value );
		return( FALSE );
		}
	if( value == CRYPT_CERTTYPE_CERTCHAIN )
		{
		value = 0;
		cryptAddCertComponentNumeric( cryptCert, 
					CRYPT_CERTINFO_CURRENT_CERTIFICATE, CRYPT_CURSOR_FIRST );
		do
			value++;
		while( cryptAddCertComponentNumeric( cryptCert,
					CRYPT_CERTINFO_CURRENT_CERTIFICATE, CRYPT_CURSOR_NEXT ) == CRYPT_OK );
		printf( "Cert chain length = %d.\n", value );
		}

	/* Check the cert against the CRL.  Any kind of error is a failure since
	   the cert isn't in the CRL */
	if( keysetType != CRYPT_KEYSET_LDAP && \
		keysetType != CRYPT_KEYSET_HTTP )
		{
		puts( "Checking certificate against CRL." );
		status = cryptCheckCert( cryptCert, cryptKeyset );
		if( cryptStatusError( status ) )
			{
			printf( "cryptCheckCert() (for CRL in keyset) failed with error "
					"code %d, line %d\n", status, __LINE__ );
			return( FALSE );
			}
		}

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	cryptDestroyCert( cryptCert );
	return( TRUE );
	}

static int testKeysetWrite( const CRYPT_KEYSET_TYPE keysetType,
							const char *keysetName )
	{
	CRYPT_KEYSET cryptKeyset;
	CRYPT_CERTIFICATE cryptCert;
	int status;

	/* Import the certificate from a file - this is easier than creating one
	   from scratch */
	status = importCertFile( &cryptCert, CERT_FILE );
	if( cryptStatusError( status ) )
		{
		puts( "Couldn't read certificate from file, skipping test of keyset "
			  "write..." );
		return( TRUE );
		}

	/* Create the database keyset with a check to make sure this access
	   method exists so we can return an appropriate error message.  If the
	   database table already exists, this will return a duplicate data
	   error so we retry the open with no flags to open the existing database
	   keyset for write access */
	status = cryptKeysetOpen( &cryptKeyset, keysetType, keysetName,
							  CRYPT_KEYOPT_CREATE );
	if( status == CRYPT_BADPARM2 )
		{
		/* This type of keyset access isn't available, return a special error
		   code to indicate that the test wasn't performed, but that this
		   isn't a reason to abort processing */
		cryptDestroyCert( cryptCert );
		return( CRYPT_ERROR_NOTAVAIL );
		}
	if( status == CRYPT_DATA_DUPLICATE )
		status = cryptKeysetOpen( &cryptKeyset, keysetType, keysetName, 0 );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		if( status == CRYPT_DATA_OPEN )
			return( CRYPT_ERROR_FAILED );
		return( FALSE );
		}

	/* Write the key to the database */
	puts( "Adding certificate." );
	status = cryptAddPublicKey( cryptKeyset, cryptCert );
	if( status == CRYPT_DATA_DUPLICATE )
		{
		/* The key is already present, delete it and retry the write */
		status = cryptDeleteKey( cryptKeyset, CRYPT_KEYID_NAME,
						"Class 1 Public Primary Certification Authority" );
		if( cryptStatusError( status ) )
			{
			printf( "cryptDeleteKey() failed with error code %d, line %d\n",
					status, __LINE__ );
			return( FALSE );
			}
		status = cryptAddPublicKey( cryptKeyset, cryptCert );
		}
	if( cryptStatusError( status ) )
		{
		printKeysetError( cryptKeyset, "cryptAddPublicKey", status );

		/* LDAP writes can fail due to the chosen directory not supporting the
		   schema du jour, so we're a bit more careful about cleaning up since
		   we'll skip the error and continue processing */
		cryptDestroyCert( cryptCert );
		cryptKeysetClose( cryptKeyset );
		return( FALSE );
		}
	cryptDestroyCert( cryptCert );

	/* Now try the same thing with a CRL.  This code also tests the 
	   duplicate-detection mechanism, if we don't get a duplicate error 
	   there's a problem */
	puts( "Adding CRL." );
	status = importCertFile( &cryptCert, CRL_FILE );
	if( cryptStatusError( status ) )
		{
		puts( "Couldn't read CRL from file, skipping test of keyset "
			  "write..." );
		return( TRUE );
		}
	status = cryptAddPublicKey( cryptKeyset, cryptCert );
	if( cryptStatusError( status ) && status != CRYPT_DATA_DUPLICATE )
		{
		printKeysetError( cryptKeyset, "cryptAddPublicKey", status );
		return( FALSE );
		}
	status = cryptAddPublicKey( cryptKeyset, cryptCert );
	if( status != CRYPT_DATA_DUPLICATE )
		{
		puts( "Addition of duplicate item to keyset failed to produce "
			  "CRYPT_DATA_DUPLICATE" );
		return( FALSE );
		}
	cryptDestroyCert( cryptCert );

	/* Finally, try it with a cert chain */
	puts( "Adding cert chain." );
	status = importCertFile( &cryptCert, CERTCHAIN_FILE );
	if( cryptStatusError( status ) )
		{
		puts( "Couldn't read cert chain from file, skipping test of keyset "
			  "write..." );
		return( TRUE );
		}
	status = cryptAddPublicKey( cryptKeyset, cryptCert );
	if( cryptStatusError( status ) && status != CRYPT_DATA_DUPLICATE )
		{
		printKeysetError( cryptKeyset, "cryptAddPublicKey", status );
		return( FALSE );
		}
	cryptDestroyCert( cryptCert );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );

	return( TRUE );
	}

/* Perform a general keyset query */

int testQuery( const CRYPT_KEYSET_TYPE keysetType, const char *keysetName )
	{
	CRYPT_KEYSET cryptKeyset;
	int count = 0, status;

	/* Open the database keyset */
	status = cryptKeysetOpen( &cryptKeyset, keysetType, keysetName,
							  CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d\n",
				status, __LINE__ );
		if( status == CRYPT_DATA_OPEN )
			return( CRYPT_ERROR_FAILED );
		return( FALSE );
		}

	/* Send the query to the database and read back the results */
	status = cryptKeysetQuery( cryptKeyset, "$C='US'" );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetQuery() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	do
		{
		CRYPT_CERTIFICATE cryptCert;

		status = cryptGetPublicKey( cryptKeyset, &cryptCert,
									CRYPT_KEYID_NONE, NULL );
		if( cryptStatusOK( status ) )
			{
			count++;
			cryptDestroyCert( cryptCert );
			}
		}
	while( cryptStatusOK( status ) );
	if( cryptStatusError( status ) && status != CRYPT_ERROR_COMPLETE )
		{
		printf( "cryptGetPublicKey() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "%d certificate(s) matched the query.\n", count );

	/* Close the keyset */
	status = cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetClose() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

/* Read/write/query a certificate from a database keyset */

int testReadCert( void )
	{
	int status;

	puts( "Testing certificate database read..." );
	status = testKeysetRead( DATABASE_KEYSET_TYPE, DATABASE_KEYSET_NAME,
	 						 "Class 1 Public Primary Certification Authority",
							 CRYPT_CERTTYPE_CERTIFICATE );
	if( status == CRYPT_ERROR_NOTAVAIL )	/* Database keyset access not available */
		return( CRYPT_ERROR_NOTAVAIL );
	if( status == CRYPT_ERROR_FAILED )
		{
		puts( "This is probably because you haven't set up a database or "
			  "data source for use\nas a key database.  For this test to "
			  "work, you need to set up a database/data\nsource with the "
			  "name '" DATABASE_KEYSET_NAME "'.\n" );
		return( TRUE );
		}
	if( !status )
		return( FALSE );
	puts( "Reading complete cert chain." );
	status = testKeysetRead( DATABASE_KEYSET_TYPE, DATABASE_KEYSET_NAME,
	 						 "Thawte Freemail Member", 
							 CRYPT_CERTTYPE_CERTCHAIN );
	if( !status )
		return( FALSE );
	puts( "Certificate database read succeeded.\n" );
	return( TRUE );
	}

int testWriteCert( void )
	{
	int status;

	puts( "Testing certificate database write..." );
	status = testKeysetWrite( DATABASE_KEYSET_TYPE, DATABASE_KEYSET_NAME );
	if( status == CRYPT_ERROR_NOTAVAIL )	/* Database keyset access not available */
		return( CRYPT_ERROR_NOTAVAIL );
	if( status == CRYPT_ERROR_FAILED )
		{
		printf( "This may be because you haven't set up a data source "
				"called '" DATABASE_KEYSET_NAME "'\nof type %d which can be "
				"used for the certificate store.  You can configure\nthe "
				"data source type and name using the DATABASE_KEYSET_xxx "
				"settings in\ntest/test.h.\n", DATABASE_KEYSET_TYPE );
		return( TRUE );
		}
	if( !status )
		return( FALSE );
	puts( "Certificate database write succeeded.\n" );
	return( TRUE );
	}

int testKeysetQuery( void )
	{
	int status;

	puts( "Testing general certificate database query..." );
	status = testQuery( DATABASE_KEYSET_TYPE, DATABASE_KEYSET_NAME );
	if( status == CRYPT_ERROR_NOTAVAIL )	/* Database keyset access not available */
		return( CRYPT_ERROR_NOTAVAIL );
	if( status == CRYPT_ERROR_FAILED )
		{
		puts( "This is probably because you haven't set up a database or "
			  "data source for use\nas a key database.  For this test to "
			  "work, you need to set up a database/data\nsource with the "
			  "name '" DATABASE_KEYSET_NAME "'.\n" );
		return( TRUE );
		}
	if( !status )
		return( FALSE );
	puts( "Certificate database query succeeded.\n" );
	return( TRUE );
	}

/* Read/write/query a certificate from an LDAP keyset */

int testReadCertLDAP( void )
	{
	char certName[ CRYPT_MAX_TEXTSIZE ], caCertName[ CRYPT_MAX_TEXTSIZE ];
	char crlName[ CRYPT_MAX_TEXTSIZE ];
	int length, status;

	/* Because the LDAP directory we're using for these tests doesn't 
	   recognise the ';binary' modifier which is required by LDAP servers in
	   order to get them to work properly, we have to change the attribute
	   name around the read calls to the format expected by the server.
	   
	   In addition because the magic formula for fetching a CRL doesn't seem
	   to work for certificates, the CRL read is done first */
	puts( "Testing LDAP CRL read..." );
	cryptGetOptionString( CRYPT_OPTION_KEYS_LDAP_CRLNAME, crlName, &length );
	certName[ length ] = '\0';
	cryptSetOptionString( CRYPT_OPTION_KEYS_LDAP_CRLNAME, 
						  "certificateRevocationList" );
	status = testKeysetRead( CRYPT_KEYSET_LDAP, LDAP_KEYSET_NAME,
							 LDAP_CRL_NAME, CRYPT_CERTTYPE_CRL );
	cryptSetOptionString( CRYPT_OPTION_KEYS_LDAP_CRLNAME, crlName );
	if( status == CRYPT_ERROR_NOTAVAIL )	/* LDAP keyset access not available */
		return( CRYPT_ERROR_NOTAVAIL );
	if( status == CRYPT_ERROR_FAILED )
		{
		puts( "This may be because you haven't set up an LDAP directory "
			  "called\n'" LDAP_KEYSET_NAME "' which can be used for the "
			  "certificate store.  You can\nconfigure the LDAP directory "
			  "using the LDAP_KEYSET_xxx settings in\ntest/test.h.  If "
			  "this message took a long time to appear, you may be "
			  "behind\na firewall which blocks LDAP traffic.\n" );
		return( FALSE );
		}
	if( !status )
		{
		/* Since we can never be sure about the LDAP schema du jour, we
		   don't treat a failure as a fatal error */
		puts( "LDAP directory read failed, probably due to the standard "
			  "being used by the\ndirectory server differing from the one "
			  "used by the LDAP client software\n(pick a standard, any "
			  "standard).  If you know how the directory being used\nis "
			  "configured, you can try changing the "
			  "CRYPT_OPTION_KEYS_LDAP_xxx settings\nto match those used by "
			  "the server.  Processing will continue without\ntreating this "
			  "as a fatal error.\n" );
		return( FALSE );
		}

	puts( "Testing LDAP certificate read..." );
	cryptGetOptionString( CRYPT_OPTION_KEYS_LDAP_CERTNAME, certName, &length );
	certName[ length ] = '\0';
	cryptSetOptionString( CRYPT_OPTION_KEYS_LDAP_CERTNAME, "userCertificate" );
	cryptGetOptionString( CRYPT_OPTION_KEYS_LDAP_CACERTNAME, caCertName, &length );
	certName[ length ] = '\0';
	cryptSetOptionString( CRYPT_OPTION_KEYS_LDAP_CACERTNAME, "cACertificate" );
	status = testKeysetRead( CRYPT_KEYSET_LDAP, LDAP_KEYSET_NAME,
							 LDAP_CERT_NAME, CRYPT_CERTTYPE_CERTIFICATE );
	cryptSetOptionString( CRYPT_OPTION_KEYS_LDAP_CERTNAME, certName );
	cryptSetOptionString( CRYPT_OPTION_KEYS_LDAP_CACERTNAME, caCertName );
	if( !status )
		{
		/* Since we can never be sure about the LDAP schema du jour, we
		   don't treat a failure as a fatal error */
		puts( "LDAP directory read failed, probably due to the magic "
			  "incantatation to fetch\na certificate from this server not "
			  "matching the one used to fetch a CRL.\nProcessing will "
			  "continue without treating this as a fatal error.\n" );
		return( FALSE );
		}
	puts( "LDAP certificate/CRL read succeeded.\n" );

	return( TRUE );
	}

int testWriteCertLDAP( void )
	{
	int status;

	puts( "Testing LDAP directory write..." );
	status = testKeysetWrite( CRYPT_KEYSET_LDAP, LDAP_KEYSET_NAME );
	if( status == CRYPT_ERROR_NOTAVAIL )	/* LDAP keyset access not available */
		return( CRYPT_ERROR_NOTAVAIL );
	if( status == CRYPT_ERROR_FAILED )
		{
		puts( "This is probably because you haven't set up an LDAP "
			  "directory for use as the\nkey store.  For this test to work,"
			  "you need to set up a directory with the\nname '"
			  LDAP_KEYSET_NAME "'.\n" );
		return( FALSE );
		}
	if( !status )
		{
		/* Since we can never be sure about the LDAP schema du jour, we
		   don't treat a failure as a fatal error */
		puts( "LDAP directory write failed, probably due to the standard "
			  "being used by the\ndirectory differing from the one used "
			  "by cryptlib (pick a standard, any\nstandard).  Processing "
			  "will continue without treating this as a fatal error.\n" );
		return( FALSE );
		}
	puts( "LDAP directory write succeeded.\n" );
	return( TRUE );
	}

/* Read a certificate from a web page */

int testReadCertHTTP( void )
	{
	int status;

	puts( "Testing HTTP certificate read..." );
	status = testKeysetRead( CRYPT_KEYSET_HTTP, NULL, HTTP_KEYSET_CERT_NAME, 
							 CRYPT_CERTTYPE_CERTIFICATE );
	if( status == CRYPT_ERROR_NOTAVAIL )	/* HTTP keyset access not avail.*/
		return( CRYPT_ERROR_NOTAVAIL );
	if( !status )
		{
		/* The HTTP error return is slightly different from the standard one,
		   since HTTP is stateless the connection isn't actually opened until
		   the caller tries to read a key so the failure is detcted at a 
		   later point and we don't get a (translated) CRYPT_FAILED */
		puts( "If this message took a long time to appear, you may be "
			  "behind a firewall\nwhich blocks HTTP traffic.\n" );
		return( FALSE );
		}
	puts( "Testing HTTP CRL read..." );
	status = testKeysetRead( CRYPT_KEYSET_HTTP, NULL, HTTP_KEYSET_CRL_NAME, 
							 CRYPT_CERTTYPE_CRL );
	if( status == CRYPT_ERROR_NOTAVAIL )	/* HTTP keyset access not avail.*/
		return( CRYPT_ERROR_NOTAVAIL );
	if( !status )
		return( FALSE );

	puts( "HTTP certificate/CRL read succeeded.\n" );
	return( TRUE );
	}
