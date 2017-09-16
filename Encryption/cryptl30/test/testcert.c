/****************************************************************************
*																			*
*					cryptlib Certificate Handling Test Routines				*
*						Copyright Peter Gutmann 1997-1999					*
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

/* Generic I/O buffer size.  This has to be of a reasonable size so we can
   handle cert chains */

#if defined( __MSDOS__ ) && defined( __TURBOC__ )
  #define BUFFER_SIZE		4096
#else
  #define BUFFER_SIZE		8192
#endif /* __MSDOS__ && __TURBOC__ */

/****************************************************************************
*																			*
*						Certificate Creation Routines Test					*
*																			*
****************************************************************************/

BYTE FAR_BSS certBuffer[ BUFFER_SIZE ];
int certificateLength;

/* Exit with an error message */

static BOOLEAN errorExit( const CRYPT_CERTIFICATE cryptCert,
						  const char *functionName, const int errorCode,
						  const int lineNumber )
	{
	printf( "%s failed with error code %d, line %d\n", functionName,
			errorCode, lineNumber );
	printCertErrorInfo( cryptCert );
	return( FALSE );
	}

/* Create a series of self-signed certs */

static const CERT_DATA certData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Dave's Wetaburgers" },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, "Procurement" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave Smith" },

	/* Self-signed X.509v1 certificate */
	{ CRYPT_CERTINFO_SELFSIGNED, IS_NUMERIC, TRUE },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

int testCert( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	int value, status;

#if defined( _MSC_VER ) && ( _MSC_VER <= 800 )
	time_t testTime = time( NULL ), newTime;

	newTime = mktime( localtime( &testTime ) );
	if( newTime == testTime )
		{
		puts( "Illogical local/GMT time detected.  VC++ 1.5x occasionally "
			  "exhibits a bug in\nits time zone handling in which it thinks "
			  "that the local time zone is GMT and\nGMT itself is some "
			  "negative offset from the current time.  This upsets\n"
			  "cryptlibs certificate date validity checking, since "
			  "certificates appear to\nhave inconsistent dates.  Deleting "
			  "all the temporary files and rebuilding\ncryptlib after "
			  "restarting your machine may fix this.\n" );
		return( FALSE );
		}
#endif /* VC++ 1.5 bug check */

	puts( "Testing certificate creation/export..." );

	/* Create the RSA en/decryption contexts */
	if( !loadRSAContexts( CRYPT_UNUSED, &pubKeyContext, &privKeyContext ) )
		return( FALSE );

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add some certificate components */
	status = cryptAddCertComponentNumeric( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddCertComponentNumeric() failed with error code %d, "
				"line %d\n", status, __LINE__ );
		return( FALSE );
		}
	if( !addCertFields( cryptCert, certData ) )
		return( FALSE );

	/* Delete a component and replace it with something else */
	status = cryptDeleteCertComponent( cryptCert,
									   CRYPT_CERTINFO_COMMONNAME );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDeleteCertComponent() failed with error code %d, "
				"line %d\n", status, __LINE__ );
		return( FALSE );
		}
	cryptAddCertComponentString( cryptCert,
				CRYPT_CERTINFO_COMMONNAME, "Dave Taylor", 11 );

	/* Sign the certificate.  Since we're creating a self-signed cert, we need
	   to make it an X.509v1 cert because the default X.509v3 keyUsage doesn't
	   allow cert signing unless this is explicitly set */
	cryptGetOptionNumeric( CRYPT_OPTION_CERT_CREATEV3CERT, &value );
	cryptSetOptionNumeric( CRYPT_OPTION_CERT_CREATEV3CERT, FALSE );
	status = cryptSignCert( cryptCert, privKeyContext );
	cryptSetOptionNumeric( CRYPT_OPTION_CERT_CREATEV3CERT, value );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptSignCert()", status, __LINE__ ) );

	/* Print information on what we've got */
	printCertInfo( cryptCert );

	/* Check the signature.  Since it's self-signed, we don't need to pass in
	   a signature check key */
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptCheckCert()", status, __LINE__ ) );

	/* Set the cert usage to untrusted for any purpose, which should result 
	   in the signature check failing */
	cryptAddCertComponentNumeric( cryptCert, CRYPT_CERTINFO_TRUSTED_USAGE, 
								  CRYPT_KEYUSAGE_NONE );
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusOK( status ) )
		{
		puts( "Untrusted cert signature check succeeded, should have "
			  "failed." );
		return( FALSE );
		}
	cryptDeleteCertComponent( cryptCert, CRYPT_CERTINFO_TRUSTED_USAGE );

	/* Export the cert.  We perform a length check using a null buffer to
	   make sure this is working as required */
	status = cryptExportCert( NULL, &value, CRYPT_CERTFORMAT_CERTIFICATE, 
							  cryptCert );
	if( cryptStatusOK( status ) )
		status = cryptExportCert( certBuffer, &certificateLength,
								  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptExportCert()", status, __LINE__ ) );
	if( value != certificateLength )
		{
		puts( "Exported certificate size != actual data size." );
		return( FALSE );
		}
	printf( "Exported certificate is %d bytes long.\n", certificateLength );
	debugDump( "cert", certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptCheckCert()", status, __LINE__ ) );
	cryptDestroyCert( cryptCert );

	/* Clean up */
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	puts( "Certificate creation succeeded.\n" );
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

	/* Expiry date set to > Y2K to test for Y2K problems */
	{ CRYPT_CERTINFO_VALIDTO, IS_TIME, 0, NULL, 0x46300C01L },

	/* CA extensions.  Policies are very much CA-specific and currently
	   undefined, so we use a dummy OID for a nonexistant private org for
	   now */
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC,
	  CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN },
	{ CRYPT_CERTINFO_CA, IS_NUMERIC, TRUE },
	{ CRYPT_CERTINFO_CERTPOLICYID, IS_STRING, 0, "1 3 6 1 4 1 9999 1" },
		/* Blank line needed due to bug in Borland C++ parser */
	{ CRYPT_CERTINFO_CERTPOLICY_EXPLICITTEXT, IS_STRING, 0, "This policy "
		"isn't worth the paper it's not printed on." },
	{ CRYPT_CERTINFO_CERTPOLICY_ORGANIZATION, IS_STRING, 0, "Honest Joe's "
		"used cars and certification authority" },
	{ CRYPT_CERTINFO_CERTPOLICY_NOTICENUMBERS, IS_NUMERIC, 1 },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

int testCACert( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	int status;

	puts( "Testing CA certificate creation/export..." );

	/* Create the RSA en/decryption contexts */
	if( !loadRSAContexts( CRYPT_UNUSED, &pubKeyContext, &privKeyContext ) )
		return( FALSE );

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add some certificate components */
	status = cryptAddCertComponentNumeric( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddCertComponentNumeric() failed with error code %d, "
				"line %d\n", status, __LINE__ );
		return( FALSE );
		}
	if( !addCertFields( cryptCert, cACertData ) )
		return( FALSE );

	/* Sign the certificate */
	status = cryptSignCert( cryptCert, privKeyContext );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptSignCert()", status, __LINE__ ) );

	/* Print information on what we've got */
	printCertInfo( cryptCert );

	/* Export the cert */
	status = cryptExportCert( certBuffer, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptExportCert()", status, __LINE__ ) );
	printf( "Exported certificate is %d bytes long.\n", certificateLength );
	debugDump( "cacert", certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure we can read what we created.  We make the second parameter 
	   to the check function the cert (rather than CRYPT_UNUSED as done for
	   the basic self-signed cert) to check that this option works as 
	   required */
	status = cryptImportCert( certBuffer, certificateLength, &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, cryptCert );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptCheckCert()", status, __LINE__ ) );
	cryptDestroyCert( cryptCert );

	/* Clean up */
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	puts( "CA certificate creation succeeded.\n" );
	return( TRUE );
	}

static const CERT_DATA complexCertData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Dave's Wetaburgers and Netscape CA" },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, "SSL Certificates" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave Himself" },

	/* Self-signed X.509v3 certificate */
	{ CRYPT_CERTINFO_SELFSIGNED, IS_NUMERIC, TRUE },

	/* Subject altName */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, "dave@wetas-r-us.com" },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, "http://www.wetas-r-us.com" },

	/* Oddball altName components.  Note that the otherName.value must be a
	   DER-encoded ASN.1 object */
	{ CRYPT_CERTINFO_EDIPARTYNAME_NAMEASSIGNER, IS_STRING, 0, "EDI Name Assigner" },
	{ CRYPT_CERTINFO_EDIPARTYNAME_PARTYNAME, IS_STRING, 0, "EDI Party Name" },
	{ CRYPT_CERTINFO_OTHERNAME_TYPEID, IS_STRING, 0, "1 3 6 1 4 1 9999 2" },
	{ CRYPT_CERTINFO_OTHERNAME_VALUE, IS_STRING, 0, "\x04\x08" "12345678" },

	/* Path constraint.  Note the two-stage selection process, first we
	   select the GeneralName with CRYPT_CERTINFO_EXCLUDEDSUBTREES, then we
	   select the DN in the GeneralName with CRYPT_CERTINFO_DIRECTORYNAME */
	{ CRYPT_CERTINFO_EXCLUDEDSUBTREES, IS_NUMERIC, CRYPT_UNUSED },
	{ CRYPT_CERTINFO_DIRECTORYNAME, IS_NUMERIC, CRYPT_UNUSED },
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Dave's Brother's CA" },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, "SSL Certificates" },

	/* Netscape cert-type extension, revocation URL, and Netscape SGC cert
	   (this is a pretty confused certificate) */
	{ CRYPT_CERTINFO_NS_CERTTYPE, IS_NUMERIC,
	  CRYPT_NS_CERTTYPE_SSLSERVER | CRYPT_NS_CERTTYPE_SMIME },
	{ CRYPT_CERTINFO_NS_REVOCATIONURL, IS_STRING, 0, "http://www.revocations.com/certs/" },
	{ CRYPT_CERTINFO_EXTKEY_NS_SERVERGATEDCRYPTO, IS_NUMERIC, CRYPT_UNUSED },

	/* Add a vendor-specific extension, in this case a Thawte strong extranet
	   extension */
	{ CRYPT_CERTINFO_STRONGEXTRANET_ZONE, IS_NUMERIC, 0x99 },
	{ CRYPT_CERTINFO_STRONGEXTRANET_ID, IS_STRING, 0, "EXTRA1" },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

int testComplexCert( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	int status;

	puts( "Testing complex certificate creation/export..." );

	/* Create the RSA en/decryption contexts */
	if( !loadRSAContexts( CRYPT_UNUSED, &pubKeyContext, &privKeyContext ) )
		return( FALSE );

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add some certificate components */
	status = cryptAddCertComponentNumeric( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddCertComponentNumeric() failed with error code %d, "
				"line %d\n", status, __LINE__ );
		return( FALSE );
		}
	if( !addCertFields( cryptCert, complexCertData ) )
		return( FALSE );

	/* Add a non-CA basicConstraint, delete it, and re-add it as CA
	   constraint */
	status = cryptAddCertComponentNumeric( cryptCert,
					CRYPT_CERTINFO_CA, FALSE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddCertComponentNumeric() failed with error code %d, "
				"line %d\n", status, __LINE__ );
		printCertErrorInfo( cryptCert );
		return( FALSE );
		}
	status = cryptDeleteCertComponent( cryptCert,
									   CRYPT_CERTINFO_BASICCONSTRAINTS );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDeleteCertComponent() failed with error code %d, "
				"line %d\n", status, __LINE__ );
		printCertErrorInfo( cryptCert );
		return( FALSE );
		}
	if( cryptStatusOK( status ) )
		status = cryptAddCertComponentNumeric( cryptCert,
					CRYPT_CERTINFO_CA, TRUE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddCertComponentNumeric() failed with error code %d, "
				"line %d\n", status, __LINE__ );
		printCertErrorInfo( cryptCert );
		return( FALSE );
		}

	/* Sign the certificate */
	status = cryptSignCert( cryptCert, privKeyContext );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptSignCert()", status, __LINE__ ) );

	/* Print information on what we've got */
	printCertInfo( cryptCert );

	/* Export the cert */
	status = cryptExportCert( certBuffer, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptExportCert()", status, __LINE__ ) );
	printf( "Exported certificate is %d bytes long.\n", certificateLength );
	debugDump( "certc", certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptCheckCert()", status, __LINE__ ) );
	cryptDestroyCert( cryptCert );

	/* Clean up */
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	puts( "Complex certificate creation succeeded.\n" );
	return( TRUE );
	}

static const CERT_DATA setCertData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Dave's Wetaburgers and Temple of SET" },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, "SET Commerce Division" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave's Cousin Bob" },

	/* Self-signed X.509v3 certificate */
	{ CRYPT_CERTINFO_SELFSIGNED, IS_NUMERIC, TRUE },

	/* Add the SET extensions */
	{ CRYPT_CERTINFO_SET_CERTIFICATETYPE, IS_NUMERIC, CRYPT_SET_CERTTYPE_RCA },
	{ CRYPT_CERTINFO_SET_CERTCARDREQUIRED, IS_NUMERIC, TRUE },
	{ CRYPT_CERTINFO_SET_ROOTKEYTHUMBPRINT, IS_STRING, 20, "12345678900987654321" },
	{ CRYPT_CERTINFO_SET_MERID, IS_STRING, 0, "Wetaburger Vendor" },
	{ CRYPT_CERTINFO_SET_MERACQUIRERBIN, IS_STRING, 0, "123456" },
	{ CRYPT_CERTINFO_SET_MERCHANTLANGUAGE, IS_STRING, 0, "English" },
	{ CRYPT_CERTINFO_SET_MERCHANTNAME, IS_STRING, 0, "Dave's Wetaburgers and SET Merchant" },
	{ CRYPT_CERTINFO_SET_MERCHANTCITY, IS_STRING, 0, "Eketahuna" },
	{ CRYPT_CERTINFO_SET_MERCHANTCOUNTRYNAME, IS_STRING, 0, "New Zealand" },
	{ CRYPT_CERTINFO_SET_MERCOUNTRY, IS_NUMERIC, 554 },		/* ISO 3166 */

	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

int testSETCert( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	int value, status;

	puts( "Testing SET certificate creation/export..." );

	/* Create the RSA en/decryption contexts */
	if( !loadRSAContexts( CRYPT_UNUSED, &pubKeyContext, &privKeyContext ) )
		return( FALSE );

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add some certificate components */
	status = cryptAddCertComponentNumeric( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddCertComponentNumeric() failed with error code %d, "
				"line %d\n", status, __LINE__ );
		return( FALSE );
		}
	if( !addCertFields( cryptCert, setCertData ) )
		return( FALSE );

	/* Sign the certificate.  Like the self-signed cert, we have to turn off
	   the default addition of X.509v3 components because this isn't marked
	   as a CA cert.  The cert will still be v3 because of the SET extensions,
	   it just won't be a SET CA cert */
	cryptGetOptionNumeric( CRYPT_OPTION_CERT_CREATEV3CERT, &value );
	cryptSetOptionNumeric( CRYPT_OPTION_CERT_CREATEV3CERT, FALSE );
	status = cryptSignCert( cryptCert, privKeyContext );
	cryptSetOptionNumeric( CRYPT_OPTION_CERT_CREATEV3CERT, value );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptSignCert()", status, __LINE__ ) );

	/* Print information on what we've got */
	printCertInfo( cryptCert );

	/* Export the cert */
	status = cryptExportCert( certBuffer, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptExportCert()", status, __LINE__ ) );
	printf( "Exported certificate is %d bytes long.\n", certificateLength );
	debugDump( "certset", certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptCheckCert()", status, __LINE__ ) );
	cryptDestroyCert( cryptCert );

	/* Clean up */
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	puts( "SET certificate creation succeeded.\n" );
	return( TRUE );
	}

static const CERT_DATA attributeCertData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Dave's Wetaburgers and Attributes" },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, "Attribute Management" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave's Mum" },

	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

int testAttributeCert( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT cryptAuthorityKey;
	int value, status;

	puts( "Testing attribute certificate creation/export..." );

	/* Get the authorities private key */
	status = getPrivateKey( &cryptAuthorityKey, CA_PRIVKEY_FILE,
							CA_PRIVKEY_LABEL, CA_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "Authority private key read failed with error code %d, "
				"line %d\n", status, __LINE__ );
		return( FALSE );
		}

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_CERTTYPE_ATTRIBUTE_CERT );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add some certificate components.  Note that we don't add any
	   attributes because these hadn't been defined yet (at least not as of
	   the JTC1 SC21/ITU-T Q.17/7 draft of July 1997) */
	if( !addCertFields( cryptCert, attributeCertData ) )
		return( FALSE );

	/* Sign the certificate.  Like the self-signed cert, we have to turn off
	   the default addition of X.509v3 components because this isn't marked
	   as an authority cert */
	cryptGetOptionNumeric( CRYPT_OPTION_CERT_CREATEV3CERT, &value );
	cryptSetOptionNumeric( CRYPT_OPTION_CERT_CREATEV3CERT, FALSE );
	status = cryptSignCert( cryptCert, cryptAuthorityKey );
	cryptSetOptionNumeric( CRYPT_OPTION_CERT_CREATEV3CERT, value );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptSignCert()", status, __LINE__ ) );

	/* Print information on what we've got */
	printCertInfo( cryptCert );

	/* Export the cert */
	status = cryptExportCert( certBuffer, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptExportCert()", status, __LINE__ ) );
	printf( "Exported certificate is %d bytes long.\n", certificateLength );
	debugDump( "certattr", certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, cryptAuthorityKey );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptCheckCert()", status, __LINE__ ) );
	cryptDestroyCert( cryptCert );

	/* Clean up */
	cryptDestroyContext( cryptAuthorityKey );
	puts( "Attribute certificate creation succeeded.\n" );
	return( TRUE );
	}

/* Test certification request code. Note the similarity with the certificate
   creation code, only the call to cryptCreateCert() differs */

static const CERT_DATA certRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Dave's Wetaburgers" },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, "Procurement" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave Smith" },

	{ CRYPT_ATTRIBUTE_NONE, 0, 0, NULL }
	};

int testCertRequest( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	int status;

	puts( "Testing certification request creation/export..." );

	/* Create the RSA en/decryption contexts */
	if( !loadRSAContexts( CRYPT_UNUSED, &pubKeyContext, &privKeyContext ) )
		return( FALSE );

	/* Create the certificate object */
	status = cryptCreateCert( &cryptCert, CRYPT_CERTTYPE_CERTREQUEST );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add some certification request components */
	status = cryptAddCertComponentNumeric( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddCertComponentNumeric() failed with error code %d, "
				"line %d\n", status, __LINE__ );
		return( FALSE );
		}
	if( !addCertFields( cryptCert, certRequestData ) )
		return( FALSE );

	/* Sign the certification request */
	status = cryptSignCert( cryptCert, privKeyContext );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptSignCert()", status, __LINE__ ) );

	/* Print information on what we've got */
	printCertInfo( cryptCert );

	/* Check the signature.  Since it's self-signed, we don't need to pass in
	   a signature check key */
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptCheckCert()", status, __LINE__ ) );

	/* Export the cert */
	status = cryptExportCert( certBuffer, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptExportCert()", status, __LINE__ ) );
	printf( "Exported certification request is %d bytes long.\n",
			certificateLength );
	debugDump( "certreq", certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptCheckCert()", status, __LINE__ ) );
	cryptDestroyCert( cryptCert );

	/* Clean up */
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	puts( "Certification request creation succeeded.\n" );
	return( TRUE );
	}

/* Test complex certification request code */

static const CERT_DATA complexCertRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Dave's Wetaburgers" },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, "Procurement" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave Smith" },

	/* Subject altName */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, "dave@wetas-r-us.com" },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, "http://www.wetas-r-us.com" },

	/* SSL server and client authentication */
	{ CRYPT_CERTINFO_EXTKEY_SERVERAUTH, IS_NUMERIC, CRYPT_UNUSED },
	{ CRYPT_CERTINFO_EXTKEY_CLIENTAUTH, IS_NUMERIC, CRYPT_UNUSED },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

int testComplexCertRequest( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	int status;

	puts( "Testing complex certification request creation/export..." );

	/* Create the RSA en/decryption contexts */
	if( !loadRSAContexts( CRYPT_UNUSED, &pubKeyContext, &privKeyContext ) )
		return( FALSE );

	/* Create the certificate object */
	status = cryptCreateCert( &cryptCert, CRYPT_CERTTYPE_CERTREQUEST );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add some certification request components */
	status = cryptAddCertComponentNumeric( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddCertComponentNumeric() failed with error code %d, "
				"line %d\n", status, __LINE__ );
		return( FALSE );
		}
	if( !addCertFields( cryptCert, complexCertRequestData ) )
		return( FALSE );

	/* Sign the certification request */
	status = cryptSignCert( cryptCert, privKeyContext );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptSignCert()", status, __LINE__ ) );

	/* Check the signature.  Since it's self-signed, we don't need to pass in
	   a signature check key */
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptCheckCert()", status, __LINE__ ) );

	/* Print information on what we've got */
	printCertInfo( cryptCert );

	/* Export the cert */
	status = cryptExportCert( certBuffer, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptExportCert()", status, __LINE__ ) );
	printf( "Exported certification request is %d bytes long.\n",
			certificateLength );
	debugDump( "certreqc", certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptCheckCert()", status, __LINE__ ) );
	cryptDestroyCert( cryptCert );

	/* Clean up */
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	puts( "Complex certification request creation succeeded.\n" );
	return( TRUE );
	}

/* Test CRMF certification request code */

int testCRMFRequest( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	int status;

	puts( "Testing CRMF certification request creation/export..." );

	/* Create the RSA en/decryption contexts */
	if( !loadRSAContexts( CRYPT_UNUSED, &pubKeyContext, &privKeyContext ) )
		return( FALSE );

	/* Create the certificate object */
	status = cryptCreateCert( &cryptCert, CRYPT_CERTTYPE_CRMF_REQUEST );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add some certification request components */
	status = cryptAddCertComponentNumeric( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddCertComponentNumeric() failed with error code %d, "
				"line %d\n", status, __LINE__ );
		return( FALSE );
		}
	if( !addCertFields( cryptCert, certRequestData ) )
		return( FALSE );

	/* Sign the certification request */
	status = cryptSignCert( cryptCert, privKeyContext );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptSignCert()", status, __LINE__ ) );

	/* Print information on what we've got */
	printCertInfo( cryptCert );

	/* Check the signature.  Since it's self-signed, we don't need to pass in
	   a signature check key */
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptCheckCert()", status, __LINE__ ) );

	/* Export the cert */
	status = cryptExportCert( certBuffer, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptExportCert()", status, __LINE__ ) );
	printf( "Exported certification request is %d bytes long.\n",
			certificateLength );
	debugDump( "crmfreq", certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptCheckCert()", status, __LINE__ ) );
	cryptDestroyCert( cryptCert );

	/* Clean up */
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	puts( "CRMF certification request creation succeeded.\n" );
	return( TRUE );
	}

int testComplexCRMFRequest( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	int status;

	puts( "Testing complex CRMF certification request creation/export..." );

	/* Create the RSA en/decryption contexts */
	if( !loadRSAContexts( CRYPT_UNUSED, &pubKeyContext, &privKeyContext ) )
		return( FALSE );

	/* Create the certificate object */
	status = cryptCreateCert( &cryptCert, CRYPT_CERTTYPE_CRMF_REQUEST );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add some certification request components */
	status = cryptAddCertComponentNumeric( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddCertComponentNumeric() failed with error code %d, "
				"line %d\n", status, __LINE__ );
		return( FALSE );
		}
	if( !addCertFields( cryptCert, complexCertRequestData ) )
		return( FALSE );

	/* Sign the certification request */
	status = cryptSignCert( cryptCert, privKeyContext );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptSignCert()", status, __LINE__ ) );

	/* Check the signature.  Since it's self-signed, we don't need to pass in
	   a signature check key */
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptCheckCert()", status, __LINE__ ) );

	/* Print information on what we've got */
	printCertInfo( cryptCert );

	/* Export the cert */
	status = cryptExportCert( certBuffer, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptExportCert()", status, __LINE__ ) );
	printf( "Exported certification request is %d bytes long.\n",
			certificateLength );
	debugDump( "crmfreqc", certBuffer, certificateLength );

	/* Destroy the certificate */
	status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptCheckCert()", status, __LINE__ ) );
	cryptDestroyCert( cryptCert );

	/* Clean up */
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	puts( "Complex CRMF certification request creation succeeded.\n" );
	return( TRUE );
	}

/* Test CRL code.  This one represents a bit of a chicken-and-egg problem
   since we need a CA cert to create the CRL, but we can't read this until
   the private key file read has been tested, and that requires testing of
   the cert management.  At the moment we just assume that private key file
   reads work for this test */

int testCRL( void )
	{
	CRYPT_CERTIFICATE cryptCRL;
	CRYPT_CONTEXT cryptCAKey;
	int status;

	puts( "Testing CRL creation/export..." );

	/* Get the CA's private key */
	status = getPrivateKey( &cryptCAKey, CA_PRIVKEY_FILE,
							CA_PRIVKEY_LABEL, CA_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "CA private key read failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Create the CRL */
	status = cryptCreateCert( &cryptCRL, CRYPT_CERTTYPE_CRL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add some CRL components.  In this case the CA is revoking its own
	   key */
	status = cryptAddCertComponentNumeric( cryptCRL,
					CRYPT_CERTINFO_USERCERTIFICATE, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddCertComponentNumeric() failed with error code %d, "
				"line %d\n", status, __LINE__ );
		return( FALSE );
		}

	/* Sign the CRL */
	status = cryptSignCert( cryptCRL, cryptCAKey );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCRL, "cryptSignCert()", status, __LINE__ ) );

	/* Print information on what we've got */
	printCertInfo( cryptCRL );

	/* Check the signature.  Since we have the CA private key handy, we
	   use that to check the signature */
	status = cryptCheckCert( cryptCRL, cryptCAKey );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCRL, "cryptCheckCert()", status, __LINE__ ) );

	/* Export the CRL */
	status = cryptExportCert( certBuffer, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCRL );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCRL, "cryptExportCert()", status, __LINE__ ) );
	printf( "Exported CRL is %d bytes long.\n", certificateLength );
	debugDump( "crl", certBuffer, certificateLength );

	/* Destroy the CRL */
	status = cryptDestroyCert( cryptCRL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, &cryptCRL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCRL, cryptCAKey );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCRL, "cryptCheckCert()", status, __LINE__ ) );
	cryptDestroyCert( cryptCRL );
	cryptDestroyContext( cryptCAKey );

	/* Clean up */
	puts( "CRL creation succeeded.\n" );
	return( TRUE );
	}

/* Test complex CRL code */

static const CERT_DATA complexCRLData[] = {
	/* Next update time */
	{ CRYPT_CERTINFO_NEXTUPDATE, IS_TIME, 0, NULL, 0x42000000L },

	/* CRL number and delta CRL indicator */
	{ CRYPT_CERTINFO_CRLNUMBER, IS_NUMERIC, 1 },
	{ CRYPT_CERTINFO_DELTACRLINDICATOR, IS_NUMERIC, 2 },

	/* Issuing distribution points.  Note the two-stage selection process,
	   first we select the GeneralName with
	   CRYPT_CERTINFO_ISSUINGDIST_FULLNAME, then we access the URI in the
	   GeneralName with CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER */
	{ CRYPT_CERTINFO_ISSUINGDIST_FULLNAME, IS_NUMERIC, CRYPT_UNUSED },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, "http://www.wetas-r-us.com" },
	{ CRYPT_CERTINFO_ISSUINGDIST_USERCERTSONLY, IS_NUMERIC, TRUE },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

int testComplexCRL( void )
	{
	CRYPT_CERTIFICATE cryptCRL, cryptRevokeCert;
	CRYPT_CONTEXT cryptCAKey;
	int status;

	puts( "Testing complex CRL creation/export..." );

	/* Get the CA's private key */
	status = getPrivateKey( &cryptCAKey, CA_PRIVKEY_FILE,
							CA_PRIVKEY_LABEL, CA_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "CA private key read failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Create the CRL */
	status = cryptCreateCert( &cryptCRL, CRYPT_CERTTYPE_CRL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add some CRL components with per-entry attributes.  In this case the
	   CA is revoking its own key because it was compromised (would you trust
	   this CRL?) and some keys from test certs */
	if( !addCertFields( cryptCRL, complexCRLData ) )
		return( FALSE );
	status = cryptAddCertComponentNumeric( cryptCRL,
					CRYPT_CERTINFO_USERCERTIFICATE, cryptCAKey );
	if( cryptStatusOK( status ) )
		/* The CA key was compromised */
		status = cryptAddCertComponentNumeric( cryptCRL,
					CRYPT_CERTINFO_CRLREASON, CRYPT_CRLREASON_CACOMPROMISE );
	if( cryptStatusOK( status ) )
		status = importCertFile( &cryptRevokeCert, CRLCERT1_FILE );
	if( cryptStatusOK( status ) )
		{
		status = cryptAddCertComponentNumeric( cryptCRL,
					CRYPT_CERTINFO_USERCERTIFICATE, cryptRevokeCert );
		cryptDestroyCert( cryptRevokeCert );
		}
	if( cryptStatusOK( status ) )
		{
		/* Hold cert, call issuer for details */
		status = cryptAddCertComponentNumeric( cryptCRL,
					CRYPT_CERTINFO_CRLREASON, CRYPT_CRLREASON_CERTIFICATEHOLD );
		if( cryptStatusOK( status ) )
			status = cryptAddCertComponentNumeric( cryptCRL,
					CRYPT_CERTINFO_HOLDINSTRUCTIONCODE, CRYPT_HOLDINSTRUCTION_CALLISSUER );
		}
	if( cryptStatusOK( status ) )
		status = importCertFile( &cryptRevokeCert, CRLCERT2_FILE );
	if( cryptStatusOK( status ) )
		{
		status = cryptAddCertComponentNumeric( cryptCRL,
					CRYPT_CERTINFO_USERCERTIFICATE, cryptRevokeCert );
		cryptDestroyCert( cryptRevokeCert );
		}
	if( cryptStatusOK( status ) )
		{
		const time_t invalidityDate = 0x2C000000L;

		/* The private key was invalid ages ago */
		status = cryptAddCertComponentString( cryptCRL,
					CRYPT_CERTINFO_INVALIDITYDATE, &invalidityDate,
					sizeof( time_t ) );
		}
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddCertComponentNumeric() failed with error code %d, "
				"line %d\n", status, __LINE__ );
		return( FALSE );
		}

	/* Sign the CRL */
	status = cryptSignCert( cryptCRL, cryptCAKey );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCRL, "cryptSignCert()", status, __LINE__ ) );

	/* Print information on what we've got */
	printCertInfo( cryptCRL );

	/* Check the signature.  Since we have the CA private key handy, we
	   use that to check the signature */
	status = cryptCheckCert( cryptCRL, cryptCAKey );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCRL, "cryptCheckCert()", status, __LINE__ ) );

	/* Export the CRL */
	status = cryptExportCert( certBuffer, &certificateLength,
							  CRYPT_CERTFORMAT_CERTIFICATE, cryptCRL );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCRL, "cryptExportCert()", status, __LINE__ ) );
	printf( "Exported CRL is %d bytes long.\n", certificateLength );
	debugDump( "crlc", certBuffer, certificateLength );

	/* Destroy the CRL */
	status = cryptDestroyCert( cryptCRL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, &cryptCRL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCRL, cryptCAKey );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCRL, "cryptCheckCert()", status, __LINE__ ) );

	/* Check the newly-revoked CA key agains the CRL */
	status = cryptCheckCert( cryptCAKey, cryptCRL );
	if( status != CRYPT_ERROR_INVALID )
		{
		printf( "Revoked cert wasn't reported as being revoked, line %d\n",
				__LINE__ );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyCert( cryptCRL );
	cryptDestroyContext( cryptCAKey );
	puts( "CRL creation succeeded.\n" );
	return( TRUE );
	}

/* Test cert chain creation */

int testCertChain( void )
	{
	CRYPT_CERTIFICATE cryptCertChain, cryptCertRequest;
	CRYPT_CONTEXT pubKeyContext, privKeyContext;
	CRYPT_CONTEXT cryptCAKey;
	int value, status;

	puts( "Testing certificate chain creation/export..." );

	/* Get the CA's private key */
	status = getPrivateKey( &cryptCAKey, CA_PRIVKEY_FILE,
							CA_PRIVKEY_LABEL, CA_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "CA private key read failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Create the cert chain */
	status = cryptCreateCert( &cryptCertChain, CRYPT_CERTTYPE_CERTCHAIN );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Create a simple cert request to turn into the end-user cert */
	if( !loadRSAContexts( CRYPT_UNUSED, &pubKeyContext, &privKeyContext ) )
		return( FALSE );
	status = cryptCreateCert( &cryptCertRequest, CRYPT_CERTTYPE_CERTREQUEST );
	if( cryptStatusOK( status ) )
		status = cryptAddCertComponentNumeric( cryptCertRequest,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, pubKeyContext );
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptCertRequest, certRequestData ) )
		return( FALSE );
	destroyContexts( CRYPT_UNUSED, pubKeyContext, privKeyContext );
	if( cryptStatusError( status ) )
		{
		printf( "Certificate creation failed, line %d\n", status, __LINE__ );
		return( FALSE );
		}

	/* Add the end-user cert to the chain */
	status = cryptAddCertComponentNumeric( cryptCertChain,
					CRYPT_CERTINFO_CERTREQUEST, cryptCertRequest );
	if( cryptStatusError( status ) )
		{
		printf( "cryptAddCertComponentNumeric() failed with error code %d, "
				"line %d\n", status, __LINE__ );
		return( FALSE );
		}
	cryptDestroyCert( cryptCertRequest );

	/* Sign the cert chain */
	status = cryptSignCert( cryptCertChain, cryptCAKey );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCertChain, "cryptSignCert()", status,
						   __LINE__ ) );

	/* Check the signature.  Since the chain counts as self-signed, we don't
	   need to supply a sig.check key.  Since the DIY CA cert isn't trusted,
	   we have to force cryptlib to treat it as explicitly trusted when we 
	   try to verify the chain */
	cryptGetOptionNumeric( CRYPT_OPTION_CERT_TRUSTCHAINROOT, &value );
	cryptSetOptionNumeric( CRYPT_OPTION_CERT_TRUSTCHAINROOT, 1 );
	status = cryptCheckCert( cryptCertChain, CRYPT_UNUSED );
	cryptSetOptionNumeric( CRYPT_OPTION_CERT_TRUSTCHAINROOT, value );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCertChain, "cryptCheckCert()", status,
						   __LINE__ ) );

	/* Try the other way of verifying the chain, by making the signing key
	   implicitly trusted */
	cryptAddCertComponentNumeric( cryptCAKey, CRYPT_CERTINFO_TRUSTED_IMPLICIT, 
								  TRUE );
	status = cryptCheckCert( cryptCertChain, CRYPT_UNUSED );
	cryptAddCertComponentNumeric( cryptCAKey, CRYPT_CERTINFO_TRUSTED_IMPLICIT, 
								  FALSE );
	cryptDestroyContext( cryptCAKey );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCertChain, "cryptCheckCert()", status,
						   __LINE__ ) );

	/* Export the cert chain */
	status = cryptExportCert( certBuffer, &certificateLength,
							  CRYPT_CERTFORMAT_CERTCHAIN, cryptCertChain );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCertChain, "cryptExportCert()", status,
						   __LINE__ ) );
	printf( "Exported cert chain is %d bytes long.\n", certificateLength );
	debugDump( "certchn", certBuffer, certificateLength );

	/* Destroy the cert chain */
	status = cryptDestroyCert( cryptCertChain );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Make sure we can read what we created */
	status = cryptImportCert( certBuffer, certificateLength, &cryptCertChain );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "Checking signatures... " );
	cryptGetOptionNumeric( CRYPT_OPTION_CERT_TRUSTCHAINROOT, &value );
	cryptSetOptionNumeric( CRYPT_OPTION_CERT_TRUSTCHAINROOT, 1 );
	status = cryptCheckCert( cryptCertChain, CRYPT_UNUSED );
	cryptSetOptionNumeric( CRYPT_OPTION_CERT_TRUSTCHAINROOT, value );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCertChain, "cryptCheckCert()", status,
						   __LINE__ ) );
	puts( "signatures verified." );

	/* Display info on each cert in the chain */
	printCertChainInfo( cryptCertChain );

	/* Clean up */
	cryptDestroyCert( cryptCertChain );
	puts( "Certificate chain creation succeeded.\n" );
	return( TRUE );
	}

/* Test CMS attribute code.  This doesn't actually test much since this
   object type is just a basic data container used for the extended signing
   functions */

static const CERT_DATA cmsAttributeData[] = {
	/* Content type and an S/MIME capability */
	{ CRYPT_CERTINFO_CMS_CONTENTTYPE, IS_NUMERIC, CRYPT_CONTENT_SIGNEDDATA },
	{ CRYPT_CERTINFO_CMS_SMIMECAP_PREFERSIGNEDDATA, IS_NUMERIC, CRYPT_UNUSED },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

int testCMSAttributes( void )
	{
	CRYPT_CERTIFICATE cryptAttributes;
	int status;

	puts( "Testing CMS attribute creation..." );

	/* Create the CMS attribute container */
	status = cryptCreateCert( &cryptAttributes, CRYPT_CERTTYPE_CMS_ATTRIBUTES );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Add some CMS attribute components */
	if( !addCertFields( cryptAttributes, cmsAttributeData ) )
		return( FALSE );

	/* Print information on what we've got */
	printCertInfo( cryptAttributes );

	/* Destroy the attributes.  We can't do much more than this at this
	   stage since the attributes are only used internally by other
	   functions */
	status = cryptDestroyCert( cryptAttributes );
	if( cryptStatusError( status ) )
		{
		printf( "cryptDestroyCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	puts( "CMS attribute creation succeeded.\n" );
	return( TRUE );
	}

/****************************************************************************
*																			*
*							Certificate Import Routines Test				*
*																			*
****************************************************************************/

/* Test certificate/certificate request/cert chain import code */

int testCertImport( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int count, value, status;

	if( ( filePtr = fopen( CERT_FILE, "rb" ) ) == NULL )
		{
		puts( "Couldn't find certificate file, skipping test of certificate "
			  "import..." );
		return( TRUE );
		}
	puts( "Testing certificate import..." );
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
	printf( "Certificate has size %d bytes.\n", count );

	/* Import the certificate */
	status = cryptImportCert( buffer, count, &cryptCert );
	if( status == CRYPT_ERROR_NOTAVAIL || status == CRYPT_ERROR_BADDATA )
		{
		puts( "The certificate import failed, probably because you're "
			  "using an\nolder version of unzip which corrupts "
			  "certain types of files when it\nextracts them.  To fix this, "
			  "you need to re-extract test/*.der without\nusing the -a "
			  "option to convert text files.\n" );
		return( TRUE );		/* Skip this test and continue */
		}
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptGetCertComponentNumeric( cryptCert, CRYPT_CERTINFO_SELFSIGNED,
										   &value );
	if( cryptStatusError( status ) )
		{
		/* Sanity check to make sure the cert internal state is consistent -
		   this should never happen */
		printf( "Couldn't get cert.self-signed status, line %d\n", status, 
				__LINE__ );
		return( FALSE );
		}
	if( value )
		{
		printf( "Certificate is self-signed, checking signature... " );
		status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
		if( cryptStatusError( status ) )
			{
			putchar( '\n' );
			return( errorExit( cryptCert, "cryptCheckCert()", status, __LINE__ ) );
			}
		puts( "signature verified." );
		}
	else
		puts( "Certificate is signed, signature key unknown." );

	/* Print information on what we've got */
	printCertInfo( cryptCert );

	/* Clean up */
	cryptDestroyCert( cryptCert );
	puts( "Certificate import succeeded.\n" );
	return( TRUE );
	}

int testCertReqImport( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int count, status;

	if( ( filePtr = fopen( CERTREQ_FILE, "rb" ) ) == NULL )
		{
		puts( "Couldn't find certificate request file, skipping test of "
			  "certificate request\nimport..." );
		return( TRUE );
		}
	puts( "Testing certificate request import..." );
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
	printf( "Certificate request has size %d bytes.\n", count );

	/* Import the certificate request and check that the signature is valid */
	status = cryptImportCert( buffer, count, &cryptCert );
	if( status == CRYPT_ERROR_NOTAVAIL || status == CRYPT_ERROR_BADDATA )
		{
		puts( "The certificate request import failed, probably because "
			  "you're using an\nolder version of unzip which corrupts "
			  "certain types of files when it\nextracts them.  To fix this, "
			  "you need to re-extract test/*.der without\nusing the -a "
			  "option to convert text files.\n" );
		return( TRUE );		/* Skip this test and continue */
		}
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "Checking signature... " );
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptCheckCert()", status, __LINE__ ) );
	puts( "signature verified." );

	/* Print information on what we've got */
	printCertInfo( cryptCert );

	/* Clean up */
	cryptDestroyCert( cryptCert );
	puts( "Certificate request import succeeded.\n" );
	return( TRUE );
	}

int testCRLImport( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int count, status;

	if( ( filePtr = fopen( CRL_FILE, "rb" ) ) == NULL )
		{
		puts( "Couldn't find CRL, skipping test of CRL import..." );
		return( TRUE );
		}
	puts( "Testing CRL import..." );
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
	printf( "CRL has size %d bytes.\n", count );

	/* Import the CRL.  Since CRL's don't include the signing cert, we can't
	   (easily) check the signature on it */
	status = cryptImportCert( buffer, count, &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Print information on what we've got */
	printCertInfo( cryptCert );

	/* Clean up */
	cryptDestroyCert( cryptCert );
	puts( "CRL import succeeded.\n" );
	return( TRUE );
	}

int testCertChainImport( void )
	{
	CRYPT_CERTIFICATE cryptCertChain;
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int count, status;

	if( ( filePtr = fopen( CERTCHAIN_FILE, "rb" ) ) == NULL )
		{
		puts( "Couldn't find certificate chain file, skipping test of "
			  "certificate import..." );
		return( TRUE );		/* Skip this test and continue */
		}
	puts( "Testing certificate chain import..." );
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
	if( count == BUFFER_SIZE )
		{
		puts( "The certificate buffer size is too small for the certificate "
			  "chain.  To fix\nthis, increase the BUFFER_SIZE value in "
			  "test/testcert.c and recompile the code." );
		return( TRUE );		/* Skip this test and continue */
		}
	printf( "Certificate chain has size %d bytes.\n", count );

	/* Import the certificate chain.  This assumes that the default certs are
	   installed as trusted certs, which is required for cryptCheckCert() */
	status = cryptImportCert( buffer, count, &cryptCertChain );
	if( status == CRYPT_ERROR_NOTAVAIL || status == CRYPT_ERROR_BADDATA )
		{
		puts( "The certificate chain import failed, probably because you're "
			  "using an\nolder version of unzip which corrupts "
			  "certain types of files when it\nextracts them.  To fix this, "
			  "you need to re-extract test/*.der without\nusing the -a "
			  "option to convert text files.\n" );
		return( TRUE );		/* Skip this test and continue */
		}
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "Checking signatures... " );
	status = cryptCheckCert( cryptCertChain, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		/* The error should be CRYPT_INVALID which will have occured 
		   because the default certs aren't installed.  Complain but
		   continue anyway */
		puts( "\nThe certificate chain didn't verify, this is probably "
			  "because you haven't\ninstalled the default CA "
			  "certificates using the 'certinst' utility as\ndescribed "
			  "in the manual.  Continuing with the unverified chain..." );
	else
		puts( "signatures verified." );

	/* Display info on each cert in the chain */
	printCertChainInfo( cryptCertChain );

	/* Clean up */
	cryptDestroyCert( cryptCertChain );
	puts( "Certificate chain import succeeded.\n" );
	return( TRUE );
	}

int testSPKACImport( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int count, status;

	if( ( filePtr = fopen( SPKAC_FILE, "rb" ) ) == NULL )
		{
		puts( "Couldn't find SignedPublicKeyAndChallenge file, skipping "
			  "test of SPKAC\nimport..." );
		return( TRUE );
		}
	puts( "Testing SignedPublicKeyAndChallenge import..." );
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
	printf( "SPKAC has size %d bytes.\n", count );

	/* Import the SPKAC and check that the signature is valid */
	status = cryptImportCert( buffer, count, &cryptCert );
	if( status == CRYPT_ERROR_NOTAVAIL || status == CRYPT_ERROR_BADDATA )
		{
		puts( "The SPKAC import failed, probably because you're using an "
			  "older version of\nunzip which corrupts certain types of "
			  "files when it extracts them.  To fix\nthis, you need to "
			  "re-extract test/*.der without using the -a option to\n"
			  "convert text files.\n" );
		return( TRUE );		/* Skip this test and continue */
		}
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "Checking signature... " );
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( errorExit( cryptCert, "cryptCheckCert()", status, __LINE__ ) );
	puts( "signature verified." );

	/* Print information on what we've got */
	printCertInfo( cryptCert );

	/* Clean up */
	cryptDestroyCert( cryptCert );
	puts( "SPKAC import succeeded.\n" );
	return( TRUE );
	}

/****************************************************************************
*																			*
*							Certificate Processing Test						*
*																			*
****************************************************************************/

static const CERT_DATA certProcessData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, "NZ" },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, "Dave's Wetaburgers" },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, "Procurement" },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, "Dave Smith" },

	/* Subject altName */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, "dave@wetas-r-us.com" },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, "http://www.wetas-r-us.com" },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

/* Create a certification request */

static int createCertRequest( void *certRequest, const CRYPT_ALGO cryptAlgo )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT cryptContext;
	int length, status;

	/* Create a new key */
	cryptCreateContext( &cryptContext, cryptAlgo, CRYPT_MODE_PKC );
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL, 
							 "Private key", 11 );
	status = cryptGenerateKeyEx( cryptContext, 64 );
	if( cryptStatusError( status ) )
		return( status );

	/* Create the certification request */
	status = cryptCreateCert( &cryptCert, CRYPT_CERTTYPE_CERTREQUEST );
	if( cryptStatusError( status ) )
		return( status );
	status = cryptAddCertComponentNumeric( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
	if( cryptStatusError( status ) )
		return( status );
	if( !addCertFields( cryptCert, complexCertRequestData ) )
		return( -1 );
	status = cryptSignCert( cryptCert, cryptContext );
	if( cryptStatusOK( status ) )
		status = cryptExportCert( certRequest, &length,
								  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusOK( status ) )
		status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		return( status );

	/* Clean up */
	cryptDestroyContext( cryptContext );
	return( length );
	}

/* Create a certificate from a cert request */

static int createCertificate( void *certificate, const void *certRequest,
							  const int certReqLength, 
							  const CRYPT_CONTEXT caKeyContext )
	{
	CRYPT_CERTIFICATE cryptCert, cryptCertRequest;
	int length, status;

	/* Import and verify the certification request */
	status = cryptImportCert( certRequest, certReqLength, &cryptCertRequest );
	if( cryptStatusOK( status ) )
		status = cryptCheckCert( cryptCertRequest, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( status );

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	status = cryptAddCertComponentNumeric( cryptCert,
					CRYPT_CERTINFO_CERTREQUEST, cryptCertRequest );
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCert, caKeyContext );
	if( cryptStatusOK( status ) )
		status = cryptExportCert( certificate, &length,
								  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusOK( status ) )
		status = cryptDestroyCert( cryptCert );

	/* Clean up */
	cryptDestroyCert( cryptCertRequest );
	return( ( cryptStatusOK( status ) ) ? length : status );
	}

/* Create a certificate directly, used for algorithms which don't support 
   self-signed cert requests */

static int createCertDirect( void *certificate, const CRYPT_ALGO cryptAlgo,
							 const CRYPT_CONTEXT caKeyContext )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT cryptContext;
	int length, status;

	/* Create a new key */
	cryptCreateContext( &cryptContext, cryptAlgo, CRYPT_MODE_PKC );
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL, 
							 "Private key", 11 );
	status = cryptGenerateKeyEx( cryptContext, 64 );
	if( cryptStatusError( status ) )
		return( status );

	/* Create the certification */
	status = cryptCreateCert( &cryptCert, CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	status = cryptAddCertComponentNumeric( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
	if( cryptStatusError( status ) )
		return( status );
	if( !addCertFields( cryptCert, certProcessData ) )
		return( FALSE );
	status = cryptSignCert( cryptCert, caKeyContext );
	if( cryptStatusOK( status ) )
		status = cryptExportCert( certificate, &length,
								  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusOK( status ) )
		status = cryptDestroyCert( cryptCert );

	/* Clean up */
	cryptDestroyContext( cryptContext );
	return( ( cryptStatusOK( status ) ) ? length : status );
	}

/* Test the full certification process */

static int certProcess( const CRYPT_ALGO cryptAlgo,
						const char *algoName, 
						const CRYPT_CONTEXT cryptCAKey )
	{
	CRYPT_CERTIFICATE cryptCert;
	const char *certName = \
			( cryptAlgo == CRYPT_ALGO_RSA ) ? "prcrtrsa" : \
			( cryptAlgo == CRYPT_ALGO_DSA ) ? "prcrtdsa" : \
			( cryptAlgo == CRYPT_ALGO_DH ) ? "prcrtdh" : \
			( cryptAlgo == CRYPT_ALGO_ELGAMAL ) ? "prcrtelg" : "prcrtxxx";
	int length, status;

	printf( "Testing %s certificate processing...\n", algoName );

	/* Some algorithms can't create self-signed cert requests so we have to
	   create the cert directly */
	if( cryptAlgo != CRYPT_ALGO_DH )
		{
		const char *reqName = \
			( cryptAlgo == CRYPT_ALGO_RSA ) ? "prreqrsa" : \
			( cryptAlgo == CRYPT_ALGO_DSA ) ? "prreqdsa" : \
			( cryptAlgo == CRYPT_ALGO_DH ) ? "prreqdh" : \
			( cryptAlgo == CRYPT_ALGO_ELGAMAL ) ? "prreqelg" : "prreqxxx";

		/* Create the certification request */
		status = length = createCertRequest( certBuffer, cryptAlgo );
		if( cryptStatusError( status ) )
			{
			printf( "Certification request creation failed with error code "
					"%d, line %d\n", status, __LINE__ );
			return( FALSE );
			}
		debugDump( reqName, certBuffer, length );

		/* Create a certificate from the certification request */
		status = createCertificate( certBuffer, certBuffer, length, 
									cryptCAKey );
		}
	else
		status = createCertDirect( certBuffer, cryptAlgo, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		printf( "Certificate creation failed with error code %d, line "
				"%d\n", status, __LINE__ );
		return( FALSE );
		}
	length = status;
	debugDump( certName, certBuffer, length );

	/* Import the certificate and check its validity using the CA key (we use
	   the private key context since it's handy, in practice we should use
	   the public key certificate */
	status = cryptImportCert( certBuffer, length, &cryptCert );
	if( cryptStatusOK( status ) )
		status = cryptCheckCert( cryptCert, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		printf( "Certificate validation failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyCert( cryptCert );
	printf( "%s certificate processing succeeded.\n\n", algoName );
	return( TRUE );
	}

int testCertProcess( void )
	{
	CRYPT_CONTEXT cryptCAKey;
	int status;

	/* Get the CA's private key */
	status = getPrivateKey( &cryptCAKey, CA_PRIVKEY_FILE,
							CA_PRIVKEY_LABEL, CA_PRIVKEY_PASSWORD ); 
	if( cryptStatusError( status ) )
		{
		printf( "CA private key read failed with error code %d, line %d\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Test each PKC algorithm */
	if( !certProcess( CRYPT_ALGO_RSA, "RSA", cryptCAKey ) )
		return( FALSE );
	if( !certProcess( CRYPT_ALGO_DSA, "DSA", cryptCAKey ) )
		return( FALSE );
	if( !certProcess( CRYPT_ALGO_ELGAMAL, "Elgamal", cryptCAKey ) )
		return( FALSE );
	if( !certProcess( CRYPT_ALGO_DH, "Diffie-Hellman", cryptCAKey ) )
		return( FALSE );

	/* Clean up */
	cryptDestroyContext( cryptCAKey );
	return( TRUE );
	}
