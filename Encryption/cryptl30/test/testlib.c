/****************************************************************************
*																			*
*								cryptlib Test Code							*
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
#endif /* Braindamaged VC++ include handling */

/* The size of the test buffers */

#define TESTBUFFER_SIZE		256

/* Prototypes for functions in testhl.c */

int testLargeBufferEncrypt( void );
int testDeriveKey( void );
int testRandomRoutines( void );
int testConventionalExportImport( void );
int testMACExportImport( void );
int testKeyExportImport( void );
int testSignData( void );
int testKeyAgreement( void );
int testKeygen( void );
int testKeygenAsync( void );
int testKeyExportImportCMS( void );
int testSignDataCMS( void );
int testDevices( void );

/* Prototypes for functions in testkey.c */

int testGetPGPPublicKey( void );
int testGetPGPPrivateKey( void );
int testGetBorkenKey( void );
int testReadWriteFileKey( void );
int testReadFilePublicKey( void );
int testAddTrustedCert( void );
int testDeleteFileKey( void );
int testChangeFileKeyPassword( void );
int testUpdateFileCert( void );
int testWriteFileCertChain( void );
int testReadFileCert( void );
int testReadFileCertChain( void );
int testSingleStepFileCert( void );
int testWriteCardKey( void );
int testReadCardKey( void );
int testWriteCert( void );
int testReadCert( void );
int testKeysetQuery( void );
int testWriteCertLDAP( void );
int testReadCertLDAP( void );
int testReadCertHTTP( void );

/* Prototypes for functions in testenv.c.  Data and SessionCrypt and both
   CMS and cryptlib, the remainder are either cryptlib or CMS */

int testEnvelopeData( void );
int testLargeBufferEnvelopeData( void );
int testEnvelopeCompress( void );
int testEnvelopeSessionCrypt( void );
int testEnvelopeCrypt( void );
int testEnvelopePKCCrypt( void );
int testEnvelopeSign( void );
int testCMSEnvelopePKCCrypt( void );
int testCMSEnvelopeSign( void );
int testCMSEnvelopeDetachedSig( void );
int testCMSImportSignedData( void );

/* Prototypes for functions in testcert.c */

int testCert( void );
int testCACert( void );
int testComplexCert( void );
int testSETCert( void );
int testAttributeCert( void );
int testCRL( void );
int testComplexCRL( void );
int testCertChain( void );
int testCertRequest( void );
int testComplexCertRequest( void );
int testCRMFRequest( void );
int testComplexCRMFRequest( void );
int testCMSAttributes( void );
int testCertImport( void );
int testCertReqImport( void );
int testCRLImport( void );
int testCertChainImport( void );
int testSPKACImport( void );
int testCertProcess( void );

/* Prototypes for functions in testsess.c */

int testSessionSSH( void );
int testSessionSSL( void );
int testSessionTLS( void );

/* Whether the PKC read in testhl.c worked - used later to test other
   routines.  We initially set it to TRUE in case the keyset read tests are
   never called, so we can still trying reading the keys in other tests */

int keyReadOK = TRUE;

/* The keys for testing the RSA, DSA, and Elgamal implementations. These are
   the same 512-bit keys as the one used for the lib_xxx.c self-tests */

typedef struct {
	const int nLen; const BYTE n[ 96 ];
	const int eLen; const BYTE e[ 3 ];
	const int dLen; const BYTE d[ 96 ];
	const int pLen; const BYTE p[ 48 ];
	const int qLen; const BYTE q[ 48 ];
	const int uLen; const BYTE u[ 48 ];
	const int e1Len; const BYTE e1[ 48 ];
	const int e2Len; const BYTE e2[ 48 ];
	} RSA_KEY;

static const RSA_KEY rsa512TestKey = {
	/* n */
	512,
	{ 0xE1, 0x95, 0x41, 0x17, 0xB4, 0xCB, 0xDC, 0xD0,
	  0xCB, 0x9B, 0x11, 0x19, 0x9C, 0xED, 0x04, 0x6F,
	  0xBD, 0x70, 0x2D, 0x5C, 0x8A, 0x32, 0xFF, 0x16,
	  0x22, 0x57, 0x30, 0x3B, 0xD4, 0x59, 0x9C, 0x01,
	  0xF0, 0xA3, 0x70, 0xA1, 0x6C, 0x16, 0xAC, 0xCC,
	  0x8C, 0xAD, 0xB0, 0xA0, 0xAF, 0xC7, 0xCC, 0x49,
	  0x4F, 0xD9, 0x5D, 0x32, 0x1C, 0x2A, 0xE8, 0x4E,
	  0x15, 0xE1, 0x26, 0x6C, 0xC4, 0xB8, 0x94, 0xE1 },
	/* e */
	5,
	{ 0x11 },
	/* d */
	509,
	{ 0x13, 0xE7, 0x85, 0xBE, 0x53, 0xB7, 0xA2, 0x8A,
	  0xE4, 0xC9, 0xEA, 0xEB, 0xAB, 0xF6, 0xCB, 0xAF,
	  0x81, 0xA8, 0x04, 0x00, 0xA2, 0xC8, 0x43, 0xAF,
	  0x21, 0x25, 0xCF, 0x8C, 0xCE, 0xF8, 0xD9, 0x0F,
	  0x10, 0x78, 0x4C, 0x1A, 0x26, 0x5D, 0x90, 0x18,
	  0x79, 0x90, 0x42, 0x83, 0x6E, 0xAE, 0x3E, 0x20,
	  0x0B, 0x0C, 0x5B, 0x6B, 0x8E, 0x31, 0xE5, 0xCF,
	  0xD6, 0xE0, 0xBB, 0x41, 0xC1, 0xB8, 0x2E, 0x17 },
	/* p */
	256,
	{ 0xED, 0xE4, 0x02, 0x90, 0xA4, 0xA4, 0x98, 0x0D,
	  0x45, 0xA2, 0xF3, 0x96, 0x09, 0xED, 0x7B, 0x40,
	  0xCD, 0xF6, 0x21, 0xCC, 0xC0, 0x1F, 0x83, 0x09,
	  0x56, 0x37, 0x97, 0xFB, 0x05, 0x5B, 0x87, 0xB7 },
	/* q */
	256,
	{ 0xF2, 0xC1, 0x64, 0xE8, 0x69, 0xF8, 0x5E, 0x54,
	  0x8F, 0xFD, 0x20, 0x8E, 0x6A, 0x23, 0x90, 0xF2,
	  0xAF, 0x57, 0x2F, 0x4D, 0x10, 0x80, 0x8E, 0x11,
	  0x3C, 0x61, 0x44, 0x33, 0x2B, 0xE0, 0x58, 0x27 },
	/* u */
	255,
	{ 0x87, 0xB5, 0xEE, 0xA0, 0xC1, 0xF8, 0x27, 0x93,
	  0xCB, 0xE3, 0xD8, 0xA4, 0x5C, 0xF1, 0xBE, 0x17,
	  0xAA, 0x1A, 0xBB, 0xF6, 0x5C, 0x0A, 0x92, 0xEC,
	  0x92, 0xD8, 0x57, 0x53, 0xDC, 0xCA, 0x3D, 0x74 },
	/* exponent1 */
	256,
	{ 0x99, 0xED, 0xE3, 0x8A, 0xC4, 0xE2, 0xF8, 0xF9,
	  0x87, 0x69, 0x70, 0x70, 0x24, 0x8A, 0x9B, 0x0B,
	  0xD0, 0x90, 0x33, 0xFC, 0xF4, 0xC9, 0x18, 0x8D,
	  0x92, 0x23, 0xF8, 0xED, 0xB8, 0x2C, 0x2A, 0xA3 },
	/* exponent2 */
	256,
	{ 0xB9, 0xA2, 0xF2, 0xCF, 0xD8, 0x90, 0xC0, 0x9B,
	  0x04, 0xB2, 0x82, 0x4E, 0xC9, 0xA2, 0xBA, 0x22,
	  0xFE, 0x8D, 0xF6, 0xFE, 0xB2, 0x44, 0x30, 0x67,
	  0x88, 0x86, 0x9D, 0x90, 0x8A, 0xF6, 0xD9, 0xFF }
	};

typedef struct {
	const int pLen; const BYTE p[ 64 ];
	const int qLen; const BYTE q[ 20 ];
	const int gLen; const BYTE g[ 64 ];
	const int xLen; const BYTE x[ 20 ];
	const int yLen; const BYTE y[ 64 ];
	} DLP_PRIVKEY;

static const DLP_PRIVKEY dlpTestKey = {
	/* p */
	512,
	{ 0x8D, 0xF2, 0xA4, 0x94, 0x49, 0x22, 0x76, 0xAA,
	  0x3D, 0x25, 0x75, 0x9B, 0xB0, 0x68, 0x69, 0xCB,
	  0xEA, 0xC0, 0xD8, 0x3A, 0xFB, 0x8D, 0x0C, 0xF7,
	  0xCB, 0xB8, 0x32, 0x4F, 0x0D, 0x78, 0x82, 0xE5,
	  0xD0, 0x76, 0x2F, 0xC5, 0xB7, 0x21, 0x0E, 0xAF,
	  0xC2, 0xE9, 0xAD, 0xAC, 0x32, 0xAB, 0x7A, 0xAC,
	  0x49, 0x69, 0x3D, 0xFB, 0xF8, 0x37, 0x24, 0xC2,
	  0xEC, 0x07, 0x36, 0xEE, 0x31, 0xC8, 0x02, 0x91 },
	/* q */
	160,
	{ 0xC7, 0x73, 0x21, 0x8C, 0x73, 0x7E, 0xC8, 0xEE,
	  0x99, 0x3B, 0x4F, 0x2D, 0xED, 0x30, 0xF4, 0x8E,
	  0xDA, 0xCE, 0x91, 0x5F },
	/* g */
	512,
	{ 0x62, 0x6D, 0x02, 0x78, 0x39, 0xEA, 0x0A, 0x13,
	  0x41, 0x31, 0x63, 0xA5, 0x5B, 0x4C, 0xB5, 0x00,
	  0x29, 0x9D, 0x55, 0x22, 0x95, 0x6C, 0xEF, 0xCB,
	  0x3B, 0xFF, 0x10, 0xF3, 0x99, 0xCE, 0x2C, 0x2E,
	  0x71, 0xCB, 0x9D, 0xE5, 0xFA, 0x24, 0xBA, 0xBF,
	  0x58, 0xE5, 0xB7, 0x95, 0x21, 0x92, 0x5C, 0x9C,
	  0xC4, 0x2E, 0x9F, 0x6F, 0x46, 0x4B, 0x08, 0x8C,
	  0xC5, 0x72, 0xAF, 0x53, 0xE6, 0xD7, 0x88, 0x02 },
	/* x */
	160,
	{ 0x20, 0x70, 0xB3, 0x22, 0x3D, 0xBA, 0x37, 0x2F,
	  0xDE, 0x1C, 0x0F, 0xFC, 0x7B, 0x2E, 0x3B, 0x49,
	  0x8B, 0x26, 0x06, 0x14 },
	/* y */
	512,
	{ 0x19, 0x13, 0x18, 0x71, 0xD7, 0x5B, 0x16, 0x12,
	  0xA8, 0x19, 0xF2, 0x9D, 0x78, 0xD1, 0xB0, 0xD7,
	  0x34, 0x6F, 0x7A, 0xA7, 0x7B, 0xB6, 0x2A, 0x85,
	  0x9B, 0xFD, 0x6C, 0x56, 0x75, 0xDA, 0x9D, 0x21,
	  0x2D, 0x3A, 0x36, 0xEF, 0x16, 0x72, 0xEF, 0x66,
	  0x0B, 0x8C, 0x7C, 0x25, 0x5C, 0xC0, 0xEC, 0x74,
	  0x85, 0x8F, 0xBA, 0x33, 0xF4, 0x4C, 0x06, 0x69,
	  0x96, 0x30, 0xA7, 0x6B, 0x03, 0x0E, 0xE3, 0x33 }
	};

#ifdef TEST_CONFIG

/* The names of the configuration options we check for */

static struct {
	const CRYPT_ATTRIBUTE_TYPE option;	/* Option */
	const char *name;					/* Option name */
	const BOOLEAN isNumeric;			/* Whether it's a numeric option */
	} configOption[] = {
	{ CRYPT_OPTION_INFO_DESCRIPTION, "CRYPT_OPTION_INFO_DESCRIPTION", FALSE },
	{ CRYPT_OPTION_INFO_COPYRIGHT, "CRYPT_OPTION_INFO_COPYRIGHT", FALSE },
	{ CRYPT_OPTION_INFO_MAJORVERSION, "CRYPT_OPTION_INFO_MAJORVERSION", TRUE },
	{ CRYPT_OPTION_INFO_MINORVERSION, "CRYPT_OPTION_INFO_MINORVERSION", TRUE },
	{ CRYPT_OPTION_INFO_STEPPING, "CRYPT_OPTION_INFO_STEPPING", TRUE },

	{ CRYPT_OPTION_ENCR_ALGO, "CRYPT_OPTION_ENCR_ALGO", TRUE },
	{ CRYPT_OPTION_ENCR_HASH, "CRYPT_OPTION_ENCR_HASH", TRUE },

	{ CRYPT_OPTION_PKC_ALGO, "CRYPT_OPTION_PKC_ALGO", TRUE },
	{ CRYPT_OPTION_PKC_KEYSIZE, "CRYPT_OPTION_PKC_KEYSIZE", TRUE },

	{ CRYPT_OPTION_SIG_ALGO, "CRYPT_OPTION_SIG_ALGO", TRUE },
	{ CRYPT_OPTION_SIG_KEYSIZE, "CRYPT_OPTION_SIG_KEYSIZE", TRUE },

	{ CRYPT_OPTION_KEYING_ALGO, "CRYPT_OPTION_KEYING_ALGO", TRUE },
	{ CRYPT_OPTION_KEYING_ITERATIONS, "CRYPT_OPTION_KEYING_ITERATIONS", TRUE },

	{ CRYPT_OPTION_CERT_CREATEV3CERT, "CRYPT_OPTION_CERT_CREATEV3CERT", TRUE },
	{ CRYPT_OPTION_CERT_PKCS10ALT, "CRYPT_OPTION_CERT_PKCS10ALT", TRUE },
	{ CRYPT_OPTION_CERT_CHECKENCODING, "CRYPT_OPTION_CERT_CHECKENCODING", TRUE },
	{ CRYPT_OPTION_CERT_FIXSTRINGS, "CRYPT_OPTION_CERT_FIXSTRINGS", TRUE },
	{ CRYPT_OPTION_CERT_FIXEMAILADDRESS, "CRYPT_OPTION_CERT_FIXEMAILADDRESS", TRUE },
	{ CRYPT_OPTION_CERT_ISSUERNAMEBLOB, "CRYPT_OPTION_CERT_ISSUERNAMEBLOB", TRUE },
	{ CRYPT_OPTION_CERT_KEYIDBLOB, "CRYPT_OPTION_CERT_KEYIDBLOB", TRUE },
	{ CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES, "CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES", TRUE },
	{ CRYPT_OPTION_CERT_TRUSTCHAINROOT, "CRYPT_OPTION_CERT_TRUSTCHAINROOT", TRUE },
	{ CRYPT_OPTION_CERT_VALIDITY, "CRYPT_OPTION_CERT_VALIDITY", TRUE },
	{ CRYPT_OPTION_CERT_UPDATEINTERVAL, "CRYPT_OPTION_CERT_UPDATEINTERVAL", TRUE },
	{ CRYPT_OPTION_CERT_ENCODE_VALIDITYNESTING, "CRYPT_OPTION_CERT_ENCODE_VALIDITYNESTING", TRUE },
	{ CRYPT_OPTION_CERT_DECODE_VALIDITYNESTING, "CRYPT_OPTION_CERT_DECODE_VALIDITYNESTING", TRUE },
	{ CRYPT_OPTION_CERT_ENCODE_CRITICAL, "CRYPT_OPTION_CERT_ENCODE_CRITICAL", TRUE },
	{ CRYPT_OPTION_CERT_DECODE_CRITICAL, "CRYPT_OPTION_CERT_DECODE_CRITICAL", TRUE },

	{ CRYPT_OPTION_KEYS_HTTP_PROXY, "CRYPT_OPTION_KEYS_HTTP_PROXY", FALSE },
	{ CRYPT_OPTION_KEYS_HTTP_TIMEOUT, "CRYPT_OPTION_KEYS_HTTP_TIMEOUT", TRUE },

	{ CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS, "CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_OBJECTTYPE, "CRYPT_OPTION_KEYS_LDAP_OBJECTTYPE", TRUE },
	{ CRYPT_OPTION_KEYS_LDAP_CACERTNAME, "CRYPT_OPTION_KEYS_LDAP_CACERTNAME", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_CERTNAME, "CRYPT_OPTION_KEYS_LDAP_CERTNAME", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_CRLNAME, "CRYPT_OPTION_KEYS_LDAP_CRLNAME", FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_EMAILNAME, "CRYPT_OPTION_KEYS_LDAP_EMAILNAME", FALSE },

	{ CRYPT_OPTION_DEVICE_PKCS11_DVR01, "CRYPT_OPTION_DEVICE_PKCS11_DVR01", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR02, "CRYPT_OPTION_DEVICE_PKCS11_DVR02", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR03, "CRYPT_OPTION_DEVICE_PKCS11_DVR03", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR04, "CRYPT_OPTION_DEVICE_PKCS11_DVR04", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR05, "CRYPT_OPTION_DEVICE_PKCS11_DVR05", FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_HARDWAREONLY, "CRYPT_OPTION_DEVICE_PKCS11_HARDWAREONLY", TRUE },
	{ CRYPT_OPTION_DEVICE_SERIALRNG, "CRYPT_OPTION_DEVICE_SERIALRNG", FALSE },
	{ CRYPT_OPTION_DEVICE_SERIALRNG_PARAMS, "CRYPT_OPTION_DEVICE_SERIALPARAMS", FALSE },

	{ CRYPT_OPTION_CMS_DEFAULTATTRIBUTES, "CRYPT_OPTION_CMS_DEFAULTATTRIBUTES", TRUE },

	{ CRYPT_OPTION_SESSION_TIMEOUT, "CRYPT_OPTION_SESSION_TIMEOUT", TRUE },

	{ CRYPT_OPTION_MISC_FORCELOCK, "CRYPT_OPTION_MISC_FORCELOCK", TRUE },
	{ CRYPT_OPTION_MISC_ASYNCINIT, "CRYPT_OPTION_MISC_ASYNCINIT", TRUE },
	{ CRYPT_ATTRIBUTE_NONE, NULL, 0 }
	};
#endif /* TEST_CONFIG */

/* There are some sizeable (for DOS) data structures used, so we increase the
   stack size to allow for them */

#if defined( __MSDOS16__ ) && defined( __TURBOC__ )
  extern unsigned _stklen = 16384;

/* We also fake out a few unnecessary/unused functions */

void gfInit( void ) {}
void gfQuit( void ) {}
void deflateInit_( void ) {}
void deflateInit2_( void ) {}
void deflate( void ) {}
void deflateEnd( void ) {}

int pgpProcessPreamble( void ) { return( CRYPT_ERROR_NOTAVAIL ); }
int pgpProcessPostamble( void ) { return( CRYPT_ERROR_NOTAVAIL ); }

#ifdef __BORLANDC__x

/* BC++ 3.x doesn't have mbstowcs() in the default library, and also defines
   wchar_t as char (!!) so we fake it here */

size_t mbstowcs( char *pwcs, const char *s, size_t n )
	{
	memcpy( pwcs, s, n );
	return( n );
	}
#endif /* __BORLANDC__ */

#endif /* __MSDOS16__ && __TURBOC__ */

/* Some algorithms can be disabled to eliminate patent problems or reduce the
   size of the code.  The following functions are used to select generally
   equivalent alternatives if the required algorithm isn't available.  These
   selections make certain assumptions (that the given algorithms are always
   available, which is virtually guaranteed, and that they have the same
   general properties as the algorithms they're replacing, which is also
   usually the case - Blowfish for IDEA, RC2, or RC5, and MD5 for MD4) */

CRYPT_ALGO selectCipher( const CRYPT_ALGO algorithm )
	{
	if( cryptStatusOK( cryptQueryCapability( algorithm, NULL ) ) )
		return( algorithm );
	return( CRYPT_ALGO_BLOWFISH );
	}

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

static BOOLEAN setLabel( const CRYPT_CONTEXT cryptContext, const char *label )
	{
	if( cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL, 
								 label, strlen( label ) ) == CRYPT_DATA_DUPLICATE )
		{
		printf( "A key object with the label '%s' already exists inside the\n"
				"device.  To perform this test, you need to delete the "
				"existing object so\nthat cryptlib can create a new one.\n", 
				label );
		return( FALSE );
		}

	return( TRUE );
	}

/* Load RSA, DSA, and Elgamal PKC encrytion contexts */

BOOLEAN loadRSAContexts( const CRYPT_DEVICE cryptDevice,
						 CRYPT_CONTEXT *cryptContext,
						 CRYPT_CONTEXT *decryptContext )
	{
	CRYPT_PKCINFO_RSA *rsaKey;
	const BOOLEAN isDevice = ( cryptDevice != CRYPT_UNUSED ) ? TRUE : FALSE;
	int status;

	/* Allocate room for the public-key components */
	if( ( rsaKey = ( CRYPT_PKCINFO_RSA * ) malloc( sizeof( CRYPT_PKCINFO_RSA ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );

	/* Create the encryption context */
	if( cryptContext != NULL )
		{
		if( isDevice )
			status = cryptDeviceCreateContext( cryptDevice, cryptContext,
											   CRYPT_ALGO_RSA, CRYPT_MODE_PKC );
		else
			status = cryptCreateContext( cryptContext, CRYPT_ALGO_RSA,
										 CRYPT_MODE_PKC );
		if( cryptStatusError( status ) )
			{
			free( rsaKey );
			printf( "crypt%sCreateContext() failed with error code %d.\n",
					isDevice ? "Device" : "", status );
			return( FALSE );
			}
		if( !setLabel( *cryptContext, RSA_PUBKEY_LABEL ) )
			{
			free( rsaKey );
			cryptDestroyContext( *cryptContext );
			return( FALSE );
			}
		cryptInitComponents( rsaKey, CRYPT_KEYTYPE_PUBLIC );
		cryptSetComponent( rsaKey->n, rsa512TestKey.n, rsa512TestKey.nLen );
		cryptSetComponent( rsaKey->e, rsa512TestKey.e, rsa512TestKey.eLen );
		status = cryptSetAttributeString( *cryptContext, 
									CRYPT_CTXINFO_KEY_COMPONENTS, rsaKey, 
									sizeof( CRYPT_PKCINFO_RSA ) );
		cryptDestroyComponents( rsaKey );
		if( cryptStatusError( status ) )
			{
			free( rsaKey );
			cryptDestroyContext( *cryptContext );
			printf( "cryptLoadKey() failed with error code %d.\n", status );
			return( FALSE );
			}
		if( decryptContext == NULL )
			{
			free( rsaKey );
			return( TRUE );
			}
		}

	/* Create the decryption context */
	if( isDevice )
		status = cryptDeviceCreateContext( cryptDevice, decryptContext,
										   CRYPT_ALGO_RSA, CRYPT_MODE_PKC );
	else
		status = cryptCreateContext( decryptContext, CRYPT_ALGO_RSA,
									 CRYPT_MODE_PKC );
	if( cryptStatusError( status ) )
		{
		free( rsaKey );
		if( cryptContext != NULL )
			{
			cryptDestroyContext( *cryptContext );
			if( isDevice )
				cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME, 
								RSA_PUBKEY_LABEL );
			}
		printf( "crypt%sCreateContext() failed with error code %d.\n",
				isDevice ? "Device" : "", status );
		return( FALSE );
		}
	if( !setLabel( *decryptContext, RSA_PRIVKEY_LABEL ) )
		{
		free( rsaKey );
		cryptDestroyContext( *decryptContext );
		if( cryptContext != NULL )
			{
			cryptDestroyContext( *cryptContext );
			if( isDevice )
				cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME, 
								RSA_PUBKEY_LABEL );
			}
		return( FALSE );
		}
	cryptInitComponents( rsaKey, CRYPT_KEYTYPE_PRIVATE );
	cryptSetComponent( rsaKey->n, rsa512TestKey.n, rsa512TestKey.nLen );
	cryptSetComponent( rsaKey->e, rsa512TestKey.e, rsa512TestKey.eLen );
	cryptSetComponent( rsaKey->d, rsa512TestKey.d, rsa512TestKey.dLen );
	cryptSetComponent( rsaKey->p, rsa512TestKey.p, rsa512TestKey.pLen );
	cryptSetComponent( rsaKey->q, rsa512TestKey.q, rsa512TestKey.qLen );
	cryptSetComponent( rsaKey->u, rsa512TestKey.u, rsa512TestKey.uLen );
	cryptSetComponent( rsaKey->e1, rsa512TestKey.e1, rsa512TestKey.e1Len );
	cryptSetComponent( rsaKey->e2, rsa512TestKey.e2, rsa512TestKey.e2Len );
	status = cryptSetAttributeString( *decryptContext, 
									  CRYPT_CTXINFO_KEY_COMPONENTS, rsaKey, 
									  sizeof( CRYPT_PKCINFO_RSA ) );
	cryptDestroyComponents( rsaKey );
	free( rsaKey );
	if( cryptStatusError( status ) )
		{
		if( cryptContext != NULL )
			{
			cryptDestroyContext( *cryptContext );
			if( isDevice )
				cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME, 
								RSA_PUBKEY_LABEL );
			}
		cryptDestroyContext( *decryptContext );
		printf( "cryptLoadKey() failed with error code %d.\n", status );
		return( FALSE );
		}

	return( TRUE );
	}

BOOLEAN loadDSAContexts( const CRYPT_DEVICE cryptDevice,
						 CRYPT_CONTEXT *signContext,
						 CRYPT_CONTEXT *sigCheckContext )
	{
	CRYPT_PKCINFO_DLP *dsaKey;
	const BOOLEAN isDevice = ( cryptDevice != CRYPT_UNUSED ) ? TRUE : FALSE;
	int status;

	/* Allocate room for the public-key components */
	if( ( dsaKey = ( CRYPT_PKCINFO_DLP * ) malloc( sizeof( CRYPT_PKCINFO_DLP ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );

	/* Create the encryption context */
	if( signContext != NULL )
		{
		if( isDevice )
			status = cryptDeviceCreateContext( cryptDevice, signContext,
											   CRYPT_ALGO_DSA, CRYPT_MODE_PKC );
		else
			status = cryptCreateContext( signContext, CRYPT_ALGO_DSA,
										 CRYPT_MODE_PKC );
		if( cryptStatusError( status ) )
			{
			free( dsaKey );
			printf( "cryptCreateContext() failed with error code %d.\n",
					status );
			return( FALSE );
			}
		if( !setLabel( *signContext, DSA_PRIVKEY_LABEL ) )
			{
			free( dsaKey );
			cryptDestroyContext( *signContext );
			return( FALSE );
			}
		cryptInitComponents( dsaKey, CRYPT_KEYTYPE_PRIVATE );
		cryptSetComponent( dsaKey->p, dlpTestKey.p, dlpTestKey.pLen );
		cryptSetComponent( dsaKey->q, dlpTestKey.q, dlpTestKey.qLen );
		cryptSetComponent( dsaKey->g, dlpTestKey.g, dlpTestKey.gLen );
		cryptSetComponent( dsaKey->x, dlpTestKey.x, dlpTestKey.xLen );
		cryptSetComponent( dsaKey->y, dlpTestKey.y, dlpTestKey.yLen );
		status = cryptSetAttributeString( *signContext, 
									CRYPT_CTXINFO_KEY_COMPONENTS, dsaKey, 
									sizeof( CRYPT_PKCINFO_DLP ) );
		cryptDestroyComponents( dsaKey );
		if( cryptStatusError( status ) )
			{
			free( dsaKey );
			cryptDestroyContext( *signContext );
			printf( "cryptLoadKey() failed with error code %d.\n", status );
			return( FALSE );
			}
		if( sigCheckContext == NULL )
			{
			free( dsaKey );
			return( TRUE );
			}
		}

	/* Create the decryption context */
	if( isDevice )
		status = cryptDeviceCreateContext( cryptDevice, sigCheckContext,
										   CRYPT_ALGO_DSA, CRYPT_MODE_PKC );
	else
		status = cryptCreateContext( sigCheckContext, CRYPT_ALGO_DSA, 
									 CRYPT_MODE_PKC );
	if( cryptStatusError( status ) )
		{
		free( dsaKey );
		if( signContext != NULL )
			{
			cryptDestroyContext( *signContext );
			if( isDevice )
				cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME, 
								DSA_PRIVKEY_LABEL );
			}
		printf( "cryptCreateContext() failed with error code %d.\n", status );
		return( FALSE );
		}
	if( !setLabel( *sigCheckContext, DSA_PUBKEY_LABEL ) )
		{
		if( signContext != NULL )
			{
			cryptDestroyContext( *signContext );
			if( isDevice )
				cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME, 
								DSA_PRIVKEY_LABEL );
			}
		cryptDestroyContext( *sigCheckContext );
		return( FALSE );
		}
	cryptInitComponents( dsaKey, CRYPT_KEYTYPE_PUBLIC );
	cryptSetComponent( dsaKey->p, dlpTestKey.p, dlpTestKey.pLen );
	cryptSetComponent( dsaKey->q, dlpTestKey.q, dlpTestKey.qLen );
	cryptSetComponent( dsaKey->g, dlpTestKey.g, dlpTestKey.gLen );
	cryptSetComponent( dsaKey->y, dlpTestKey.y, dlpTestKey.yLen );
	status = cryptSetAttributeString( *sigCheckContext, 
									  CRYPT_CTXINFO_KEY_COMPONENTS, dsaKey, 
									  sizeof( CRYPT_PKCINFO_DLP ) );
	cryptDestroyComponents( dsaKey );
	free( dsaKey );
	if( cryptStatusError( status ) )
		{
		if( signContext != NULL )
			{
			cryptDestroyContext( *signContext );
			if( isDevice )
				cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME, 
								DSA_PRIVKEY_LABEL );
			}
		cryptDestroyContext( *sigCheckContext );
		printf( "cryptLoadKey() failed with error code %d.\n", status );
		return( FALSE );
		}

	return( TRUE );
	}

BOOLEAN loadElgamalContexts( CRYPT_CONTEXT *cryptContext,
							 CRYPT_CONTEXT *decryptContext )
	{
	CRYPT_PKCINFO_DLP *elgamalKey;
	int status;

	/* Allocate room for the public-key components */
	if( ( elgamalKey = ( CRYPT_PKCINFO_DLP * ) malloc( sizeof( CRYPT_PKCINFO_DLP ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );

	/* Create the encryption context */
	if( cryptContext != NULL )
		{
		status = cryptCreateContext( cryptContext, CRYPT_ALGO_ELGAMAL, CRYPT_MODE_PKC );
		if( cryptStatusError( status ) )
			{
			free( elgamalKey );
			printf( "cryptCreateContext() failed with error code %d.\n", status );
			return( FALSE );
			}
		if( !setLabel( *cryptContext, ELGAMAL_PUBKEY_LABEL ) )
			{
			free( elgamalKey );
			cryptDestroyContext( *cryptContext );
			return( FALSE );
			}
		cryptInitComponents( elgamalKey, CRYPT_KEYTYPE_PUBLIC );
		cryptSetComponent( elgamalKey->p, dlpTestKey.p, dlpTestKey.pLen );
		cryptSetComponent( elgamalKey->g, dlpTestKey.g, dlpTestKey.gLen );
		cryptSetComponent( elgamalKey->q, dlpTestKey.q, dlpTestKey.qLen );
		cryptSetComponent( elgamalKey->y, dlpTestKey.y, dlpTestKey.yLen );
		status = cryptSetAttributeString( *cryptContext, 
									CRYPT_CTXINFO_KEY_COMPONENTS, elgamalKey, 
									sizeof( CRYPT_PKCINFO_DLP ) );
		cryptDestroyComponents( elgamalKey );
		if( cryptStatusError( status ) )
			{
			free( elgamalKey );
			cryptDestroyContext( *cryptContext );
			printf( "cryptLoadKey() failed with error code %d.\n", status );
			return( FALSE );
			}
		if( decryptContext == NULL )
			{
			free( elgamalKey );
			return( TRUE );
			}
		}

	/* Create the decryption context */
	status = cryptCreateContext( decryptContext, CRYPT_ALGO_ELGAMAL, CRYPT_MODE_PKC );
	if( cryptStatusError( status ) )
		{
		free( elgamalKey );
		if( cryptContext != NULL )
			cryptDestroyContext( *cryptContext );
		printf( "cryptCreateContext() failed with error code %d.\n", status );
		return( FALSE );
		}
	if( !setLabel( *decryptContext, ELGAMAL_PRIVKEY_LABEL ) )
		{
		free( elgamalKey );
		if( cryptContext != NULL )
			cryptDestroyContext( *cryptContext );
		cryptDestroyContext( *decryptContext );
		return( FALSE );
		}
	cryptInitComponents( elgamalKey, CRYPT_KEYTYPE_PRIVATE );
	cryptSetComponent( elgamalKey->p, dlpTestKey.p, dlpTestKey.pLen );
	cryptSetComponent( elgamalKey->g, dlpTestKey.g, dlpTestKey.gLen );
	cryptSetComponent( elgamalKey->q, dlpTestKey.q, dlpTestKey.qLen );
	cryptSetComponent( elgamalKey->y, dlpTestKey.y, dlpTestKey.yLen );
	cryptSetComponent( elgamalKey->x, dlpTestKey.x, dlpTestKey.xLen );
	status = cryptSetAttributeString( *decryptContext, 
									  CRYPT_CTXINFO_KEY_COMPONENTS, elgamalKey, 
									  sizeof( CRYPT_PKCINFO_DLP ) );
	cryptDestroyComponents( elgamalKey );
	free( elgamalKey );
	if( cryptStatusError( status ) )
		{
		cryptDestroyContext( *cryptContext );
		cryptDestroyContext( *decryptContext );
		printf( "cryptLoadKey() failed with error code %d.\n", status );
		return( FALSE );
		}

	return( TRUE );
	}

/* Load Diffie-Hellman encrytion contexts */

BOOLEAN loadDHContexts( CRYPT_CONTEXT *cryptContext1,
						CRYPT_CONTEXT *cryptContext2, int keySize )
	{
	CRYPT_PKCINFO_DLP *dhKey;
	int status;

	/* Allocate room for the public-key components */
	if( ( dhKey = ( CRYPT_PKCINFO_DLP * ) malloc( sizeof( CRYPT_PKCINFO_DLP ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );

	/* Create the first encryption context */
	status = cryptCreateContext( cryptContext1, CRYPT_ALGO_DH, CRYPT_MODE_PKC );
	if( cryptStatusError( status ) )
		{
		free( dhKey );
		printf( "cryptCreateContext() failed with error code %d.\n", status );
		return( FALSE );
		}
	if( !setLabel( *cryptContext1, DH_KEY1_LABEL ) )
		{
		free( dhKey );
		cryptDestroyContext( *cryptContext1 );
		return( FALSE );
		}
	cryptInitComponents( dhKey, CRYPT_UNUSED );
	status = cryptSetAttributeString( *cryptContext1, 
									  CRYPT_CTXINFO_KEY_COMPONENTS, dhKey, 
									  sizeof( CRYPT_PKCINFO_DLP ) );
	cryptDestroyComponents( dhKey );
	if( cryptStatusError( status ) )
		{
		free( dhKey );
		printf( "cryptLoadKey() failed with error code %d.\n", status );
		return( FALSE );
		}
	if( cryptContext2 == NULL )
		{
		free( dhKey );
		return( TRUE );
		}

	/* Create the second encryption context */
	status = cryptCreateContext( cryptContext2, CRYPT_ALGO_DH, CRYPT_MODE_PKC );
	if( cryptStatusError( status ) )
		{
		free( dhKey );
		printf( "cryptCreateContext() failed with error code %d.\n", status );
		return( FALSE );
		}
	if( !setLabel( *cryptContext2, DH_KEY2_LABEL ) )
		{
		free( dhKey );
		if( cryptContext1 != NULL )
			cryptDestroyContext( *cryptContext1 );
		cryptDestroyContext( *cryptContext2 );
		return( FALSE );
		}
	cryptInitComponents( dhKey, CRYPT_UNUSED );
	status = cryptSetAttributeString( *cryptContext2, 
									  CRYPT_CTXINFO_KEY_COMPONENTS, dhKey, 
									  sizeof( CRYPT_PKCINFO_DLP ) );
	cryptDestroyComponents( dhKey );
	free( dhKey );
	if( cryptStatusError( status ) )
		{
		printf( "cryptLoadKey() failed with error code %d.\n", status );
		return( FALSE );
		}

	return( TRUE );
	}

/* Destroy the encryption contexts */

void destroyContexts( const CRYPT_DEVICE cryptDevice, 
					  CRYPT_CONTEXT cryptContext, 
					  CRYPT_CONTEXT decryptContext )
	{
	int cryptAlgo, status;

	cryptGetAttribute( cryptContext, CRYPT_CTXINFO_ALGO, &cryptAlgo );
	status = cryptDestroyContext( cryptContext );
	if( cryptStatusError( status ) )
		printf( "cryptDestroyContext() failed with error code %d.\n", status );
	status = cryptDestroyContext( decryptContext );
	if( cryptStatusError( status ) )
		printf( "cryptDestroyContext() failed with error code %d.\n", status );
	if( cryptDevice == CRYPT_UNUSED )
		return;

	/* If the context is associated with a device then creating the object 
	   will generally also create a persistent object in the device, after
	   performing the tests we have to explicitly delete the persistent
	   object */
	if( cryptAlgo == CRYPT_ALGO_RSA )
		{
		cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME, RSA_PUBKEY_LABEL );
		cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME, RSA_PRIVKEY_LABEL );
		}
	else
		if( cryptAlgo == CRYPT_ALGO_DSA )
			{
			cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME, DSA_PUBKEY_LABEL );
			cryptDeleteKey( cryptDevice, CRYPT_KEYID_NAME, DSA_PRIVKEY_LABEL );
			}
	}

/****************************************************************************
*																			*
*							Low-level Routines Test							*
*																			*
****************************************************************************/

#if defined( TEST_LOWLEVEL ) || defined( TEST_DEVICE )

/* Work routines: Set a pair of encrypt/decrypt buffers to a known state,
   and make sure they're still in that known state */

static void initTestBuffers( BYTE *buffer1, BYTE *buffer2 )
	{
	/* Set the buffers to a known state */
	memset( buffer1, '*', TESTBUFFER_SIZE );
	memcpy( buffer1, "12345678", 8 );		/* For endianness check */
	memcpy( buffer2, buffer1, TESTBUFFER_SIZE );
	}

static BOOLEAN checkTestBuffers( const BYTE *buffer1, const BYTE *buffer2 )
	{
	/* Make sure everything went OK */
	if( memcmp( buffer1, buffer2, TESTBUFFER_SIZE ) )
		{
		puts( "Error: Decrypted data != original plaintext." );

		/* Try and guess at block chaining problems */
		if( !memcmp( buffer1, "12345678****", 12 ) )
			puts( "\t\bIt looks like there's a problem with block chaining." );
		else
			/* Try and guess at endianness problems - we want "1234" */
			if( !memcmp( buffer1, "4321", 4 ) )
				puts( "\t\bIt looks like the 32-bit word endianness is "
					  "reversed." );
			else
				if( !memcmp( buffer1, "2143", 4 ) )
					puts( "\t\bIt looks like the 16-bit word endianness is "
						  "reversed." );
			else
				if( buffer1[ 0 ] >= '1' && buffer1[ 0 ] <= '9' )
					puts( "\t\bIt looks like there's some sort of endianness "
						  "problem which is\n\t more complex than just a "
						  "reversal." );
				else
					puts( "\t\bIt's probably more than just an endianness "
						  "problem." );
		return( FALSE );
		}

	return( TRUE );
	}

/* Perform a test en/decryption */

static BOOLEAN testCrypt( CRYPT_CONTEXT cryptContext, 
						  CRYPT_CONTEXT decryptContext, BYTE *buffer )
	{
	BYTE iv[ CRYPT_MAX_IVSIZE ];
	int cryptAlgo, cryptMode, status;

	/* Find out about the algorithm we're using */
	cryptGetAttribute( cryptContext, CRYPT_CTXINFO_ALGO, &cryptAlgo );
	cryptGetAttribute( cryptContext, CRYPT_CTXINFO_MODE, &cryptMode );
	if( cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL && \
		( cryptMode == CRYPT_MODE_CFB || cryptMode == CRYPT_MODE_OFB ) )
		{
		/* Encrypt the buffer in two odd-sized chunks */
		status = cryptEncrypt( cryptContext, buffer, 79 );
		if( cryptStatusOK( status ) )
			status = cryptEncrypt( cryptContext, buffer + 79, 
								   TESTBUFFER_SIZE - 79 );
		if( cryptStatusError( status ) )
			{
			printf( "Couldn't encrypt data, status = %d.\n", status );
			return( FALSE );
			}

		/* Copy the IV from the encryption to the decryption context if
		   necessary */
		if( cryptAlgo != CRYPT_ALGO_RC4 )
			{
			int ivLength;

			status = cryptRetrieveIV( cryptContext, iv, &ivLength );
			if( cryptStatusError( status ) )
				{
				printf( "Couldn't retrieve IV after encryption, status = %d.\n",
						status );
				return( FALSE );
				}
			status = cryptLoadIV( decryptContext, iv, ivLength );
			if( cryptStatusError( status ) )
				{
				printf( "Couldn't load IV for decryption, status = %d.\n", status );
				return( FALSE );
				}
			}

		/* Decrypt the buffer in different odd-size chunks */
		status = cryptDecrypt( decryptContext, buffer, 125 );
		if( cryptStatusOK( status ) )
			status = cryptDecrypt( decryptContext, buffer + 125, 
								   TESTBUFFER_SIZE - 125 );
		if( cryptStatusError( status ) )
			{
			printf( "Couldn't decrypt data, status = %d.\n", status );
			return( FALSE );
			}

		return( TRUE );
		}
	if( cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL && \
		( cryptMode == CRYPT_MODE_ECB || cryptMode == CRYPT_MODE_CBC ) )
		{
		/* Encrypt the buffer in two odd-sized chunks */
		status = cryptEncrypt( cryptContext, buffer, 80 );
		if( cryptStatusOK( status ) )
			status = cryptEncrypt( cryptContext, buffer + 80, 
								   TESTBUFFER_SIZE - 80 );
		if( cryptStatusOK( status ) )
			status = cryptEncrypt( cryptContext, buffer + TESTBUFFER_SIZE, 0 );
		if( cryptStatusError( status ) )
			{
			printf( "Couldn't encrypt data, status = %d.\n", status );
			return( FALSE );
			}

		/* Copy the IV from the encryption to the decryption context if
		   necessary */
		if( cryptMode != CRYPT_MODE_ECB )
			{
			int ivLength;

			status = cryptRetrieveIV( cryptContext, iv, &ivLength );
			if( cryptStatusError( status ) )
				printf( "Couldn't retrieve IV after encryption, status = %d.\n",
						status );
			status = cryptLoadIV( decryptContext, iv, ivLength );
			if( cryptStatusError( status ) )
				printf( "Couldn't load IV for decryption, status = %d.\n", status );
			status = cryptEncrypt( cryptContext, buffer + TESTBUFFER_SIZE, 0 );
			}

		/* Decrypt the buffer in different odd-size chunks */
		status = cryptDecrypt( decryptContext, buffer, 128 );
		if( cryptStatusOK( status ) )
			status = cryptDecrypt( decryptContext, buffer + 128, 
								   TESTBUFFER_SIZE - 128 );
		if( cryptStatusOK( status ) )
			status = cryptDecrypt( decryptContext, buffer + TESTBUFFER_SIZE, 0 );
		if( cryptStatusError( status ) )
			{
			printf( "Couldn't decrypt data, status = %d.\n", status );
			return( FALSE );
			}

		return( TRUE );
		}
	if( cryptAlgo >= CRYPT_ALGO_FIRST_PKC && cryptAlgo <= CRYPT_ALGO_LAST_PKC )
		{
		static const BYTE rsaValue[] = \
			"\x4E\x1F\x2F\x10\xA9\xFB\x4F\xD9\xC1\x25\x79\x7A\x36\x00\x58\xD0"
			"\x9E\x8B\x9F\xBA\xC7\x04\x10\x77\xDB\xBC\xC9\xD1\x70\xCD\xF6\x86"
			"\xA4\xDC\x39\xA9\x57\xD7\xC7\xE0\x87\xF2\x31\xDF\x83\x7d\x27\x0E"
			"\xB4\xA6\x93\x3D\x11\xEB\xA5\x0E\x42\x66\x7B\x30\x50\x84\xC1\x81";
		BYTE testBuffer[ TESTBUFFER_SIZE ];
		BOOLEAN encryptOK = TRUE;
		int length;

		/* To ensure that the magnitude of the integer corresponding to the
		   data to be encrypted is less than the modulus (in the case of
		   RSA), we set the first byte of the buffer to 1.  This is only
		   required for this test code which uses a set data pattern and
		   isn't necessary for the usual mid-level calls like
		   cryptExportKey() */
		int ch = buffer[ 0 ];

		/* Take a copy of the input so we can compare it with decrypted 
		   output */
		memcpy( testBuffer, buffer, TESTBUFFER_SIZE );

		/* Since the PKC algorithms only handle a single block, we only
		   perform a single encrypt and decrypt operation */
		buffer[ 0 ] = 1;
		status = cryptEncrypt( cryptContext, buffer, 64 );
		if( cryptStatusError( status ) )
			{
			printf( "Couldn't encrypt data, status = %d.\n", status );
			return( FALSE );
			}
		if( cryptAlgo == CRYPT_ALGO_RSA && memcmp( buffer, rsaValue, 64 ) )
			{
			/* For a non-randomized PKC the encryption of the fixed value 
			   produces known output, we make sure this matches the expected 
			   value.  This makes diagnosing problems with crypto devices 
			   rather easier */
			puts( "The actual encrypted value doesn't match the expected value." );
			encryptOK = FALSE;
			}
		status = cryptDecrypt( decryptContext, buffer, 64 );
		if( cryptStatusError( status ) )
			{
			if( encryptOK )
				printf( "Couldn't decrypt data even though the encrypted "
						"input data was valid,\nstatus = %d.\n", status );
			else
				printf( "Couldn't decrypt data, probably because the data "
						"produced by the encrypt step\nwas invalid, status = "
						"%d.\n", status );
			return( FALSE );
			}
		buffer[ 0 ] = ch;

		/* Make sure the recovered result matches the input data */
		cryptGetAttribute( cryptContext, CRYPT_CTXINFO_KEYSIZE, &length );
		if( memcmp( buffer, testBuffer, length ) )
			{
			if( encryptOK )
				/* This could happen with simple-minded CRT implementations 
				   which only work when p > q (the test key has p < q in 
				   order to find this problem) */
				puts( "Decryption failed even though encryption produced "
					  "valid data.  The RSA\ndecryption step is broken." );
			else
				puts( "Decryption failed because the encryption step "
					  "produced invalid data. The RSA\nencryption step is "
					  "broken." );
			return( FALSE );
			}
		else
			if( !encryptOK )
				{
				puts( "Decryption succeeded even though encryption produced "
					  "invalid data.  The RSA\nimplementation is broken." );
				return( FALSE );
				}

		return( TRUE );
		}
	if( cryptAlgo >= CRYPT_ALGO_FIRST_HASH && \
		cryptAlgo <= CRYPT_ALGO_LAST_MAC )
		{
		/* Hash the buffer in two odd-sized chunks */
		status = cryptEncrypt( cryptContext, buffer, 80 );
		if( cryptStatusOK( status ) )
			status = cryptEncrypt( cryptContext, buffer + 80, 
								   TESTBUFFER_SIZE - 80 );
		if( cryptStatusOK( status ) )
			status = cryptEncrypt( cryptContext, buffer + TESTBUFFER_SIZE, 0 );
		if( cryptStatusError( status ) )
			{
			printf( "Couldn't hash data, status = %d.\n", status );
			return( FALSE );
			}

		/* Hash the buffer in different odd-size chunks */
		status = cryptEncrypt( decryptContext, buffer, 128 );
		if( cryptStatusOK( status ) )
			status = cryptEncrypt( decryptContext, buffer + 128, 
								   TESTBUFFER_SIZE - 128 );
		if( cryptStatusOK( status ) )
			status = cryptEncrypt( decryptContext, buffer + TESTBUFFER_SIZE, 0 );
		if( cryptStatusError( status ) )
			{
			printf( "Couldn't hash data, status = %d.\n", status );
			return( FALSE );
			}

		return( TRUE );
		}

	printf( "Unknown encryption algorithm/mode %d.\n", cryptAlgo );
	return( FALSE );
	}

/* Load the encryption contexts */

static BOOLEAN loadContexts( CRYPT_CONTEXT *cryptContext, CRYPT_CONTEXT *decryptContext,
							 const CRYPT_DEVICE cryptDevice,
							 const CRYPT_ALGO cryptAlgo,
							 const CRYPT_MODE cryptMode,
							 const BYTE *key, const int length )
	{
	const BOOLEAN isDevice = ( cryptDevice != CRYPT_UNUSED ) ? TRUE : FALSE;
	const BOOLEAN hasKey = ( cryptAlgo >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
							 cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL ) || \
						   ( cryptAlgo >= CRYPT_ALGO_FIRST_MAC && \
							 cryptAlgo <= CRYPT_ALGO_LAST_MAC );
	BOOLEAN adjustKey = FALSE;
	int status;

	/* Create the encryption context */
	if( isDevice )
		status = cryptDeviceCreateContext( cryptDevice, cryptContext,
										   cryptAlgo, 0 );
	else
		status = cryptCreateContext( cryptContext, cryptAlgo, 0 );
	if( cryptStatusError( status ) )
		{
		printf( "crypt%sCreateContext() failed with error code %d.\n",
				isDevice ? "Device" : "", status );
		return( FALSE );
		}
	if( cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL )
		{
		status = cryptSetAttribute( *cryptContext, CRYPT_CTXINFO_MODE,
									cryptMode );
		if( cryptStatusError( status ) )
			{
			cryptDestroyContext( *cryptContext );
			if( status == CRYPT_ERROR_NOTAVAIL )
				/* This mode isn't available, return a special-case value to
				   tell the calling code to continue */
				return( status );
			printf( "Encryption mode %d selection failed with status %d.\n",
					cryptMode, status );
			return( FALSE );
			}
		}
	if( hasKey )
		{
		status = cryptLoadKey( *cryptContext, key, length );
		if( length > 16 && status == CRYPT_ERROR_PARAM4 )
			{
			status = cryptLoadKey( *cryptContext, key, 16 );
			if( cryptStatusOK( status ) )
				{
				puts( "  Load of full-length key failed, using shorter 128-"
					  "bit key." );
				adjustKey = TRUE;
				}
			}
		if( cryptStatusError( status ) )
			{
			printf( "cryptLoadKey() failed with error code %d.\n", status );
			return( FALSE );
			}
		}
	if( decryptContext == NULL )
		return( TRUE );

	/* Create the decryption context */
	if( cryptDevice == CRYPT_UNUSED )
		status = cryptCreateContext( decryptContext, cryptAlgo, cryptMode );
	else
		status = cryptDeviceCreateContext( cryptDevice, decryptContext,
										   cryptAlgo, cryptMode );
	if( cryptStatusError( status ) )
		{
		printf( "crypt%sCreateContext() failed with error code %d.\n",
				( cryptDevice != CRYPT_UNUSED ) ? "Device" : "", status );
		return( FALSE );
		}
	if( cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL )
		{
		status = cryptSetAttribute( *decryptContext, CRYPT_CTXINFO_MODE,
									cryptMode );
		if( cryptStatusError( status ) )
			{
			cryptDestroyContext( *cryptContext );
			if( status == CRYPT_ERROR_NOTAVAIL )
				/* This mode isn't available, return a special-case value to
				   tell the calling code to continue */
				return( status );
			printf( "Encryption mode %d selection failed with status %d.\n",
					cryptMode, status );
			return( FALSE );
			}
		}
	if( hasKey )
		{
		status = cryptLoadKey( *decryptContext, key, adjustKey ? 16 : length );
		if( cryptStatusError( status ) )
			{
			printf( "cryptLoadKey() failed with error code %d.\n", status );
			return( FALSE );
			}
		}

	return( TRUE );
	}

/* Check for an algorithm/mode */

static BOOLEAN checkLowlevelInfo( const CRYPT_DEVICE cryptDevice,
								  const CRYPT_ALGO cryptAlgo )
	{
	CRYPT_QUERY_INFO cryptQueryInfo;
	const BOOLEAN isDevice = ( cryptDevice != CRYPT_UNUSED ) ? TRUE : FALSE;
	int status;

	if( isDevice )
		status = cryptDeviceQueryCapability( cryptDevice, cryptAlgo, 
											 &cryptQueryInfo );
	else
		status = cryptQueryCapability( cryptAlgo, &cryptQueryInfo );
	if( cryptStatusError( status ) )
		{
		printf( "crypt%sQueryCapability() reports algorithm %d is not "
				"available, status = %d.\n", isDevice ? "Device" : "", 
				cryptAlgo, status );
		return( FALSE );
		}
	printf( "cryptQueryCapability() reports availability of %s algorithm "
			"with\n  block size %d bits", cryptQueryInfo.algoName, 
			bytesToBits( cryptQueryInfo.blockSize ) );
	if( cryptAlgo < CRYPT_ALGO_FIRST_HASH || cryptAlgo > CRYPT_ALGO_LAST_HASH )
		{
		printf( ", keysize %d-%d bits (recommended = %d bits)",
				bytesToBits( cryptQueryInfo.minKeySize ),
				bytesToBits( cryptQueryInfo.maxKeySize ),
				bytesToBits( cryptQueryInfo.keySize ) );
		}
	puts( "." );

	return( TRUE );
	}

/* Test an algorithm/mode implementation */

int testLowlevel( const CRYPT_DEVICE cryptDevice, const CRYPT_ALGO cryptAlgo,
				  const BOOLEAN checkOnly )
	{
	CRYPT_MODE cryptMode = CRYPT_MODE_ECB;
	CRYPT_CONTEXT cryptContext, decryptContext;
	BYTE buffer[ TESTBUFFER_SIZE ], testBuffer[ TESTBUFFER_SIZE ];
	BOOLEAN modesTested[ 8 ] = { 0 }, testSucceeded = FALSE;
	int status;

	/* Initialise the test buffers */
	initTestBuffers( buffer, testBuffer );

	/* Check cryptlib's capabilities */
	if( !checkLowlevelInfo( cryptDevice, cryptAlgo ) )
		return( FALSE );

	/* If we're only doing a capability check, don't try anything else */
	if( checkOnly )
		return( TRUE );

	/* Since DH and KEA only perform key agreement rather than a true key
	   exchange, we can't test their encryption capabilities */
	if( cryptAlgo == CRYPT_ALGO_DH || cryptAlgo == CRYPT_ALGO_KEA )
		return( TRUE );

	do
		{
		/* Set up an encryption context, load a user key into it, and 
		   perform a key setup */
		switch( cryptAlgo )
			{
			case CRYPT_ALGO_DES:
				status = loadContexts( &cryptContext, &decryptContext, 
									   cryptDevice, cryptAlgo, cryptMode,
									   ( BYTE * ) "12345678", 8 );
				break;

			case CRYPT_ALGO_SKIPJACK:
				status = loadContexts( &cryptContext, &decryptContext, 
									   cryptDevice, cryptAlgo, cryptMode,
									   ( BYTE * ) "1234567890", 10 );
				break;

			case CRYPT_ALGO_CAST:
			case CRYPT_ALGO_IDEA:
			case CRYPT_ALGO_SAFER:
				status = loadContexts( &cryptContext, &decryptContext, 
									   cryptDevice, cryptAlgo, cryptMode,
									   ( BYTE * ) "1234567887654321", 16 );
				break;

			case CRYPT_ALGO_3DES:
				status = loadContexts( &cryptContext, &decryptContext, 
									   cryptDevice, cryptAlgo, cryptMode,
									   ( BYTE * ) "123456788765432112345678", 24 );
				break;

			case CRYPT_ALGO_RC2:
			case CRYPT_ALGO_RC4:
			case CRYPT_ALGO_RC5:
			case CRYPT_ALGO_BLOWFISH:
			case CRYPT_ALGO_HMAC_MD5:
			case CRYPT_ALGO_HMAC_SHA:
			case CRYPT_ALGO_HMAC_RIPEMD160:
				status = loadContexts( &cryptContext, &decryptContext, 
									   cryptDevice, cryptAlgo, cryptMode,
									   ( BYTE * ) "1234567890098765432112345678900987654321", 40 );
				break;

			case CRYPT_ALGO_MD2:
			case CRYPT_ALGO_MD4:
			case CRYPT_ALGO_MD5:
			case CRYPT_ALGO_SHA:
			case CRYPT_ALGO_RIPEMD160:
			case CRYPT_ALGO_MDC2:
				status = loadContexts( &cryptContext, &decryptContext, 
									   cryptDevice, cryptAlgo, CRYPT_MODE_NONE,
									   ( BYTE * ) "", 0 );
				break;

			case CRYPT_ALGO_RSA:
				status = loadRSAContexts( cryptDevice, &cryptContext, 
										  &decryptContext );
				break;

			case CRYPT_ALGO_DSA:
				status = loadDSAContexts( cryptDevice, &cryptContext, 
										  &decryptContext );
				break;

			case CRYPT_ALGO_ELGAMAL:
				status = loadElgamalContexts( &cryptContext, &decryptContext );
				break;

			default:
				printf( "Unknown encryption algorithm ID %d, cannot perform "
						"encryption test\n", cryptAlgo );
				return( FALSE );
			}
		if( status == CRYPT_ERROR_NOTAVAIL )
			{
			/* It's a conventional algorithm for which this mode isn't 
			   available, try a different mode */
			cryptMode++;
			continue;
			}
		if( !status )
			return( FALSE );

		/* DSA can't be called from user code because of the special data-
		   formatting requirements */
		if( cryptAlgo == CRYPT_ALGO_DSA )
			{
			destroyContexts( cryptDevice, cryptContext, decryptContext );
			return( TRUE );
			}

		/* Perform a test en/decryption */
		if( !testCrypt( cryptContext, decryptContext, buffer ) )
			return( FALSE );

		/* Make sure everything went OK */
		if( cryptAlgo >= CRYPT_ALGO_FIRST_HASH )
			{
			BYTE hash1[ CRYPT_MAX_HASHSIZE ], hash2[ CRYPT_MAX_HASHSIZE ];
			int length1, length2;

			status = cryptGetAttributeString( cryptContext, CRYPT_CTXINFO_HASHVALUE, 
											  hash1, &length1 );
			cryptGetAttributeString( decryptContext, CRYPT_CTXINFO_HASHVALUE, 
									 hash2, &length2 );
			if( cryptStatusError( status ) )
				{
				printf( "Couldn't get hash information, status = %d\n", status );
				return( FALSE );
				}
			else
				{
				if( ( length1 != length2 ) || memcmp( hash1, hash2, length1 ) )
					{
					puts( "Error: Hash value of identical buffers differs." );
					return( FALSE );
					}
				if( !memcmp( hash1, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 ) || \
					!memcmp( hash2, "\x00\x00\x00\x00\x00\x00\x00\x00", 8 ) )
					{
					puts( "Error: Hash contains all zeroes." );
					return( FALSE );
					}
				}
			}
		else
			/* If it's a PKC we'll have performed the check during the 
			   encrypt/decrypt step */
			if( cryptAlgo < CRYPT_ALGO_FIRST_PKC && \
				!checkTestBuffers( buffer, testBuffer ) )
				return( FALSE );

		/* Remember that at least one test succeeded */
		testSucceeded = TRUE;
		if( cryptAlgo < CRYPT_ALGO_LAST_CONVENTIONAL )
			modesTested[ cryptMode++ ] = TRUE;

		/* Clean up */
		destroyContexts( cryptDevice, cryptContext, decryptContext );
		}
	while( cryptAlgo < CRYPT_ALGO_LAST_CONVENTIONAL && \
		   cryptMode < CRYPT_MODE_LAST );

	/* If it's a conventional algorithm, report the encryption modes which 
	   were tested */
	if( cryptAlgo < CRYPT_ALGO_LAST_CONVENTIONAL )
		{
		printf( "  Encryption modes tested:" );
		if( modesTested[ CRYPT_MODE_ECB ] )
			printf( " ECB" );
		if( modesTested[ CRYPT_MODE_CBC ] )
			printf( " CBC" );
		if( modesTested[ CRYPT_MODE_CFB ] )
			printf( " CFB" );
		if( modesTested[ CRYPT_MODE_OFB ] )
			printf( " OFB" );
		puts( "." );
		}

	/* Make sure at least one of the algorithm's modes was tested */
	if( !testSucceeded )
		{
		puts( "No processing modes were found for this algorithm.\n" );
		return( FALSE );
		}

	return( TRUE );
	}
#endif /* TEST_LOWLEVEL || TEST_DEVICE */

/****************************************************************************
*																			*
*								Misc.Kludges								*
*																			*
****************************************************************************/

/* Update the cryptlib config file.  This code can be used to set the
   information required to load PKCS #11 device drivers:

	- Set the driver path in the CRYPT_OPTION_DEVICE_PKCS11_DVR01 setting
	  below.
	- Add a call to updateConfig() from somewhere (eg testKludge()).
	- Run the test code until it calls updateConfig().
	- Remove the updateConfig() call, then run the test code as normal.
	  The testDevices() call will report the results of trying to use your
	  driver */

static void updateConfig( void )
	{
	/* Set the path for a PKCS #11 device driver.  We only enable one of 
	   these at a time to speed the startup time */
#if 0
	cryptSetOptionString( CRYPT_OPTION_DEVICE_PKCS11_DVR01, 
						  "d:/spool/nexus/nxpkcs11.dll" );
	cryptSetOptionString( CRYPT_OPTION_DEVICE_PKCS11_DVR01, 
						  "c:/program files/eracom/cprov sw/cryptoki.dll" );
	cryptSetOptionString( CRYPT_OPTION_DEVICE_PKCS11_DVR01, 
						  "c:/winnt/system32/dkck232.dll" );
	cryptSetOptionString( CRYPT_OPTION_DEVICE_PKCS11_DVR01, 
						  "c:/winnt/system32/slbck.dll" );
#endif /* 0 */
	cryptSetOptionString( CRYPT_OPTION_DEVICE_PKCS11_DVR01, 
						  "c:/winnt/system32/dkck232.dll" );

	/* Update the options */
	cryptWriteOptions();
	}

/* Generic test code insertion point.  The following routine is called 
   before any of the other tests are run and can be used to handle special-
   case tests which aren't part of the main test suite */

void testKludge( void )
	{
	}

/****************************************************************************
*																			*
*								Main Test Code								*
*																			*
****************************************************************************/

#if defined( _WINDOWS ) || defined( WIN32 ) || defined( _WIN32 )
  #define __WINDOWS__
  #define INC_CHILD
#endif /* _WINDOWS || WIN32 || _WIN32 */

/* Exercise various aspects of cryptlib */

int main( int argc, char **argv )
	{
#ifdef TEST_LOWLEVEL
	CRYPT_ALGO cryptAlgo;
#endif /* TEST_LOWLEVEL */
#ifdef TEST_CONFIG
	int i;
#endif /* TEST_CONFIG */
	int status;
	void testSystemSpecific( void );

	/* Get rid of compiler warnings */
	if( argc || argv );

	/* Make sure various system-specific features are set right */
	testSystemSpecific();

	/* VisualAge C++ doesn't set the TZ correctly.  The check for this isn't
	   as simple as it would seem since most IBM compilers define the same
	   preprocessor values even though it's not documented anywhere, so we
	   have to enable the tzset() call for (effectively) all IBM compilers
	   and then disable it for ones other than VisualAge C++ */
#if ( defined( __IBMC__ ) || defined( __IBMCPP__ ) ) && !defined( __VMCMS__ )
	tzset();
#endif /* VisualAge C++ */

	/* Initialise cryptlib.  To speed up the startup time, we only call
	   cryptInitEx() if the low-level functions are being tested,
	   presumably once these have been tested exhaustively the code isn't
	   going to break itself */
#if defined( TEST_LOWLEVEL )
	status = cryptInitEx();
#else
	status = cryptInit();
#endif /* TEST_LOWLEVEL */
	if( cryptStatusError( status ) )
		{
		printf( "cryptInit() failed with error code %d.\n", status );
		exit( EXIT_FAILURE );
		}

#ifndef TEST_RANDOM
	/* In order to avoid having to do a randomness poll for every test run,
	   we bypass the randomness-handling by adding some junk - it doesn't
	   matter here because we're not worried about security, but should never
	   be done in production code */
	cryptAddRandom( "a", 1 );
#endif /* TEST_RANDOM */

	/* For general testing purposes we can insert test code at this point to
	   test special cases which aren't covered in the general tests below */
	testKludge();

#ifdef TEST_LOWLEVEL
	/* Test the conventional encryption routines */
	for( cryptAlgo = CRYPT_ALGO_FIRST_CONVENTIONAL;
		 cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL; cryptAlgo++ )
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, NULL ) ) && \
			!testLowlevel( CRYPT_UNUSED, cryptAlgo, FALSE ) )
			goto errorExit;

	/* Test the public-key encryption routines */
	for( cryptAlgo = CRYPT_ALGO_FIRST_PKC;
		 cryptAlgo <= CRYPT_ALGO_LAST_PKC; cryptAlgo++ )
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, NULL ) ) && \
			!testLowlevel( CRYPT_UNUSED, cryptAlgo, FALSE ) )
				goto errorExit;

	/* Test the hash routines */
	for( cryptAlgo = CRYPT_ALGO_FIRST_HASH;
		 cryptAlgo <= CRYPT_ALGO_LAST_HASH; cryptAlgo++ )
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, NULL ) ) && \
			!testLowlevel( CRYPT_UNUSED, cryptAlgo, FALSE ) )
			goto errorExit;

	/* Test the MAC routines */
	for( cryptAlgo = CRYPT_ALGO_FIRST_MAC;
		 cryptAlgo <= CRYPT_ALGO_LAST_MAC; cryptAlgo++ )
		if( cryptStatusOK( cryptQueryCapability( cryptAlgo, NULL ) ) && \
			!testLowlevel( CRYPT_UNUSED, cryptAlgo, FALSE ) )
			goto errorExit;

	putchar( '\n' );
#else
	puts( "Skipping test of low-level encryption routines...\n" );
#endif /* TEST_LOWLEVEL */

	/* Test the randomness-gathering routines */
#ifdef TEST_RANDOM
	if( !testRandomRoutines() )
		{
		puts( "The self-test will proceed without using a strong random "
			  "number source.\n" );

		/* Kludge the randomness routines so we can continue the self-tests */
		cryptAddRandom( "a", 1 );
		}
#else
	puts( "Skipping test of randomness routines...\n" );
#endif /* TEST_RANDOM */

	/* Test the configuration options routines */
#ifdef TEST_CONFIG
	for( i = 0; configOption[ i ].option != CRYPT_ATTRIBUTE_NONE; i++ )
		{
		if( configOption[ i ].isNumeric )
			{
			int value;

			cryptGetOptionNumeric( configOption[ i ].option, &value );
			printf( "%s = %d.\n", configOption[ i ].name, value );
			}
		else
			{
			char buffer[ 256 ];
			int length;

			cryptGetOptionString( configOption[ i ].option, buffer, &length );
			buffer[ length ] = '\0';
			printf( "%s = %s.\n", configOption[ i ].name, buffer );
			}
		}

	putchar( '\n' );
#else
	puts( "Skipping display of config options...\n" );
#endif /* TEST_CONFIG */

	/* Test the crypto device routines */
#ifdef TEST_DEVICE
	status = testDevices();
	if( status == CRYPT_ERROR_NOTAVAIL )
		puts( "Handling for crypto devices doesn't appear to be enabled in "
			  "this build of\ncryptlib.\n" );
	else
		if( !status )
			goto errorExit;
#else
	puts( "Skipping test of crypto device routines...\n" );
#endif /* TEST_DEVICE */

	/* Test the mid-level routines.  This is implemented as a series of
	   separate function calls rather than a monolithic
	   if( a || b || c || ... ) block to make testing easier */
#ifdef TEST_MIDLEVEL
	if( !testLargeBufferEncrypt() )
		goto errorExit;
	if( !testDeriveKey() )
		goto errorExit;
	if( !testConventionalExportImport() )
		goto errorExit;
	if( !testKeyExportImport() )
		goto errorExit;
	if( !testSignData() )
		goto errorExit;
/*	Disabled for now since there's no useful DH mechanism defined in any
	standard.  Note that KEA is still tested via the Fortezza device test
	if( !testKeyAgreement() )
		goto errorExit; */
	if( !testKeygen() )
		goto errorExit;
	if( !testKeygenAsync() )
		goto errorExit;
	/* No need for putchar, mid-level functions leave a blank line at end */
#else
	puts( "Skipping test of mid-level encryption routines...\n" );
#endif /* TEST_MIDLEVEL */

	/* Test the certificate management routines */
#ifdef TEST_CERT
	if( !testCert() )
		goto errorExit;
	if( !testCACert() )
		goto errorExit;
	if( !testComplexCert() )
		goto errorExit;
	if( !testSETCert() )
		goto errorExit;
	if( !testAttributeCert() )
		goto errorExit;
	if( !testCertRequest() )
		goto errorExit;
	if( !testComplexCertRequest() )
		goto errorExit;
	if( !testCRMFRequest() )
		goto errorExit;
	if( !testComplexCRMFRequest() )
		goto errorExit;
	if( !testCRL() )
		goto errorExit;
	if( !testComplexCRL() )
		goto errorExit;
	if( !testCertChain() )
		goto errorExit;
	if( !testCMSAttributes() )
		goto errorExit;
	if( !testCertImport() )
		goto errorExit;
	if( !testCertReqImport() )
		goto errorExit;
	if( !testCRLImport() )
		goto errorExit;
	if( !testCertChainImport() )
		goto errorExit;
	if( !testSPKACImport() )
		goto errorExit;
#else
	puts( "Skipping test of certificate managment routines...\n" );
#endif /* TEST_CERT */

	/* Test the keyset read routines */
#ifdef TEST_KEYSET
	status = testGetPGPPublicKey();
	if( status == CRYPT_ERROR_NOTAVAIL )
		puts( "Couldn't find key files, skipping test of\nPGP keyset read "
			  "routines...\n" );
	else
		{
		if( !status )
			goto errorExit;
		if( !testGetPGPPrivateKey() )
			goto errorExit;
		}
	if( !testGetBorkenKey() )
		goto errorExit;
	if( !testReadWriteFileKey() )
		goto errorExit;
	if( !testReadFilePublicKey() )
		goto errorExit;
	if( !testDeleteFileKey() )
		goto errorExit;
	if( !testUpdateFileCert() )
		goto errorExit;
	if( !testReadFileCert() )
		goto errorExit;
	if( !testWriteFileCertChain() )
		goto errorExit;
	if( !testReadFileCertChain() )
		goto errorExit;
	if( !testSingleStepFileCert() )
		goto errorExit;
#ifdef TEST_KEYSET_SMARTCARD
	/* The following test is rather slow so we provide the ability to
	   disable this one separately */
	status = testWriteCardKey();
	if( status == CRYPT_ERROR_NOTAVAIL )
		puts( "Couldn't access any smart card readers, skipping test of "
			  "card key read\nroutines.\n" );
	else
		{
		if( !status )
			goto errorExit;
		if( !testReadCardKey() )
			goto errorExit;
		}
#endif /* TEST_KEYSET_SMARTCARD */
	status = testWriteCert();
	if( status == CRYPT_ERROR_NOTAVAIL )
		puts( "Handling for certificate databases doesn't appear to be "
			  "enabled in this\nbuild of cryptlib, skipping the test of "
			  "the certificate database routines.\n" );
	else
		{
		if( !status )
			goto errorExit;
		if( !testReadCert() )
			goto errorExit;
		if( !testKeysetQuery() )
			goto errorExit;
		}
	/* For the following tests we may have read access but not write access,
	   so we test a read of known-present certs before trying a write - 
	   unlike the local keysets we don't need to add a cert before we can try
	   reading it */
	status = testReadCertLDAP();
	if( status == CRYPT_ERROR_NOTAVAIL )
		puts( "Handling for LDAP certificate directories doesn't appear to "
			  "be enabled in\nthis build of cryptlib, skipping the test of "
			  "the certificate directory\nroutines.\n" );
	else
		/* LDAP access can fail if the directory doesn't use the standard
		   du jour, so we don't treat a failure as a fatal error */
		if( status )
			{
			if( !testWriteCertLDAP() )
				goto errorExit;
			}
	status = testReadCertHTTP();
	if( status == CRYPT_ERROR_NOTAVAIL )
		puts( "Handling for fetching certificates from web pages doesn't "
			  "appear to be\nenabled in this build of cryptlib, skipping "
			  "the test of the HTTP routines.\n" );
#else
	puts( "Skipping test of keyset read routines...\n" );
#endif /* TEST_KEYSET */

	/* Test the certificate processing functionality */
#ifdef TEST_CERTPROCESS
	if( !testCertProcess() )
		goto errorExit;
#else
	puts( "Skipping test of certificate handling process...\n" );
#endif /* TEST_CERTPROCESS */

	/* Test the high-level routines (these are similar to the mid-level
	   routines but rely on things like certificate management to work) */
#ifdef TEST_HIGHLEVEL
	if( !testKeyExportImportCMS() )
		goto errorExit;
	if( !testSignDataCMS() )
		goto errorExit;
#endif /* TEST_HIGHLEVEL */

	/* Test the enveloping routines */
#ifdef TEST_ENVELOPE
	if( !testEnvelopeData() )
		goto errorExit;
	if( !testLargeBufferEnvelopeData() )
		goto errorExit;
	if( !testEnvelopeCompress() )
		goto errorExit;
	if( !testEnvelopeSessionCrypt() )
		goto errorExit;
	if( !testEnvelopeCrypt() )
		goto errorExit;
	if( !testEnvelopePKCCrypt() )
		goto errorExit;
	if( !testEnvelopeSign() )
		goto errorExit;
	if( !testCMSEnvelopePKCCrypt() )
		goto errorExit;
	if( !testCMSEnvelopeSign() )
		goto errorExit;
	if( !testCMSEnvelopeDetachedSig() )
		goto errorExit;
	if( !testCMSImportSignedData() )
		goto errorExit;
#else
	puts( "Skipping test of enveloping routines...\n" );
#endif /* TEST_ENVELOPE */

	/* Test the session routines */
#ifdef TEST_SESSION
	status = testSessionSSL();
	if( status == CRYPT_ERROR_NOTAVAIL )
		puts( "Network access doesn't appear to be enabled in this build of "
			  "cryptlib,\nskipping the test of the SSL/TLS/SSH routines.\n" );
	else
		{
		if( !testSessionTLS() )
			goto errorExit;
		if( !testSessionSSH() )
			goto errorExit;
		}
#endif /* TEST_SESSION */

	/* Shut down cryptlib */
	status = cryptEnd();
	if( cryptStatusError( status ) )
		{
		printf( "cryptEnd() failed with error code %d.\n", status );
		goto errorExit1;
		}

	puts( "All tests concluded successfully." );
	return( EXIT_SUCCESS );

	/* All errors end up here */
errorExit:
	cryptEnd();
errorExit1:
	puts( "\nThe test was aborted due to an error being detected.  If you "
		  "want to report\nthis problem, please provide as much information "
		  "as possible to allow it to\nbe diagnosed, for example the call "
		  "stack, the location inside cryptlib where\nthe problem occurred, "
		  "and the values of any variables which might be\nrelevant." );
#ifdef __WINDOWS__
	/* The pseudo-CLI VC++ output windows are closed when the program exits
	   so we need to explicitly wait to allow the user to read them */
	puts( "\nHit a key..." );
	getchar();
#endif /* __WINDOWS__ */
	return( EXIT_FAILURE );
	}

/* Test the system-specific defines in crypt.h.  This is the last function in
   the file because we want to avoid any definitions in crypt.h messing with
   the rest of the test.c code.

   The following include is needed only so we can check whether the defines
   are set right.  crypt.h should never be included in a program which uses
   cryptlib */

#undef __WINDOWS__
#undef __WIN16__
#undef __WIN32__
#undef BOOLEAN
#undef BYTE
#undef FALSE
#undef TRUE
#ifdef _MSC_VER
  #include "../crypt.h"
#else
  #include "crypt.h"
#endif /* Braindamaged MSC include handling */

void testSystemSpecific( void )
	{
	int bigEndian;

	/* Make sure we've got the endianness set right.  If the machine is
	   big-endian (up to 64 bits) the following value will be signed,
	   otherwise it will be unsigned.  Unfortunately we can't test for
	   things like middle-endianness without knowing the size of the data
	   types */
	bigEndian = ( *( long * ) "\x80\x00\x00\x00\x00\x00\x00\x00" < 0 );
#ifdef DATA_LITTLEENDIAN
	if( bigEndian )
		{
		puts( "The CPU endianness define is set wrong in crypt.h, this "
			  "machine appears to be\nbig-endian, not little-endian.  Edit "
			  "the file and rebuild cryptlib." );
		exit( EXIT_FAILURE );
		}
#else
	if( !bigEndian )
		{
		puts( "The CPU endianness define is set wrong in crypt.h, this "
			  "machine appears to be\nlittle-endian, not big-endian.  Edit "
			  "the file and rebuild cryptlib." );
		exit( EXIT_FAILURE );
		}
#endif /* DATA_LITTLEENDIAN */

	/* If we're compiling under Windows or OS/2, make sure the LONG type is
	   correct */
#if defined( __WINDOWS__ ) || defined( __OS2__ )
	{
	LONG test = 0x80000000L;

	if( test < 0 )
		{
		puts( "typeof( LONG ) is incorrect.  It evaluates to a signed 32-bit "
			  "value rather\nthan an unsigned 32-bit value.  You need to edit "
			  "crypt.h and recompile \ncryptlib." );
		exit( EXIT_FAILURE );
		}
	}
#endif /* __WINDOWS__ || __OS2__ */
	}
