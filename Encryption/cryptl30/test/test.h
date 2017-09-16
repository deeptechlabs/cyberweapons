/****************************************************************************
*																			*
*						cryptlib Test Routines Header File					*
*						Copyright Peter Gutmann 1995-1999					*
*																			*
****************************************************************************/

/* Define the following to enable/disable various blocks of tests */

/*#define TEST_DEVICE			/* Needed if called in testKludge() */
#if 1
#define TEST_LOWLEVEL		/* Test low-level functions */
#define TEST_RANDOM			/* Test randomness functions */
#define TEST_CONFIG			/* Test configuration functions */
#define TEST_DEVICE			/* Test crypto device functions */
#define TEST_MIDLEVEL		/* Test high-level encr/sig.functions */
#endif /* 0 */
#if 1
#define TEST_CERT			/* Test certificate management functions */
#define TEST_KEYSET			/* Test keyset read functions */
#define TEST_CERTPROCESS	/* Test certificate handling process */
#define TEST_HIGHLEVEL		/* Test high-level encr/sig.functions */
#endif /* 0 */
#if 1
#define TEST_ENVELOPE		/* Test enveloping functions */
#endif /* 0 */

/* Some of the token-based tests can be rather slow, the following defines 
   disable these tests for speed reasons.  Note that the Fortezza test can
   be further cut down by not performing the CAW test (which erases any
   existing data on the card), this is turned off by default in testhl.c */

/* #define TEST_KEYSET_SMARTCARD */
/* #define TEST_DEVICE_FORTEZZA */

/* When commenting out code for testing, the following macro displays a 
   warning that the behaviour has been changed as well as the location of
   the change */

#define KLUDGE_WARN( str )	\
		printf( "Kludging " str ", file " __FILE__ ", line %d.\n", __LINE__ );

#include <time.h>

/* Various useful types */

#define BOOLEAN	int
#define BYTE	unsigned char
#ifndef TRUE
  #define FALSE	0
  #define TRUE	!FALSE
#endif /* TRUE */

/* Sentinel value used to denote non-data/non-values */

#define SENTINEL		-1000

/* There are a few OS's broken enough not to define the standard exit codes
   (SunOS springs to mind) so we define some sort of equivalent here just
   in case */

#ifndef EXIT_SUCCESS
  #define EXIT_SUCCESS	0
  #define EXIT_FAILURE	!EXIT_SUCCESS
#endif /* EXIT_SUCCESS */

/* If we're using a DOS compiler but not a 32-bit one, record this */

#if defined( __MSDOS__ ) && !defined( __MSDOS32__ )
  #define __MSDOS16__
#endif /* __MSDOS__ && !__MSDOS32__ */

/* In certain memory-starved environments we have to kludge things to help
   the compiler along.  The following define tells the compiler to move BSS
   data outside the default data segment */

#if defined( _MSC_VER ) && ( _MSC_VER <= 800 )
  #define FAR_BSS			far
#else
  #define FAR_BSS
#endif /* Win16 */

/* The key size to use for the PKC routines.  This is the minimum allowed by
   cryptlib, it speeds up the various tests but shouldn't be used in
   practice */

#define PKC_KEYSIZE			512

/* The names of the test key and certificate files.  DSA/RSA_PRIVKEY_FILE is
   the test private key file which is created and modified during the testing
   process. CA_PRIVKEY_FILE and USER_PRIVKEY_FILE are the CA private key +
   cert and user private key + cert chain.  For flat filesystems, we give the
   test files names starting with 'z' so they're easier to find */

#if defined( _MSC_VER )
  #define TEST_PRIVKEY_FILE		"../test/test_key.p15"
  #define CA_PRIVKEY_FILE		"../test/ca_key.p15"
  #define USER_PRIVKEY_FILE		"../test/user_key.p15"

  #define PGP_PUBKEY_FILE		"../test/pubring.pgp"
  #define PGP_PRIVKEY_FILE		"../test/secring.pgp"
  #define PKCS12_FILE			"../test/key.p12"

  #define CERT_FILE				"../test/cert.der"
  #define CERTREQ_FILE			"../test/cert_req.der"
  #define CRL_FILE				"../test/cert_crl.der"
  #define CERTCHAIN_FILE		"../test/cert_chn.der"
  #define SPKAC_FILE			"../test/cert_spk.der"
  #define CRLCERT1_FILE			"../test/crlcert1.der"
  #define CRLCERT2_FILE			"../test/crlcert2.der"

  #define SMIME_SIGNED_FILE		"../test/smime.p7s"
  #define SMIME_ENVELOPED_FILE	"../test/smime.p7m"

  #define COMPRESS_FILE			"../test/test.h"
#elif defined( __VMCMS__ )
  #define TEST_PRIVKEY_FILE		"ztestkey.p15"
  #define CA_PRIVKEY_FILE		"zcakey.p15"
  #define USER_PRIVKEY_FILE		"zuserkey.p15"

  #define PGP_PUBKEY_FILE		"zpubring.pgp"
  #define PGP_PRIVKEY_FILE		"zsecring.pgp"
  #define PKCS12_FILE			"zkey.p12"

  #define CERT_FILE				"zcert.der"
  #define CERTREQ_FILE			"zcertreq.der"
  #define CRL_FILE				"zcertcrl.der"
  #define CERTCHAIN_FILE		"zcertchn.der"
  #define SPKAC_FILE			"zcertspk.der"
  #define CRLCERT1_FILE			"zcrlcrt1.der"
  #define CRLCERT2_FILE			"zcrlcrt2.der"

  #define SMIME_SIGNED_FILE		"zsmime.p7s"
  #define SMIME_ENVELOPED_FILE	"zsmime.p7m"

  #define COMPRESS_FILE			"test.h"
#elif defined( __OS400__ )
  #define TEST_PRIVKEY_FILE		"testlib/ztestkey"
  #define CA_PRIVKEY_FILE		"testlib/zcakey"
  #define USER_PRIVKEY_FILE		"testlib/zuserkey"

  #define PGP_PUBKEY_FILE		"testlib/zpubring"
  #define PGP_PRIVKEY_FILE		"testlib/zsecring"
  #define PKCS12_FILE			"testlib/zkey"

  #define CERT_FILE				"testlib/zcert"
  #define CERTREQ_FILE			"testlib/zcertreq"
  #define CRL_FILE				"testlib/zcertcrl"
  #define CERTCHAIN_FILE		"testlib/zcertchn"
  #define SPKAC_FILE			"testlib/zcertspk"
  #define CRLCERT1_FILE			"testlib/zcrlcrt1"
  #define CRLCERT2_FILE			"testlib/zcrlcrt2"

  #define SMIME_SIGNED_FILE		"testlib/zsmime"
  #define SMIME_ENVELOPED_FILE	"testlib/zsmime"

  #define COMPRESS_FILE			"testlib/test"
#else
  #define TEST_PRIVKEY_FILE		"test/test_key.p15"
  #define CA_PRIVKEY_FILE		"test/ca_key.p15"
  #define USER_PRIVKEY_FILE		"test/user_key.p15"

  #define PGP_PUBKEY_FILE		"test/pubring.pgp"
  #define PGP_PRIVKEY_FILE		"test/secring.pgp"
  #define PKCS12_FILE			"test/key.p12"

  #define CERT_FILE				"test/cert.der"
  #define CERTREQ_FILE			"test/cert_req.der"
  #define CRL_FILE				"test/cert_crl.der"
  #define CERTCHAIN_FILE		"test/cert_chn.der"
  #define SPKAC_FILE			"test/cert_spk.der"
  #define CRLCERT1_FILE			"test/crlcert1.der"
  #define CRLCERT2_FILE			"test/crlcert2.der"

  #define SMIME_SIGNED_FILE		"test/smime.p7s"
  #define SMIME_ENVELOPED_FILE	"test/smime.p7m"

  #define COMPRESS_FILE			"test/test.h"
#endif /* More MSC braindamage */

/* The passwords for private keys */

#define TEST_PRIVKEY_PASSWORD	"test"
#define CA_PRIVKEY_PASSWORD		"test"
#define USER_PRIVKEY_PASSWORD	"test"

/* The database keyset type and name.  Under Windoze we use ODBC, for
   anything else we use the first database which is enabled by a preprocessor
   define, defaulting to mSQL (which doesn't have to be available, if it's
   not present we continue after printing a warning) */

#if defined( _MSC_VER )
  #define DATABASE_KEYSET_TYPE	CRYPT_KEYSET_ODBC
#elif defined( DBX_BSQL )
  #define DATABASE_KEYSET_TYPE	CRYPT_KEYSET_BSQL
#elif defined( DBX_MSQL )
  #define DATABASE_KEYSET_TYPE	CRYPT_KEYSET_MSQL
#elif defined( DBX_MYSQL )
  #define DATABASE_KEYSET_TYPE	CRYPT_KEYSET_MYSQL
#elif defined( DBX_ORACLE )
  #define DATABASE_KEYSET_TYPE	CRYPT_KEYSET_ORACLE
#elif defined( DBX_POSTGRES )
  #define DATABASE_KEYSET_TYPE	CRYPT_KEYSET_POSTGRES
#elif defined( DBX_RAIMA )
  #define DATABASE_KEYSET_TYPE	CRYPT_KEYSET_RAIMA
#elif defined( DBX_SOLID )
  #define DATABASE_KEYSET_TYPE	CRYPT_KEYSET_SOLID
#else
  #define DATABASE_KEYSET_TYPE	CRYPT_KEYSET_MSQL
#endif /* Various database backends */
#define DATABASE_KEYSET_NAME	"testkeys"

/* The LDAP keyset name (this one seems to contain some certs in some places)
   and names of known-present certs and CRL's.  There's a list of more LDAP 
   servers at http://www.dante.net/np/pdi.html, none of these are known to 
   contain certificates */

#define LDAP_KEYSET_NAME		"ds.katalog.posten.se"
#define LDAP_CERT_NAME			"cn=Posten CertPolicy_eIDKort_1 CA_nyckel_1, " \
								"o=Posten_Sverige_AB 556451-4148, c=SE"
#define LDAP_CRL_NAME			"cn=Posten CertPolicy_eIDKort_1 CA_nyckel_1, " \
								"o=Posten_Sverige_AB 556451-4148, c=SE"

/* The HTTP keyset names (actually URL's for page's containing a cert and 
   CRL) */

#define HTTP_KEYSET_CERT_NAME	"www.thawte.com/persfree.crt"
#define HTTP_KEYSET_CRL_NAME	"crl.verisign.com/Class1Individual.crl"

/* The SSH, SSL, amd TLS server names and authentication information */

#define SSH_SERVER_NAME			"localhost"
#define SSH_USER_NAME			"test"
#define SSH_PASSWORD			"test"
#define SSL_SERVER_NAME			"www.amazon.com"
#define TLS_SERVER_NAME			"www.amazon.com"

/* Labels for the various public-key objects.  These are needed when the
   underlying implemenation creates persistent objects (eg keys held in PKCS 
   #11 tokens) which need to be identified */

#define RSA_PUBKEY_LABEL		"Test RSA public key"
#define RSA_PRIVKEY_LABEL		"Test RSA private key"
#define RSA_BIG_PRIVKEY_LABEL	"Test RSA big private key"
#define DSA_PUBKEY_LABEL		"Test DSA sigcheck key"
#define DSA_PRIVKEY_LABEL		"Test DSA signing key"
#define ELGAMAL_PUBKEY_LABEL	"Test Elgamal public key"
#define ELGAMAL_PRIVKEY_LABEL	"Test Elgamal private key"
#define DH_KEY1_LABEL			"Test DH key #1"
#define DH_KEY2_LABEL			"Test DH key #2"
#define CA_PRIVKEY_LABEL		RSA_PRIVKEY_LABEL
#define USER_PRIVKEY_LABEL		"Test user key"
#define USER_EMAIL				"dave@wetaburgers.com"

/* A structure which allows us to specify a collection of extension
   components.  This is used when adding a collection of extensions to a
   cert */

typedef enum { IS_VOID, IS_NUMERIC, IS_STRING, IS_TIME } COMPONENT_TYPE;

typedef struct {
	const CRYPT_ATTRIBUTE_TYPE type;/* Extension component ID */
	const COMPONENT_TYPE componentType;	/* Component type */
	const int numericValue;			/* Value if numeric */
	const char *stringValue;		/* Value if string */
	const time_t timeValue;			/* Value if time */
	} CERT_DATA;

/* Prototypes for functions in certutil.c */

void printCertErrorInfo( const CRYPT_CERTIFICATE certificate );
void printCertInfo( const CRYPT_CERTIFICATE certificate );
void printCertChainInfo( const CRYPT_CERTIFICATE certChain );
int importCertFile( CRYPT_CERTIFICATE *cryptCert, const char *fileName );
int addCertFields( const CRYPT_CERTIFICATE certificate,
				   const CERT_DATA *certData );
int getPrivateKey( CRYPT_CONTEXT *cryptContext, const char *keysetName,
				   const char *keyName, const char *password );
void debugDump( const char *fileName, const void *data,
				const int dataLength );

/* Prototypes for functions in testlib.c */

BOOLEAN loadRSAContexts( const CRYPT_DEVICE cryptDevice,
						 CRYPT_CONTEXT *cryptContext,
						 CRYPT_CONTEXT *decryptContext );
BOOLEAN loadDSAContexts( const CRYPT_DEVICE cryptDevice,
						 CRYPT_CONTEXT *signContext,
						 CRYPT_CONTEXT *sigCheckContext );
BOOLEAN loadElgamalContexts( CRYPT_CONTEXT *cryptContext,
							 CRYPT_CONTEXT *decryptContext );
BOOLEAN loadDHContexts( CRYPT_CONTEXT *cryptContext1,
						CRYPT_CONTEXT *cryptContext2, int keySize );
void destroyContexts( const CRYPT_DEVICE cryptDevice,
					  CRYPT_CONTEXT cryptContext, 
					  CRYPT_CONTEXT decryptContext );
CRYPT_ALGO selectCipher( const CRYPT_ALGO algorithm );
