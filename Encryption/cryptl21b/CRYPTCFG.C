/****************************************************************************
*																			*
*						 cryptlib Configuration Routines					*
*						Copyright Peter Gutmann 1994-1999					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "stream.h"
#else
  #include "keymgmt/stream.h"
#endif /* Compiler-specific includes */

/* Prototypes for functions in keymgmt/certrust.c */

int setTrustItem( void *itemBuffer, const int itemLength,
				  const BOOLEAN isEncoded );
int getTrustItem( void **statePtr, int *stateIndex, void *itemBuffer,
				  int *itemLength, const BOOLEAN encodeData );

/* Prototypes for functions in misc/registry.c */

#ifdef __WIN32__

int beginRegistryUpdate( const BOOLEAN isRead, HANDLE *h1, HANDLE *h2 );
int endRegistryUpdate( HANDLE h1, HANDLE h2 );
int readRegistryString( HANDLE h1, const char *keyName, char *string );
int readRegistryBinary( HANDLE h1, const char *keyName, void *value,
						int *length );
int readRegistryValue( HANDLE h1, const char *keyName, int *value );
int writeRegistryString( HANDLE h1, const char *keyName, const char *string );
int writeRegistryBinary( HANDLE h1, const char *keyName, const void *value,
						 const int length );
int writeRegistryValue( HANDLE h1, const char *keyName, const int value );

#endif /* __WIN32__ */

/****************************************************************************
*																			*
*							Configuration Options							*
*																			*
****************************************************************************/

/* The configuration options are stored in a hierarchical structure a bit
   like the Windows registry.  For systems which don't have an equivalent of
   the registry, we store the options in a text file with the option name as
   a string with the steps in the heirarcy separated by dots.  The initial
   options are hardcoded, if any of the values are changed they're written
   either to the systemwide config area or to the per-user config area.  For
   the flat-file storage method, only the non-default values are written, if
   the config area contains a setting which is equal to the default setting
   it's deleted.  For registry storage this would be too slow, instead we
   only write options which have been changed during the current session */

/* Configuration option types */

typedef enum {
	OPTION_NONE,					/* Non-option */
	OPTION_STRING,					/* Literal string */
	OPTION_NUMERIC,					/* Numeric value */
	OPTION_BOOLEAN					/* Boolean flag */
	} OPTION_TYPE;

/* Multivalued configuration option mapping categories (see the config
   options comment for an explanation of these) */

typedef enum {
	MAPCAT_NONE,					/* No mapping category */
	MAPCAT_KEYS_PUBLIC,				/* Encryption PKC databases */
	MAPCAT_KEYS_PRIVATE,			/* Decryption PKC databases */
	MAPCAT_KEYS_SIGCHECK,			/* Sig.check PKC databases */
	MAPCAT_KEYS_SIGNATURE			/* Sig.generation PKC databases */
	} MAP_CAT;

/* The configuration options.  The mapping option information is used for
   special-case config options where the option selects one of a number of
   other options.  If the value is set to CRYPT_ERROR then it's a normal
   option.  If it's set to CRYPT_OK then it's a mapping source and the
   integer option value selects another config option.  If it's set to a
   value other than CRYPT_OK and CRYPT_ERROR then it's a mapping target and
   contains one of integer values which may be held by the mapping source.
   The mapping category binds a mapping source and a collection of mapping
   targets together.

   To map a source to a target, we get the option value and then search all
   other options with the same mapping category as the source to find the
   required target */

typedef struct {
	const CRYPT_OPTION_TYPE option;	/* Magic number for this option */
	const char FAR_BSS *name;		/* Full path of option */
	const OPTION_TYPE type;			/* Option type */
	char *strValue;					/* Value if it's a string option */
	char *fqStrValue;				/* Fully qualified string value */
	int intValue;					/* Value if it's a numeric/boolean */
	const int lowRange;
	const int highRange;			/* Min/max allowed if numeric/boolean */
	const char FAR_BSS *strDefault;	/* Default if it's a string option */
	const int intDefault;			/* Default if it's a numeric/boolean */
	const BOOLEAN nullStringOK;		/* Whether an empty string setting is OK */
	const BOOLEAN localValue;		/* Whether per-user or systemwide option */
	const int mapOption;			/* Config mapping option */
	const MAP_CAT mapCategory;		/* Config mapping option category */
	const BOOLEAN readOnly;			/* Whether option can't be changed */
	BOOLEAN dirty;					/* Whether option has been changed */
	} OPTION_INFO;

static OPTION_INFO FAR_BSS configOptions[] = {
	/* Dummy entry for CRYPT_OPTION_NONE */
	{ CRYPT_OPTION_NONE, 0 },

	/* cryptlib information (read-only) */
	{ CRYPT_OPTION_INFO_DESCRIPTION, "Info.Description", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  "cryptlib encryption library",
	  0, FALSE, TRUE, CRYPT_ERROR, MAPCAT_NONE, TRUE, FALSE },
	{ CRYPT_OPTION_INFO_COPYRIGHT, "Info.Copyright", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  "Copyright Peter Gutmann, Eric Young, 1994-1999",
	  0, FALSE, TRUE, CRYPT_ERROR, MAPCAT_NONE, TRUE, FALSE },
	{ CRYPT_OPTION_INFO_MAJORVERSION, "Info.MajorVersion", OPTION_NUMERIC,
	  NULL, NULL, 0, 0, 0,
	  NULL, 2, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, TRUE, FALSE },
	{ CRYPT_OPTION_INFO_MINORVERSION, "Info.MinorVersion", OPTION_NUMERIC,
	  NULL, NULL, 0, 0, 0,
	  NULL, 10, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, TRUE, FALSE },

	/* Conventional encryption/hash/MAC options */
	{ CRYPT_OPTION_ENCR_ALGO, "Encryption.Algorithm", OPTION_NUMERIC,
	  NULL, NULL, 0, CRYPT_ALGO_FIRST_CONVENTIONAL, CRYPT_ALGO_LAST_CONVENTIONAL,
	  NULL, CRYPT_ALGO_3DES, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_ENCR_MODE, "Encryption.Mode", OPTION_NUMERIC,
	  NULL, NULL, 0, CRYPT_MODE_FIRST_CONVENTIONAL, CRYPT_MODE_LAST_CONVENTIONAL,
	  NULL, CRYPT_MODE_CBC, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_ENCR_HASH, "Encryption.Hash", OPTION_NUMERIC,
	  NULL, NULL, 0, CRYPT_ALGO_FIRST_HASH, CRYPT_ALGO_LAST_HASH,
	  NULL, CRYPT_ALGO_SHA, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },

	/* PKC options */
	{ CRYPT_OPTION_PKC_ALGO, "Public_Key_Encryption.Algorithm", OPTION_NUMERIC,
	  NULL, NULL, 0, CRYPT_ALGO_FIRST_PKC, CRYPT_ALGO_LAST_PKC,
	  NULL, CRYPT_ALGO_RSA, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_PKC_KEYSIZE, "Public_Key_Encryption.Keysize", OPTION_NUMERIC,
	  NULL, NULL, 0, bitsToBytes( 512 ), CRYPT_MAX_PKCSIZE,
	  NULL, bitsToBytes( 1024 ), FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },

	/* Signature options */
	{ CRYPT_OPTION_SIG_ALGO, "Signature.Algorithm", OPTION_NUMERIC,
	  NULL, NULL, 0, CRYPT_ALGO_FIRST_PKC, CRYPT_ALGO_LAST_PKC,
	  NULL, CRYPT_ALGO_RSA, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_SIG_KEYSIZE, "Signature.Keysize", OPTION_NUMERIC,
	  NULL, NULL, 0, bitsToBytes( 512 ), CRYPT_MAX_PKCSIZE,
	  NULL, bitsToBytes( 1024 ), FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },

	/* Keying options */
	{ CRYPT_OPTION_KEYING_ALGO, "Keying.Algorithm", OPTION_NUMERIC,
	  NULL, NULL, 0, CRYPT_ALGO_FIRST_HASH, CRYPT_ALGO_LAST_HASH,
	  NULL, CRYPT_ALGO_SHA, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_KEYING_ITERATIONS, "Keying.Iterations", OPTION_NUMERIC,
	  NULL, NULL, 0, 1, 20000,
	  NULL, 100, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },

	/* Certificate options */
	{ CRYPT_OPTION_CERT_CREATEV3CERT, "Certificate.Create_V3_Certificates", OPTION_BOOLEAN,
	  NULL, NULL, 0, FALSE, TRUE,
	  NULL, TRUE, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_CERT_PKCS10ALT, "Certificate.PKCS10_Alternative_Encoding", OPTION_BOOLEAN,
	  NULL, NULL, 0, FALSE, TRUE,
	  NULL, FALSE, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_CERT_CHECKENCODING, "Certificate.Check_Encoding", OPTION_BOOLEAN,
	  NULL, NULL, 0, FALSE, TRUE,
	  NULL, TRUE, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_CERT_FIXSTRINGS, "Certificate.Fix_String_Encoding", OPTION_BOOLEAN,
	  NULL, NULL, 0, FALSE, TRUE,
	  NULL, TRUE, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_CERT_FIXEMAILADDRESS, "Certificate.Fix_EmailAddress_Encoding", OPTION_BOOLEAN,
	  NULL, NULL, 0, FALSE, TRUE,
	  NULL, TRUE, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_CERT_ISSUERNAMEBLOB, "Certificate.IssuerName_Blob", OPTION_BOOLEAN,
	  NULL, NULL, 0, FALSE, TRUE,
	  NULL, TRUE, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_CERT_KEYIDBLOB, "Certificate.KeyID_Blob", OPTION_BOOLEAN,
	  NULL, NULL, 0, FALSE, TRUE,
	  NULL, TRUE, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES, "Certificate.Sign_Unrecognised_Attributes", OPTION_BOOLEAN,
	  NULL, NULL, 0, FALSE, TRUE,
	  NULL, FALSE, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_CERT_TRUSTCHAINROOT, "Certificate.Trust_Chain_Root", OPTION_BOOLEAN,
	  NULL, NULL, 0, FALSE, TRUE,
	  NULL, FALSE, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_CERT_VALIDITY, "Certificate.Validity", OPTION_NUMERIC,
	  NULL, NULL, 0, 1, 7300,
	  NULL, 365, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_CERT_UPDATEINTERVAL, "Certificate.Update_Interval", OPTION_NUMERIC,
	  NULL, NULL, 0, 1, 365,
	  NULL, 90, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_CERT_ENCODE_VALIDITYNESTING, "Certificate.Encode_Validity_Nesting", OPTION_BOOLEAN,
	  NULL, NULL, 0, FALSE, TRUE,
	  NULL, TRUE, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_CERT_DECODE_VALIDITYNESTING, "Certificate.Decode_Validity_Nesting", OPTION_BOOLEAN,
	  NULL, NULL, 0, FALSE, TRUE,
	  NULL, FALSE, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_CERT_ENCODE_CRITICAL, "Certificate.Encode_Critical", OPTION_BOOLEAN,
	  NULL, NULL, 0, FALSE, TRUE,
	  NULL, TRUE, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_CERT_DECODE_CRITICAL, "Certificate.Decode_Critical", OPTION_BOOLEAN,
	  NULL, NULL, 0, FALSE, TRUE,
	  NULL, TRUE, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },

	/* Keyset options */
	{ CRYPT_OPTION_KEYS_PUBLIC, "Key_Database.Default_Public", OPTION_NUMERIC,
	  NULL, NULL, 0, CRYPT_KEYSET_NONE + 1, CRYPT_KEYSET_LAST - 1,
	  NULL, 0, FALSE, FALSE, CRYPT_OK, MAPCAT_KEYS_PUBLIC, FALSE, FALSE },
	{ CRYPT_OPTION_KEYS_PRIVATE, "Key_Database.Default_Private", OPTION_NUMERIC,
	  NULL, NULL, 0, CRYPT_KEYSET_NONE + 1, CRYPT_KEYSET_LAST - 1,
	  NULL, 0, FALSE, FALSE, CRYPT_OK, MAPCAT_KEYS_PRIVATE, FALSE },
	{ CRYPT_OPTION_KEYS_SIGCHECK, "Key_Database.Default_Sigature_Check", OPTION_NUMERIC,
	  NULL, NULL, 0, CRYPT_KEYSET_NONE + 1, CRYPT_KEYSET_LAST - 1,
	  NULL, 0, FALSE, FALSE, CRYPT_OK, MAPCAT_KEYS_SIGCHECK, FALSE, FALSE },
	{ CRYPT_OPTION_KEYS_SIGNATURE, "Key_Database.Default_Signature", OPTION_NUMERIC,
	  NULL, NULL, 0, CRYPT_KEYSET_NONE + 1, CRYPT_KEYSET_LAST - 1,
	  NULL, 0, FALSE, FALSE, CRYPT_OK, MAPCAT_KEYS_SIGNATURE, FALSE, FALSE },

	/* File keyset options */
	{ CRYPT_OPTION_KEYS_FILE_PRIVATE, "Key_Database.File.Private", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  NULL, 0, FALSE, TRUE, CRYPT_KEYSET_FILE, MAPCAT_KEYS_PRIVATE, FALSE, FALSE },
	{ CRYPT_OPTION_KEYS_FILE_SIGNATURE, "Key_Database.File.Signature", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  NULL, 0, FALSE, TRUE, CRYPT_KEYSET_FILE, MAPCAT_KEYS_SIGNATURE, FALSE, FALSE },

	/* PGP keyset options */
	{ CRYPT_OPTION_KEYS_PGP_PUBLIC, "Key_Database.PGP.Public", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  "%PGPPATH%/pubring.pgp", 0, FALSE, TRUE, CRYPT_KEYSET_FILE,
	  MAPCAT_KEYS_PUBLIC, FALSE, FALSE },
	{ CRYPT_OPTION_KEYS_PGP_PRIVATE, "Key_Database.PGP.Private", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  "%PGPPATH%/secring.pgp", 0, FALSE, TRUE, CRYPT_KEYSET_FILE,
	  MAPCAT_KEYS_PRIVATE, FALSE, FALSE },
	{ CRYPT_OPTION_KEYS_PGP_SIGCHECK, "Key_Database.PGP.Signature_Check", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  "%PGPPATH%/pubring.pgp", 0, FALSE, TRUE, CRYPT_KEYSET_FILE,
	  MAPCAT_KEYS_SIGCHECK, FALSE, FALSE },
	{ CRYPT_OPTION_KEYS_PGP_SIGNATURE, "Key_Database.PGP.Signature", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  "%PGPPATH%/secring.pgp", 0, FALSE, TRUE, CRYPT_KEYSET_FILE,
	  MAPCAT_KEYS_SIGNATURE, FALSE, FALSE },

	/* RDBMS keyset options */
	{ CRYPT_OPTION_KEYS_DBMS_NAMETABLE, "Key_Database.DBMS.Name_Table", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  "PublicKeys", 0, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_KEYS_DBMS_NAMECRLTABLE, "Key_Database.DBMS.Name_CRL_Table", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  "CRLs", 0, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_KEYS_DBMS_NAME_C, "Key_Database.DBMS.Name_C", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  "PK_C", 0, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_KEYS_DBMS_NAME_SP, "Key_Database.DBMS.Name_SP", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  "PK_SP", 0, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_KEYS_DBMS_NAME_L, "Key_Database.DBMS.Name_L", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  "PK_L", 0, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_KEYS_DBMS_NAME_O, "Key_Database.DBMS.Name_O", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  "PK_O", 0, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_KEYS_DBMS_NAME_OU, "Key_Database.DBMS.Name_OU", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  "PK_OU", 0, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_KEYS_DBMS_NAME_CN, "Key_Database.DBMS.Name_CN", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  "Name", 0, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_KEYS_DBMS_NAMEEMAIL, "Key_Database.DBMS.Name_Email", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  "Email", 0, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_KEYS_DBMS_NAMEDATE, "Key_Database.DBMS.Name_Date", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  "PK_Date", 0, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_KEYS_DBMS_NAMENAMEID, "Key_Database.DBMS.Name_NameID", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  "PK_NameID", 0, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_KEYS_DBMS_NAMEISSUERID, "Key_Database.DBMS.Name_IssuerID", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  "PK_IssuerID", 0, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_KEYS_DBMS_NAMEKEYID, "Key_Database.DBMS.Name_KeyID", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  "PK_KeyID", 0, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_KEYS_DBMS_NAMEKEYDATA, "Key_Database.DBMS.Name_Key_Data", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  "PK_KeyData", 0, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },

	/* HTTP keyset access options */
	{ CRYPT_OPTION_KEYS_HTTP_PROXY, "Key_Database.HTTP.Proxy", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  NULL, 0, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_KEYS_HTTP_TIMEOUT, "Key_Database.HTTP.Timeout", OPTION_NUMERIC,
	  NULL, NULL, 0, 5, 300,
	  NULL, 60, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },

	/* LDAP keyset options */
	{ CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS, "Key_Database.LDAP.ObjectClass", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  "inetOrgPerson", 0, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_CACERTNAME, "Key_Database.LDAP.CA_Certificate_Name", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  "cACertificate;binary", 0, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_CERTNAME, "Key_Database.LDAP.Certificate_Name", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  "userCertificate;binary", 0, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_CRLNAME, "Key_Database.LDAP.CRL_Name", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  "certificateRevocationList;binary", 0, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_EMAILNAME, "Key_Database.LDAP.Email_Address_Name", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  "emailAddress", 0, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },

	/* Crypto device options */
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR01, "Device.PKCS11.Driver01", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  NULL, FALSE, FALSE, TRUE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR02, "Device.PKCS11.Driver02", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  NULL, FALSE, FALSE, TRUE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR03, "Device.PKCS11.Driver03", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  NULL, FALSE, FALSE, TRUE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR04, "Device.PKCS11.Driver04", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  NULL, FALSE, FALSE, TRUE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR05, "Device.PKCS11.Driver05", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  NULL, FALSE, FALSE, TRUE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_DEVICE_SERIALRNG, "Device.Serial_RNG", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  NULL, FALSE, FALSE, TRUE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_DEVICE_SERIALRNG_PARAMS, "Device.Serial_RNG_Parameters", OPTION_STRING,
	  NULL, NULL, 0, 0, 0,
	  NULL, FALSE, FALSE, TRUE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_DEVICE_SERIALRNG_ONLY, "Device.Serial_RNG_Only", OPTION_BOOLEAN,
	  NULL, NULL, 0, FALSE, TRUE,
	  NULL, FALSE, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },

	/* CMS options */
	{ CRYPT_OPTION_CMS_DEFAULTATTRIBUTES, "Certificate.CMS.Default_Attributes", OPTION_BOOLEAN,
	  NULL, NULL, 0, FALSE, TRUE,
	  NULL, TRUE, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },

	/* Miscellaneous options */
	{ CRYPT_OPTION_MISC_FORCELOCK, "Miscellaneous.Force_Memory_Lock", OPTION_BOOLEAN,
	  NULL, NULL, 0, FALSE, TRUE,
	  NULL, FALSE, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_MISC_ASYNCINIT, "Miscellaneous.Asynchronous_Initialisation", OPTION_BOOLEAN,
	  NULL, NULL, 0, FALSE, TRUE,
	  NULL, TRUE, FALSE, FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE },
	{ CRYPT_OPTION_NONE, NULL, OPTION_NONE, NULL, NULL, 0, 0, 0, NULL, 0, 0,
	  FALSE, CRYPT_ERROR, MAPCAT_NONE, FALSE, FALSE }
	};

/* Locking variables to handle access to the configuration information in a
   multithreaded environment.  Note that the functions which return strings
   aren't entirely thread-safe since they return pointers to the string
   storage rather than copying them out, so the value can change after the
   function is called but before the value is used.  It's possible that this
   behaviour isn't correct, but it's a lot easier than taking a snapshot of
   the requested config option when the getXXX() function is called, which
   requires a lot of extra work on the calling side */

DECLARE_LOCKING_VARS( config )

/****************************************************************************
*																			*
*						Set/Query Library-wide Config Options				*
*																			*
****************************************************************************/

/* Some string options aren't fully qualified (for example they may contain
   portions which have to be obtained from the environment).  The following
   function fully expands the string by searching for environment variable
   names delimited by '%'s and returns the expanded string, a pointer to the
   original if there's nothing to be expanded, or NULL if the allocation of
   the expanded string fails */

#if defined( __MSDOS__ ) || defined( __WINDOWS__ ) || defined( __OS2__ )
  #define FULLPATH_SEPERATORS	"\\/:"	/* Seperators in full paths */
  #define PATH_SEPERATORS		"\\/"	/* Seperators between path components */
  #define DIR_SEPERATOR			'/'		/* Seperator to insert */
#elif defined( __UNIX__ ) || defined( __BEOS__ )
  #define FULLPATH_SEPERATORS	"/"
  #define PATH_SEPERATORS		"/"
  #define DIR_SEPERATOR			'/'
#elif defined( __TANDEM__ )
  #define PATH_SEPERATOR		"."
  #define PATH_SEPERATORS		"."
  #define DIR_SEPERATOR			'.'
#else
  #error Need to define filesystem path component seperator in cryptcfg.c
#endif /* OS-specific path component seperators */

static char *qualifyString( const char *string )
	{
	char envVarName[ 128 ], *envPtr, *retVal;
	int startIndex, endIndex, endLen, envLen, oldEnvLen, needsSeperator = 0;

	/* Some strings don't have any value set */
	if( string == NULL )
		return( NULL );

	/* Look for the start qualifier */
	for( startIndex = 0; string[ startIndex ] && string[ startIndex ] != '%';
		 startIndex++ );
	if( !string[ startIndex ] )
		return( ( char * ) string );

	/* Look for the end qualifier */
	for( endIndex = startIndex + 1; string[ endIndex ] && \
		 string[ endIndex ] != '%'; endIndex++ );
	if( !string[ endIndex ] )
		return( ( char * ) string );

	/* Make sure the environment variable name is of a sensible length and
	   extract it from the string */
	envLen = endIndex - ( startIndex + 1 );
	if( envLen < 1 || envLen >= 128 )
		return( NULL );
	memcpy( envVarName, string + startIndex + 1, envLen );
	envVarName[ envLen ] = '\0';
	endLen = strlen( string + endIndex + 1 );

	/* Try and get the environment variable and build the expanded string
	   with it.  Note that we have to be very careful here because a race
	   condition with getenv/setenv could allow a buffer overflow attack if
	   the length of the environment string changes, so we remember the
	   length of the string (rather than calling strlen/strcpy later) and
	   call strncpy instead.  Just to be safe, we also perform a sanity check
	   on the length after we've copied it */
	envPtr = getenv( envVarName );
	if( envPtr == NULL )
		return( NULL );
	oldEnvLen = envLen = strlen( envPtr );
	if( strchr( PATH_SEPERATORS, string[ endIndex + 1 ] ) == NULL )
		{
		/* If there are no path seperators at the end of the environment
		   string or the start of the rest of the string, remember that we
		   need to add one */
		if( strchr( FULLPATH_SEPERATORS, envPtr[ envLen - 1 ] ) == NULL )
			needsSeperator++;
		}
	else
		/* If there's a seperator at the end of the environment string and the
		   start of the rest of the string, zap the one at the end of the
		   enrivonment string */
		if( strchr( PATH_SEPERATORS, envPtr[ envLen - 1 ] ) != NULL )
			envLen--;	/* Duplicate seperators, skip one of the two */
	if( ( retVal = malloc( startIndex + envLen + needsSeperator +
						   endLen + 1 ) ) == NULL )
		return( NULL );
	if( startIndex )
		/* Copy everything in the string before the enrivonment variable */
		strncpy( retVal, string, startIndex );
	strncpy( retVal + startIndex, envPtr, envLen );
	if( endLen )
		{
		/* Append the rest of the string to what's given in the environment
		   variable */
		if( needsSeperator )
			retVal[ startIndex + envLen ] = DIR_SEPERATOR;
		strcpy( retVal + startIndex + envLen + needsSeperator,
				string + endIndex + 1 );
		}
	else
		/* Add der terminador */
		retVal[ startIndex + envLen + needsSeperator + endLen ] = '\0';
	if( oldEnvLen != ( int ) strlen( envPtr ) )
		{
		/* Something funny is going on (the value changed while we were
		   working with it), we can't rely on the data */
		free( retVal );
		return( NULL );
		}

	return( ( char * ) retVal );
	}

/* Set the value of a numeric or string option */

int setOptionNumeric( const CRYPT_OPTION_TYPE option, const int value )
	{
	OPTION_INFO *optionInfoPtr;

	/* Get a pointer to the option information and make sure everything is
	   OK */
	if( option <= CRYPT_OPTION_NONE || option >= CRYPT_OPTION_LAST )
		return( CRYPT_BADPARM1 );
	if( value < 0 )
		return( CRYPT_BADPARM2 );
	optionInfoPtr = &configOptions[ option ];
	if( optionInfoPtr->type != OPTION_NUMERIC && \
		optionInfoPtr->type != OPTION_BOOLEAN )
		return( CRYPT_BADPARM1 );
	if( optionInfoPtr->type == OPTION_NUMERIC &&
		( value < optionInfoPtr->lowRange || value > optionInfoPtr->highRange ) )
		return( CRYPT_BADPARM2 );
	if( optionInfoPtr->readOnly )
		return( CRYPT_NOPERM );

	/* Lock the config information to ensure other threads don't try to
	   access it */
	lockGlobalResource( config );

	/* Set the value */
	if( optionInfoPtr->type == OPTION_BOOLEAN )
		/* Turn a generic zero/nonzero boolean into TRUE or FALSE */
		optionInfoPtr->intValue = ( value ) ? TRUE : FALSE;
	else
		optionInfoPtr->intValue = value;
	optionInfoPtr->dirty = TRUE;

	/* Unlock the config information to allow access by other threads */
	unlockGlobalResource( config );

	return( CRYPT_OK );
	}

int setOptionString( const CRYPT_OPTION_TYPE option, const char *value )
	{
	OPTION_INFO *optionInfoPtr;
	char *valuePtr;

	/* Get a pointer to the option information and make sure everything is
	   OK */
	if( option <= CRYPT_OPTION_NONE || option >= CRYPT_OPTION_LAST )
		return( CRYPT_BADPARM1 );
	if( value == NULL )
		return( CRYPT_BADPARM2 );
	optionInfoPtr = &configOptions[ option ];
	if( optionInfoPtr->type != OPTION_STRING )
		return( CRYPT_BADPARM1 );
	if( optionInfoPtr->readOnly )
		return( CRYPT_NOPERM );
	if( !optionInfoPtr->nullStringOK && !*value )
		return( CRYPT_BADPARM2 );

	/* Try and allocate room for the new option */
	if( ( valuePtr = malloc( strlen( value ) + 1 ) ) == NULL )
		return( CRYPT_NOMEM );
	strcpy( valuePtr, value );

	/* Lock the config information to ensure other threads don't try to
	   access it */
	lockGlobalResource( config );

	/* If the string value which is currently set isn't the default setting,
	   clear and free it; if the qualified value is set, clear it and free
	   it */
	if( optionInfoPtr->strValue != optionInfoPtr->strDefault )
		{
		zeroise( optionInfoPtr->strValue, strlen( optionInfoPtr->strValue ) );
		free( optionInfoPtr->strValue );
		}
	if( optionInfoPtr->fqStrValue != NULL )
		{
		zeroise( optionInfoPtr->fqStrValue, strlen( optionInfoPtr->fqStrValue ) );
		free( optionInfoPtr->fqStrValue );
		}

	/* Set the value */
	optionInfoPtr->strValue = valuePtr;
	optionInfoPtr->fqStrValue = qualifyString( valuePtr );
	optionInfoPtr->dirty = TRUE;

	/* Unlock the config information to allow access by other threads */
	unlockGlobalResource( config );

	return( CRYPT_OK );
	}

/* Query the value of a numeric or string option */

int getOptionNumeric( const CRYPT_OPTION_TYPE option )
	{
	const OPTION_INFO *optionInfoPtr;
	int value;

	/* Get a pointer to the option information and make sure everything is
	   OK */
	if( option <= CRYPT_OPTION_NONE || option >= CRYPT_OPTION_LAST )
		return( CRYPT_BADPARM1 );
	optionInfoPtr = &configOptions[ option ];
	if( optionInfoPtr->type != OPTION_NUMERIC && \
		optionInfoPtr->type != OPTION_BOOLEAN )
		return( CRYPT_BADPARM1 );

	/* Lock the config information to ensure other threads don't try to
	   access it */
	lockGlobalResource( config );

	value = optionInfoPtr->intValue;

	/* Unlock the config information to allow access by other threads */
	unlockGlobalResource( config );

	return( value );
	}

char *getOptionString( const CRYPT_OPTION_TYPE option )
	{
	const OPTION_INFO *optionInfoPtr;
	char *value;

	/* Get a pointer to the option information and make sure everything is
	   OK */
	if( option <= CRYPT_OPTION_NONE || option >= CRYPT_OPTION_LAST )
		return( NULL );
	optionInfoPtr = &configOptions[ option ];
	if( optionInfoPtr->type != OPTION_STRING )
		return( NULL );

	/* Lock the config information to ensure other threads don't try to
	   access it */
	lockGlobalResource( config );

	value = ( optionInfoPtr->fqStrValue != NULL ) ? \
			optionInfoPtr->fqStrValue : "";

	/* Unlock the config information to allow access by other threads */
	unlockGlobalResource( config );

	return( value );
	}

/* Map a config option category type to an actual config option.  Some
   config options aren't really meant to be used directly, but instead
   map to one of a number of other config options.  This function is used
   to map these indirect options */

char *mapOLEName( const CRYPT_OPTION_TYPE option )
	{
	const OPTION_INFO *optionInfoPtr;
	MAP_CAT mapCategory;
	char *name = NULL;
	int value, i;

	/* Make sure everything is OK */
	if( option <= CRYPT_OPTION_NONE || option >= CRYPT_OPTION_LAST )
		return( NULL );
	optionInfoPtr = &configOptions[ option ];
	if( optionInfoPtr->type != OPTION_NUMERIC || \
		optionInfoPtr->mapOption != CRYPT_OK )
		return( NULL );

	/* Lock the config information to ensure other threads don't try to
	   access it */
	lockGlobalResource( config );

	/* Get the mapping source options */
	mapCategory = optionInfoPtr->mapCategory;
	value = optionInfoPtr->intValue;

	/* Walk through the config options looking for the mapping target */
	for( i = 1; configOptions[ i ].option != OPTION_NONE; i++ )
		if( ( configOptions[ i ].mapOption == value ) && \
			( configOptions[ i ].mapCategory == mapCategory ) )
			{
			name = getOptionString( i );
			break;
			}

	/* Unlock the config information to allow access by other threads */
	unlockGlobalResource( config );

	return( name );
	}

/* Initialise/clean up the config option handling */

void initConfig( void )
	{
	int i;

	/* Initialize any data structures required to make the config information
	   thread-safe */
	initGlobalResourceLock( config );
	lockGlobalResource( config );

	/* Walk through the config table setting up each option to point to
	   its default value */
	for( i = 1; configOptions[ i ].option != CRYPT_OPTION_NONE; i++ )
		if( configOptions[ i ].type == OPTION_STRING )
			{
			configOptions[ i ].strValue = \
				( char * ) configOptions[ i ].strDefault;
			configOptions[ i ].fqStrValue = \
				qualifyString( configOptions[ i ].strValue );
			}
		else
			configOptions[ i ].intValue = configOptions[ i ].intDefault;

	unlockGlobalResource( config );
	}

void endConfig( void )
	{
	int i;

	/* Lock the config information to ensure other threads don't try to
	   access it */
	lockGlobalResource( config );

	/* Walk through the config table clearing and freeing each option */
	for( i = 1; configOptions[ i ].option != OPTION_NONE; i++ )
		{
		OPTION_INFO *optionInfoPtr = &configOptions[ i ];

		if( optionInfoPtr->type == OPTION_STRING )
			{
			/* If the string value which is currently set isn't the default
			   setting, clear and free it; if the qualified value is set,
			   clear it and free it */
			if( optionInfoPtr->strValue != optionInfoPtr->strDefault )
				{
				zeroise( optionInfoPtr->strValue,
						 strlen( optionInfoPtr->strValue ) );
				free( optionInfoPtr->strValue );
				}
			if( optionInfoPtr->fqStrValue != NULL && \
				optionInfoPtr->fqStrValue != optionInfoPtr->strValue )
				{
				zeroise( optionInfoPtr->fqStrValue,
						 strlen( optionInfoPtr->fqStrValue ) );
				free( optionInfoPtr->fqStrValue );
				}
			optionInfoPtr->strValue = optionInfoPtr->fqStrValue = NULL;
			}
		else
			optionInfoPtr->intValue = 0;
		}

	/* Destroy any data structures required to make the config information
	   thread-safe */
	unlockGlobalResource( config );
	deleteGlobalResourceLock( config );
	}

/****************************************************************************
*																			*
*						External Set/Query Option Interface					*
*																			*
****************************************************************************/

/* These functions are just wrappers for the internal functions which convert
   the more useful internal function style to a style which conforms to the
   external functions */

CRET cryptSetOptionNumeric( const CRYPT_OPTION_TYPE cryptOption,
							const int value )
	{
	return( setOptionNumeric( cryptOption, value ) );
	}

CRET cryptSetOptionString( const CRYPT_OPTION_TYPE cryptOption,
						   const char CPTR value )
	{
	return( setOptionString( cryptOption, value ) );
	}

/* Query the value of a numeric or string option */

CRET cryptGetOptionNumeric( const CRYPT_OPTION_TYPE cryptOption,
							int CPTR value )
	{
	int status;

	if( checkBadPtrWrite( value, sizeof( int ) ) )
		return( CRYPT_BADPARM2 );
	status = getOptionNumeric( cryptOption );
	*value = status;

	return( cryptStatusError( status ) ? status : CRYPT_OK );
	}

CRET cryptGetOptionString( const CRYPT_OPTION_TYPE cryptOption,
						   char CPTR value, int CPTR valueLength )
	{
	char *retVal;

	if( checkBadPtrWrite( valueLength, sizeof( int ) ) )
		return( CRYPT_BADPARM3 );
	*valueLength = CRYPT_ERROR;
	if( value != NULL )
		*value = '\0';
	retVal = getOptionString( cryptOption );
	if( retVal == NULL )
		return( CRYPT_DATA_NOTFOUND );
	*valueLength = strlen( retVal ) + 1;
	if( value != NULL )
		{
		if( checkBadPtrWrite( value, *valueLength ) )
			return( CRYPT_BADPARM2 );
		strcpy( value, retVal );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Read a Config File 							*
*																			*
****************************************************************************/

#ifndef __WIN32__

/* The types of errors we check for in config files */

typedef enum {
	CONFIG_OK,						/* No error */
	CONFIG_ERROR,					/* Generic error */
	CONFIG_BADCHAR,					/* Bad char in file */
	CONFIG_LINELENGTH,				/* Input line too long */
	CONFIG_ENDDATA,					/* End of input data */
	CONFIG_BADSTRING,				/* Bad literal string format */
	CONFIG_UNKNOWNOPTION,			/* Unknown config option */
	CONFIG_EXPECTEDASSIGN,			/* Expected '=' operator */
	CONFIG_BADNUMERIC,				/* Bad numeric data format */
	CONFIG_BADBOOLEAN,				/* Bad boolean data format */
	CONFIG_END
	} CONFIG_STATUS;

/* Files coming from DOS/Windows systems may have a ^Z (the CP/M EOF char)
   at the end, so we need to filter this out */

#define CPM_EOF	0x1A		/* ^Z = CPM EOF char */

/* The maximum input line length */

#ifdef __MSDOS16__
  #define MAX_LINESIZE	768
#else
  #define MAX_LINESIZE	( CRYPT_MAX_PKCSIZE * 3 )
#endif /* __MSDOS16__ */

/* Read a line of text from the config file */

static CONFIG_STATUS readLine( STREAM *stream, char *buffer )
	{
	CONFIG_STATUS errType = CONFIG_OK;
	int bufCount = 0, ch;

	/* Skip whitespace */
	while( ( ( ch = sgetc( stream ) ) == ' ' || ch == '\t' ) && \
		   sGetStatus( stream ) == CRYPT_OK );

	/* Get a line into the buffer */
	while( ch != '\r' && ch != '\n' && ch != CPM_EOF && \
		   sGetStatus( stream ) == CRYPT_OK )
		{
		/* Check for an illegal char in the data.  Note that we don't just
		   check for chars with high bits set because these are legal in
		   non-ASCII strings */
		if( ( ch & 0x7F ) < ' ' && ch != '\t' )
			if( errType != CONFIG_LINELENGTH )
				errType = CONFIG_BADCHAR;

		/* Check to see if it's a comment line */
		if( ch == '#' )
			{
			/* Skip comment section and trailing whitespace */
			while( ch != '\r' && ch != '\n' && ch != CPM_EOF && \
				   sGetStatus( stream ) == CRYPT_OK )
				ch = sgetc( stream );
			break;
			}

		/* Make sure the path is of the correct length.  Note that the
		   code is ordered so that a CONFIG_LINELENGTH error takes precedence
		   over a CONFIG_BADCHAR error */
		if( bufCount > MAX_LINESIZE )
			errType = CONFIG_LINELENGTH;
		else
			if( ch )	/* Can happen if we read a binary file */
				buffer[ bufCount++ ] = ch;

		/* Get next character */
		ch = sgetc( stream );
		}

	/* If we've just passed a CR, check for a following LF */
	if( ch == '\r' )
		if( ( ch = sgetc( stream ) ) != '\n' )
			sungetc( stream );

	/* Skip trailing whitespace and add der terminador */
	while( bufCount > 0 &&
		   ( ( ch = buffer[ bufCount - 1 ] ) == ' ' || ch == '\t' ) )
		bufCount--;
	buffer[ bufCount ] = '\0';

	/* Handle special-case of ^Z if file came off an MSDOS system */
	if( ch == CPM_EOF )
		while( sGetStatus( stream ) == CRYPT_OK )
			/* Keep going until we hit the true EOF (or some sort of error) */
			ch = sgetc( stream );

	return( ( sGetStatus( stream ) == CRYPT_UNDERFLOW ) ? CONFIG_ENDDATA : errType );
	}
#endif /* __WIN32__ */

/****************************************************************************
*																			*
*						Line- and Keyword-Parsing Routines					*
*																			*
****************************************************************************/

#ifndef __WIN32__

/* The following routines parse the flat-file form of the configuration
   information.  The routines deliberately accept a far looser form of input
   than what is generated by the code which writes the options to the file
   in case users decide to manually edit the file and don't quite get it
   right */

/* The state of the parsing */

typedef struct {
	/* The current parse state */
	char *tokenStrPtr;				/* The string being parsed */
	char tokenBuffer[ MAX_LINESIZE ];	/* Buffer for current token */

	/* The last string or value parsed */
	char parsedString[ MAX_LINESIZE ];
	int parsedValue;
	} PARSE_STATE;

/* Get a string constant */

static int getString( PARSE_STATE *parseState )
	{
	BOOLEAN noQuote = FALSE;
	int stringIndex = 0;
	char ch = *parseState->tokenStrPtr++;

	/* Skip whitespace */
	while( ch && ( ch == ' ' || ch == '\t' ) )
		ch = *parseState->tokenStrPtr++;

	/* Check for non-string */
	if( ch != '\"' )
		{
		/* Check for special case of null string */
		if( !ch )
			{
			parseState->tokenStrPtr--;	/* Don't overshoot the '\0' */
			*parseState->parsedString = '\0';
			return( CONFIG_OK );
			}

		/* Use nasty non-rigorous string format */
		noQuote = TRUE;
		}

	/* Get first char of string */
	if( !noQuote )
		ch = *parseState->tokenStrPtr++;

	/* Get string into string value */
	while( ch && ch != '\"' )
		{
		/* Exit on '#' if using non-rigorous format */
		if( noQuote && ch == '#' )
			break;

		parseState->parsedString[ stringIndex++ ] = ch;
		if( ( ch = *parseState->tokenStrPtr ) != '\0' )
			parseState->tokenStrPtr++;
		}

	/* If using the non-rigorous format, stomp trailing spaces */
	if( noQuote )
		while( stringIndex > 0 && \
			   parseState->parsedString[ stringIndex - 1 ] == ' ' )
			stringIndex--;
	parseState->parsedString[ stringIndex ] = '\0';
	parseState->parsedValue = stringIndex;

	/* Check for missing string terminator */
	if( ch != '\"' && !noQuote )
		return( CONFIG_BADSTRING );

	return( CONFIG_OK );
	}

/* Get the first/next token from a string of tokens */

static char *getNextToken( PARSE_STATE *parseState )
	{
	int index = 0;
	char ch;

	/* Check to see if it's a quoted string */
	if( *parseState->tokenStrPtr == '\"' )
		{
		getString( parseState );
		strcpy( parseState->tokenBuffer, parseState->parsedString );
		}
	else
		{
		/* Find end of current token */
		while( ( index < MAX_LINESIZE ) && \
        	   ( ch = parseState->tokenStrPtr[ index ] ) != '\0' &&
			   ( ch != ' ' ) && ( ch != '\t' ) && ( ch != '=' ) &&
			   ( ch != '\"' ) && ( ch != ',' ) )
			index++;
		if( !index && ( ch == ',' || ch == '=' || ch == '\"' ) )
			index++;

		/* Copy the token to the token buffer */
		strncpy( parseState->tokenBuffer, parseState->tokenStrPtr, index );
		parseState->tokenBuffer[ index ] = '\0';
		parseState->tokenStrPtr += index;
		}

	/* Skip to start of next token */
	while( ( ch = *parseState->tokenStrPtr ) != '\0' && \
		   ( ch == ' ' || ch == '\t' ) )
		parseState->tokenStrPtr++;
	if( ch == '\0' || ch == '#' )
		/* Set end marker when we pass the last token */
		parseState->tokenStrPtr = "";

	return( parseState->tokenBuffer );
	}

static char *getFirstToken( PARSE_STATE *parseState, const char *buffer )
	{
	char ch;

	/* Skip any leading whitespace in the string */
	parseState->tokenStrPtr = ( char * ) buffer;
	while( ( ch = *parseState->tokenStrPtr ) != '\0' && \
		   ( ch == ' ' || ch == '\t' ) )
		parseState->tokenStrPtr++;

	return( getNextToken( parseState ) );
	}

/* Get an assignment to an intrinsic */

static CONFIG_STATUS getAssignment( PARSE_STATE *parseState,
									OPTION_TYPE optionType )
	{
	CONFIG_STATUS status;
	int index;
	char *token;

	token = getNextToken( parseState );
	if( !*token && ( optionType == OPTION_BOOLEAN ) )
		{
		/* Boolean option, no assignment gives setting of TRUE */
		parseState->parsedValue = TRUE;
		return( CONFIG_OK );
		}

	/* Check for an assignment operator */
	if( *token != '=' )
		return( CONFIG_EXPECTEDASSIGN );

	switch( optionType )
		{
		case OPTION_BOOLEAN:
			/* Check for known intrinsic - really more general than just
			   checking for TRUE or FALSE */
			token = getNextToken( parseState );
			if( !stricmp( token, "TRUE" ) || !stricmp( token, "1" ) )
				parseState->parsedValue = TRUE;
			else
				if( !stricmp( token, "FALSE" ) || !stricmp( token, "0" ) )
					parseState->parsedValue = FALSE;
				else
					return( CONFIG_BADBOOLEAN );
			break;

		case OPTION_STRING:
			/* Get a string */
			status = getString( parseState );
			break;

		case OPTION_NUMERIC:
			/* Get numeric input.  Error checking is a pain since atoi()
			   has no real equivalent of NAN */
			token = getNextToken( parseState );
			for( index = 0; token[ index ]; index++ )
				if( !isdigit( token[ index ] ) )
					return( CONFIG_BADNUMERIC );
			parseState->parsedValue = atoi( token );
			status = CONFIG_OK;
			break;
			}

	return( status );
	}

/* Process an individual line from a config file */

static int processLine( const char *configLine )
	{
	PARSE_STATE parseState;
	static char *token;
	int readToken = TRUE;

	memset( &parseState, 0, sizeof( PARSE_STATE ) );

	token = getFirstToken( &parseState, configLine );
	while( TRUE )
		{
		CONFIG_STATUS status;
		int index;

		/* Get the next input token */
		if( !readToken )
			token = getNextToken( &parseState );
		readToken = FALSE;
		if( !*token )
			break;

		/* Search the list of options for a match using.  We use a simple
		   linear search because the option list is currently so short that
		   there's little to be gained from a more fancy binary search */
		for( index = 0; configOptions[ index ].name != NULL && \
			 stricmp( token, configOptions[ index ].name ); index++ );
		if( configOptions[ index ].name == NULL )
			{
			if( strnicmp( token, "TrustInfo.TrustedCert", 20 ) )
				return( CONFIG_UNKNOWNOPTION );

			/* It's a trust item used internally, add it to the trust info */
			status = getAssignment( &parseState, OPTION_STRING );
			if( status != CONFIG_OK )
				return( status );
			setTrustItem( parseState.parsedString, parseState.parsedValue,
						  TRUE );
			}
		else
			{
			/* Handle the assignment associated with it */
			status = getAssignment( &parseState, configOptions[ index ].type );
			if( status != CONFIG_OK )
				return( status );
			if( configOptions[ index ].type == OPTION_STRING )
				setOptionString( configOptions[ index ].option,
								 parseState.parsedString );
			else
				setOptionNumeric( configOptions[ index ].option,
								  parseState.parsedValue );
			}
		}

	return( CONFIG_OK );
	}
#endif /* __WIN32__ */

/****************************************************************************
*																			*
*						Read and Write the Config Options 					*
*																			*
****************************************************************************/

/* The reading and writing of config options works completely differently for
   the flat-file and heirarchical-database versions.  For the flat-file
   version we take each line we read and try to match it against what's
   available in memory.  In contrast for the heirarchical-database version we
   take what we have in memory and request the setting corresponding to this
   in the database */

#ifdef __UNIX__
  #include <pwd.h>

  /* SunOS 4.1.x doesn't define FILENAME_MAX in limits.h, however it does
	 define a POSIX path length limit so we use that instead.  There are a
	 number of places in various headers in which a max.path length is
	 defined either as 255 or 1024, but we use the POSIX limit since this is
	 the only thing defined in limits.h */
  #if defined( sun ) && ( OSVERSION == 4 ) && !defined( FILENAME_MAX )
	#define FILENAME_MAX  _POSIX_PATH_MAX
  #endif /* SunOS 4.1.x FILENAME_MAX define */
#endif /* __UNIX__ */

#if defined( __OS2__ )
  #define INCL_DOSMISC			/* DosQuerySysInfo() */
  #include <os2.h>

#endif /* __OS2__ */

#ifndef __WIN32__

/* Build the path to the config file */

static void buildConfigPath( char *path, const char *basePath )
	{
#ifdef __OS2__
	ULONG aulSysInfo[ 1 ] = { 0 };
#endif /* __OS2__ */

	/* Make sure the open fails if we can't build the path */
	*path = '\0';

	/* Build the path to the configuration file if necessary */
#if defined( __MSDOS__ )
	strcpy( path, "misc/cryptrc" );

	UNUSED( basePath );
#elif defined( __WINDOWS__ )
	GetWindowsDirectory( path, _MAX_PATH - 9 );
	strcat( path, "\\cryptrc" );

	UNUSED( basePath );
#elif defined( __OS2__ )
	DosQuerySysInfo( QSV_BOOT_DRIVE, QSV_BOOT_DRIVE, ( PVOID ) aulSysInfo,
					 sizeof( ULONG ) );		/* Get boot drive info */
	if( *aulSysInfo == 0 )
		return;		/* No boot drive info */
	path[ 0 ] = *aulSysInfo + 'A' - 1;
	strcpy( path + 1, ":\\OS2\\cryptrc" );	/* eg. C:\OS2\cryptrc */
#elif defined( __UNIX__ )
	/* Get the path to the config file, either the (supplied) systemwide one
	   or the one in the users home directory */
	if( basePath != NULL )
		strcpy( path, basePath );
	else
		{
		struct passwd *passwd;
		char *pathPtr;
		int length;

		if( ( passwd = getpwuid( getuid() ) ) == NULL )
			return;		/* Huh? User not in passwd file */
		if( ( length = strlen( passwd->pw_dir ) ) > 1000 )
			/* You're kidding, right? */
			return;
		strncpy( path, passwd->pw_dir, length );
		if( path[ length ] != '/' )
			path[ length++ ] = '/';
		strcpy( path + length, ".cryptrc" );
		}
#elif defined( __TANDEM__ )
	strcpy( path, "$system.system.cryptrc" );

	UNUSED( basePath );
#else
  #error You need to add the OS-specific code to build the config file path to cryptcfg.c.
#endif /* Various OS-specific file path defines */
	}
#endif /* __WIN32__ */

/* Read all configuration options.  This works slightly differently for Win32
   (where information is stored in the registry) and for everything else.
   For Win32 we step through all the options trying to read a value for each
   one, while for everything else we read everything we can find and load the
   appropriate option */

#ifdef __WIN32__

CRET cryptReadOptions( void )
	{
	HANDLE h1, h2;
	int objectIndex = 0, i, status;

	/* Start a cryptlib registry info read */
	status = beginRegistryUpdate( TRUE, &h1, &h2 );
	if( cryptStatusError( status ) )
		return( CRYPT_DATA_OPEN );

	/* Lock the config information to ensure other threads don't try to
	   access it */
	lockGlobalResource( config );

	/* Walk through the config table trying to read each option */
	for( i = 1; configOptions[ i ].option != OPTION_NONE; i++ )
		{
		OPTION_INFO *optionInfoPtr = &configOptions[ i ];

		if( optionInfoPtr->type == OPTION_STRING )
			{
			char string[ 256 ];

			if( cryptStatusOK( readRegistryString( h1, optionInfoPtr->name,
												   string ) ) )
				setOptionString( optionInfoPtr->option, string );
			}
		else
			{
			int value;

			if( cryptStatusOK( readRegistryValue( h1, optionInfoPtr->name,
												  &value ) ) )
				setOptionNumeric( optionInfoPtr->option, value );
			}
		}

	/* Read the internal options used by cryptlib */
	do
		{
		BYTE buffer[ CRYPT_MAX_PKCSIZE * 2 ];
		char objectName[ 32 ];
		int length;

		sprintf( objectName, "TrustInfo.TrustedCert%04d", objectIndex++ );
		status = readRegistryBinary( h1, objectName, buffer, &length );
		if( cryptStatusOK( status ) )
			setTrustItem( buffer, length, FALSE );
		}
	while( cryptStatusOK( status ) );

	/* Unlock the config information to allow access by other threads */
	unlockGlobalResource( config );

	/* Finish the cryptlib registry info update */
	status = endRegistryUpdate( h1, h2 );

	return( cryptStatusError( status ) ? CRYPT_DATA_READ : CRYPT_OK );
	}

#else

CRET cryptReadOptions( void )
	{
	STREAM stream;
	CONFIG_STATUS configStatus = CONFIG_OK, errType = CONFIG_OK;
	BOOLEAN endOfData = FALSE;
	char configFilePath[ FILENAME_MAX ];
	int errCount = 0, status;

	/* Try and open the config file */
	buildConfigPath( configFilePath, NULL );
	status = sFileOpen( &stream, configFilePath, FILE_READ );
	if( cryptStatusError( status ) )
		return( status );

	/* Rumble through the file processing each line */
	while( !endOfData )
		{
		char buffer[ MAX_LINESIZE ];

		configStatus = readLine( &stream, buffer );
		if( configStatus == CONFIG_ENDDATA )
			{
			endOfData = TRUE;
			configStatus = CONFIG_OK;
			}
		if( configStatus == CONFIG_OK )
			/* If there was valid data on the line, process it */
			configStatus = processLine( buffer );

		/* If there were errors, remember the details (actually we can only
		   remember details on the first error, the non-interactive API isn't
		   set up very well for error reporting) */
		if( configStatus != CONFIG_OK )
			{
			errCount++;
			if( errType == CONFIG_OK )
				errType = configStatus;

			/* Exit if there are too many errors */
			if( errCount >= 10 )
				break;
			}
		}

	/* Clean up */
	sFileClose( &stream );

	return( ( errCount ) ? CRYPT_DATA_READ : CRYPT_OK );
	}
#endif /* __WIN32__ */

/* Write all the non-default configuration options */

#ifdef __WIN32__

CRET cryptWriteOptions( void )
	{
	HANDLE h1, h2;
	char buffer[ CRYPT_MAX_PKCSIZE * 3 ];
	void *statePtr = NULL;
	int stateIndex = -1, objectIndex = 0;
	int length, i, status;

	/* Start a cryptlib registry info update */
	status = beginRegistryUpdate( FALSE, &h1, &h2 );
	if( cryptStatusError( status ) )
		return( CRYPT_DATA_OPEN );

	/* Lock the config information to ensure other threads don't try to
	   access it */
	lockGlobalResource( config );

	/* Walk through the config table writing each changed option */
	for( i = 1; configOptions[ i ].option != OPTION_NONE; i++ )
		{
		OPTION_INFO *optionInfoPtr = &configOptions[ i ];

		/* Only try to update the option if it's changed */
		if( !optionInfoPtr->dirty )
			continue;

		if( optionInfoPtr->type == OPTION_STRING )
			writeRegistryString( h1, optionInfoPtr->name,
								 ( optionInfoPtr->fqStrValue != NULL ) ? \
									optionInfoPtr->fqStrValue : \
									optionInfoPtr->strValue );
		else
			writeRegistryValue( h1, optionInfoPtr->name, \
								optionInfoPtr->intValue  );
		}

	/* Write the internal options used by cryptlib */
	while( getTrustItem( &statePtr, &stateIndex, buffer, &length, FALSE ) )
		{
		char objectName[ 32 ];

		sprintf( objectName, "TrustInfo.TrustedCert%04d", objectIndex++ );
		writeRegistryBinary( h1, objectName, buffer, length );
		}

	/* Unlock the config information to allow access by other threads */
	unlockGlobalResource( config );

	/* Finish the cryptlib registry info update */
	status = endRegistryUpdate( h1, h2 );

	return( cryptStatusError( status ) ? CRYPT_DATA_WRITE : CRYPT_OK );
	}
#else

CRET cryptWriteOptions( void )
	{
	STREAM stream;
	FILE *filePtr;
	BOOLEAN wroteOption = TRUE;
	char configFilePath[ FILENAME_MAX ], lastOption[ 4 ] = { 0 };
	char buffer[ CRYPT_MAX_PKCSIZE * 3 ];
	void *statePtr = NULL;
	int stateIndex = -1, objectIndex = 0;
	int i, status;

	/* Build the path to the config file and try and open it */
	buildConfigPath( configFilePath, NULL );
	status = sFileOpen( &stream, configFilePath, FILE_WRITE | FILE_PRIVATE );
	if( cryptStatusError( status ) )
		return( status );

	/* Extract the file pointer from the stream structure.  This is very
	   naughty, but saves a lot of hassle because we need to perform
	   formatted I/O which isn't supported by the stream interface */
	filePtr = stream.filePtr;

	/* Write the header comments */
	fputs( "# This file is used to record default options for software "
		   "using the cryptlib\n# encryption library.  The file is usually "
		   "modified by programs using the\n# cryptlib interface, but can "
		   "be edited manually if required (although this\n# is not "
		   "recommended).\n", filePtr );

	/* Walk through the config options writing the ones which don't match
	   the default settings */
	for( i = 1; configOptions[ i ].option != OPTION_NONE; i++ )
		{
		const OPTION_INFO *optionInfoPtr = &configOptions[ i ];

		/* If we're moving on to a new group of options, separate if from
		   the previous group with a blank line */
		if( memcmp( lastOption, optionInfoPtr->name, 4 ) )
			{
			memcpy( lastOption, optionInfoPtr->name, 4 );
			if( wroteOption )
				fputc( '\n', filePtr );
			wroteOption = FALSE;
			}

		if( optionInfoPtr->type == OPTION_STRING )
			{
			/* If the string value which is currently set isn't the default
			   setting, write it to the file.  Note that we compare the
			   value rather than the pointers since they could point to the
			   same value */
			if( strcmp( optionInfoPtr->strValue, optionInfoPtr->strDefault ) )
				{
				fprintf( filePtr, "%s = %s\n", optionInfoPtr->name,
						 optionInfoPtr->strValue );
				wroteOption = TRUE;
				}
			continue;
			}

		/* If the integer/boolean value which is currently set isn't the
		   default setting, write it to the file */
		if( optionInfoPtr->intValue != optionInfoPtr->intDefault )
			{
			if( optionInfoPtr->type == OPTION_NUMERIC )
				fprintf( filePtr, "%s = %d\n", optionInfoPtr->name,
						 optionInfoPtr->intValue );
			else
				fprintf( filePtr, "%s = %s\n", optionInfoPtr->name,
						 ( optionInfoPtr->intValue ) ? "TRUE" : "FALSE" );
			wroteOption = TRUE;
			}
		}
	if( wroteOption )
		fputc( '\n', filePtr );

	/* Write the internal options used by cryptlib */
	while( getTrustItem( &statePtr, &stateIndex, buffer, NULL, TRUE ) )
		fprintf( filePtr, "TrustInfo.TrustedCert%04d = %s\n", objectIndex++,
				 buffer );

	/* Clean up */
	sFileClose( &stream );
	return( CRYPT_OK );
	}
#endif /* __WIN32__ */

#ifdef TEST

int main( void )
	{
	char *pubKeys;

	initConfig();

	/* First, try and process the local config file */
	readConfigOptions();

	/* If there's a system-wide config file, try that as well (anything not
	   in the local config file is read from the system-wide one) */
#ifdef x__UNIX__
	readConfigOptionsEx( "/etc/cryptrc" );
	if( !geteuid() )
		writeConfigOptionsEx( "/etc/cryptrc" );
#endif /* __UNIX__ */

	/* Make sure the mapping facility works */
	pubKeys = mapOLEName( CRYPT_OPTION_KEYS_PUBLIC );

	/* Write the options to the config file */
	writeConfigOptions();

	endConfig();

	return( 0 );
	}
#endif /* TEST */
