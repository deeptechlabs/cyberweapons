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
  #include "asn1.h"
#else
  #include "keymgmt/asn1.h"
#endif /* Compiler-specific includes */

/* Prototypes for functions in certrust.c */

CRYPT_CERTIFICATE getFirstTrustedCert( void **statePtr, int *stateIndex );
CRYPT_CERTIFICATE getNextTrustedCert( void **statePtr, int *stateIndex );

/****************************************************************************
*																			*
*							Configuration Options							*
*																			*
****************************************************************************/

/* Configuration option types */

typedef enum {
	OPTION_NONE,					/* Non-option */
	OPTION_STRING,					/* Literal string */
	OPTION_NUMERIC,					/* Numeric value */
	OPTION_BOOLEAN					/* Boolean flag */
	} OPTION_TYPE;

/* The configuration options.  Alongside the CRYPT_ATTRIBUTE_TYPE we store
   a persistant index value for the option which always stays the same even
   if the attribute type changes, this avoids the need to change the config
   file every time an attribute is added or deleted */

typedef struct {
	const CRYPT_ATTRIBUTE_TYPE option;/* Magic number for this option */
	const OPTION_TYPE type;			/* Option type */
	const int index;				/* Index value for this option */
	char *strValue;					/* Value if it's a string option */
	char *fqStrValue;				/* Fully qualified string value */
	int intValue;					/* Value if it's a numeric/boolean */
	const char FAR_BSS *strDefault;	/* Default if it's a string option */
	const int intDefault;			/* Default if it's a numeric/boolean */
	BOOLEAN dirty;					/* Whether option has been changed */
	} OPTION_INFO;

static OPTION_INFO FAR_BSS configOptions[] = {
	/* Dummy entry for CRYPT_ATTRIBUTE_NONE */
	{ CRYPT_ATTRIBUTE_NONE, 0 },

	/* cryptlib information (read-only) */
	{ CRYPT_OPTION_INFO_DESCRIPTION, OPTION_STRING, CRYPT_UNUSED,
	  NULL, NULL, 0, "cryptlib encryption library", 0, FALSE },
	{ CRYPT_OPTION_INFO_COPYRIGHT, OPTION_STRING, CRYPT_UNUSED,
	  NULL, NULL, 0, "Copyright Peter Gutmann, Eric Young, 1994-1999", 0, FALSE },
	{ CRYPT_OPTION_INFO_MAJORVERSION, OPTION_NUMERIC, CRYPT_UNUSED,
	  NULL, NULL, 0, NULL, 3, FALSE },
	{ CRYPT_OPTION_INFO_MINORVERSION, OPTION_NUMERIC, CRYPT_UNUSED,
	  NULL, NULL, 0, NULL, 0, FALSE },
	{ CRYPT_OPTION_INFO_STEPPING, OPTION_NUMERIC, CRYPT_UNUSED,
	  NULL, NULL, 0, NULL, 1, FALSE },

	/* Context options, base = 0 */
	/* Algorithm = Conventional encryption/hash/MAC options */
	{ CRYPT_OPTION_ENCR_ALGO, OPTION_NUMERIC, 0,
	  NULL, NULL, 0, NULL, CRYPT_ALGO_3DES, FALSE },
	{ CRYPT_OPTION_ENCR_HASH, OPTION_NUMERIC, 1,
	  NULL, NULL, 0, NULL, CRYPT_ALGO_SHA, FALSE },

	/* Algorithm = PKC options */
	{ CRYPT_OPTION_PKC_ALGO, OPTION_NUMERIC, 2,
	  NULL, NULL, 0, NULL, CRYPT_ALGO_RSA, FALSE },
	{ CRYPT_OPTION_PKC_KEYSIZE, OPTION_NUMERIC, 3,
	  NULL, NULL, 0, NULL, bitsToBytes( 1024 ), FALSE },

	/* Algorithm = Signature options */
	{ CRYPT_OPTION_SIG_ALGO, OPTION_NUMERIC, 4,
	  NULL, NULL, 0, NULL, CRYPT_ALGO_RSA, FALSE },
	{ CRYPT_OPTION_SIG_KEYSIZE, OPTION_NUMERIC, 5,
	  NULL, NULL, 0, NULL, bitsToBytes( 1024 ), FALSE },

	/* Algorithm = Key derivation options */
	{ CRYPT_OPTION_KEYING_ALGO, OPTION_NUMERIC, 6,
	  NULL, NULL, 0, NULL, CRYPT_ALGO_SHA, FALSE },
	{ CRYPT_OPTION_KEYING_ITERATIONS, OPTION_NUMERIC, 7,
	  NULL, NULL, 0, NULL, 500, FALSE },

	/* Certificate options, base = 100 */
	{ CRYPT_OPTION_CERT_CREATEV3CERT, OPTION_BOOLEAN, 100,
	  NULL, NULL, 0, NULL, TRUE, FALSE },
	{ CRYPT_OPTION_CERT_PKCS10ALT, OPTION_BOOLEAN, 101,
	  NULL, NULL, 0, NULL, FALSE, FALSE },
	{ CRYPT_OPTION_CERT_CHECKENCODING, OPTION_BOOLEAN, 102,
	  NULL, NULL, 0, NULL, TRUE, FALSE },
	{ CRYPT_OPTION_CERT_FIXSTRINGS, OPTION_BOOLEAN, 103,
	  NULL, NULL, 0, NULL, TRUE, FALSE },
	{ CRYPT_OPTION_CERT_FIXEMAILADDRESS, OPTION_BOOLEAN, 104,
	  NULL, NULL, 0, NULL, TRUE, FALSE },
	{ CRYPT_OPTION_CERT_ISSUERNAMEBLOB, OPTION_BOOLEAN, 105,
	  NULL, NULL, 0, NULL, TRUE, FALSE },
	{ CRYPT_OPTION_CERT_KEYIDBLOB, OPTION_BOOLEAN, 106,
	  NULL, NULL, 0, NULL, TRUE, FALSE },
	{ CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES, OPTION_BOOLEAN, 107,
	  NULL, NULL, 0, NULL, FALSE, FALSE },
	{ CRYPT_OPTION_CERT_TRUSTCHAINROOT, OPTION_BOOLEAN, 108,
	  NULL, NULL, 0, NULL, FALSE, FALSE },
	{ CRYPT_OPTION_CERT_VALIDITY, OPTION_NUMERIC, 109,
	  NULL, NULL, 0, NULL, 365, FALSE },
	{ CRYPT_OPTION_CERT_UPDATEINTERVAL, OPTION_NUMERIC, 110,
	  NULL, NULL, 0, NULL, 90, FALSE },
	{ CRYPT_OPTION_CERT_ENCODE_VALIDITYNESTING, OPTION_BOOLEAN, 111,
	  NULL, NULL, 0, NULL, TRUE, FALSE },
	{ CRYPT_OPTION_CERT_DECODE_VALIDITYNESTING, OPTION_BOOLEAN, 112,
	  NULL, NULL, 0, NULL, FALSE, FALSE },
	{ CRYPT_OPTION_CERT_ENCODE_CRITICAL, OPTION_BOOLEAN, 113,
	  NULL, NULL, 0, NULL, TRUE, FALSE },
	{ CRYPT_OPTION_CERT_DECODE_CRITICAL, OPTION_BOOLEAN, 114,
	  NULL, NULL, 0, NULL, TRUE, FALSE },

	/* CMS options */
	{ CRYPT_OPTION_CMS_DEFAULTATTRIBUTES, OPTION_BOOLEAN, 130,
	  NULL, NULL, 0, NULL, TRUE, FALSE },

	/* Keyset options, base = 200 */
	/* Keyset = HTTP options */
	{ CRYPT_OPTION_KEYS_HTTP_PROXY, OPTION_STRING, 200,
	  NULL, NULL, 0, NULL, 0, FALSE },
	{ CRYPT_OPTION_KEYS_HTTP_TIMEOUT, OPTION_NUMERIC, 201,
	  NULL, NULL, 0, NULL, 60, FALSE },

	/* Keyset = LDAP options */
	{ CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS, OPTION_STRING, 210,
	  NULL, NULL, 0, "inetOrgPerson", 0, FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_OBJECTTYPE, OPTION_NUMERIC, 211,
	  NULL, NULL, 0, NULL, CRYPT_CERTTYPE_NONE, FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_CACERTNAME, OPTION_STRING, 212,
	  NULL, NULL, 0, "cACertificate;binary", 0, FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_CERTNAME, OPTION_STRING, 213,
	  NULL, NULL, 0, "userCertificate;binary", 0, FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_CRLNAME, OPTION_STRING, 214,
	  NULL, NULL, 0, "certificateRevocationList;binary", 0, FALSE },
	{ CRYPT_OPTION_KEYS_LDAP_EMAILNAME, OPTION_STRING, 215,
	  NULL, NULL, 0, "emailAddress", 0, FALSE },

	/* Device options, base = 300 */
	/* Device = PKCS #11 token options */
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR01, OPTION_STRING, 300,
	  NULL, NULL, 0, NULL, FALSE, FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR02, OPTION_STRING, 301,
	  NULL, NULL, 0, NULL, FALSE, FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR03, OPTION_STRING, 302,
	  NULL, NULL, 0, NULL, FALSE, FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR04, OPTION_STRING, 303,
	  NULL, NULL, 0, NULL, FALSE, FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_DVR05, OPTION_STRING, 304,
	  NULL, NULL, 0, NULL, FALSE, FALSE },
	{ CRYPT_OPTION_DEVICE_PKCS11_HARDWAREONLY, OPTION_BOOLEAN, 305,
	  NULL, NULL, 0, NULL, FALSE, FALSE },

	/* Device = Hardware RNG options */
	{ CRYPT_OPTION_DEVICE_SERIALRNG, OPTION_STRING, 310,
	  NULL, NULL, 0, NULL, FALSE, FALSE },
	{ CRYPT_OPTION_DEVICE_SERIALRNG_PARAMS, OPTION_STRING, 311,
	  NULL, NULL, 0, NULL, FALSE, FALSE },

	/* Session options, base = 400 */
	{ CRYPT_OPTION_SESSION_TIMEOUT, OPTION_NUMERIC, 400,
	  NULL, NULL, 0, NULL, 60, FALSE },

	/* Miscellaneous options, base = 500 */
	{ CRYPT_OPTION_MISC_FORCELOCK, OPTION_BOOLEAN, 500,
	  NULL, NULL, 0, NULL, FALSE, FALSE },
	{ CRYPT_OPTION_MISC_ASYNCINIT, OPTION_BOOLEAN, 501,
	  NULL, NULL, 0, NULL, TRUE, FALSE },

	/* Config option status.  This is a special option which is updated
	   dynamically, it's set to TRUE if any config option is changed,
	   writing it to FALSE commits the changes to disk */
	{ CRYPT_OPTION_CONFIGCHANGED, OPTION_BOOLEAN, CRYPT_UNUSED,
	  NULL, NULL, 0, NULL, FALSE, FALSE },

	{ CRYPT_ATTRIBUTE_NONE, OPTION_NONE, CRYPT_UNUSED,
	  NULL, NULL, 0, NULL, 0, FALSE }
	};

/* The last option which is written to disk.  Further options beyond this one
   are ephemeral and are never written to disk */

#define LAST_STORED_OPTION	CRYPT_OPTION_MISC_ASYNCINIT

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
   the expanded string fails.  For embedded systems there's no environment
   so we just return NULL if there's an environment delimiter present.  In
   addition in environments with a flat filesystem we don't bother with the
   environment stuff since it's only used to get directory paths */

#if defined( __MSDOS__ ) || defined( __WINDOWS__ ) || defined( __OS2__ )
  #define FULLPATH_SEPARATORS	"\\/:"	/* Seperators in full paths */
  #define PATH_SEPARATORS		"\\/"	/* Seperators between path components */
  #define DIR_SEPARATOR			'/'		/* Seperator to insert */
#elif defined( __UNIX__ ) || defined( __BEOS__ )
  #define FULLPATH_SEPARATORS	"/"
  #define PATH_SEPARATORS		"/"
  #define DIR_SEPARATOR			'/'
#elif defined( __TANDEM__ )
  #define FULLPATH_SEPARATORS	"."
  #define PATH_SEPARATORS		"."
  #define DIR_SEPARATOR			'.'
#elif defined( __MAC__ )
  #define FULLPATH_SEPARATORS	":"
  #define PATH_SEPARATORS		":"
  #define DIR_SEPARATOR			':'
#elif ( defined( __IBM4758__ ) || defined( __VMCMS__ ) )
  /* You can set env.vars with the DDfile EDCENV under VM but since there are
     no directories it's not needed */
  #define NO_ENVIRONMENT
#else
  #error Need to define filesystem path component seperator in cryptcfg.c
#endif /* OS-specific path component seperators */

static char *qualifyString( const char *string )
	{
#ifndef NO_ENVIRONMENT
	char envVarName[ 128 ], *envPtr, *retVal;
	int endLen, envLen, oldEnvLen, needsSeperator = 0;
#endif /* NO_ENVIRONMENT */
	int startIndex, endIndex;

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

#ifdef NO_ENVIRONMENT
	/* Embedded systems have no environment so we can't go any further than
	   this */
	return( NULL );
#else
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
	if( strchr( PATH_SEPARATORS, string[ endIndex + 1 ] ) == NULL )
		{
		/* If there are no path seperators at the end of the environment
		   string or the start of the rest of the string, remember that we
		   need to add one */
		if( strchr( FULLPATH_SEPARATORS, envPtr[ envLen - 1 ] ) == NULL )
			needsSeperator++;
		}
	else
		/* If there's a seperator at the end of the environment string and the
		   start of the rest of the string, zap the one at the end of the
		   enrivonment string */
		if( strchr( PATH_SEPARATORS, envPtr[ envLen - 1 ] ) != NULL )
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
			retVal[ startIndex + envLen ] = DIR_SEPARATOR;
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
#endif /* NO_ENVIRONMENT */
	}

/* Set the value of a numeric or string option */

int setOption( const CRYPT_ATTRIBUTE_TYPE option, const int value )
	{
	STATIC_FN int writeConfig( void );
	OPTION_INFO *optionInfoPtr;

	/* Get a pointer to the option information and make sure everything is
	   OK */
	assert( option > CRYPT_OPTION_FIRST && option < CRYPT_OPTION_LAST );
	optionInfoPtr = &configOptions[ option - CRYPT_OPTION_FIRST ];
	assert( optionInfoPtr->type == OPTION_NUMERIC || \
			optionInfoPtr->type == OPTION_BOOLEAN );

	/* Lock the config information to ensure other threads don't try to
	   access it */
	lockGlobalResource( config );

	/* If the value is the same as the current one, there's nothing to do */
	if( optionInfoPtr->intValue == value )
		{
		unlockGlobalResource( config );
		return( CRYPT_OK );
		}

	/* If we're forcing a commit by returning the config.changed flag to its
	   ground state, write any changed options to disk */
	if( option == CRYPT_OPTION_CONFIGCHANGED )
		{
		int i;

		/* Make sure there's something to write.  We do this to avoid problems
		   with programs which always try to update the config (whether it's
		   necessary or not), which can cause problems with media with limited
		   writeability */
		for( i = 1; configOptions[ i ].option != CRYPT_ATTRIBUTE_NONE; i++ )
			if( configOptions[ i ].dirty )
				break;
		if( configOptions[ i ].option == CRYPT_ATTRIBUTE_NONE )
			{
			/* Nothing has been changed, there's nothing to write */
			unlockGlobalResource( config );
			return( CRYPT_OK );
			}

		/* Unlock the config options before we perform the write, since the
		   config write code performs its own fine-grained locking */
		unlockGlobalResource( config );
		return( writeConfig() );
		}

	if( optionInfoPtr->type == OPTION_BOOLEAN )
		/* Turn a generic zero/nonzero boolean into TRUE or FALSE */
		optionInfoPtr->intValue = ( value ) ? TRUE : FALSE;
	else
		optionInfoPtr->intValue = value;
	optionInfoPtr->dirty = TRUE;

	/* Remember that the config options have been changed */
	optionInfoPtr = \
			&configOptions[ CRYPT_OPTION_CONFIGCHANGED - CRYPT_OPTION_FIRST ];
	optionInfoPtr->intValue = TRUE;

	/* Unlock the config information to allow access by other threads */
	unlockGlobalResource( config );

	return( CRYPT_OK );
	}

int setOptionString( const CRYPT_ATTRIBUTE_TYPE option, const char *value,
					 const int valueLength )
	{
	OPTION_INFO *optionInfoPtr;
	char *valuePtr;

	/* Get a pointer to the option information and make sure everything is
	   OK */
	assert( option > CRYPT_OPTION_FIRST && option < CRYPT_OPTION_LAST );
	optionInfoPtr = &configOptions[ option - CRYPT_OPTION_FIRST ];
	assert( optionInfoPtr->type == OPTION_STRING );

	/* Try and allocate room for the new option */
	if( ( valuePtr = malloc( valueLength + 1 ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memcpy( valuePtr, value, valueLength );
	valuePtr[ valueLength ] = '\0';

	/* Lock the config information to ensure other threads don't try to
	   access it */
	lockGlobalResource( config );

	/* If the new value isn't different from the current one, don't do
	   anything */
	if( optionInfoPtr->strValue != NULL && \
		!memcmp( optionInfoPtr->strValue, value, valueLength ) )
		{
		free( valuePtr );
		unlockGlobalResource( config );
		return( CRYPT_OK );
		}

	/* If the string value which is currently set isn't the default setting,
	   clear and free it; if the qualified value is set, clear it and free
	   it */
	if( optionInfoPtr->strValue != optionInfoPtr->strDefault )
		{
		zeroise( optionInfoPtr->strValue, strlen( optionInfoPtr->strValue ) );
		free( optionInfoPtr->strValue );
		}
	if( optionInfoPtr->fqStrValue != NULL && \
		optionInfoPtr->fqStrValue != optionInfoPtr->strValue )
		{
		zeroise( optionInfoPtr->fqStrValue, strlen( optionInfoPtr->fqStrValue ) );
		free( optionInfoPtr->fqStrValue );
		}

	/* Set the value */
	optionInfoPtr->strValue = valuePtr;
	optionInfoPtr->fqStrValue = qualifyString( valuePtr );
	optionInfoPtr->dirty = TRUE;

	/* Remember that the config options have been changed */
	optionInfoPtr = \
			&configOptions[ CRYPT_OPTION_CONFIGCHANGED - CRYPT_OPTION_FIRST ];
	optionInfoPtr->intValue = TRUE;

	/* Unlock the config information to allow access by other threads */
	unlockGlobalResource( config );

	return( CRYPT_OK );
	}

/* Query the value of a numeric or string option */

int getOption( const CRYPT_ATTRIBUTE_TYPE option )
	{
	const OPTION_INFO *optionInfoPtr;
	int value;

	/* Get a pointer to the option information and make sure everything is
	   OK */
	assert( option > CRYPT_OPTION_FIRST && option < CRYPT_OPTION_LAST );
	optionInfoPtr = &configOptions[ option - CRYPT_OPTION_FIRST ];
	assert( optionInfoPtr->type == OPTION_NUMERIC || \
			optionInfoPtr->type == OPTION_BOOLEAN );

	/* Lock the config information to ensure other threads don't try to
	   access it */
	lockGlobalResource( config );

	value = optionInfoPtr->intValue;

	/* Unlock the config information to allow access by other threads */
	unlockGlobalResource( config );

	return( value );
	}

char *getOptionString( const CRYPT_ATTRIBUTE_TYPE option )
	{
	const OPTION_INFO *optionInfoPtr;
	char *value;

	/* Get a pointer to the option information and make sure everything is
	   OK */
	assert( option > CRYPT_OPTION_FIRST && option < CRYPT_OPTION_LAST );
	optionInfoPtr = &configOptions[ option - CRYPT_OPTION_FIRST ];
	assert( optionInfoPtr->type == OPTION_STRING );

	/* Lock the config information to ensure other threads don't try to
	   access it */
	lockGlobalResource( config );

	value = ( optionInfoPtr->fqStrValue != NULL ) ? \
			optionInfoPtr->fqStrValue : "";

	/* Unlock the config information to allow access by other threads */
	unlockGlobalResource( config );

	return( value );
	}

/* Initialise/clean up the config option handling */

void initConfig( void )
	{
	int i;

	/* Initialize any data structures required to make the config information
	   thread-safe */
	initGlobalResourceLock( config );
	lockGlobalResource( config );

	/* Perform a consistency check on the options */
	for( i = 1; i < CRYPT_OPTION_LAST - CRYPT_OPTION_FIRST; i++ )
		assert( configOptions[ i ].option == i + CRYPT_OPTION_FIRST );

	/* Walk through the config table setting up each option to point to
	   its default value */
	for( i = 1; configOptions[ i ].option != CRYPT_ATTRIBUTE_NONE; i++ )
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
	for( i = 1; configOptions[ i ].option != CRYPT_ATTRIBUTE_NONE; i++ )
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
*						Read and Write the Config Options 					*
*																			*
****************************************************************************/

#if defined( __UNIX__ )
  #include <pwd.h>
#elif defined( __OS2__ )
  #define INCL_DOSMISC			/* DosQuerySysInfo() */
  #include <os2.h>
#elif defined( __WIN32__ )
  #undef BOOLEAN				/* shlobj.h wants to redefine BOOLEAN */
  #include <shlobj.h>
  #define BOOLEAN	int
  #ifndef CSIDL_PERSONAL
    #define CSIDL_PERSONAL		0x05	/* 'My Documents' */
	#define CSIDL_APPDATA		0x1A	/* '<luser name>/Application Data' */
  #endif /* !CSIDL_PERSONAL */
  #ifndef CSIDL_FLAG_CREATE
	#define CSIDL_FLAG_CREATE	0x8000	/* Force directory creation */
  #endif /* !CSIDL_FLAG_CREATE */
  #ifndef SHGFP_TYPE_CURRENT
	#define SHGFP_TYPE_CURRENT	0
  #endif /* !SHGFP_TYPE_CURRENT */
#endif /* OS-specific includes */

/* Build the path to the config file */

static void buildConfigPath( char *path )
	{
#if defined( __OS2__ )
	ULONG aulSysInfo[ 1 ] = { 0 };
#elif defined( __UNIX__ )
	struct passwd *passwd;
	char *pathPtr;
	int length;
#elif defined( __WINDOWS__ )
	BOOLEAN gotPath = FALSE;
  #ifdef __WIN32__
	HINSTANCE hShell;
  #endif /* __WIN32__ */
#endif /* OS-specific info */

	/* Make sure the open fails if we can't build the path */
	*path = '\0';

	/* Build the path to the configuration file if necessary */
#if defined( __MSDOS__ )
	strcpy( path, "misc/cryptlib.p15" );
#elif defined( __WINDOWS__ )
  #if defined( __WIN32__ ) && \
	  !( defined( __BORLANDC__ ) && ( __BORLANDC__ < 0x500 ) )
	hShell = LoadLibrary( "SHFolder.dll" );
	if( hShell != NULL )
		{
		typedef HRESULT ( WINAPI *SHGETFOLDERPATH )( HWND hwndOwner,  
										int nFolder, HANDLE hToken, 
										DWORD dwFlags, LPTSTR lpszPath );
		SHGETFOLDERPATH pSHGetFolderPath;

		/* Try and find the location of the closest thing Windows has to a 
		   home directory.  This is a bit of a problem function in that both
		   the function name and parameters have changed over time, and it's
		   only included in pre-Win2K versions of the OS via a kludge DLL 
		   which takes the call and redirects it to the appropriate function 
		   anderswhere */
		pSHGetFolderPath = ( SHGETFOLDERPATH ) GetProcAddress( hShell, "SHGetFolderPathA" );
		if( pSHGetFolderPath != NULL && \
			pSHGetFolderPath( NULL, CSIDL_APPDATA | CSIDL_FLAG_CREATE, NULL,
							  SHGFP_TYPE_CURRENT, path ) == S_OK )
			gotPath = TRUE;
		FreeLibrary( hShell );
		}
  #endif /* __WIN32__ && !( Old Borland compiler) */
	if( !gotPath )
		GetWindowsDirectory( path, _MAX_PATH - 9 );
	strcat( path, "\\cryptlib.p15" );
#elif defined( __OS2__ )
	DosQuerySysInfo( QSV_BOOT_DRIVE, QSV_BOOT_DRIVE, ( PVOID ) aulSysInfo,
					 sizeof( ULONG ) );		/* Get boot drive info */
	if( *aulSysInfo == 0 )
		return;		/* No boot drive info */
	path[ 0 ] = *aulSysInfo + 'A' - 1;
	strcpy( path + 1, ":\\OS2\\cryptlib.p15" );	/* eg. C:\OS2\cryptlib.p15 */
#elif defined( __UNIX__ )
	/* Get the path to the config file in the users home directory */
	if( ( passwd = getpwuid( getuid() ) ) == NULL )
		return;		/* Huh? User not in passwd file */
	if( ( length = strlen( passwd->pw_dir ) ) > 1000 )
		/* You're kidding, right? */
		return;
	strncpy( path, passwd->pw_dir, length );
	if( path[ length ] != '/' )
		path[ length++ ] = '/';
	strcpy( path + length, ".cryptlib.p15" );
#elif defined( __TANDEM__ )
	strcpy( path, "$system.system.cryptlib" );
#elif defined( __MAC__ )
	strcpy( path, ":cryptlib.p15" );
#elif defined( __IBM4758__ )
	strcpy( path, "cryptlib" );
#elif defined( __VMCMS__ )
	strcpy( path, "cryptlib p15" );
#else
  #error You need to add the OS-specific code to build the config file path to cryptcfg.c.
#endif /* Various OS-specific file path defines */
	}

/* Read any user-defined configuration options.  Since the config file is an 
   untrusted source, we set the values in it via external messages rather than
   manipulating the config info directly, which means everything read is 
   subject to the usual ACL checks */

int readConfig( void )
	{
	CRYPT_KEYSET iCryptKeyset;
	CREATEOBJECT_INFO createInfo;
	RESOURCE_DATA msgData;
	STREAM stream;
	char configFilePath[ MAX_PATH_LENGTH + 128 ];	/* Protection for Windows */
	BYTE buffer[ 512 ], *bufPtr = buffer;
	int dataLength, status;

	/* Try and open the config file.  If we can't open it, it means the file 
	   doesn't exist, which isn't an error */
	buildConfigPath( configFilePath );
	if( strlen( configFilePath ) >= MAX_ATTRIBUTE_SIZE )
		/* It's somewhat suspicious if the path is this long, we can at least
		   try to read it using a shortened version */
		configFilePath[ MAX_ATTRIBUTE_SIZE ] = '\0';
	setMessageCreateObjectInfo( &createInfo, CRYPT_KEYSET_FILE );
	createInfo.arg1 = CRYPT_KEYOPT_READONLY;
	createInfo.strArg1 = configFilePath;
	createInfo.strArgLen1 = strlen( configFilePath );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_KEYSET );
	if( cryptStatusError( status ) )
		return( CRYPT_OK );
	iCryptKeyset = createInfo.cryptHandle;

	/* Get the config info from the keyset */
	setResourceData( &msgData, NULL, 0 );
	status = krnlSendMessage( iCryptKeyset, RESOURCE_IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_CONFIGDATA );
	if( cryptStatusOK( status ) && msgData.length > 512 && \
		( bufPtr = malloc( msgData.length ) ) == NULL )
		status = CRYPT_ERROR_MEMORY;
	if( cryptStatusOK( status ) )
		{
		msgData.data = bufPtr;
		status = krnlSendMessage( iCryptKeyset, RESOURCE_IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_CONFIGDATA );
		}
	krnlSendNotifier( iCryptKeyset, RESOURCE_IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		if( bufPtr != buffer && bufPtr != NULL )
			free( bufPtr );
		return( status );
		}
	dataLength = msgData.length;

	/* Read each config option */
	sMemConnect( &stream, bufPtr, msgData.length );
	while( !cryptStatusError( status ) && stell( &stream ) < dataLength )
		{
		CRYPT_ATTRIBUTE_TYPE attributeType;
		long option;
		int value, tag, i;

		/* Read the wrapper and option index and map it to the actual option.  
		   If we find an unknown index, we skip it and continue (this is done 
		   to handle new options which may have been added) */
		status = readSequence( &stream, NULL );
		if( !cryptStatusError( status ) )
			status = readShortInteger( &stream, &option );
		if( cryptStatusError( status ) )
			continue;
		for( i = 1; configOptions[ i ].option <= LAST_STORED_OPTION; i++ )
			if( configOptions[ i ].index == option )
				break;
		if( configOptions[ i ].option > LAST_STORED_OPTION )
			{
			readUniversal( &stream );
			continue;
			}
		attributeType = configOptions[ i ].option;

		/* Read the option value and set the option.  We don't treat a failure
		   to set the option as a problem since the user probably doesn't want
		   the entire system to fail because of a bad config option, and in any
		   case we'll fall back to a safe default value */
		tag = peekTag( &stream );
		if( tag == BER_BOOLEAN || tag == BER_INTEGER )
			{
			/* It's a numeric value, read the appropriate type and try and set
			   the option */
			if( tag == BER_BOOLEAN )
				status = readBoolean( &stream, &value );
			else
				{
				long integer;

				status = readShortInteger( &stream, &integer );
				value = ( int ) integer;
				}
			krnlSendMessage( CRYPT_UNUSED, RESOURCE_MESSAGE_SETATTRIBUTE,
							 &value, attributeType );
			}
		else
			{
			long length;

			/* It's a string value, set the option straight from the encoded
			   data */
			readTag( &stream );
			status = readLength( &stream, &length );
			if( cryptStatusError( status ) )
				continue;
			setResourceData( &msgData, sMemBufPtr( &stream ), length );
			krnlSendMessage( CRYPT_UNUSED, RESOURCE_MESSAGE_SETATTRIBUTE_S,
							 &msgData, attributeType );
			sSkip( &stream, length );
			}
		}
	sMemClose( &stream );

	/* Clean up */
	if( bufPtr != buffer )
		free( bufPtr );
	return( CRYPT_OK );
	}

/* Write any user-defined configuration options */

static int writeConfig( void )
	{
	CRYPT_CERTIFICATE iCryptCert;
	CREATEOBJECT_INFO createInfo;
	RESOURCE_DATA msgData;
	STREAM stream;
	char configFilePath[ MAX_PATH_LENGTH + 128 ];	/* Protection for Windows */
	void *trustedCertStatePtr, *buffer;
	int trustedCertStateIndex, i, dataLength = 0, status;

	/* Lock the config information to ensure other threads don't try to
	   access it */
	lockGlobalResource( config );

	/* Make a first pass through the config options to determine the total
	   encoded length of the ones which don't match the default setting */
	for( i = 1; configOptions[ i ].option <= LAST_STORED_OPTION; i++ )
		{
		const OPTION_INFO *optionInfoPtr = &configOptions[ i ];

		if( optionInfoPtr->type == OPTION_STRING )
			{
			/* If the string value is the same as the default, there's 
			   nothing to do.  Note that we compare the value rather than 
			   the pointers since they could point to the same value */
			if( optionInfoPtr->strValue == NULL || \
				( optionInfoPtr->strDefault != NULL && \
				  !strcmp( optionInfoPtr->strValue, optionInfoPtr->strDefault ) ) )
				continue;
			assert( optionInfoPtr->index != CRYPT_UNUSED );
			dataLength += ( int ) sizeofObject( \
						sizeofShortInteger( optionInfoPtr->index ) + \
						sizeofObject( strlen( optionInfoPtr->strValue ) ) );
			}
		else
			{
			/* If the integer/boolean value which is currently set isn't the
			   default setting, update it */
			if( optionInfoPtr->intValue == optionInfoPtr->intDefault )
				continue;
			assert( optionInfoPtr->index != CRYPT_UNUSED );
			dataLength += ( int ) sizeofObject( \
						sizeofShortInteger( optionInfoPtr->index ) + \
						( optionInfoPtr->type == OPTION_NUMERIC ? \
						  sizeofShortInteger( optionInfoPtr->intValue ) : \
						  sizeofBoolean() ) );
			}
		}

	/* If there are config options to store, write them to a memory buffer */
	if( dataLength )
		{
		/* Allocate a buffer to hold the encoded values */
		if( ( buffer = malloc( dataLength ) ) == NULL )
			{
			unlockGlobalResource( config );
			return( CRYPT_ERROR_MEMORY );
			}

		/* Write the config options */
		sMemOpen( &stream, buffer, dataLength );
		for( i = 1; configOptions[ i ].option <= LAST_STORED_OPTION; i++ )
			{
			const OPTION_INFO *optionInfoPtr = &configOptions[ i ];

			if( optionInfoPtr->type == OPTION_STRING )
				{
				if( optionInfoPtr->strValue == NULL || \
					( optionInfoPtr->strDefault != NULL && \
					  !strcmp( optionInfoPtr->strValue, 
							   optionInfoPtr->strDefault ) ) )
					continue;
				writeSequence( &stream, 
							   sizeofShortInteger( optionInfoPtr->index ) +
							   sizeofObject( strlen( optionInfoPtr->strValue ) ) );
				writeShortInteger( &stream, optionInfoPtr->index, DEFAULT_TAG );
				writeCharacterString( &stream, optionInfoPtr->strValue,
									  strlen( optionInfoPtr->strValue ), 
									  BER_STRING_UTF8 );
				continue;
				}

			if( optionInfoPtr->intValue == optionInfoPtr->intDefault )
				continue;
			if( optionInfoPtr->type == OPTION_NUMERIC )
				{
				writeSequence( &stream, 
							   sizeofShortInteger( optionInfoPtr->index ) +
							   sizeofShortInteger( optionInfoPtr->intValue ) );
				writeShortInteger( &stream, optionInfoPtr->index, 
								   DEFAULT_TAG );
				writeShortInteger( &stream, optionInfoPtr->intValue, 
								   DEFAULT_TAG );
				}
			else
				{
				writeSequence( &stream, 
							   sizeofShortInteger( optionInfoPtr->index ) +
							   sizeofBoolean() );
				writeShortInteger( &stream, optionInfoPtr->index, 
								   DEFAULT_TAG );
				writeBoolean( &stream, optionInfoPtr->intValue, DEFAULT_TAG );
				}
			}
		assert( sGetStatus( &stream ) == CRYPT_OK );
		sMemDisconnect( &stream );
		}

	/* Unlock the config information to allow access by other threads */
	unlockGlobalResource( config );

	/* If we've gone back to all default values from having non-default ones 
	   stored and there aren't any implicitly trusted certs, there won't be 
	   anything to write, so we just delete the config file */
	if( !dataLength && \
		getFirstTrustedCert( &trustedCertStatePtr, 
							 &trustedCertStateIndex ) == CRYPT_ERROR )
		{
		buildConfigPath( configFilePath );
		fileUnlink( configFilePath );
		return( CRYPT_OK );
		}

	/* Build the path to the config file and try and create it */
	buildConfigPath( configFilePath );
	setMessageCreateObjectInfo( &createInfo, CRYPT_KEYSET_FILE );
	createInfo.arg1 = CRYPT_KEYOPT_CREATE;
	createInfo.strArg1 = configFilePath;
	createInfo.strArgLen1 = strlen( configFilePath );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_KEYSET );
	if( cryptStatusError( status ) )
		{
		free( buffer );
		return( status );
		}

	/* Send the config info to the keyset if there is any */
	if( dataLength )
		{
		setResourceData( &msgData, buffer, dataLength );
		status = krnlSendMessage( createInfo.cryptHandle, 
								  RESOURCE_IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_IATTRIBUTE_CONFIGDATA );
		free( buffer );
		}

	/* Send any implicitly trusted certs to the keyset.  Since there's not
	   much we can do in terms of error recovery if a failure occurs at this 
	   point, we don't check the return value for the setkey message but just
	   move on to the next cert */
	iCryptCert = getFirstTrustedCert( &trustedCertStatePtr, 
									  &trustedCertStateIndex );
	while( iCryptCert != CRYPT_ERROR )
		{
		MESSAGE_KEYMGMT_INFO setkeyInfo;

		setMessageKeymgmtInfo( &setkeyInfo, CRYPT_KEYID_NONE, NULL, 0, 
							   NULL, 0, KEYMGMT_FLAG_PUBLICKEY );
		krnlSendMessage( createInfo.cryptHandle, RESOURCE_IMESSAGE_KEY_SETKEY, 
						 &setkeyInfo, iCryptCert );
		iCryptCert = getNextTrustedCert( &trustedCertStatePtr, 
										 &trustedCertStateIndex );
		}

	/* Clean up */
	krnlSendNotifier( createInfo.cryptHandle, RESOURCE_IMESSAGE_DECREFCOUNT );
	return( status );
	}
