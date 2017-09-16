/****************************************************************************
*																			*
*						cryptlib LDAP Mapping Routines						*
*					  Copyright Peter Gutmann 1998-1999						*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "keyset.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "keyset.h"
#else
  #include "crypt.h"
  #include "misc/keyset.h"
#endif /* Compiler-specific includes */

/* LDAP requires us to set up complicated structures to handle DN's.  The
   following values define the upper limit for DN string data and the
   maximum number of attributes we write to a directory */

#define MAX_DN_STRINGSIZE		1024
#define MAX_LDAP_ATTRIBUTES		20

#ifdef DBX_LDAP

/* Whether the LDAP library supports SSL-protected access to the directory */

static BOOLEAN isLDAPSSL = FALSE;

/****************************************************************************
*																			*
*						 	Windows Init/Shutdown Routines					*
*																			*
****************************************************************************/

#ifdef __WINDOWS__

/* Global function pointers.  These are necessary because the functions need
   to be dynamically linked since very few systems contain the necessary
   DLL's (LDAP?  Get real).  Explicitly linking to them will make cryptlib
   unloadable on most systems */

#define NULL_HINSTANCE	( HINSTANCE ) NULL

static HINSTANCE hLDAP = NULL_HINSTANCE;

typedef int ( LDAP_CALL *LDAP_ADD_S )( LDAP *ld, const char *dn, LDAPMod **attrs );
typedef void ( LDAP_CALL *LDAP_BER_FREE )( BerElement *ber, int freebuf );
typedef int ( LDAP_CALL *LDAP_DELETE_S )( LDAP *ld, const char *dn );
typedef char * ( LDAP_CALL *LDAP_FIRST_ATTRIBUTE )( LDAP *ld, LDAPMessage *entry,
										  BerElement **ber );
typedef LDAPMessage * ( LDAP_CALL *LDAP_FIRST_ENTRY )( LDAP *ld, LDAPMessage *result );
typedef int ( LDAP_CALL *LDAP_GET_LDERRNO )( LDAP *ld, char **m, char **s );
typedef struct berval ** ( LDAP_CALL *LDAP_GET_VALUES_LEN )( LDAP *ld, LDAPMessage *entry,
												   const char *attr );
typedef LDAP * ( LDAP_CALL *LDAP_INIT )( const char *host, int port );
typedef void ( LDAP_CALL *LDAP_MEMFREE )( void *p );
typedef void ( LDAP_CALL *LDAP_MODSFREE )( LDAPMod **mods, int freemods );
typedef int ( LDAP_CALL *LDAP_MSGFREE )( LDAPMessage *lm );
typedef LDAPMessage * ( LDAP_CALL *LDAP_NEXT_ENTRY )( LDAP *ld, LDAPMessage *result );
typedef int ( LDAP_CALL *LDAP_SEARCH_S )( LDAP *ld, const char *base, int scope,
								const char *filter, char **attrs,
								int attrsonly, LDAPMessage **res );
typedef int ( LDAP_CALL *LDAP_SET_OPTION )( LDAP *ld, int option, void *optdata );
typedef int ( LDAP_CALL *LDAP_SIMPLE_BIND_S )( LDAP *ld, const char *who,
									 const char *passwd );
typedef int ( LDAP_CALL *LDAP_UNBIND )( LDAP *ld );
typedef void ( LDAP_CALL *LDAP_VALUE_FREE_LEN )( struct berval **vals );
typedef LDAP * ( LDAP_CALL *LDAPSSL_INIT )( const char *defhost, int defport, int defsecure );
typedef int ( LDAP_CALL *LDAPSSL_CLIENT_INIT )( const char *certdbpath, void *certdbhandle );
static LDAP_ADD_S p_ldap_add_s = NULL;
static LDAP_BER_FREE p_ldap_ber_free = NULL;
static LDAP_DELETE_S p_ldap_delete_s = NULL;
static LDAP_FIRST_ATTRIBUTE p_ldap_first_attribute = NULL;
static LDAP_FIRST_ENTRY p_ldap_first_entry = NULL;
static LDAP_GET_LDERRNO p_ldap_get_lderrno = NULL;
static LDAP_GET_VALUES_LEN p_ldap_get_values_len = NULL;
static LDAP_INIT p_ldap_init = NULL;
static LDAP_MEMFREE p_ldap_memfree = NULL;
static LDAP_MODSFREE p_ldap_mods_free = NULL;
static LDAP_NEXT_ENTRY p_ldap_next_entry = NULL;
static LDAP_MSGFREE p_ldap_msgfree = NULL;
static LDAP_SEARCH_S p_ldap_search_s = NULL;
static LDAP_SET_OPTION p_ldap_set_option = NULL;
static LDAP_SIMPLE_BIND_S p_ldap_simple_bind_s = NULL;
static LDAP_UNBIND p_ldap_unbind = NULL;
static LDAP_VALUE_FREE_LEN p_ldap_value_free_len = NULL;
static LDAPSSL_INIT p_ldapssl_init = NULL;
static LDAPSSL_CLIENT_INIT p_ldapssl_client_init = NULL;

/* The use of dynamically bound function pointers vs statically linked
   functions requires a bit of sleight of hand since we can't give the
   pointers the same names as prototyped functions.  To get around this we
   redefine the actual function names to the names of the pointers */

#define ldap_add_s				p_ldap_add_s
#define ldap_ber_free			p_ldap_ber_free
#define ldap_delete_s			p_ldap_delete_s
#define ldap_first_attribute	p_ldap_first_attribute
#define ldap_first_entry		p_ldap_first_entry
#define ldap_get_lderrno		p_ldap_get_lderrno
#define ldap_get_values_len		p_ldap_get_values_len
#define ldap_init				p_ldap_init
#define ldap_memfree			p_ldap_memfree
#define ldap_mods_free			p_ldap_mods_free
#define ldap_msgfree			p_ldap_msgfree
#define ldap_next_entry			p_ldap_next_entry
#define ldap_search_s			p_ldap_search_s
#define ldap_set_option			p_ldap_set_option
#define ldap_simple_bind_s		p_ldap_simple_bind_s
#define ldap_unbind				p_ldap_unbind
#define ldap_value_free_len		p_ldap_value_free_len
#define ldapssl_init			p_ldapssl_init
#define ldapssl_client_init		p_ldapssl_client_init

/* The name of the LDAP driver, in this case the Netscape LDAPv3 driver.
   These come in SSL and non-SSL versions, first we try the SSL one and then
   the non-SSL one */

#ifdef __WIN16__
  #define LDAP_LIBNAME		"NSLDSS16.DLL"
  #define LDAP_SSL_LIBNAME	"NSLDAP16.DLL"
#else
  #define LDAP_LIBNAME		"NSLDAP32v30.DLL"
  #define LDAP_SSL_LIBNAME	"NSLDAPSSL32v30.DLL"
#endif /* __WIN16__ */

/* Dynamically load and unload any necessary LDAP libraries */

void dbxInitLDAP( void )
	{
#ifdef __WIN16__
	UINT errorMode;
#endif /* __WIN16__ */

	/* If the LDAP module is already linked in, don't do anything */
	if( hLDAP != NULL_HINSTANCE )
		return;

	/* Obtain a handle to the module containing the LDAP functions */
#ifdef __WIN16__
	errorMode = SetErrorMode( SEM_NOOPENFILEERRORBOX );
	if( ( hLDAP = LoadLibrary( LDAP_SSL_LIBNAME ) ) >= HINSTANCE_ERROR )
		isLDAPSSL = TRUE;
	else
		hLDAP = LoadLibrary( LDAP_LIBNAME );
	SetErrorMode( errorMode );
	if( hLDAP < HINSTANCE_ERROR )
		{
		hLDAP = NULL_HINSTANCE;
		return;
		}
#else
	if( ( hLDAP = LoadLibrary( LDAP_SSL_LIBNAME ) ) != NULL_HINSTANCE )
		isLDAPSSL = TRUE;
	else
		if( ( hLDAP = LoadLibrary( LDAP_LIBNAME ) ) == NULL_HINSTANCE )
			return;
#endif /* __WIN32__ */

	/* Now get pointers to the functions */
	p_ldap_add_s = ( LDAP_ADD_S ) GetProcAddress( hLDAP, "ldap_add_s" );
	p_ldap_ber_free = ( LDAP_BER_FREE ) GetProcAddress( hLDAP, "ldap_ber_free" );
	p_ldap_delete_s = ( LDAP_DELETE_S ) GetProcAddress( hLDAP, "ldap_delete_s" );
	p_ldap_first_attribute = ( LDAP_FIRST_ATTRIBUTE ) GetProcAddress( hLDAP, "ldap_first_attribute" );
	p_ldap_first_entry = ( LDAP_FIRST_ENTRY ) GetProcAddress( hLDAP, "ldap_first_entry" );
	p_ldap_get_lderrno = ( LDAP_GET_LDERRNO ) GetProcAddress( hLDAP, "ldap_get_lderrno" );
	p_ldap_get_values_len = ( LDAP_GET_VALUES_LEN ) GetProcAddress( hLDAP, "ldap_get_values_len" );
	p_ldap_init = ( LDAP_INIT ) GetProcAddress( hLDAP, "ldap_init" );
	p_ldap_memfree = ( LDAP_MEMFREE ) GetProcAddress( hLDAP, "ldap_memfree" );
	p_ldap_mods_free = ( LDAP_MODSFREE ) GetProcAddress( hLDAP, "ldap_mods_free" );
	p_ldap_msgfree = ( LDAP_MSGFREE ) GetProcAddress( hLDAP, "ldap_msgfree" );
	p_ldap_next_entry = ( LDAP_NEXT_ENTRY ) GetProcAddress( hLDAP, "ldap_next_entry" );
	p_ldap_search_s = ( LDAP_SEARCH_S ) GetProcAddress( hLDAP, "ldap_search_s" );
	p_ldap_set_option = ( LDAP_SET_OPTION ) GetProcAddress( hLDAP, "ldap_set_option" );
	p_ldap_simple_bind_s = ( LDAP_SIMPLE_BIND_S ) GetProcAddress( hLDAP, "ldap_simple_bind_s" );
	p_ldap_unbind = ( LDAP_UNBIND ) GetProcAddress( hLDAP, "ldap_unbind" );
	p_ldap_value_free_len = ( LDAP_VALUE_FREE_LEN ) GetProcAddress( hLDAP, "ldap_value_free_len" );
	p_ldapssl_init = ( LDAPSSL_INIT ) GetProcAddress( hLDAP, "ldapssl_init" );
	p_ldapssl_client_init = ( LDAPSSL_CLIENT_INIT ) GetProcAddress( hLDAP, "ldapssl_client_init" );

	/* Make sure we got valid pointers for every LDAP function */
	if( p_ldap_add_s == NULL || p_ldap_ber_free == NULL || \
		p_ldap_delete_s == NULL || p_ldap_first_attribute == NULL || \
		p_ldap_first_entry == NULL || p_ldap_init == NULL || \
		p_ldap_get_lderrno == NULL || p_ldap_get_values_len == NULL || \
		p_ldap_memfree == NULL || p_ldap_mods_free == NULL || \
		p_ldap_msgfree == NULL || p_ldap_next_entry == NULL || \
		p_ldap_search_s == NULL || p_ldap_set_option == NULL || \
		p_ldap_simple_bind_s == NULL || p_ldap_unbind == NULL || \
		p_ldap_value_free_len == NULL )
		{
		/* Free the library reference and reset the handle */
		FreeLibrary( hLDAP );
		hLDAP = NULL_HINSTANCE;
		}

	/* If we got this far but can't find the SSL entry points, continue
	   without SSL support */
	if( isLDAPSSL && ( p_ldapssl_init == NULL || p_ldapssl_client_init == NULL ) )
		isLDAPSSL = FALSE;
	}

void dbxEndLDAP( void )
	{
	if( hLDAP != NULL_HINSTANCE )
		FreeLibrary( hLDAP );
	hLDAP = NULL_HINSTANCE;
	}
#endif /* __WINDOWS__ */

/****************************************************************************
*																			*
*						 		Utility Routines							*
*																			*
****************************************************************************/

/* Assign a name for an LDAP object/attribute field */

static void assignFieldName( char *buffer, CRYPT_ATTRIBUTE_TYPE option )
	{
	RESOURCE_DATA msgData;

	setResourceData( &msgData, buffer, CRYPT_MAX_TEXTSIZE );
	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE_S, 
					 &msgData, option );
	buffer[ msgData.length ] = '\0';
	}

/* Get information on an LDAP error */

static void getErrorInfo( KEYSET_INFO *keysetInfo )
	{
	char *errorMessage;

	keysetInfo->errorCode = ldap_get_lderrno( keysetInfo->keysetLDAP.ld, NULL,
											  &errorMessage );
	if( errorMessage != NULL )
		{
		strncpy( keysetInfo->errorMessage, errorMessage, MAX_ERRMSG_SIZE - 1 );
		keysetInfo->errorMessage[ MAX_ERRMSG_SIZE - 1 ] = '\0';
		}
	else
		*keysetInfo->errorMessage = '\0';
	}

/* Map an LDAP error to the corresponding cryptlib error */

static int mapLDAPerror( const int ldapError, const int defaultError )
	{
	switch( ldapError )
		{
		case LDAP_INAPPROPRIATE_AUTH:
		case LDAP_INVALID_CREDENTIALS:
		case LDAP_INSUFFICIENT_ACCESS:
			return( CRYPT_ERROR_PERMISSION );

		case LDAP_TYPE_OR_VALUE_EXISTS:
			return( CRYPT_ERROR_DUPLICATE );
		}

	return( defaultError );
	}

/* Copy attribute information into an LDAPMod structure so it can be written to
   the directory */

static LDAPMod *copyAttribute( const char *attributeName,
							   const void *attributeValue,
							   const int attributeLength )
	{
	LDAPMod *ldapModPtr;

	/* Allocate room for the LDAPMod structure and the data pointers.
	   mod_values and mod_bvalues members have the same representation so we
	   can allocate them with the same malloc */
	if( ( ldapModPtr = ( LDAPMod * ) malloc( sizeof( LDAPMod ) ) ) == NULL )
		return( NULL );
	if( ( ldapModPtr->mod_values = malloc( 2 * sizeof( void * ) ) ) == NULL )
		{
		free( ldapModPtr );
		return( NULL );
		}

	/* Set up the pointers to the attribute information.  This differs
	   slightly depending on whether we're adding text or binary data */
	if( !attributeLength )
		{
		ldapModPtr->mod_op = LDAP_MOD_ADD;
		ldapModPtr->mod_type = ( char * ) attributeName;
		ldapModPtr->mod_values[ 0 ] = ( char * ) attributeValue;
		ldapModPtr->mod_values[ 1 ] = NULL;
		}
	else
		{
		if( ( ldapModPtr->mod_bvalues[ 0 ] = \
							malloc( sizeof( struct berval ) ) ) == NULL )
			{
			free( ldapModPtr->mod_values );
			free( ldapModPtr );
			return( NULL );
			}
		ldapModPtr->mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
		ldapModPtr->mod_type = ( char * ) attributeName;
		ldapModPtr->mod_bvalues[ 0 ]->bv_len = attributeLength;
		ldapModPtr->mod_bvalues[ 0 ]->bv_val = ( char * ) attributeValue;
		ldapModPtr->mod_bvalues[ 1 ] = NULL;
		}

	return( ldapModPtr );
	}

/* Get DN information from a certificate.  We don't have to check for 
   overflows because the cert.management code limits the size of each 
   component to a small fraction of the total buffer size */

static void copyComponent( char *dest, char *src )
	{
	while( *src )
		{
		const char ch = *src++;

		if( ch == ',' )
			*dest++ = '\\';
		*dest++ = ch;
		}
	*dest++ = '\0';
	}

static int getDNInfo( const CRYPT_HANDLE iCryptHandle, char *dn, char *C, 
					  char *SP, char *L, char *O, char *OU, char *CN, 
					  char *email )
	{
	char *bufPtr = dn;

	strcpy( dn, "CN=" );
#if 0
	strcpy( buffer + 3, ldapInfo->CN );
	bufPtr += strlen( bufPtr );
	if( ldapInfo->OU && *( ldapInfo->OU ) )
		{
		strcpy( bufPtr, ",OU=" );
		copyComponent( bufPtr + 4, ldapInfo->OU );
		bufPtr += strlen( bufPtr );
		}
	if( ldapInfo->O && *( ldapInfo->O ) )
		{
		strcpy( bufPtr, ",O=" );
		copyComponent( bufPtr + 3, ldapInfo->O );
		bufPtr += strlen( bufPtr );
		}
	if( ldapInfo->L && *( ldapInfo->L ) )
		{
		strcpy( bufPtr, ",L=" );
		copyComponent( bufPtr + 3, ldapInfo->L );
		bufPtr += strlen( bufPtr );
		}
	if( ldapInfo->SP && *( ldapInfo->SP ) )
		{
		strcpy( bufPtr, ",ST=" );	/* Not to be confused with ST=street */
		copyComponent( bufPtr + 4, ldapInfo->SP );
		bufPtr += strlen( bufPtr );
		}
	strcpy( bufPtr, ",C=" );
	copyComponent( bufPtr + 3, ldapInfo->C );
#endif

	return( CRYPT_OK );
	}

/* Decompose an LDAP URL into a server name and optional port */

static int parseURL( char *ldapServer, const char *url, const BOOLEAN isSSL )
	{
	int ldapPort = ( isSSL ) ? LDAPS_PORT : LDAP_PORT, len;

	/* Skip a leading URL specifier if this is present */
	if( !strnicmp( url, "ldap://", 7 ) )
		url += 7;
	else
		if( !strnicmp( url, "ldaps://", 8 ) )
			url += 8;

	/* Decompose what's left into a FQDN and port */
	for( len = 0; url[ len ]; len++ )
		if( url[ len ] == ':' )
			break;
	strncpy( ldapServer, url, len );
	ldapServer[ len ] = '\0';
	if( url[ len ] )
		ldapPort = atoi( url + len + 1 );

	return( ldapPort );
	}

/****************************************************************************
*																			*
*						 	Directory Open/Close Routines					*
*																			*
****************************************************************************/

/* Close a previously-opened LDAP connection.  We have to have this before
   the init function since it may be called by it if the open process fails.  
   This is necessary because the complex LDAP open may require a fairly 
   extensive cleanup afterwards */

static void shutdownKeysetFunction( KEYSET_INFO *keysetInfo )
	{
	/* If there was a problem opening the connection, there's nothing to do */
	if( !keysetInfo->isOpen )
		return;

	ldap_unbind( keysetInfo->keysetLDAP.ld );
	keysetInfo->keysetLDAP.ld = NULL;
	}

/* Open a connection to an LDAP directory */

static int initKeysetFunction( KEYSET_INFO *keysetInfo, const char *server,
							   const char *user, const char *password,
							   const char *sslInfo, 
							   const CRYPT_KEYOPT_TYPE options )
	{
	char ldapServer[ MAX_URL_SIZE ];
	int maxEntries = 2, ldapPort;

	/* Check the URL.  The Netscape API provides the function
	   ldap_is_ldap_url() for this, but this requires a complete LDAP URL
	   rather than just a server name and port */
	if( strlen( server ) > MAX_URL_SIZE - 1 )
		return( CRYPT_ARGERROR_STR1 );
	ldapPort = parseURL( ldapServer, server, ( sslInfo != NULL ) ? TRUE : FALSE );

	/* Open the connection to the server.  If the call has supplied SSL
	   information, we try an SSL connect, otherwise we do a normal connect */
	if( sslInfo != NULL )
		{
		if( !isLDAPSSL || ldapssl_client_init( sslInfo, NULL ) < 0 )
			/* We can't connect at the requested security level */
			return( CRYPT_ERROR_NOSECURE );
		if( ( keysetInfo->keysetLDAP.ld = ldapssl_init( ldapServer, ldapPort, 1 ) ) == NULL )
			return( CRYPT_ERROR_OPEN );
		}
	else
		if( ( keysetInfo->keysetLDAP.ld = ldap_init( ldapServer, ldapPort ) ) == NULL )
			return( CRYPT_ERROR_OPEN );
	if( ldap_simple_bind_s( keysetInfo->keysetLDAP.ld, ( char * ) user,
							( char * ) password ) != LDAP_SUCCESS )
		{
		getErrorInfo( keysetInfo );
		ldap_unbind( keysetInfo->keysetLDAP.ld );
		keysetInfo->keysetLDAP.ld = NULL;
		return( CRYPT_ERROR_OPEN );
		}

	/* Set the maximum number of returned entries to 2 */
	ldap_set_option( keysetInfo->keysetLDAP.ld, LDAP_OPT_SIZELIMIT, &maxEntries );

	/* Set up the names of the objects and attributes */
	assignFieldName( keysetInfo->keysetLDAP.nameObjectClass,
					 CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS );
	assignFieldName( keysetInfo->keysetLDAP.nameCACert,
					 CRYPT_OPTION_KEYS_LDAP_CACERTNAME );
	assignFieldName( keysetInfo->keysetLDAP.nameCert,
					 CRYPT_OPTION_KEYS_LDAP_CERTNAME );
	assignFieldName( keysetInfo->keysetLDAP.nameCRL,
					 CRYPT_OPTION_KEYS_LDAP_CRLNAME );
	assignFieldName( keysetInfo->keysetLDAP.nameEmail,
					 CRYPT_OPTION_KEYS_LDAP_EMAILNAME );
	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
					 &keysetInfo->keysetLDAP.objectType, 
					 CRYPT_OPTION_KEYS_LDAP_OBJECTTYPE );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Directory Access Routines						*
*																			*
****************************************************************************/

/* Retrieve a key attribute from an LDAP directory */

static int getItemFunction( KEYSET_INFO *keysetInfo, 
							CRYPT_HANDLE *iCryptHandle, 
							const CRYPT_KEYID_TYPE keyIDtype, 
							const void *keyID,  const int keyIDlength, 
							void *auxInfo, int *auxInfoLength, 
							const int flags )
	{
	LDAPMessage *result, *resultEntry;
	BerElement *ber;
	struct berval **valuePtrs;
	char *attributePtr;
	int status = CRYPT_OK;

	assert( keyIDtype == CRYPT_KEYID_NAME || keyIDtype == CRYPT_KEYID_EMAIL );
	assert( auxInfo == NULL ); assert( *auxInfoLength == 0 );

	/* If we're not in the middle of an ongoing fetch, send the query to the
	   server */
	if( keysetInfo->keysetLDAP.queryState != QUERY_INPROGRESS )
		{
		const CRYPT_CERTTYPE_TYPE objectType = keysetInfo->keysetLDAP.objectType;
		const char *certAttributes[] = { keysetInfo->keysetLDAP.nameCert, NULL };
		const char *caCertAttributes[] = { keysetInfo->keysetLDAP.nameCACert, NULL };
		const char *crlAttributes[] = { keysetInfo->keysetLDAP.nameCRL, NULL };
		char dn[ MAX_DN_STRINGSIZE ];
		int ldapStatus = LDAP_OTHER;

		/* Convert the DN into a null-terminated form */
		if( keyIDlength > MAX_DN_STRINGSIZE - 1 )
			return( CRYPT_ARGERROR_STR1 );
		memcpy( dn, keyID, keyIDlength );
		dn[ keyIDlength ] = '\0';

		/* Try and retrieve the entry for this DN from the directory.  We use
		   a base specified by the DN, a chop of 0 (to return only the
		   current entry), any object class (to get around the problem of
		   implementations which stash certs in whatever they feel like), and
		   look for a certificate attribute.  If the search fails for this
		   attribute, we try again but this time go for a CA certificate
		   attribute which unfortunately slows down the search somewhat when
		   the cert isn't found but can't really be avoided since there's no
		   way to tell in advance whether a cert will be an end entity or a
		   CA cert.  To complicate things even further, we may also need to 
		   check for a CRL in case this is what the user is after */
		if( objectType == CRYPT_CERTTYPE_NONE || \
			objectType == CRYPT_CERTTYPE_CERTIFICATE )
			ldapStatus = ldap_search_s( keysetInfo->keysetLDAP.ld, dn,
								LDAP_SCOPE_BASE, "(objectclass=*)", 
								( char ** ) certAttributes, 0, &result );
		if( ldapStatus != LDAP_SUCCESS && \
			( objectType == CRYPT_CERTTYPE_NONE || \
			  objectType == CRYPT_CERTTYPE_CERTIFICATE ) )
			ldapStatus = ldap_search_s( keysetInfo->keysetLDAP.ld, dn,
								LDAP_SCOPE_BASE, "(objectclass=*)", 
								( char ** ) caCertAttributes, 0, &result );
		if( ldapStatus != LDAP_SUCCESS && \
			( objectType == CRYPT_CERTTYPE_NONE || \
			  objectType == CRYPT_CERTTYPE_CRL ) )
			ldapStatus = ldap_search_s( keysetInfo->keysetLDAP.ld, dn,
								LDAP_SCOPE_BASE, "(objectclass=*)", 
								( char ** ) crlAttributes, 0, &result );
		if( ldapStatus != LDAP_SUCCESS )
			{
			getErrorInfo( keysetInfo );
			return( mapLDAPerror( ldapStatus, CRYPT_ERROR_READ ) );
			}

		/* We got something, start fetching the results */
		if( ( resultEntry = ldap_first_entry( keysetInfo->keysetLDAP.ld, result ) ) == NULL )
			{
			ldap_msgfree( result );
			return( CRYPT_ERROR_NOTFOUND );
			}
		}
	else
		{
		/* Make sure the parameters are correct for a query */
		if( keyIDtype != CRYPT_KEYID_NONE || keyID != NULL )
			return( CRYPT_ERROR_INCOMPLETE );

		/* We're in an ongoing query, try and fetch the next set of results */
		if( ( resultEntry = ldap_next_entry( keysetInfo->keysetLDAP.ld,
								keysetInfo->keysetLDAP.result ) ) == NULL )
			{
			/* No more results, wrap up the processing */
			ldap_msgfree( keysetInfo->keysetLDAP.result );
			keysetInfo->keysetLDAP.result = NULL;
			keysetInfo->keysetLDAP.queryState = QUERY_NONE;
			return( CRYPT_ERROR_COMPLETE );
			}
		}

	/* If this is the start of a general query, save the query state and 
	   record the fact that we're in the middle of a query */
	if( keysetInfo->keysetLDAP.queryState == QUERY_START )
		{
		keysetInfo->keysetLDAP.queryState = QUERY_INPROGRESS;
		keysetInfo->keysetLDAP.result = result;
		}

	/* Copy out the certificate */
	if( ( attributePtr = ldap_first_attribute( keysetInfo->keysetLDAP.ld,
											   resultEntry, &ber ) ) == NULL )
		{
		if( keysetInfo->keysetLDAP.queryState != QUERY_INPROGRESS )
			ldap_msgfree( result );
		return( CRYPT_ERROR_NOTFOUND );
		}
	valuePtrs = ldap_get_values_len( keysetInfo->keysetLDAP.ld, resultEntry,
									 attributePtr );
	if( valuePtrs != NULL )
		{
		CREATEOBJECT_INFO createInfo;

		/* Create a certificate object from the returned data */
		setMessageCreateObjectInfo( &createInfo, CERTIMPORT_NORMAL );
		createInfo.createIndirect = TRUE;
		createInfo.strArg1 = valuePtrs[ 0 ]->bv_val;
		createInfo.strArgLen1 = valuePtrs[ 0 ]->bv_len;
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
								  &createInfo, OBJECT_TYPE_CERTIFICATE );
		if( cryptStatusOK( status ) )
			*iCryptHandle = createInfo.cryptHandle;

		ldap_value_free_len( valuePtrs );
		}
	else
		status = CRYPT_ERROR_NOTFOUND;

	/* Clean up */
	ldap_ber_free( ber, 1 );
	ldap_memfree( attributePtr );
	if( keysetInfo->keysetLDAP.queryState != QUERY_INPROGRESS )
		ldap_msgfree( result );
	return( status );
	}

/* Add an entry/attribute to an LDAP directory */

static int addCert( KEYSET_INFO *keysetInfo, const CRYPT_HANDLE iCryptHandle )
	{
	RESOURCE_DATA msgData;
	LDAPMod *ldapMod[ MAX_LDAP_ATTRIBUTES ];
	BYTE keyData[ MAX_CERT_SIZE ];
	char dn[ MAX_DN_STRINGSIZE ];
	char C[ CRYPT_MAX_TEXTSIZE + 1 ], SP[ CRYPT_MAX_TEXTSIZE + 1 ],
		L[ CRYPT_MAX_TEXTSIZE + 1 ], O[ CRYPT_MAX_TEXTSIZE + 1 ],
		OU[ CRYPT_MAX_TEXTSIZE + 1 ], CN[ CRYPT_MAX_TEXTSIZE + 1 ],
		email[ CRYPT_MAX_TEXTSIZE + 1 ];
	int keyDataLength, ldapModIndex = 1, status = CRYPT_OK;

	/* Get the DN information from the certificate */
	status = getDNInfo( iCryptHandle, dn, C, SP, L, O, OU, CN, email );
	if( cryptStatusOK( status ) )
		{
		/* Get the certificate data */
		setResourceData( &msgData, keyData, MAX_CERT_SIZE );
		status = krnlSendMessage( iCryptHandle, RESOURCE_IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_ENC_CERT );
		keyDataLength = msgData.length;
		}
	if( cryptStatusError( status ) )
		/* Convert any low-level cert-specific error into something generic
		   which makes a bit more sense to the caller */
		return( CRYPT_ARGERROR_NUM1 );

	/* Set up the fixed attributes and certificate data.  This currently
	   always adds a cert as a standard certificate rather than a CA
	   certificate because of uncertainty over what other implementations
	   will try and look for, once enough other software uses the CA cert
	   attribute this can be switched over */
	if( ( ldapMod[ 0 ] = copyAttribute( keysetInfo->keysetLDAP.nameObjectClass,
										"certPerson", 0 ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	if( ( ldapMod[ ldapModIndex++ ] = copyAttribute( keysetInfo->keysetLDAP.nameCert,
										keyData, keyDataLength ) ) == NULL )
		status = CRYPT_ERROR_MEMORY;

	/* Set up the DN/identification information */
	if( cryptStatusOK( status ) && *email && \
		( ldapMod[ ldapModIndex++ ] = \
				copyAttribute( keysetInfo->keysetLDAP.nameEmail, email, 0 ) ) == NULL )
		status = CRYPT_ERROR_MEMORY;
	if( cryptStatusOK( status ) && *CN && \
		( ldapMod[ ldapModIndex++ ] = copyAttribute( "CN", CN, 0 ) ) == NULL )
		status = CRYPT_ERROR_MEMORY;
	if( cryptStatusOK( status ) && *OU && \
		( ldapMod[ ldapModIndex++ ] = copyAttribute( "OU", OU, 0 ) ) == NULL )
		status = CRYPT_ERROR_MEMORY;
	if( cryptStatusOK( status ) && *O && \
		( ldapMod[ ldapModIndex++ ] = copyAttribute( "O", O, 0 ) ) == NULL )
		status = CRYPT_ERROR_MEMORY;
	if( cryptStatusOK( status ) && *L && \
		( ldapMod[ ldapModIndex++ ] = copyAttribute( "L", L, 0 ) ) == NULL )
		status = CRYPT_ERROR_MEMORY;
	if( cryptStatusOK( status ) && *SP && \
		( ldapMod[ ldapModIndex++ ] = copyAttribute( "SP", SP, 0 ) ) == NULL )
		status = CRYPT_ERROR_MEMORY;
	if( cryptStatusOK( status ) && *C && \
		( ldapMod[ ldapModIndex++ ] = copyAttribute( "C", C, 0 ) ) == NULL )
		status = CRYPT_ERROR_MEMORY;
	ldapMod[ ldapModIndex ] = NULL;

	/* Add the new attribute/entry */
	if( cryptStatusOK( status ) )
		{
		if( ( status = ldap_add_s( keysetInfo->keysetLDAP.ld, dn,
								   ldapMod ) ) != LDAP_SUCCESS )
			{
			getErrorInfo( keysetInfo );
			status = mapLDAPerror( status, CRYPT_ERROR_WRITE );
			}
		}

	/* Clean up.  We do it the hard way rather than using 
	   ldap_mods_free() here partially because the ldapMod[] array 
	   isn't malloc()'d, but mostly because ldap_mods_free() causes
	   some sort of memory corruption, possibly because it's trying
	   to free the mod_values[] entries which are statically
	   allocated */
	for( ldapModIndex = 0; ldapMod[ ldapModIndex ] != NULL; 
		 ldapModIndex++ )
		{
		if( ldapMod[ ldapModIndex ]->mod_op & LDAP_MOD_BVALUES )
			free( ldapMod[ ldapModIndex ]->mod_bvalues[ 0 ] );
		free( ldapMod[ ldapModIndex ]->mod_values );
		free( ldapMod[ ldapModIndex ] );
		}
	return( status );
	}

static int setItemFunction( KEYSET_INFO *keysetInfo, 
							const CRYPT_HANDLE iCryptHandle,
							const char *password, const int passwordLength )
	{
	BOOLEAN seenNonDuplicate = FALSE;
	int type, status;

	assert( password == NULL ); assert( passwordLength == 0 );

	/* If we're in the middle of a query, we can't do anything else */
	if( keysetInfo->keysetDBMS.queryState == QUERY_INPROGRESS )
		return( CRYPT_ERROR_INCOMPLETE );

	/* Make sure we've been given a cert or cert chain */
	status = krnlSendMessage( iCryptHandle, RESOURCE_MESSAGE_GETATTRIBUTE,
							  &type, CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusError( status ) )
		return( CRYPT_ARGERROR_NUM1 );
	if( type != CRYPT_CERTTYPE_CERTIFICATE && \
		type != CRYPT_CERTTYPE_CERTCHAIN )
		return( CRYPT_ARGERROR_NUM1 );

	/* Lock the cert for our exclusive use (in case it's a cert chain, we 
	   also select the first cert in the chain), update the keyset with the 
	   cert(s), and unlock it to allow others access */
	krnlSendMessage( iCryptHandle, RESOURCE_IMESSAGE_SETATTRIBUTE, 
					 MESSAGE_VALUE_CURSORFIRST, 
					 CRYPT_CERTINFO_CURRENT_CERTIFICATE );
	status = krnlSendNotifier( iCryptHandle, RESOURCE_IMESSAGE_LOCK );
	if( cryptStatusError( status ) )
		return( status );
	do
		{
		/* Add the certificate */
		status = addCert( keysetInfo, iCryptHandle );

		/* A cert being added may already be present, however we can't fail
		   immediately because what's being added may be a chain containing 
		   further certs, so we keep track of whether we've successfully 
		   added at least one cert and clear data duplicate errors */
		if( status == CRYPT_OK )
			seenNonDuplicate = TRUE;
		else
			if( status == CRYPT_ERROR_DUPLICATE )
				status = CRYPT_OK;
		}
	while( cryptStatusOK( status ) && \
		   krnlSendMessage( iCryptHandle, RESOURCE_IMESSAGE_SETATTRIBUTE, 
							MESSAGE_VALUE_CURSORNEXT,
							CRYPT_CERTINFO_CURRENT_CERTIFICATE ) == CRYPT_OK );
	krnlSendNotifier( iCryptHandle, RESOURCE_IMESSAGE_UNLOCK );
	if( cryptStatusOK( status ) && !seenNonDuplicate )
		/* We reached the end of the chain without finding anything we could
		   add, return a data duplicate error */
		status = CRYPT_ERROR_DUPLICATE;

	return( status );
	}

/* Delete an entry from an LDAP directory */

static int deleteItemFunction( KEYSET_INFO *keysetInfo,
							   const CRYPT_KEYID_TYPE keyIDtype,
							   const void *keyID, const int keyIDlength )
	{
	char dn[ MAX_DN_STRINGSIZE ];
	int status;

	assert( keyIDtype == CRYPT_KEYID_NAME || keyIDtype == CRYPT_KEYID_EMAIL );

	/* Convert the DN into a null-terminated form */
	if( keyIDlength > MAX_DN_STRINGSIZE - 1 )
		return( CRYPT_ARGERROR_STR1 );
	memcpy( dn, keyID, keyIDlength );
	dn[ keyIDlength ] = '\0';

	/* Delete the entry */
	if( ( status = ldap_delete_s( keysetInfo->keysetLDAP.ld, dn ) ) != LDAP_SUCCESS )
		{
		getErrorInfo( keysetInfo );
		status = mapLDAPerror( status, CRYPT_ERROR_WRITE );
		}

	return( status );
	}

/* Send a query to the LDAP directory */

static int queryFunction( KEYSET_INFO *keysetInfo, const char *query,
						  const int queryLength )
	{
	keysetInfo->keysetLDAP.queryState = QUERY_START;
	return( getItemFunction( keysetInfo, NULL, CRYPT_KEYID_NAME,
							 query, queryLength, NULL, 0, 0 ) );
	}

int setAccessMethodLDAP( KEYSET_INFO *keysetInfo )
	{
#ifdef __WINDOWS__
	/* Make sure the LDAP driver is bound in */
	if( hLDAP == NULL_HINSTANCE )
		return( CRYPT_ERROR_OPEN );
#endif /* __WINDOWS__ */

	/* Set the access method pointers */
	keysetInfo->initKeysetFunction = initKeysetFunction;
	keysetInfo->shutdownKeysetFunction = shutdownKeysetFunction;
	keysetInfo->getItemFunction = getItemFunction;
	keysetInfo->setItemFunction = setItemFunction;
	keysetInfo->deleteItemFunction = deleteItemFunction;
	keysetInfo->queryFunction = queryFunction;

	return( CRYPT_OK );
	}
#endif /* ( __WINDOWS__ || __UNIX__ ) && DBX_LDAP */
