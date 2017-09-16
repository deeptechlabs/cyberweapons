/****************************************************************************
*																			*
*						 cryptlib Key Database Routines						*
*						Copyright Peter Gutmann 1995-1999					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "asn1.h"
  #include "asn1keys.h"
  #include "asn1objs.h"
  #include "dbms.h"
#else
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1keys.h"
  #include "keymgmt/asn1objs.h"
  #include "misc/dbms.h"
#endif /* Compiler-specific includes */

/* The key database access strategies for the various database types are:

		   |PGP/X.509	clib/Smartcard	RDBMS		LDAP	HTTP
	-------+---------------------------------------------------------
	Create |	-		Zap existing,	Only if not	-		-
		   |			create MT set	existing
		   +---------------------------------------------------------
	Write  |	-		Only if MT		Add			Add		-
		   +---------------------------------------------------------
	Read   |Yes: Name,	Yes: Nothing	Yes: Name,	Yes: DN	Yes : URL
		   |email, ID					email, ID
		   +---------------------------------------------------------
	Delete |	-		Yes, create		Yes: Name,	Yes: DN	-
		   |			MT set			email, ID */

/* Prototypes for functions in lib_cert.c */

int unpackCertInfo( const CRYPT_CERTIFICATE certificate, void *C, void *SP,
					void *L, void *O, void *OU, void *CN, void *email,
					time_t *date, void *nameID, void *issuerID, void *keyID,
					void *keyData, int *keyDataLength );

/* Prototypes for DBMS key read/write functions */

int dbmsAddKey( KEYSET_INFO *keysetInfo, const void *nameID,
				const void *issuerID, const void *keyID,
				const void *keyData, const int keyDataLen );
int dbmsGetKey( KEYSET_INFO *keysetInfo, const CRYPT_KEYID_TYPE keyIDtype,
				const void *keyID, void *keyData );
int dbmsDeleteKey( KEYSET_INFO *keysetInfo, const CRYPT_KEYID_TYPE keyIDtype,
				   const void *keyID );
int dbmsQuery( KEYSET_INFO *keysetInfo, const char *query, void *keyData );
int dbmsOpenDatabase( KEYSET_INFO *keysetInfo, const char *name,
					  const char *server, const char *user,
					  const char *password );
int dbmsCreateDatabase( KEYSET_INFO *keysetInfo );

/* Prototypes for LDAP key read/write functions */

int ldapAddKey( KEYSET_INFO *keysetInfo, const void *keyData,
				const int keyDataLen );
int ldapDeleteKey( KEYSET_INFO *keysetInfo, const char *dn );
int ldapGetKey( KEYSET_INFO *keysetInfo, const char *dn, void *keyData );

/* Prototypes for HTTP key read/write functions */

int httpGetKey( KEYSET_INFO *keysetInfo, const char *url );

/* Some database types aren't supported on some platforms, so we replace a
   call to the mapping function with an error code */

#ifndef __WINDOWS__
  #define setAccessMethodODBC( x )		CRYPT_BADPARM2
#endif /* !__WINDOWS__ */
#ifndef DBX_BSQL
  #define setAccessMethodBSQL( x )		CRYPT_BADPARM2
#endif /* !DBX_BSQL */
#ifndef DBX_MSQL
  #define setAccessMethodMSQL( x )		CRYPT_BADPARM2
#endif /* !DBX_MSQL */
#ifndef DBX_MYSQL
  #define setAccessMethodMySQL( x )		CRYPT_BADPARM2
#endif /* !DBX_MYSQL */
#ifndef DBX_ORACLE
  #define setAccessMethodOracle( x )	CRYPT_BADPARM2
#endif /* !DBX_ORACLE */
#ifndef DBX_POSTGRES
  #define setAccessMethodPostgres( x )	CRYPT_BADPARM2
#endif /* !DBX_POSTGRES */
#ifndef DBX_RAIMA
  #define setAccessMethodRaima( x )		CRYPT_BADPARM2
#endif /* !DBX_RAIMA */
#ifndef DBX_SOLID
  #define setAccessMethodSolid( x )		CRYPT_BADPARM2
#endif /* !DBX_SOLID */
#ifndef DBX_LDAP
  #define setAccessMethodLDAP( x )		CRYPT_BADPARM2
#endif /* !DBX_LDAP */

/* Relational databases and LDAP aren't supported on some platforms so we
   alias the calls out */

#if !( defined( __WINDOWS__ ) || defined( __UNIX__ ) )
  #define dbmsAddKey( a, b, c, d, e, f )	CRYPT_ERROR
  #define dbmsGetKey( a, b, c, d )			CRYPT_ERROR
  #define dbmsDeleteKey( a, b, c )			CRYPT_ERROR
  #define dbmsQuery( a, b, c )				CRYPT_ERROR
  #define dbmsOpenDatabase( a, b, c, d, e )	CRYPT_ERROR
  #define dbmsCreateDatabase( a )			CRYPT_ERROR
#endif /* !( __WINDOWS__ || __UNIX__ ) */
#ifndef DBX_LDAP
  #define ldapAddKey( a, b, c )				CRYPT_ERROR
  #define ldapDeleteKey( a, b )				CRYPT_ERROR
  #define ldapGetKey( a, b, c )				CRYPT_ERROR
#endif /* DBX_LDAP */
#ifndef DBX_HTTP
  #define httpGetKey( a, b )				CRYPT_ERROR
#endif /* DBX_HTTP */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Initialise and down any databases and smart card readers we're working
   with */

void dbxInitODBC( void );
void dbxEndODBC( void );
void dbxInitLDAP( void );
void dbxEndLDAP( void );
void dbxInitHTTP( void );
void dbxEndHTTP( void );

void scardInitASE( void );
void scardInitGemplus( void );
void scardInitTowitoko( void );
void scardEndASE( void );
void scardEndGemplus( void );
void scardEndTowitoko( void );

void initDBX( void )
	{
#if defined( __WINDOWS__ ) && !defined( NT_DRIVER )
	dbxInitODBC();
  #ifdef DBX_LDAP
	dbxInitLDAP();
  #endif /* DBX_LDAP */
#endif /* __WINDOWS__ && !NT_DRIVER */
#ifdef DBX_HTTP
	dbxInitHTTP();
#endif /* DBX_LDAP */
	}

void shutdownDBX( void )
	{
#if defined( __WINDOWS__ ) && !defined( NT_DRIVER )
	dbxEndODBC();
  #ifdef DBX_LDAP
	dbxEndLDAP();
  #endif /* DBX_LDAP */
#endif /* __WINDOWS__ && !NT_DRIVER */
#ifdef DBX_HTTP
	dbxEndHTTP();
#endif /* DBX_HTTP */
	}

void initReaders( void )
	{
#if defined( __WINDOWS__ ) && !defined( NT_DRIVER )
  #ifdef __WIN32__
	scardInitASE();
  #endif /* __WIN32__ */
	scardInitGemplus();
	scardInitTowitoko();
#endif /* __WINDOWS__ && !NT_DRIVER */
	}

void shutdownReaders( void )
	{
#if defined( __WINDOWS__ ) && !defined( NT_DRIVER )
  #ifdef __WIN32__
	scardEndASE();
  #endif /* __WIN32__ */
	scardEndGemplus();
	scardEndTowitoko();
#endif /* __WINDOWS__ && !NT_DRIVER */
	}

/* Check that a keyset is of the correct type for the required access */

static int checkKeysetAccess( KEYSET_INFO *keysetInfoPtr,
							  const BOOLEAN isPublicKey,
							  const BOOLEAN isRead )
	{
	/* Make sure the keyset is actually open before we try to access it.
	   This can occur in some rare instances when the keyset is closed for
	   some reason (eg due to a connection to a database being lost) and the
	   caller doesn't check the return code and later tries to read a key
	   from the closed keyset */
	if( keysetInfoPtr->type == CRYPT_KEYSET_FILE )
		{
		if( !keysetInfoPtr->keysetFile.streamOpen )
			return( CRYPT_NOTINITED );
		}
	else
		if( keysetInfoPtr->type == CRYPT_KEYSET_SMARTCARD )
			{
			if( !keysetInfoPtr->keysetScard.readerHandle )
				return( CRYPT_NOTINITED );
			}
		else
			if( keysetInfoPtr->type == CRYPT_KEYSET_LDAP )
				{
				if( !keysetInfoPtr->keysetLDAP.directoryOpen )
					return( CRYPT_NOTINITED );
				}
			else
				if( keysetInfoPtr->isDatabaseKeyset && \
					!keysetInfoPtr->keysetDBMS.databaseOpen )
					return( CRYPT_NOTINITED );

	/* Make sure we've got the right type of keyset.  We have to be somewhat
	   careful here because for sensibly-designed private key storage formats
	   (ie PGP) we can get a public key from a private key file (although
	   it's somewhat peculiar), but for other types (anything based on PKCS
	   #1 or PKCS #8) we can't.  The error we return is a generic
	   CRYPT_BADPARM which is mapped to the correct parameter by the calling
	   code */
	if( !isPublicKey )
		{
		/* We're attempting a private key read/write */
		if( keysetInfoPtr->type == CRYPT_KEYSET_LDAP || \
			keysetInfoPtr->type == CRYPT_KEYSET_HTTP || \
			keysetInfoPtr->isDatabaseKeyset )
			return( CRYPT_BADPARM );
		}
	else
		{
		/* We're attempting a public key read/write.  Public key reads from
		   smartcard/cryptlib keysets are allowed since they contain both
		   public and private key components, although it's not usually
		   done */
		if( keysetInfoPtr->subType == KEYSET_SUBTYPE_NETSCAPE )
			return( CRYPT_BADPARM );
		if( !isRead && ( keysetInfoPtr->type == CRYPT_KEYSET_SMARTCARD || \
						 keysetInfoPtr->subType == KEYSET_SUBTYPE_CRYPTLIB ) )
			return( CRYPT_BADPARM );
		}

	return( CRYPT_OK );
	}

/* Extract a cryptlib key ID from a key management or signature object */

static int getKeyIDfromObject( const void *object, void *keyID )
	{
	OBJECT_INFO objectInfo;
	STREAM stream;
	int status;

	/* Make sure we've got a public-key object and determine the key ID */
	sMemConnect( &stream, object, STREAMSIZE_UNKNOWN );
	status = queryObject( &stream, &objectInfo );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) || \
		objectInfo.type == CRYPT_OBJECT_ENCRYPTED_KEY )
		{
		zeroise( &objectInfo, sizeof( OBJECT_INFO ) );
		return( CRYPT_BADPARM );
		}

	/* Copy over the key identifier information */
	memcpy( keyID, objectInfo.keyID, KEYID_SIZE );
	zeroise( &objectInfo, sizeof( OBJECT_INFO ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Low-level Key Access Functions					*
*																			*
****************************************************************************/

/* Get a key from a keyset */

static int getKey( KEYSET_INFO *keysetInfoPtr,
				   const CRYPT_KEYID_TYPE keyIDtype, const void *keyID,
				   const char *password, CRYPT_HANDLE *iCryptKey,
				   char *userID, const BOOLEAN readPublicKey )
	{
	const BOOLEAN isSingleKeyKeyset = \
		( keysetInfoPtr->type == CRYPT_KEYSET_SMARTCARD || \
		  ( keysetInfoPtr->type == CRYPT_KEYSET_FILE && \
			keysetInfoPtr->subType == KEYSET_SUBTYPE_CRYPTLIB ) ) ? TRUE : FALSE;
	const BOOLEAN isStringID = ( keyIDtype == CRYPT_KEYID_NAME || \
							keyIDtype == CRYPT_KEYID_EMAIL ) ? TRUE : FALSE;
	STREAM *stream = ( keysetInfoPtr->type == CRYPT_KEYSET_FILE ) ?
					 &keysetInfoPtr->keysetFile.stream : NULL;
	int length, status;

	/* Check that the keyset is of the appropriate type for this access */
	status = checkKeysetAccess( keysetInfoPtr, readPublicKey, TRUE );
	if( cryptStatusError( status ) )
		/* Map the parameter error to the correct parameter for the users
		   parameter */
		return( ( status == CRYPT_BADPARM ) ? CRYPT_BADPARM2 : status );

	/* If we're doing a getFirst(), go back to the start of the file */
	if( keysetInfoPtr->type == CRYPT_KEYSET_FILE && \
		keysetInfoPtr->keysetFile.streamOpen && \
		keyID == CRYPT_KEYSET_GETFIRST )
		sseek( stream, 0L );

	/* If there's only one key present in the keyset (cryptlib keyset) or the
	   key we're looking for matches the cached key (PGP keyset), reread it
	   from cache.  For the cryptlib-format keys this will just skip the key
	   read function and reuse the cached data, for the PGP-format keys it
	   will call the read function with a null stream which will result in
	   the code rereading the key info from the cached data */
	if( keysetInfoPtr->cachedKeyPresent )
		{
		/* A keyset which can only store one key can always reuse the cached
		   key */
		if( isSingleKeyKeyset )
			stream = NULL;
		else
			/* Reuse the cached key if the ID we're using to read it matches
			   the one used previously */
			if( keyID != NULL && \
				( keyIDtype == CRYPT_KEYID_OBJECT && \
				  !memcmp( keysetInfoPtr->cachedKeyTag, keyID, KEYID_SIZE ) ) || \
				( isStringID && \
				  !strcmp( ( char * ) keysetInfoPtr->cachedKeyTag, keyID ) ) )
				stream = NULL;
		}

	/* We're about to overwrite the cached key, mark it as absent */
	keysetInfoPtr->cachedKeyPresent = FALSE;
	memset( keysetInfoPtr->cachedKeyTag, 0, CRYPT_MAX_TEXTSIZE );
	memset( keysetInfoPtr->cachedKeyID, 0, KEYID_SIZE );

	/* Get the key from the key collection */
	switch( keysetInfoPtr->type )
		{
		case CRYPT_KEYSET_ODBC:
		case CRYPT_KEYSET_BSQL:
		case CRYPT_KEYSET_MSQL:
		case CRYPT_KEYSET_MYSQL:
		case CRYPT_KEYSET_ORACLE:
		case CRYPT_KEYSET_POSTGRES:
		case CRYPT_KEYSET_RAIMA:
		case CRYPT_KEYSET_SOLID:
			/* If we're doing a CRL query, just check whether the entry is
			   present.  The checking of parameters is to ensure that we've
			   been called via the internal getKeyFromID() function, and that
			   we're not looking for a key but only doing a general query */
			if( keyIDtype == CRYPT_KEYID_OBJECT && iCryptKey == NULL && \
				userID != NULL )
				return( dbmsGetKey( keysetInfoPtr, keyIDtype, keyID, NULL ) );

			/* If we're in the middle of a general query, just fetch the next
			   result */
			if( keyIDtype == CRYPT_UNUSED )
				status = dbmsQuery( keysetInfoPtr, NULL,
									keysetInfoPtr->cachedKey );
			else
				status = dbmsGetKey( keysetInfoPtr, keyIDtype, keyID,
									 keysetInfoPtr->cachedKey );
			break;

		case CRYPT_KEYSET_LDAP:
			status = ldapGetKey( keysetInfoPtr, keyID,
								 keysetInfoPtr->cachedKey );
			break;

		case CRYPT_KEYSET_SMARTCARD:
			if( stream == NULL )
				break;	/* Data is cached, skip the read */
			status = keysetInfoPtr->keysetScard.readData( &keysetInfoPtr->keysetScard,
												keysetInfoPtr->cachedKey );
			break;

		case CRYPT_KEYSET_FILE:
			switch( keysetInfoPtr->subType )
				{
				case KEYSET_SUBTYPE_PGP_PUBLIC:
				case KEYSET_SUBTYPE_PGP_PRIVATE:
					status = pgpGetKey( stream, keyIDtype, keyID, password,
										keysetInfoPtr->cachedKey, iCryptKey,
										userID, readPublicKey );
					break;

				case KEYSET_SUBTYPE_X509:
					status = x509GetKey( stream, keyIDtype, keyID, iCryptKey,
										 userID );
					break;

				case KEYSET_SUBTYPE_NETSCAPE:
					status = netscapeGetKey( stream, password, iCryptKey,
											 userID  );
					break;

				case KEYSET_SUBTYPE_CRYPTLIB:
					if( stream == NULL )
						break;	/* Data is cached, skip the read */

					/* Read the start of the key file and make sure it's
					   valid */
					sseek( &keysetInfoPtr->keysetFile.stream, 0 );
					status = sread( &keysetInfoPtr->keysetFile.stream,
									keysetInfoPtr->cachedKey, 8 );
					if( cryptStatusError( status ) )
						{
						status = CRYPT_DATA_READ;	/* Convert to cryptlib error code */
						break;
						}
					length = getObjectLength( keysetInfoPtr->cachedKey, 8 );
					if( cryptStatusError( length ) || \
						length > MAX_PRIVATE_KEYSIZE )
						{
						status = CRYPT_BADDATA;
						break;
						}

					/* Read the rest of the key file */
					status = sread( &keysetInfoPtr->keysetFile.stream,
									keysetInfoPtr->cachedKey + 8,
									length - 8 );
					if( cryptStatusError( status ) )
						status = CRYPT_DATA_READ;	/* Convert to cryptlib error code */
					break;

				default:
					/* Internal error, should never happen */
					status = CRYPT_ERROR;
				}
			break;

		case CRYPT_KEYSET_HTTP:
			status = httpGetKey( keysetInfoPtr, keyID );
			break;

		default:
			/* Internal error, should never happen */
			status = CRYPT_ERROR;
		}

	/* If the read succeeded, remember the key tag */
	if( ( status == CRYPT_OK || status == CRYPT_WRONGKEY ) && \
		keysetInfoPtr->type != CRYPT_KEYSET_HTTP )
		{
		/* Remember that we have a cached key present, and save the key ID
		   if there's one being used */
		keysetInfoPtr->cachedKeyPresent = TRUE;
		if( keyID != NULL )
			if( isStringID )
				{
				strncpy( ( char * ) keysetInfoPtr->cachedKeyTag, keyID,
						 CRYPT_MAX_TEXTSIZE );
				keysetInfoPtr->cachedKeyTag[ CRYPT_MAX_TEXTSIZE - 1 ] = '\0';
				}
			else
				memcpy( keysetInfoPtr->cachedKeyTag, keyID, KEYID_SIZE );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* If it's an LDAP, HTTP, RDBMS, or private key keyset, the data
	   returned is raw key data which needs to be converted into a
	   certificate or encryption context */
	if( keysetInfoPtr->type == CRYPT_KEYSET_LDAP || \
		keysetInfoPtr->isDatabaseKeyset )
		{
		/* It's an encoded cert, create a certificate object from it */
		status = iCryptImportCert( keysetInfoPtr->cachedKey, iCryptKey, NULL );
		if( !cryptStatusError( status ) )
			status = CRYPT_OK;	/* iCryptImportCert() returns a length code */
		}
	if( keysetInfoPtr->type == CRYPT_KEYSET_HTTP )
		{
		/* It's an encoded cert or CRL, create a certificate object from it */
		status = iCryptImportCert( keysetInfoPtr->keysetHTTP.buffer,
								   iCryptKey, NULL );
		if( !cryptStatusError( status ) )
			status = CRYPT_OK;	/* iCryptImportCert() returns a length code */
		}
	if( keysetInfoPtr->type == CRYPT_KEYSET_SMARTCARD || \
		( keysetInfoPtr->type == CRYPT_KEYSET_FILE && \
		  keysetInfoPtr->subType == KEYSET_SUBTYPE_CRYPTLIB ) )
		/* It's a non-cached key read, turn the key into a context */
		status = readPrivateKeyBuffer( keysetInfoPtr->cachedKey, password,
					iCryptKey, keysetInfoPtr->cachedKeyID, readPublicKey );

	return( status );
	}

/* Add a certificate to a DBMS or LDAP keyset.  This involves extracting
   various pieces of certificate information and decorating the keyset info
   with them before passing the data on to the relevant access routines */

static int putCertificate( KEYSET_INFO *keysetInfoPtr,
						   const CRYPT_CERTIFICATE certificate,
						   const CRYPT_KEYSET_TYPE keysetType )
	{
	BYTE nameID[ KEYID_SIZE ], issuerID[ KEYID_SIZE ], keyID[ KEYID_SIZE ];
	BYTE keyData[ MAX_KEYDATA_SIZE ];
	int keyDataSize, type, status;

	/* We can be given a cert or a CRL, find out what it is we've got */
	status = cryptGetCertComponentNumeric( certificate,
										   CRYPT_CERTINFO_CERTTYPE, &type );
	if( cryptStatusError( status ) )
		return( CRYPT_BADPARM2 );

	/* If it's a CRL, lock it for our exclusive use and add each entry in it
	   to the keyset */
	if( type == CRYPT_CERTTYPE_CRL )
		{
		void *revocationEntryState = NULL;

		/* For each entry in the CRL, add its issuerID to the keyset */
		status = krnlSendNotifier( certificate, RESOURCE_MESSAGE_LOCK );
		while( cryptStatusOK( status ) )
			{
			status = unpackCertInfo( certificate, NULL, NULL, NULL, NULL,
									 NULL, NULL, NULL, NULL, NULL, issuerID,
									 NULL, &revocationEntryState, NULL );
			if( cryptStatusOK( status ) )
				status = dbmsAddKey( keysetInfoPtr, NULL, issuerID, NULL,
									 NULL, 0 );
			}
		krnlSendNotifier( certificate, RESOURCE_MESSAGE_UNLOCK );

		/* If there were no entries in the CRL or we finished processing 
		   all the entries in the CRL then a CRYPT_DATA_NOTFOUND from the
		   unpack function isn't an error */
		return( ( status == CRYPT_DATA_NOTFOUND && revocationEntryState == NULL ) ? \
				CRYPT_OK : status );
		}

	/* It's a certificate, unpack the various fields we require */
	if( type != CRYPT_CERTTYPE_CERTIFICATE )
		return( CRYPT_BADPARM2 );
	if( keysetInfoPtr->type == CRYPT_KEYSET_LDAP )
		status = unpackCertInfo( certificate, keysetInfoPtr->keysetLDAP.C,
				keysetInfoPtr->keysetLDAP.SP, keysetInfoPtr->keysetLDAP.L,
				keysetInfoPtr->keysetLDAP.O, keysetInfoPtr->keysetLDAP.OU,
				keysetInfoPtr->keysetLDAP.CN, keysetInfoPtr->keysetLDAP.email,
				&keysetInfoPtr->keysetLDAP.date, nameID, issuerID, keyID,
				keyData, &keyDataSize );
	else
		status = unpackCertInfo( certificate, keysetInfoPtr->keysetDBMS.C,
				keysetInfoPtr->keysetDBMS.SP, keysetInfoPtr->keysetDBMS.L,
				keysetInfoPtr->keysetDBMS.O, keysetInfoPtr->keysetDBMS.OU,
				keysetInfoPtr->keysetDBMS.CN, keysetInfoPtr->keysetDBMS.email,
				&keysetInfoPtr->keysetDBMS.date, nameID, issuerID, keyID,
				keyData, &keyDataSize );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_BADPARM1 ) ? CRYPT_BADPARM2 : status );

	/* Add the certificate to the database */
	if( cryptStatusOK( status ) )
		if( keysetType == CRYPT_KEYSET_LDAP )
			status = ldapAddKey( keysetInfoPtr, keyData, keyDataSize );
		else
			status = dbmsAddKey( keysetInfoPtr, nameID, issuerID, keyID,
								 keyData, keyDataSize );

	/* Clean up */
	zeroise( nameID, KEYID_SIZE ); zeroise( issuerID, KEYID_SIZE );
	zeroise( keyID, KEYID_SIZE ); zeroise( keyData, keyDataSize );
	return( status );
	}

/* Put a key into a keyset.  The CRYPT_HANDLE is a certificate for a public
   key and a context for a private key */

static int putKey( KEYSET_INFO *keysetInfoPtr, CRYPT_HANDLE cryptKey,
				   const char *password, const BOOLEAN isPublicKey,
				   const BOOLEAN isCachedUpdate )
	{
	void *keyData;
	int keyDataSize, status;

	/* Make sure the keyset is of a type which allows the addition of keys */
	if( !isCachedUpdate )
		{
		status = checkKeysetAccess( keysetInfoPtr, isPublicKey, FALSE );
		if( cryptStatusError( status ) )
			/* Map the parameter error to the correct parameter for the users
			   parameter */
			return( ( status == CRYPT_BADPARM ) ? CRYPT_BADPARM2 : status );
		}

	/* If it's a private key, convert it to the flat format so we can write
	   it to the keyset */
	if( !isPublicKey )
		{
		/* If it's a cached update, we need to take the existing complete
		   private key record, extract only the encrypted key, and rewrite
		   it as a new private key record with the exported cert as the
		   public key components */
		if( isCachedUpdate )
			{
			status = convertPrivateKeyBuffer( &keyData, &keyDataSize, cryptKey,
											  keysetInfoPtr->cachedKey );
			if( cryptStatusOK( status ) && keysetInfoPtr->keysetFile.streamOpen )
				/* If it's a stream-based keyset, reset the stream position
				   to the start so we can overwrite it with the new key */
				sseek( &keysetInfoPtr->keysetFile.stream, 0 );
			}
		else
			/* It's a straight private key write, write it to a buffer */
			status = writePrivateKeyBuffer( &keyData, &keyDataSize, cryptKey,
											password );
		if( status == CRYPT_BADPARM3 )
			status = CRYPT_BADPARM2;	/* Map to correct error code */
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Write the key to the key collection */
	switch( keysetInfoPtr->type )
		{
		case CRYPT_KEYSET_ODBC:
		case CRYPT_KEYSET_BSQL:
		case CRYPT_KEYSET_MSQL:
		case CRYPT_KEYSET_MYSQL:
		case CRYPT_KEYSET_ORACLE:
		case CRYPT_KEYSET_POSTGRES:
		case CRYPT_KEYSET_RAIMA:
		case CRYPT_KEYSET_SOLID:
		case CRYPT_KEYSET_LDAP:
			status = putCertificate( keysetInfoPtr, cryptKey,
									 keysetInfoPtr->type );
			break;

		case CRYPT_KEYSET_SMARTCARD:
			status = keysetInfoPtr->keysetScard.writeData( &keysetInfoPtr->keysetScard,
													keyData, keyDataSize );
			break;

		case CRYPT_KEYSET_FILE:
			if( keysetInfoPtr->subType != KEYSET_SUBTYPE_CRYPTLIB )
				status = CRYPT_ERROR;	/* Internal error, should never happen */
			status = swrite( &keysetInfoPtr->keysetFile.stream, keyData,
							 keyDataSize );
			if( cryptStatusError( status ) )
				status = CRYPT_DATA_WRITE;	/* Convert to cryptlib error code */
			break;

		default:
			/* Internal error, should never happen */
			status = CRYPT_ERROR;
		}

	/* If it's a private key, clean up the storage allocated to the flat-file
	   version */
	if( !isPublicKey )
		{
		zeroise( keyData, keyDataSize );
		free( keyData );
		}

	return( status );
	}

/****************************************************************************
*																			*
*						Internal Keyset Access Functions					*
*																			*
****************************************************************************/

/* Get a key and optionally key owner name from a keyset based on a keyID and
   return it as an internal keyset.  This is an internal function used by
   the enveloping code and isn't subject to some of the constraints of
   cryptGetXXXKey() when the keyset reference count is nonzero */

int getKeyFromID( const CRYPT_KEYSET keyset, CRYPT_HANDLE *cryptKey,
				  const void *keyID, const void *password, char *ownerName )
	{
	KEYSET_INFO *keysetInfoPtr;
	BOOLEAN isPublicKey = ( BOOLEAN )	/* Fix for VC++ */
		( password == ( void * ) CRYPT_UNUSED ) ? TRUE : FALSE;
	char userID[ CRYPT_MAX_TEXTSIZE + 1 ];
	void *passwordPtr = ( isPublicKey ) ? NULL : ( void * ) password;
	int status;

	/* Lock the keyset */
	getCheckInternalResource( keyset, keysetInfoPtr, RESOURCE_TYPE_KEYSET );

	/* Make sure the context is invalid if the get fails */
	if( cryptKey != NULL )
		*cryptKey = CRYPT_ERROR;

	/* Get the key */
	status = getKey( keysetInfoPtr, CRYPT_KEYID_OBJECT, keyID, passwordPtr,
					 cryptKey, userID, isPublicKey );

	/* Return the key owner name as well if required (this is only needed for
	   decryption keys).  The method of obtaining the name depends on the
	   source of the key, if it came from a cryptlib flat file or smart card
	   it won't be present so we copy in an identification string to indicate
	   its origins, if it came from a PGP flat file it'll be present in the
	   getkeyInfo structure */
	if( ownerName != NULL )
		{
		strcpy( ownerName, "???" );	/* Should never make it out alive */
		if( keysetInfoPtr->type == CRYPT_KEYSET_SMARTCARD || \
			( keysetInfoPtr->type == CRYPT_KEYSET_FILE && \
			  keysetInfoPtr->subType == KEYSET_SUBTYPE_CRYPTLIB ) )
			strcpy( ownerName, "cryptlib Private Key" );
		if( keysetInfoPtr->type == CRYPT_KEYSET_FILE && \
			( keysetInfoPtr->subType == KEYSET_SUBTYPE_PGP_PUBLIC || \
			  keysetInfoPtr->subType == KEYSET_SUBTYPE_PGP_PRIVATE ) )
			strcpy( ownerName, userID );
		}

	unlockResourceExit( keysetInfoPtr, status );
	}

/****************************************************************************
*																			*
*								Keyset API Functions						*
*																			*
****************************************************************************/

/* Handle a message sent to a keyset object */

static int keysetMessageFunction( const CRYPT_KEYSET cryptKeyset,
								  const RESOURCE_MESSAGE_TYPE message,
								  void *messageDataPtr,
								  const int messageValue,
								  const int errorCode )
	{
	KEYSET_INFO *keysetInfoPtr;
	int status = errorCode;

	UNUSED( messageDataPtr );
	if( messageValue );		/* Get rid of compiler warning */
	getCheckInternalResource( cryptKeyset, keysetInfoPtr, RESOURCE_TYPE_KEYSET );

	/* Process the destroy object message */
	if( message == RESOURCE_MESSAGE_DESTROY )
		{
		/* If the keyset is implemented as a file, close it */
		if( keysetInfoPtr->type == CRYPT_KEYSET_FILE && \
			keysetInfoPtr->keysetFile.streamOpen )
			{
			sFileClose( &keysetInfoPtr->keysetFile.stream );
			keysetInfoPtr->keysetFile.streamOpen = FALSE;

			/* If it's a newly-created empty keyset file, remove it (this can
			   occur if there's some sort of error on writing and no keys are
			   ever written to the keyset */
			if( keysetInfoPtr->keysetEmpty )
				remove( keysetInfoPtr->keysetFile.fileName );
			}
		else
		/* If the keyset is implemented using a smart card, shut down the
		   session with the card */
		if( keysetInfoPtr->type == CRYPT_KEYSET_SMARTCARD && \
			keysetInfoPtr->keysetScard.readerHandle > 0 )
			{
			/* Close down the session */
			keysetInfoPtr->keysetScard.shutdownReader( &keysetInfoPtr->keysetScard );
			}
		else
		/* Close the database connection if necessary */
		if( keysetInfoPtr->isDatabaseKeyset && \
			keysetInfoPtr->keysetDBMS.databaseOpen )
			{
			/* If we're in the middle of a bulk update or query, complete the
			   operation */
			if( keysetInfoPtr->keysetDBMS.bulkUpdateState != BULKUPDATE_NONE )
				{
				int status;

				/* Finish the bulk update */
				keysetInfoPtr->keysetDBMS.bulkUpdateState = BULKUPDATE_FINISH;
				status = dbmsAddKey( keysetInfoPtr, NULL, NULL, NULL, NULL, 0 );

				/* On some systems the dbmsXXX() functions are aliased to
				   CRYPT_ERROR so we need to include the following code to
				   tell the compiler to ignore this value */
				UNUSED( status );
				}
			if( keysetInfoPtr->keysetDBMS.queryState == QUERY_INPROGRESS )
				{
				int status;

				/* Finish the query */
				status = dbmsQuery( keysetInfoPtr, "cancel", NULL );

				/* On some systems the dbmsXXX() functions are aliased to
				   CRYPT_ERROR so we need to include the following code to
				   tell the compiler to ignore this value */
				UNUSED( status );
				}

			keysetInfoPtr->keysetDBMS.closeDatabase( keysetInfoPtr );
			}
		else
		/* Close the connection to the LDAP directory if necessary */
		if( keysetInfoPtr->type == CRYPT_KEYSET_LDAP && \
			keysetInfoPtr->keysetLDAP.directoryOpen )
			keysetInfoPtr->keysetLDAP.closeDatabase( keysetInfoPtr );
		else
		/* Free the HTTP read buffer if necessary */
		if( keysetInfoPtr->type == CRYPT_KEYSET_HTTP && \
			keysetInfoPtr->keysetHTTP.buffer != NULL )
			free( keysetInfoPtr->keysetHTTP.buffer );

		/* We've finished deleting the objects data, mark it as partially
		   destroyed, which ensures that any further attempts to access it
		   fail.  This avoids a race condition where other threads may try
		   to use the partially-destroyed object after we unlock it but
		   before we finish destroying it, note that we set the urgent flag
		   to ensure that the status change is processed immediately rather
		   than being queued until after the current (destroy) message has
		   been processed */
		status = CRYPT_SIGNALLED;
		krnlSendMessage( cryptKeyset,
						 RESOURCE_MESSAGE_SETPROPERTY | RESOURCE_MESSAGE_URGENT,
						 &status, RESOURCE_MESSAGE_PROPERTY_STATUS, 0 );

		/* Delete the objects locking variables and the object itself */
		unlockResource( keysetInfoPtr );
		deleteResourceLock( keysetInfoPtr );
		zeroise( keysetInfoPtr, sizeof( KEYSET_INFO ) );
		free( keysetInfoPtr );

		return( CRYPT_OK );
		}

	/* Process the increment/decrement object reference count message */
	if( message == RESOURCE_MESSAGE_INCREFCOUNT )
		{
		/* Increment the objects reference count */
		if( !keysetInfoPtr->refCount )
			{
			/* If this is the first time the keyset is being cloned, make it
			   read-only */
			keysetInfoPtr->savedOptions = keysetInfoPtr->options;
			keysetInfoPtr->options |= CRYPT_KEYOPT_READONLY;
			}
		keysetInfoPtr->refCount++;

		status = CRYPT_OK;
		}
	if( message == RESOURCE_MESSAGE_DECREFCOUNT )
		{
		/* If we're already at a single reference, destroy the object */
		if( !keysetInfoPtr->refCount )
			krnlSendNotifier( cryptKeyset, RESOURCE_IMESSAGE_DESTROY );
		else
			{
			/* Decrement the objects reference count */
			keysetInfoPtr->refCount--;
			if( !keysetInfoPtr->refCount )
				/* We're back to a single reference, reinstate the original
				   access */
				keysetInfoPtr->options = keysetInfoPtr->savedOptions;
			}

		status = CRYPT_OK;
		}

	/* Process messages which check a keyset */
	if( message == RESOURCE_MESSAGE_CHECK )
		status = checkKeysetAccess( keysetInfoPtr,
				( messageValue == RESOURCE_MESSAGE_CHECK_PKC_ENCRYPT || \
				  messageValue == RESOURCE_MESSAGE_CHECK_PKC_SIGCHECK ) ? \
				TRUE : FALSE, TRUE );

	/* Process messages which get data from the object */
	if( message == RESOURCE_MESSAGE_GETDATA )
		{
		status = CRYPT_OK;

		switch( messageValue )
			{
			case RESOURCE_MESSAGE_DATA_ERRORINFO:
				/* Because of private key data cacheing, we can't read from a
				   cloned private key keyset since this could overwrite the
				   cached data, so any error information which is present
				   won't be meaningful */
				if( keysetInfoPtr->refCount && \
					( keysetInfoPtr->type == CRYPT_KEYSET_SMARTCARD || \
					  ( keysetInfoPtr->type == CRYPT_KEYSET_FILE && \
						( keysetInfoPtr->subType == KEYSET_SUBTYPE_CRYPTLIB || \
						  keysetInfoPtr->subType == KEYSET_SUBTYPE_PGP_PRIVATE ) ) ) )
					status = CRYPT_BUSY;
				else
					{
					/* Non-DBMS, HTTP, LDAP and smartcard keysets don't have
					   error codes or messages */
					if( !keysetInfoPtr->isDatabaseKeyset && \
						keysetInfoPtr->type != CRYPT_KEYSET_SMARTCARD && \
						keysetInfoPtr->type != CRYPT_KEYSET_HTTP && \
						keysetInfoPtr->type != CRYPT_KEYSET_LDAP )
						status = CRYPT_BADPARM1;
					}

				if( cryptStatusOK( status ) )
					{
					RESOURCE_DATA_EX *msgDataEx = ( RESOURCE_DATA_EX * ) messageDataPtr;

					msgDataEx->length1 = keysetInfoPtr->errorCode;
					if( msgDataEx->data2 != NULL )
						strcpy( msgDataEx->data2, keysetInfoPtr->errorMessage );
					msgDataEx->length2 = strlen( keysetInfoPtr->errorMessage ) + 1;
					}
				break;
			}
		}

	unlockResourceExit( keysetInfoPtr, status );
	}

/* Open a keyset.  This is a common function called by the cryptKeysetOpen()
   functions */

static int openKeyset( CRYPT_KEYSET *keyset,
					   const CRYPT_KEYSET_TYPE keysetType,
					   const char *name, const char *param1,
					   const char *param2, const char *param3,
					   const CRYPT_KEYOPT_TYPE options,
					   KEYSET_INFO **keysetInfoPtrPtr, const int objectFlags )
	{
	KEYSET_INFO *keysetInfoPtr;
	int status;

	/* Clear the return values */
	*keyset = CRYPT_ERROR;
	*keysetInfoPtrPtr = NULL;

	/* Wait for any async keyset driver binding to complete */
	waitSemaphore( SEMAPHORE_DRIVERBIND );

	/* Create the keyset object */
	krnlCreateObject( status, keysetInfoPtr, RESOURCE_TYPE_KEYSET,
				sizeof( KEYSET_INFO ), objectFlags, keysetMessageFunction );
	if( cryptStatusError( status ) )
		return( status );
	*keysetInfoPtrPtr = keysetInfoPtr;
	*keyset = status;
	keysetInfoPtr->type = keysetType;
	keysetInfoPtr->options = options;
	keysetInfoPtr->serviceID = CRYPT_ERROR;

	/* If it's a flat-file keyset, open a handle to it.  The semantics for
	   this are as follows:

		Operation	Type	Action
		---------	----	------
		  New		PGP		CRYPT_KEYSET_PGP (not currently present)
					X.509	Not supported (use cert.export functions)
					clib	CRYPT_KEYSET_FILE, CRYPT_KEYOPT_CREATE
		  Write		PGP		As New but appends to file
					X.509	As New
					clib	Not supported (only one key per file)
		  Read		PGP		CRYPT_KEYSET_FILE
					X.509	CRYPT_KEYSET_FILE
					clib	CRYPT_KEYSET_FILE
	*/
	if( keysetType == CRYPT_KEYSET_FILE )
		{
		int openMode;

		/* Remember the key file's name */
		if( strlen( name ) > FILENAME_MAX - 1 )
			return( CRYPT_BADPARM3 );
		strcpy( keysetInfoPtr->keysetFile.fileName, name );

		/* If the file is read-only, put the keyset into read-only mode.  We
		   have to perform this test before we try to open it because some
		   OS's don't allow a file to be reopened for write access when it's
		   already open, and it's better to have it appear read-only than
		   not at all */
		if( fileReadonly( name ) )
			{
			/* If we want to create a new file, we can't do it if we don't
			   have write permission */
			if( options == CRYPT_KEYOPT_CREATE )
				return( CRYPT_NOPERM );

			/* Open the file in readonly mode */
			keysetInfoPtr->options = CRYPT_KEYOPT_READONLY;
			openMode = FILE_READ;
			}
		else
			/* If we're creating the file, open it in write-only mode */
			if( options == CRYPT_KEYOPT_CREATE )
				openMode = FILE_WRITE | FILE_PRIVATE;
			else
				/* Open it for read or read/write depending on whether the
				   readonly flag is set */
				openMode = ( options != CRYPT_KEYOPT_READONLY ) ? \
						   FILE_READ | FILE_WRITE : FILE_READ;

		/* Pre-open the file containing the keyset.  This initially opens it
		   in read-only mode for auto-detection of the file type so we can
		   check for various problems (eg trying to open a non-writeable file
		   format type for write access) */
		status = sFileOpen( &keysetInfoPtr->keysetFile.stream, name,
							FILE_READ );
		if( cryptStatusError( status ) )
			{
			/* The file doesn't exit, if the create flag isn't set return an
			   error */
			if( options != CRYPT_KEYOPT_CREATE )
				return( status );

			/* Try and create a new file */
			status = sFileOpen( &keysetInfoPtr->keysetFile.stream, name,
								openMode );
			if( cryptStatusError( status ) )
				return( status );

			/* Everything went OK, it's an empty keyset of the default type
			   (ie cryptlib) */
			keysetInfoPtr->subType = KEYSET_SUBTYPE_CRYPTLIB;
			keysetInfoPtr->keysetEmpty = \
				keysetInfoPtr->keysetFile.streamOpen = TRUE;
			return( CRYPT_OK );
			}

		/* The file exists, get its type */
		keysetInfoPtr->subType = getKeysetType( &keysetInfoPtr->keysetFile.stream );
		if( keysetInfoPtr->subType == KEYSET_SUBTYPE_ERROR )
			/* If we're creating a new keyset and there's already something
			   there, make it look like a cryptlib keyset so it'll get
			   overwritten later */
			if( options == CRYPT_KEYOPT_CREATE )
				keysetInfoPtr->subType = KEYSET_SUBTYPE_CRYPTLIB;
			else
				return( CRYPT_BADDATA );

		/* If it's a cryptlib keyset we can open it in any mode */
		if( keysetInfoPtr->subType == KEYSET_SUBTYPE_CRYPTLIB )
			{
			/* If we're opening it something other than readonly mode, reopen
			   it in that mode */
			if( openMode != FILE_READ )
				{
				sFileClose( &keysetInfoPtr->keysetFile.stream );
				status = sFileOpen( &keysetInfoPtr->keysetFile.stream, name,
									openMode );
				if( cryptStatusError( status ) )
					return( status );
				if( options == CRYPT_KEYOPT_CREATE )
					/* We've created a new file, mark it as being empty */
					keysetInfoPtr->keysetEmpty = TRUE;
				}
			}
		else
			/* If it's a PGP or X.509-related keyset, we can't open it for
			   anything other than read-only access */
			if( options != CRYPT_KEYOPT_READONLY )
				return( CRYPT_NOPERM );

		/* Everything went OK */
		keysetInfoPtr->keysetFile.streamOpen = TRUE;
		return( CRYPT_OK );
		}

	/* If it's a smart card, try and open a session to the card */
	if( keysetType == CRYPT_KEYSET_SMARTCARD )
		{
		COMM_PARAMS commParams;

		/* Set up the pointers to the error information in the encapsulating
		   object */
		keysetInfoPtr->keysetScard.errorCode = &keysetInfoPtr->errorCode;
		keysetInfoPtr->keysetScard.errorMessage = keysetInfoPtr->errorMessage;

		/* Set up the appropriate access method pointers */
		if( !stricmp( name, "ASE" ) )
			status = setAccessMethodASE( &keysetInfoPtr->keysetScard );
		else
		if( !stricmp( name, "Auto" ) )
			status = setAccessMethodAuto( &keysetInfoPtr->keysetScard );
		else
		if( !stricmp( name, "Gemplus" ) )
			status = setAccessMethodGemplus( &keysetInfoPtr->keysetScard );
		else
		if( !stricmp( name, "Towitoko" ) )
			status = setAccessMethodTowitoko( &keysetInfoPtr->keysetScard );
		else
			status = CRYPT_BADPARM3;
		if( cryptStatusError( status ) )
			return( CRYPT_BADPARM3 );

		/* Set up the comms params if they're present */
		status = getCommParams( &commParams, param3, FALSE );
		if( status == CRYPT_BADPARM )
			status = CRYPT_BADPARM6;	/* Map to correct error code */
		if( cryptStatusError( status ) )
			return( status );

		/* Open a session to the reader and card.  If an error occurs we need
		   to map the scInitReader()-relative status codes to
		   cryptKeysetOpenEx()-relative codes */
		status = keysetInfoPtr->keysetScard.initReader( &keysetInfoPtr->keysetScard,
											param1, param2, &commParams );
		if( cryptStatusError( status ) )
			return( ( status == CRYPT_BADPARM2 ) ? CRYPT_BADPARM4 : \
					( status == CRYPT_BADPARM3 ) ? CRYPT_BADPARM5 : status );

		/* If we're opening the keyset in create mode, wipe the old keyset.
		   This clears any existing data on the card and also checks for
		   writeability during the keyset open phase rather than later when
		   we're trying to write a key */
		if( options == CRYPT_KEYOPT_CREATE )
			{
			/* Smart cards don't explicitly support the ability to delete
			   records, so we write a null record which tells the lower-level
			   routines to overwrite whatever's on the card */
			status = keysetInfoPtr->keysetScard.writeData( &keysetInfoPtr->keysetScard,
														   NULL, 0 );
			if( cryptStatusError( status ) )
				return( status );
			keysetInfoPtr->keysetEmpty = TRUE;
			}

		return( status );
		}

	/* If it's an LDAP server, try and open a session with the server */
	if( keysetType == CRYPT_KEYSET_LDAP )
		{
		/* Set up the access method pointers */
		status = setAccessMethodLDAP( keysetInfoPtr );
		if( cryptStatusError( status ) )
			return( status );

		status = keysetInfoPtr->keysetLDAP.openDatabase( keysetInfoPtr, name,
														 param1, param2, param3 );
		return( ( status == CRYPT_BADPARM2 ) ? CRYPT_BADPARM3 : \
				( status == CRYPT_BADPARM3 ) ? CRYPT_BADPARM4 : status );
		}

	/* If it's an HTTP connection, we don't do anything except initialise the
	   TCP/IP comms until the user tries to fetch the key */
	if( keysetType == CRYPT_KEYSET_HTTP )
		{
		/* We can't open an HTTP keyset for anything other than read-only
		   access */
		if( options != CRYPT_KEYOPT_READONLY )
			return( CRYPT_NOPERM );

		/* HTTP is stateless so there's nothing to do at this point.  Because
		   of this we also do an explicit check for DBX_HTTP here since
		   there's no setup function which we can use to detect this */
#ifdef DBX_HTTP
		return( CRYPT_OK );
#else
		return( CRYPT_BADPARM2 );
#endif /* DBX_HTTP */
		}

	/* It's an RDBMS, set up the appropriate access method pointers */
	switch( keysetType )
		{
		case CRYPT_KEYSET_ODBC:
			status = setAccessMethodODBC( keysetInfoPtr );
			break;

		case CRYPT_KEYSET_BSQL:
			status = setAccessMethodBSQL( keysetInfoPtr );
			break;

		case CRYPT_KEYSET_MSQL:
			status = setAccessMethodMSQL( keysetInfoPtr );
			break;

		case CRYPT_KEYSET_MYSQL:
			status = setAccessMethodMySQL( keysetInfoPtr );
			break;

		case CRYPT_KEYSET_ORACLE:
			status = setAccessMethodOracle( keysetInfoPtr );
			break;

		case CRYPT_KEYSET_POSTGRES:
			status = setAccessMethodPostgres( keysetInfoPtr );
			break;

		case CRYPT_KEYSET_RAIMA:
			status = setAccessMethodRaima( keysetInfoPtr );
			break;

		case CRYPT_KEYSET_SOLID:
			status = setAccessMethodSolid( keysetInfoPtr );
			break;

		default:
			status = CRYPT_ERROR;	/* Internal error, should never happen */
		}
	if( cryptStatusError( status ) )
		return( status );
	keysetInfoPtr->isDatabaseKeyset = TRUE;

	/* Open the connection to the database and create a new database if
	   required */
	status = dbmsOpenDatabase( keysetInfoPtr, name, param1, param2, param3 );
	if( cryptStatusOK( status ) && options == CRYPT_KEYOPT_CREATE )
		status = dbmsCreateDatabase( keysetInfoPtr );

	return( status );
	}

/* Open and close a keyset */

CRET cryptKeysetOpenEx( CRYPT_KEYSET CPTR keyset, const CRYPT_KEYSET_TYPE keysetType,
						const char CPTR name, const char CPTR param1,
						const char CPTR param2, const char CPTR param3,
						const CRYPT_KEYOPT_TYPE options )
	{
	KEYSET_INFO *keysetInfoPtr;
	int status;

	/* Perform basic error checking */
	if( checkBadPtrRead( keyset, sizeof( CRYPT_KEYSET ) ) )
		return( CRYPT_BADPARM1 );
	if( keysetType <= CRYPT_KEYSET_NONE || keysetType >= CRYPT_KEYSET_LAST )
		return( CRYPT_BADPARM2 );
	if( keysetType == CRYPT_KEYSET_HTTP )
		{
		if( name != NULL )
			return( CRYPT_BADPARM3 );
		}
	else
		if( checkBadPtrRead( name, 2 ) )	/* One char + terminator */
			return( CRYPT_BADPARM3 );
	if( options < CRYPT_KEYOPT_NONE || options >= CRYPT_KEYOPT_LAST )
		/* CRYPT_KEYOPT_NONE is a valid setting for this parameter */
		return( CRYPT_BADPARM7 );

	/* Pass the call on to the lower-level open function */
	status = openKeyset( keyset, keysetType, name, param1, param2,
						 param3, options, &keysetInfoPtr, 0 );
	if( keysetInfoPtr == NULL )
		return( status );	/* Create object failed, return immediately */
	if( cryptStatusError( status ) )
		{
		/* The keyset was created/opened in an incomplete state, destroy it
		   before returning */
		unlockResource( keysetInfoPtr );
		krnlSendNotifier( *keyset, RESOURCE_IMESSAGE_DESTROY );
		*keyset = CRYPT_ERROR;
		return( status );
		}

	unlockResourceExit( keysetInfoPtr, CRYPT_OK );
	}

CRET cryptKeysetOpen( CRYPT_KEYSET CPTR keyset, const CRYPT_KEYSET_TYPE keysetType,
					  const char CPTR name, const CRYPT_KEYOPT_TYPE options )
	{
	int status;

	/* Since the keyset options are passed in a different position for
	   cryptKeysetOpenEx(), we need to convert the error value */
	status = cryptKeysetOpenEx( keyset, keysetType, name, NULL, NULL, NULL,
								options );
	return( ( status == CRYPT_BADPARM7 ) ? CRYPT_BADPARM4 : status );
	}

CRET cryptKeysetClose( const CRYPT_KEYSET keyset )
	{
	return( cryptDestroyObject( keyset ) );
	}

/* Internal open/close functions.  These mark the keyset as being internal/
   skip the internal resource check, and return slightly different error
   codes for parameter errors.  The reason for this is that they're only
   called by cryptlib internal functions so passing any type of parameter
   error back to the caller will cause problems.  For this reason we instead
   pass back the more generic CRYPT_DATA_xxx codes */

int iCryptKeysetOpen( CRYPT_KEYSET *keyset, const CRYPT_KEYSET_TYPE keysetType,
					  const char *name )
	{
	KEYSET_INFO *keysetInfoPtr;
	int status;

	/* Perform simplified error checking */
	if( keysetType <= CRYPT_KEYSET_NONE || keysetType >= CRYPT_KEYSET_LAST || \
		checkBadPtrRead( name, 2 ) )
		return( CRYPT_DATA_OPEN );

	/* Pass the call on to the lower-level open function */
	status = openKeyset( keyset, keysetType, name, NULL, NULL, NULL,
						 CRYPT_KEYOPT_READONLY, &keysetInfoPtr,
						 RESOURCE_FLAG_INTERNAL );
	if( status >= CRYPT_BADPARM && status <= CRYPT_BADPARM10 )
		status = CRYPT_DATA_OPEN;	/* Convert to generic error code */
	if( keysetInfoPtr == NULL )
		return( status );	/* Create object failed, return immediately */
	if( cryptStatusError( status ) )
		{
		/* The keyset was created in an incomplete state, destroy it before
		   returning */
		unlockResource( keysetInfoPtr );
		krnlSendNotifier( *keyset, RESOURCE_IMESSAGE_DESTROY );
		*keyset = CRYPT_ERROR;
		return( status );
		}

	unlockResourceExit( keysetInfoPtr, CRYPT_OK );
	}

int iCryptKeysetClose( const CRYPT_KEYSET keyset )
	{
	/* Decrement the keysets reference count */
	return( krnlSendNotifier( keyset, RESOURCE_IMESSAGE_DECREFCOUNT ) );
	}

/* Retrieve a key from a keyset or equivalent object */

CRET cryptGetPrivateKey( const CRYPT_HANDLE keyset,
						 CRYPT_CONTEXT CPTR cryptContext,
						 const CRYPT_KEYID_TYPE keyIDtype,
						 const void CPTR keyID, const void CPTR password )
	{
	CRYPT_CONTEXT iCryptContext;
	KEYSET_INFO *keysetInfoPtr;
	QUERY_STATE queryState;
	RESOURCE_TYPE objectType;
	BOOLEAN isPublicKey = ( BOOLEAN )	/* Fix for VC++ */
		( password == ( void * ) CRYPT_UNUSED ) ? TRUE : FALSE;
	BOOLEAN isCachedRead = ( BOOLEAN )	/* Fix for VC++ */
		( !isPublicKey && cryptContext == NULL && password == NULL ) ? TRUE : FALSE;
	void *passwordPtr = ( isPublicKey ) ? NULL : ( void * ) password;
	int status;

	/* Although we usually get a key from a keyset, we can also instantiate
	   it via a device, which creates a context or certificate object as if
	   it had been done via cryptDeviceCreateContext() or a hypothetical
	   cryptDeviceCreateCert().  To do this we have to check whether the
	   object passed in is a device or not, if it is we create the requested
	   object via the device instead of trying to read it from a keyset */
	status = krnlSendMessage( keyset, RESOURCE_MESSAGE_GETPROPERTY,
							  &objectType, RESOURCE_MESSAGE_PROPERTY_TYPE,
							  CRYPT_BADPARM1 );
	if( cryptStatusError( status ) )
		return( status );
	if( objectType == RESOURCE_TYPE_DEVICE )
		{
		RESOURCE_DATA_EX resourceDataEx;

		/* Check various parameters - we can only instiate a named object
		   through a device so we make sure everything is set up correctly
		   for this */
		if( checkBadPtrWrite( cryptContext, sizeof( CRYPT_CONTEXT ) ) )
			return( CRYPT_BADPARM2 );
		*cryptContext = CRYPT_ERROR;
		if( keyIDtype == CRYPT_KEYID_NONE )
			{
			if( keyID != NULL )
				return( CRYPT_BADPARM4 );
			}
		else
			{
			if( keyIDtype != CRYPT_KEYID_NAME )
				return( CRYPT_BADPARM3 );
			if( checkBadPtrRead( keyID, 2 ) )	/* One char + terminator */
				return( CRYPT_BADPARM4 );
			}

		setResourceDataEx( &resourceDataEx, cryptContext, 0, 
						   ( void * ) keyID, isPublicKey );
		return( krnlSendMessage( keyset, RESOURCE_MESSAGE_DEV_GETCONTEXT,
								 &resourceDataEx, 0, CRYPT_BADPARM1 ) );
		}

	/* Perform basic error checking */
	getCheckResource( keyset, keysetInfoPtr, RESOURCE_TYPE_KEYSET,
					  CRYPT_BADPARM1 );
	keysetInfoPtr->cachedUpdate = FALSE;	/* Always reset this flag */
	if( isCachedRead )
		{
		/* The read can only be a cached read if it's from a cryptlib or
		   smart card private key keyset */
		if( keysetInfoPtr->type != CRYPT_KEYSET_SMARTCARD && \
			!( keysetInfoPtr->type == CRYPT_KEYSET_FILE && \
			   keysetInfoPtr->subType == KEYSET_SUBTYPE_CRYPTLIB ) )
			unlockResourceExit( keysetInfoPtr, CRYPT_BADPARM2 );
		}
	else
		{
		if( checkBadPtrWrite( cryptContext, sizeof( CRYPT_CONTEXT ) ) )
			unlockResourceExit( keysetInfoPtr, CRYPT_BADPARM2 );
		*cryptContext = CRYPT_ERROR;
		}
	queryState = ( keysetInfoPtr->isDatabaseKeyset ) ? \
				 keysetInfoPtr->keysetDBMS.queryState : \
				 ( keysetInfoPtr->type == CRYPT_KEYSET_LDAP ) ? \
				 keysetInfoPtr->keysetLDAP.queryState : QUERY_NONE;
	if( keyIDtype == CRYPT_KEYID_NONE )
		{
		/* Only private-key keysets containing a single key or ongoing query
		   operations can have a null key ID */
		if( keysetInfoPtr->type != CRYPT_KEYSET_SMARTCARD && \
			!( keysetInfoPtr->type == CRYPT_KEYSET_FILE && \
			   keysetInfoPtr->subType == KEYSET_SUBTYPE_CRYPTLIB ) && \
			!( isPublicKey && queryState == QUERY_INPROGRESS ) )
			return( CRYPT_BADPARM3 );
		}
	else
		if( keyIDtype <= CRYPT_KEYID_NONE || keyIDtype >= CRYPT_KEYID_LAST )
			return( CRYPT_BADPARM3 );
	if( keyIDtype == CRYPT_KEYID_NAME || keyIDtype == CRYPT_KEYID_EMAIL )
		{
		if( checkBadPtrRead( keyID, 2 ) )	/* One char + terminator */
			unlockResourceExit( keysetInfoPtr, CRYPT_BADPARM4 );
		}
	else
		if( keyIDtype == CRYPT_KEYID_OBJECT )
			{
			/* HTTP fetches specify a URL as the key name, so they can't
			   do a fetch by object ID */
			if( keysetInfoPtr->type == CRYPT_KEYSET_HTTP )
				unlockResourceExit( keysetInfoPtr, CRYPT_BADPARM3 );

			if( checkBadPtrRead( keyID, MIN_CRYPT_OBJECTSIZE ) )
				unlockResourceExit( keysetInfoPtr, CRYPT_BADPARM4 );
			}
		else
			if( keyID != NULL )
				unlockResourceExit( keysetInfoPtr, CRYPT_BADPARM4 );
	if( passwordPtr != NULL && checkBadPtrRead( passwordPtr, 2 ) )
		unlockResourceExit( keysetInfoPtr, CRYPT_BADPARM5 );
	if( !isPublicKey && keysetInfoPtr->refCount )
		/* Because of private key data cacheing, we can't read from a cloned
		   private key keyset since this could overwrite the cached data */
		unlockResourceExit( keysetInfoPtr, CRYPT_BUSY );

	/* If it's an ongoing fetch, just grab the next key */
	if( queryState == QUERY_INPROGRESS )
		{
		if( keyIDtype != CRYPT_KEYID_NONE )
			unlockResourceExit( keysetInfoPtr, CRYPT_BADPARM3 );

		/* Fetch the key using the existing parameters */
		status = getKey( keysetInfoPtr, CRYPT_UNUSED, NULL, NULL,
						 &iCryptContext, NULL, TRUE );
		}
	else
		{
		BYTE objectKeyID[ KEYID_SIZE ];

		/* It's a new fetch, set up the key ID info which is used to identify
		   the key if necessary and fetch it */
		if( keyIDtype == CRYPT_KEYID_OBJECT )
			{
			status = getKeyIDfromObject( keyID, objectKeyID );
			if( cryptStatusError( status ) )
				unlockResourceExit( keysetInfoPtr, ( status == CRYPT_BADPARM ) ? \
									CRYPT_BADPARM4 : status );
			keyID = objectKeyID;
			}
		status = getKey( keysetInfoPtr, keyIDtype, keyID, passwordPtr,
						 ( isCachedRead ) ? NULL : &iCryptContext, NULL,
						 isPublicKey );
		}

	/* Make the result externally visible */
	if( cryptStatusOK( status ) )
		{
		if( isCachedRead )
			/* Remember that we're in the middle of a cached update */
			keysetInfoPtr->cachedUpdate = TRUE;
		else
			{
			const int isInternal = FALSE;
			int owner;

			/* If the keyset is bound to a thread, bind the key read from it
			   to the thread as well.  If this fails, we don't return the
			   imported key to the caller since it would be returned in a
			   potentially unbound state */
			status = krnlSendMessage( keyset, RESOURCE_MESSAGE_GETPROPERTY,
									  &owner, RESOURCE_MESSAGE_PROPERTY_OWNER,
									  0 );
			if( cryptStatusError( status ) )
				{
				iCryptDestroyObject( iCryptContext );
				unlockResourceExit( keysetInfoPtr, status );
				}
			krnlSendMessage( iCryptContext, RESOURCE_IMESSAGE_SETPROPERTY,
							 &owner, RESOURCE_MESSAGE_PROPERTY_OWNER,
							 0 );

			/* Make the key externally visible */
			krnlSendMessage( iCryptContext, RESOURCE_IMESSAGE_SETPROPERTY,
							 ( int * ) &isInternal, 
							 RESOURCE_MESSAGE_PROPERTY_INTERNAL, 0 );
			*cryptContext = iCryptContext;
			}
		}
	unlockResourceExit( keysetInfoPtr, status );
	}

CRET cryptGetPublicKey( const CRYPT_KEYSET keyset,
						CRYPT_HANDLE CPTR cryptKey,
						const CRYPT_KEYID_TYPE keyIDtype,
						const void CPTR keyID )
	{
	return( cryptGetPrivateKey( keyset, cryptKey, keyIDtype, keyID,
								( void * ) CRYPT_UNUSED ) );
	}

/* Write a key to a keyset */

CRET cryptAddPrivateKey( const CRYPT_KEYSET keyset,
						 const CRYPT_HANDLE cryptKey,
						 const void CPTR password )
	{
	KEYSET_INFO *keysetInfoPtr;
	BOOLEAN isPublicKey = ( BOOLEAN )	/* Fix for VC++ */
		( password == ( void * ) CRYPT_UNUSED ) ? TRUE : FALSE;
	BOOLEAN isCachedUpdate = FALSE;
	void *passwordPtr = ( isPublicKey ) ? NULL : ( void * ) password;
	int status;

	/* Make sure the keyset parameter is in order */
	getCheckResource( keyset, keysetInfoPtr, RESOURCE_TYPE_KEYSET,
					  CRYPT_BADPARM1 );

	/* If it's a cached update of a private key keyset and everything isn't
	   exactly right, complain */
	if( keysetInfoPtr->cachedUpdate )
		{
		ICRYPT_QUERY_INFO iCryptQueryInfo;
		int context, value;

		/* It's no longer a cached update after we exit from this call,
		   whether the update succeeds or not */
		keysetInfoPtr->cachedUpdate = FALSE;

		/* Make sure we're adding an exportable certificate as a private
		   key */
		if( isPublicKey || password != NULL || \
			cryptStatusError( cryptGetCertComponentNumeric( cryptKey,
								CRYPT_CERTINFO_IMMUTABLE, &value ) ) || \
			value != TRUE )
			unlockResourceExit( keysetInfoPtr, CRYPT_BADPARM2 );

		/* Check that the cert matches the cached private key info */
		status = krnlSendMessage( cryptKey, RESOURCE_MESSAGE_GETDATA,
								  &context, RESOURCE_MESSAGE_DATA_CONTEXT,
								  CRYPT_BADPARM2 );
		if( cryptStatusError( status ) )
			unlockResourceExit( keysetInfoPtr, status );
		status = iCryptQueryContext( context, &iCryptQueryInfo );
		if( cryptStatusError( status ) )
			{
			if( status == CRYPT_BADPARM1 )
				status = CRYPT_BADPARM2;	/* Map to correct error code */
			unlockResourceExit( keysetInfoPtr, status );
			}
		if( memcmp( keysetInfoPtr->cachedKeyID, iCryptQueryInfo.keyID, KEYID_SIZE ) )
			unlockResourceExit( keysetInfoPtr, CRYPT_BADPARM2 );

		/* Remember that this is a cached update with special requirements */
		isCachedUpdate = TRUE;
		}

	/* If it's a bulk update indicator, we don't do anything but simply
	   signal the lower-level routines that this is the start/finish of a
	   bulk update */
	if( cryptKey == CRYPT_KEYUPDATE_BEGIN || cryptKey == CRYPT_KEYUPDATE_END )
		{
		const QUERY_STATE queryState = ( keysetInfoPtr->isDatabaseKeyset ) ? \
						keysetInfoPtr->keysetDBMS.queryState : \
						( keysetInfoPtr->type == CRYPT_KEYSET_LDAP ) ? \
						keysetInfoPtr->keysetLDAP.queryState : QUERY_NONE;

		/* Bulk updates are only valid for DBMS keysets */
		if( !keysetInfoPtr->isDatabaseKeyset )
			unlockResourceExit( keysetInfoPtr, CRYPT_BADPARM2 );

		/* We can't start a bulk update if we're currently in the middle of
		   a general query or another update */
		if( queryState != QUERY_NONE || \
			( cryptKey == CRYPT_KEYUPDATE_BEGIN && \
			  keysetInfoPtr->keysetDBMS.bulkUpdateState != BULKUPDATE_NONE ) )
			return( CRYPT_INCOMPLETE );

		/* We can't finish a bulk update unless we've started one */
		if( cryptKey == CRYPT_KEYUPDATE_END && \
			!( keysetInfoPtr->keysetDBMS.bulkUpdateState == BULKUPDATE_START || \
			   keysetInfoPtr->keysetDBMS.bulkUpdateState == BULKUPDATE_UPDATE ) )
			unlockResourceExit( keysetInfoPtr, CRYPT_BADPARM2 );
		if( passwordPtr != NULL )
			unlockResourceExit( keysetInfoPtr, CRYPT_BADPARM3 );
		}
	else
		{
		/* If it's a private key, make sure that the password is valid if
		   there's one supplied */
		if( !isPublicKey && passwordPtr != NULL && \
			( checkBadPtrRead( passwordPtr, 2 ) || \
			  checkBadPassword( passwordPtr ) ) )
			unlockResourceExit( keysetInfoPtr, CRYPT_BADPARM3 );
		}

	/* Make sure we can write to the keyset.  This covers all possibilities
	   (both keyset types for which writing isn't supported, and individual
	   keysets which we can't write to because of things like file
	   permissions), so once we pass this check we know we can write to the
	   keyset */
	if( keysetInfoPtr->options == CRYPT_KEYOPT_READONLY )
		unlockResourceExit( keysetInfoPtr, CRYPT_NOPERM );

	/* If it's keyset type which can only contain a single key and we've
	   already written a key to it, we can't write any more keys */
	if( ( keysetInfoPtr->type == CRYPT_KEYSET_SMARTCARD || \
		  ( keysetInfoPtr->type == CRYPT_KEYSET_FILE && \
			keysetInfoPtr->subType == KEYSET_SUBTYPE_CRYPTLIB ) ) && \
		!( keysetInfoPtr->keysetEmpty || isCachedUpdate ) )
		unlockResourceExit( keysetInfoPtr, CRYPT_INITED );

	/* Add the key */
	status = putKey( keysetInfoPtr, cryptKey, password, isPublicKey,
					 isCachedUpdate );
	if( cryptStatusOK( status ) )
		/* Record the fact that we've successfully added a key */
		keysetInfoPtr->keysetEmpty = FALSE;
	unlockResourceExit( keysetInfoPtr, status );
	}

CRET cryptAddPublicKey( const CRYPT_KEYSET keyset,
						const CRYPT_CERTIFICATE certificate )
	{
	return( cryptAddPrivateKey( keyset, certificate, ( void * ) CRYPT_UNUSED ) );
	}

/* Delete a key from a keyset */

CRET cryptDeleteKey( const CRYPT_KEYSET keyset,
					 const CRYPT_KEYID_TYPE keyIDtype,
					 const void CPTR keyID )
	{
	KEYSET_INFO *keysetInfoPtr;
	BYTE objectKeyID[ KEYID_SIZE ];
	int status;

	/* Perform basic error checking */
	getCheckResource( keyset, keysetInfoPtr, RESOURCE_TYPE_KEYSET,
					  CRYPT_BADPARM1 );
	keysetInfoPtr->cachedUpdate = FALSE;	/* Always reset this flag */
	if( keyIDtype <= CRYPT_KEYID_NONE || keyIDtype >= CRYPT_KEYID_LAST )
		unlockResourceExit( keysetInfoPtr, CRYPT_BADPARM2 );
	if( keyIDtype == CRYPT_KEYID_NAME || keyIDtype == CRYPT_KEYID_EMAIL )
		{
		if( checkBadPtrRead( keyID, 2 ) )	/* One char + terminator */
			unlockResourceExit( keysetInfoPtr, CRYPT_BADPARM4 );
		}
	else
		if( checkBadPtrRead( keyID, MIN_CRYPT_OBJECTSIZE ) )
			unlockResourceExit( keysetInfoPtr, CRYPT_BADPARM4 );

	/* Make sure we can write to the keyset.  This covers all possibilities
	   (both keyset types for which writing isn't supported, and individual
	   keysets which we can't write to because of things like file
	   permissions), so once we pass this check we know we can write to the
	   keyset */
	if( keysetInfoPtr->options == CRYPT_KEYOPT_READONLY )
		unlockResourceExit( keysetInfoPtr, CRYPT_NOPERM );

	/* If it's a cryptlib native keyset type, turn it into an empty keyset */
	if( keysetInfoPtr->type == CRYPT_KEYSET_FILE && \
		keysetInfoPtr->subType == KEYSET_SUBTYPE_CRYPTLIB )
		{
		fileCloseErase( &keysetInfoPtr->keysetFile.stream,
						keysetInfoPtr->keysetFile.fileName );
		status = sFileOpen( &keysetInfoPtr->keysetFile.stream,
        					keysetInfoPtr->keysetFile.fileName,
							FILE_READ | FILE_WRITE | FILE_PRIVATE );
		keysetInfoPtr->keysetEmpty = \
			keysetInfoPtr->keysetFile.streamOpen = TRUE;
		if( cryptStatusError( status ) )
			{
			/* We only get here if something really peculiar happens (eg
			   another process making the file readonly between us opening it
			   and performing the delete).  Since whatever made the change
			   probably has a good reason for doing this, we leave it alone
			   and mark the keyset as closed.  We also map the error into a
			   write error since the file open will have returned some sort
			   of file open error which won't make much sense to the caller */
			keysetInfoPtr->keysetEmpty = \
				keysetInfoPtr->keysetFile.streamOpen = FALSE;
			unlockResourceExit( keysetInfoPtr, CRYPT_DATA_WRITE );
			}
		unlockResourceExit( keysetInfoPtr, CRYPT_OK );
		}

	/* If it's a smart card keyset, overwrite the data on the card */
	if( keysetInfoPtr->type == CRYPT_KEYSET_SMARTCARD )
		{
		/* Smart cards don't explicitly support the ability to delete
		   records, so we write a null record which tells the lower-level
		   routines to overwrite whatever's on the card */
		status = keysetInfoPtr->keysetScard.writeData( &keysetInfoPtr->keysetScard,
													   NULL, 0 );
		keysetInfoPtr->keysetEmpty = TRUE;
		unlockResourceExit( keysetInfoPtr, status );
		}

	/* If it's an LDAP keyset, delete the directory entry */
	if( keysetInfoPtr->type == CRYPT_KEYSET_LDAP )
		{
		status = ldapDeleteKey( keysetInfoPtr, keyID );
		unlockResourceExit( keysetInfoPtr, status );
		}

	/* Make sure the keyset type is one which allows key deletion */
	if( !keysetInfoPtr->isDatabaseKeyset )
		unlockResourceExit( keysetInfoPtr, CRYPT_NOPERM );

	/* Set up the key ID which is used to identify the key if necessary.
	   Because of this it's also possible to delete keys based on keyID's,
	   which is somewhat odd but there doesn't seem to be any good reason to
	   prohibit this */
	if( keyIDtype == CRYPT_KEYID_OBJECT )
		{
		status = getKeyIDfromObject( keyID, objectKeyID );
		if( cryptStatusError( status ) )
			unlockResourceExit( keysetInfoPtr, ( status == CRYPT_BADPARM ) ? \
								CRYPT_BADPARM3 : status );
		keyID = objectKeyID;
		}

	/* Delete the key */
	status = dbmsDeleteKey( keysetInfoPtr, keyIDtype, keyID );
	unlockResourceExit( keysetInfoPtr, status );
	}

/* Send a general query to a keyset data source */

CRET cryptKeysetQuery( const CRYPT_KEYSET keyset, const char CPTR query )
	{
	KEYSET_INFO *keysetInfoPtr;
	int status;

	/* Perform basic error checking */
	getCheckResource( keyset, keysetInfoPtr, RESOURCE_TYPE_KEYSET,
					  CRYPT_BADPARM1 );
	if( !keysetInfoPtr->isDatabaseKeyset && \
		keysetInfoPtr->type != CRYPT_KEYSET_LDAP )
		unlockResourceExit( keysetInfoPtr, CRYPT_BADPARM1 );
	if( checkBadPtrRead( query, 6 ) || strlen( query ) < 6 )
		/* The query must be at least 6 characters long (the length of
		   "cancel") */
		unlockResourceExit( keysetInfoPtr, CRYPT_BADPARM2 );

	/* Send the query to the data source */
	if( keysetInfoPtr->type == CRYPT_KEYSET_LDAP )
		status = ldapGetKey( keysetInfoPtr, query, NULL );
	else
		status = dbmsQuery( keysetInfoPtr, query, NULL );

	unlockResourceExit( keysetInfoPtr, status );
	}
