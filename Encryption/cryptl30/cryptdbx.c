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
  #include "keyset.h"
#else
  #include "keymgmt/asn1.h"
  #include "misc/keyset.h"
#endif /* Compiler-specific includes */

/* The key database access strategies for the various database types are:

		   |PGP			PKCS #15		RDBMS		LDAP	HTTP
	-------+---------------------------------------------------------
	Create |	-		Zap existing,	Only if not	-		-
		   |			create MT set	existing
		   +---------------------------------------------------------
	Write  |	-		Add				Add			Add		-
		   +---------------------------------------------------------
	Read   |Yes: Name,	Yes: Name,		Yes: Name,	Yes: DN	Yes : URL
		   |email, ID	email, ID		email, ID
		   +---------------------------------------------------------
	Delete |	-		Yes: Name,		Yes: Name,	Yes: DN	-
		   |			email, ID		email, ID */

/* Prototypes for misc key read functions */

int getKeysetType( STREAM *stream );

/* Some keysets aren't supported on some platforms so we alias the calls out */

#if !( defined( __WINDOWS__ ) || defined( __UNIX__ ) )
  #define setAccessMethodDBMS( x, y )		CRYPT_ARGERROR_NUM1
#endif /* !( __WINDOWS__ || __UNIX__ ) */
#ifndef DBX_LDAP
  #define setAccessMethodLDAP( x )			CRYPT_ARGERROR_NUM1
#endif /* DBX_LDAP */
#ifndef DBX_HTTP
  #define setAccessMethodHTTP( x )			CRYPT_ARGERROR_NUM1
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

void scardInitASE( void );
void scardInitGemplus( void );
void scardInitTowitoko( void );
void scardEndASE( void );
void scardEndGemplus( void );
void scardEndTowitoko( void );

void initKeysets( void )
	{
#ifdef DBX_ODBC
	dbxInitODBC();
#endif /* DBX_ODBC */
#ifdef DBX_LDAP
	dbxInitLDAP();
#endif /* DBX_LDAP */
#if defined( __WINDOWS__ ) && !defined( NT_DRIVER )
  #ifdef __WIN32__
	scardInitASE();
  #endif /* __WIN32__ */
	scardInitGemplus();
	scardInitTowitoko();
#endif /* __WINDOWS__ && !NT_DRIVER */
	}

void shutdownKeysets( void )
	{
#ifdef DBX_ODBC
	dbxEndODBC();
#endif /* DBX_ODBC */
#ifdef DBX_LDAP
	dbxEndLDAP();
#endif /* DBX_LDAP */
#if defined( __WINDOWS__ ) && !defined( NT_DRIVER )
  #ifdef __WIN32__
	scardEndASE();
  #endif /* __WIN32__ */
	scardEndGemplus();
	scardEndTowitoko();
#endif /* __WINDOWS__ && !NT_DRIVER */
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
								  const int messageValue )
	{
	KEYSET_INFO *keysetInfoPtr;

	getCheckInternalResource( cryptKeyset, keysetInfoPtr, OBJECT_TYPE_KEYSET );

	/* Process the destroy object message */
	if( message == RESOURCE_MESSAGE_DESTROY )
		{
		int status = CRYPT_OK;

		/* Shut down the keyset if required */
		if( keysetInfoPtr->shutdownKeysetFunction != NULL )
			keysetInfoPtr->shutdownKeysetFunction( keysetInfoPtr );

		/* If the keyset is implemented as a file, close it (the keyset-
		   specific handler sees only an I/O stream and doesn't perform any
		   file-level functions) */
		if( keysetInfoPtr->type == CRYPT_KEYSET_FILE && \
			keysetInfoPtr->isOpen )
			{
			/* Since the update may have changed the overall size, we
			   need to clear any leftover data from the previous 
			   version of the keyset before we close the file */
			if( keysetInfoPtr->isDirty )
				fileClearToEOF( &keysetInfoPtr->keysetFile.stream );
			sFileClose( &keysetInfoPtr->keysetFile.stream );

			/* If it's a newly-created empty keyset file, remove it (this can
			   occur if there's some sort of error on writing and no keys are
			   ever written to the keyset */
			if( keysetInfoPtr->isEmpty )
				fileUnlink( keysetInfoPtr->keysetFile.fileName );
			}

		/* Delete the objects locking variables and the object itself */
		unlockResource( keysetInfoPtr );
		deleteResourceLock( keysetInfoPtr );
		zeroise( keysetInfoPtr, sizeof( KEYSET_INFO ) );
		free( keysetInfoPtr );

		return( status );
		}

	/* Process attribute get/set/delete messages */
	if( message == RESOURCE_MESSAGE_SETATTRIBUTE )
		{
		assert( messageValue == CRYPT_IATTRIBUTE_INITIALISED );

		/* It's an initialisation message, there's nothing to do */
		unlockResourceExit( keysetInfoPtr, CRYPT_OK );
		}
	if( message == RESOURCE_MESSAGE_SETATTRIBUTE_S )
		{
		RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
		int status;

		/* If it's encoded config data, pass it through to the keyset */
		if( messageValue == CRYPT_IATTRIBUTE_CONFIGDATA )
			{
			assert( keysetInfoPtr->subType == KEYSET_SUBTYPE_PKCS15 );
			assert( keysetInfoPtr->setItemFunction != NULL );

			status = keysetInfoPtr->setItemFunction( keysetInfoPtr,
							CRYPT_UNUSED, msgData->data, msgData->length );
			if( cryptStatusOK( status ) )
				{
				/* The update succeeded, remember that the data in the keyset 
				   has changed */
				keysetInfoPtr->isDirty = TRUE;
				keysetInfoPtr->isEmpty = FALSE;
				}
			unlockResourceExit( keysetInfoPtr, status );
			}

		assert( messageValue == CRYPT_KEYSETINFO_QUERY );

		if( keysetInfoPtr->queryFunction == NULL )
			unlockResourceExit( keysetInfoPtr, CRYPT_ARGERROR_VALUE );

		/* Send the query to the data source */
		status = keysetInfoPtr->queryFunction( keysetInfoPtr, msgData->data,
											   msgData->length );
		unlockResourceExit( keysetInfoPtr, status );
		}
	if( message == RESOURCE_MESSAGE_GETATTRIBUTE )
		{
		int *valuePtr = ( int * ) messageDataPtr;

		switch( messageValue )
			{
			case CRYPT_ATTRIBUTE_ERRORTYPE:
				*valuePtr = keysetInfoPtr->errorType;
				break;

			case CRYPT_ATTRIBUTE_ERRORLOCUS:
				*valuePtr = keysetInfoPtr->errorLocus;
				break;
			
			case CRYPT_ATTRIBUTE_INT_ERRORCODE:
				*valuePtr = keysetInfoPtr->errorCode;
				break;

			default:
				assert( NOTREACHED );
			}
		unlockResourceExit( keysetInfoPtr, CRYPT_OK );
		}
	if( message == RESOURCE_MESSAGE_GETATTRIBUTE_S )
		{
		RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
		int status;

		/* If it's encoded config data, fetch it from to the keyset */
		if( messageValue == CRYPT_IATTRIBUTE_CONFIGDATA )
			{
			assert( keysetInfoPtr->subType == KEYSET_SUBTYPE_PKCS15 );

			status = keysetInfoPtr->getItemFunction( keysetInfoPtr,
										NULL, CRYPT_KEYID_NONE, NULL, 0,
										msgData->data, &msgData->length, 0 );
			if( !cryptStatusError( status ) )
				{
				msgData->length = status;
				status = CRYPT_OK;
				}
			unlockResourceExit( keysetInfoPtr, status );
			}

		assert( messageValue == CRYPT_ATTRIBUTE_INT_ERRORMESSAGE );

		status = attributeCopy( msgData, keysetInfoPtr->errorMessage,
								strlen( keysetInfoPtr->errorMessage ) );
		unlockResourceExit( keysetInfoPtr, status );
		}

	/* Process messages which check a keyset */
	if( message == RESOURCE_MESSAGE_CHECK )
		{
		if( ( messageValue == RESOURCE_MESSAGE_CHECK_PKC_PRIVATE || \
			  messageValue == RESOURCE_MESSAGE_CHECK_PKC_ENCRYPT || \
			  messageValue == RESOURCE_MESSAGE_CHECK_PKC_SIGCHECK ) && \
			( keysetInfoPtr->type == KEYSET_DBMS || \
			  keysetInfoPtr->type == KEYSET_LDAP || \
			  keysetInfoPtr->type == KEYSET_HTTP ) )
			unlockResourceExit( keysetInfoPtr, CRYPT_ARGERROR_OBJECT );

		unlockResourceExit( keysetInfoPtr, CRYPT_OK );
		}

	/* Process object-specific messages */
	if( message == RESOURCE_MESSAGE_KEY_GETKEY )
		{
		MESSAGE_KEYMGMT_INFO *getkeyInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;
		CRYPT_KEYID_TYPE keyIDtype = getkeyInfo->keyIDtype;
		BYTE keyIDbuffer[ KEYID_SIZE ];
		const void *keyID = getkeyInfo->keyID;
		int keyIDlength = getkeyInfo->keyIDlength, status;

		assert( ( keyIDtype == CRYPT_KEYID_NONE && \
				  keyID == NULL && getkeyInfo->keyIDlength == 0 ) || \
				( keyIDtype != CRYPT_KEYID_NONE && \
				  keyID != NULL && getkeyInfo->keyIDlength > 0 ) );

		/* Make sure this access type is valid for this keyset */
		if( ( getkeyInfo->flags & KEYMGMT_FLAG_PRIVATEKEY ) && \
			( keysetInfoPtr->type == KEYSET_DBMS || \
			  keysetInfoPtr->type == KEYSET_LDAP || \
			  keysetInfoPtr->type == KEYSET_HTTP ) )
			unlockResourceExit( keysetInfoPtr, CRYPT_ARGERROR_OBJECT );
		if( keysetInfoPtr->getItemFunction == NULL )
			unlockResourceExit( keysetInfoPtr, CRYPT_ERROR_NOTAVAIL );
		if( keyIDtype == CRYPT_KEYID_NONE && \
			!( keysetInfoPtr->type == KEYSET_DBMS || \
			   keysetInfoPtr->type == KEYSET_LDAP ) )
			/* A null key ID implies a query which is only valid for DBMS
			   and LDAP keysets */
			unlockResourceExit( keysetInfoPtr, CRYPT_ARGERROR_NUM1 );

		/* If we've been passed a full issuerAndSerialNumber as a key ID and 
		   the keyset needs an issuerID, convert it */
		if( keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER && \
			( keysetInfoPtr->type == KEYSET_DBMS || \
			  ( keysetInfoPtr->type == KEYSET_FILE && \
			    keysetInfoPtr->subType == KEYSET_SUBTYPE_PKCS15 ) ) )
			{
			HASHFUNCTION hashFunction;
			int hashSize;

			/* Get the hash algorithm information */
			getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );

			/* Hash the full iAndS to get an issuerID and use that for the keyID */
			hashFunction( NULL, keyIDbuffer, ( BYTE * ) keyID, keyIDlength, 
						  HASH_ALL );
			keyIDtype = CRYPT_IKEYID_ISSUERID;
			keyID = keyIDbuffer;
			keyIDlength = hashSize;
			}

		/* Get the key */
		status = keysetInfoPtr->getItemFunction( keysetInfoPtr,
								&getkeyInfo->cryptHandle, keyIDtype, keyID, 
								keyIDlength, getkeyInfo->auxInfo, 
								&getkeyInfo->auxInfoLength, getkeyInfo->flags );
		unlockResourceExit( keysetInfoPtr, status );
		}
	if( message == RESOURCE_MESSAGE_KEY_SETKEY )
		{
		MESSAGE_KEYMGMT_INFO *setkeyInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;
		int status;

		/* Make sure this access type is valid for this keyset */
		if( ( setkeyInfo->flags & KEYMGMT_FLAG_PRIVATEKEY ) && \
			( keysetInfoPtr->type == KEYSET_DBMS || \
			  keysetInfoPtr->type == KEYSET_LDAP || \
			  keysetInfoPtr->type == KEYSET_HTTP ) )
			unlockResourceExit( keysetInfoPtr, CRYPT_ARGERROR_OBJECT );

		/* Make sure we can write to the keyset.  This covers all 
		   possibilities (both keyset types for which writing isn't 
		   supported, and individual keysets which we can't write to because 
		   of things like file permissions), so once we pass this check we 
		   know we can write to the keyset */
		if( keysetInfoPtr->options == CRYPT_KEYOPT_READONLY )
			unlockResourceExit( keysetInfoPtr, CRYPT_ERROR_PERMISSION );
		if( keysetInfoPtr->setItemFunction == NULL )
			unlockResourceExit( keysetInfoPtr, CRYPT_ERROR_NOTAVAIL );

		/* Set the key */
		status = keysetInfoPtr->setItemFunction( keysetInfoPtr, messageValue, 
							setkeyInfo->auxInfo, setkeyInfo->auxInfoLength );
		if( cryptStatusOK( status ) )
			{
			/* The update succeeded, remember that the data in the keyset has 
			   changed */
			keysetInfoPtr->isDirty = TRUE;
			keysetInfoPtr->isEmpty = FALSE;
			}
		unlockResourceExit( keysetInfoPtr, status );
		}
	if( message == RESOURCE_MESSAGE_KEY_DELETEKEY )
		{
		MESSAGE_KEYMGMT_INFO *deletekeyInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;
		CRYPT_KEYID_TYPE keyIDtype = deletekeyInfo->keyIDtype;
		BYTE keyIDbuffer[ KEYID_SIZE ];
		const void *keyID = deletekeyInfo->keyID;
		int keyIDlength = deletekeyInfo->keyIDlength, status;

		/* Make sure we can write to the keyset.  This covers all 
		   possibilities (both keyset types for which writing isn't supported, 
		   and individual keysets which we can't write to because of things 
		   like file permissions), so once we pass this check we know we can 
		   write to the keyset */
		if( keysetInfoPtr->options == CRYPT_KEYOPT_READONLY )
			unlockResourceExit( keysetInfoPtr, CRYPT_ERROR_PERMISSION );
		if( keysetInfoPtr->deleteItemFunction == NULL )
			unlockResourceExit( keysetInfoPtr, CRYPT_ERROR_NOTAVAIL );

		/* If we've been passed a full issuerAndSerialNumber as a key ID and 
		   the keyset needs an issuerID, convert it */
		if( keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER && \
			( keysetInfoPtr->type == KEYSET_DBMS || \
			  ( keysetInfoPtr->type == KEYSET_FILE && \
			    keysetInfoPtr->subType == KEYSET_SUBTYPE_PKCS15 ) ) )
			{
			HASHFUNCTION hashFunction;
			int hashSize;

			/* Get the hash algorithm information */
			getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );

			/* Hash the full iAndS to get an issuerID and use that for the keyID */
			hashFunction( NULL, keyIDbuffer, ( BYTE * ) keyID, keyIDlength, 
						  HASH_ALL );
			keyIDtype = CRYPT_IKEYID_ISSUERID;
			keyID = keyIDbuffer;
			keyIDlength = hashSize;
			}

		/* Delete the key */
		status = keysetInfoPtr->deleteItemFunction( keysetInfoPtr, keyIDtype, 
													keyID, keyIDlength );
		if( cryptStatusOK( status ) )
			/* The update succeeded, remember that the data in the keyset has 
			   changed */
			keysetInfoPtr->isDirty = TRUE;
		unlockResourceExit( keysetInfoPtr, status );
		}
	if( message == RESOURCE_MESSAGE_KEY_GETNEXTCERT )
		{
		MESSAGE_KEYMGMT_INFO *getnextcertInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;
		int status = CRYPT_ERROR_NOTAVAIL;

		assert( getnextcertInfo->auxInfoLength == sizeof( int ) );

		/* Fetch a cert in a cert chain from the keyset */
		if( keysetInfoPtr->getNextCertFunction != NULL )
			status = keysetInfoPtr->getNextCertFunction( keysetInfoPtr,
						&getnextcertInfo->cryptHandle, getnextcertInfo->auxInfo,
						getnextcertInfo->keyIDtype, getnextcertInfo->keyID, 
						getnextcertInfo->keyIDlength, getnextcertInfo->flags );

		unlockResourceExit( keysetInfoPtr, status );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR_NOTAVAIL );	/* Get rid of compiler warning */
	}

/* Open a keyset.  This is a low-level function encapsulated by createKeyset()
   and used to manage error exits */

static int openKeyset( CRYPT_KEYSET *iCryptKeyset,
					   const CRYPT_KEYSET_TYPE keysetType,
					   const char *name, const char *param1,
					   const char *param2, const char *param3,
					   const CRYPT_KEYOPT_TYPE options,
					   KEYSET_INFO **keysetInfoPtrPtr )
	{
	KEYSET_INFO *keysetInfoPtr;
	const int subType = \
		( keysetType == CRYPT_KEYSET_FILE ) ? SUBTYPE_KEYSET_FILE : \
		( keysetType == CRYPT_KEYSET_HTTP ) ? SUBTYPE_KEYSET_HTTP : \
		( keysetType == CRYPT_KEYSET_LDAP ) ? SUBTYPE_KEYSET_LDAP : \
		( keysetType == CRYPT_KEYSET_SMARTCARD ) ? SUBTYPE_KEYSET_SCARD : \
		SUBTYPE_KEYSET_DBMS;
	int status;

	/* Clear the return values */
	*iCryptKeyset = CRYPT_ERROR;
	*keysetInfoPtrPtr = NULL;

	/* Wait for any async keyset driver binding to complete */
	waitSemaphore( SEMAPHORE_DRIVERBIND );

	/* Create the keyset object */
	status = krnlCreateObject( ( void ** ) &keysetInfoPtr, 
							   OBJECT_TYPE_KEYSET, subType,
							   sizeof( KEYSET_INFO ), 0, 0, 
							   keysetMessageFunction );
	if( cryptStatusError( status ) )
		return( status );
	initResourceLock( keysetInfoPtr ); 
	lockResource( keysetInfoPtr ); 
	*keysetInfoPtrPtr = keysetInfoPtr;
	*iCryptKeyset = keysetInfoPtr->objectHandle = status;
	keysetInfoPtr->options = options;

	/* If it's a flat-file keyset, open a handle to it */
	if( keysetType == CRYPT_KEYSET_FILE )
		{
		int openMode;

		keysetInfoPtr->type = KEYSET_FILE;

		/* Remember the key file's name */
		if( strlen( name ) > MAX_PATH_LENGTH - 1 )
			return( CRYPT_ARGERROR_STR1 );
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
				return( CRYPT_ERROR_PERMISSION );

			/* Open the file in readonly mode */
			keysetInfoPtr->options = CRYPT_KEYOPT_READONLY;
			openMode = FILE_READ;
			}
		else
			/* If we're creating the file, open it in write-only mode.  Since
			   we'll (presumably) be storing private keys in it, we mark it 
			   as both private (owner-access-only ACL) and sensitive (store 
			   in secure storage if possible) */
			if( options == CRYPT_KEYOPT_CREATE )
				openMode = FILE_WRITE | FILE_PRIVATE | FILE_SENSITIVE;
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
			keysetInfoPtr->subType = KEYSET_SUBTYPE_PKCS15;
			setAccessMethodPKCS15( keysetInfoPtr );
			}
		else
			{
			/* The file exists, get its type */
			keysetInfoPtr->subType = getKeysetType( &keysetInfoPtr->keysetFile.stream );
			if( keysetInfoPtr->subType == KEYSET_SUBTYPE_ERROR )
				/* If we're creating a new keyset and there's already 
				   something there, make it look like a cryptlib keyset so 
				   it'll get overwritten later */
				if( options == CRYPT_KEYOPT_CREATE )
					keysetInfoPtr->subType = KEYSET_SUBTYPE_PKCS15;
				else
					{
					/* "It doesn't look like anything from here" */
					sFileClose( &keysetInfoPtr->keysetFile.stream );
					return( CRYPT_ERROR_BADDATA );
					}

			/* Set up the access information for the file */
			switch( keysetInfoPtr->subType )
				{
				case KEYSET_SUBTYPE_PKCS12:
					setAccessMethodPKCS12( keysetInfoPtr );
					break;

				case KEYSET_SUBTYPE_PKCS15:
					setAccessMethodPKCS15( keysetInfoPtr );
					break;

				case KEYSET_SUBTYPE_PGP_PUBLIC:
				case KEYSET_SUBTYPE_PGP_PRIVATE:
					setAccessMethodPGP( keysetInfoPtr );
					break;

				default:
					assert( NOTREACHED );
				}

			/* If it's a cryptlib keyset we can open it in any mode */
			if( keysetInfoPtr->subType == KEYSET_SUBTYPE_PKCS15 )
				{
				/* If we're opening it something other than readonly mode, 
				   reopen it in that mode */
				if( openMode != FILE_READ )
					{
					sFileClose( &keysetInfoPtr->keysetFile.stream );
					status = sFileOpen( &keysetInfoPtr->keysetFile.stream, 
										name, openMode );
					if( cryptStatusError( status ) )
						return( status );	/* Exit with file closed */
					}
				}
			else
				/* If it's a non-cryptlib keyset we can't open it for 
				   anything other than read-only access */
				if( options != CRYPT_KEYOPT_READONLY )
					status = CRYPT_ERROR_PERMISSION;
			}
		if( cryptStatusOK( status ) )
			status = keysetInfoPtr->initKeysetFunction( keysetInfoPtr, NULL, 
												NULL, NULL, NULL, options );
		if( cryptStatusError( status ) )
			{
			sFileClose( &keysetInfoPtr->keysetFile.stream );
			return( status );
			}
		keysetInfoPtr->isOpen = TRUE;
		if( options == CRYPT_KEYOPT_CREATE )
			keysetInfoPtr->isEmpty = TRUE;
		return( CRYPT_OK );
		}

	/* It's a specific type of keyset, set up the access information for it
	   and connect to it */
	switch( keysetType )
		{
		case CRYPT_KEYSET_MSQL:
		case CRYPT_KEYSET_MYSQL:
		case CRYPT_KEYSET_ODBC:
		case CRYPT_KEYSET_ORACLE:
		case CRYPT_KEYSET_POSTGRES:
			keysetInfoPtr->type = KEYSET_DBMS;
			status = setAccessMethodDBMS( keysetInfoPtr, keysetType );
			break;

		case CRYPT_KEYSET_HTTP:
			/* We can't open an HTTP keyset for anything other than read-only
			   access */
			if( options != CRYPT_KEYOPT_READONLY )
				return( CRYPT_ERROR_PERMISSION );

			keysetInfoPtr->type = KEYSET_HTTP;
			status = setAccessMethodHTTP( keysetInfoPtr );
			break;

		case CRYPT_KEYSET_LDAP:
			/* We can't create an LDAP directory */
			if( options == CRYPT_KEYOPT_CREATE )
				return( CRYPT_ERROR_PERMISSION );

			keysetInfoPtr->type = KEYSET_LDAP;
			status = setAccessMethodLDAP( keysetInfoPtr );
			break;

		case CRYPT_KEYSET_SMARTCARD:
			keysetInfoPtr->type = KEYSET_SMARTCARD;
			status = setAccessMethodScard( keysetInfoPtr, name );
			break;

		default:
			assert( NOTREACHED );
		}
	if( cryptStatusOK( status ) )
		status = keysetInfoPtr->initKeysetFunction( keysetInfoPtr, name,
										param1, param2, param3, options );
	if( cryptStatusError( status ) )
		return( status );
	keysetInfoPtr->isOpen = TRUE;
	if( options == CRYPT_KEYOPT_CREATE )
		keysetInfoPtr->isEmpty = TRUE;
	return( status );
	}

/* Create a keyset object */

int createKeyset( CREATEOBJECT_INFO *createInfo, 
				   const void *auxDataPtr, const int auxValue )
	{
	CRYPT_KEYSET iCryptKeyset;
	const CRYPT_KEYSET_TYPE keysetType = createInfo->arg1;
	const CRYPT_KEYOPT_TYPE options = createInfo->arg2;
	KEYSET_INFO *keysetInfoPtr;
	char nameBuffer[ MAX_ATTRIBUTE_SIZE + 1 ];
	char argBuffer[ MAX_ATTRIBUTE_SIZE + 1 ];
	int initStatus, status;

	assert( auxDataPtr == NULL );
	assert( auxValue == 0 );

	/* Perform basic error checking */
	if( keysetType <= CRYPT_KEYSET_NONE || keysetType >= CRYPT_KEYSET_LAST )
		return( CRYPT_ARGERROR_NUM1 );
	if( keysetType == CRYPT_KEYSET_HTTP )
		{
		if( createInfo->strArg1 != NULL )
			return( CRYPT_ARGERROR_STR1 );
		}
	else
		{
		if( createInfo->strArgLen1 < 2 || \
			createInfo->strArgLen1 >= MAX_ATTRIBUTE_SIZE )
			return( CRYPT_ARGERROR_STR1 );
		memcpy( nameBuffer, createInfo->strArg1, createInfo->strArgLen1 );
		nameBuffer[ createInfo->strArgLen1 ] = '\0';
		if( createInfo->strArgLen2 > 0 )
			{
			if( createInfo->strArgLen2 < 2 || \
				createInfo->strArgLen2 >= MAX_ATTRIBUTE_SIZE )
				return( CRYPT_ARGERROR_STR2 );
			memcpy( argBuffer, createInfo->strArg2, createInfo->strArgLen1 );
			argBuffer[ createInfo->strArgLen1 ] = '\0';
			}
		}
	if( options < CRYPT_KEYOPT_NONE || options >= CRYPT_KEYOPT_LAST )
		/* CRYPT_KEYOPT_NONE is a valid setting for this parameter */
		return( CRYPT_ARGERROR_NUM2 );

	/* Pass the call on to the lower-level open function */
	initStatus = openKeyset( &iCryptKeyset, keysetType, nameBuffer, 
							 argBuffer, NULL, NULL, options, &keysetInfoPtr );
	if( keysetInfoPtr == NULL )
		return( initStatus );	/* Create object failed, return immediately */
	if( cryptStatusError( initStatus ) )
		/* The keyset open failed, make sure the object gets destroyed when 
		   we notify the kernel that the setup process is complete */
		krnlSendNotifier( iCryptKeyset, RESOURCE_IMESSAGE_DESTROY );

	/* We've finished setting up the object-type-specific info, tell the 
	   kernel the object is ready for use */
	unlockResource( keysetInfoPtr );
	status = krnlSendMessage( iCryptKeyset, RESOURCE_IMESSAGE_SETATTRIBUTE, 
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusError( initStatus ) || cryptStatusError( status ) )
		return( cryptStatusError( initStatus ) ? initStatus : status );
	createInfo->cryptHandle = iCryptKeyset;
	return( CRYPT_OK );
	}
