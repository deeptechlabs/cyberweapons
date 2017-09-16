/****************************************************************************
*																			*
*					  Certificate Trust Management Routines					*
*						Copyright Peter Gutmann 1998-1999					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "asn1.h"
  #include "asn1objs.h"
  #include "cert.h"
#else
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1objs.h"
  #include "keymgmt/cert.h"
#endif /* Compiler-specific includes */

/* The ASN.1 object used to store trust information is as follows:

	TrustInfo ::= SEQUENCE {
		sCheck			INTEGER,				-- Fletcher chk.of subjName
		sHash			OCTET STRING SIZE(20),	-- Hash of subjectName
		publicKey		SubjectPublicKeyInfo	-- Trusted key
		} */

typedef struct TI {
	/* Identification information */
	int sCheck;
	BYTE sHash[ 20 ];			/* Checksum and hash of subjectName */

	/* The trusted certificate.  When we read trusted certs from a config 
	   file, the cert is stored in the encoded form to save creating 
	   cert objects which will never be used, when it's needed the cert is
	   created on the fly from the encoded form.  When we get the trust info 
	   from the user setting it, the cert object already exists and the 
	   encoded form isn't used */
	void *certObject;
	int certObjectLength;
	CRYPT_CERTIFICATE iCryptCert;

	/* Pointer to the next entry */
	struct TI *next;				/* Next trustInfo record in the chain */
	} TRUST_INFO;

/****************************************************************************
*																			*
*						Trust Information Management Routines				*
*																			*
****************************************************************************/

/* Locking variables used to serialise access to the trust information.  All
   functions declared static assume the trustInfo mutex is held by the
   calling function */

DECLARE_LOCKING_VARS( trustInfo )

/* The table of trust information */

static TRUST_INFO *trustInfoIndex[ 256 ];

/* Checksum and hash a DN */

static int checksumName( const BYTE *name, const int nameLength )
	{
	int sum1 = 0, sum2 = 0, i;

	/* Calculate an 8-bit Fletcher checksum of the name */
	for( i = 0; i < nameLength; i++ )
		{
		sum1 += name[ i ];
		sum2 += sum1;
		}

	return( sum2 & 0xFF );
	}

static void hashName( BYTE *hash, const BYTE *name, const int nameLength )
	{
	static HASHFUNCTION hashFunction = NULL;
	int hashSize;

	/* Get the hash algorithm information if necessary */
	if( hashFunction == NULL )
		getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );

	/* Hash the DN */
	hashFunction( NULL, hash, ( BYTE * ) name, nameLength, HASH_ALL );
	}

/* Add and delete a trust entry */

static int addTrustEntry( const CERT_INFO *certInfoPtr,
						  const void *certObject, const int certObjectLength )
	{
	TRUST_INFO *newElement;

	/* Allocate memory for the new element and copy the information across */
	if( ( newElement  = ( TRUST_INFO * ) malloc( sizeof( TRUST_INFO ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memset( newElement, 0, sizeof( TRUST_INFO ) );
	if( certObject != NULL )
		{
		STREAM stream;
		void *subjectDNptr;
		int value, subjectDNsize;

		/* The trusted cert is being read from config data, remember it for
		   later use */
		if( ( newElement->certObject = malloc( certObjectLength ) ) == NULL )
			{
			free( newElement );
			return( CRYPT_ERROR_MEMORY );
			}
		memcpy( newElement->certObject, certObject, certObjectLength );
		newElement->certObjectLength = certObjectLength;
		newElement->iCryptCert = CRYPT_ERROR;

		/* Parse the certificate to locate the start of the encoded subject DN */
		sMemConnect( &stream, certObject, certObjectLength );
		readSequence( &stream, NULL );	/* Outer wrapper */
		readSequence( &stream, NULL );	/* Inner wrapper */
		if( checkReadCtag( &stream, 0, TRUE ) )
			readUniversal( &stream );	/* Version */
		readUniversal( &stream );		/* Serial number */
		readUniversal( &stream );		/* Sig.algo */
		readUniversal( &stream );		/* Issuer DN */
		readUniversal( &stream );		/* Validity */
		subjectDNptr = sMemBufPtr( &stream );
		value = readSequence( &stream, &subjectDNsize );
		subjectDNsize += value;
		sMemDisconnect( &stream );

		/* Generate the checksum and hash of the certs subject name */
		newElement->sCheck = checksumName( subjectDNptr, subjectDNsize );
		hashName( newElement->sHash, subjectDNptr, subjectDNsize );
		}
	else
		{
		/* The trusted key exists as a context, remember it for later */
		krnlSendNotifier( certInfoPtr->objectHandle, 
						  RESOURCE_IMESSAGE_INCREFCOUNT );
		newElement->iCryptCert = certInfoPtr->objectHandle;

		/* Generate the checksum and hash of the certs subject name */
		newElement->sCheck = checksumName( certInfoPtr->subjectDNptr,
										   certInfoPtr->subjectDNsize );
		hashName( newElement->sHash, certInfoPtr->subjectDNptr, 
				  certInfoPtr->subjectDNsize );
		}

	/* Add it to the list */
	if( trustInfoIndex[ newElement->sCheck ] == NULL )
		trustInfoIndex[ newElement->sCheck ] = newElement;
	else
		{
		TRUST_INFO *trustInfoPtr;

		/* Add the new element to the end of the list */
		for( trustInfoPtr = trustInfoIndex[ newElement->sCheck ];
			 trustInfoPtr->next != NULL; trustInfoPtr = trustInfoPtr->next );
		trustInfoPtr->next = newElement;
		}

	return( CRYPT_OK );
	}

static void deleteTrustEntry( TRUST_INFO *trustInfoPtr )
	{
	if( trustInfoPtr->iCryptCert != CRYPT_ERROR )
		krnlSendNotifier( trustInfoPtr->iCryptCert,
						  RESOURCE_IMESSAGE_DECREFCOUNT );
	if( trustInfoPtr->certObject != NULL )
		{
		zeroise( trustInfoPtr->certObject, trustInfoPtr->certObjectLength );
		free( trustInfoPtr->certObject );
		}
	memset( trustInfoPtr, 0, sizeof( TRUST_INFO ) );
	free( trustInfoPtr );
	}

/* Find the trust info entry for a given DN */

static TRUST_INFO *findTrustEntry( const void *name, const int nameLength )
	{
	const int trustInfoPos = checksumName( name, nameLength );
	TRUST_INFO *trustInfoPtr = trustInfoIndex[ trustInfoPos ];
	BYTE sHash[ 20 ];

	/* Perform a quick check using a checksum of the name to weed out most 
	   entries */
	if( trustInfoPtr == NULL )
		return( NULL );

	/* Check to see whether something with the issuers DN is present */
	hashName( sHash, name, nameLength );
	while( trustInfoPtr != NULL )
		{
		if( !memcmp( trustInfoPtr->sHash, sHash, 20 ) )
			return( trustInfoPtr );
		trustInfoPtr = trustInfoPtr->next;
		}

	return( NULL );
	}

/* Get a trusted cert from the trust info.  To save having to instantiate 
   dozens of certs every time we start, we only instantiate them on demand */

static CRYPT_CERTIFICATE getTrustedCert( TRUST_INFO *trustInfoPtr )
	{
	CREATEOBJECT_INFO createInfo;
	int status;

	/* If the cert has already been instantiated, return it */
	if( trustInfoPtr->iCryptCert != CRYPT_ERROR )
		return( trustInfoPtr->iCryptCert );

	/* Instantiate the cert */
	setMessageCreateObjectInfo( &createInfo, CERTIMPORT_NORMAL );
	createInfo.strArg1 = trustInfoPtr->certObject;
	createInfo.strArgLen1 = trustInfoPtr->certObjectLength;
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR );

	/* The cert was successfully instantiated, free its encoded form */
	zeroise( trustInfoPtr->certObject, trustInfoPtr->certObjectLength );
	free( trustInfoPtr->certObject );
	trustInfoPtr->certObject = NULL;
	trustInfoPtr->certObjectLength = 0;

	return( createInfo.cryptHandle );
	}

/* Initialise and shut down the trust information */

int initTrustInfo( void )
	{
	/* Create any required thread synchronization variables and the trust
	   information table */
	initGlobalResourceLock( trustInfo );
	memset( trustInfoIndex, 0, sizeof( trustInfoIndex ) );

	return( CRYPT_OK );
	}

void endTrustInfo( void )
	{
	int i;

	lockGlobalResource( trustInfo );

	/* Destroy the chain of items at each table position */
	for( i = 0; i < 256; i++ )
		{
		TRUST_INFO *trustInfoPtr = trustInfoIndex[ i ];

		/* Destroy any items in the list */
		while( trustInfoPtr != NULL )
			{
			TRUST_INFO *itemToFree = trustInfoPtr;

			trustInfoPtr = trustInfoPtr->next;
			deleteTrustEntry( itemToFree );
			}
		}
	memset( trustInfoIndex, 0, sizeof( trustInfoIndex ) );

	unlockGlobalResource( trustInfo );
	deleteGlobalResourceLock( trustInfo );
	}

/* Check whether we have trust information present for the issuer of this
   cert.  If there's an entry, return the associated cert */

BOOLEAN checkCertTrusted( const CERT_INFO *certInfoPtr )
	{
	TRUST_INFO *trustInfoPtr;

	/* A non-cert can never be implicitly trusted */
	if( certInfoPtr->type != CRYPT_CERTTYPE_CERTIFICATE )
		return( FALSE );

	/* Check whether the cert is present in the trusted certs collection */
	lockGlobalResource( trustInfo );
	trustInfoPtr = findTrustEntry( certInfoPtr->subjectDNptr, 
								   certInfoPtr->subjectDNsize );

	unlockGlobalResource( trustInfo );

	return( ( trustInfoPtr != NULL ) ? TRUE : FALSE );
	}

CRYPT_CERTIFICATE findTrustedCert( const void *dn, const int dnSize )
	{
	CRYPT_CERTIFICATE iCryptCert;
	TRUST_INFO *trustInfoPtr;

	lockGlobalResource( trustInfo );

	/* If there's no entry present, return an error */
	if( ( trustInfoPtr = findTrustEntry( dn, dnSize ) ) == NULL )
		{
		unlockGlobalResource( trustInfo );
		return( CRYPT_ERROR );
		}

	/* Get the trusted cert from the trust info */
	iCryptCert = getTrustedCert( trustInfoPtr );

	unlockGlobalResource( trustInfo );

	return( iCryptCert );
	}

/* Add trust information for a cert */

int addTrustInfo( const CERT_INFO *certInfoPtr )
	{
	int status;

	lockGlobalResource( trustInfo );

	/* Make sure that trust information for this cert isn't already present */
	if( findTrustEntry( certInfoPtr->subjectDNptr,
						certInfoPtr->subjectDNsize ) != NULL )
		{
		unlockGlobalResource( trustInfo );
		return( CRYPT_ERROR_INITED );
		}

	status = addTrustEntry( certInfoPtr, NULL, 0 );
	unlockGlobalResource( trustInfo );
	return( status );
	}

/* Delete trust information for a cert */

int deleteTrustInfo( const CERT_INFO *certInfoPtr )
	{
	TRUST_INFO *entryToDelete, *trustInfoPtr, *nextEntry;
	const int trustInfoPos = checksumName( certInfoPtr->subjectDNptr,
										   certInfoPtr->subjectDNsize );
	int status = CRYPT_OK;

	lockGlobalResource( trustInfo );

	/* Find the entry to delete */
	entryToDelete = findTrustEntry( certInfoPtr->subjectDNptr,
									certInfoPtr->subjectDNsize );
	if( entryToDelete == NULL )
		{
		unlockGlobalResource( trustInfo );
		return( CRYPT_ERROR_NOTFOUND );
		}

	/* Delete the entry from the list */
	trustInfoPtr = trustInfoIndex[ trustInfoPos ];
	nextEntry = entryToDelete->next;
	if( entryToDelete == trustInfoPtr )
		{
		/* Special case for the start of the list */
		deleteTrustEntry( entryToDelete );
		trustInfoIndex[ trustInfoPos ] = nextEntry;
		}
	else
		{
		/* Find the previous entry in the list and link it to the one which 
		   follows the deleted entry */
		while( trustInfoPtr->next != entryToDelete )
			   trustInfoPtr = trustInfoPtr->next;
		deleteTrustEntry( entryToDelete );
		trustInfoPtr->next = nextEntry;
		}

	unlockGlobalResource( trustInfo );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Read/Write Trusted Certs						*
*																			*
****************************************************************************/

#if 0	/* 13/11/99 Superseded by PKCS #15 trusted certs */

/* Read/write a trust item */

static int readTrustItem( STREAM *stream, int *sCheck, BYTE *sHash,
						  void **pubKeyPtr, int *pubKeySize )
	{
	long value;
	int totalLength, dummy, status;

	/* Read the primitive fields at the start of the trust info */
	readSequence( stream, &totalLength );
	readShortInteger( stream, &value );
	*sCheck = ( int ) value;
	status = readOctetString( stream, sHash, &dummy, 20 );
	if( cryptStatusError( status ) )
		return( status );
		
	/* Decode the information on the public key data */
	*pubKeyPtr = sMemBufPtr( stream );
	status = getObjectLength( *pubKeyPtr, totalLength - \
			( int ) ( sizeofShortInteger( value ) + sizeofObject( 20 ) ) );
	if( cryptStatusError( status ) )
		return( status );
	*pubKeySize = status;

	return( CRYPT_OK );
	}

/* Add a trust item in encoded form */

int setTrustItem( void *itemBuffer, const int itemLength,
				  const BOOLEAN isEncoded )
	{
	BYTE buffer[ CRYPT_MAX_PKCSIZE * 2 ], sHash[ 20 ];
	STREAM stream;
	void *pubKeyPtr;
	int sCheck, length = itemLength, pubKeySize, status;

	/* Decode the data if necessary */
	if( isEncoded )
		{
		length = base64decode( buffer, itemBuffer, itemLength,
							   CRYPT_CERTFORMAT_NONE );
		if( !length )
			return( CRYPT_ERROR_BADDATA );
		}

	/* Read the trust information */
	sMemConnect( &stream, isEncoded ? buffer : itemBuffer, length );
	status = readTrustItem( &stream, &sCheck, sHash, &pubKeyPtr, &pubKeySize );
	sMemDisconnect( &stream );
	if( cryptStatusOK( status ) )
		{
		lockGlobalResource( trustInfo );
		status = addTrustEntry( sCheck, sHash, CRYPT_ERROR, pubKeyPtr,
								pubKeySize );
		unlockGlobalResource( trustInfo );
		}

	return( status );
	}
#endif /* 0 */

/* Enumerate trusted certificates */

static CRYPT_CERTIFICATE getTrustedCertNext( void **statePtr, int *stateIndex )
	{
	TRUST_INFO *trustInfoPtr = ( TRUST_INFO * ) *statePtr;
	int trustInfoPos = *stateIndex;

	do
		{
		/* If there's nothing left in the current chain of entries, move on
		   to the next chain */
		if( trustInfoPtr == NULL && trustInfoPos < 255 )
			trustInfoPtr = trustInfoIndex[ ++trustInfoPos ];

		/* If there's an entry present, return it to the caller */
		if( trustInfoPtr != NULL )
			{
			const CRYPT_CERTIFICATE iCryptCert = \
								getTrustedCert( trustInfoPtr );

			/* Update the state and exit */
			*statePtr = trustInfoPtr->next;
			*stateIndex = trustInfoPos;
			return( iCryptCert );
			}
		}
	while( trustInfoPos < 255 );

	return( CRYPT_ERROR );
	}

CRYPT_CERTIFICATE getFirstTrustedCert( void **statePtr, int *stateIndex )
	{
	CRYPT_CERTIFICATE iCryptCert = CRYPT_ERROR;
	int trustInfoPos;

	/* Clear return value */
	*statePtr = NULL;
	*stateIndex = CRYPT_ERROR;

	lockGlobalResource( trustInfo );
	for( trustInfoPos = 0; trustInfoPos < 256; trustInfoPos++ )
		if( trustInfoIndex[ trustInfoPos ] != NULL )
			{
			/* Remember how far we got */
			*statePtr = trustInfoIndex[ trustInfoPos ];
			*stateIndex = trustInfoPos;

			/* Get the cert from the trust info.  If there's a problem, we
			   try for the next cert (there's not much we can do in terms of
			   error recovery) */
			iCryptCert = getTrustedCertNext( statePtr, stateIndex );
			if( iCryptCert != CRYPT_ERROR )
				break;
			}
	unlockGlobalResource( trustInfo );

	return( iCryptCert );
	}

CRYPT_CERTIFICATE getNextTrustedCert( void **statePtr, int *stateIndex )
	{
	CRYPT_CERTIFICATE iCryptCert;

	lockGlobalResource( trustInfo );
	iCryptCert = getTrustedCertNext( statePtr, stateIndex );
	unlockGlobalResource( trustInfo );

	return( iCryptCert );
	}
