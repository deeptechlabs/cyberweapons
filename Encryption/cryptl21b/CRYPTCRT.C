/****************************************************************************
*																			*
*					cryptlib Certificate Management Routines				*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

/* "By the power vested in me, I now declare this text string and this bit
	string 'name' and 'key'.  What RSA has joined, let no man put asunder".
											-- Bob Blakley */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "asn1.h"
  #include "asn1objs.h"
  #include "cert.h"
#else
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1objs.h"
  #include "keymgmt/cert.h"
#endif /* Compiler-specific includes */

/* The minimum size of a certificate.  This is used by the pointer-check
   macros (for the OS's which support this) to check that the pointers being
   passed to these functions point to the minimal amount of valid memory
   required for an object */

#define MIN_CERTSIZE		256

/* The minimum size for an OBJECT IDENTIFIER expressed as ASCII characters */

#define MIN_ASCII_OIDSIZE	7

/* The maximum size of a certificate attribute.  In theory this can be any
   size, but in practice we limit it to the following maximum to stop people
   including MPEGs of themselves playing with their cat */

#define MAX_ATTRIBUTE_SIZE	1024

/* Prototypes for functions in certext.c */

BOOLEAN isValidField( const CRYPT_CERTINFO_TYPE fieldID,
					  const CRYPT_CERTTYPE_TYPE certType );

/****************************************************************************
*																			*
*						Low-level Certificate Functions						*
*																			*
****************************************************************************/

/* Convert an ASCII OID arc sequence into an encoded OID and back */

static long scanValue( char **string, int *length )
	{
	char *strPtr = *string;
	long retVal = -1;
	int count = *length;

	if( count && isdigit( *strPtr ) )
		{
		retVal = *strPtr++ - '0';
		count--;
		}
	while( count && isdigit( *strPtr ) )
		{
		retVal = ( retVal * 10 ) + ( *strPtr++ - '0' );
		count--;
		}
	while( count && ( *strPtr == ' ' || *strPtr == '.' || *strPtr == '\t' ) )
		{
		strPtr++;
		count--;
		}
	if( count && !isdigit( *strPtr ) )
		retVal = -1;
	*string = strPtr;
	*length = count;
	return( retVal );
	}

int textToOID( const char *oid, const int oidLength, BYTE *binaryOID )
	{
	char *oidPtr = ( char * ) oid;
	long value, val2;
	int length = 3, count = oidLength;

	/* Perform some basic checks and make sure the first two arcs are in
	   order */
	if( oidLength < MIN_ASCII_OIDSIZE || oidLength > CRYPT_MAX_TEXTSIZE )
		return( FALSE );
	while( count && ( *oidPtr == ' ' || *oidPtr == '.' || *oidPtr == '\t' ) )
		{
		oidPtr++;	/* Skip leading whitespace */
		count--;
		}
	value = scanValue( &oidPtr, &count );
	val2 = scanValue( &oidPtr, &count );
	if( value < 0 || value > 2 || val2 < 1 || \
		( ( value < 2 && val2 > 39 ) || ( value == 2 && val2 > 175 ) ) )
		return( 0 );
	binaryOID[ 0 ] = 0x06;	/* OBJECT IDENTIFIER tag */
	binaryOID[ 2 ] = ( BYTE )( ( value * 40 ) + val2 );

	/* Convert the remaining arcs */
	while( count )
		{
		BOOLEAN hasHighBits = FALSE;

		/* Scan the next value and write the high octets (if necessary) with
		   flag bits set, followed by the final octet */
		value = scanValue( &oidPtr, &count );
		if( value < 0 )
			break;
		if( value >= 16384 )
			{
			binaryOID[ length++ ] = ( BYTE ) ( 0x80 | ( value >> 14 ) );
			value %= 16384;
			hasHighBits = TRUE;
			}
		if( ( value > 128 ) || hasHighBits )
			{
			binaryOID[ length++ ] = ( BYTE ) ( 0x80 | ( value >> 7 ) );
			value %= 128;
			}
		binaryOID[ length++ ] = ( BYTE ) value;
		}
	binaryOID[ 1 ] = length - 2;

	return( value == -1 ? 0 : length );
	}

/* Check that an attempt to modify a certificate member is valid for this
   type of certificate object */

typedef enum { UPDATE_READ, UPDATE_WRITE, UPDATE_DELETE } UPDATE_TYPE;

static int isValidMember( const CRYPT_CERTTYPE_TYPE certType,
						  const CRYPT_CERTINFO_TYPE memberType,
						  const CRYPT_CERTINFO_TYPE selectedGeneralName,
						  const CRYPT_CERTINFO_TYPE selectedDN,
						  const UPDATE_TYPE updateType )
	{
	if( memberType <= CRYPT_CERTINFO_NONE || \
		memberType >= CRYPT_CERTINFO_LAST )
		return( CRYPT_BADPARM2 );
	if( isCursorComponent( memberType ) )
		{
		if( memberType == CRYPT_CERTINFO_CURRENT_CERTIFICATE && \
			( certType != CRYPT_CERTTYPE_CERTCHAIN && \
			  certType != CRYPT_CERTTYPE_CRL ) )
			return( CRYPT_BADPARM2 );
		return( CRYPT_OK );
		}
	if( isDNSelectionComponent( memberType ) || \
		isGeneralNameSelectionComponent( memberType ) )
		{
		/* CMS attributes don't have name components */
		if( certType == CRYPT_CERTTYPE_CMS_ATTRIBUTES )
			return( CRYPT_BADPARM2 );

		return( CRYPT_OK );
		}
	if( isGeneralNameComponent( memberType ) || \
		isDNComponent( memberType ) )
		{
		/* CMS attributes don't have name components */
		if( certType == CRYPT_CERTTYPE_CMS_ATTRIBUTES )
			return( CRYPT_BADPARM2 );

		/* Issuer names can't be explicitly written to */
		if( updateType != UPDATE_READ && \
			( selectedGeneralName == CRYPT_CERTINFO_ISSUERALTNAME || \
			  selectedDN == CRYPT_CERTINFO_ISSUERNAME ) )
			return( CRYPT_NOPERM );

		return( CRYPT_OK );
		}
	if( memberType == CRYPT_CERTINFO_IMMUTABLE || \
		memberType == CRYPT_CERTINFO_CERTTYPE )
		return( ( updateType != UPDATE_READ ) ? CRYPT_NOPERM : CRYPT_OK );
	if( memberType == CRYPT_CERTINFO_TRUSTED && \
		( certType == CRYPT_CERTTYPE_CERTIFICATE || \
		  certType == CRYPT_CERTTYPE_CERTCHAIN ) )
		return( CRYPT_OK );
	if( certType == CRYPT_CERTTYPE_CERTIFICATE || \
		certType == CRYPT_CERTTYPE_CERTCHAIN )
		{
		/* Some certificate members are read-only */
		if( updateType != UPDATE_READ && \
			( memberType == CRYPT_CERTINFO_SERIALNUMBER || \
			  memberType == CRYPT_CERTINFO_ISSUERUNIQUEID || \
			  memberType == CRYPT_CERTINFO_SUBJECTUNIQUEID ) )
			return( CRYPT_NOPERM );

		/* Basic members */
		if( memberType == CRYPT_CERTINFO_SERIALNUMBER || \
			memberType == CRYPT_CERTINFO_ISSUERUNIQUEID || \
			memberType == CRYPT_CERTINFO_SUBJECTUNIQUEID || \
			memberType == CRYPT_CERTINFO_VALIDFROM || \
			memberType == CRYPT_CERTINFO_VALIDTO || \
			memberType == CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO || \
			memberType == CRYPT_CERTINFO_CERTREQUEST )
			return( CRYPT_OK );

		/* Adding a full certificate is only valid for certificate chains */
		if( memberType == CRYPT_CERTINFO_CERTIFICATE && \
			certType == CRYPT_CERTTYPE_CERTCHAIN )
			return( CRYPT_OK );

		/* Extensions */
		if( memberType >= CRYPT_FIRST_EXTENSION && \
			isValidField( memberType, CRYPT_CERTTYPE_CERTIFICATE ) )
			return( CRYPT_OK );

		/* Pseudo - information */
		if( memberType == CRYPT_CERTINFO_SELFSIGNED || \
			( ( memberType == CRYPT_CERTINFO_FINGERPRINT_MD5 || \
				memberType == CRYPT_CERTINFO_FINGERPRINT_SHA ) && \
			  updateType == UPDATE_READ ) )
			return( CRYPT_OK );
		}
	if( certType == CRYPT_CERTTYPE_ATTRIBUTE_CERT )
		{
		/* Some certificate members are read-only */
		if( updateType != UPDATE_READ && \
			( memberType == CRYPT_CERTINFO_SERIALNUMBER || \
			  memberType == CRYPT_CERTINFO_ISSUERUNIQUEID ) )
			return( CRYPT_NOPERM );

		/* Basic members */
		if( memberType == CRYPT_CERTINFO_SERIALNUMBER || \
			memberType == CRYPT_CERTINFO_ISSUERUNIQUEID || \
			memberType == CRYPT_CERTINFO_VALIDFROM || \
			memberType == CRYPT_CERTINFO_VALIDTO || \
			memberType == CRYPT_CERTINFO_CERTREQUEST || \
			memberType == CRYPT_CERTINFO_USERCERTIFICATE )
			return( CRYPT_OK );

		/* Extensions */
		if( memberType >= CRYPT_FIRST_EXTENSION && \
			isValidField( memberType, CRYPT_CERTTYPE_ATTRIBUTE_CERT ) )
			return( CRYPT_OK );
		}
	if( certType == CRYPT_CERTTYPE_CRL )
		{
		/* Basic members */
		if( memberType == CRYPT_CERTINFO_THISUPDATE || \
			memberType == CRYPT_CERTINFO_NEXTUPDATE || \
			memberType == CRYPT_CERTINFO_REVOCATIONDATE ||
			memberType == CRYPT_CERTINFO_USERCERTIFICATE )
			return( CRYPT_OK );

		/* Extensions */
		if( memberType >= CRYPT_FIRST_EXTENSION && \
			isValidField( memberType, CRYPT_CERTTYPE_CRL ) )
			return( CRYPT_OK );
		}
	if( certType == CRYPT_CERTTYPE_CERTREQUEST )
		{
		/* Basic members */
		if( memberType == CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO )
			return( CRYPT_OK );

		/* Extensions */
		if( memberType >= CRYPT_FIRST_EXTENSION && \
			isValidField( memberType, CRYPT_CERTTYPE_CERTREQUEST ) )
			return( CRYPT_OK );
		}
	if( certType == CRYPT_CERTTYPE_CMS_ATTRIBUTES )
		{
		/* CMS attribute objects are effectively pure collections of
		   extensions */
		if( memberType >= CRYPT_FIRST_CMS && \
			memberType <= CRYPT_LAST_CMS )
			return( CRYPT_OK );
		}

	return( CRYPT_BADPARM2 );
	}

/****************************************************************************
*																			*
*								Internal API Functions						*
*																			*
****************************************************************************/

/* Certificates and CRL's are usually treated as opaque blobs, however when
   we add them to a keyset we need to extract certain pieces of information
   in order to allow a user to identify the cert or query the CRL in the
   database.  In addition various crypto standards and protocols identify
   certs by a number of peculiar and complex mechanisms such as the subject
   DN or issuer DN and certificate serial number.  A much more practical way
   to work with these is to use a hash of these values.  The following
   function makes both the human-friendly and crypto-standard-related values
   available to other functions */

int unpackCertInfo( const CRYPT_CERTIFICATE certificate, void *C, void *SP,
					void *L, void *O, void *OU, void *CN, void *email,
					time_t *date, void *nameID, void *issuerID, void *keyID,
					void *keyData, int *keyDataLength )
	{
	ICRYPT_QUERY_INFO iCryptQueryInfo;
	SELECTION_STATE selectionState;
	CERT_INFO *certInfoPtr;
	const int dummy = CRYPT_UNUSED;
	int length, status;

	getCheckResource( certificate, certInfoPtr, RESOURCE_TYPE_CERTIFICATE,
					  CRYPT_BADPARM1 );

	/* If it's a CRL, we only export the issuerID */
	if( certInfoPtr->type == CERTTYPE_CRL && nameID == NULL && keyID == NULL )
		{
		CRL_ENTRY *crlEntry = *( ( CRL_ENTRY ** ) keyData );

		/* Select the first or next entry and copy out the ID of the revoked
		   cert */
		if( crlEntry == NULL )
			crlEntry = certInfoPtr->revocations;
		else
			crlEntry = crlEntry->next;
		if( crlEntry != NULL )
			memcpy( issuerID, crlEntry->issuerID, KEYID_SIZE );

		/* Update the callers state information */
		*( ( CRL_ENTRY ** ) keyData ) = crlEntry;

		unlockResourceExit( certInfoPtr, ( crlEntry == NULL ) ? \
							CRYPT_DATA_NOTFOUND : CRYPT_OK );
		}

	/* Make sure it's something which can be written to a keyset */
	if( certInfoPtr->type != CERTTYPE_CERTIFICATE && \
		certInfoPtr->type != CERTTYPE_CERTCHAIN && \
		certInfoPtr->type != CERTTYPE_NS_CERTSEQUENCE )
		unlockResourceExit( certInfoPtr, CRYPT_BADPARM1 );

	/* Lock the currently selected cert in a cert chain if necessary */
	if( certInfoPtr->certChainPos != CRYPT_ERROR )
		{
		CERT_INFO *certChainInfoPtr;

		getCheckInternalResource( certInfoPtr->certChain[ certInfoPtr->certChainPos ],
								  certChainInfoPtr, RESOURCE_TYPE_CERTIFICATE );
		unlockResource( certInfoPtr );
		certInfoPtr = certChainInfoPtr;
		}

	/* Make sure there's a key loaded into the certificate and generate the
	   name and issuer ID's */
	status = iCryptQueryContext( certInfoPtr->iCryptContext,
								 &iCryptQueryInfo );
	if( cryptStatusOK( status ) && nameID != NULL )
		status = generateCertID( certInfoPtr->subjectName, NULL, 0, nameID );
	if( cryptStatusOK( status ) && issuerID != NULL )
		status = generateCertID( certInfoPtr->issuerName, 
				certInfoPtr->serialNumber, certInfoPtr->serialNumberLength, 
				issuerID );
	if( cryptStatusOK( status ) && keyID != NULL )
		memcpy( keyID, iCryptQueryInfo.keyID, KEYID_SIZE );
	memset( &iCryptQueryInfo, 0, sizeof( ICRYPT_QUERY_INFO ) );
	if( cryptStatusError( status ) )
		unlockResourceExit( certInfoPtr, status );

	/* Pull out the email address.  Since this changes the current
	   GeneralName selection, we have to be careful about saving and
	   restoring the state */
	saveSelectionState( selectionState, certInfoPtr );
	addCertComponent( certInfoPtr, CRYPT_CERTINFO_SUBJECTALTNAME,
							   &dummy, 0 );
	status = getCertComponent( certInfoPtr, CRYPT_CERTINFO_RFC822NAME,
							   NULL, &length );
	if( cryptStatusOK( status ) && length < CRYPT_MAX_TEXTSIZE )
		getCertComponent( certInfoPtr, CRYPT_CERTINFO_RFC822NAME, email,
						  &length );
	else
		length = 0;
	( ( BYTE * ) email )[ length ] = '\0';
	restoreSelectionState( selectionState, certInfoPtr );

	/* Retrieve the subject DN and validity information from the
	   certificate */
	status = getCertComponent( certInfoPtr, CRYPT_CERTINFO_COMMONNAME, CN,
							   &length );
	if( status == CRYPT_DATA_NOTFOUND )
		{
		/* Some certs don't have CN components, so we try for the OU instead.
		   If that also fails, we try for the O.  This gets a bit messy, but
		   duplicating the OU/O into the CN seems to be the best way to
		   handle this */
		status = getCertComponent( certInfoPtr,
					CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, CN, &length );
		if( status == CRYPT_DATA_NOTFOUND )
			status = getCertComponent( certInfoPtr,
					CRYPT_CERTINFO_ORGANIZATIONNAME, CN, &length );
		}
	if( cryptStatusOK( status ) )
		{
		( ( BYTE * ) CN )[ length ] = '\0';
		status = getCertComponent( certInfoPtr, CRYPT_CERTINFO_VALIDTO, date,
								   &length );
		}
	if( cryptStatusOK( status ) )
		{
		/* Extract various optional DN components */
		if( cryptStatusError( getCertComponent( certInfoPtr,
						CRYPT_CERTINFO_COUNTRYNAME, C, &length ) ) )
			length = 0;
		( ( BYTE * ) C )[ length ] = '\0';
		if( cryptStatusError( getCertComponent( certInfoPtr,
						CRYPT_CERTINFO_STATEORPROVINCENAME, SP, &length ) ) )
			length = 0;
		( ( BYTE * ) SP )[ length ] = '\0';
		if( cryptStatusError( getCertComponent( certInfoPtr,
						CRYPT_CERTINFO_LOCALITYNAME, L, &length ) ) )
			length = 0;
		( ( BYTE * ) L )[ length ] = '\0';
		if( cryptStatusError( getCertComponent( certInfoPtr,
						CRYPT_CERTINFO_ORGANIZATIONNAME, O, &length ) ) )
			length = 0;
		( ( BYTE * ) O )[ length ] = '\0';
		if( cryptStatusError( getCertComponent( certInfoPtr,
						CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, OU, &length ) ) )
			length = 0;
		( ( BYTE * ) OU )[ length ] = '\0';
		}
	if( cryptStatusError( status ) )
		{
		if( status != CRYPT_BADPARM1 )
			/* Convert any low-level cert-specific error into something which
			   makes sense to the caller */
			status = CRYPT_NOTINITED;
		unlockResourceExit( certInfoPtr, status );
		}

	/* Finally, retrieve the certificate itself and add it to the database */
	status = exportCert( keyData, keyDataLength, CRYPT_CERTFORMAT_CERTIFICATE,
						 certInfoPtr );

	unlockResourceExit( certInfoPtr, status );
	}

/****************************************************************************
*																			*
*					Internal Certificate Management Functions				*
*																			*
****************************************************************************/

/* Create a certificate */

int iCryptCreateCert( CRYPT_CERTIFICATE *iCertificate,
					  const CRYPT_CERTTYPE_TYPE certType )
	{
	int createCertificate( CERT_INFO **certInfoPtr, const int objectFlags );
	CERT_INFO *certInfoPtr;
	int certHandle;

	*iCertificate = CRYPT_ERROR;

	/* Create the internal certificate context */
	certHandle = createCertificate( &certInfoPtr, RESOURCE_FLAG_INTERNAL );
	if( cryptStatusError( certHandle ) )
		return( certHandle );
	certInfoPtr->type = certType;
	*iCertificate = certHandle;

	unlockResourceExit( certInfoPtr, CRYPT_OK );
	}

/* Import a certificate blob.  If iCryptContext is non-null, this will create
   a data-only cert and a context to hold the public key components.  Returns
   the length of the certificate */

int iCryptImportCert( const void *certObject, CRYPT_CERTIFICATE *iCertificate,
					  CRYPT_CONTEXT *iCryptContext )
	{
	/* Pass the call straight through to the low-level import function */
	return( importCert( certObject, iCertificate, iCryptContext, TRUE ) );
	}

/* Export a certificate object containing a pre-encoded certificate */

int iCryptExportCert( void *certObject, int *certObjectLength,
					  const CRYPT_CERTIFICATE iCertificate )
	{
	CERT_INFO *certInfoPtr;
	int status = CRYPT_OK;

	getCheckInternalResource( iCertificate, certInfoPtr, RESOURCE_TYPE_CERTIFICATE );
	if( certInfoPtr->type == CRYPT_CERTTYPE_CMS_ATTRIBUTES )
		{
		STREAM stream;

		/* CMS attributes aren't signed objects like other cert.objects so
		   they aren't pre-encoded when we sign them (they also have the
		   potential to change on each use if the same CMS attributes are
		   reused for multiple signatures).  Because of this we write them
		   out on export rather than copying the pre-encoded form from an
		   internal buffer */
		sMemOpen( &stream, certObject, STREAMSIZE_UNKNOWN );
		status = writeCMSAttributes( &stream, certInfoPtr );
		*certObjectLength = sMemSize( &stream );
		sMemDisconnect( &stream );
		}
	else
		/* Cert chains aren't pre-encoded but are written on the fly from a
		   collection of certificates */
		if( certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN )
			status = exportCert( certObject, certObjectLength,
								 CRYPT_CERTFORMAT_CERTCHAIN, certInfoPtr );
		else
			{
			/* It's a pre-encoded signed object, just copy it to the output */
			*certObjectLength = certInfoPtr->certificateSize;
			if( certObject != NULL )
				memcpy( certObject, certInfoPtr->certificate, *certObjectLength );
			}
	unlockResourceExit( certInfoPtr, status );
	}

/* Get/add/delete a certificate component */

int iCryptGetCertComponent( const CRYPT_CERTIFICATE iCertificate,
							const CRYPT_CERTINFO_TYPE certInfoType,
							void *certInfo, int *certInfoLength )
	{
	CERT_INFO *certInfoPtr;
	int status;

	getCheckInternalResource( iCertificate, certInfoPtr, RESOURCE_TYPE_CERTIFICATE );
	status = getCertComponent( certInfoPtr, certInfoType, certInfo,
							   certInfoLength );
	unlockResourceExit( certInfoPtr, status );
	}

int iCryptAddCertComponent( const CRYPT_CERTIFICATE iCertificate,
							const CRYPT_CERTINFO_TYPE certInfoType,
							const void *certInfo, const int certInfoLength )
	{
	CERT_INFO *certInfoPtr;
	int status;

	getCheckInternalResource( iCertificate, certInfoPtr, RESOURCE_TYPE_CERTIFICATE );
	status = addCertComponent( certInfoPtr, certInfoType, certInfo,
							   certInfoLength );
	unlockResourceExit( certInfoPtr, status );
	}

int iCryptDeleteCertComponent( const CRYPT_CERTIFICATE iCertificate,
							   const CRYPT_CERTINFO_TYPE certInfoType )
	{
	CERT_INFO *certInfoPtr;
	int status;

	getCheckInternalResource( iCertificate, certInfoPtr, RESOURCE_TYPE_CERTIFICATE );
	status = deleteCertComponent( certInfoPtr, certInfoType );
	unlockResourceExit( certInfoPtr, status );
	}

/****************************************************************************
*																			*
*						Certificate Management API Functions				*
*																			*
****************************************************************************/

/* Handle a message sent to a certificate context */

static int certificateMessageFunction( const CRYPT_CERTIFICATE certificate,
									   const RESOURCE_MESSAGE_TYPE message,
									   void *messageDataPtr,
									   const int messageValue,
									   const int errorCode )
	{
	CERT_INFO *certInfoPtr;
	int status = errorCode;

	getCheckInternalResource( certificate, certInfoPtr, RESOURCE_TYPE_CERTIFICATE );

	/* Process destroy object messages */
	if( message == RESOURCE_MESSAGE_DESTROY )
		{
		/* Clear the encoded certificate and miscellaneous components if
		   necessary */
		if( certInfoPtr->certificate != NULL )
			{
			zeroise( certInfoPtr->certificate, certInfoPtr->certificateSize );
			free( certInfoPtr->certificate );
			}
		if( certInfoPtr->serialNumber != NULL )
			free( certInfoPtr->serialNumber );
		if( certInfoPtr->issuerUniqueID != NULL )
			free( certInfoPtr->issuerUniqueID );
		if( certInfoPtr->subjectUniqueID != NULL )
			free( certInfoPtr->subjectUniqueID );

		/* Clear the DN's if necessary */
		if( certInfoPtr->issuerName != NULL )
			deleteDN( &certInfoPtr->issuerName );
		if( certInfoPtr->subjectName != NULL )
			deleteDN( &certInfoPtr->subjectName );

		/* Clear the attributes and CRL's if necessary */
		if( certInfoPtr->attributes != NULL )
			deleteAttributes( &certInfoPtr->attributes );
		if( certInfoPtr->revocations != NULL )
			deleteCRLEntries( &certInfoPtr->revocations );

		/* Clear the cert chain if necessary */
		if( certInfoPtr->certChainEnd )
			{
			int i;

			for( i = 0; i < certInfoPtr->certChainEnd; i++ )
				krnlSendNotifier( certInfoPtr->certChain[ i ],
								  RESOURCE_IMESSAGE_DECREFCOUNT );
			}

		/* Clear the encryption context containing the key for this
		   certificate */
		if( certInfoPtr->iCryptContext != CRYPT_ERROR )
			krnlSendNotifier( certInfoPtr->iCryptContext,
							  RESOURCE_IMESSAGE_DECREFCOUNT );

		/* We've finished deleting the objects data, mark it as partially
		   destroyed, which ensures that any further attempts to access it
		   fail.  This avoids a race condition where other threads may try
		   to use the partially-destroyed object after we unlock it but
		   before we finish destroying it, note that we set the urgent flag
		   to ensure that the status change is processed immediately rather
		   than being queued until after the current (destroy) message has
		   been processed */
		status = CRYPT_SIGNALLED;
		krnlSendMessage( certificate,
						 RESOURCE_MESSAGE_SETPROPERTY | RESOURCE_MESSAGE_URGENT,
						 &status, RESOURCE_MESSAGE_PROPERTY_STATUS, 0 );

		/* Delete the objects locking variables and the object itself */
		unlockResource( certInfoPtr );
		deleteResourceLock( certInfoPtr );
		zeroise( certInfoPtr, sizeof( CERT_INFO ) );
		free( certInfoPtr );

		return( CRYPT_OK );
		}

	/* Process the increment/decrement object reference count message */
	if( message == RESOURCE_MESSAGE_INCREFCOUNT )
		{
		/* Increment the objects reference count */
		certInfoPtr->refCount++;

		status = CRYPT_OK;
		}
	if( message == RESOURCE_MESSAGE_DECREFCOUNT )
		{
		/* If we're already at a single reference, destroy the object */
		if( !certInfoPtr->refCount )
			krnlSendNotifier( certificate, RESOURCE_IMESSAGE_DESTROY );
		else
			/* Decrement the objects reference count */
			certInfoPtr->refCount--;

		status = CRYPT_OK;
		}

	/* Process messages which get data from the object */
	if( message == RESOURCE_MESSAGE_GETDATA )
		{
		RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
		RESOURCE_DATA_EX *msgDataEx = ( RESOURCE_DATA_EX * ) messageDataPtr;
		STREAM stream;

		status = CRYPT_OK;

		switch( messageValue )
			{
			case RESOURCE_MESSAGE_DATA_CONTEXT:
				if( certInfoPtr->iCryptContext != CRYPT_ERROR )
					*( ( int * ) messageDataPtr ) = certInfoPtr->iCryptContext;
				else
					status = errorCode;
				break;

			case RESOURCE_MESSAGE_DATA_CERTIFICATE:
				*( ( int * ) messageDataPtr ) = certificate;
				break;

			case RESOURCE_MESSAGE_DATA_ISSUERANDSERIALNUMBER:
				msgData->length = ( int ) \
						sizeofObject( certInfoPtr->issuerDNsize + \
									  sizeofStaticInteger( \
											certInfoPtr->serialNumber,
											certInfoPtr->serialNumberLength ) );
				if( msgData->data != NULL )
					{
					sMemConnect( &stream, msgData->data, STREAMSIZE_UNKNOWN );
					writeSequence( &stream, certInfoPtr->issuerDNsize +
								   sizeofStaticInteger( certInfoPtr->serialNumber,
											certInfoPtr->serialNumberLength ) );
					swrite( &stream, certInfoPtr->issuerDNptr,
							certInfoPtr->issuerDNsize );
					writeStaticInteger( &stream, certInfoPtr->serialNumber,
								certInfoPtr->serialNumberLength, DEFAULT_TAG );
					sMemDisconnect( &stream );
					}
				break;

			case RESOURCE_MESSAGE_DATA_CERTSET:
				msgData->length = ( int ) sizeofCertSet( certInfoPtr );
				if( msgData->data != NULL )
					{
					sMemConnect( &stream, msgData->data, STREAMSIZE_UNKNOWN );
					writeCertSet( &stream, certInfoPtr );
					sMemDisconnect( &stream );
					}
				break;

			case RESOURCE_MESSAGE_DATA_ERRORINFO:
				/* If it's a cert chain, lock the currently selected cert */
				if( certInfoPtr->certChainPos != CRYPT_ERROR )
					{
					CERT_INFO *certChainInfoPtr;

					getCheckInternalResource( \
							certInfoPtr->certChain[ certInfoPtr->certChainPos ],
							certChainInfoPtr, RESOURCE_TYPE_CERTIFICATE );
					if( certChainInfoPtr->errorType == CRYPT_CERTERROR_NONE )
						{
						/* There's no error information set in the currently
						   selected cert in the chain, the error must be a
						   general one set in the leaf cert (eg "Missing cert
						   in chain") */
						unlockResource( certInfoPtr );
						}
					else
						{
						unlockResource( certInfoPtr );
						certInfoPtr = certChainInfoPtr;
						}
					}

				/* Return information on the error */
				msgDataEx->length1 = certInfoPtr->errorType;
				msgDataEx->length2 = certInfoPtr->errorLocus;
				break;

			default:
				status = errorCode;
			}

		if( cryptStatusError( status ) )
			*( ( int * ) messageDataPtr ) = CRYPT_ERROR;
		}

	/* Process messages which compare or clone the object */
	if( message == RESOURCE_MESSAGE_COMPARE )
		{
		CERT_INFO *certInfoPtr2;
		STREAM stream;
		BYTE *dataStart;
		long dataLength;
		int length;

		status = errorCode;

		switch( messageValue )
			{
			case RESOURCE_MESSAGE_COMPARE_OBJECT:
				getCheckInternalResource( *( ( CRYPT_CERTIFICATE * ) messageDataPtr ),
								certInfoPtr2, RESOURCE_TYPE_CERTIFICATE );
				if( certInfoPtr->certificate == NULL || \
					certInfoPtr2->certificate == NULL )
					/* If the cert objects haven't been signed yet, we can't
					   compare them */
					status = CRYPT_NOTINITED;
				else
					/* Compare the encoded certificate data */
					status = ( certInfoPtr->certificateSize == \
										certInfoPtr2->certificateSize && \
							   !memcmp( certInfoPtr->certificate, certInfoPtr2->certificate,
										certInfoPtr->certificateSize ) ) ? \
							 CRYPT_OK : CRYPT_ERROR;
				unlockResource( certInfoPtr2 );
				break;

			case RESOURCE_MESSAGE_COMPARE_ISSUERANDSERIALNUMBER:
				status = CRYPT_OK;

				/* Compare the issuerName */
				sMemConnect( &stream, messageDataPtr, STREAMSIZE_UNKNOWN );
				readSequence( &stream, &length );
				dataStart = sMemBufPtr( &stream );
				readTag( &stream );
				length = readLength( &stream, &dataLength );
				sSkip( &stream, dataLength );
				dataLength += 1 + length;	/* Add length of tag+length */
				if( dataLength != certInfoPtr->issuerDNsize || \
					memcmp( dataStart, certInfoPtr->issuerDNptr,
							certInfoPtr->issuerDNsize ) )
					{
					sMemDisconnect( &stream );
					status = CRYPT_ERROR;
					break;
					}

				/* Compare the serialNumber.  This one can get a bit tricky
				   because Microsoft fairly consistently encode the serial
				   numbers incorrectly, so we normalise the values to have no
				   leading zero which is the lowest common denominator */
				readTag( &stream );
				readLength( &stream, &dataLength );
				dataStart = sMemBufPtr( &stream );
				sMemDisconnect( &stream );
				if( !*dataStart )
					{ dataStart++; dataLength--; }	/* Skip leading zero */
				if( dataLength != certInfoPtr->serialNumberLength || \
					memcmp( dataStart, certInfoPtr->serialNumber,
							certInfoPtr->serialNumberLength ) )
					status = CRYPT_ERROR;
				break;
			}
		}

	/* Process messages which check a certificate */
	if( message == RESOURCE_MESSAGE_CHECK )
		{
		const int certCheckValue = \
			( messageValue == RESOURCE_MESSAGE_CHECK_PKC_ENCRYPT || \
              messageValue == RESOURCE_MESSAGE_CHECK_PKC_DECRYPT ) ? \
				CRYPT_KEYUSAGE_KEYENCIPHERMENT : \
			( messageValue == RESOURCE_MESSAGE_CHECK_PKC_SIGN || \
              messageValue == RESOURCE_MESSAGE_CHECK_PKC_SIGCHECK ) ? \
				( CRYPT_KEYUSAGE_DIGITALSIGNATURE | \
				  CRYPT_KEYUSAGE_NONREPUDIATION | \
				  CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN ) : \
				CRYPT_KEYUSAGE_KEYAGREEMENT;

		/* First we check the cert itself.  If this is OK and there's a
		   context attached, we pass the call down to the attached context */
		status = checkCertUsage( certInfoPtr, certCheckValue,
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );
		if( cryptStatusOK( status ) && certInfoPtr->iCryptContext != CRYPT_ERROR )
			status = krnlSendMessage( certInfoPtr->iCryptContext,
							RESOURCE_IMESSAGE_CHECK, NULL, messageValue,
							errorCode );
		}

	/* Process messages which lock/unlock an object for exclusive use */
	if( message == RESOURCE_MESSAGE_LOCK )
		/* Exit without unlocking the object.  Any other threads trying to
		   use the object after this point will be blocked */
		return( CRYPT_OK );
	if( message == RESOURCE_MESSAGE_UNLOCK )
		{
		/* "Wenn drei Leute in ein Zimmer reingehen und fuenf kommen raus,
			dann muessen erst mal zwei wieder reingehen bis das Zimmer lehr
			ist" */
		unlockResource( certInfoPtr );	/* Undo RESOURCE_MESSAGE_LOCK lock */
		status = CRYPT_OK;
		}

	unlockResourceExit( certInfoPtr, status );
	}

/* Create a certificate context */

int createCertificate( CERT_INFO **certInfoPtr, const int objectFlags )
	{
	CRYPT_CERTIFICATE certificate;

	/* Create the certificate context */
	krnlCreateObject( certificate, *certInfoPtr, RESOURCE_TYPE_CERTIFICATE,
					  sizeof( CERT_INFO ), objectFlags,
					  certificateMessageFunction );
	if( cryptStatusError( certificate ) )
		return( certificate );

	/* Set up any internal objects to contain invalid handles */
	( *certInfoPtr )->iCryptContext = CRYPT_ERROR;

	/* Set the state information to its initial state */
	( *certInfoPtr )->certChainPos = CRYPT_ERROR;

	return( certificate );
	}

/* Create/destroy a certificate */

CRET cryptCreateCert( CRYPT_CERTIFICATE CPTR certificate,
					  const CRYPT_CERTTYPE_TYPE certType )
	{
	CERT_INFO *certInfoPtr;
	int certHandle;

	/* Perform basic error checking */
	if( checkBadPtrWrite( certificate, sizeof( CRYPT_CERTIFICATE ) ) )
		return( CRYPT_BADPARM1 );
	*certificate = CRYPT_ERROR;
	if( certType <= CRYPT_CERTTYPE_NONE || certType >= CRYPT_CERTTYPE_LAST )
		return( CRYPT_BADPARM2 );

	/* Create the certificate context */
	certHandle = createCertificate( &certInfoPtr, 0 );
	if( cryptStatusError( certHandle ) )
		return( certHandle );
	certInfoPtr->type = certType;
	*certificate = certHandle;

	unlockResourceExit( certInfoPtr, CRYPT_OK );
	}

CRET cryptDestroyCert( const CRYPT_CERTIFICATE certificate )
	{
	return( cryptDestroyObject( certificate ) );
	}

/* Get/add/delete certificate components */

CRET cryptGetCertComponentNumeric( const CRYPT_HANDLE cryptHandle,
								   const CRYPT_CERTINFO_TYPE certInfoType,
								   int CPTR certInfo )
	{
	CRYPT_CERTIFICATE certificate;
	CERT_INFO *certInfoPtr;
	int status;

	/* Perform basic error checking */
	status = krnlSendMessage( cryptHandle, RESOURCE_MESSAGE_GETDATA,
							  &certificate, RESOURCE_MESSAGE_DATA_CERTIFICATE,
							  CRYPT_BADPARM1 );
	if( cryptStatusError( status ) )
		return( status );
	getCheckInternalResource( certificate, certInfoPtr, RESOURCE_TYPE_CERTIFICATE );
	status = isValidMember( certInfoPtr->type, certInfoType,
							certInfoPtr->currentGeneralName,
							certInfoPtr->currentDN, UPDATE_READ );
	if( cryptStatusError( status ) )
		unlockResourceExit( certInfoPtr, CRYPT_BADPARM2 );
	if( checkBadPtrWrite( certInfo, sizeof( int ) ) )
		unlockResourceExit( certInfoPtr, CRYPT_BADPARM4 );
	*certInfo = CRYPT_ERROR;

	/* Lock the currently selected cert in a cert chain if necessary */
	if( certInfoPtr->certChainPos != CRYPT_ERROR )
		{
		CERT_INFO *certChainInfoPtr;

		getCheckInternalResource( certInfoPtr->certChain[ certInfoPtr->certChainPos ],
								  certChainInfoPtr, RESOURCE_TYPE_CERTIFICATE );
		unlockResource( certInfoPtr );
		certInfoPtr = certChainInfoPtr;
		}

	status = getCertComponent( certInfoPtr, certInfoType, certInfo, NULL );
	unlockResourceExit( certInfoPtr, status );
	}

CRET cryptGetCertComponentString( const CRYPT_HANDLE cryptHandle,
								  const CRYPT_CERTINFO_TYPE certInfoType,
								  void CPTR certInfo, int CPTR certInfoLength )
	{
	CRYPT_CERTIFICATE certificate;
	CERT_INFO *certInfoPtr;
	int status;

	/* Perform basic error checking */
	status = krnlSendMessage( cryptHandle, RESOURCE_MESSAGE_GETDATA,
							  &certificate, RESOURCE_MESSAGE_DATA_CERTIFICATE,
							  CRYPT_BADPARM1 );
	if( cryptStatusError( status ) )
		return( status );
	getCheckInternalResource( certificate, certInfoPtr, RESOURCE_TYPE_CERTIFICATE );
	status = isValidMember( certInfoPtr->type, certInfoType,
							certInfoPtr->currentGeneralName,
							certInfoPtr->currentDN, UPDATE_READ );
	if( cryptStatusError( status ) )
		unlockResourceExit( certInfoPtr, CRYPT_BADPARM2 );
	if( certInfo != NULL )
		*( ( BYTE * ) certInfo ) = '\0';
	if( checkBadPtrWrite( certInfoLength, sizeof( int ) ) )
		unlockResourceExit( certInfoPtr, CRYPT_BADPARM4 );
	*certInfoLength = CRYPT_ERROR;

	/* Lock the currently selected cert in a cert chain if necessary */
	if( certInfoPtr->certChainPos != CRYPT_ERROR )
		{
		CERT_INFO *certChainInfoPtr;

		getCheckInternalResource( certInfoPtr->certChain[ certInfoPtr->certChainPos ],
								  certChainInfoPtr, RESOURCE_TYPE_CERTIFICATE );
		unlockResource( certInfoPtr );
		certInfoPtr = certChainInfoPtr;
		}

	status = getCertComponent( certInfoPtr, certInfoType, certInfo,
							   certInfoLength );
	unlockResourceExit( certInfoPtr, status );
	}

CRET cryptAddCertComponentNumeric( const CRYPT_HANDLE cryptHandle,
								   const CRYPT_CERTINFO_TYPE certInfoType,
								   const int certInfo )
	{
	CRYPT_CERTIFICATE certificate;
	CERT_INFO *certInfoPtr;
	BOOLEAN validCursorPosition;
	int status;

	/* Perform basic error checking */
	status = krnlSendMessage( cryptHandle, RESOURCE_MESSAGE_GETDATA,
							  &certificate, RESOURCE_MESSAGE_DATA_CERTIFICATE,
							  CRYPT_BADPARM1 );
	if( cryptStatusError( status ) )
		return( status );
	getCheckInternalResource( certificate, certInfoPtr, RESOURCE_TYPE_CERTIFICATE );
	if( ( certInfoPtr->certificate != NULL || \
		  certInfoPtr->certChainPos != CRYPT_ERROR ) && \
		!isDNSelectionComponent( certInfoType ) && \
		!isGeneralNameSelectionComponent( certInfoType ) && \
		!isCursorComponent( certInfoType ) && \
		!isControlComponent( certInfoType ) )
		unlockResourceExit( certInfoPtr, CRYPT_INITED );
	status = isValidMember( certInfoPtr->type, certInfoType,
							certInfoPtr->currentGeneralName,
							certInfoPtr->currentDN, UPDATE_WRITE );
	if( cryptStatusError( status ) )
		unlockResourceExit( certInfoPtr, CRYPT_BADPARM2 );
	validCursorPosition = \
		( certInfoPtr->type == CRYPT_CERTTYPE_CMS_ATTRIBUTES ) ? \
		certInfoType >= CRYPT_FIRST_CMS && certInfoType <= CRYPT_LAST_CMS : \
		certInfoType >= CRYPT_FIRST_EXTENSION && certInfoType <= CRYPT_LAST_EXTENSION;
	if( certInfo < 0 && certInfo != CRYPT_UNUSED && \
		( certInfo > CRYPT_CURSOR_FIRST || certInfo < CRYPT_CURSOR_LAST ) &&
		!validCursorPosition && certInfoType != CRYPT_CERTINFO_SELFSIGNED )
		unlockResourceExit( certInfoPtr, CRYPT_BADPARM3 );

	/* Lock the currently selected cert in a cert chain if necessary */
	if( certInfoPtr->certChainPos != CRYPT_ERROR && \
		certInfoType != CRYPT_CERTINFO_CURRENT_CERTIFICATE )
		{
		CERT_INFO *certChainInfoPtr;

		getCheckInternalResource( certInfoPtr->certChain[ certInfoPtr->certChainPos ],
								  certChainInfoPtr, RESOURCE_TYPE_CERTIFICATE );
		unlockResource( certInfoPtr );
		certInfoPtr = certChainInfoPtr;
		}

	status = addCertComponent( certInfoPtr, certInfoType, &certInfo,
							   CRYPT_UNUSED );
	unlockResourceExit( certInfoPtr, status );
	}

CRET cryptAddCertComponentString( const CRYPT_CERTIFICATE certificate,
								  const CRYPT_CERTINFO_TYPE certInfoType,
								  const void CPTR certInfo,
								  const int certInfoLength )
	{
	CERT_INFO *certInfoPtr;
	int status;

	/* Perform basic error checking */
	getCheckResource( certificate, certInfoPtr, RESOURCE_TYPE_CERTIFICATE,
					  CRYPT_BADPARM1 );
	if( certInfoPtr->certificate != NULL || \
		certInfoPtr->certChainPos != CRYPT_ERROR )
		unlockResourceExit( certInfoPtr, CRYPT_INITED );
	status = isValidMember( certInfoPtr->type, certInfoType,
							certInfoPtr->currentGeneralName,
							certInfoPtr->currentDN, UPDATE_WRITE );
	if( cryptStatusError( status ) )
		unlockResourceExit( certInfoPtr, CRYPT_BADPARM2 );
	if( certInfoLength < 2 || certInfoLength > MAX_ATTRIBUTE_SIZE )
		unlockResourceExit( certInfoPtr, CRYPT_BADPARM4 );
	if( checkBadPtrRead( certInfo, certInfoLength ) )
		unlockResourceExit( certInfoPtr, CRYPT_BADPARM3 );

	status = addCertComponent( certInfoPtr, certInfoType, certInfo,
							   certInfoLength );
	unlockResourceExit( certInfoPtr, status );
	}

CRET cryptDeleteCertComponent( const CRYPT_CERTIFICATE certificate,
							   const CRYPT_CERTINFO_TYPE certInfoType )
	{
	CERT_INFO *certInfoPtr;
	int status;

	/* Perform basic error checking */
	getCheckResource( certificate, certInfoPtr, RESOURCE_TYPE_CERTIFICATE,
					  CRYPT_BADPARM1 );
	if( certInfoPtr->certificate != NULL || \
		certInfoPtr->certChainPos != CRYPT_ERROR )
		unlockResourceExit( certInfoPtr, CRYPT_NOPERM );
	status = isValidMember( certInfoPtr->type, certInfoType,
							certInfoPtr->currentGeneralName,
							certInfoPtr->currentDN, UPDATE_DELETE );
	if( cryptStatusError( status ) )
		unlockResourceExit( certInfoPtr, CRYPT_BADPARM2 );

	status = deleteCertComponent( certInfoPtr, certInfoType );
	unlockResourceExit( certInfoPtr, status );
	}

/* Get/add/delete certificate attributes */

CRET cryptGetCertExtension( const CRYPT_HANDLE cryptHandle,
							const char CPTR oid, int CPTR criticalFlag,
							void CPTR extension, int CPTR extensionLength )
	{
	CRYPT_CERTIFICATE certificate;
	CERT_INFO *certInfoPtr;
	ATTRIBUTE_LIST *attributeListPtr;
	BYTE binaryOID[ CRYPT_MAX_TEXTSIZE ];
	BOOLEAN returnData = ( extension != NULL ) ? TRUE : FALSE;
	int status;

	/* Perform basic error checking */
	status = krnlSendMessage( cryptHandle, RESOURCE_MESSAGE_GETDATA,
							  &certificate, RESOURCE_MESSAGE_DATA_CERTIFICATE,
							  CRYPT_BADPARM1 );
	if( cryptStatusError( status ) )
		return( status );
	getCheckInternalResource( certificate, certInfoPtr, RESOURCE_TYPE_CERTIFICATE );
	if( checkBadPtrRead( oid, MIN_ASCII_OIDSIZE ) )
		unlockResourceExit( certInfoPtr, CRYPT_BADPARM2 );
	if( checkBadPtrWrite( criticalFlag, sizeof( int ) ) )
		unlockResourceExit( certInfoPtr, CRYPT_BADPARM3 );
	*criticalFlag = CRYPT_ERROR;
	if( extension != NULL )
		*( ( BYTE * ) extension ) = 0;
	if( checkBadPtrWrite( extensionLength, sizeof( int ) ) )
		unlockResourceExit( certInfoPtr, CRYPT_BADPARM5 );
	*extensionLength = CRYPT_ERROR;

	/* Lock the currently selected cert in a cert chain if necessary */
	if( certInfoPtr->certChainPos != CRYPT_ERROR )
		{
		CERT_INFO *certChainInfoPtr;

		getCheckInternalResource( certInfoPtr->certChain[ certInfoPtr->certChainPos ],
								  certChainInfoPtr, RESOURCE_TYPE_CERTIFICATE );
		unlockResource( certInfoPtr );
		certInfoPtr = certChainInfoPtr;
		}

	/* Convert the OID to its binary form and try and locate the attribute
	   identified by the OID */
	if( !textToOID( oid, strlen( oid ), binaryOID ) )
		unlockResourceExit( certInfoPtr, CRYPT_BADPARM2 );
	attributeListPtr = findAttributeByOID( certInfoPtr->attributes, binaryOID );
	if( attributeListPtr == NULL )
		unlockResourceExit( certInfoPtr, CRYPT_DATA_NOTFOUND );
	*criticalFlag = attributeListPtr->isCritical;
	*extensionLength = attributeListPtr->dataLength;
	if( returnData )
		{
		const void *dataPtr = ( attributeListPtr->dataLength <= CRYPT_MAX_TEXTSIZE ) ? \
							  attributeListPtr->smallData : attributeListPtr->data;

		if( checkBadPtrWrite( extension, attributeListPtr->dataLength ) )
			unlockResourceExit( certInfoPtr, CRYPT_BADPARM3 );
		memcpy( extension, dataPtr, attributeListPtr->dataLength );
		}
	unlockResourceExit( certInfoPtr, CRYPT_OK );
	}

CRET cryptAddCertExtension( const CRYPT_CERTIFICATE certificate,
							const char CPTR oid, const int criticalFlag,
							const void CPTR extension,
							const int extensionLength )
	{
	CERT_INFO *certInfoPtr;
	BYTE binaryOID[ CRYPT_MAX_TEXTSIZE ];
	int status;

	/* Perform basic error checking */
	getCheckResource( certificate, certInfoPtr, RESOURCE_TYPE_CERTIFICATE,
					  CRYPT_BADPARM1 );
	if( certInfoPtr->certificate != NULL || \
		certInfoPtr->certChainPos != CRYPT_ERROR )
		unlockResourceExit( certInfoPtr, CRYPT_NOPERM );
	if( checkBadPtrRead( oid, MIN_ASCII_OIDSIZE ) )
		unlockResourceExit( certInfoPtr, CRYPT_BADPARM2 );
	if( certInfoPtr->type == CRYPT_CERTTYPE_CMS_ATTRIBUTES && \
		criticalFlag != CRYPT_UNUSED )
		unlockResourceExit( certInfoPtr, CRYPT_BADPARM3 );
	if( extensionLength <= 3 || extensionLength > MAX_ATTRIBUTE_SIZE )
		unlockResourceExit( certInfoPtr, CRYPT_BADPARM4 );
	if( checkBadPtrRead( extension, extensionLength ) )
		unlockResourceExit( certInfoPtr, CRYPT_BADPARM5 );

	/* Convert the OID to its binary form, copy the data to an internal
	   buffer, and add the attribute to the certificate */
	if( !textToOID( oid, strlen( oid ), binaryOID ) )
		unlockResourceExit( certInfoPtr, CRYPT_BADPARM2 );
	status = addAttribute( ( certInfoPtr->type == CRYPT_CERTTYPE_CMS_ATTRIBUTES ) ? \
		ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE, &certInfoPtr->attributes,
		binaryOID, ( BOOLEAN )	/* Fix for VC++ */
		( ( certInfoPtr->type == CRYPT_CERTTYPE_CMS_ATTRIBUTES ) ? FALSE : \
		  criticalFlag ), extension, extensionLength );
	if( status == CRYPT_INITED )
		/* If the attribute is already present, set error information for it.
		   We can't set an error locus since it's an unknown blob */
		setCertError( certInfoPtr, CRYPT_CERTINFO_NONE,
					  CRYPT_CERTERROR_PRESENT );
	unlockResourceExit( certInfoPtr, status );
	}

CRET cryptDeleteCertExtension( const CRYPT_CERTIFICATE certificate,
							   const char CPTR oid )
	{
	CERT_INFO *certInfoPtr;
	ATTRIBUTE_LIST *attributeListPtr;
	BYTE binaryOID[ CRYPT_MAX_TEXTSIZE ];

	/* Perform basic error checking */
	getCheckResource( certificate, certInfoPtr, RESOURCE_TYPE_CERTIFICATE,
					  CRYPT_BADPARM1 );
	if( certInfoPtr->certificate != NULL || \
		certInfoPtr->certChainPos != CRYPT_ERROR )
		unlockResourceExit( certInfoPtr, CRYPT_NOPERM );
	if( checkBadPtrRead( oid, MIN_ASCII_OIDSIZE ) )
		unlockResourceExit( certInfoPtr, CRYPT_BADPARM2 );

	/* Convert the OID to its binary form, find the attribute identified by
	   this OID, and delete it */
	if( !textToOID( oid, strlen( oid ), binaryOID ) )
		unlockResourceExit( certInfoPtr, CRYPT_BADPARM2 );
	attributeListPtr = findAttributeByOID( certInfoPtr->attributes, binaryOID );
	if( attributeListPtr == NULL )
		unlockResourceExit( certInfoPtr, CRYPT_DATA_NOTFOUND );
	deleteAttribute( &certInfoPtr->attributes, NULL, attributeListPtr );
	unlockResourceExit( certInfoPtr, CRYPT_OK );
	}

/* Sign a certificate object.  The possibilities are as follows:

						Signer
	Type  |		Cert				Chain
	------+--------------------+---------------
	Cert  | Cert			   | Cert
		  |					   |
	Chain | Chain, length = 2  | Chain, length = n+1 */

CRET cryptSignCert( const CRYPT_CERTIFICATE certificate,
					const CRYPT_CONTEXT signContext )
	{
	CERT_INFO *certInfoPtr;
	int status;

	/* Perform basic error checking */
	getCheckResource( certificate, certInfoPtr, RESOURCE_TYPE_CERTIFICATE,
					  CRYPT_BADPARM1 );
	if( certInfoPtr->certificate != NULL )
		unlockResourceExit( certInfoPtr, CRYPT_NOPERM );
	if( certInfoPtr->type == CERTTYPE_CMS_ATTRIBUTES || \
		certInfoPtr->type == CERTTYPE_NS_SPKAC )
		/* CMS attributes aren't certs and can't be explicitly signed, and
		   the SPKAC is an import-only format */
		unlockResourceExit( certInfoPtr, CRYPT_BADPARM1 );
	status = krnlSendMessage( signContext, RESOURCE_MESSAGE_CHECK, NULL,
							  RESOURCE_MESSAGE_CHECK_PKC_SIGN, CRYPT_BADPARM2 );
	if( cryptStatusError( status ) )
		unlockResourceExit( certInfoPtr, status );

	/* We're changing data in a certificate, clear the error information */
	clearCertError( certInfoPtr );

	status = signCert( certInfoPtr, signContext );
	unlockResourceExit( certInfoPtr, status );
	}

/* Check the validity of a cert object, either against an issuing key/
   certificate or against a CRL */

CRET cryptCheckCert( const CRYPT_HANDLE certificate,
					 const CRYPT_HANDLE sigCheckKey )
	{
	CRYPT_CERTIFICATE localCert;
	CERT_INFO *certInfoPtr;
	int status;

	/* Perform basic error checking */
	status = krnlSendMessage( certificate, RESOURCE_MESSAGE_GETDATA,
							  &localCert, RESOURCE_MESSAGE_DATA_CERTIFICATE,
							  CRYPT_BADPARM1 );
	if( cryptStatusError( status ) )
		return( status );
	getCheckInternalResource( localCert, certInfoPtr, RESOURCE_TYPE_CERTIFICATE );
	if( certInfoPtr->certificate == NULL )
		unlockResourceExit( certInfoPtr, CRYPT_NOTINITED );
	if( certInfoPtr->type == CRYPT_CERTTYPE_CMS_ATTRIBUTES )
		/* CMS attributes aren't certs and can't be explicitly checked */
		unlockResourceExit( certInfoPtr, CRYPT_BADPARM1 );

	/* We're checking data in a certificate, clear the error information */
	clearCertError( certInfoPtr );

	status = checkCertValidity( certInfoPtr, sigCheckKey );
	unlockResourceExit( certInfoPtr, status );
	}

/* Import/export a certificate, CRL, certification request, or cert chain.
   In the export case this just copies the internal encoded object to an
   external buffer.  For cert/cert chain export the possibilities are as
   follows:

						Export
	Type  |		Cert				Chain
	------+--------------------+---------------
	Cert  | Cert			   | Cert as chain
		  |					   |
	Chain | Currently selected | Chain
		  | cert in chain	   | */

CRET cryptImportCert( const void CPTR certObject,
					  CRYPT_CERTIFICATE CPTR certificate )
	{
	int status;

	/* Perform basic error checking */
	if( checkBadPtrRead( certObject, MIN_CERTSIZE ) )
		return( CRYPT_BADPARM1 );
	if( checkBadPtrWrite( certificate, sizeof( CRYPT_CERTIFICATE ) ) )
		return( CRYPT_BADPARM2 );

	status = importCert( certObject, certificate, NULL, FALSE );
	return( cryptStatusError( status ) ? status : CRYPT_OK );
	}

CRET cryptExportCert( void CPTR certObject, int CPTR certObjectLength,
					  const CRYPT_CERTFORMAT_TYPE certFormatType,
					  const CRYPT_HANDLE certificate )
	{
	CRYPT_CERTIFICATE localCert;
	CERT_INFO *certInfoPtr;
	int status;

	/* Perform basic error checking */
	if( certObject != NULL )
		{
		if( checkBadPtrWrite( certObject, MIN_CERTSIZE ) )
			return( CRYPT_BADPARM1 );
		memset( certObject, 0, MIN_CERTSIZE );
		}
	if( checkBadPtrWrite( certObjectLength, sizeof( int ) ) )
		return( CRYPT_BADPARM2 );
	*certObjectLength = CRYPT_ERROR;
	if( certFormatType <= CRYPT_CERTFORMAT_NONE || \
		certFormatType >= CRYPT_CERTFORMAT_LAST )
		return( CRYPT_BADPARM3 );
	status = krnlSendMessage( certificate, RESOURCE_MESSAGE_GETDATA,
							  &localCert, RESOURCE_MESSAGE_DATA_CERTIFICATE,
							  CRYPT_BADPARM4 );
	if( cryptStatusError( status ) )
		return( status );
	getCheckInternalResource( localCert, certInfoPtr, RESOURCE_TYPE_CERTIFICATE );
	if( certFormatType == CRYPT_CERTFORMAT_SMIME_CERTIFICATE && \
		( certInfoPtr->type != CRYPT_CERTTYPE_CERTREQUEST && \
		  certInfoPtr->type != CRYPT_CERTTYPE_CERTCHAIN ) )
		/* Only cert requests or chains can be exported in S/MIME format */
		unlockResourceExit( certInfoPtr, CRYPT_BADPARM3 );
	if( certInfoPtr->type == CERTTYPE_CMS_ATTRIBUTES || \
		certInfoPtr->type == CERTTYPE_NS_SPKAC )
		/* CMS attributes aren't certs and can't be explicitly exported, and
		   the SPKAC is an import-only format */
		unlockResourceExit( certInfoPtr, CRYPT_BADPARM4 );

	/* If we're exporting a single cert from a chain, lock the currently
	   selected cert in the cert chain */
	if( ( certFormatType == CRYPT_CERTFORMAT_CERTIFICATE || \
		  certFormatType == CRYPT_CERTFORMAT_TEXT_CERTIFICATE ) && \
		certInfoPtr->certChainPos != CRYPT_ERROR )
		{
		CERT_INFO *certChainInfoPtr;

		getCheckInternalResource( certInfoPtr->certChain[ certInfoPtr->certChainPos ],
								  certChainInfoPtr, RESOURCE_TYPE_CERTIFICATE );
		unlockResource( certInfoPtr );
		certInfoPtr = certChainInfoPtr;
		}
	else
		if( certInfoPtr->certificate == NULL )
			unlockResourceExit( certInfoPtr, CRYPT_NOTINITED );

	status = exportCert( certObject, certObjectLength, certFormatType,
						 certInfoPtr );
	unlockResourceExit( certInfoPtr, status );
	}

