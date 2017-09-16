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

/* The minimum size for an OBJECT IDENTIFIER expressed as ASCII characters */

#define MIN_ASCII_OIDSIZE	7

/* Prototypes for functions in certext.c */

BOOLEAN isValidField( const CRYPT_ATTRIBUTE_TYPE fieldID,
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
		return( 0 );
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
						  const CRYPT_ATTRIBUTE_TYPE memberType,
						  const CRYPT_ATTRIBUTE_TYPE selectedGeneralName,
						  const CRYPT_ATTRIBUTE_TYPE selectedDN,
						  const UPDATE_TYPE updateType )
	{
	assert( memberType > CRYPT_CERTINFO_FIRST && \
			memberType < CRYPT_CERTINFO_LAST );

	if( isCursorComponent( memberType ) )
		{
		if( memberType == CRYPT_CERTINFO_CURRENT_CERTIFICATE && \
			( certType != CRYPT_CERTTYPE_CERTCHAIN && \
			  certType != CRYPT_CERTTYPE_CRL ) )
			return( CRYPT_ARGERROR_VALUE );
		return( CRYPT_OK );
		}
	if( isDNSelectionComponent( memberType ) || \
		isGeneralNameSelectionComponent( memberType ) )
		{
		/* CMS attributes don't have name components */
		if( certType == CRYPT_CERTTYPE_CMS_ATTRIBUTES )
			return( CRYPT_ARGERROR_VALUE );

		return( CRYPT_OK );
		}
	if( isGeneralNameComponent( memberType ) || \
		isDNComponent( memberType ) )
		{
		/* CMS attributes don't have name components */
		if( certType == CRYPT_CERTTYPE_CMS_ATTRIBUTES )
			return( CRYPT_ARGERROR_VALUE );

		/* Issuer names can't be explicitly written to */
		if( updateType != UPDATE_READ && \
			( selectedGeneralName == CRYPT_CERTINFO_ISSUERALTNAME || \
			  selectedDN == CRYPT_CERTINFO_ISSUERNAME ) )
			return( CRYPT_ERROR_PERMISSION );

		return( CRYPT_OK );
		}
	if( memberType == CRYPT_CERTINFO_IMMUTABLE || \
		memberType == CRYPT_CERTINFO_CERTTYPE )
		return( ( updateType != UPDATE_READ ) ? \
				CRYPT_ERROR_PERMISSION : CRYPT_OK );
	if( ( memberType == CRYPT_CERTINFO_TRUSTED_USAGE || \
		  memberType == CRYPT_CERTINFO_TRUSTED_IMPLICIT ) && \
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
			return( CRYPT_ERROR_PERMISSION );

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
			return( CRYPT_ERROR_PERMISSION );

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
	if( certType == CRYPT_CERTTYPE_CERTREQUEST || \
		certType == CRYPT_CERTTYPE_CRMF_REQUEST )
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

	return( CRYPT_ARGERROR_VALUE );
	}

/****************************************************************************
*																			*
*					Internal Certificate Management Functions				*
*																			*
****************************************************************************/

/* Import a certificate blob or cert chain by sending get_next_cert messages 
   to the source object to obtain all the certs in a chain.  Returns the 
   length of the certificate.
   
   This isn't really a direct certificate function since the control flow 
   sequence is:

	import indirect: 
		GETNEXTCERT -> source object
			source object: 
				CREATEOBJECT_INDIRECT -> system device
					system device: createCertificate() 
		GETNEXTCERT -> source object
			source object: 
				CREATEOBJECT_INDIRECT -> system device
					system device: createCertificate() 
		[...]					

   however this seems to be the best place to put the code */

int iCryptImportCertIndirect( CRYPT_CERTIFICATE *iCertificate,
							  const CRYPT_HANDLE iCertSource, 
							  const CRYPT_KEYID_TYPE keyIDtype,
							  const void *keyID, const int keyIDlength,
							  const CERTIMPORT_TYPE importType )
	{
	/* We're importing a sequence of certs as a chain from a source object, 
	   assemble the collection via the object */
	return( assembleCertChain( iCertificate, iCertSource, keyIDtype, 
							   keyID, keyIDlength, importType ) );
	}

/****************************************************************************
*																			*
*						Certificate Management API Functions				*
*																			*
****************************************************************************/

/* Handle data sent to or read from a cert object */

static int processCertData( CERT_INFO *certInfoPtr,
						    const RESOURCE_MESSAGE_TYPE message,
							void *messageDataPtr, const int messageValue )
	{
	RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
	int *valuePtr = ( int * ) messageDataPtr;

	/* Process get/set/delete attribute messages */
	if( message == RESOURCE_MESSAGE_GETATTRIBUTE )
		{
		if( messageValue == CRYPT_ATTRIBUTE_ERRORTYPE )
			{
			*valuePtr = certInfoPtr->errorType;
			return( CRYPT_OK );
			}
		if( messageValue == CRYPT_ATTRIBUTE_ERRORLOCUS )
			{
			*valuePtr = certInfoPtr->errorLocus;
			return( CRYPT_OK );
			}
		return( getCertComponent( certInfoPtr, messageValue, valuePtr, NULL ) );
		}
	if( message == RESOURCE_MESSAGE_GETATTRIBUTE_S )
		{
		STREAM stream;
		void *serialNumber;
		int serialNumberLength, length;

		/* If it's a general attribute, pass the call on down to the cert.
		   component manipulation functions */
		if( !isInternalAttribute( messageValue ) )
			return( getCertComponent( certInfoPtr, messageValue, 
									  msgData->data, &msgData->length ) );

		/* Handle internal attributes */		
		if( messageValue == CRYPT_IATTRIBUTE_SUBJECT )
			return( attributeCopy( msgData, certInfoPtr->subjectDNptr, 
								   certInfoPtr->subjectDNsize ) );
		if( messageValue == CRYPT_IATTRIBUTE_ISSUER )
			return( attributeCopy( msgData, certInfoPtr->issuerDNptr, 
								   certInfoPtr->issuerDNsize ) );
		if( messageValue == CRYPT_IATTRIBUTE_SPKI )
			return( attributeCopy( msgData, certInfoPtr->publicKeyInfo, 
						getObjectLength( certInfoPtr->publicKeyInfo, 16 ) ) );
		if( messageValue == CRYPT_IATTRIBUTE_CERTSET )
			{
			length = ( int ) sizeofCertSet( certInfoPtr );
			if( msgData->data != NULL )
				{
				if( length > msgData->length )
					return( CRYPT_ERROR_OVERFLOW );
				sMemConnect( &stream, msgData->data, STREAMSIZE_UNKNOWN );
				writeCertSet( &stream, certInfoPtr );
				sMemDisconnect( &stream );
				}
			msgData->length = ( int ) sizeofCertSet( certInfoPtr );

			return( CRYPT_OK );
			}
		if( messageValue == CRYPT_IATTRIBUTE_ENC_CERT || \
			messageValue == CRYPT_IATTRIBUTE_ENC_CERTCHAIN || \
			messageValue == CRYPT_IATTRIBUTE_ENC_CMSATTR || \
			messageValue == CRYPT_IATTRIBUTE_TEXT_CERT || \
			messageValue == CRYPT_IATTRIBUTE_TEXT_CERTCHAIN )
			{
			const CRYPT_CERTFORMAT_TYPE formatType = \
				( messageValue == CRYPT_IATTRIBUTE_ENC_CERT ) ? \
					CRYPT_CERTFORMAT_CERTIFICATE : \
				( messageValue == CRYPT_IATTRIBUTE_ENC_CERTCHAIN ) ? \
					CRYPT_CERTFORMAT_CERTCHAIN : \
				( messageValue == CRYPT_IATTRIBUTE_TEXT_CERT ) ? \
					CRYPT_CERTFORMAT_TEXT_CERTIFICATE : \
					CRYPT_CERTFORMAT_TEXT_CERTCHAIN;

			assert( certInfoPtr->type < CRYPT_CERTTYPE_LAST_EXTERNAL );

			/* CMS attributes aren't signed objects like other cert.objects 
			   so they aren't pre-encoded when we sign them (they also have 
			   the potential to change on each use if the same CMS 
			   attributes are reused for multiple signatures).  Because of 
			   this we write them out on export rather than copying the pre-
			   encoded form from an internal buffer */
			if( certInfoPtr->type == CRYPT_CERTTYPE_CMS_ATTRIBUTES )
				{
				STREAM stream;
				int status;

				sMemOpen( &stream, msgData->data, msgData->length );
				status = writeCMSAttributes( &stream, certInfoPtr );
				msgData->length = ( int ) stell( &stream );
				sMemDisconnect( &stream );

				return( status );
				}

			assert( certInfoPtr->certificate != NULL );

			/* If we're exporting a single cert from a chain, lock the 
			   currently selected cert in the chain and export that */
			if( ( formatType == CRYPT_CERTFORMAT_CERTIFICATE || \
				  formatType == CRYPT_CERTFORMAT_TEXT_CERTIFICATE ) && \
				certInfoPtr->certChainPos != CRYPT_ERROR )
				{
				CERT_INFO *certChainInfoPtr;
				int status;

				getCheckInternalResource( certInfoPtr->certChain[ certInfoPtr->certChainPos ],
										  certChainInfoPtr, OBJECT_TYPE_CERTIFICATE );
				status = exportCert( msgData->data, &msgData->length, 
									 formatType, certChainInfoPtr );
				unlockResource( certChainInfoPtr );
				return( status );
				}

			return( exportCert( msgData->data, &msgData->length, 
								formatType, certInfoPtr ) );
			}
		assert( messageValue == CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
		if( certInfoPtr->type == CRYPT_CERTTYPE_CRL )
			{
			CRL_ENTRY *crlInfoPtr = certInfoPtr->currentRevocation;

			/* If it's a CRL, use the serial number of the currently selected 
			   CRL entry */
			assert( crlInfoPtr != NULL );

			serialNumber = crlInfoPtr->serialNumber;
			serialNumberLength = crlInfoPtr->serialNumberLength;
			}
		else
			{
			serialNumber = certInfoPtr->serialNumber;
			serialNumberLength = certInfoPtr->serialNumberLength;
			}
		length = ( int ) \
			sizeofObject( certInfoPtr->issuerDNsize + \
						  sizeofInteger( serialNumber, serialNumberLength ) );
		if( msgData->data != NULL )
			{
			if( length > msgData->length )
				return( CRYPT_ERROR_OVERFLOW );
			sMemConnect( &stream, msgData->data, STREAMSIZE_UNKNOWN );
			writeSequence( &stream, certInfoPtr->issuerDNsize +
						   sizeofInteger( serialNumber, serialNumberLength ) );
			swrite( &stream, certInfoPtr->issuerDNptr, 
					certInfoPtr->issuerDNsize );
			writeInteger( &stream, serialNumber, serialNumberLength, 
						  DEFAULT_TAG );
			sMemDisconnect( &stream );
			}
		msgData->length = length;

		return( CRYPT_OK );
		}
	if( message == RESOURCE_MESSAGE_SETATTRIBUTE )
		{
		const BOOLEAN validCursorPosition = \
			( certInfoPtr->type == CRYPT_CERTTYPE_CMS_ATTRIBUTES ) ? \
			messageValue >= CRYPT_FIRST_CMS && messageValue <= CRYPT_LAST_CMS : \
			messageValue >= CRYPT_FIRST_EXTENSION && messageValue <= CRYPT_LAST_EXTENSION;

		/* If it's a completed certificate, we can only add a restricted 
		   class of component selection control values to the object */
		assert( certInfoPtr->certificate == NULL || \
				isDNSelectionComponent( messageValue ) || \
				isGeneralNameSelectionComponent( messageValue ) || \
				isCursorComponent( messageValue ) || \
				isControlComponent( messageValue ) || \
				messageValue == CRYPT_IATTRIBUTE_INITIALISED );

		/* If it's an initialisation message, there's nothing to do (we get 
		   these when importing a cert, when the import is complete the 
		   import code sends this message to move the cert into the high
		   state because it's already signed) */
		if( messageValue == CRYPT_IATTRIBUTE_INITIALISED )
			return( CRYPT_OK );

		/* If the passed-in value is a cursor-positioning code, make sure 
		   it's valid */
		if( *valuePtr < 0 && *valuePtr != CRYPT_UNUSED && \
			( *valuePtr > CRYPT_CURSOR_FIRST || *valuePtr < CRYPT_CURSOR_LAST ) &&
			!validCursorPosition && messageValue != CRYPT_CERTINFO_SELFSIGNED )
			return( CRYPT_ARGERROR_NUM1 );

		return( addCertComponent( certInfoPtr, messageValue, valuePtr, 
								  CRYPT_UNUSED ) );
		}
	if( message == RESOURCE_MESSAGE_SETATTRIBUTE_S )
		return( addCertComponent( certInfoPtr, messageValue, msgData->data, 
								  msgData->length ) );
	if( message == RESOURCE_MESSAGE_DELETEATTRIBUTE )
		return( deleteCertComponent( certInfoPtr, messageValue ) );

	assert( NOTREACHED );
	return( 0 );		/* Get rid of compiler warning */
	}

/* Handle a message sent to a certificate context */

static int certificateMessageFunction( const CRYPT_CERTIFICATE certificate,
									   const RESOURCE_MESSAGE_TYPE message,
									   void *messageDataPtr,
									   const int messageValue )
	{
	CERT_INFO *certInfoPtr;

	getCheckInternalResource( certificate, certInfoPtr, OBJECT_TYPE_CERTIFICATE );

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

		/* Delete the objects locking variables and the object itself */
		unlockResource( certInfoPtr );
		deleteResourceLock( certInfoPtr );
		zeroise( certInfoPtr, sizeof( CERT_INFO ) );
		free( certInfoPtr );

		return( CRYPT_OK );
		}

	/* Process attribute get/set/delete messages */
	if( isAttributeMessage( message ) )
		{
		const UPDATE_TYPE updateType = \
				( message == RESOURCE_MESSAGE_GETATTRIBUTE || \
				  message == RESOURCE_MESSAGE_GETATTRIBUTE_S ) ? UPDATE_READ : \
				( message == RESOURCE_MESSAGE_SETATTRIBUTE || \
				  message == RESOURCE_MESSAGE_SETATTRIBUTE_S ) ? UPDATE_WRITE : \
				UPDATE_DELETE;
		int status = CRYPT_OK;

		/* Lock the currently selected cert in a cert chain unless the 
		   message being processed is a certificate cursor movement command 
		   or something specifically directed at the entire chain (for
		   example a get type or self-signed status command - we want to get 
		   the type/status of the chain, not of the certs within it) */
		if( certInfoPtr->certChainPos != CRYPT_ERROR && \
			!( ( message == RESOURCE_MESSAGE_SETATTRIBUTE ) && \
			   ( messageValue == CRYPT_CERTINFO_CURRENT_CERTIFICATE ) ) && \
			!( ( message == RESOURCE_MESSAGE_GETATTRIBUTE ) && \
			   ( messageValue == CRYPT_CERTINFO_CERTTYPE || \
				 messageValue == CRYPT_CERTINFO_SELFSIGNED ) ) && \
			!( ( message == RESOURCE_MESSAGE_GETATTRIBUTE_S ) && \
			   ( messageValue == CRYPT_IATTRIBUTE_CERTSET || \
				 messageValue == CRYPT_IATTRIBUTE_ENC_CERT || \
				 messageValue == CRYPT_IATTRIBUTE_ENC_CERTCHAIN || \
				 messageValue == CRYPT_IATTRIBUTE_ENC_CMSATTR || \
				 messageValue == CRYPT_IATTRIBUTE_TEXT_CERT || \
				 messageValue == CRYPT_IATTRIBUTE_TEXT_CERTCHAIN ) ) )
			{
			CERT_INFO *certChainInfoPtr;

			getCheckInternalResource( certInfoPtr->certChain[ certInfoPtr->certChainPos ],
									  certChainInfoPtr, OBJECT_TYPE_CERTIFICATE );
			unlockResource( certInfoPtr );
			certInfoPtr = certChainInfoPtr;
			}

		/* If we're being asked for error info, return it to the caller */
		if( messageValue == CRYPT_ATTRIBUTE_ERRORTYPE || \
			messageValue == CRYPT_ATTRIBUTE_ERRORLOCUS )
			{
			assert( message == RESOURCE_MESSAGE_GETATTRIBUTE );

			*( ( int * ) messageDataPtr ) = \
				( messageValue == CRYPT_ATTRIBUTE_ERRORTYPE ) ? \
				certInfoPtr->errorType : certInfoPtr->errorLocus;
			unlockResourceExit( certInfoPtr, CRYPT_OK );
			}

		/* Make sure the attribute is valid for the selected object and update 
		   type, and perform the update */
		if( !( isInternalAttribute( messageValue ) || \
			   messageValue == CRYPT_ATTRIBUTE_ERRORTYPE || \
			   messageValue == CRYPT_ATTRIBUTE_ERRORLOCUS ) )
			status = isValidMember( certInfoPtr->type, messageValue,
									certInfoPtr->currentGeneralName,
									certInfoPtr->currentDN, updateType );
		if( cryptStatusOK( status ) )
			status = processCertData( certInfoPtr, message, messageDataPtr, 
									  messageValue );
		unlockResourceExit( certInfoPtr, status );
		}

	/* Process messages which compare the object */
	if( message == RESOURCE_MESSAGE_COMPARE )
		{
		CERT_INFO *certInfoPtr2;
		STREAM stream;
		BYTE *dataStart;
		long serialNoLength;
		int dataLength, length, status;

		switch( messageValue )
			{
			case RESOURCE_MESSAGE_COMPARE_ISSUERANDSERIALNUMBER:
				/* Compare the issuerName */
				sMemConnect( &stream, messageDataPtr, STREAMSIZE_UNKNOWN );
				readSequence( &stream, NULL );
				dataStart = sMemBufPtr( &stream );
				length = readSequence( &stream, &dataLength );
				sSkip( &stream, dataLength );
				dataLength += length;	/* Add length of header */
				if( dataLength != certInfoPtr->issuerDNsize || \
					memcmp( dataStart, certInfoPtr->issuerDNptr,
							certInfoPtr->issuerDNsize ) )
					{
					sMemDisconnect( &stream );
					unlockResourceExit( certInfoPtr, CRYPT_ERROR );
					}

				/* Compare the serialNumber.  This one can get a bit tricky
				   because Microsoft fairly consistently encode the serial
				   numbers incorrectly, so we normalise the values to have no
				   leading zero which is the lowest common denominator */
				readTag( &stream );
				readLength( &stream, &serialNoLength );
				dataStart = sMemBufPtr( &stream );
				sMemDisconnect( &stream );
				if( !*dataStart )
					{ dataStart++; serialNoLength--; }	/* Skip leading zero */
				if( serialNoLength != certInfoPtr->serialNumberLength || \
					memcmp( dataStart, certInfoPtr->serialNumber,
							certInfoPtr->serialNumberLength ) )
					unlockResourceExit( certInfoPtr, CRYPT_ERROR );

				unlockResourceExit( certInfoPtr, CRYPT_OK );

			case RESOURCE_MESSAGE_COMPARE_FINGERPRINT:
				getCheckInternalResource( *( ( CRYPT_CERTIFICATE * ) messageDataPtr ),
								certInfoPtr2, OBJECT_TYPE_CERTIFICATE );
				if( certInfoPtr->certificate == NULL || \
					certInfoPtr2->certificate == NULL )
					{
					/* If the cert objects haven't been signed yet, we can't
					   compare them */
					unlockResource( certInfoPtr2 );
					unlockResourceExit( certInfoPtr, CRYPT_ERROR_NOTINITED );
					}

				/* Compare the encoded certificate data.  This is the same as
				   comparing the fingerprint without requiring any hashing */
				status = ( certInfoPtr->certificateSize == \
									certInfoPtr2->certificateSize && \
						   !memcmp( certInfoPtr->certificate, certInfoPtr2->certificate,
									certInfoPtr->certificateSize ) ) ? \
						 CRYPT_OK : CRYPT_ERROR;
				unlockResource( certInfoPtr2 );
				unlockResourceExit( certInfoPtr, status );
			}

		assert( NOTREACHED );
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
			( messageValue == RESOURCE_MESSAGE_CHECK_PKC_KA_EXPORT ) ? \
				CRYPT_KEYUSAGE_ENCIPHERONLY : \
			( messageValue == RESOURCE_MESSAGE_CHECK_PKC_KA_IMPORT ) ? \
				CRYPT_KEYUSAGE_DECIPHERONLY : 0;
			/* enc/decOnly usage falls back to plain keyAgree if necessary */
		int status;

		/* If we're not checking for a specific type of functionality 
		   restriction set by the cert then any kind of usage is OK */
		if( !certCheckValue )
			unlockResourceExit( certInfoPtr, CRYPT_OK );

		status = checkCertUsage( certInfoPtr, certCheckValue,
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );
		status = cryptStatusError( status ) ? \
				 CRYPT_ARGERROR_OBJECT : CRYPT_OK;	/* Convert to correct form */
		unlockResourceExit( certInfoPtr, status );
		}

	/* Process messages which lock/unlock an object for exclusive use */
	if( message == RESOURCE_MESSAGE_LOCK )
		{
		/* Save the current volatile state so that any changes made while
		   the object is locked aren't reflected back to the caller */
		saveSelectionState( certInfoPtr->selectionState, certInfoPtr );

		/* Exit without unlocking the object.  Any other threads trying to
		   use the object after this point will be blocked */
		return( CRYPT_OK );
		}
	if( message == RESOURCE_MESSAGE_UNLOCK )
		{
		/* Restore the volatile state from before the object was locked */
		restoreSelectionState( certInfoPtr->selectionState, certInfoPtr );

		/* "Wenn drei Leute in ein Zimmer reingehen und fuenf kommen raus,
			dann muessen erst mal zwei wieder reingehen bis das Zimmer leer
			ist" */
		unlockResource( certInfoPtr );	/* Undo RESOURCE_MESSAGE_LOCK lock */
		unlockResourceExit( certInfoPtr, CRYPT_OK );
		}

	/* Process object-specific messages */
	if( message == RESOURCE_MESSAGE_CRT_SIGN )
		{
		int status;

		assert( certInfoPtr->certificate == NULL );
		assert( certInfoPtr->type != CRYPT_CERTTYPE_CMS_ATTRIBUTES && \
				certInfoPtr->type != CRYPT_CERTTYPE_NS_SPKAC );

		/* Make sure the signing object can actually be used for signing */
		status = krnlSendMessage( messageValue, RESOURCE_MESSAGE_CHECK, NULL,
								  RESOURCE_MESSAGE_CHECK_PKC_SIGN );
		if( cryptStatusError( status ) )
			unlockResourceExit( certInfoPtr, CRYPT_ARGERROR_VALUE );

		/* We're changing data in a certificate, clear the error 
		   information */
		clearErrorInfo( certInfoPtr );

		status = signCert( certInfoPtr, messageValue );
		unlockResourceExit( certInfoPtr, status );
		}
	if( message == RESOURCE_MESSAGE_CRT_SIGCHECK )
		{
		int status;

		assert( certInfoPtr->certificate != NULL );
		assert( certInfoPtr->type != CRYPT_CERTTYPE_CMS_ATTRIBUTES );

		/* We're checking data in a certificate, clear the error 
		   information */
		clearErrorInfo( certInfoPtr );

		status = checkCertValidity( certInfoPtr, messageValue );
		unlockResourceExit( certInfoPtr, status );
		}

	assert( NOTREACHED );
	return( 0 );		/* Get rid of compiler warning */
	}

/* Create a certificate object, returning a pointer to the locked cert info 
   ready for further initialisation */

int createCertificateInfo( CERT_INFO **certInfoPtrPtr, 
						   const CRYPT_CERTTYPE_TYPE certType )
	{
	CRYPT_CERTIFICATE iCertificate;
	CERT_INFO *certInfoPtr;
	const int subType = \
		/* Standard types */
		( certType == CRYPT_CERTTYPE_CERTIFICATE ) ? SUBTYPE_CERT_CERT : \
		( certType == CRYPT_CERTTYPE_ATTRIBUTE_CERT ) ? SUBTYPE_CERT_ATTRCERT : \
		( certType == CRYPT_CERTTYPE_CERTCHAIN ) ? SUBTYPE_CERT_CERTCHAIN : \
		( certType == CRYPT_CERTTYPE_CERTREQUEST ) ? SUBTYPE_CERT_CERTREQ : \
		( certType == CRYPT_CERTTYPE_CRMF_REQUEST ) ? SUBTYPE_CERT_CERTREQ : \
		( certType == CRYPT_CERTTYPE_CRL ) ? SUBTYPE_CERT_CRL : \
		( certType == CRYPT_CERTTYPE_CMS_ATTRIBUTES ) ? SUBTYPE_CERT_CMSATTR : \
		/* Special-case types which are mapped to standard types */
		( certType == CRYPT_CERTTYPE_NS_CERTSEQUENCE ) ? SUBTYPE_CERT_CERTCHAIN : \
		( certType == CRYPT_CERTTYPE_NS_SPKAC ) ? SUBTYPE_CERT_CERTREQ : \
		( certType == CRYPT_CERTTYPE_CMS_CERTSET ) ? SUBTYPE_CERT_CERTCHAIN : 0;

	assert( certInfoPtrPtr != NULL );

	*certInfoPtrPtr = NULL;

	/* Create the certificate object */
	iCertificate = krnlCreateObject( ( void ** ) &certInfoPtr, 
									 OBJECT_TYPE_CERTIFICATE, subType,
									 sizeof( CERT_INFO ), 0, 0, 
									 certificateMessageFunction );
	if( cryptStatusError( iCertificate ) )
		return( iCertificate );
	initResourceLock( certInfoPtr ); 
	lockResource( certInfoPtr ); 
	certInfoPtr->objectHandle = iCertificate;
	certInfoPtr->type = certType;

	/* Set up any internal objects to contain invalid handles */
	certInfoPtr->iCryptContext = CRYPT_ERROR;

	/* Set the state information to its initial state */
	certInfoPtr->certChainPos = CRYPT_ERROR;
	certInfoPtr->trustedUsage = CRYPT_ERROR;

	/* Return the locked cert info pointer */
	*certInfoPtrPtr = certInfoPtr;
	return( iCertificate );
	}

/* Create a certificate */

int createCertificate( CREATEOBJECT_INFO *createInfo, const void *auxDataPtr, 
					   const int auxValue )
	{
	CRYPT_CERTIFICATE iCertificate;
	CERT_INFO *certInfoPtr;
	int status;

	assert( auxDataPtr == NULL );
	assert( auxValue == 0 );

	/* If we're doing an indirect object create (ie from encoded object 
	   data), import the data into a new object */
	if( createInfo->createIndirect )
		{
		assert( createInfo->arg1 > CERTIMPORT_NONE && \
				createInfo->arg1 < CERTIMPORT_LAST );
		assert( createInfo->arg2 >= CERTFORMAT_NORMAL && \
				createInfo->arg2 < CERTFORMAT_LAST );
		assert( createInfo->strArg1 != NULL );
		assert( createInfo->strArgLen1 > 16 );	/* May be CMS attr.*/

		/* Pass the call through to the low-level import function.  This
		   returns a length value so we convert it to a proper status for
		   the caller */
		status = importCert( createInfo->strArg1, createInfo->strArgLen1,
							 &iCertificate, createInfo->arg1, 
							 createInfo->arg2 );
		if( !cryptStatusError( status ) )
			{
			createInfo->cryptHandle = iCertificate;
			return( CRYPT_OK );
			}
		return( status );
		}

	/* Perform basic error checking */
	if( createInfo->arg1 <= CRYPT_CERTTYPE_NONE || \
		createInfo->arg1 >= CRYPT_CERTTYPE_LAST )
		return( CRYPT_ARGERROR_NUM1 );

	status = createCertificateInfo( &certInfoPtr, createInfo->arg1 );
	if( cryptStatusError( status ) )
		return( status );
	iCertificate = status;

	/* We've finished setting up the object-type-specific info, tell the 
	   kernel the object is ready for use */
	unlockResource( certInfoPtr );
	status = krnlSendMessage( iCertificate, RESOURCE_IMESSAGE_SETATTRIBUTE, 
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusOK( status ) )
		createInfo->cryptHandle = iCertificate;
	return( status );
	}

/* Get/add/delete certificate attributes */

C_RET cryptGetCertExtension( C_IN CRYPT_HANDLE cryptHandle,
							 C_IN char C_PTR oid, 
							 C_OUT int C_PTR criticalFlag,
							 C_OUT void C_PTR extension, 
							 C_OUT int C_PTR extensionLength )
	{
	CRYPT_CERTIFICATE certificate;
	CERT_INFO *certInfoPtr;
	ATTRIBUTE_LIST *attributeListPtr;
	BYTE binaryOID[ CRYPT_MAX_TEXTSIZE ];
	BOOLEAN returnData = ( extension != NULL ) ? TRUE : FALSE;
	int status;

	/* Perform basic error checking */
	status = krnlSendMessage( cryptHandle, RESOURCE_MESSAGE_GETDEPENDENT,
							  &certificate, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ERROR_PARAM1 : status );
	getCheckInternalResource( certificate, certInfoPtr, OBJECT_TYPE_CERTIFICATE );
	if( checkBadPtrRead( oid, MIN_ASCII_OIDSIZE ) )
		unlockResourceExit( certInfoPtr, CRYPT_ERROR_PARAM2 );
	if( checkBadPtrWrite( criticalFlag, sizeof( int ) ) )
		unlockResourceExit( certInfoPtr, CRYPT_ERROR_PARAM3 );
	*criticalFlag = CRYPT_ERROR;
	if( extension != NULL )
		*( ( BYTE * ) extension ) = 0;
	if( checkBadPtrWrite( extensionLength, sizeof( int ) ) )
		unlockResourceExit( certInfoPtr, CRYPT_ERROR_PARAM5 );
	*extensionLength = CRYPT_ERROR;

	/* Lock the currently selected cert in a cert chain if necessary */
	if( certInfoPtr->certChainPos != CRYPT_ERROR )
		{
		CERT_INFO *certChainInfoPtr;

		getCheckInternalResource( certInfoPtr->certChain[ certInfoPtr->certChainPos ],
								  certChainInfoPtr, OBJECT_TYPE_CERTIFICATE );
		unlockResource( certInfoPtr );
		certInfoPtr = certChainInfoPtr;
		}

	/* Convert the OID to its binary form and try and locate the attribute
	   identified by the OID */
	if( !textToOID( oid, strlen( oid ), binaryOID ) )
		unlockResourceExit( certInfoPtr, CRYPT_ERROR_PARAM2 );
	attributeListPtr = findAttributeByOID( certInfoPtr->attributes, binaryOID );
	if( attributeListPtr == NULL )
		unlockResourceExit( certInfoPtr, CRYPT_ERROR_NOTFOUND );
	*criticalFlag = attributeListPtr->isCritical;
	*extensionLength = attributeListPtr->dataLength;
	if( returnData )
		{
		const void *dataPtr = ( attributeListPtr->dataLength <= CRYPT_MAX_TEXTSIZE ) ? \
							  attributeListPtr->smallData : attributeListPtr->data;

		if( checkBadPtrWrite( extension, attributeListPtr->dataLength ) )
			unlockResourceExit( certInfoPtr, CRYPT_ERROR_PARAM3 );
		memcpy( extension, dataPtr, attributeListPtr->dataLength );
		}
	unlockResourceExit( certInfoPtr, CRYPT_OK );
	}

C_RET cryptAddCertExtension( C_IN CRYPT_CERTIFICATE certificate,
							 C_IN char C_PTR oid, C_IN int criticalFlag,
							 C_IN void C_PTR extension,
							 C_IN int extensionLength )
	{
	CERT_INFO *certInfoPtr;
	BYTE binaryOID[ CRYPT_MAX_TEXTSIZE ];
	int status;

	/* Perform basic error checking */
	getCheckResource( certificate, certInfoPtr, OBJECT_TYPE_CERTIFICATE,
					  CRYPT_ERROR_PARAM1 );
	if( certInfoPtr->certificate != NULL || \
		certInfoPtr->certChainPos != CRYPT_ERROR )
		unlockResourceExit( certInfoPtr, CRYPT_ERROR_PERMISSION );
	if( checkBadPtrRead( oid, MIN_ASCII_OIDSIZE ) )
		unlockResourceExit( certInfoPtr, CRYPT_ERROR_PARAM2 );
	if( certInfoPtr->type == CRYPT_CERTTYPE_CMS_ATTRIBUTES && \
		criticalFlag != CRYPT_UNUSED )
		unlockResourceExit( certInfoPtr, CRYPT_ERROR_PARAM3 );
	if( extensionLength <= 3 || extensionLength > MAX_ATTRIBUTE_SIZE )
		unlockResourceExit( certInfoPtr, CRYPT_ERROR_PARAM5 );
	if( checkBadPtrRead( extension, extensionLength ) )
		unlockResourceExit( certInfoPtr, CRYPT_ERROR_PARAM4 );
	status = checkEncoding( extension, extensionLength );
	if( cryptStatusError( status ) )
		unlockResourceExit( certInfoPtr, CRYPT_ERROR_PARAM4 );

	/* Convert the OID to its binary form, copy the data to an internal
	   buffer, and add the attribute to the certificate */
	if( !textToOID( oid, strlen( oid ), binaryOID ) )
		unlockResourceExit( certInfoPtr, CRYPT_ERROR_PARAM2 );
	status = addAttribute( ( certInfoPtr->type == CRYPT_CERTTYPE_CMS_ATTRIBUTES ) ? \
		ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE, &certInfoPtr->attributes,
		binaryOID, ( BOOLEAN )	/* Fix for VC++ */
		( ( certInfoPtr->type == CRYPT_CERTTYPE_CMS_ATTRIBUTES ) ? FALSE : \
		  criticalFlag ), extension, extensionLength );
	if( status == CRYPT_ERROR_INITED )
		/* If the attribute is already present, set error information for it.
		   We can't set an error locus since it's an unknown blob */
		setErrorInfo( certInfoPtr, CRYPT_ATTRIBUTE_NONE,
					  CRYPT_ERRTYPE_ATTR_PRESENT );
	unlockResourceExit( certInfoPtr, status );
	}

C_RET cryptDeleteCertExtension( C_IN CRYPT_CERTIFICATE certificate,
								C_IN char C_PTR oid )
	{
	CERT_INFO *certInfoPtr;
	ATTRIBUTE_LIST *attributeListPtr;
	BYTE binaryOID[ CRYPT_MAX_TEXTSIZE ];

	/* Perform basic error checking */
	getCheckResource( certificate, certInfoPtr, OBJECT_TYPE_CERTIFICATE,
					  CRYPT_ERROR_PARAM1 );
	if( certInfoPtr->certificate != NULL || \
		certInfoPtr->certChainPos != CRYPT_ERROR )
		unlockResourceExit( certInfoPtr, CRYPT_ERROR_PERMISSION );
	if( checkBadPtrRead( oid, MIN_ASCII_OIDSIZE ) )
		unlockResourceExit( certInfoPtr, CRYPT_ERROR_PARAM2 );

	/* Convert the OID to its binary form, find the attribute identified by
	   this OID, and delete it */
	if( !textToOID( oid, strlen( oid ), binaryOID ) )
		unlockResourceExit( certInfoPtr, CRYPT_ERROR_PARAM2 );
	attributeListPtr = findAttributeByOID( certInfoPtr->attributes, binaryOID );
	if( attributeListPtr == NULL )
		unlockResourceExit( certInfoPtr, CRYPT_ERROR_NOTFOUND );
	deleteAttribute( &certInfoPtr->attributes, NULL, attributeListPtr );
	unlockResourceExit( certInfoPtr, CRYPT_OK );
	}
