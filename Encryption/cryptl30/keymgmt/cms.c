/****************************************************************************
*																			*
*					  Cryptographic Message Syntax Routines					*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "asn1.h"
  #include "asn1objs.h"
  #include "asn1oid.h"
  #include "cert.h"
#else
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1objs.h"
  #include "keymgmt/asn1oid.h"
  #include "keymgmt/cert.h"
#endif /* Compiler-specific includes */

/* The CMS version number */

#define CMS_VERSION		1

/****************************************************************************
*																			*
*							Read/Write RecipientInfo						*
*																			*
****************************************************************************/

/****************************************************************************
*																			*
*								Read/Write SignerInfo						*
*																			*
****************************************************************************/

/* Read signed attributes */

int readCMSAttributes( STREAM *stream, CERT_INFO *attributeInfoPtr )
	{
	/* CMS attributes are straight attribute objects so we just pass the call
	   through */
	return( readAttributes( stream, &attributeInfoPtr->attributes,
							CRYPT_CERTTYPE_CMS_ATTRIBUTES, CRYPT_UNUSED,
							&attributeInfoPtr->errorLocus,
							&attributeInfoPtr->errorType ) );
	}

/* Read the information in a SignerInfo record */

int readSignerInfo( STREAM *stream, CRYPT_ALGO *hashAlgorithm,
					void **iAndSStart, void **attributes, int *attributeSize,
					void **signature )
	{
	QUERY_INFO queryInfo;
	int status;

	*hashAlgorithm = CRYPT_ERROR;
	*attributes = *signature = NULL;
	*attributeSize = 0;

	/* Obtain the hash algorithm and issuer ID using the standard query
	   function */
	status = queryObject( stream, &queryInfo );
	if( queryInfo.formatType != CRYPT_FORMAT_CMS )
		status = CRYPT_ERROR_BADDATA;
	if( cryptStatusError( status ) )
		return( status );
	*iAndSStart = queryInfo.iAndSStart;
	*hashAlgorithm = queryInfo.hashAlgo;

	/* Remember where the attributes and signature start.  Since
	   queryObject() resets the stream, we seek to the start of the payload
	   before we try to process anything */
	sseek( stream, ( BYTE * ) queryInfo.dataStart - sMemBufPtr( stream ) );
	if( peekTag( stream ) == MAKE_CTAG( 0 ) )
		{
		int length;

		*attributes = sMemBufPtr( stream );
		readConstructed( stream, &length, 0 );
		*attributeSize = ( int ) sizeofObject( length );
		sSkip( stream, length );
		}
	*signature = sMemBufPtr( stream );
	zeroise( &queryInfo, sizeof( QUERY_INFO ) );

	return( CRYPT_OK );
	}

/* Write signed attributes */

int writeCMSAttributes( STREAM *stream, CERT_INFO *attributeInfoPtr )
	{
	ATTRIBUTE_LIST *attributeListPtr;
	int addDefaultAttributes, attributeSize, status;

	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
					 &addDefaultAttributes, 
					 CRYPT_OPTION_CMS_DEFAULTATTRIBUTES );

	/* Make sure there's a hash and content type present */
	if( findAttributeField( attributeInfoPtr->attributes,
							CRYPT_CERTINFO_CMS_MESSAGEDIGEST,
							CRYPT_ATTRIBUTE_NONE ) == NULL )
		{
		setErrorInfo( attributeInfoPtr, CRYPT_CERTINFO_CMS_MESSAGEDIGEST,
					  CRYPT_ERRTYPE_ATTR_ABSENT );
		return( CRYPT_ERROR_INVALID );
		}
	attributeListPtr = findAttribute( attributeInfoPtr->attributes,
									  CRYPT_CERTINFO_CMS_CONTENTTYPE );
	if( attributeListPtr == NULL )
		{
		const int value = CRYPT_CONTENT_DATA;

		/* If there's no content type and we're not adding it automatically,
		   complain */
		if( !addDefaultAttributes )
			{
			setErrorInfo( attributeInfoPtr, CRYPT_CERTINFO_CMS_CONTENTTYPE,
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_INVALID );
			}

		/* There's no content type present, treat it as straight data (which
		   means this is signedData) */
		status = addCertComponent( attributeInfoPtr, CRYPT_CERTINFO_CMS_CONTENTTYPE,
								   &value, CRYPT_UNUSED );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If there's no signing time attribute present and we're adding the
	   default attributes, add it now */
	if( addDefaultAttributes && \
		( attributeListPtr = findAttribute( attributeInfoPtr->attributes,
							CRYPT_CERTINFO_CMS_SIGNINGTIME ) ) == NULL )
		{
		const time_t currentTime = time( NULL );

		status = addCertComponent( attributeInfoPtr, CRYPT_CERTINFO_CMS_SIGNINGTIME,
								   &currentTime, sizeof( time_t ) );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Check that the attributes are in order and determine how big the whole
	   mess will be */
	status = checkAttributes( ATTRIBUTE_CMS, attributeInfoPtr->attributes,
							  &attributeInfoPtr->errorLocus,
							  &attributeInfoPtr->errorType );
	if( cryptStatusError( status ) )
		return( status );
	attributeSize = sizeofAttributes( attributeInfoPtr->attributes );

	/* Write the attributes */
	return( writeAttributes( stream, attributeInfoPtr->attributes,
							 CRYPT_CERTTYPE_CMS_ATTRIBUTES, attributeSize ) );
	}

/* Write signer information:

	SignerInfo ::= SEQUENCE {
		version					INTEGER (1),
		issuerAndSerialNumber	IssuerAndSerialNumber,
		digestAlgorithm			AlgorithmIdentifier,
		signedAttrs		  [ 0 ]	IMPLICIT SET OF Attribute OPTIONAL,
		signatureAlgorithm		AlgorithmIdentifier,
		signature				OCTET STRING
		} */

int writeSignerInfo( STREAM *stream, CRYPT_CERTIFICATE certificate,
					 const CRYPT_ALGO hashAlgorithm,
					 const void *attributes, const int attributeSize,
					 const void *signature, const int signatureSize )
	{
	CERT_INFO *signerInfoPtr;
	int issuerAndSerialNumberSize;
	int length;

	getCheckInternalResource( certificate, signerInfoPtr,
							  OBJECT_TYPE_CERTIFICATE );

	/* Determine the size of the signerInfo information */
	issuerAndSerialNumberSize = \
				sizeofInteger( signerInfoPtr->serialNumber, 
							   signerInfoPtr->serialNumberLength ) +
				signerInfoPtr->issuerDNsize;
	length = sizeofShortInteger( CMS_VERSION ) +
			 ( int ) sizeofObject( issuerAndSerialNumberSize ) +
			 sizeofAlgoID( hashAlgorithm ) + attributeSize + signatureSize;

	/* Write the outer SEQUENCE wrapper and version number */
	writeSequence( stream, length );
	writeShortInteger( stream, CMS_VERSION, DEFAULT_TAG );

	/* Write the issuer name and serial number, and digest algorithm
	   identifier */
	writeSequence( stream, issuerAndSerialNumberSize );
	swrite( stream, signerInfoPtr->issuerDNptr, signerInfoPtr->issuerDNsize );
	writeInteger( stream, signerInfoPtr->serialNumber, 
				  signerInfoPtr->serialNumberLength, DEFAULT_TAG );
	writeAlgoID( stream, hashAlgorithm );

	/* Write the attributes (if there are any) and signature */
	if( attributeSize )
		swrite( stream, attributes, attributeSize );
	swrite( stream, signature, signatureSize );

	unlockResourceExit( signerInfoPtr, sGetStatus( stream ) );
	}
