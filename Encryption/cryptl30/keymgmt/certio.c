/****************************************************************************
*																			*
*						Certificate Import/Export Routines					*
*						Copyright Peter Gutmann 1997-1999					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
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

/* Context-specific tags for attribute certificates */

enum { CTAG_AC_BASECERTIFICATEID, CTAG_AC_ENTITYNAME,
	   CTAG_AC_OBJECTDIGESTINFO };

/* Oddball OID's which may be used to wrap certs */

#define OID_X509_USERCERTIFICATE	"\x06\x03\x55\x04\x24"

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Determine whether an object is a certificate, attribute certificate, CRL,
   certification request, PKCS #7 certificate chain, Netscape certificate
   sequence, or Netscape SignedPublicKeyAndChallenge, and how long the total
   object is.  If fed an unknown object we can determine its type at runtime
   (although it's hardly LL(1)) and import it as appropriate.  The start of
   the various object types are:

	1a.	SEQUENCE {
	1b.	[0] {										-- CMS attrs if present
	2a		contentType			OBJECT IDENTIFIER,	-- Cert chain/seq if present
	2b.		SEQUENCE {
				version		[0]	INTEGER DEFAULT(0),	-- Cert if present
	3a.			version			INTEGER (0),		-- For cert request
	3b.			version			INTEGER DEFAULT(0),	-- For CRL
	3c.			version			INTEGER DEFAULT(1),	-- For attribute cert
	3d.			serialNumber	INTEGER,			-- For cert
	3e.			certReqID		INTEGER,			-- For CRMF request
													-- CRL or SPKAC if absent
	4a.			owner		[0] or [1] or [2]		-- Attribute cert
								-- Note that this doesn't clash with the
								-- cert version since this is an explicit
								-- constructed tag and the cert version is
								-- implicit primitive
	4b.			SEQUENCE {							-- DN or AlgoID or CertTemplate
	5a.				SET {							-- CertRequest if present
	5b.				algo		OBJECT IDENTIFIER,	-- Cert or CRL if present
	5c.				SEQUENCE { ... }				-- SPKAC if present
	5d.				template	[0]...[6] ANY		-- CRMF request if present
					...
					}
	6			SEQUENCE { ... }					-- DN for Cert and CRL
	7a			SEQUENCE {							-- Cert if present
	7b			UTCTime								-- CRL if present

   This means that sorting out which is which involves quite a bit of
   lookahead.  The fact that the version and serial number integers clash
   for the raw certificate objects doesn't help much either */

static int decodeCertWrapper( STREAM *stream, int *offset )
	{
	BYTE buffer[ 32 ];
	BOOLEAN isCertChain = FALSE;
	int bufferLength, value, status;

	/* Read the contentType OID, determine the content type based on it,
	   and read the content encapsulation and header.  It can be either
	   a PKCS #7 cert chain, a Netscape cert sequence, or an X.509
	   userCertificate (which is just an oddball cert wrapper) */
	status = readRawObject( stream, buffer, &bufferLength, 32, 
							BER_OBJECT_IDENTIFIER );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_BADDATA );
	if( !memcmp( buffer, OID_CMS_SIGNEDDATA, bufferLength ) )
		isCertChain = TRUE;
	else
		if( !memcmp( buffer, OID_X509_USERCERTIFICATE, bufferLength ) )
			{
			/* Oddball wrapper type, set the payload offset to point to 
			   the certificate and indicate no wrapper present */
			*offset = ( int ) stell( stream );
			status = readSequence( stream, NULL );
			return( cryptStatusError( status ) ? \
					status : CRYPT_CERTTYPE_NONE );
			}
		else
			if( memcmp( buffer, OID_NS_CERTSEQ, bufferLength ) )
				return( CRYPT_ERROR_BADDATA );
	if( cryptStatusError( readConstructed( stream, NULL, 0 ) ) || \
		cryptStatusError( readSequence( stream, NULL ) ) )
		return( CRYPT_ERROR_BADDATA );

	/* If it's a PKCS #7 certificate chain, burrow into the inner PKCS #7
	   content */
	if( isCertChain )
		{
		long integer;

		/* Read the version number (1 = PKCS #7 v1.5, 2 = PKCS #7 v1.6,
		   3 = S/MIME with attribute certificate(s)) and SET OF
		   DigestAlgorithmIdentifier (this is empty for a pure cert chain,
		   nonempty for signed data) */
		if( cryptStatusError( readShortInteger( stream, &integer ) ) || \
											integer < 1 || integer > 3 || \
			cryptStatusError( readSet( stream, &value ) ) )
			return( CRYPT_ERROR_BADDATA );
		if( value )
			sSkip( stream, value );

		/* Read the ContentInfo header, contentType OID and the inner
		   content encapsulation */
		if( cryptStatusError( readSequence( stream, NULL ) ) )
			return( CRYPT_ERROR_BADDATA );
		status = readRawObject( stream, buffer, &bufferLength, 32, 
								BER_OBJECT_IDENTIFIER );
		if( cryptStatusError( status ) || \
			memcmp( buffer, OID_CMS_DATA, bufferLength ) )
			return( CRYPT_ERROR_BADDATA );
		checkEOC( stream );
		if( cryptStatusError( readConstructed( stream, NULL, 0 ) ) )
			return( CRYPT_ERROR_BADDATA );
		}

	/* We've finally reached the certificate(s), retry the read of the
	   certificate start */
	status = readSequence( stream, NULL );
	return( cryptStatusError( status ) ? status : CRYPT_CERTTYPE_CERTCHAIN );
	}

static int getCertObjectInfo( const void *object, const int objectTotalLength,
							  int *objectOffset, int *objectLength, 
							  CRYPT_CERTTYPE_TYPE *objectType,
							  const CERTFORMAT_TYPE formatType )
	{
	STREAM stream;
	CRYPT_CERTTYPE_TYPE wrapperType = CRYPT_CERTTYPE_NONE;
	CRYPT_CERTTYPE_TYPE type = CRYPT_CERTTYPE_NONE;
	int totalLength, innerLength, innerStart, value, sequenceLength, status;
	long length;

	/* Set initial default values */
	*objectOffset = 0;
	*objectLength = CRYPT_ERROR;
	*objectType = CRYPT_ERROR;

	sMemConnect( &stream, object, objectTotalLength );

	/* If it's an SSL cert chain there's no recognisable tagging, however the
	   caller will have told us what it is */
	if( formatType == CERTFORMAT_SSLCHAIN )
		{
		BYTE *objectPtr = ( void * ) object;

		*objectLength = objectTotalLength;
		*objectOffset = 0;
		*objectType = CRYPT_CERTTYPE_SSL_CERTCHAIN;
		return( CRYPT_OK );
		}

	/* First we check for the easy one, CMS attributes whose contents are
	   always DER-encoded and which begin with a [0] IMPLICIT SET followed 
	   by a SEQUENCE */
	if( peekTag( &stream ) == MAKE_CTAG( 0 ) || \
		formatType == CERTFORMAT_CERTSET )
		{
		/* Determine the length of the object.  Since the SET OF Certificate
		   can be BER-encoded, we look down one level to the contents if
		   necessary */
		readTag( &stream );
		readLength( &stream, &length );
		status = readSequence( &stream, &innerLength );
		if( !length )
			length = sizeofObject( innerLength );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );
		*objectLength = ( int ) sizeofObject( length );
		*objectType = ( formatType == CERTFORMAT_CERTSET ) ? \
				CRYPT_CERTTYPE_CMS_CERTSET : CRYPT_CERTTYPE_CMS_ATTRIBUTES;
		return( CRYPT_OK );
		}

	/* Check that the start of the object is in order.  We may get a
	   totalLength value of zero if the outer wrapper is encoded using the
	   BER instead of the DER, at least one oddball implementation does
	   this, so we remember where the inner sequence data starts so we can
	   skip over it later to find the rest of the data and determine its
	   length */
	status = readSequence( &stream, &totalLength );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	if( totalLength )
		totalLength += status;	/* Add length of sequence header */

	/* If it's a PKCS #7 certificate chain or Netscape cert.sequence,
	   there'll be an object identifier present.  Some sources also wrap
	   certs up on oddball OID's, so we check for these as well */
	if( peekTag( &stream ) == BER_OBJECT_IDENTIFIER )
		{
		status = decodeCertWrapper( &stream, objectOffset );
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( status );
			}
		wrapperType = status;
		type = CRYPT_CERTTYPE_CERTIFICATE;
		}

	/* Read the inner sequence */
	status = readSequence( &stream, &innerLength );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	innerStart = ( int ) stell( &stream );

	/* If it's a certificate, there may be a version number present */
	if( peekTag( &stream ) == MAKE_CTAG( 0 ) )
		{
		long integer;

		/* Look for an integer value of 1 or 2 */
		status = readConstructed( &stream, NULL, 0 );
		if( !cryptStatusError( status ) )
			status = readShortInteger( &stream, &integer );
		if( cryptStatusError( status ) || integer < 1 || integer > 2 )
			{
			sMemDisconnect( &stream );
			return( CRYPT_ERROR_BADDATA );
			}

		/* If we find this then it's definitely a v2 or v3 certificate */
		type = CRYPT_CERTTYPE_CERTIFICATE;
		}

	/* If it's a CRL, there may be no version number present */
	if( checkReadTag( &stream, BER_INTEGER ) )
		{
		/* If there's an integer present, it's either 0 for a cert.request,
		   1 for a v2 CRL, or any value (including bignums) for a CRMF
		   request or certificate.  We don't care about this value much, all 
		   we do is check that it's there */
		if( cryptStatusError( readLength( &stream, &length ) ) || length < 1 )
			{
			sMemDisconnect( &stream );
			return( CRYPT_ERROR_BADDATA );
			}
		sSkip( &stream, length );
		}
	else
		/* No integer at this point, it's either a v1 CRL or a SPKAC.  For
		   now we guess a CRL, this is adjusted to a SPKAC later if
		   necessary */
		type = CRYPT_CERTTYPE_CRL;

	/* If it's a constructed context-specific tag, it's an attribute
	   certificate.  Note that the [0] variant doesn't clash with the tagged
	   version number in a certificate since here it's constructed while for
	   the version number it's primitive */
	value = peekTag( &stream );
	if( value == MAKE_CTAG( CTAG_AC_BASECERTIFICATEID ) || \
		value == MAKE_CTAG( CTAG_AC_ENTITYNAME ) || \
		value == MAKE_CTAG( CTAG_AC_OBJECTDIGESTINFO ) )
		{
		readTag( &stream );		/* Skip the tagging */
		if( cryptStatusError( readLength( &stream, NULL ) ) )
			return( CRYPT_ERROR_BADDATA );
		type = CRYPT_CERTTYPE_ATTRIBUTE_CERT;
		}

	/* Next is another SEQUENCE, either the DN for a cert request, an
	   AlgorithmIdentifier for a cert or CRL, the payload for a CRMF cert
	   request, or one of a variety of types for attribute certs */
	status = readSequence( &stream, &sequenceLength );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( CRYPT_ERROR_BADDATA );
		}

	/* If it's an attribute cert, we've made a positive ID */
	if( type == CRYPT_CERTTYPE_ATTRIBUTE_CERT )
		status = CRYPT_OK;
	else
		{
		/* Next is either an OBJECT IDENTIFIER for a cert or CRL, a SET for 
		   a cert request, or a tag from [0] to [6] for a CRMF.  Since CRMF
		   allows the requester to specify arbitrary (and totally illogical)
		   certificate contents, we could in theory end up with any kind of
		   tag, however we have to at least have a [6] (for the public key)
		   so we can stop looking there */
		status = CRYPT_ERROR_BADDATA;
		value = readTag( &stream );
		if( value == BER_SET && type == CRYPT_CERTTYPE_NONE )
			{
			type = CRYPT_CERTTYPE_CERTREQUEST;
			status = CRYPT_OK;
			}
		else
			if( value == BER_OBJECT_IDENTIFIER )
				{
				/* Skip the algorithm identifier and subject/issuer DN */
				sSkip( &stream, sequenceLength - 1 );
				if( cryptStatusError( readUniversal( &stream ) ) )
					status = CRYPT_ERROR_BADDATA;
				else
					{
					/* Next is either a SEQUENCE for a cert or a UTCTime or
					   GeneralisedTime for a CRL */
					value = readTag( &stream );
					if( value == BER_SEQUENCE && \
						( type == CRYPT_CERTTYPE_NONE || \
						  type == CRYPT_CERTTYPE_CERTIFICATE ) )
						{
						type = CRYPT_CERTTYPE_CERTIFICATE;
						status = CRYPT_OK;
						}
					else
						if( ( value == BER_TIME_UTC || \
							  value == BER_TIME_GENERALIZED ) && \
							( type == CRYPT_CERTTYPE_NONE || \
							  type == CRYPT_CERTTYPE_CRL ) )
							{
							type = CRYPT_CERTTYPE_CRL;
							status = CRYPT_OK;
							}
					}
				}
			else
				/* If it's another sequence (the start of the
				   AlgorithmIdentifier) followed by a BIT STRING, it's a
				   SPKAC */
				if( value == BER_SEQUENCE && \
					!cryptStatusError( readUniversalData( &stream ) ) && \
					readTag( &stream ) == BER_BITSTRING )
					{
					type = CRYPT_CERTTYPE_NS_SPKAC;
					status = CRYPT_OK;
					}
				else
					/* If it's a tag from [0] to [6] it's a CRMF request */
					if( value >= MAKE_CTAG( 0 ) && value <= MAKE_CTAG( 6 ) )
						{
						type = CRYPT_CERTTYPE_CRMF_REQUEST;
						status = CRYPT_OK;
						}
		if( cryptStatusError( status ) )
			{
			sMemDisconnect( &stream );
			return( CRYPT_ERROR_BADDATA );
			}
		}

	/* If the outer wrapper is encoded using the BER, we need to move past
	   the payload and find out how big the signature is */
	if( !totalLength )
		{
		/* Skip over the signed object, then check for and skip over the
		   signature algorithm information and signature fields.  Once we've
		   done this we've reached the end of the object which tells us its
		   total length */
		sseek( &stream, innerStart + innerLength );
		if( cryptStatusError( readSequence( &stream, &sequenceLength ) ) || \
			sequenceLength < 8 )
			status = CRYPT_ERROR_BADDATA;
		else
			{
			sSkip( &stream, sequenceLength );
			if( readTag( &stream ) != BER_BITSTRING || \
				cryptStatusError( readLength( &stream, &length ) ) || \
				length < 32 )
				status = CRYPT_ERROR_BADDATA;
			else
				{
				sSkip( &stream, ( int ) length );
				totalLength = ( int ) stell( &stream );
				}
			}
		}
	if( cryptStatusOK( status ) && \
		cryptStatusError( sGetStatus( &stream ) ) )
		/* We ran out of input, we can't process this object */
		status = CRYPT_ERROR_BADDATA;
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* We're done, tell the caller what we found */
	*objectLength = totalLength;
	*objectType = ( wrapperType != CRYPT_CERTTYPE_NONE ) ? wrapperType : type;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Import/Export Functions						*
*																			*
****************************************************************************/

/* Import a certificate object.  If the import type is set to create a data-
   only cert, its publicKeyInfo pointer is set to the start of the encoded 
   public key to allow it to be decoded later.  Returns the length of the 
   certificate */

int importCert( const void *certObject, const int certObjectLength,
				CRYPT_CERTIFICATE *certificate,
				const CERTIMPORT_TYPE importType,
				const CERTFORMAT_TYPE formatType )
	{
	CERT_INFO *certInfoPtr;
	CRYPT_CERTFORMAT_TYPE format = CRYPT_CERTFORMAT_NONE;
	CRYPT_CERTTYPE_TYPE type;
	STREAM stream;
	int ( *readCertObjectFunction )( STREAM *stream, CERT_INFO *certInfoPtr );
	void *certObjectPtr = ( void * ) certObject, *certBuffer;
	int length, offset, initStatus = CRYPT_OK, status;

	*certificate = CRYPT_ERROR;

	/* If it's not a special-case format, check whether it's an S/MIME or 
	   base64-encoded certificate object */
	if( formatType == CERTFORMAT_NORMAL )
		{
		if( ( length = smimeCheckHeader( certObject, 
										 certObjectLength ) ) != 0 )
			format = CRYPT_ICERTFORMAT_SMIME_CERTIFICATE;
		else
			if( ( length = base64checkHeader( certObject, 
											  certObjectLength ) ) != 0 )
				format = CRYPT_CERTFORMAT_TEXT_CERTIFICATE;
		if( length )
			{
			int decodedLength;

			/* It's base64 / S/MIME-encoded, decode it into a temporary 
			   buffer */
			decodedLength = base64decodeLen( ( const char * ) certObject + length,
											 certObjectLength );
			if( decodedLength <= 128 || decodedLength > 8192 )
				return( CRYPT_ERROR_BADDATA );
			if( ( certObjectPtr = malloc( decodedLength ) ) == NULL )
				return( CRYPT_ERROR_MEMORY );
			if( !base64decode( certObjectPtr, ( const char * ) certObject +
							   length, 0, format ) )
				{
				free( certObjectPtr );
				return( CRYPT_ERROR_BADDATA );
				}
			}
		}

	/* Check the object to determine its type and length, and check the
	   encoding if necessary */
	status = getCertObjectInfo( certObjectPtr, certObjectLength, &offset, 
								&length, &type, formatType );
	if( !cryptStatusError( status ) && formatType != CERTFORMAT_SSLCHAIN )
		{
		int doCheckEncoding;

		krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
						 &doCheckEncoding, CRYPT_OPTION_CERT_CHECKENCODING );
		if( doCheckEncoding )
			status = checkEncoding( certObjectPtr, length );
		}
	if( cryptStatusError( status ) )
		{
		if( certObjectPtr != certObject )
			free( certObjectPtr );
		return( status );
		}
	status = CRYPT_OK;	/* checkEncoding() returns a length */

	/* If it's a cert chain, this is handled specially since we need to
	   import a plurality of certs at once */
	if( type == CRYPT_CERTTYPE_CERTCHAIN || \
		type == CRYPT_CERTTYPE_CMS_CERTSET || \
		type == CRYPT_CERTTYPE_SSL_CERTCHAIN )
		{
		/* Read the cert chain into a collection of internal cert resources.
		   This returns a handle to the leaf cert in the chain, with the
		   remaining certs being accessible within it via the cert cursor
		   functions */
		sMemConnect( &stream, ( BYTE * ) certObjectPtr + offset, length );
		if( type == CRYPT_CERTTYPE_CERTCHAIN )
			readSequence( &stream, NULL );	/* Skip the outer wrapper */
		status = readCertChain( &stream, certificate, type, importType );
		sMemDisconnect( &stream );
		if( certObjectPtr != certObject )
			free( certObjectPtr );
		if( cryptStatusError( status ) )
			return( status );
		return( length );
		}

	/* Select the function to use to read the certificate object */
	switch( type )
		{
		case CRYPT_CERTTYPE_CERTIFICATE:
			readCertObjectFunction = readCertInfo;
			break;

		case CRYPT_CERTTYPE_ATTRIBUTE_CERT:
			readCertObjectFunction = readAttributeCertInfo;
			break;

		case CRYPT_CERTTYPE_CERTREQUEST:
			readCertObjectFunction = readCertRequestInfo;
			break;

		case CRYPT_CERTTYPE_CRMF_REQUEST:
			readCertObjectFunction = readCRMFRequestInfo;
			break;

		case CRYPT_CERTTYPE_CRL:
			readCertObjectFunction = readCRLInfo;
			break;

		case CRYPT_CERTTYPE_NS_SPKAC:
			readCertObjectFunction = readSPKACInfo;
			break;

		case CRYPT_CERTTYPE_CMS_ATTRIBUTES:
			readCertObjectFunction = readCMSAttributes;
			break;

		default:
			assert( NOTREACHED );
		}

	/* Allocate a buffer to store a copy of the object so we can preserve the
	   original for when it's needed again later, and try and create the
	   certificate object.  All the objects (including the CMS attributes,
	   which in theory aren't needed for anything further) need to be kept
	   around in their encoded form, which is often incorrect and therefore
	   can't be reconstructed.  The readXXX() function record pointers to the
	   required encoded fields so they can be recovered later in their
	   (possibly incorrect) form, and these pointers need to be to a
	   persistent copy of the encoded object.  In addition the cert objects
	   need to be kept around anyway for sig checks and possible re-export */
	if( ( certBuffer = malloc( length ) ) == NULL )
		status = CRYPT_ERROR_MEMORY;
	if( cryptStatusOK( status ) )
		/* Create the certificate object */
		status = createCertificateInfo( &certInfoPtr, type );
	if( cryptStatusError( status ) )
		{
		if( certObjectPtr != certObject )
			free( certObjectPtr );
		free( certBuffer );
		return( status );
		}
	*certificate = status;

	/* If we're doing a deferred read of the public key components (they'll
	   be decoded later when we know whether we need them), set the data-only
	   flag to ensure we don't try to decode them */
	certInfoPtr->dataOnly = ( importType == CERTIMPORT_DATA_ONLY ) ? TRUE : FALSE;

	/* Copy in the certificate object for later use */
	memcpy( certBuffer, ( BYTE * ) certObjectPtr + offset, length );
	certInfoPtr->certificate = certBuffer;
	certInfoPtr->certificateSize = length;

	/* Parse the object into the certificate.  Note that we have to use the
	   copy in the certBuffer rather than the original since the readXXX()
	   functions record pointers to various encoded fields */
	sMemConnect( &stream, certBuffer, length );
	if( type != CRYPT_CERTTYPE_CMS_ATTRIBUTES )
		readSequence( &stream, NULL );	/* Skip the outer wrapper */
	status = readCertObjectFunction( &stream, certInfoPtr );
	sMemDisconnect( &stream );
	if( certObjectPtr != certObject )
		free( certObjectPtr );
	if( cryptStatusError( status ) )
		{
		/* The import failed, make sure the object gets destroyed when we 
		   notify the kernel that the setup process is complete */
		krnlSendNotifier( *certificate, RESOURCE_IMESSAGE_DESTROY );
		initStatus = status;
		}
	else
		/* If this is a type of object which has a public key associated with 
		   it, notify the kernel that the given context is attached to the 
		   cert.  This is an internal object used only by the cert so we tell 
		   the kernel not to increment its reference count when it attaches
		   it*/
		if( certInfoPtr->iCryptContext != CRYPT_ERROR )
			krnlSendMessage( *certificate, RESOURCE_IMESSAGE_SETDEPENDENT,
							 &certInfoPtr->iCryptContext, FALSE );

	/* We've finished setting up the object-type-specific info, tell the 
	   kernel the object is ready for use and mark it as initialised (we
	   can't do this before the initialisation is complete because the
	   kernel won't forward the message to a partially-initialised object) */
	unlockResource( certInfoPtr );
	status = krnlSendMessage( *certificate, RESOURCE_IMESSAGE_SETATTRIBUTE, 
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusError( initStatus ) || cryptStatusError( status ) )
		{
		*certificate = CRYPT_ERROR;
		return( cryptStatusError( initStatus ) ? initStatus : status );
		}
	krnlSendMessage( *certificate, RESOURCE_IMESSAGE_SETATTRIBUTE,
					 MESSAGE_VALUE_UNUSED, CRYPT_IATTRIBUTE_INITIALISED );
	return( length );
	}

/* Export a certificate/certification request.  This just writes the
   internal encoded object to an external buffer.  For cert/cert chain export
   the possibilities are as follows:

						Export
	Type  |		Cert				Chain
	------+--------------------+---------------
	Cert  | Cert			   | Cert as chain
		  |					   |
	Chain | Currently selected | Chain
		  | cert in chain	   |					*/

int exportCert( void *certObject, int *certObjectLength,
				const CRYPT_CERTFORMAT_TYPE certFormatType,
				const CERT_INFO *certInfoPtr )
	{
	/* If it's a binary format, the base format is the actual format type.
	   If it's a text (base64) format, the base format is given by subtracting
			the difference between the text and binary formats */
	const CRYPT_CERTFORMAT_TYPE baseFormatType = \
		( certFormatType < CRYPT_CERTFORMAT_TEXT_CERTIFICATE ) ? \
			certFormatType : 
			certFormatType - ( CRYPT_CERTFORMAT_TEXT_CERTIFICATE - 1 );
	STREAM stream;
	void *buffer;
	int length, encodedLength, status;

	/* Determine how big the output object will be */
	if( baseFormatType == CRYPT_CERTFORMAT_CERTCHAIN )
		{
		STREAM nullStream;
		int status;

		assert( certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
				certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN );

		sMemOpen( &nullStream, NULL, 0 );
		status = writeCertChain( &nullStream, certInfoPtr );
		length = ( int ) stell( &nullStream );
		sMemClose( &nullStream );
		if( cryptStatusError( status ) )
			return( status );
		}
	else
		length = certInfoPtr->certificateSize;
	encodedLength = ( certFormatType >= CRYPT_CERTFORMAT_TEXT_CERTIFICATE ) ? \
		base64encodeLen( length, certInfoPtr->type ) : length;

	/* Set up the length information */
	*certObjectLength = encodedLength;
	if( certObject == NULL )
		return( CRYPT_OK );
	if( checkBadPtrWrite( certObject, encodedLength ) )
		return( CRYPT_ERROR_PARAM1 );

	/* If it's a simple object, write either the DER-encoded object or its
	   base64 / S/MIME-encoded form directly to the output */
	if( certFormatType == CRYPT_CERTFORMAT_CERTIFICATE )
		{
		memcpy( certObject, certInfoPtr->certificate, length );
		return( CRYPT_OK );
		}
	if( certFormatType == CRYPT_CERTFORMAT_TEXT_CERTIFICATE )
		{
		base64encode( certObject, certInfoPtr->certificate,
					  certInfoPtr->certificateSize, certInfoPtr->type );
		return( CRYPT_OK );
		}

	/* It's a straight cert chain, write it directly to the output */
	if( certFormatType == CRYPT_CERTFORMAT_CERTCHAIN )
		{
		sMemOpen( &stream, certObject, length );
		status = writeCertChain( &stream, certInfoPtr );
		sMemDisconnect( &stream );
		return( status );
		}

	/* It's a base64 / S/MIME-encoded cert chain, write it to a temporary
	   buffer and then encode it to the output */
	if( ( buffer = malloc( length ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	sMemOpen( &stream, buffer, length );
	status = writeCertChain( &stream, certInfoPtr );
	if( cryptStatusOK( status ) )
		base64encode( certObject, buffer, length, CRYPT_CERTTYPE_CERTCHAIN );
	sMemClose( &stream );
	free( buffer );

	return( status );
	}
