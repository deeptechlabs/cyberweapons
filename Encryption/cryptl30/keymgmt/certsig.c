/****************************************************************************
*																			*
*					  Certificate Signing/Checking Routines					*
*						Copyright Peter Gutmann 1997-1999					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "asn1.h"
  #include "cert.h"
#else
  #include "keymgmt/asn1.h"
  #include "keymgmt/cert.h"
#endif /* Compiler-specific includes */

/* Prototypes for functions in lib_sign.c */

int createX509signature( void *signedObject, int *signedObjectLength,
						 const void *object, const int objectLength,
						 CRYPT_CONTEXT signContext,
						 const CRYPT_ALGO hashAlgo );
int checkX509signature( const void *signedObject, void **object,
						int *objectLength, CRYPT_CONTEXT sigCheckContext );

/* Sign a certificate object */

int signCert( CERT_INFO *certInfoPtr, const CRYPT_CONTEXT signContext )
	{
	CERT_INFO *issuerCertInfoPtr;
	STREAM stream;
	BOOLEAN issuerCertPresent = FALSE, isCertificate = FALSE;
	int ( *writeCertObjectFunction )( STREAM *stream, CERT_INFO *subjectCertInfoPtr,
									  const CERT_INFO *issuerCertInfoPtr,
									  const CRYPT_CONTEXT iIssuerCryptContext );
	void *certObject, *signedCertObject;
	const time_t currentTime = time( NULL );
	long serialNumber;
	int certObjectLength, signedCertObjectLength, dataLength, status;

	/* Obtain the issuer certificate from the private key if necessary */
	if( certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
		certInfoPtr->type == CRYPT_CERTTYPE_ATTRIBUTE_CERT || \
		certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN )
		isCertificate = TRUE;
	if( isCertificate || certInfoPtr->type == CRYPT_CERTTYPE_CRL )
		{
		/* If it's a self-signed cert, the issuer is also the subject */
		if( certInfoPtr->selfSigned )
			issuerCertInfoPtr = certInfoPtr;
		else
			{
			CRYPT_CERTIFICATE dataOnlyCert;

			/* Get the data-only certificate from the context */
			status = krnlSendMessage( signContext, 
								RESOURCE_IMESSAGE_GETDEPENDENT, &dataOnlyCert,
								OBJECT_TYPE_CERTIFICATE );
			if( cryptStatusError( status ) )
				return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
						CRYPT_ARGERROR_VALUE : status );
			getCheckInternalResource( dataOnlyCert, issuerCertInfoPtr,
									  OBJECT_TYPE_CERTIFICATE );
			issuerCertPresent = TRUE;
			}

		/* Make sure the key associated with the issuer cert is valid for
		   cert/CRL signing: We need a key+complete certificate (unless we're
		   creating a self-signed cert), and the cert has to allow the key to
		   be used for cert/CRL signing */
		if( ( issuerCertInfoPtr->type != CRYPT_CERTTYPE_CERTIFICATE && \
			  issuerCertInfoPtr->type != CRYPT_CERTTYPE_CERTCHAIN ) || \
			( issuerCertPresent && issuerCertInfoPtr->certificate == NULL ) )
			status = CRYPT_ARGERROR_VALUE;
		else
			status = checkCertUsage( issuerCertInfoPtr, ( isCertificate ) ? \
						CRYPT_KEYUSAGE_KEYCERTSIGN : CRYPT_KEYUSAGE_CRLSIGN,
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );
		if( cryptStatusError( status ) )
			{
			if( issuerCertPresent )
				unlockResource( issuerCertInfoPtr );
			return( status );
			}
		}

	/* If it's a certificate chain, copy over the signing cert and order the
	   certificates in the chain from the current one up to the root */
	if( certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN )
		{
		/* If there's a chain of certs present (for example from a previous
		   signing attempt which wasn't completed due to an error), free
		   them */
		if( certInfoPtr->certChainEnd )
			{
			int i;

			for( i = 0; i < certInfoPtr->certChainEnd; i++ )
				krnlSendNotifier( certInfoPtr->certChain[ i ],
								  RESOURCE_IMESSAGE_DECREFCOUNT );
			certInfoPtr->certChainEnd = 0;
			}

		/* If it's a self-signed cert, it must be the only cert in the chain
		   (creating a chain like this doesn't make much sense, but we handle
		   it anyway) */
		if( certInfoPtr->selfSigned )
			{
			if( certInfoPtr->certChainEnd )
				{
				setErrorInfo( certInfoPtr, CRYPT_CERTINFO_CERTIFICATE,
							  CRYPT_ERRTYPE_ATTR_PRESENT );
				return( CRYPT_ERROR_INVALID );
				}
			}
		else
			{
			/* Copy the cert chain into the cert to be signed */
			status = copyCertChain( certInfoPtr, signContext );
			if( cryptStatusError( status ) )
				return( status );
			}
		}

	/* If it's some certificate variant or CRL and the various timestamps
	   haven't been set yet, start them at the current time and give them the
	   default validity period or next update time if these haven't been set.
	   The time used is the local time, this is converted to GMT when we
	   write it to the certificate.  Issues like validity period nesting and
	   checking for valid time periods are handled when the data is encoded */
	if( ( isCertificate || certInfoPtr->type == CRYPT_CERTTYPE_CRL ) && \
		!certInfoPtr->startTime )
		certInfoPtr->startTime = currentTime;
	if( isCertificate && !certInfoPtr->endTime )
		{
		int validity;

		krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
						 &validity, CRYPT_OPTION_CERT_VALIDITY );
		certInfoPtr->endTime = certInfoPtr->startTime + \
							   ( ( time_t ) validity * 86400L );
		}
	if( certInfoPtr->type == CRYPT_CERTTYPE_CRL )
		{
		if( !certInfoPtr->endTime )
			{
			int updateInterval;

			krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
							 &updateInterval, CRYPT_OPTION_CERT_UPDATEINTERVAL );

			certInfoPtr->endTime = certInfoPtr->startTime + \
								   ( ( time_t ) updateInterval * 86400L );
			}
		if( !certInfoPtr->revocationTime )
			certInfoPtr->revocationTime = currentTime;
		}

	/* If it's a certificate, set up the certificate serial number.  Ideally
	   we would store this as a static value in the configuration database,
	   but this has three disadvantages: Updating the serial number updates
	   the entire configuration database (including things the user might not
	   want updated), if the config database update fails the serial number
	   never changes, and the predictable serial number allows tracking of
	   the number of certificates which have been signed by the CA, which is
	   both nasty if various braindamaged government regulation attempts ever
	   come to fruition, and a potential problem if a CA ends up revealing
	   just how few certs it's actually signing.  Because of this, we use the
	   time in seconds since 1 Jan 1999 as the serial number, which should
	   yield unique numbers and doesn't leak any real information (the
	   validity period will probably be the same as the serial number
	   timestamp).  We don't have to worry about the rare case where the
	   system clock is set before the current date since we'll just end up
	   with a very large serial number (the unsigned interpretation of the
	   negative time offset) */
	if( isCertificate )
		{
		BYTE *dataPtr;

		serialNumber = currentTime - 0x3682E000L;
		dataLength = ( serialNumber <= 0xFFFFFFL ) ? 3 : 4;
		if( ( dataPtr = malloc( dataLength ) ) == NULL )
			{
			if( issuerCertPresent )
				unlockResource( issuerCertInfoPtr );
			return( CRYPT_ERROR_MEMORY );
			}
		if( certInfoPtr->serialNumber != NULL )
			free( certInfoPtr->serialNumber );

		/* Copy in the serial number as a big-endian integer value */
		certInfoPtr->serialNumber = dataPtr;
		certInfoPtr->serialNumberLength = dataLength;
		if( dataLength == 4 )
			*dataPtr++ = ( BYTE ) ( serialNumber >> 24 );
		*dataPtr++ = ( BYTE ) ( serialNumber >> 16 );
		*dataPtr++ = ( BYTE ) ( serialNumber >> 8 );
		*dataPtr = ( BYTE ) ( serialNumber );
		}

	/* Select the function to use to write the certificate object to be
	   signed */
	switch( certInfoPtr->type )
		{
		case CRYPT_CERTTYPE_CERTIFICATE:
		case CRYPT_CERTTYPE_CERTCHAIN:
			writeCertObjectFunction = writeCertInfo;
			break;

		case CRYPT_CERTTYPE_ATTRIBUTE_CERT:
			writeCertObjectFunction = writeAttributeCertInfo;
			break;

		case CRYPT_CERTTYPE_CERTREQUEST:
			writeCertObjectFunction = writeCertRequestInfo;
			break;

		case CRYPT_CERTTYPE_CRMF_REQUEST:
			writeCertObjectFunction = writeCRMFRequestInfo;
			break;

		case CRYPT_CERTTYPE_CRL:
			writeCertObjectFunction = writeCRLInfo;
			break;

		default:
			assert( NOTREACHED );
		}

	/* Determine how big the encoded certificate information will be,
	   allocate memory for it and the full signed certificate, and write the
	   encoded certificate information */
	sMemOpen( &stream, NULL, 0 );
	status = writeCertObjectFunction( &stream, certInfoPtr, issuerCertInfoPtr,
									  signContext );
	certObjectLength = ( int ) stell( &stream );
	sMemClose( &stream );
	if( cryptStatusError( status ) )
		{
		if( issuerCertPresent )
			unlockResource( issuerCertInfoPtr );
		return( status );
		}
	if( ( certObject = malloc( certObjectLength ) ) == NULL || \
		( signedCertObject = malloc( certObjectLength + 1024 ) ) == NULL )
		{
		if( certObject != NULL )
			free( certObject );
		if( issuerCertPresent )
			unlockResource( issuerCertInfoPtr );
		return( CRYPT_ERROR_MEMORY );
		}
	sMemOpen( &stream, certObject, certObjectLength );
	status = writeCertObjectFunction( &stream, certInfoPtr, issuerCertInfoPtr,
									  signContext );
	sMemDisconnect( &stream );
	if( issuerCertPresent )
		unlockResource( issuerCertInfoPtr );
	if( cryptStatusError( status ) )
		{
		zeroise( certObject, certObjectLength );
		free( certObject );
		free( signedCertObject );
		return( status );
		}

	/* Sign the certificate information and assign it to the certificate
	   context */
	status = createX509signature( signedCertObject, &signedCertObjectLength,
								  certObject, certObjectLength, signContext,
								  CRYPT_ALGO_SHA );
	if( cryptStatusOK( status ) )
		{
		certInfoPtr->certificate = signedCertObject;
		certInfoPtr->certificateSize = signedCertObjectLength;

		/* CRMF uses a signature format which is almost, but not quite, 
		   right, so we have to rewrite the signature slightly to use the
		   nonstandard format.  Rewriting it here is easier than trying to
		   pass a "use nonstandard signature format" flag down 20 levels of
		   function calls to have it done by the signature-generation code */
		if( certInfoPtr->type == CRYPT_CERTTYPE_CRMF_REQUEST )
			{
			BYTE *payloadStart;
			int totalSize, sigSize;

			/* Rewrite the outer wrapper to account for the overhead of the
			   extra tag, copy down the payload, and re-wrap the signature
			   in an extra [1] tag */
			sMemConnect( &stream, signedCertObject, signedCertObjectLength );
			readSequence( &stream, &totalSize );	/* Outer wrapper */
			payloadStart = sMemBufPtr( &stream );
			sigSize = totalSize - certObjectLength;
			sseek( &stream, 0 );
			memmove( payloadStart + 16, payloadStart, totalSize );
			writeSequence( &stream, 
						   certObjectLength + sizeofObject( sigSize ) );
			memmove( sMemBufPtr( &stream ), payloadStart + 16, certObjectLength );
			sSkip( &stream, certObjectLength );
			writeConstructed( &stream, sigSize, 1 );
			memmove( sMemBufPtr( &stream ), payloadStart + 16 + certObjectLength,
					 sigSize );
			sMemDisconnect( &stream );
			
			/* Adjust the size of the cert object to account for the extra tag */
			certInfoPtr->certificateSize = \
					sizeofObject( certObjectLength + sizeofObject( sigSize ) );
			}

		/* If it's a certification request, it's now self-signed */
		if( certInfoPtr->type == CRYPT_CERTTYPE_CERTREQUEST || \
			certInfoPtr->type == CRYPT_CERTTYPE_CRMF_REQUEST )
			certInfoPtr->selfSigned = TRUE;

		/* If it's a cert chain and the root is self-signed, the entire chain
		   counts as self-signed */
		if( certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN )
			{
			int selfSigned;

			status = krnlSendMessage( \
						certInfoPtr->certChain[ certInfoPtr->certChainEnd - 1 ], 
						RESOURCE_IMESSAGE_GETATTRIBUTE, &selfSigned,
						CRYPT_CERTINFO_SELFSIGNED );
			if( cryptStatusOK( status ) && selfSigned )
				certInfoPtr->selfSigned = TRUE;
			}

		/* If it's a certificate, parse the signed form to locate the start 
		   of the encoded issuer and subject DN and public key (the length is 
		   recorded when the cert data is written, but their position in the 
		   cert can't be determined until the cert has been signed) */
		if( certInfoPtr->type == CRYPT_CERTTYPE_CERTIFICATE || \
			certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN )
			{
			sMemConnect( &stream, signedCertObject, signedCertObjectLength );
			readSequence( &stream, NULL );	/* Outer wrapper */
			readSequence( &stream, NULL );	/* Inner wrapper */
			if( checkReadCtag( &stream, 0, TRUE ) )
				readUniversal( &stream );	/* Version */
			readUniversal( &stream );		/* Serial number */
			readUniversal( &stream );		/* Sig.algo */
			certInfoPtr->issuerDNptr = sMemBufPtr( &stream );
			readUniversal( &stream );		/* Issuer DN */
			readUniversal( &stream );		/* Validity */
			certInfoPtr->subjectDNptr = sMemBufPtr( &stream );
			readUniversal( &stream );		/* Subject DN */
			certInfoPtr->publicKeyInfo = sMemBufPtr( &stream );
			sMemDisconnect( &stream );
			}
		}

	/* Clean up */
	zeroise( certObject, certObjectLength );
	free( certObject );
	return( status );
	}

/* Check a certificate against a CRL */

static int checkCRL( CERT_INFO *certInfoPtr, const CRYPT_CERTIFICATE cryptCRL )
	{
	CERT_INFO *crlInfoPtr;
	int i, status;

	/* Check that the CRL is a full, signed CRL and not a newly-created CRL
	   object */
	getCheckResource( cryptCRL, crlInfoPtr, OBJECT_TYPE_CERTIFICATE,
					  CRYPT_ARGERROR_VALUE );
	if( crlInfoPtr->certificate == NULL )
		return( CRYPT_ERROR_NOTINITED );

	/* Check the base cert against the CRL.  If it's been revoked or there's
	   only a single cert present, exit */
	status = checkRevocation( certInfoPtr, crlInfoPtr );
	if( cryptStatusError( status ) || \
		( certInfoPtr->type != CRYPT_CERTTYPE_CERTCHAIN && \
		  certInfoPtr->type != CRYPT_CERTTYPE_NS_CERTSEQUENCE ) )
		unlockResourceExit( crlInfoPtr, status );

	/* It's a cert chain, check every remaining cert in the chain against the
	   CRL */
	for( i = 0; i < certInfoPtr->certChainEnd; i++ )
		{
		CERT_INFO *certChainInfoPtr;

		/* Check this cert agains the CRL */
		getCheckInternalResource( certInfoPtr->certChain[ i ],
								  certChainInfoPtr, OBJECT_TYPE_CERTIFICATE );
		status = checkRevocation( certChainInfoPtr, crlInfoPtr );
		unlockResource( certChainInfoPtr );

		/* If the cert has been revoked, set the currently selected cert to
		   the revoked one */
		if( cryptStatusError( status ) )
			{
			certInfoPtr->certChainPos = i;
			break;
			}
		}

	unlockResourceExit( crlInfoPtr, status );
	}

/* Check the validity of a cert object, either against an issuing key/
   certificate or against a CRL */

int checkCertValidity( CERT_INFO *certInfoPtr, const CRYPT_HANDLE sigCheckKey )
	{
	CRYPT_CONTEXT cryptContext;
	CRYPT_CERTTYPE_TYPE sigCheckKeyType = CRYPT_ERROR;
	CERT_INFO *issuerCertInfoPtr = NULL;
	OBJECT_TYPE type;
	int status;

	/* If there's no signature checking key supplied, the cert must be self-
	   signed, either an implicitly self-signed object like a cert chain or
	   an explicitly self-signed object like a cert request or self-signed
	   cert */
	if( sigCheckKey == CRYPT_UNUSED )
		{
		/* If it's a cert chain, it's a (complex) self-signed object 
		   containing more than one cert so we need a special function to check 
		   the entire chain.  If not, it has to be explicitly self-signed */
		if( certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN )
			return( checkCertChain( certInfoPtr ) );
		if( !certInfoPtr->selfSigned )
			return( CRYPT_ARGERROR_VALUE );

		/* Check the signer details and signature */
		status = checkCert( certInfoPtr, certInfoPtr );	/* Issuer = subject */
		if( cryptStatusError( status ) )
			return( status );
		if( checkCertTrusted( certInfoPtr ) )
			/* It's an implicitly trusted cert, we don't need to go any 
			   further */
			return( CRYPT_OK );
		return( checkX509signature( certInfoPtr->certificate, NULL, NULL,
									certInfoPtr->iCryptContext ) );
		}

	/* Find out what the sig.check object is */
	status = krnlSendMessage( sigCheckKey, RESOURCE_IMESSAGE_GETATTRIBUTE,
							  &type, CRYPT_IATTRIBUTE_TYPE );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_VALUE : status );
	if( type == OBJECT_TYPE_CERTIFICATE )
		krnlSendMessage( sigCheckKey, RESOURCE_IMESSAGE_GETATTRIBUTE, 
						 &sigCheckKeyType, CRYPT_CERTINFO_CERTTYPE );

	/* If the checking key is a CRL or keyset which may contain a CRL then 
	   this is a revocation check which works rather differently from a 
	   straight signature check */
	if( type == OBJECT_TYPE_CERTIFICATE && \
		sigCheckKeyType == CRYPT_CERTTYPE_CRL )
		return( checkCRL( certInfoPtr, sigCheckKey ) );
	if( type == OBJECT_TYPE_KEYSET )
		{
		BYTE issuerID[ CRYPT_MAX_HASHSIZE ];

		/* Generate the issuerID for this cert and check whether it's present 
		   in the CRL.  Since all we're interested in is a yes/no answer, we 
		   tell the keyset to perform a check only */
		status = generateCertID( certInfoPtr->issuerName, 
				certInfoPtr->serialNumber, certInfoPtr->serialNumberLength,
				issuerID );
		if( cryptStatusOK( status ) )
			{
			MESSAGE_KEYMGMT_INFO getkeyInfo;

			setMessageKeymgmtInfo( &getkeyInfo, CRYPT_IKEYID_ISSUERID, 
						issuerID, KEYID_SIZE, NULL, 0,
						KEYMGMT_FLAG_CHECK_ONLY | KEYMGMT_FLAG_PUBLICKEY );
			status = krnlSendMessage( sigCheckKey, RESOURCE_IMESSAGE_KEY_GETKEY,
									  &getkeyInfo, 0 );

			/* Reverse the results of the check: OK -> certificate revoked, 
			   not found -> certificate not revoked */
			if( cryptStatusOK( status ) )
				status = CRYPT_ERROR_INVALID;
			else
				if( status == CRYPT_ERROR_NOTFOUND )
					status = CRYPT_OK;
			}

		return( status );
		}

	/* Make sure that the sig.check object is of the correct type */
	if( type != OBJECT_TYPE_CONTEXT && type != OBJECT_TYPE_CERTIFICATE )
		return( CRYPT_ARGERROR_VALUE );

	/* If we've been given a self-signed cert, make sure the sig check key is 
	   the same as the cert.  To test this we have to compare both the 
	   signing key and, if the sig check object is a cert, the cert */
	if( certInfoPtr->selfSigned )
		{
		RESOURCE_DATA msgData;
		BYTE keyID[ KEYID_SIZE ];

		/* Check that the key in the cert and the key in the sig.check object 
		   are identical */
		setResourceData( &msgData, keyID, KEYID_SIZE );
		status = krnlSendMessage( sigCheckKey, RESOURCE_IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_IATTRIBUTE_KEYID );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( certInfoPtr->objectHandle, 
									  RESOURCE_IMESSAGE_COMPARE, keyID,
									  RESOURCE_MESSAGE_COMPARE_KEYID );
		if( cryptStatusError( status ) )
			return( CRYPT_ARGERROR_VALUE );

		/* If the sig.check object is a cert, check that it's identical to the
		   cert.  This may be somewhat stricter than required, but it'll weed
		   out technically valid but questionable combinations like a cert
		   request being used to validate a cert and misleading ones such as 
		   one cert chain being used to check a second chain */
		if( type == OBJECT_TYPE_CERTIFICATE )
			{
			status = krnlSendMessage( certInfoPtr->objectHandle, 
						RESOURCE_IMESSAGE_COMPARE, ( void * ) &sigCheckKey, 
						RESOURCE_MESSAGE_COMPARE_FINGERPRINT );
			if( cryptStatusError( status ) )
				return( CRYPT_ARGERROR_VALUE );
			}

		/* If it's a cert chain, it's a (complex) self-signed object 
		   containing more than one cert so we need a special function to check 
		   the entire chain */
		if( certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN )
			return( checkCertChain( certInfoPtr ) );

		/* Check the signer details and signature */
		status = checkCert( certInfoPtr, certInfoPtr );	/* Issuer = subject */
		if( cryptStatusError( status ) )
			return( status );
		if( checkCertTrusted( certInfoPtr ) )
			/* It's an implicitly trusted cert, we don't need to go any 
			   further */
			return( CRYPT_OK );
		return( checkX509signature( certInfoPtr->certificate, NULL, NULL,
									certInfoPtr->iCryptContext ) );
		}

	/* The signature check key may be a certificate or a context.  If it's 
	   a cert, we get the issuer cert info and extract the context from it 
	   before continuing */
	if( type == OBJECT_TYPE_CERTIFICATE )
		{
		/* Get the context from the issuer certificate */
		status = krnlSendMessage( sigCheckKey, 
								  RESOURCE_IMESSAGE_GETDEPENDENT, 
								  &cryptContext, OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
					CRYPT_ARGERROR_VALUE : status );

		/* Lock the issuer certificate info */
		getCheckInternalResource2( sigCheckKey, issuerCertInfoPtr,
								   OBJECT_TYPE_CERTIFICATE, certInfoPtr );
		}
	else
		{
		CRYPT_CERTIFICATE localCert;

		cryptContext = sigCheckKey;

		/* It's a context, we may have a certificate present in it so we try 
		   to extract that and use it as the issuer certificate if possible.  
		   If the issuer cert isn't present this isn't an error, since it 
		   could be just a raw context */
		status = krnlSendMessage( sigCheckKey, RESOURCE_IMESSAGE_GETDEPENDENT,
								  &localCert, OBJECT_TYPE_CERTIFICATE );
		if( cryptStatusOK( status ) )
			getCheckInternalResource2( localCert, issuerCertInfoPtr,
									   OBJECT_TYPE_CERTIFICATE, certInfoPtr );
		}

	/* If there's an issuer certificate present, check the validity of the
	   subject cert based on it */
	if( issuerCertInfoPtr != NULL )
		{
		status = checkCert( certInfoPtr, issuerCertInfoPtr );
		unlockResource( issuerCertInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Check the signature */
	if( checkCertTrusted( certInfoPtr ) )
		/* It's an implicitly trusted cert, we don't need to go any 
		   further */
		return( CRYPT_OK );
	return( checkX509signature( certInfoPtr->certificate, NULL, NULL,
								cryptContext ) );
	}
