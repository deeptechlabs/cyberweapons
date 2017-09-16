/****************************************************************************
*																			*
*						cryptlib Enveloping Routines						*
*					  Copyright Peter Gutmann 1996-1999						*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "asn1.h"
  #include "asn1objs.h"
  #include "asn1oid.h"
  #include "envelope.h"
#elif defined( INC_CHILD )
  #include "../keymgmt/asn1.h"
  #include "../keymgmt/asn1objs.h"
  #include "../keymgmt/asn1oid.h"
  #include "../envelope/envelope.h"
#else
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1objs.h"
  #include "keymgmt/asn1oid.h"
  #include "envelope/envelope.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*							Low-level Enveloping Functions					*
*																			*
****************************************************************************/

/* Get the OID for a CMS content type.  If no type is explicitly given, we
   assume raw data */

static const struct {
	const CRYPT_CONTENT_TYPE contentType;
	const BYTE *oid;
	} contentOIDs[] = {
	{ CRYPT_CONTENT_DATA, OID_CMS_DATA },
	{ CRYPT_CONTENT_SIGNEDDATA, OID_CMS_SIGNEDDATA },
	{ CRYPT_CONTENT_ENVELOPEDDATA, OID_CMS_ENVELOPEDDATA },
	{ CRYPT_CONTENT_SIGNEDANDENVELOPEDDATA, MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x04" ) },
	{ CRYPT_CONTENT_DIGESTEDDATA, OID_CMS_DIGESTEDDATA },
	{ CRYPT_CONTENT_ENCRYPTEDDATA, OID_CMS_ENCRYPTEDDATA },
	{ CRYPT_CONTENT_COMPRESSEDDATA, OID_CMS_COMPRESSEDDATA },
	{ CRYPT_CONTENT_SPCINDIRECTDATACONTEXT, MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x04" ) },
	{ 0, NULL }
	};

static const BYTE *getContentOID( const CRYPT_CONTENT_TYPE contentType )
	{
	int i;

	for( i = 0; contentOIDs[ i ].oid != NULL; i++ )
		if( contentOIDs[ i ].contentType == contentType )
			return( contentOIDs[ i ].oid );

	assert( NOTREACHED );
	return( NULL );		/* Get rid of compiler warning */
	}

/* Copy as much information from the auxiliary buffer to the main buffer as
   possible.  There are two variants of this function, one which copies
   straight from the auxiliary buffer, the second which synchronizes the
   auxStream status with the auxiliary buffer and then copies the data
   across */

static int copyFromAuxBuffer( ENVELOPE_INFO *envelopeInfoPtr )
	{
	int bytesCopied, dataLeft;

	/* Copy as much as we can across */
	bytesCopied = min( envelopeInfoPtr->bufSize - envelopeInfoPtr->bufPos,
					   envelopeInfoPtr->auxBufPos );
	memcpy( envelopeInfoPtr->buffer + envelopeInfoPtr->bufPos,
			envelopeInfoPtr->auxBuffer, bytesCopied );
	envelopeInfoPtr->bufPos += bytesCopied;

	/* If there's anything left, move it down in the buffer */
	dataLeft = envelopeInfoPtr->auxBufPos - bytesCopied;
	if( dataLeft )
		memmove( envelopeInfoPtr->auxBuffer, envelopeInfoPtr->auxBuffer + bytesCopied,
				 dataLeft );
	envelopeInfoPtr->auxBufPos = dataLeft;

	/* Rewind the memory stream to the new end of the data */
	sseek( &envelopeInfoPtr->auxStream, dataLeft );

	return( dataLeft );
	}

static int copyFromAuxStream( ENVELOPE_INFO *envelopeInfoPtr )
	{
	int auxStreamSize = ( int ) stell( &envelopeInfoPtr->auxStream );

	if( sGetStatus( &envelopeInfoPtr->auxStream ) != CRYPT_OK )
		return( sGetStatus( &envelopeInfoPtr->auxStream ) );
	envelopeInfoPtr->auxBufPos = auxStreamSize;
	return( copyFromAuxBuffer( envelopeInfoPtr ) );
	}

/****************************************************************************
*																			*
*					Envelope Pre/Post-processing Functions					*
*																			*
****************************************************************************/

/* The following functions take care of pre/post-processing of envelope data
   during the enveloping/deenveloping process */

static int processKeyexchangeActions( ENVELOPE_INFO *envelopeInfoPtr )
	{
	CRYPT_DEVICE iCryptDevice = CRYPT_ERROR;
	ACTION_LIST *actionListPtr, *cryptActionPtr;
	BYTE originatorDomainParams[ CRYPT_MAX_HASHSIZE ];
	int totalSize, originatorDomainParamSize = 0, status;

	/* If there's an originator chain present, get the originators domain 
	   parameters and if the key is tied to a device, get the devices handle
	   so we can create the session key object in it */
	if( envelopeInfoPtr->iOriginatorChain != CRYPT_ERROR )
		{
		RESOURCE_DATA msgData;

		setResourceData( &msgData, originatorDomainParams, 
						 CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( envelopeInfoPtr->iOriginatorChain,
								  RESOURCE_IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_DOMAINPARAMS );
		if( cryptStatusError( status ) )
			return( status );
		originatorDomainParamSize = msgData.length;
		status = krnlSendMessage( envelopeInfoPtr->iOriginatorChain, 
								  RESOURCE_IMESSAGE_GETDEPENDENT, &iCryptDevice,
								  OBJECT_TYPE_DEVICE );
		if( cryptStatusError( status ) )
			iCryptDevice = CRYPT_ERROR;
		}

	/* Create the session key if necessary */
	cryptActionPtr = findAction( envelopeInfoPtr->actionList, ACTION_CRYPT );
	if( cryptActionPtr == NULL )
		{
		CREATEOBJECT_INFO createInfo;
		int status;

		/* Create a default encryption action */
		setMessageCreateObjectInfo( &createInfo, envelopeInfoPtr->defaultAlgo );
		status = krnlSendMessage( ( iCryptDevice != CRYPT_ERROR ) ? \
								  iCryptDevice : SYSTEM_OBJECT_HANDLE,
								  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
								  &createInfo, OBJECT_TYPE_CONTEXT );
		if( cryptStatusOK( status ) )
			{
			status = krnlSendMessage( createInfo.cryptHandle, 
									  RESOURCE_IMESSAGE_CTX_GENKEY, 
									  MESSAGE_VALUE_DEFAULT, FALSE );
			if( cryptStatusOK( status ) )
				{
				/* Insert the encryption action into the list */
				findCheckLastAction( &envelopeInfoPtr->actionList,
							&cryptActionPtr, ACTION_CRYPT, CRYPT_UNUSED );
				status = addAction( &envelopeInfoPtr->actionList,
							&cryptActionPtr, ACTION_CRYPT, 
							createInfo.cryptHandle );
				}
			if( cryptStatusError( status ) )
				krnlSendNotifier( createInfo.cryptHandle, 
								  RESOURCE_IMESSAGE_DECREFCOUNT );
			}
		if( cryptStatusError( status ) )
			return( status );
		}
	else
		{
		/* If the session key context is tied to a device, get its handle so 
		   we can check that all key exchange objects are also in the same 
		   device */
		status = krnlSendMessage( cryptActionPtr->iCryptHandle, 
								  RESOURCE_MESSAGE_GETDEPENDENT, 
								  &iCryptDevice, OBJECT_TYPE_DEVICE );
		if( cryptStatusError( status ) )
			iCryptDevice = CRYPT_ERROR;
		}

	/* Notify the kernel that the session key context is attached to the 
	   envelope.  This is an internal object used only by the envelope so we
	   tell the kernel not to increment its reference count when it attaches
	   it */
	krnlSendMessage( envelopeInfoPtr->objectHandle, 
					 RESOURCE_IMESSAGE_SETDEPENDENT, 
					 &cryptActionPtr->iCryptHandle, FALSE );

	/* Now walk down the list of key exchange actions connecting each one to 
	   the session key action and evaluating their size */
	totalSize = 0;
	actionListPtr = findAction( envelopeInfoPtr->preActionList,
								ACTION_KEYEXCHANGE_PKC );
	if( actionListPtr == NULL )
		actionListPtr = findAction( envelopeInfoPtr->preActionList,
									ACTION_KEYEXCHANGE );
	while( actionListPtr != NULL && \
		   ( actionListPtr->action == ACTION_KEYEXCHANGE || \
			 actionListPtr->action == ACTION_KEYEXCHANGE_PKC ) )
		{
		/* If the session key context is tied to a device, make sure the key 
		   exchange object is in the same device */
		if( iCryptDevice != CRYPT_ERROR )
			{
			CRYPT_DEVICE iKeyexDevice;

			status = krnlSendMessage( actionListPtr->iCryptHandle, 
									  RESOURCE_MESSAGE_GETDEPENDENT, 
									  &iKeyexDevice, OBJECT_TYPE_DEVICE );
			if( cryptStatusError( status ) || iCryptDevice != iKeyexDevice )
				return( CRYPT_ERROR_INVALID );
			}

		/* If it's a key agreement action, make sure there's originator info 
		   present and that the domain parameters match */
		if( actionListPtr->action == ACTION_KEYEXCHANGE_PKC && \
			cryptStatusOK( krnlSendMessage( actionListPtr->iCryptHandle, 
									RESOURCE_IMESSAGE_CHECK, NULL, 
									RESOURCE_MESSAGE_CHECK_PKC_KA_EXPORT ) ) )
			{
			RESOURCE_DATA msgData;
			BYTE domainParams[ CRYPT_MAX_HASHSIZE ];

			if( !originatorDomainParamSize )
				{
				setErrorInfo( envelopeInfoPtr, CRYPT_ENVINFO_ORIGINATOR,
							  CRYPT_ERRTYPE_ATTR_ABSENT );
				return( CRYPT_ERROR_NOTINITED );
				}
			setResourceData( &msgData, domainParams, CRYPT_MAX_HASHSIZE );
			status = krnlSendMessage( actionListPtr->iCryptHandle,
									  RESOURCE_IMESSAGE_GETATTRIBUTE_S,
									  &msgData, CRYPT_IATTRIBUTE_DOMAINPARAMS );
			if( cryptStatusError( status ) )
				return( status );
			if( ( originatorDomainParamSize != msgData.length ) || \
				memcmp( originatorDomainParams, domainParams, 
						originatorDomainParamSize ) )
				{
				setErrorInfo( envelopeInfoPtr, CRYPT_ENVINFO_ORIGINATOR,
							  CRYPT_ERRTYPE_CONSTRAINT );
				return( CRYPT_ERROR_INVALID );
				}
			}

		/* Remember that we now have a controlling action and connect the
		   controller to the subject */
		cryptActionPtr->needsController = FALSE;
		actionListPtr->associatedAction = cryptActionPtr;

		/* Evaluate the size of the exported action.  If it's a conventional 
		   key exchange, we force the use of the CMS format since there's no 
		   reason to use the cryptlib format */
		status = iCryptExportKeyEx( NULL, &actionListPtr->encodedSize,
						( actionListPtr->action == ACTION_KEYEXCHANGE ) ? \
							CRYPT_FORMAT_CMS : envelopeInfoPtr->type,
						cryptActionPtr->iCryptHandle,
						actionListPtr->iCryptHandle, 
						( envelopeInfoPtr->iOriginatorChain != CRYPT_ERROR ) ? \
							envelopeInfoPtr->iOriginatorChain : CRYPT_UNUSED );
		if( cryptStatusError( status ) )
			return( status );
		totalSize += actionListPtr->encodedSize;
		actionListPtr = actionListPtr->next;
		}
	envelopeInfoPtr->cryptActionSize = totalSize;

	return( CRYPT_OK );	
	}

static int preEnvelopeEncrypt( ENVELOPE_INFO *envelopeInfoPtr )
	{
	ACTION_LIST *actionListPtr;

	/* If there's originator info present, find out what it'll take to encode
	   it into the envelope header */
	if( envelopeInfoPtr->iOriginatorChain != CRYPT_ERROR )
		{
		RESOURCE_DATA msgData;
		int status;

		/* Determine how big the originator cert chain will be */
		setResourceData( &msgData, NULL, 0 );
		status = krnlSendMessage( envelopeInfoPtr->iOriginatorChain,
								  RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_CERTSET );
		if( cryptStatusError( status ) )
			return( status );
		envelopeInfoPtr->extraDataSize = msgData.length;

		/* If we have very long originator cert chains, the auxBuffer may not 
		   be large enough to contain the resulting chain, so we have to 
		   expand it to handle the chain */
		if( envelopeInfoPtr->auxBufSize < envelopeInfoPtr->extraDataSize + 64 )
			{
			free( envelopeInfoPtr->auxBuffer );
			if( ( envelopeInfoPtr->auxBuffer = \
					malloc( envelopeInfoPtr->extraDataSize + 64 ) ) == NULL )
				return( CRYPT_ERROR_MEMORY );
			envelopeInfoPtr->auxBufSize = envelopeInfoPtr->extraDataSize + 64;
			}
		}

	/* If there are key exchange actions, connect them to the session key
	   action */
	if( findAction( envelopeInfoPtr->preActionList,
					ACTION_KEYEXCHANGE ) != NULL || \
		findAction( envelopeInfoPtr->preActionList,
					ACTION_KEYEXCHANGE_PKC ) != NULL )
		{
		int status;

		status = processKeyexchangeActions( envelopeInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Check for unattached encryption actions */
	for( actionListPtr = findAction( envelopeInfoPtr->actionList, ACTION_CRYPT );
		 actionListPtr != NULL && actionListPtr->action == ACTION_CRYPT;
		 actionListPtr = actionListPtr->next )
		if( actionListPtr->needsController )
			return( CRYPT_ERROR_INCOMPLETE );

	return( CRYPT_OK );
	}

static int preEnvelopeSign( ENVELOPE_INFO *envelopeInfoPtr )
	{
	ACTION_LIST *actionListPtr;
	int largestSignatureSize = 0, status;

	/* If we're generating a detached signature, the content is supplied
	   externally and has zero size */
	if( envelopeInfoPtr->detachedSig )
		envelopeInfoPtr->payloadSize = 0;

	/* Remember the start of the set of hash actions for the data-processing
	   stage */
	envelopeInfoPtr->hashActions = findAction( envelopeInfoPtr->actionList,
											   ACTION_HASH );

	/* Evaluate the size of each signature action */
	for( actionListPtr = findAction( envelopeInfoPtr->postActionList, ACTION_SIGN );
		 actionListPtr != NULL && actionListPtr->action == ACTION_SIGN;
		 actionListPtr = actionListPtr->next )
		{
		int cryptAlgo, signatureSize, signingAttributes;

		/* If it's a CMS envelope, we have to write the signing cert chain
		   alongside the signatures as extra data, so we record how large the
		   info will be for later.  In addition we have to match the content-
		   type in the authenticated attributes with the signed content type
		   if it's anything other than 'data' (the data content-type is added
		   automatically) */
		if( envelopeInfoPtr->type == CRYPT_FORMAT_CMS || \
			envelopeInfoPtr->type == CRYPT_FORMAT_SMIME )
			{
			RESOURCE_DATA msgData;

			/* Determine how big the cert chain will be */
			setResourceData( &msgData, NULL, 0 );
			status = krnlSendMessage( actionListPtr->iCryptHandle,
								RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData,
								CRYPT_IATTRIBUTE_CERTSET );
			if( cryptStatusError( status ) )
				return( status );
			envelopeInfoPtr->extraDataSize += msgData.length;
			if( msgData.length > largestSignatureSize )
				largestSignatureSize = msgData.length;

			/* If there's no content-type present and the signed content
			   type isn't 'data' or it's an S/MIME envelope, create signing
			   attributes to hold the content-type and smimeCapabilities.
			   Then, make sure that the content-type in the attributes
			   matches the actual content type */
			if( actionListPtr->iExtraData == CRYPT_ERROR && \
				( envelopeInfoPtr->contentType != CRYPT_CONTENT_DATA || \
				  envelopeInfoPtr->type == CRYPT_FORMAT_SMIME ) )
				{
				CREATEOBJECT_INFO createInfo;

				setMessageCreateObjectInfo( &createInfo, 
											CRYPT_CERTTYPE_CMS_ATTRIBUTES );
				status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
										  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
										  &createInfo, OBJECT_TYPE_CERTIFICATE );
				if( cryptStatusError( status ) )
					return( status );
				actionListPtr->iExtraData = createInfo.cryptHandle;
				}
			if( actionListPtr->iExtraData != CRYPT_ERROR )
				{
				int value;

				/* Delete any existing content-type (quietly fixing things if
				   necessary is easier than trying to report this error back
				   to the caller) and add our one */
				if( krnlSendMessage( actionListPtr->iExtraData, 
						RESOURCE_IMESSAGE_GETATTRIBUTE, &value, 
						CRYPT_CERTINFO_CMS_CONTENTTYPE ) != CRYPT_ERROR_NOTFOUND )
					krnlSendMessage( actionListPtr->iExtraData,
						RESOURCE_IMESSAGE_DELETEATTRIBUTE, NULL, 
						CRYPT_CERTINFO_CMS_CONTENTTYPE );
				krnlSendMessage( actionListPtr->iExtraData,
						RESOURCE_IMESSAGE_SETATTRIBUTE, &envelopeInfoPtr->contentType,
						CRYPT_CERTINFO_CMS_CONTENTTYPE );

				/* If it's an S/MIME (vs pure CMS) envelope, add the
				   sMIMECapabilities to further bloat things up */
				if( envelopeInfoPtr->type == CRYPT_FORMAT_SMIME )
					{
					CRYPT_QUERY_INFO queryInfo;

					krnlSendMessage( actionListPtr->iExtraData,
									 RESOURCE_IMESSAGE_SETATTRIBUTE, 
									 MESSAGE_VALUE_UNUSED,
									 CRYPT_CERTINFO_CMS_SMIMECAP_3DES );
					if( cryptStatusOK( krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
									   RESOURCE_IMESSAGE_DEV_QUERYCAPABILITY,
									   &queryInfo, CRYPT_ALGO_CAST ) ) )
						krnlSendMessage( actionListPtr->iExtraData,
										 RESOURCE_IMESSAGE_SETATTRIBUTE, 
										 MESSAGE_VALUE_UNUSED,
										 CRYPT_CERTINFO_CMS_SMIMECAP_CAST128 );
					if( cryptStatusOK( krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
									   RESOURCE_IMESSAGE_DEV_QUERYCAPABILITY,
									   &queryInfo, CRYPT_ALGO_IDEA ) ) )
						krnlSendMessage( actionListPtr->iExtraData,
										 RESOURCE_IMESSAGE_SETATTRIBUTE, 
										 MESSAGE_VALUE_UNUSED,
										 CRYPT_CERTINFO_CMS_SMIMECAP_IDEA );
					if( cryptStatusOK( krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
									   RESOURCE_IMESSAGE_DEV_QUERYCAPABILITY,
									   &queryInfo, CRYPT_ALGO_RC2 ) ) )
						krnlSendMessage( actionListPtr->iExtraData,
										 RESOURCE_IMESSAGE_SETATTRIBUTE, 
										 MESSAGE_VALUE_UNUSED,
										 CRYPT_CERTINFO_CMS_SMIMECAP_RC2 );
					if( cryptStatusOK( krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
									   RESOURCE_IMESSAGE_DEV_QUERYCAPABILITY,
									   &queryInfo, CRYPT_ALGO_SKIPJACK ) ) )
						krnlSendMessage( actionListPtr->iExtraData,
										 RESOURCE_IMESSAGE_SETATTRIBUTE, 
										 MESSAGE_VALUE_UNUSED,
										 CRYPT_CERTINFO_CMS_SMIMECAP_SKIPJACK );
					}
				}
			}

		/* Determine the type of signing attributes to use.  If none are 
		   specified (which can only happen if the signed content is data),
		   either get the signing code to add the default ones for use, or
		   use none at all if the use of default attributes is disabled */
		signingAttributes = actionListPtr->iExtraData;
		if( signingAttributes == CRYPT_ERROR )
			{
			int useDefaultAttributes;

			krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
							 &useDefaultAttributes, 
							 CRYPT_OPTION_CMS_DEFAULTATTRIBUTES );
			signingAttributes = useDefaultAttributes ? \
								CRYPT_USE_DEFAULT : CRYPT_UNUSED;
			}

		/* Evaluate the size of the exported action.  Even though it's not
		   required for encoding the length for DSA, we still need to
		   evaluate it to determine whether the allocated auxBuffer is big
		   enough to contain the largest possible signature */
		status = iCryptCreateSignatureEx( NULL, &signatureSize,
						envelopeInfoPtr->type, actionListPtr->iCryptHandle,
						actionListPtr->associatedAction->iCryptHandle,
						signingAttributes, actionListPtr->auxInfo );
		if( cryptStatusError( status ) )
			return( status );
		status = krnlSendMessage( actionListPtr->iCryptHandle, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE, &cryptAlgo,
								  CRYPT_CTXINFO_ALGO );
		if( cryptStatusError( status ) )
			return( status );
		if( cryptAlgo == CRYPT_ALGO_DSA )
			{
			/* If there are any signature actions which will result in
			   indefinite-length signatures present, we can't use a definite-
			   length encoding for the signatures */
			envelopeInfoPtr->hasIndefiniteTrailer = TRUE;
			actionListPtr->encodedSize = CRYPT_UNUSED;
			}
		else
			{
			actionListPtr->encodedSize = signatureSize;
			envelopeInfoPtr->signActionSize += signatureSize;
			}
		if( signatureSize > largestSignatureSize )
			largestSignatureSize = signatureSize;
		}
	largestSignatureSize += 64;		/* Add some slop for ASN.1 wrappers */

	/* If we're signing with very long cert chains or chains where the certs
	   have half the Verisign CPS included as text, the auxBuffer may not be
	   large enough to contain the resulting signature, so we have to expand
	   it to handle the signature */
	if( envelopeInfoPtr->auxBufSize < largestSignatureSize )
		{
		free( envelopeInfoPtr->auxBuffer );
		if( ( envelopeInfoPtr->auxBuffer = malloc( largestSignatureSize ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		envelopeInfoPtr->auxBufSize = largestSignatureSize;
		}

	/* Check for unattached hash actions */
	for( actionListPtr = envelopeInfoPtr->hashActions;
		 actionListPtr != NULL && actionListPtr->action == ACTION_HASH;
		 actionListPtr = actionListPtr->next )
		if( actionListPtr->needsController )
			return( CRYPT_ERROR_INCOMPLETE );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Emit Header Functions						*
*																			*
****************************************************************************/

/* Write the header fields which encapsulate any enveloped data:

   SignedData/DigestedData */

static int writeAuthenticatedDataHeader( STREAM *stream,
										 const ENVELOPE_INFO *envelopeInfoPtr,
										 const BOOLEAN isSignedData )
	{
	const BYTE *contentOID = getContentOID( envelopeInfoPtr->contentType );
	ACTION_LIST *actionListPtr;
	long dataSize;
	int hashActionSize = 0;

	/* Determine the size of the hash actions */
	for( actionListPtr = envelopeInfoPtr->hashActions;
		 actionListPtr != NULL && actionListPtr->action == ACTION_HASH;
		 actionListPtr = actionListPtr->next )
		hashActionSize += sizeofContextAlgoID( actionListPtr->iCryptHandle,
											   CRYPT_ALGO_NONE );

	/* Determine the size of the SignedData/DigestedData */
	if( envelopeInfoPtr->payloadSize == CRYPT_UNUSED || \
		envelopeInfoPtr->hasIndefiniteTrailer )
		dataSize = CRYPT_UNUSED;
	else
		{
		/* Determine the size of the content OID + content */
		dataSize = ( envelopeInfoPtr->payloadSize ) ? \
			sizeofObject( sizeofObject( envelopeInfoPtr->payloadSize ) ) : 0;
		dataSize = sizeofObject( sizeofOID( contentOID ) + dataSize );

		/* Determine the size of the version, hash algoID, content, cert
		   chain, and signatures */
		dataSize = sizeofShortInteger( 1 ) + sizeofObject( hashActionSize ) +
				   dataSize + envelopeInfoPtr->extraDataSize +
				   sizeofObject( envelopeInfoPtr->signActionSize );
		}

	/* Write the SignedData/DigestedData header, version number, and SET OF
	   DigestInfo */
	writeCMSheader( stream, ( isSignedData ) ? \
					OID_CMS_SIGNEDDATA : OID_CMS_DIGESTEDDATA, dataSize );
	writeShortInteger( stream, 1, DEFAULT_TAG );
	writeSet( stream, hashActionSize );
	for( actionListPtr = envelopeInfoPtr->hashActions;
		 actionListPtr != NULL && actionListPtr->action == ACTION_HASH;
		 actionListPtr = actionListPtr->next )
		{
		int status = writeContextAlgoID( stream,
							actionListPtr->iCryptHandle, CRYPT_ALGO_NONE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Write the inner Data header */
	writeCMSheader( stream, contentOID, envelopeInfoPtr->payloadSize );
	return( CRYPT_OK );
	}

/* EncryptedContentInfo contained within EnvelopedData */

static int writeEncryptedContentHeader( STREAM *stream,
							const BYTE *contentOID,
							const CRYPT_CONTEXT iCryptContext,
							const long payloadSize, const long blockSize )
	{
	const long blockedPayloadSize = ( payloadSize == CRYPT_UNUSED ) ? \
						CRYPT_UNUSED : paddedSize( payloadSize, blockSize );

	return( writeCMSencrHeader( stream, contentOID, blockedPayloadSize,
								iCryptContext ) );
	}

/* EncryptedData, EnvelopedData */

static void writeEncryptionHeader( STREAM *stream, const BYTE *oid,
								   const int version, const long payloadSize,
								   const long blockSize, const long extraSize )
	{
	const long blockedPayloadSize = ( payloadSize == CRYPT_UNUSED ) ? \
						CRYPT_UNUSED : paddedSize( payloadSize, blockSize );

	writeCMSheader( stream, oid, ( payloadSize == CRYPT_UNUSED ) ? \
					CRYPT_UNUSED : sizeofShortInteger( 0 ) + extraSize + \
					blockedPayloadSize );
	writeShortInteger( stream, version, DEFAULT_TAG );
	}

static int writeEncryptedDataHeader( STREAM *stream,
									 const ENVELOPE_INFO *envelopeInfoPtr )
	{
	const BYTE *contentOID = getContentOID( envelopeInfoPtr->contentType );
	const int encrContentInfoSize = sizeofCMSencrHeader( contentOID,
			envelopeInfoPtr->payloadSize, envelopeInfoPtr->iCryptContext );

	if( cryptStatusError( encrContentInfoSize ) )
		return( encrContentInfoSize );

	/* Write the EncryptedData header and version number, and
	   EncryptedContentInfo header */
	writeEncryptionHeader( stream, OID_CMS_ENCRYPTEDDATA, 0,
				envelopeInfoPtr->payloadSize, envelopeInfoPtr->blockSize,
				encrContentInfoSize );
	return( writeEncryptedContentHeader( stream, contentOID,
				envelopeInfoPtr->iCryptContext, envelopeInfoPtr->payloadSize,
				envelopeInfoPtr->blockSize ) );
	}

static int writeEnvelopedDataHeader( STREAM *stream,
									 const ENVELOPE_INFO *envelopeInfoPtr )
	{
	const BYTE *contentOID = getContentOID( envelopeInfoPtr->contentType );
	const int encrContentInfoSize = sizeofCMSencrHeader( contentOID,
			envelopeInfoPtr->payloadSize, envelopeInfoPtr->iCryptContext );
	const int originatorInfoSize = envelopeInfoPtr->extraDataSize ? \
			( int ) sizeofObject( envelopeInfoPtr->extraDataSize ) : 0;

	if( cryptStatusError( encrContentInfoSize ) )
		return( encrContentInfoSize );

	/* Write the EnvelopedData header and version number and start of the SET
	   OF RecipientInfo/EncryptionKeyInfo */
	writeEncryptionHeader( stream, OID_CMS_ENVELOPEDDATA, 
				originatorInfoSize ? 2 : 0, envelopeInfoPtr->payloadSize, 
				envelopeInfoPtr->blockSize, 
				sizeofObject( envelopeInfoPtr->cryptActionSize ) +
				originatorInfoSize + encrContentInfoSize );
	if( originatorInfoSize )
		{
		RESOURCE_DATA msgData;
		const int bytesLeft = envelopeInfoPtr->bufSize - ( int ) stell( stream );
		int status;

		/* Write the wrapper for the originator info and the originator info 
		   itself */
		writeCtag( stream, 0 );
		writeLength( stream, envelopeInfoPtr->extraDataSize );

		/* Export the originator cert chain either directly into the main 
		   buffer or into the auxBuffer if there's not enough room */
		if( originatorInfoSize >= bytesLeft )
			{
			/* The originator chain is too big for the main buffer, we have
			   to write everything from this point on into the auxBuffer */
			stream = ( STREAM * ) &envelopeInfoPtr->auxStream;
			setResourceData( &msgData, envelopeInfoPtr->auxBuffer, 
							 envelopeInfoPtr->auxBufSize );
			}
		else
			setResourceData( &msgData, sMemBufPtr( stream ), bytesLeft );
		status = krnlSendMessage( envelopeInfoPtr->iOriginatorChain,
								  RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_CERTSET );
		if( cryptStatusError( status ) )
			return( status );
		sSkip( stream, msgData.length );
		}

	return( writeSet( stream, envelopeInfoPtr->cryptActionSize ) );
	}

/* CompressedData */

static void writeCompressedDataHeader( STREAM *stream,
									   ENVELOPE_INFO *envelopeInfoPtr )
	{
	/* Since compressing the data changes its length, we have to use the
	   indefinite-length encoding even if we know how big the payload is */
	envelopeInfoPtr->payloadSize = CRYPT_UNUSED;

	/* Write the CompressedData header, version number, and Zlib algoID */
	writeCMSheader( stream, OID_CMS_COMPRESSEDDATA, CRYPT_UNUSED );
	writeShortInteger( stream, 0, DEFAULT_TAG );
	swrite( stream, ALGOID_CMS_ZLIB, sizeofOID( ALGOID_CMS_ZLIB ) );

	/* Write the inner Data header */
	writeCMSheader( stream, getContentOID( envelopeInfoPtr->contentType ), 
					CRYPT_UNUSED );
	}

/****************************************************************************
*																			*
*							Emit Envelope Preamble/Postamble				*
*																			*
****************************************************************************/

/* Output as much of the preamble as possible into the envelope buffer */

int emitPreamble( ENVELOPE_INFO *envelopeInfoPtr )
	{
	ENV_STATE state = envelopeInfoPtr->envState;
	int status = CRYPT_OK;

	/* If there's any data left in the auxiliary buffer, try and empty that
	   first */
	if( envelopeInfoPtr->auxBufPos && copyFromAuxBuffer( envelopeInfoPtr ) )
		return( CRYPT_ERROR_OVERFLOW );

	/* If we've finished processing the header information, don't do
	   anything */
	if( state == ENVSTATE_DONE )
		return( CRYPT_OK );

	/* If we haven't started doing anything yet, perform various final
	   initialisations */
	if( state == ENVSTATE_NONE )
		{
		/* If there's no nested content type set, default to plain data */
		if( envelopeInfoPtr->contentType == CRYPT_CONTENT_NONE )
			envelopeInfoPtr->contentType = CRYPT_CONTENT_DATA;

		/* Perform any remaining initialisation */
		if( envelopeInfoPtr->usage == ACTION_CRYPT )
			status = preEnvelopeEncrypt( envelopeInfoPtr );
		else
			if( envelopeInfoPtr->usage == ACTION_SIGN )
				status = preEnvelopeSign( envelopeInfoPtr );
		if( cryptStatusError( status ) )
			return( status );

		/* We're ready to go, connect a write stream to the auxBuffer and
		   prepare to emit the outer header */
		sMemConnect( &envelopeInfoPtr->auxStream, envelopeInfoPtr->auxBuffer,
					 envelopeInfoPtr->auxBufSize );
		state = ENVSTATE_HEADER;
		}

	/* Emit the outer header */
	if( state == ENVSTATE_HEADER )
		{
		ACTION_LIST *actionListPtr;
		STREAM stream;

		/* If we're encrypting, set up the encryption-related information */
		if( ( actionListPtr = findAction( envelopeInfoPtr->actionList,
										  ACTION_CRYPT ) ) != NULL )
			{
			status = initEnvelopeEncryption( envelopeInfoPtr,
								actionListPtr->iCryptHandle, CRYPT_UNUSED,
								CRYPT_UNUSED, NULL, 0, FALSE );
			if( cryptStatusError( status ) )
				return( status );
			}

		/* Write the appropriate CMS header based on the envelope usage.
		   Since this is the first data written, we can write it directly to
		   the envelope buffer without having to go via the auxBuffer.  The
		   DigestedData action is never taken since the higher-level code
		   assumes that the presence of hash actions indicates the desire to
		   create signed data and returns an error if no signature actions
		   are present */
		sMemConnect( &stream, envelopeInfoPtr->buffer,
					 envelopeInfoPtr->bufSize );
		switch( envelopeInfoPtr->usage )
			{
			case ACTION_CRYPT:
				if( envelopeInfoPtr->preActionList == NULL )
					status = writeEncryptedDataHeader( &stream, envelopeInfoPtr );
				else
					status = writeEnvelopedDataHeader( &stream, envelopeInfoPtr );
				break;

			case ACTION_SIGN:
				status = writeAuthenticatedDataHeader( &stream, 
												envelopeInfoPtr, TRUE );
				break;

			case ACTION_HASH:
				status = writeAuthenticatedDataHeader( &stream, 
												envelopeInfoPtr, FALSE );
				break;

			case ACTION_COMPRESS:
				writeCompressedDataHeader( &stream, envelopeInfoPtr );
				break;

			case ACTION_NONE:
				writeCMSheader( &stream, OID_CMS_DATA, 
								envelopeInfoPtr->payloadSize );
				break;

			default:
				assert( NOTREACHED );
			}
		envelopeInfoPtr->bufPos = ( int ) stell( &stream );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );

		/* If we're not encrypting with key exchange actions, we're done */
		if( envelopeInfoPtr->usage != ACTION_CRYPT || \
			envelopeInfoPtr->preActionList == NULL )
			{
			/* Make sure we start a new segment if we try to add any data,
			   set the block size mask to all ones if we're not encrypting
			   (since we can begin and end data segments on arbitrary
			   boundaries), and record the fact that we're done */
			envelopeInfoPtr->segmentComplete = TRUE;
			if( envelopeInfoPtr->usage != ACTION_CRYPT )
				envelopeInfoPtr->blockSizeMask = -1;
			envelopeInfoPtr->lastAction = NULL;
			envelopeInfoPtr->envState = ENVSTATE_DONE;
			return( CRYPT_OK );
			}

		/* Start emitting the key exchange actions */
		envelopeInfoPtr->lastAction = findAction( envelopeInfoPtr->preActionList,
												  ACTION_KEYEXCHANGE_PKC );
		if( envelopeInfoPtr->lastAction == NULL )
			envelopeInfoPtr->lastAction = findAction( envelopeInfoPtr->preActionList,
													  ACTION_KEYEXCHANGE );
		state = ENVSTATE_KEYINFO;

		/* In very rare instances (when we're using a key agreement key and 
		   there's a lot of originator info) the header can contain a large 
		   amount of data which won't fit into the main buffer, so we copy it 
		   into the auxBuffer instead.  If this happens we need to tell the 
		   user to pop some data so we can move more of it out of the 
		   auxBuffer */
		if( envelopeInfoPtr->auxBufPos && copyFromAuxBuffer( envelopeInfoPtr ) )
			{
			envelopeInfoPtr->envState = ENVSTATE_KEYINFO;
			return( CRYPT_ERROR_OVERFLOW );
			}
		}

	/* Keep producing output until we fill the envelope buffer or run out of
	   header information to encode */
	while( TRUE )
		{
		/* Handle key export actions */
		if( state == ENVSTATE_KEYINFO )
			{
			ACTION_LIST *lastActionPtr = envelopeInfoPtr->lastAction;

			/* Export the session key using each of the PKC or conventional
			   keys.  If it's a conventional key exchange, we force the use 
			   of the CMS format since there's no reason to use the cryptlib
			   format */
			while( cryptStatusOK( status ) && lastActionPtr != NULL )
				{
				status = iCryptExportKeyEx( envelopeInfoPtr->auxBuffer,
							&envelopeInfoPtr->auxBufPos, 
							( lastActionPtr->action == ACTION_KEYEXCHANGE ) ? \
							CRYPT_FORMAT_CMS : envelopeInfoPtr->type,
							envelopeInfoPtr->iCryptContext,
							lastActionPtr->iCryptHandle,
							( envelopeInfoPtr->iOriginatorChain != CRYPT_ERROR ) ? \
								envelopeInfoPtr->iOriginatorChain : CRYPT_UNUSED );
				if( !cryptStatusError( status ) )
					{
					lastActionPtr = lastActionPtr->next;
					if( copyFromAuxBuffer( envelopeInfoPtr ) )
						status = CRYPT_ERROR_OVERFLOW;
					}
				}
			envelopeInfoPtr->lastAction = lastActionPtr;

			/* If we've reached the last key exchange action, move on to the
			   next state.  Since the emission of the key exchange
			   information is interruptible, we only move on to the next
			   state if there are no errors */
			if( cryptStatusError( status ) )
				break;
			state = ENVSTATE_ENCRINFO;
			}

		/* Handle encrypted content information */
		if( state == ENVSTATE_ENCRINFO )
			{
			/* Write the encrypted content header */
			status = writeEncryptedContentHeader( &envelopeInfoPtr->auxStream,
				getContentOID( envelopeInfoPtr->contentType ),
				envelopeInfoPtr->iCryptContext, envelopeInfoPtr->payloadSize,
				envelopeInfoPtr->blockSize );
			if( cryptStatusOK( status ) && \
				copyFromAuxStream( envelopeInfoPtr ) )
				status = CRYPT_ERROR_OVERFLOW;

			/* Make sure we start a new segment if we try to add any data */
			envelopeInfoPtr->segmentComplete = TRUE;

			/* We're finished */
			state = ENVSTATE_DONE;
			break;
			}
		}

	/* Remember the state information */
	envelopeInfoPtr->envState = state;

	return( status );
	}

/* Output as much of the postamble as possible into the envelope buffer */

int emitPostamble( ENVELOPE_INFO *envelopeInfoPtr )
	{
	ENV_STATE state = envelopeInfoPtr->envState;
	int status = CRYPT_OK;

	/* If there's any data left in the auxiliary buffer, try and empty that
	   first */
	if( envelopeInfoPtr->auxBufPos && copyFromAuxBuffer( envelopeInfoPtr ) )
		return( CRYPT_ERROR_OVERFLOW );

	/* Emit the trailer */
	if( state == ENVSTATE_NONE )
		{
		/* Finish the OCTET STRING encoding by flushing any remaining data
		   from internal buffers into the envelope buffer and adding PKCS #5
		   padding if we're using a block encryption mode */
		status = envelopeInfoPtr->copyToEnvelope( envelopeInfoPtr, 
												  ( BYTE * ) "", 0 );
		if( cryptStatusError( status ) )
			return( status );

		/* If it's something other than pure encrypted data, emit the data
		   end-of-contents octets and follow it with the trailer */
		if( envelopeInfoPtr->usage == ACTION_SIGN )
			{
			/* Write the end-of-contents octets for the Data OCTET STRING,
			   [0], and SEQUENCE if necessary */
			if( envelopeInfoPtr->payloadSize == CRYPT_UNUSED )
				{
				writeEndIndef( &envelopeInfoPtr->auxStream );
				writeEndIndef( &envelopeInfoPtr->auxStream );
				writeEndIndef( &envelopeInfoPtr->auxStream );
				}
			envelopeInfoPtr->lastAction = \
				findAction( envelopeInfoPtr->postActionList, ACTION_SIGN );

			/* Write the signing cert chain if it's a CMS signature, and the
			   SET OF SignerInfo header */
			if( envelopeInfoPtr->type == CRYPT_FORMAT_CMS || \
				envelopeInfoPtr->type == CRYPT_FORMAT_SMIME )
				{
				RESOURCE_DATA msgData;

				setResourceData( &msgData, 
								 sMemBufPtr( &envelopeInfoPtr->auxStream ), 
								 sMemBufSize( &envelopeInfoPtr->auxStream ) - \
									stell( &envelopeInfoPtr->auxStream ) );
				status = krnlSendMessage( envelopeInfoPtr->lastAction->iCryptHandle,
								RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData,
								CRYPT_IATTRIBUTE_CERTSET );
				if( cryptStatusError( status ) )
					return( status );
				sSkip( &envelopeInfoPtr->auxStream,
					   envelopeInfoPtr->extraDataSize );
				}
			writeSet( &envelopeInfoPtr->auxStream,
					  envelopeInfoPtr->signActionSize );

			state = ENVSTATE_SIGNATURE;
			if( copyFromAuxStream( envelopeInfoPtr ) )
				{
				envelopeInfoPtr->envState = state;
				return( CRYPT_ERROR_OVERFLOW );
				}
			}
		else
			{
			/* There's no trailer, emit the various end-of-contents octets if 
			   necessary */
			if( envelopeInfoPtr->payloadSize == CRYPT_UNUSED ) 
				{
				/* Write the end-of-contents octets for the encapsulated data
				   if necessary */
				if( envelopeInfoPtr->usage == ACTION_CRYPT || \
					envelopeInfoPtr->usage == ACTION_COMPRESS ) 
					{
					writeEndIndef( &envelopeInfoPtr->auxStream );
					writeEndIndef( &envelopeInfoPtr->auxStream );
					if( envelopeInfoPtr->usage == ACTION_COMPRESS )
						/* Compressed data requires an extra EOC due to the 
						   explicit tagging */
						writeEndIndef( &envelopeInfoPtr->auxStream );
					}
				state = ENVSTATE_EOC;
				}
			else
				state = ENVSTATE_DONE;
			}
		}

	/* Keep producing output until we fill the envelope buffer or run out of
	   trailer information to encode */
	while( state != ENVSTATE_DONE )
		{
		/* Handle signing actions */
		if( state == ENVSTATE_SIGNATURE )
			{
			ACTION_LIST *lastActionPtr = envelopeInfoPtr->lastAction;

			assert( lastActionPtr != NULL && lastActionPtr->action == ACTION_SIGN );

			/* Sign each hash using the associated signature key */
			while( cryptStatusOK( status ) && lastActionPtr != NULL )
				{
				int signingAttributes;

				/* Determine the type of signing attributes to use.  If none 
				   are specified (which can only happen under circumstances
				   controlled by the pre-envelope-signing code), either get 
				   the signing code to add the default ones for use, or use 
				   none at all if the use of default attributes is disabled */
				signingAttributes = lastActionPtr->iExtraData;
				if( signingAttributes == CRYPT_ERROR )
					{
					int useDefaultAttributes;

					krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
									 &useDefaultAttributes, 
									 CRYPT_OPTION_CMS_DEFAULTATTRIBUTES );
					signingAttributes = useDefaultAttributes ? \
										CRYPT_USE_DEFAULT : CRYPT_UNUSED;
					}

				/* Generate the signature into the aux.buffer and copy as
				   much as possible of it into the envelope buffer */
				status = iCryptCreateSignatureEx( envelopeInfoPtr->auxBuffer,
						&envelopeInfoPtr->auxBufPos, envelopeInfoPtr->type,
						lastActionPtr->iCryptHandle,
						lastActionPtr->associatedAction->iCryptHandle,
						signingAttributes, lastActionPtr->auxInfo );
				lastActionPtr = lastActionPtr->next;
				if( !cryptStatusError( status ) && \
					copyFromAuxBuffer( envelopeInfoPtr ) )
					status = CRYPT_ERROR_OVERFLOW;
				}
			envelopeInfoPtr->lastAction = lastActionPtr;

			/* If we've reached the last signature action, move on to the
			   next state.  Since the emission of the signature information
			   is interruptible, we only move on to the next state if there
			   are no errors */
			if( cryptStatusError( status ) )
				break;
			if( envelopeInfoPtr->hasIndefiniteTrailer )
				{
				/* The trailer has an indefinite length, write the EOC for
				   the trailer to the output */
				writeEndIndef( &envelopeInfoPtr->auxStream );
				if( copyFromAuxStream( envelopeInfoPtr ) )
					status = CRYPT_ERROR_OVERFLOW;
				}
			state = ( envelopeInfoPtr->payloadSize == CRYPT_UNUSED ) ? \
					ENVSTATE_EOC : ENVSTATE_DONE;
			}

		/* Handle the final end-of-contents octets */
		if( state == ENVSTATE_EOC )
			{
			/* Write the end-of-contents octets for the OCTET STRING/SEQUENCE,
			   [0], and SEQUENCE if necessary */
			writeEndIndef( &envelopeInfoPtr->auxStream );
			writeEndIndef( &envelopeInfoPtr->auxStream );
			writeEndIndef( &envelopeInfoPtr->auxStream );
			if( copyFromAuxStream( envelopeInfoPtr ) )
				status = CRYPT_ERROR_OVERFLOW;

			/* We're done */
			state = ENVSTATE_DONE;
			}
		}

	/* Remember the state information */
	envelopeInfoPtr->envState = state;

	/* Now that we've written the final end-of-contents octets, set the end-
	   of-segment-data pointer to the end of the data in the buffer so
	   copyFromEnvelope() can copy out the remaining data */
	if( cryptStatusOK( status ) && state == ENVSTATE_DONE )
		envelopeInfoPtr->segmentDataEnd = envelopeInfoPtr->bufPos;

	return( status );
	}
