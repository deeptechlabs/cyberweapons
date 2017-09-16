/****************************************************************************
*																			*
*						cryptlib Enveloping Routines						*
*					  Copyright Peter Gutmann 1996-1999						*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "asn1oid.h"
  #include "envelope.h"
#else
  #include "keymgmt/asn1oid.h"
  #include "envelope/envelope.h"
#endif /* Compiler-specific includes */

/* The default size for the envelope buffer and auxiliary buffer used as a 
   staging area for assembling information.  Under DOS and Win16 they're 
   smaller because of memory and int size limitations */

#if defined( __MSDOS16__ )
  #define DEFAULT_BUFFER_SIZE		8192
#elif defined( __WIN16__ )
  #define DEFAULT_BUFFER_SIZE		16384
#else
  #define DEFAULT_BUFFER_SIZE		32768
#endif /* OS-specific envelope size defines */
#define DEFAULT_AUXBUFFER_SIZE		8192

/* Prototypes for functions in envelope/resource.c */

void deleteActionList( ACTION_LIST *actionListPtr );
void deleteContentList( CONTENT_LIST *contentListPtr );

/****************************************************************************
*																			*
*						Envelope Attribute Handling Functions				*
*																			*
****************************************************************************/

/* Move the envelope component cursor */

static int moveCursor( ENVELOPE_INFO *envelopeInfoPtr, const int value )
	{
	if( envelopeInfoPtr->contentList == NULL )
		return( CRYPT_ERROR_NOTFOUND );	/* Nothing to move the cursor to */

	switch( value )
		{
		case CRYPT_CURSOR_FIRST:
			envelopeInfoPtr->contentListCurrent = envelopeInfoPtr->contentList;
			break;

		case CRYPT_CURSOR_PREVIOUS:
			if( envelopeInfoPtr->contentListCurrent == NULL || \
				envelopeInfoPtr->contentListCurrent == envelopeInfoPtr->contentList )
				return( CRYPT_ERROR_NOTFOUND );
			else
				{
				CONTENT_LIST *contentListPtr = envelopeInfoPtr->contentList;

				/* Find the previous element in the list */
				while( contentListPtr->next != envelopeInfoPtr->contentListCurrent )
					contentListPtr = contentListPtr->next;
				envelopeInfoPtr->contentListCurrent = contentListPtr;
				}
			break;

		case CRYPT_CURSOR_NEXT:
			if( envelopeInfoPtr->contentListCurrent == NULL || \
				envelopeInfoPtr->contentListCurrent->next == NULL )
				return( CRYPT_ERROR_NOTFOUND );
			envelopeInfoPtr->contentListCurrent = envelopeInfoPtr->contentListCurrent->next;
			break;

		case CRYPT_CURSOR_LAST:
			envelopeInfoPtr->contentListCurrent = envelopeInfoPtr->contentList;
			while( envelopeInfoPtr->contentListCurrent->next != NULL )
				envelopeInfoPtr->contentListCurrent = envelopeInfoPtr->contentListCurrent->next;
			break;

		default:
			return( CRYPT_ARGERROR_NUM1 );
		}

	return( CRYPT_OK );
	}

/* Handle data sent to or read from an envelope object */

static int processGetAttribute( ENVELOPE_INFO *envelopeInfoPtr,
								void *messageDataPtr, const int messageValue )
	{
	CRYPT_HANDLE iCryptHandle;
	MESSAGE_KEYMGMT_INFO getkeyInfo;
	CONTENT_LIST *contentListItem;
	int *valuePtr = ( int * ) messageDataPtr, status;

	/* Generic attributes are valid for all envelope types */
	if( messageValue == CRYPT_ATTRIBUTE_BUFFERSIZE )
		{
		*valuePtr = envelopeInfoPtr->bufSize;
		return( CRYPT_OK );
		}
	if( messageValue == CRYPT_ATTRIBUTE_ERRORTYPE )
		{
		*valuePtr = envelopeInfoPtr->errorType;
		return( CRYPT_OK );
		}
	if( messageValue == CRYPT_ATTRIBUTE_ERRORLOCUS )
		{
		*valuePtr = envelopeInfoPtr->errorLocus;
		return( CRYPT_OK );
		}

	/* Make sure the attribute is valid for this envelope type and state */
	if( messageValue == CRYPT_ENVINFO_CURRENT_COMPONENT || \
		messageValue == CRYPT_ENVINFO_SIGNATURE_RESULT || \
		messageValue == CRYPT_ENVINFO_SIGNATURE || \
		messageValue == CRYPT_ENVINFO_SIGNATURE_EXTRADATA )
		{
		if( !envelopeInfoPtr->isDeenvelope )
			return( CRYPT_ARGERROR_OBJECT );

		/* The following check isn't strictly necessary since we can get some
		   information as soon as it's available, but it leads to less 
		   confusion (for example without this check we can get signer info 
		   long before we can get the signature results, which could be 
		   misinterpreted to mean the signature is bad) and forces the caller 
		   to do things cleanly */
		if( envelopeInfoPtr->usage == ACTION_SIGN && \
			envelopeInfoPtr->state != STATE_FINISHED )
			return( CRYPT_ERROR_INCOMPLETE );
		}
	else
		if( messageValue != CRYPT_ENVINFO_CONTENTTYPE && \
			messageValue != CRYPT_ENVINFO_DETACHEDSIGNATURE )
			return( CRYPT_ARGERROR_VALUE );

	/* If we're querying something which resides in the content list, make 
	   sure there's a content list present.  If it's present but nothing is 
	   selected, select the first entry */
	if( ( messageValue == CRYPT_ENVINFO_CURRENT_COMPONENT || \
		  messageValue == CRYPT_ENVINFO_SIGNATURE_RESULT || \
		  messageValue == CRYPT_ENVINFO_SIGNATURE_EXTRADATA ) && \
		envelopeInfoPtr->contentListCurrent == NULL )
		{
		if( envelopeInfoPtr->contentList == NULL )
			return( CRYPT_ERROR_NOTFOUND );
		envelopeInfoPtr->contentListCurrent = envelopeInfoPtr->contentList;
		}

	/* Handle the various information types */
	switch( messageValue )
		{
		case CRYPT_ENVINFO_CURRENT_COMPONENT:
			/* At this point we need some special handling for some types of 
			   data.  PGP doesn't follow the usual model of encrypting a 
			   session key with a user key and then encrypting the data with 
			   the session key, but instead encrypts the data directly with 
			   the raw key and assumes that if it finds an encrypted data 
			   packet that it should take a password, turn it into a user 
			   key, and use that to decrypt it.  For this reason if we're 
			   deenveloping PGP data and the lower-level routines tell us we 
			   need a session key, we report this to the user as requiring 
			   password information.  The envelope management routines are 
			   intelligent enough to know about the fact that for PGP a 
			   password becomes a session key */
			contentListItem = envelopeInfoPtr->contentListCurrent;
			if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP && \
				contentListItem->envInfo == CRYPT_ENVINFO_SESSIONKEY )
				{
				*valuePtr = CRYPT_ENVINFO_PASSWORD;
				return( CRYPT_OK );
				}

			/* If we need something other than a private key or we need a 
			   private key but there's no keyset present to fetch it from, 
			   just report what we need and exit */
			if( contentListItem->envInfo != CRYPT_ENVINFO_PRIVATEKEY || \
				envelopeInfoPtr->iDecryptionKeyset == CRYPT_ERROR )
				{
				*valuePtr = contentListItem->envInfo;
				return( CRYPT_OK );
				}

			/* There's a decryption keyset available, try and get the 
			   required key from it.  Unlike sig.check keyset access, we 
			   retry the access every time we're called because we may be
			   talking to a device which has a trusted authentication path
			   which is outside our control, so that the first read fails if 
			   the user hasn't entered their PIN but a second read once 
			   they've entered it will succeed */
			if( contentListItem->issuerAndSerialNumber == NULL )
				{
				setMessageKeymgmtInfo( &getkeyInfo, CRYPT_IKEYID_KEYID,
								contentListItem->keyID,
								contentListItem->keyIDsize, NULL, 0,
								KEYMGMT_FLAG_PRIVATEKEY );
				}
			else
				{
				setMessageKeymgmtInfo( &getkeyInfo, 
								CRYPT_IKEYID_ISSUERANDSERIALNUMBER,
								contentListItem->issuerAndSerialNumber,
								contentListItem->issuerAndSerialNumberSize,
								NULL, 0, KEYMGMT_FLAG_PRIVATEKEY );
				}
			status = krnlSendMessage( envelopeInfoPtr->iDecryptionKeyset,
									  RESOURCE_IMESSAGE_KEY_GETKEY, &getkeyInfo, 0 );

			/* If we managed to get the private key (either bcause it wasn't 
			   protected by a password if it's in a keyset or because it came
			   from a device), push it into the envelope.  If the call 
			   succeeds, this will import the session key and delete the 
			   required-information list */
			if( cryptStatusOK( status ) )
				{
				status = envelopeInfoPtr->addInfo( envelopeInfoPtr,
												   CRYPT_ENVINFO_PRIVATEKEY,
												   &getkeyInfo.cryptHandle, 0 );
				krnlSendNotifier( getkeyInfo.cryptHandle, 
								  RESOURCE_IMESSAGE_DECREFCOUNT );
				}

			/* If we got the key, there's nothing else needed.  If we didn't,
			   we still return an OK status since the caller is asking us for
			   the resource which is required and not the status of any 
			   background operation which was performed while trying to obtain
			   it */
			*valuePtr = cryptStatusError( status ) ? \
							envelopeInfoPtr->contentListCurrent->envInfo : \
							CRYPT_ATTRIBUTE_NONE;
			return( CRYPT_OK );

		case CRYPT_ENVINFO_CONTENTTYPE:
			if( envelopeInfoPtr->contentType == CRYPT_CONTENT_NONE )
				return( CRYPT_ERROR_NOTFOUND );
			*valuePtr = envelopeInfoPtr->contentType;
			return( CRYPT_OK );

		case CRYPT_ENVINFO_DETACHEDSIGNATURE:
			/* If this isn't a signed data or we haven't sorted out the 
			   content details yet, we don't know whether it's a detached sig 
			   or not */
			if( envelopeInfoPtr->usage != ACTION_SIGN || \
				envelopeInfoPtr->contentType == CRYPT_CONTENT_NONE )
				return( CRYPT_ERROR_NOTFOUND );
			*valuePtr = envelopeInfoPtr->detachedSig;
			return( CRYPT_OK );

		case CRYPT_ENVINFO_SIGNATURE_RESULT:
			/* Make sure the content list item is of the appropriate type, 
			   and if we've already done this one don't process it a second 
			   time.  This check is also performed by the addInfo() code, but
			   we duplicate it here to avoid having to do an unnecessary key 
			   fetch for non-CMS signatures */
			contentListItem = envelopeInfoPtr->contentListCurrent;
			if( contentListItem->envInfo != CRYPT_ENVINFO_SIGNATURE )
				return( CRYPT_ERROR_NOTFOUND );
			if( contentListItem->processed )
				{
				*valuePtr = contentListItem->processingResult;
				return( CRYPT_OK );
				}

			/* Make sure there's a keyset available to pull the key from and 
			   get the owner ID.  Since CMS signatures usually carry their 
			   own cert chains, we don't perform this check if there's a cert
			   chain available */
			if( envelopeInfoPtr->iSignerChain == CRYPT_ERROR )
				{
				if( envelopeInfoPtr->iSigCheckKeyset == CRYPT_ERROR )
					{
					setErrorInfo( envelopeInfoPtr, CRYPT_ENVINFO_KEYSET_SIGCHECK,
								  CRYPT_ERRTYPE_ATTR_ABSENT );
					return( CRYPT_ERROR_NOTINITED );
					}

				/* Try and get the key information */
				if( contentListItem->issuerAndSerialNumber == NULL )
					{
					setMessageKeymgmtInfo( &getkeyInfo, CRYPT_IKEYID_KEYID,
								contentListItem->keyID,
								contentListItem->keyIDsize, NULL, 0,
								KEYMGMT_FLAG_PUBLICKEY );
					}
				else
					{
					setMessageKeymgmtInfo( &getkeyInfo, 
								CRYPT_IKEYID_ISSUERANDSERIALNUMBER,
								contentListItem->issuerAndSerialNumber,
								contentListItem->issuerAndSerialNumberSize,
								NULL, 0, KEYMGMT_FLAG_PUBLICKEY );
					}
				status = krnlSendMessage( envelopeInfoPtr->iSigCheckKeyset,
							RESOURCE_IMESSAGE_KEY_GETKEY, &getkeyInfo, 0 );
				if( cryptStatusError( status ) )
					return( status );
				iCryptHandle = getkeyInfo.cryptHandle;
				}

			/* Push the public key into the envelope, which performs the
			   signature check */
			*valuePtr = envelopeInfoPtr->addInfo( envelopeInfoPtr,
												  CRYPT_ENVINFO_SIGNATURE,
												  &iCryptHandle, 0 );
			if( envelopeInfoPtr->iSignerChain == CRYPT_ERROR )
				/* If it's a newly-created key, we don't need it any more */
				krnlSendNotifier( iCryptHandle, RESOURCE_IMESSAGE_DECREFCOUNT );
			return( CRYPT_OK );

		case CRYPT_ENVINFO_SIGNATURE:
			/* If there's an attached cert use that, otherwise use the key 
			   which was used to check the signature */
			if( envelopeInfoPtr->iSignerChain != CRYPT_ERROR )
				iCryptHandle = envelopeInfoPtr->iSignerChain;
			else
				if( envelopeInfoPtr->contentListCurrent != NULL && \
					envelopeInfoPtr->contentListCurrent->iSigCheckKey != CRYPT_ERROR )
					iCryptHandle = envelopeInfoPtr->contentListCurrent->iSigCheckKey;
				else
					return( CRYPT_ERROR_NOTFOUND );

			/* Make the information externally visible */
			krnlSendNotifier( iCryptHandle, RESOURCE_IMESSAGE_INCREFCOUNT );
			krnlSendMessage( iCryptHandle, RESOURCE_IMESSAGE_SETATTRIBUTE,
							 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_INTERNAL );
			*valuePtr = iCryptHandle;
			return( CRYPT_OK );

		case CRYPT_ENVINFO_SIGNATURE_EXTRADATA:
			/* Make sure there's extra data present */
			iCryptHandle = envelopeInfoPtr->contentListCurrent->iExtraData;
			if( iCryptHandle == CRYPT_ERROR )
				return( CRYPT_ERROR_NOTFOUND );
	
			/* Make the information externally visible */
			krnlSendNotifier( iCryptHandle, RESOURCE_IMESSAGE_INCREFCOUNT );
			krnlSendMessage( iCryptHandle, RESOURCE_IMESSAGE_SETATTRIBUTE, 
							 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_INTERNAL );
			*valuePtr = iCryptHandle;
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( 0 );		/* Get rid of compiler warning */
	}

static int processGetAttributeS( ENVELOPE_INFO *envelopeInfoPtr,
								 void *messageDataPtr, const int messageValue )
	{
	CONTENT_LIST *contentListItem;
	int status;

	/* If we're querying something which resides in the content list, make 
	   sure there's a content list present.  If it's present but nothing is 
	   selected, select the first entry */
	if( messageValue == CRYPT_ENVINFO_PRIVATEKEY_LABEL && \
		envelopeInfoPtr->contentListCurrent == NULL )
		{
		if( envelopeInfoPtr->contentList == NULL )
			return( CRYPT_ERROR_NOTFOUND );
		envelopeInfoPtr->contentListCurrent = envelopeInfoPtr->contentList;
		}

	/* Generic attributes are valid for all envelope types */
	if( messageValue == CRYPT_ENVINFO_PRIVATEKEY_LABEL )
		{
		MESSAGE_KEYMGMT_INFO getkeyInfo;
		char label[ CRYPT_MAX_TEXTSIZE ];

		/* Make sure that the current required resource is a private key and
		   that there's a keyset available to pull the key from */
		contentListItem = envelopeInfoPtr->contentListCurrent;
		if( contentListItem->envInfo != CRYPT_ENVINFO_PRIVATEKEY )
			return( CRYPT_ERROR_NOTFOUND );
		if( envelopeInfoPtr->iDecryptionKeyset == CRYPT_ERROR )
			{
			setErrorInfo( envelopeInfoPtr, CRYPT_ENVINFO_KEYSET_DECRYPT,
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTINITED );
			}

		/* Try and get the key label information */
		if( contentListItem->issuerAndSerialNumber == NULL )
			{
			setMessageKeymgmtInfo( &getkeyInfo, CRYPT_IKEYID_KEYID,
								   contentListItem->keyID,
								   contentListItem->keyIDsize, 
								   label, CRYPT_MAX_TEXTSIZE,
								   KEYMGMT_FLAG_LABEL_ONLY );
			}
		else
			{
			setMessageKeymgmtInfo( &getkeyInfo, 
								   CRYPT_IKEYID_ISSUERANDSERIALNUMBER,
								   contentListItem->issuerAndSerialNumber,
								   contentListItem->issuerAndSerialNumberSize,
								   label, CRYPT_MAX_TEXTSIZE,
								   KEYMGMT_FLAG_LABEL_ONLY );
			}
		status = krnlSendMessage( envelopeInfoPtr->iDecryptionKeyset,
								  RESOURCE_IMESSAGE_KEY_GETKEY, &getkeyInfo, 0 );
		if( cryptStatusOK( status ) )
			return( attributeCopy( messageDataPtr, getkeyInfo.auxInfo, 
								   getkeyInfo.auxInfoLength ) );
		return( status );
		}

	assert( NOTREACHED );
	return( 0 );		/* Get rid of compiler warning */
	}

static int processSetAttribute( ENVELOPE_INFO *envelopeInfoPtr,
								void *messageDataPtr, const int messageValue )
	{
	RESOURCE_MESSAGE_CHECK_TYPE checkType = RESOURCE_MESSAGE_CHECK_NONE;
	OBJECT_TYPE objectType = OBJECT_TYPE_CONTEXT;
	const int value = *( int * ) messageDataPtr;

	/* If it's an initialisation message, there's nothing to do */
	if( messageValue == CRYPT_IATTRIBUTE_INITIALISED )
		return( CRYPT_OK );

	/* Generic attributes are valid for all envelope types */
	if( messageValue == CRYPT_ATTRIBUTE_BUFFERSIZE )
		{
		envelopeInfoPtr->bufSize = value;
		return( CRYPT_OK );
		}

	/* In general we can't add new enveloping information once we've started
	   processing data */
	if( messageValue != CRYPT_ENVINFO_CURRENT_COMPONENT && \
		envelopeInfoPtr->state != STATE_PREDATA )
		{
		/* We can't add new information once we've started enveloping */
		if( !envelopeInfoPtr->isDeenvelope )
			return( CRYPT_ERROR_INITED );

		/* We can only add signature check information once we've started
		   de-enveloping */
		if( messageValue != CRYPT_ENVINFO_SIGNATURE )
			return( CRYPT_ERROR_INITED );
		}

	/* Since the information may not be used for quite some time after it's
	   added, we do some preliminary checking here to allow us to return an
	   error code immediately rather than from some deeply-buried function an
	   indeterminate time in the future */
	switch( messageValue )
		{
		case CRYPT_ENVINFO_DATASIZE:
			if( envelopeInfoPtr->isDeenvelope )
				return( CRYPT_ARGERROR_VALUE );
			if( envelopeInfoPtr->payloadSize != CRYPT_UNUSED )
				return( CRYPT_ERROR_INITED );
			break;

#ifndef NO_COMPRESSION
		case CRYPT_ENVINFO_COMPRESSION:
			if( envelopeInfoPtr->usage == ACTION_NONE )
				envelopeInfoPtr->usage = ACTION_COMPRESS;
			else
				if( envelopeInfoPtr->usage != ACTION_COMPRESS )
					return( CRYPT_ERROR_INITED );
			break;
#endif /* NO_COMPRESSION */

		case CRYPT_ENVINFO_CONTENTTYPE:
			if( envelopeInfoPtr->isDeenvelope || \
				envelopeInfoPtr->type == CRYPT_FORMAT_SMIME )
				return( CRYPT_ARGERROR_VALUE );

			/* For user-friendliness we allow overwriting a given content
			   type with the same type, which is useful for cases when
			   cryptlib automatically presets the type based on other
			   information */
			if( envelopeInfoPtr->contentType && \
				envelopeInfoPtr->contentType != value )
				return( CRYPT_ERROR_INITED );
			break;

		case CRYPT_ENVINFO_DETACHEDSIGNATURE:
			if( envelopeInfoPtr->isDeenvelope )
				return( CRYPT_ARGERROR_VALUE );
			break;

		case CRYPT_ENVINFO_CURRENT_COMPONENT:
			if( !envelopeInfoPtr->isDeenvelope )
				return( CRYPT_ARGERROR_VALUE );
			break;

		case CRYPT_ENVINFO_KEY:
		case CRYPT_ENVINFO_SESSIONKEY:
			checkType = RESOURCE_MESSAGE_CHECK_CRYPT;
			if( envelopeInfoPtr->usage == ACTION_NONE )
				envelopeInfoPtr->usage = ACTION_CRYPT;
			else
				if( envelopeInfoPtr->usage != ACTION_CRYPT )
					return( CRYPT_ERROR_INITED );
			break;

		case CRYPT_ENVINFO_SIGNATURE:
			checkType = ( envelopeInfoPtr->isDeenvelope ) ? \
						RESOURCE_MESSAGE_CHECK_PKC_SIGCHECK : \
						RESOURCE_MESSAGE_CHECK_PKC_SIGN;
			if( envelopeInfoPtr->usage == ACTION_NONE )
				envelopeInfoPtr->usage = ACTION_SIGN;
			else
				if( envelopeInfoPtr->usage != ACTION_SIGN )
					return( CRYPT_ERROR_INITED );
			break;

		case CRYPT_ENVINFO_SIGNATURE_EXTRADATA:
			if( envelopeInfoPtr->isDeenvelope || \
				( envelopeInfoPtr->type != CRYPT_FORMAT_CMS && \
				  envelopeInfoPtr->type != CRYPT_FORMAT_SMIME ) )
				return( CRYPT_ARGERROR_VALUE );
			else
				if( envelopeInfoPtr->usage != ACTION_SIGN )
					return( CRYPT_ERROR_NOTINITED );
			break;

		case CRYPT_ENVINFO_PUBLICKEY:
			checkType = RESOURCE_MESSAGE_CHECK_PKC_ENCRYPT;
			if( envelopeInfoPtr->usage == ACTION_NONE )
				envelopeInfoPtr->usage = ACTION_CRYPT;
			else
				if( envelopeInfoPtr->usage != ACTION_CRYPT )
					return( CRYPT_ERROR_INITED );
			break;

		case CRYPT_ENVINFO_PRIVATEKEY:
			checkType = RESOURCE_MESSAGE_CHECK_PKC_DECRYPT;
			if( envelopeInfoPtr->usage == ACTION_NONE )
				envelopeInfoPtr->usage = ACTION_CRYPT;
			else
				if( envelopeInfoPtr->usage != ACTION_CRYPT )
					return( CRYPT_ERROR_INITED );
			break;

		case CRYPT_ENVINFO_ORIGINATOR:
			checkType = RESOURCE_MESSAGE_CHECK_PKC_KA_EXPORT;
			if( envelopeInfoPtr->usage == ACTION_NONE )
				envelopeInfoPtr->usage = ACTION_CRYPT;
			else
				if( envelopeInfoPtr->usage != ACTION_CRYPT )
					return( CRYPT_ERROR_INITED );
			if( envelopeInfoPtr->iOriginatorChain != CRYPT_ERROR )
				return( CRYPT_ERROR_INITED );
			break;

		case CRYPT_ENVINFO_HASH:
			checkType = RESOURCE_MESSAGE_CHECK_HASH;
			if( envelopeInfoPtr->usage == ACTION_NONE )
				envelopeInfoPtr->usage = ACTION_SIGN;
			else
				if( envelopeInfoPtr->usage != ACTION_SIGN )
					return( CRYPT_ERROR_INITED );
			break;

		case CRYPT_ENVINFO_KEYSET_ENCRYPT:
			checkType = RESOURCE_MESSAGE_CHECK_PKC_ENCRYPT;
			objectType = OBJECT_TYPE_KEYSET;
			if( envelopeInfoPtr->isDeenvelope )
				return( CRYPT_ARGERROR_VALUE );
			if( envelopeInfoPtr->iEncryptionKeyset != CRYPT_ERROR )
				return( CRYPT_ERROR_INITED );
			break;

		case CRYPT_ENVINFO_KEYSET_DECRYPT:
			checkType = RESOURCE_MESSAGE_CHECK_PKC_DECRYPT;
			objectType = OBJECT_TYPE_KEYSET;
			if( !envelopeInfoPtr->isDeenvelope )
				return( CRYPT_ARGERROR_VALUE );
			if( envelopeInfoPtr->iDecryptionKeyset != CRYPT_ERROR )
				return( CRYPT_ERROR_INITED );
			break;

		case CRYPT_ENVINFO_KEYSET_SIGCHECK:
			checkType = RESOURCE_MESSAGE_CHECK_PKC_SIGCHECK;
			objectType = OBJECT_TYPE_KEYSET;
			if( !envelopeInfoPtr->isDeenvelope )
				return( CRYPT_ARGERROR_VALUE );
			if( envelopeInfoPtr->iSigCheckKeyset != CRYPT_ERROR )
				return( CRYPT_ERROR_INITED );
			break;

		default:
			return( CRYPT_ARGERROR_VALUE );
		}
	if( checkType != RESOURCE_MESSAGE_CHECK_NONE )
		{
		int type, status;

		/* Check the object as appropriate.  A key agreement key can also act 
		   as a public key because of the way KEA works, so if a check for a
		   straight public key fails we try again to see if it's a key
		   agreement key with import capabilities */
		status = krnlSendMessage( value, RESOURCE_MESSAGE_CHECK, NULL,
								  checkType );
		if( status == CRYPT_ARGERROR_OBJECT && \
			messageValue == CRYPT_ENVINFO_PUBLICKEY )
			status = krnlSendMessage( value, RESOURCE_MESSAGE_CHECK, NULL,
									  RESOURCE_MESSAGE_CHECK_PKC_KA_IMPORT );
		if( cryptStatusError( status ) )
			return( CRYPT_ARGERROR_NUM1 );

		/* Make sure the object corresponds to a representable algorithm 
		   type */
		if( ( checkType == RESOURCE_MESSAGE_CHECK_CRYPT || 
			  checkType == RESOURCE_MESSAGE_CHECK_HASH ) && \
			( envelopeInfoPtr->type == CRYPT_FORMAT_CRYPTLIB || \
			  envelopeInfoPtr->type == CRYPT_FORMAT_CMS || \
			  envelopeInfoPtr->type == CRYPT_FORMAT_SMIME ) )
			{
			CRYPT_ALGO algorithm;
			CRYPT_MODE mode;

			krnlSendMessage( value, RESOURCE_MESSAGE_GETATTRIBUTE, &algorithm, 
							 CRYPT_CTXINFO_ALGO );
			if( algorithm >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
				algorithm <= CRYPT_ALGO_LAST_CONVENTIONAL )
				krnlSendMessage( value, RESOURCE_MESSAGE_GETATTRIBUTE, &mode, 
								 CRYPT_CTXINFO_MODE );
			else
				mode = CRYPT_MODE_NONE;
			if( !checkAlgoID( algorithm, mode ) )
				return( CRYPT_ERROR_NOTAVAIL );
			}

		/* Make sure the object is of the correct type */
		status = krnlSendMessage( value, RESOURCE_IMESSAGE_GETATTRIBUTE,
								  &type, CRYPT_IATTRIBUTE_TYPE );
		if( cryptStatusError( status ) )
			return( status );
		if( messageValue == CRYPT_ENVINFO_SIGNATURE || \
			messageValue == CRYPT_ENVINFO_PUBLICKEY || \
			messageValue == CRYPT_ENVINFO_PRIVATEKEY || \
			messageValue == CRYPT_ENVINFO_ORIGINATOR )
			{
			/* Public-key objects can be encryption contexts or certificates */
			if( type != objectType && type != OBJECT_TYPE_CERTIFICATE )
				return( CRYPT_ARGERROR_NUM1 );

			/* If we're using CMS enveloping, the object must have a cert of
			   the correct type associated with it */
			if( envelopeInfoPtr->type == CRYPT_FORMAT_CMS || \
				envelopeInfoPtr->type == CRYPT_FORMAT_SMIME )
				{
				int certType;

				status = krnlSendMessage( value, RESOURCE_MESSAGE_GETATTRIBUTE,
										  &certType, CRYPT_CERTINFO_CERTTYPE );
				if( cryptStatusError( status ) ||
					( certType != CRYPT_CERTTYPE_CERTIFICATE && \
					  certType != CRYPT_CERTTYPE_CERTCHAIN ) )
					return( CRYPT_ARGERROR_NUM1 );
				}
			}
		else
			if( type != objectType && \
				( objectType == OBJECT_TYPE_KEYSET && \
				  type != OBJECT_TYPE_DEVICE ) )
				return( CRYPT_ARGERROR_NUM1 );
		}
	else
		/* If it's additional signature information, make sure the object is
		   CMS attributes */
		if( messageValue == CRYPT_ENVINFO_SIGNATURE_EXTRADATA )
			{
			int certType, status;

			status = krnlSendMessage( value, RESOURCE_MESSAGE_GETATTRIBUTE,
									  &certType, CRYPT_CERTINFO_CERTTYPE );
			if( cryptStatusError( status ) ||
				certType != CRYPT_CERTTYPE_CMS_ATTRIBUTES )
				return( CRYPT_ARGERROR_NUM1 );
			}

	/* If it's meta-information, process it now */
	if( messageValue == CRYPT_ENVINFO_CURRENT_COMPONENT )
		return( moveCursor( envelopeInfoPtr, value ) );

	/* Add it to the envelope */
	return( envelopeInfoPtr->addInfo( envelopeInfoPtr, messageValue,
									  &value, 0 ) );
	}

static int processSetAttributeS( ENVELOPE_INFO *envelopeInfoPtr,
								 void *messageDataPtr, const int messageValue )
	{
	RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
	MESSAGE_KEYMGMT_INFO getkeyInfo;
	int status;

	/* Handle the various information types */
	switch( messageValue )
		{
		case CRYPT_ENVINFO_PASSWORD:
			/* Set the envelope usage type based on the fact that we've been
			   fed a password */
			if( envelopeInfoPtr->usage == ACTION_NONE )
				envelopeInfoPtr->usage = ACTION_CRYPT;
			else
				if( envelopeInfoPtr->usage != ACTION_CRYPT )
					return( CRYPT_ERROR_INITED );

			/* In general we can't add new enveloping information once we've 
			   started processing data */
			if( envelopeInfoPtr->state != STATE_PREDATA && \
				!envelopeInfoPtr->isDeenvelope )
				/* We can't add new information once we've started enveloping */
				return( CRYPT_ERROR_INITED );

			/* Add it to the envelope */
			return( envelopeInfoPtr->addInfo( envelopeInfoPtr, 
						CRYPT_ENVINFO_PASSWORD, msgData->data, msgData->length ) );

		case CRYPT_ENVINFO_RECIPIENT:
			/* Set the envelope usage type based on the fact that we've been
			   fed a recipient email address */
			if( envelopeInfoPtr->usage == ACTION_NONE )
				envelopeInfoPtr->usage = ACTION_CRYPT;
			else
				if( envelopeInfoPtr->usage != ACTION_CRYPT )
					return( CRYPT_ERROR_INITED );

			/* Make sure there's a keyset available to pull the recipients 
			   key from */
			if( envelopeInfoPtr->iEncryptionKeyset == CRYPT_ERROR )
				{
				setErrorInfo( envelopeInfoPtr, CRYPT_ENVINFO_KEYSET_ENCRYPT,
							  CRYPT_ERRTYPE_ATTR_ABSENT );
				return( CRYPT_ERROR_NOTINITED );
				}

			/* Try and read the recipients key from the keyset */
			setMessageKeymgmtInfo( &getkeyInfo, CRYPT_KEYID_EMAIL,
								   msgData->data, msgData->length, NULL, 0,
								   KEYMGMT_FLAG_PUBLICKEY );
			status = krnlSendMessage( envelopeInfoPtr->iEncryptionKeyset,
									  RESOURCE_IMESSAGE_KEY_GETKEY, &getkeyInfo, 0 );
			if( cryptStatusOK( status ) )
				{
				/* We got the key, add it to the envelope */
				status = envelopeInfoPtr->addInfo( envelopeInfoPtr,
												   CRYPT_ENVINFO_PUBLICKEY,
												   &getkeyInfo.cryptHandle, 0 );
				krnlSendNotifier( getkeyInfo.cryptHandle, 
								  RESOURCE_IMESSAGE_DECREFCOUNT );
				}
			return( status );

		case CRYPT_ENVINFO_TIMESTAMP_AUTHORITY:
			/* Set the envelope usage type based on the fact that we've been
			   fed a TSA URL */
			if( envelopeInfoPtr->usage == ACTION_NONE )
				envelopeInfoPtr->usage = ACTION_SIGN;
			else
				if( envelopeInfoPtr->usage != ACTION_SIGN )
					return( CRYPT_ERROR_INITED );

			/* Add it to the envelope */
			return( envelopeInfoPtr->addInfo( envelopeInfoPtr, 
						CRYPT_ENVINFO_TIMESTAMP_AUTHORITY, msgData->data, 
						msgData->length ) );
		}

	assert( NOTREACHED );
	return( 0 );		/* Get rid of compiler warning */
	}

/****************************************************************************
*																			*
*							Envelope Data Handling Functions				*
*																			*
****************************************************************************/

/* Push data into an envelope */

static int envelopePush( ENVELOPE_INFO *envelopeInfoPtr, void *buffer,
						 const int length, int *bytesCopied )
	{
	int status;

	/* Clear return value */
	*bytesCopied = 0;

	/* PGP enveloping isn't supported yet */
	if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP )
		return( CRYPT_ERROR_PERMISSION );

	/* If we haven't started processing data yet, handle the initial data
	   specially */
	if( envelopeInfoPtr->state == STATE_PREDATA )
		{
		/* If the envelope buffer hasn't been allocated yet, allocate it now */
		if( envelopeInfoPtr->buffer == NULL )
			{
			if( ( envelopeInfoPtr->buffer = malloc( envelopeInfoPtr->bufSize ) ) == NULL )
				return( CRYPT_ERROR_MEMORY );
			memset( envelopeInfoPtr->buffer, 0, envelopeInfoPtr->bufSize );
			}

		/* Emit the header information into the envelope */
		status = envelopeInfoPtr->emitPreamble( envelopeInfoPtr );
		if( cryptStatusError( status ) )
			{
			if( status != CRYPT_ERROR_OVERFLOW )
				envelopeInfoPtr->errorState = status;
			return( status );
			}

		/* The envelope is ready to process data, move it into the high 
		   state */
		krnlSendMessage( envelopeInfoPtr->objectHandle,
						 RESOURCE_IMESSAGE_SETATTRIBUTE, 
						 MESSAGE_VALUE_UNUSED, CRYPT_IATTRIBUTE_INITIALISED );
		envelopeInfoPtr->state = STATE_DATA;
		}

	/* If we're in the main data processing state, add the data and perform
	   any necessary actions on it */
	if( envelopeInfoPtr->state == STATE_DATA )
		{
		if( length )
			{
			/* Copy the data to the envelope buffer, taking blocking
			   requirements into account */
			status = envelopeInfoPtr->copyToEnvelope( envelopeInfoPtr,
													  buffer, length );
			*bytesCopied = status;
			if( cryptStatusError( status ) )
				{
				envelopeInfoPtr->errorState = status;
				return( status );
				}

			return( ( *bytesCopied < length ) ? \
					CRYPT_ERROR_OVERFLOW : CRYPT_OK );
			}

		/* This was a flush, move on to the postdata state */
		envelopeInfoPtr->state = STATE_POSTDATA;
		envelopeInfoPtr->envState = ENVSTATE_NONE;
		}

	assert( envelopeInfoPtr->state == STATE_POSTDATA );

	/* We're past the main data-processing state, emit the postamble */
	status = envelopeInfoPtr->emitPostamble( envelopeInfoPtr );
	if( cryptStatusError( status ) )
		{
		if( status != CRYPT_ERROR_OVERFLOW )
			envelopeInfoPtr->errorState = status;
		return( status );
		}
	envelopeInfoPtr->state = STATE_FINISHED;

	return( CRYPT_OK );
	}

static int deenvelopePush( ENVELOPE_INFO *envelopeInfoPtr, void *buffer,
						   const int length, int *bytesCopied )
	{
	BYTE *bufPtr = ( BYTE * ) buffer;
	int bytesIn = length, status;

	/* Clear return value */
	*bytesCopied = 0;

	/* If we haven't started processing data yet, handle the initial data
	   specially */
	if( envelopeInfoPtr->state == STATE_PREDATA )
		{
		/* If the envelope buffer hasn't been allocated yet, allocate it now */
		if( envelopeInfoPtr->buffer == NULL )
			{
			if( ( envelopeInfoPtr->buffer = malloc( envelopeInfoPtr->bufSize ) ) == NULL )
				return( CRYPT_ERROR_MEMORY );
			memset( envelopeInfoPtr->buffer, 0, envelopeInfoPtr->bufSize );
			}

		/* Since we're processing out-of-band information, just copy it in 
		   directly */
		if( bytesIn )
			{
			int bytesToCopy = min( envelopeInfoPtr->bufSize - envelopeInfoPtr->bufPos,
								   bytesIn );
			if( bytesToCopy )
				{
				memcpy( envelopeInfoPtr->buffer + envelopeInfoPtr->bufPos,
						bufPtr, bytesToCopy );
				envelopeInfoPtr->bufPos += bytesToCopy;
				bytesIn -= bytesToCopy;
				*bytesCopied = bytesToCopy;
				bufPtr += bytesToCopy;
				}
			}

		/* Process the preamble */
		status = envelopeInfoPtr->processPreamble( envelopeInfoPtr );
		if( cryptStatusError( status ) )
			{
			if( status != CRYPT_ERROR_UNDERFLOW )	/* Can recover from this */
				envelopeInfoPtr->errorState = status;
			return( status );
			}

		/* The envelope is ready to process data, move it into the high 
		   state */
		krnlSendMessage( envelopeInfoPtr->objectHandle,
						 RESOURCE_IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_UNUSED, 
						 CRYPT_IATTRIBUTE_INITIALISED );

		/* Move on to the data-processing state */
		envelopeInfoPtr->state = STATE_DATA;
		}

	/* If we're in the main data processing state, add the data and perform 
	   any necessary actions on it */
	if( envelopeInfoPtr->state == STATE_DATA )
		{
		/* If there's data to be copied, copy it into the envelope (if we've 
		   come from the predata state, we may have zero bytes to copy if 
		   everything was consumed by the preamble processing, or there may 
		   be room to copy more in if the preamble processing consumed some 
		   of what was present) */
		if( bytesIn )
			{
			/* Copy the data to the envelope */
			*bytesCopied += envelopeInfoPtr->copyToDeenvelope( envelopeInfoPtr,
														bufPtr, bytesIn );
			status = cryptStatusError( *bytesCopied ) ? \
					 *bytesCopied : CRYPT_OK;
			if( cryptStatusError( status ) )
				{
				if( status != CRYPT_ERROR_UNDERFLOW )	/* Can recover from this */
					envelopeInfoPtr->errorState = status;
				return( status );
				}
			bytesIn -= *bytesCopied;
			bufPtr += *bytesCopied;
			}

		/* If we've reached the end of the payload (either by having seen the 
		   EOC octets with the indefinite encoding or by having reached the 
		   end of the single segment with the definite encoding), move on to 
		   the postdata state */
		if( envelopeInfoPtr->endOfContents || \
			( envelopeInfoPtr->payloadSize != CRYPT_UNUSED && \
			  !envelopeInfoPtr->segmentSize ) )
			{
			envelopeInfoPtr->state = STATE_POSTDATA;
			envelopeInfoPtr->deenvState = DEENVSTATE_NONE;
			}
		}

	/* If we're past the main data-processing state, process the postamble */
	if( envelopeInfoPtr->state == STATE_POSTDATA )
		{
		/* Since we're processing trailer information, just copy it in
		   directly */
		if( bytesIn )
			{
/* The handling of EOC information in all situations is very tricky.  With
   PKCS #5 padded data the contents look like:

		    dataLeft	 bufPos
			v			 v
	[ data ][ pad ][ EOC / EOC ]

   The previous processEOC() would leave bufPos as above, the new version
   moves it down to the same location as dataLeft so that after further
   copying it becomes:

		    dataLeft = bufPos
			v			 
	[ data ][ EOC ]

   ie it adjusts both dataLeft and bufPos for padding rather than just 
   dataLeft.  For the orignial version, the two code alternatives produced the
   following results

	- 230K encrypted data, indefinite: Second version 
	- 230K signed data, indefinite: First version and second version 
	- Short signed data, n-4 bytes, then 4 bytes: First version

   The new version works with all self-tests and also with large data amounts.
   This comment has been retained in case a situation is found where it 
   doesn't work */
#if 1
			const int bytesToCopy = \
					min( envelopeInfoPtr->bufSize - envelopeInfoPtr->bufPos,
						 bytesIn );
			if( bytesToCopy )
				{
				memcpy( envelopeInfoPtr->buffer + envelopeInfoPtr->bufPos,
						bufPtr, bytesToCopy );
				envelopeInfoPtr->bufPos += bytesToCopy;
				*bytesCopied += bytesToCopy;
				}
#else
			const int bytesToCopy = \
					min( envelopeInfoPtr->bufSize - envelopeInfoPtr->dataLeft,
						 bytesIn );
			if( bytesToCopy )
				{
				memcpy( envelopeInfoPtr->buffer + envelopeInfoPtr->dataLeft,
						bufPtr, bytesToCopy );
				envelopeInfoPtr->bufPos = envelopeInfoPtr->dataLeft + \
										  bytesToCopy;
				*bytesCopied += bytesToCopy;
				}
#endif /* 1 */
			}

		/* Process the postamble.  During this processing we can encounter 
		   two special types of recoverable error, CRYPT_ERROR_UNDERFLOW (we 
		   need more data to continue) or OK_SPECIAL (we processed all the 
		   data, but there's out-of-band information still to go), if it's 
		   one of these we don't treat it as a standard error */
		status = envelopeInfoPtr->processPostamble( envelopeInfoPtr );
		if( cryptStatusError( status ) && status != OK_SPECIAL )
			{
			if( status != CRYPT_ERROR_UNDERFLOW )
				envelopeInfoPtr->errorState = status;
			return( status );
			}

		/* If the routine returns OK_SPECIAL then it's processed enough of 
		   the postamble for the caller to continue, but there's more to go 
		   so we shouldn't change the overall state yet */
		if( status == OK_SPECIAL )
			status = CRYPT_OK;
		else
			/* We've processed all data, we're done unless it's a detached 
			   sig with the data supplied out-of-band */
			envelopeInfoPtr->state = ( envelopeInfoPtr->detachedSig ) ? \
									 STATE_EXTRADATA : STATE_FINISHED;

		/* At this point we always exit since the out-of-band data has to be 
		   processed in a separate push */
		return( status );
		}

	/* If there's extra out-of-band data present, process it separately */
	if( envelopeInfoPtr->state == STATE_EXTRADATA )
		{
		/* If this is a flush, it could be a flush for the actual data or a 
		   flush for the out-of-band data.  To distinguish between the two, 
		   we use the deenveloping state, which will have been set to
		   DEENVSTATE_DONE when processing of the main data was completed.  
		   The first time we pass this point, we reset the state to
		   DEENVSTATE_NONE.  If it's a flush, it was a flush for the main 
		   data and we exit.  After this, the flush is for the out-of-band
		   data */
		if( envelopeInfoPtr->deenvState == DEENVSTATE_DONE )
			{
			envelopeInfoPtr->deenvState = DEENVSTATE_NONE;
			if( !length )
				return( CRYPT_OK );
			}

		/* This is just raw data so we feed it directly to the processing
		   function */
		status = envelopeInfoPtr->processExtraData( envelopeInfoPtr, buffer, 
													length );
		if( cryptStatusOK( status ) )
			{
			*bytesCopied = length;
			if( !length )
				envelopeInfoPtr->state = STATE_FINISHED;
			}
		}

	return( status );
	}

/* Pop data from an envelope */

static int envelopePop( ENVELOPE_INFO *envelopeInfoPtr, void *buffer,
						const int length, int *bytesCopied )
	{
	int bytesOut;

	/* If we're enveloping data, just copy as much as we can to the output */
	if( !envelopeInfoPtr->isDeenvelope )
		{
		/* Copy the data from the envelope to the output */
		bytesOut = envelopeInfoPtr->copyFromEnvelope( envelopeInfoPtr,
													  buffer, length );
		if( cryptStatusError( bytesOut ) )
			{
			envelopeInfoPtr->errorState = bytesOut;
			return( bytesOut );
			}
		*bytesCopied = bytesOut;
		return( CRYPT_OK );
		}

	/* We're de-enveoping data, if we haven't reached the data yet force a 
	   push to try and get to the data.  We can end up with this condition if 
	   the caller pushes in deenveloping information and then immediately 
	   tries to pop data without an intervening push to resolve the state of 
	   the data in the envelope */
	if( envelopeInfoPtr->state == STATE_PREDATA )
		{
		int dummy, status;

		status = deenvelopePush( envelopeInfoPtr, NULL, 0, &dummy );
		if( cryptStatusError( status ) )
			return( status );

		/* If we still haven't got anywhere, return an underflow error */
		if( envelopeInfoPtr->state == STATE_PREDATA )
			return( CRYPT_ERROR_UNDERFLOW );
		}

	/* Copy the data from the envelope to the output */
	bytesOut = envelopeInfoPtr->copyFromDeenvelope( envelopeInfoPtr,
													buffer, length );
	if( cryptStatusError( bytesOut ) )
		{
		envelopeInfoPtr->errorState = bytesOut;
		return( bytesOut );
		}
	*bytesCopied = bytesOut;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Envelope Message Handler					*
*																			*
****************************************************************************/

/* Handle a message sent to an envelope */

static int envelopeMessageFunction( const CRYPT_ENVELOPE cryptEnvelope,
									const RESOURCE_MESSAGE_TYPE message,
									void *messageDataPtr,
									const int messageValue )
	{
	ENVELOPE_INFO *envelopeInfoPtr;

	getCheckInternalResource( cryptEnvelope, envelopeInfoPtr, OBJECT_TYPE_ENVELOPE );

	/* Process destroy object messages */
	if( message == RESOURCE_MESSAGE_DESTROY )
		{
		int status = CRYPT_OK;

		/* Envelope deletion has an extra complication in that instead of 
		   simply decrementing its reference count like other objects, we 
		   check to see whether the envelope still needs operations performed 
		   on it to resolve the state of the data within it (for example if 
		   the caller pushes data but doesn't flush it, there will be a few 
		   bytes left which can't be popped).  We can't perform this check in 
		   the delete function because this may be called from other sections 
		   of the code, so we have to do it here.

		   For enveloping, destroying the envelope while it's in any state 
		   other than STATE_PREDATA or STATE_FINISHED is regarded as an error.

		   For de-enveloping we have to be more careful, since deenveloping
		   information required to resolve the envelope state could be
		   unavailable, so we shouldn't return an error if something like a
		   signature check remains to be done.  What we therefore do is check 
		   to see whether we've processed any data yet and report an error if
		   there's any data left in the envelope or if we destroy it in the
		   middle of processing data */
		if( envelopeInfoPtr->isDeenvelope )
			{
			/* If we've got to the point of processing data in the envelope 
			   and there's either more to come or some left to pop, we 
			   shouldn't be destroying it yet */
			if( envelopeInfoPtr->state == STATE_DATA || \
				( ( envelopeInfoPtr->state == STATE_POSTDATA || \
					envelopeInfoPtr->state == STATE_FINISHED ) && \
				  envelopeInfoPtr->dataLeft ) )
				status = CRYPT_ERROR_INCOMPLETE;
			}
		else
			/* If we're in the middle of processing data, we shouldn't be
			   destroying the envelope yet */
			if( envelopeInfoPtr->state != STATE_PREDATA && \
				envelopeInfoPtr->state != STATE_FINISHED )
				status = CRYPT_ERROR_INCOMPLETE;

		/* Delete the action and content lists */
		deleteActionList( envelopeInfoPtr->preActionList );
		deleteActionList( envelopeInfoPtr->actionList );
		deleteActionList( envelopeInfoPtr->postActionList );
		deleteContentList( envelopeInfoPtr->contentList );

#ifndef NO_COMPRESSION
		/* Delete the zlib compression state information if necessary */
		if( envelopeInfoPtr->zStreamInited )
			if( envelopeInfoPtr->isDeenvelope )
				inflateEnd( &envelopeInfoPtr->zStream );
			else
				deflateEnd( &envelopeInfoPtr->zStream );
#endif /* NO_COMPRESSION */

		/* Handle the keyset cleanup by calling the internal keyset close
		   function */
		if( envelopeInfoPtr->iSigCheckKeyset != CRYPT_ERROR )
			krnlSendNotifier( envelopeInfoPtr->iSigCheckKeyset, 
							  RESOURCE_IMESSAGE_DECREFCOUNT );
		if( envelopeInfoPtr->iEncryptionKeyset != CRYPT_ERROR )
			krnlSendNotifier( envelopeInfoPtr->iEncryptionKeyset, 
							  RESOURCE_IMESSAGE_DECREFCOUNT );
		if( envelopeInfoPtr->iDecryptionKeyset != CRYPT_ERROR )
			krnlSendNotifier( envelopeInfoPtr->iDecryptionKeyset, 
							  RESOURCE_IMESSAGE_DECREFCOUNT );

		/* Clean up other envelope objects */
		if( envelopeInfoPtr->iSignerChain != CRYPT_ERROR )
			krnlSendNotifier( envelopeInfoPtr->iSignerChain, 
							  RESOURCE_IMESSAGE_DECREFCOUNT );
		if( envelopeInfoPtr->iOriginatorChain != CRYPT_ERROR )
			krnlSendNotifier( envelopeInfoPtr->iOriginatorChain, 
							  RESOURCE_IMESSAGE_DECREFCOUNT );

		/* Clear and free the buffers if necessary */
		if( envelopeInfoPtr->buffer != NULL )
			{
			zeroise( envelopeInfoPtr->buffer, envelopeInfoPtr->bufSize );
			free( envelopeInfoPtr->buffer );
			}
		if( envelopeInfoPtr->auxBuffer != NULL )
			{
			zeroise( envelopeInfoPtr->auxBuffer, envelopeInfoPtr->auxBufSize );
			free( envelopeInfoPtr->auxBuffer );
			}

		/* Delete the objects locking variables and the object itself */
		unlockResource( envelopeInfoPtr );
		deleteResourceLock( envelopeInfoPtr );
		zeroise( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) );
		free( envelopeInfoPtr );

		return( status );
		}

	/* Process attribute get/set/delete messages */
	if( isAttributeMessage( message ) )
		{
		int status;

		assert( message == RESOURCE_MESSAGE_GETATTRIBUTE || \
				message == RESOURCE_MESSAGE_GETATTRIBUTE_S || \
				message == RESOURCE_MESSAGE_SETATTRIBUTE || \
				message == RESOURCE_MESSAGE_SETATTRIBUTE_S );

		if( message == RESOURCE_MESSAGE_GETATTRIBUTE )
			status = processGetAttribute( envelopeInfoPtr, messageDataPtr,
										  messageValue );
		if( message == RESOURCE_MESSAGE_GETATTRIBUTE_S )
			status = processGetAttributeS( envelopeInfoPtr, messageDataPtr,
										   messageValue );
		if( message == RESOURCE_MESSAGE_SETATTRIBUTE )
			status = processSetAttribute( envelopeInfoPtr, messageDataPtr,
										  messageValue );
		if( message == RESOURCE_MESSAGE_SETATTRIBUTE_S )
			status = processSetAttributeS( envelopeInfoPtr, messageDataPtr,
										   messageValue );
		unlockResourceExit( envelopeInfoPtr, status );
		}

	/* Process messages which lock/unlock an object for exclusive use */
	if( message == RESOURCE_MESSAGE_LOCK )
		/* Exit without unlocking the object.  Any other threads trying to
		   use the object after this point will be blocked */
		return( CRYPT_OK );
	if( message == RESOURCE_MESSAGE_UNLOCK )
		{
		/* "Wenn drei Leute in ein Zimmer reingehen und fuenf kommen raus,
			dann muessen erst mal zwei wieder reingehen bis das Zimmer leer
			ist" */
		unlockResource( envelopeInfoPtr );	/* Undo RESOURCE_MESSAGE_LOCK lock */
		unlockResourceExit( envelopeInfoPtr, CRYPT_OK );
		}

	/* Process object-specific messages */
	if( message == RESOURCE_MESSAGE_ENV_PUSHDATA )
		{
		RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
		int bytesCopied, status;

		assert( ( msgData->data == NULL && msgData->length == 0 ) || \
				( msgData->data != NULL && msgData->length > 0 ) );

		/* Make sure everything is in order */
		if( msgData->length == 0 )
			{
			/* If it's a flush, make sure we're in a state where this is 
			   valid.  We can only perform a flush on enveloping if we're in 
			   the data or postdata state, on deenveloping a flush can 
			   happen at any time since the entire payload could be buffered
			   pending the addition of a deenveloping resource, so the
			   envelope goes from pre -> post in one step */
			if( envelopeInfoPtr->state == STATE_FINISHED )
				unlockResourceExit( envelopeInfoPtr, CRYPT_OK );
			if( !envelopeInfoPtr->isDeenvelope && \
				( envelopeInfoPtr->state != STATE_DATA && \
				  envelopeInfoPtr->state != STATE_POSTDATA ) )
				unlockResourceExit( envelopeInfoPtr, 
									CRYPT_ERROR_INCOMPLETE );
			}
		if( envelopeInfoPtr->state == STATE_FINISHED )
			unlockResourceExit( envelopeInfoPtr, CRYPT_ERROR_COMPLETE );
		if( envelopeInfoPtr->errorState != CRYPT_OK )
			unlockResourceExit( envelopeInfoPtr, 
								envelopeInfoPtr->errorState );

		/* Send the data to the envelope */
		if( envelopeInfoPtr->isDeenvelope )
			status = deenvelopePush( envelopeInfoPtr, msgData->data, 
									 msgData->length, &bytesCopied );
		else
			status = envelopePush( envelopeInfoPtr, msgData->data, 
								   msgData->length, &bytesCopied );
		msgData->length = bytesCopied;

		unlockResourceExit( envelopeInfoPtr, status );
		}
	if( message == RESOURCE_MESSAGE_ENV_POPDATA )
		{
		RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
		int bytesCopied, status;

		assert( msgData->data != NULL && msgData->length > 0 );

		/* Make sure everything is in order */
		if( envelopeInfoPtr->errorState != CRYPT_OK )
			unlockResourceExit( envelopeInfoPtr, 
								envelopeInfoPtr->errorState );

		/* Get the data from the envelope */
		status = envelopePop( envelopeInfoPtr, msgData->data, 
							  msgData->length, &bytesCopied );
		msgData->length = bytesCopied;

		unlockResourceExit( envelopeInfoPtr, status );
		}

	assert( NOTREACHED );
	return( 0 );		/* Get rid of compiler warning */
	}

/* Create an envelope.  This is a low-level function encapsulated by 
   createEnvelope() and used to manage error exits */

static int initEnvelope( CRYPT_ENVELOPE *iCryptEnvelope, 
						 const CRYPT_FORMAT_TYPE formatType,
						 const BOOLEAN isDeenvelope, 
						 ENVELOPE_INFO **envelopeInfoPtrPtr )
	{
	int addEnvelopeInfo( ENVELOPE_INFO *envelopeInfoPtr,
						 const CRYPT_ATTRIBUTE_TYPE envInfo, const void *value,
						 const int valueLength );
	int addDeenvelopeInfo( ENVELOPE_INFO *envelopeInfoPtr,
						   const CRYPT_ATTRIBUTE_TYPE envInfo,
						   const void *value, const int valueLength );
	ENVELOPE_INFO *envelopeInfoPtr;
	void *auxBuffer;
	int status;

	/* Clear the return values */
	*iCryptEnvelope = CRYPT_ERROR;
	*envelopeInfoPtrPtr = NULL;

	/* Allocate the auxiliary buffer (for enveloping only) */
	if( !isDeenvelope && \
		( auxBuffer = malloc( DEFAULT_AUXBUFFER_SIZE ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );

	/* Create the envelope object */
	status = krnlCreateObject( ( void ** ) &envelopeInfoPtr, 
							   OBJECT_TYPE_ENVELOPE, isDeenvelope ? \
								SUBTYPE_ENV_DEENV : SUBTYPE_ENV_ENV, 
							   sizeof( ENVELOPE_INFO ), 0, 0, 
							   envelopeMessageFunction );
	if( cryptStatusError( status ) )
		{
		if( !isDeenvelope )
			free( auxBuffer );
		return( status );
		}
	initResourceLock( envelopeInfoPtr ); 
	lockResource( envelopeInfoPtr ); 
	*envelopeInfoPtrPtr = envelopeInfoPtr;
	*iCryptEnvelope = envelopeInfoPtr->objectHandle = status;
	envelopeInfoPtr->bufSize = DEFAULT_BUFFER_SIZE;
	if( !isDeenvelope )
		{
		envelopeInfoPtr->auxBuffer = auxBuffer;
		memset( envelopeInfoPtr->auxBuffer, 0, DEFAULT_AUXBUFFER_SIZE );
		envelopeInfoPtr->auxBufSize = DEFAULT_AUXBUFFER_SIZE;
		}
	envelopeInfoPtr->type = formatType;

	/* Set up any internal objects to contain invalid handles */
	envelopeInfoPtr->iCryptContext = envelopeInfoPtr->iSignerChain = \
		envelopeInfoPtr->iOriginatorChain = CRYPT_ERROR;
	envelopeInfoPtr->iSigCheckKeyset = envelopeInfoPtr->iEncryptionKeyset = \
		envelopeInfoPtr->iDecryptionKeyset = CRYPT_ERROR;
	envelopeInfoPtr->payloadSize = CRYPT_UNUSED;

	/* Set up the default algorithm information */
	if( !isDeenvelope )
		if( formatType == CRYPT_FORMAT_CRYPTLIB || \
			formatType == CRYPT_FORMAT_CMS || 
			formatType == CRYPT_FORMAT_SMIME )
			{
			/* Remember the current default settings for use with the
			   envelope.  We force the use of the CBC encryption mode because 
			   this is the safest and most efficient encryption mode, and the
			   only mode defined for many CMS algorithms.  Since the CMS
			   algorithms represent only a subset of what's available, we 
			   have to drop back to fixed values if the caller has selected 
			   something exotic */
			krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
							 &envelopeInfoPtr->defaultHash, 
							 CRYPT_OPTION_ENCR_HASH );
			if( !checkAlgoID( envelopeInfoPtr->defaultHash, CRYPT_MODE_NONE ) )
				envelopeInfoPtr->defaultHash = CRYPT_ALGO_SHA;
			krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
							 &envelopeInfoPtr->defaultAlgo, 
							 CRYPT_OPTION_ENCR_ALGO );
			if( !checkAlgoID( envelopeInfoPtr->defaultAlgo, 
					( envelopeInfoPtr->defaultAlgo == CRYPT_ALGO_RC4 ) ? \
					CRYPT_MODE_OFB : CRYPT_MODE_CBC ) )
				envelopeInfoPtr->defaultAlgo = CRYPT_ALGO_3DES;
			}
#ifndef NO_PGP
		else
			{
			/* Set the PGP default algorithms */
			envelopeInfoPtr->defaultHash = CRYPT_ALGO_MD5;
			envelopeInfoPtr->defaultAlgo = CRYPT_ALGO_IDEA;
			}
#endif /* NO_PGP */

	/* Set up the processing state information */
	envelopeInfoPtr->state = STATE_PREDATA;
	envelopeInfoPtr->envState = ENVSTATE_NONE;
	envelopeInfoPtr->deenvState = DEENVSTATE_NONE;
#ifndef NO_PGP
	envelopeInfoPtr->pgpEnvState = PGP_ENVSTATE_NONE;
	envelopeInfoPtr->pgpDeenvState = PGP_DEENVSTATE_NONE;
#endif /* NO_PGP */
	if( isDeenvelope )
		envelopeInfoPtr->isDeenvelope = TRUE;

	/* Set up the enveloping/deenveloping function pointers */
	if( formatType == CRYPT_FORMAT_CRYPTLIB || \
		formatType == CRYPT_FORMAT_CMS || \
		formatType == CRYPT_FORMAT_SMIME || \
		isDeenvelope )
		{
		int emitPreamble( ENVELOPE_INFO *envelopeInfoPtr );
		int emitPostamble( ENVELOPE_INFO *envelopeInfoPtr );
		int processPreamble( ENVELOPE_INFO *envelopeInfoPtr );
		int processPostamble( ENVELOPE_INFO *envelopeInfoPtr );
		int processExtraData( ENVELOPE_INFO *envelopeInfoPtr,
							  const void *buffer, const int length );
		int copyToEnvelope( ENVELOPE_INFO *envelopeInfoPtr,
							const BYTE *buffer, const int length );
		int copyFromEnvelope( ENVELOPE_INFO *envelopeInfoPtr, BYTE *buffer,
							  int length );
		int copyToDeenvelope( ENVELOPE_INFO *envelopeInfoPtr,
							  const BYTE *buffer, int length );
		int copyFromDeenvelope( ENVELOPE_INFO *envelopeInfoPtr, BYTE *buffer,
								int length );

		envelopeInfoPtr->emitPreamble = emitPreamble;
		envelopeInfoPtr->emitPostamble = emitPostamble;
		envelopeInfoPtr->processPreamble = processPreamble;
		envelopeInfoPtr->processPostamble = processPostamble;
		envelopeInfoPtr->processExtraData = processExtraData;
		envelopeInfoPtr->copyToEnvelope = copyToEnvelope;
		envelopeInfoPtr->copyFromEnvelope = copyFromEnvelope;
		envelopeInfoPtr->copyToDeenvelope = copyToDeenvelope;
		envelopeInfoPtr->copyFromDeenvelope = copyFromDeenvelope;
		}
#ifndef NO_PGP
	else
		{
		int pgpProcessPreamble( ENVELOPE_INFO *envelopeInfoPtr );
		int pgpProcessPostamble( ENVELOPE_INFO *envelopeInfoPtr );

		envelopeInfoPtr->processPreamble = pgpProcessPreamble;
		envelopeInfoPtr->processPostamble = pgpProcessPostamble;
		}
#endif /* NO_PGP */
	envelopeInfoPtr->addInfo = ( isDeenvelope ) ? addDeenvelopeInfo : \
												  addEnvelopeInfo;
	return( CRYPT_OK );
	}

int createEnvelope( CREATEOBJECT_INFO *createInfo, const void *auxDataPtr, 
					const int auxValue )
	{
	CRYPT_ENVELOPE iCryptEnvelope;
	ENVELOPE_INFO *envelopeInfoPtr;
	BOOLEAN isDeenvelope = ( createInfo->arg1 == CRYPT_FORMAT_AUTO ) ? \
						   TRUE : FALSE;
	int initStatus, status;

	assert( auxDataPtr == NULL );
	assert( auxValue == 0 );

	/* Perform basic error checking */
	if( createInfo->arg1 < CRYPT_FORMAT_FIRST_ENVELOPE || \
		createInfo->arg1 > CRYPT_FORMAT_LAST_ENVELOPE )
		return( CRYPT_ARGERROR_NUM1 );

	/* Pass the call on to the lower-level open function */
	initStatus = initEnvelope( &iCryptEnvelope, createInfo->arg1, 
							   isDeenvelope, &envelopeInfoPtr );
	if( envelopeInfoPtr == NULL )
		return( initStatus );	/* Create object failed, return immediately */
	if( cryptStatusError( initStatus ) )
		/* The session open failed, make sure the object gets destroyed when
		   we notify the kernel that the setup process is complete */
		krnlSendNotifier( iCryptEnvelope, RESOURCE_IMESSAGE_DESTROY );

	/* We've finished setting up the object-type-specific info, tell the
	   kernel the object is ready for use */
	unlockResource( envelopeInfoPtr );
	status = krnlSendMessage( iCryptEnvelope, RESOURCE_IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusError( initStatus ) || cryptStatusError( status ) )
		return( cryptStatusError( initStatus ) ? initStatus : status );
	createInfo->cryptHandle = iCryptEnvelope;
	return( CRYPT_OK );
	}
