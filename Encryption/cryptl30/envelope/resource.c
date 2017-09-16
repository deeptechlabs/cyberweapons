/****************************************************************************
*																			*
*					cryptlib Enveloping Information Management				*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "envelope.h"
#elif defined( INC_CHILD )
  #include "../envelope/envelope.h"
#else
  #include "envelope/envelope.h"
#endif /* Compiler-specific includes */

/* Prototypes for functions in pgp_misc.c */

int pgpPasswordToKey( CRYPT_CONTEXT cryptContext, const char *password,
					  const int passwordSize );

/****************************************************************************
*																			*
*					Functions for Action and Content Lists					*
*																			*
****************************************************************************/

/* Create a new action */

ACTION_LIST *createAction( const ACTION_TYPE actionType,
						   const CRYPT_HANDLE cryptHandle )
	{
	ACTION_LIST *actionListItem;

	/* Create the new action list item */
	if( ( actionListItem = malloc( sizeof( ACTION_LIST ) ) ) == NULL )
		return( NULL );
	memset( actionListItem, 0, sizeof( ACTION_LIST ) );
	actionListItem->action = actionType;
	actionListItem->iCryptHandle = cryptHandle;
	actionListItem->iExtraData = CRYPT_ERROR;

	return( actionListItem );
	}

/* Find the first action of a given type in an action list.  Since the lists
   are sorted by action type, this finds the start of a group of related
   actions */

ACTION_LIST *findAction( ACTION_LIST *actionListPtr,
						 const ACTION_TYPE actionType )
	{
	while( actionListPtr != NULL )
		{
		if( actionListPtr->action == actionType )
			return( actionListPtr );
		actionListPtr = actionListPtr->next;
		}

	return( NULL );
	}

/* Find the insertion point for a given action in an action list and at the
   same time check to make sure it isn't already present in the action group.
   If the actionType is negative we order the action in a direction which is
   the reverse of the normal order.  This is used for the main action list
   when deenveloping */

ACTION_RESULT findCheckLastAction( ACTION_LIST **actionListStart,
								   ACTION_LIST **actionListPtrPtr,
								   const ACTION_TYPE actionType,
								   const CRYPT_HANDLE cryptHandle )
	{
	ACTION_LIST *actionListPtr = *actionListStart;
	ACTION_LIST *actionListParent = ( ACTION_LIST * ) actionListStart;
	ACTION_TYPE action = ( actionType > 0 ) ? actionType : -actionType;
	BOOLEAN orderBackwards = ( actionType < 0 ) ? TRUE : FALSE;

	/* If the action list is empty, return a pointer to the list header
	   where we'll create a new list */
	if( actionListPtr == NULL )
		{
		*actionListPtrPtr = actionListParent;
		return( ACTION_RESULT_EMPTY );
		}

	/* Find the first action of this type */
	while( actionListPtr != NULL )
		{
		if( orderBackwards )
			{
			if( actionListPtr->action < action )
				break;
			}
		else
			if( actionListPtr->action >= action )
				break;

		actionListParent = actionListPtr;
		actionListPtr = actionListPtr->next;
		}

	/* Now walk down the list finding the last action in this action group */
	while( actionListPtr != NULL && actionListPtr->action == action )
		{
		/* See if the two objects contain the same key */
		if( krnlSendMessage( cryptHandle, RESOURCE_IMESSAGE_COMPARE,
							 &actionListPtr->iCryptHandle, 
							 RESOURCE_MESSAGE_COMPARE_KEYID ) == CRYPT_OK )
			{
			/* If the action was added automatically as the result of adding
			   another action then the first attempt to add it by the caller
			   isn't an error */
			if( actionListPtr->addedAutomatically )
				{
				actionListPtr->addedAutomatically = FALSE;
				return( ACTION_RESULT_PRESENT );
				}

			return( ACTION_RESULT_INITED );
			}
		actionListParent = actionListPtr;
		actionListPtr = actionListPtr->next;
		}

	*actionListPtrPtr = actionListParent;
	return( ACTION_RESULT_OK );
	}

/* Add an action to an action list */

int addAction( ACTION_LIST **actionListHeadPtrPtr,
			   ACTION_LIST **actionListPtr,
			   const ACTION_TYPE actionType,
			   const CRYPT_HANDLE cryptHandle )
	{
	ACTION_LIST *actionListItem;

	/* Create the new action */
	actionListItem = createAction( actionType, cryptHandle );
	if( actionListItem == NULL )
		return( CRYPT_ERROR_MEMORY );

	/* Link it into the list if necessary.  We have to handle the first item
	   in the list specially since it's only a pointer to the list rather than
	   an actual list item.

	   A null actionListPtr is treated specially, this is only inserted to
	   mark a dummy action if there are no other actions present and will
	   therefore be the only action present */
	if( ( actionListPtr == NULL && *actionListHeadPtrPtr == NULL ) || \
		( ( ACTION_LIST * ) actionListHeadPtrPtr == *actionListPtr ) )
		{
		actionListItem->next = *actionListHeadPtrPtr;
		*actionListHeadPtrPtr = actionListItem;
		}
	else
		{
		assert( actionListPtr != NULL );
		if( ( *actionListPtr )->next != NULL )
			actionListItem->next = ( *actionListPtr )->next;
		( *actionListPtr )->next = actionListItem;
		}

	/* Set the action list pointer to the newly-added item */
	if( actionListPtr != NULL )
		*actionListPtr = actionListItem;

	return( CRYPT_OK );
	}

/* Delete an action list */

void deleteActionList( ACTION_LIST *actionListPtr )
	{
	while( actionListPtr != NULL )
		{
		ACTION_LIST *actionListItem = actionListPtr;

		/* Destroy any attached objects and information if necessary and 
		   clear the list item memory */
		actionListPtr = actionListPtr->next;
		if( actionListItem->iCryptHandle != CRYPT_ERROR )
			krnlSendNotifier( actionListItem->iCryptHandle,
							  RESOURCE_IMESSAGE_DECREFCOUNT );
		if( actionListItem->iExtraData != CRYPT_ERROR )
			krnlSendNotifier( actionListItem->iExtraData,
							  RESOURCE_IMESSAGE_DECREFCOUNT );
		if( actionListItem->auxInfo != NULL )
			free( actionListItem->auxInfo );
		zeroise( actionListItem, sizeof( ACTION_LIST ) );
		free( actionListItem );
		}
	}

/* Create a content list item */

void initContentListItem( CONTENT_LIST *contentListItem )
	{
	memset( contentListItem, 0, sizeof( CONTENT_LIST ) );
	contentListItem->iSigCheckKey = CRYPT_ERROR;
	contentListItem->iExtraData = CRYPT_ERROR;
	}

CONTENT_LIST *createContentListItem( const CRYPT_FORMAT_TYPE formatType,
									 const void *object, const int objectSize )
	{
	CONTENT_LIST *contentListItem;

	if( ( contentListItem = malloc( sizeof( CONTENT_LIST ) ) ) == NULL )
		return( NULL );
	initContentListItem( contentListItem );
	contentListItem->formatType = formatType;
	contentListItem->object = ( void * ) object;
	contentListItem->objectSize = objectSize;

	return( contentListItem );
	}

#if 0

/* Delete an item from a content list */

void deleteContentListItem( CONTENT_LIST **contentListHead,
							CONTENT_LIST *contentListItem )
	{
	CONTENT_LIST *contentListNext = contentListItem->next;
	CONTENT_LIST *contentListPrev = *contentListHead;

	/* Find the previous item in the list */
	if( contentListPrev != contentListItem )
		while( contentListPrev != NULL && \
			   contentListPrev->next != contentListItem )
			contentListPrev = contentListPrev->next;
	assert( contentListPrev != NULL );

	/* Destroy any attached objects if necessary */
	if( contentListItem->iSigCheckKey != CRYPT_ERROR )
		krnlSendNotifier( contentListItem->iSigCheckKey,
						  RESOURCE_IMESSAGE_DECREFCOUNT );
	if( contentListItem->iExtraData != CRYPT_ERROR )
		krnlSendNotifier( contentListItem->iExtraData,
						  RESOURCE_IMESSAGE_DECREFCOUNT );

	/* Erase and free the object buffer if necessary */
	if( contentListItem->object != NULL )
		{
		zeroise( contentListItem->object, contentListItem->objectSize );
		free( contentListItem->object );
		}

	/* Erase and free the list item */
	zeroise( contentListItem, sizeof( CONTENT_LIST ) );
	free( contentListItem );

	/* Remove the item from the list */
	if( *contentListHead == contentListItem )
		*contentListHead = contentListNext;
	else
		contentListPrev->next = contentListNext;
	}
#endif /* 0 */

/* Delete a content list */

void deleteContentList( CONTENT_LIST *contentListPtr )
	{
	while( contentListPtr != NULL )
		{
		CONTENT_LIST *contentListItem = contentListPtr;

		/* Destroy any attached objects if necessary */
		if( contentListItem->iSigCheckKey != CRYPT_ERROR )
			krnlSendNotifier( contentListItem->iSigCheckKey,
							  RESOURCE_IMESSAGE_DECREFCOUNT );
		if( contentListItem->iExtraData != CRYPT_ERROR )
			krnlSendNotifier( contentListItem->iExtraData,
							  RESOURCE_IMESSAGE_DECREFCOUNT );

		/* Erase and free the object buffer if necessary */
		contentListPtr = contentListPtr->next;
		if( contentListItem->object != NULL )
			{
			zeroise( contentListItem->object, contentListItem->objectSize );
			free( contentListItem->object );
			}
		zeroise( contentListItem, sizeof( CONTENT_LIST ) );
		free( contentListItem );
		}
	}

/****************************************************************************
*																			*
*						Misc.Enveloping Info Management Functions			*
*																			*
****************************************************************************/

/* Set up the encryption for an envelope */

int initEnvelopeEncryption( ENVELOPE_INFO *envelopeInfoPtr,
							const CRYPT_CONTEXT cryptContext,
							const CRYPT_ALGO algorithm, const CRYPT_MODE mode,
							const BYTE *iv, const int ivLength,
							const BOOLEAN copyContext )
	{
	CRYPT_CONTEXT iCryptContext = cryptContext;
	CRYPT_ALGO cryptAlgo;
	CRYPT_MODE cryptMode;
	RESOURCE_DATA msgData;
	int blockSize, ivSize, status;

	/* Extract the information we need to process data */
	status = krnlSendMessage( cryptContext, RESOURCE_IMESSAGE_GETATTRIBUTE, 
							  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( cryptContext, RESOURCE_IMESSAGE_GETATTRIBUTE, 
								  &cryptMode, CRYPT_CTXINFO_MODE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( cryptContext, RESOURCE_IMESSAGE_GETATTRIBUTE, 
								  &blockSize, CRYPT_CTXINFO_BLOCKSIZE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( cryptContext, RESOURCE_IMESSAGE_GETATTRIBUTE, 
								  &ivSize, CRYPT_CTXINFO_IVSIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure the context is what's required */
	if( algorithm != CRYPT_UNUSED )
		{
		if( cryptAlgo != algorithm || cryptMode != mode )
			/* This can only happen on deenveloping if the data is corrupted 
			   or if the user is asked for a KEK and tries to supply a 
			   session key instead */
			status = CRYPT_ERROR_WRONGKEY;
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If it's a user-supplied context, take a copy for our own use.  This is
	   only done for user-supplied raw session keys, for everything else we 
	   either use cryptlib's object management to handle things for us or the
	   context is a internal one created specifically for our own use */
	if( copyContext )
		{
		status = krnlSendMessage( cryptContext, RESOURCE_MESSAGE_CLONE,
								  &iCryptContext, 0 );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Load the IV into the context and set up the encryption information for
	   the envelope */
	if( iv != NULL )
		{
		setResourceData( &msgData, ( void * ) iv, min( ivLength, ivSize ) );
		status = krnlSendMessage( iCryptContext, RESOURCE_IMESSAGE_SETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_IV );
		}
	else
		/* There's no IV specified, generate a new one */
		status = krnlSendNotifier( iCryptContext, RESOURCE_IMESSAGE_CTX_GENIV );
	if( cryptStatusError( status ) )
		{
		if( copyContext )
			/* Destroy the copy we created earlier */
			krnlSendNotifier( iCryptContext, RESOURCE_IMESSAGE_DECREFCOUNT );
		return( status );
		}
	envelopeInfoPtr->iCryptContext = iCryptContext;
	envelopeInfoPtr->blockSize = blockSize;
	envelopeInfoPtr->blockSizeMask = ~( blockSize - 1 );

	return( CRYPT_OK );
	}

/* Add keyset information */

static int addKeyset( ENVELOPE_INFO *envelopeInfoPtr,
					  const CRYPT_ATTRIBUTE_TYPE keysetFunction,
					  const CRYPT_KEYSET keyset )
	{
	CRYPT_KEYSET *iKeysetPtr;

	/* Figure out which keyset we want to set */
	switch( keysetFunction )
		{
		case CRYPT_ENVINFO_KEYSET_ENCRYPT:
			iKeysetPtr = &envelopeInfoPtr->iEncryptionKeyset;
			break;

		case CRYPT_ENVINFO_KEYSET_DECRYPT:
			iKeysetPtr = &envelopeInfoPtr->iDecryptionKeyset;
			break;

		case CRYPT_ENVINFO_KEYSET_SIGCHECK:
			iKeysetPtr = &envelopeInfoPtr->iSigCheckKeyset;
			break;

		default:
			assert( NOTREACHED );
			}

	/* Make sure the keyset hasn't already been set */
	if( *iKeysetPtr != CRYPT_ERROR )
		{
		setErrorInfo( envelopeInfoPtr, keysetFunction,
					  CRYPT_ERRTYPE_ATTR_PRESENT );
		return( CRYPT_ERROR_INITED );
		}

	/* Remember the new keyset and increment its reference count */
	*iKeysetPtr = keyset;
	return( krnlSendNotifier( keyset, RESOURCE_MESSAGE_INCREFCOUNT ) );
	}

/****************************************************************************
*																			*
*					Deenveloping Information Management Functions			*
*																			*
****************************************************************************/

/* Import a wrapped session key */

static int importSessionKey( ENVELOPE_INFO *envelopeInfoPtr, 
							 const void *encryptedSessionKey,
							 const CRYPT_CONTEXT iImportContext,
							 CRYPT_CONTEXT *iSessionKeyContext )
	{
	CREATEOBJECT_INFO createInfo;
	CONTENT_LIST *sessionKeyInfoPtr;
	int status;

	/* Look for the information required the recreate session key context */
	for( sessionKeyInfoPtr = envelopeInfoPtr->contentList;
		 sessionKeyInfoPtr != NULL && \
			sessionKeyInfoPtr->envInfo != CRYPT_ENVINFO_SESSIONKEY;
		 sessionKeyInfoPtr = sessionKeyInfoPtr->next );
	if( sessionKeyInfoPtr == NULL )
		/* We need to read more data before we can recreate the session key */
		return( CRYPT_ERROR_UNDERFLOW );

	/* Create the session key context */
	setMessageCreateObjectInfo( &createInfo, sessionKeyInfoPtr->cryptAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle, 
								  RESOURCE_IMESSAGE_SETATTRIBUTE,
								  &sessionKeyInfoPtr->cryptMode,
								  CRYPT_CTXINFO_MODE );
	if( cryptStatusError( status ) )
		return( status );

	/* Import the encrypted session key */
	status = iCryptImportKeyEx( encryptedSessionKey, iImportContext,
								createInfo.cryptHandle );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, 
						  RESOURCE_IMESSAGE_DECREFCOUNT );
		return( status );
		}
	*iSessionKeyContext = createInfo.cryptHandle;
	return( CRYPT_OK );
	}

/* Add de-enveloping information to an envelope */

int addDeenvelopeInfo( ENVELOPE_INFO *envelopeInfoPtr,
					   const CRYPT_ATTRIBUTE_TYPE envInfo, const void *value,
					   const int valueLength )
	{
	CONTENT_LIST *contentListPtr = envelopeInfoPtr->contentListCurrent;
	CRYPT_HANDLE cryptHandle = *( ( CRYPT_HANDLE * ) value ), iNewContext;
	ACTION_LIST *actionListPtr;
	ACTION_RESULT actionResult;
	int status;

	/* We can't add datasize, compression or hashing information when
	   deenveloping (in theory we can, but it doesn't make much sense) */
	if( envInfo == CRYPT_ENVINFO_DATASIZE || \
		envInfo == CRYPT_ENVINFO_COMPRESSION || \
		envInfo == CRYPT_ENVINFO_HASH )
		return( CRYPT_ARGERROR_VALUE );

	/* If it's keyset information, just keep a record of it for later use */
	if( envInfo == CRYPT_ENVINFO_KEYSET_SIGCHECK || \
		envInfo == CRYPT_ENVINFO_KEYSET_ENCRYPT || \
		envInfo == CRYPT_ENVINFO_KEYSET_DECRYPT )
		return( addKeyset( envelopeInfoPtr, envInfo, cryptHandle ) );

	/* Since we can add one of a multitude of necessary information types, we
	   need to check to make sure what we're adding is appropriate.  If the
	   caller hasn't tried to read the required resource information yet, we
	   try to match what's being added to the first information object of the 
	   correct type */
	if( contentListPtr == NULL )
		{
		contentListPtr = envelopeInfoPtr->contentList;

		/* Look for the first information object matching the supplied
		   information */
		while( contentListPtr != NULL && contentListPtr->envInfo != envInfo )
			contentListPtr = contentListPtr->next;
		if( contentListPtr == NULL )
			return( CRYPT_ARGERROR_VALUE );
		}

	/* Make sure the information we're adding matches the currently required
	   information object.  Since PGP doesn't follow the usual model of
	   encrypting a session key with a user key and then encrypting the data
	   with the session key but instead encrypts the data directly with the
	   raw key, we treat a session key, password, and encryption key
	   information as being the same thing.  In all cases the envelope
	   management code will do the right thing and turn it into the session
	   key information needed to decrypt the data.

	   For general information we can be passed password information when we
	   require a private key if the private key is encrypted, so we allow an
	   exception for this type */
#ifndef NO_PGP
	if( contentListPtr->envInfo == CRYPT_ENVINFO_SESSIONKEY && \
		envelopeInfoPtr->type == CRYPT_FORMAT_PGP )
		{
		if( envInfo != CRYPT_ENVINFO_SESSIONKEY && \
			envInfo != CRYPT_ENVINFO_KEY && \
			envInfo != CRYPT_ENVINFO_PASSWORD )
			return( CRYPT_ARGERROR_VALUE );
		}
	else
#endif /* !NO_PGP */
		if( contentListPtr->envInfo != envInfo && \
			!( contentListPtr->envInfo == CRYPT_ENVINFO_PRIVATEKEY && \
			   envInfo == CRYPT_ENVINFO_PASSWORD ) )
			return( CRYPT_ARGERROR_VALUE );

	/* If it's a signature object, check the signature and exit.  Anything
	   left after this point is a keying object */
	if( envInfo == CRYPT_ENVINFO_SIGNATURE )
		{
		int contextStatus = FALSE;

		/* If we've already processed this entry, return the saved processing
		   result */
		if( contentListPtr->processed )
			return( contentListPtr->processingResult );

		/* Find the hash action we need to check this signature.  Note that
		   we can't use the hashActions pointer for direct access since the
		   hashing will have been completed by now and the pointer will be
		   null */
		for( actionListPtr = findAction( envelopeInfoPtr->actionList, ACTION_HASH );
			 actionListPtr != NULL && actionListPtr->action == ACTION_HASH;
			 actionListPtr = actionListPtr->next )
			{
			int cryptAlgo;

			/* Check to see if it's the one we want */
			contextStatus = krnlSendMessage( actionListPtr->iCryptHandle, 
									RESOURCE_IMESSAGE_GETATTRIBUTE,
									&cryptAlgo, CRYPT_CTXINFO_ALGO );
			if( cryptStatusOK( contextStatus ) && \
				cryptAlgo == contentListPtr->hashAlgo )
					break;
			}

		/* If we can't find a hash action to match this signature, return a
		   bad signature error since something must have altered the
		   algorithm ID for the hash.  However if a hash context is in a non-
		   normal state, the reason that we couldn't find a match was more
		   likely because the context is the missing one, so we return the
		   context state as an error instead */
		if( actionListPtr == NULL || actionListPtr->action != ACTION_HASH )
			{
			contentListPtr->processed = TRUE;
			contentListPtr->processingResult = \
				cryptStatusError( contextStatus ) ? \
							CRYPT_ERROR_SIGNALLED : CRYPT_ERROR_SIGNATURE;
			return( contentListPtr->processingResult );
			}

		/* Check the signature */
		if( contentListPtr->formatType == CRYPT_FORMAT_CMS )
			{
			int value;

			status = iCryptCheckSignatureEx( contentListPtr->object,
											 envelopeInfoPtr->iSignerChain,
											 actionListPtr->iCryptHandle,
											 &contentListPtr->iExtraData );

			/* If there are authenticated attributes present we have to
			   perform an extra check here to make sure the content-type
			   specified in the authenticated attributes matches the actual
			   data content type */
			if( cryptStatusOK( status ) && \
				contentListPtr->iExtraData != CRYPT_ERROR )
				{
				status = krnlSendMessage( contentListPtr->iExtraData, 
									RESOURCE_IMESSAGE_GETATTRIBUTE, &value, 
									CRYPT_CERTINFO_CMS_CONTENTTYPE );
				if( status == CRYPT_ERROR_NOTFOUND || \
					envelopeInfoPtr->contentType != value )
					status = CRYPT_ERROR_SIGNATURE;
				}
			}
		else
			{
			status = iCryptCheckSignatureEx( contentListPtr->object,
							cryptHandle, actionListPtr->iCryptHandle, NULL );

			/* Remember the key which was used to check the signature in case
			   the user wants to query it later */
			krnlSendNotifier( cryptHandle, RESOURCE_IMESSAGE_INCREFCOUNT );
			contentListPtr->iSigCheckKey = cryptHandle;
			}

		/* Remember the processing result so we don't have to repeat the
		   processing if queried again.  Since we don't need the encoded
		   signature data any more after this point, we free it to make the
		   memory available for reuse */
		free( contentListPtr->object );
		contentListPtr->object = NULL;
		contentListPtr->objectSize = 0;
		contentListPtr->processed = TRUE;
		contentListPtr->processingResult = status;
		return( status );
		}

	/* If we need private key information and we've been given a password,
	   it's the password required to decrypt the key so we treat this
	   specially */
	if( contentListPtr->envInfo == CRYPT_ENVINFO_PRIVATEKEY && \
		envInfo == CRYPT_ENVINFO_PASSWORD )
		{
		MESSAGE_KEYMGMT_INFO getkeyInfo;

		/* Make sure there's a keyset available to pull the key from */
		if( envelopeInfoPtr->iDecryptionKeyset == CRYPT_ERROR )
			{
			setErrorInfo( envelopeInfoPtr, CRYPT_ENVINFO_KEYSET_DECRYPT,
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			return( CRYPT_ERROR_NOTINITED );
			}

		/* Try and get the key information */
		if( contentListPtr->issuerAndSerialNumber == NULL )
			{
			setMessageKeymgmtInfo( &getkeyInfo, CRYPT_IKEYID_KEYID,
								   contentListPtr->keyID,
								   contentListPtr->keyIDsize, 
								   ( void * ) value, valueLength,
								   KEYMGMT_FLAG_PRIVATEKEY );
			}
		else
			{
			setMessageKeymgmtInfo( &getkeyInfo, 
								   CRYPT_IKEYID_ISSUERANDSERIALNUMBER,
								   contentListPtr->issuerAndSerialNumber,
								   contentListPtr->issuerAndSerialNumberSize,
								   ( void * ) value, valueLength,
								   KEYMGMT_FLAG_PRIVATEKEY );
			}
		status = krnlSendMessage( envelopeInfoPtr->iDecryptionKeyset,
								  RESOURCE_IMESSAGE_KEY_GETKEY, &getkeyInfo, 0 );

		/* If we managed to get the private key, push it into the envelope.  
		   If the call succeeds, this will import the session key and delete 
		   the required-information list */
		if( status == CRYPT_OK )
			{
			status = addDeenvelopeInfo( envelopeInfoPtr,
										CRYPT_ENVINFO_PRIVATEKEY,
										&getkeyInfo.cryptHandle, 0 );
			krnlSendNotifier( getkeyInfo.cryptHandle, 
							  RESOURCE_IMESSAGE_DECREFCOUNT );
			}

		return( status );
		}

	/* If we've been given a password, create the appropriate encryption
	   context for it and derive the key from the password */
	if( envInfo == CRYPT_ENVINFO_PASSWORD )
		{
		CREATEOBJECT_INFO createInfo;

		/* Create the appropriate encryption context */
		setMessageCreateObjectInfo( &createInfo, contentListPtr->cryptAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
								  &createInfo, OBJECT_TYPE_CONTEXT );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( createInfo.cryptHandle, 
									  RESOURCE_IMESSAGE_SETATTRIBUTE,
									  &contentListPtr->cryptMode,
									  CRYPT_CTXINFO_MODE );
		if( cryptStatusError( status ) )
			return( status );

		/* Derive the key into it */
#ifndef NO_PGP
		if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP )
			status = pgpPasswordToKey( createInfo.cryptHandle, value, 
									   valueLength );
		else
#endif /* !NO_PGP */
			{
			RESOURCE_DATA msgData;

			/* Load the derivation information into the context */
			status = krnlSendMessage( createInfo.cryptHandle, 
									RESOURCE_IMESSAGE_SETATTRIBUTE,
									&contentListPtr->keySetupIterations, 
									CRYPT_CTXINFO_KEYING_ITERATIONS );
			if( cryptStatusOK( status ) )
				{
				setResourceData( &msgData, contentListPtr->saltIV, 
								 contentListPtr->saltIVsize );
				status = krnlSendMessage( createInfo.cryptHandle, 
									RESOURCE_IMESSAGE_SETATTRIBUTE_S,
									&msgData, CRYPT_CTXINFO_KEYING_SALT );
				}
			if( cryptStatusOK( status ) )
				{
				setResourceData( &msgData, ( void * ) value, valueLength );
				status = krnlSendMessage( createInfo.cryptHandle, 
									RESOURCE_IMESSAGE_SETATTRIBUTE_S, &msgData,
									CRYPT_CTXINFO_KEYING_VALUE );
				}
			}
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( createInfo.cryptHandle, 
							  RESOURCE_IMESSAGE_DECREFCOUNT );
			return( status );
			}

		/* Recover the session key using the password context and destroy it
		   when we're done with it */
#ifndef NO_PGP
		if( envelopeInfoPtr->type != CRYPT_FORMAT_PGP )
			{
#endif /* !NO_PGP */
			status = importSessionKey( envelopeInfoPtr, 
							contentListPtr->object, createInfo.cryptHandle, 
							&iNewContext );
			krnlSendNotifier( createInfo.cryptHandle, 
							  RESOURCE_IMESSAGE_DECREFCOUNT );
#ifndef NO_PGP
			}
		else
			/* In PGP there isn't any encrypted session key, so the context
			   created from the password becomes the bulk encryption
			   context */
			iNewContext = createInfo.cryptHandle;
#endif /* !NO_PGP */

		if( cryptStatusError( status ) )
			return( status );
		}

	/* If we've been given a KEK (symmetric or asymmetric), recreate the 
	   session key by importing it using the KEK */
	if( envInfo == CRYPT_ENVINFO_PRIVATEKEY || \
		envInfo == CRYPT_ENVINFO_KEY )
		{
#ifndef NO_PGP
		/* In PGP there isn't any encrypted session key so we take a copy of 
		   the context we've been passed to use as the bulk encryption 
		   context */
		if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP && \
			envInfo == CRYPT_ENVINFO_KEY )
			{
			CRYPT_CONTEXT iCryptContext;

			status = krnlSendMessage( cryptHandle, 
							RESOURCE_MESSAGE_GETDEPENDENT, &iCryptContext,
							OBJECT_TYPE_CONTEXT );
			if( cryptStatusOK( status ) )
				status = krnlSendMessage( iCryptContext, RESOURCE_IMESSAGE_CLONE,
										  &iNewContext, 0 );
			}
		else
#endif /* !NO_PGP */
			/* Import the session key using the KEK */
			status = importSessionKey( envelopeInfoPtr, 
						contentListPtr->object, cryptHandle, &iNewContext );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* At this point we have the session key, either by recovering it from a
	   key exchange action or by having it passed to us directly.  If we've
	   been given it directly then we must have reached the encryptedContent
	   so we take a copy and set up the decryption with it */
	if( envInfo == CRYPT_ENVINFO_SESSIONKEY )
		{
		status = initEnvelopeEncryption( envelopeInfoPtr, cryptHandle,
					contentListPtr->cryptAlgo, contentListPtr->cryptMode,
					contentListPtr->saltIV, contentListPtr->saltIVsize, TRUE );
		if( cryptStatusError( status ) )
			return( status );

		/* The session key context is the newly-created internal one */
		iNewContext = envelopeInfoPtr->iCryptContext;
		}
	else
		/* We've recovered the session key from a key exchange action.  If we
		   got as far as the encryptedContent (so there's content info
		   present), we set up the decryption.  If we didn't get this far,
		   it'll be set up by the deenveloping code when we reach it */
		{
		for( contentListPtr = envelopeInfoPtr->contentList;
			 contentListPtr != NULL && \
				contentListPtr->envInfo != CRYPT_ENVINFO_SESSIONKEY;
			 contentListPtr = contentListPtr->next );
		if( contentListPtr != NULL )
			{
			/* We got to the encryptedContent, set up the decryption */
			status = initEnvelopeEncryption( envelopeInfoPtr, iNewContext,
						contentListPtr->cryptAlgo, contentListPtr->cryptMode,
						contentListPtr->saltIV, contentListPtr->saltIVsize, FALSE );
			if( cryptStatusError( status ) )
				return( status );
			}
		}

	/* Add the recovered session encryption action to the action list */
	actionResult = findCheckLastAction( &envelopeInfoPtr->actionList,
								&actionListPtr, -ACTION_CRYPT, iNewContext );
	if( actionResult == ACTION_RESULT_INITED )
		return( CRYPT_ERROR_INITED );
	status = addAction( &envelopeInfoPtr->actionList, &actionListPtr,
						ACTION_CRYPT, iNewContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Notify the kernel that the session key context is attached to the 
	   envelope.  This is an internal object used only by the envelope so we
	   tell the kernel not to increment its reference count when it attaches
	   it */
	krnlSendMessage( envelopeInfoPtr->objectHandle, 
					 RESOURCE_IMESSAGE_SETDEPENDENT, &iNewContext, FALSE );

	/* Destroy the required information list, which at this point will
	   contain only (now-irrelevant) key exchange items */
	deleteContentList( envelopeInfoPtr->contentList );
	envelopeInfoPtr->contentList = envelopeInfoPtr->contentListCurrent = NULL;

	/* If the only error was an information required error, we've now
	   resolved the problem and can continue */
	if( envelopeInfoPtr->errorState == CRYPT_ENVELOPE_RESOURCE )
		envelopeInfoPtr->errorState = CRYPT_OK;

	return( status );
	}

/****************************************************************************
*																			*
*					Enveloping Information Management Functions				*
*																			*
****************************************************************************/

#ifndef NO_PGP

/* Check that an object being added is suitable for PGP use */

static int checkPGPusage( const CRYPT_HANDLE cryptHandle,
						  const ENVELOPE_INFO *envelopeInfoPtr,
						  const CRYPT_ATTRIBUTE_TYPE envInfo )
	{
	CRYPT_ALGO cryptAlgo;
	CRYPT_MODE cryptMode;
	int type, status;

	/* Make sure it's an encryption context and query its properties */
	status = krnlSendMessage( cryptHandle, RESOURCE_MESSAGE_GETATTRIBUTE,
							  &type, CRYPT_IATTRIBUTE_TYPE );
	if( cryptStatusError( status ) || type != OBJECT_TYPE_CONTEXT )
		status = CRYPT_ARGERROR_NUM1;
	else
		status = krnlSendMessage( cryptHandle, RESOURCE_MESSAGE_GETATTRIBUTE, 
								  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( cryptHandle, RESOURCE_MESSAGE_GETATTRIBUTE, 
								  &cryptMode, CRYPT_CTXINFO_MODE );
	if( cryptStatusError( status ) )
		return( status );

	if( ( envInfo == CRYPT_ENVINFO_PUBLICKEY || \
		  envInfo == CRYPT_ENVINFO_PRIVATEKEY || \
		  envInfo == CRYPT_ENVINFO_SIGNATURE ) && \
		cryptAlgo != CRYPT_ALGO_RSA )
		/* PGP only supports RSA encryption and signatures */
		return( CRYPT_ARGERROR_NUM1 );
	if( envInfo == CRYPT_ENVINFO_KEY )
		{
		/* PGP only supports IDEA/CFB encryption, and only a single instance
		   of this */
		if( cryptAlgo != CRYPT_ALGO_IDEA || cryptMode != CRYPT_MODE_CFB )
			return( CRYPT_ARGERROR_NUM1 );
		if( findAction( envelopeInfoPtr->preActionList,
						ACTION_KEYEXCHANGE_PKC ) || \
			findAction( envelopeInfoPtr->actionList,
						ACTION_CRYPT ) )
			return( CRYPT_ERROR_INITED );
		}
	if( envInfo == CRYPT_ENVINFO_SESSIONKEY )
		{
		/* PGP only supports IDEA/CFB encryption, and only a single instance
		   of this */
		if( cryptAlgo != CRYPT_ALGO_IDEA || cryptMode != CRYPT_MODE_CFB )
			return( CRYPT_ARGERROR_NUM1 );
		if( findAction( envelopeInfoPtr->preActionList,
						ACTION_KEYEXCHANGE_PKC ) || \
			findAction( envelopeInfoPtr->actionList,
						ACTION_CRYPT ) )
			return( CRYPT_ERROR_INITED );
		}
	if( envInfo == CRYPT_ENVINFO_HASH )
		{
		/* PGP only supports MD5 hashing, and only a single instance of
		   this */
		if( cryptAlgo != CRYPT_ALGO_MD5 )
			return( CRYPT_ARGERROR_NUM1 );
		if( findAction( envelopeInfoPtr->actionList, ACTION_HASH ) )
			return( CRYPT_ERROR_INITED );
		}

	return( CRYPT_OK );
	}
#endif /* NO_PGP */

/* Check that an object being added is suitable for Fortezza usage */

static int checkFortezzaUsage( const CRYPT_HANDLE cryptHandle,
							   const ENVELOPE_INFO *envelopeInfoPtr,
							   const CRYPT_ATTRIBUTE_TYPE envInfo )
	{
	CRYPT_ALGO cryptAlgo;
	int device1, device2, status;

	/* Make sure the new session key being added (if there's existing 
	   originator info) or the existing one (if it's originator info being 
	   added) is a Skipjack context */
	status = krnlSendMessage( ( envInfo == CRYPT_ENVINFO_ORIGINATOR ) ? \
							  envelopeInfoPtr->iCryptContext : cryptHandle, 
							  RESOURCE_IMESSAGE_GETATTRIBUTE, &cryptAlgo, 
							  CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) || cryptAlgo != CRYPT_ALGO_SKIPJACK )
		return( CRYPT_ARGERROR_NUM1 );

	/* Make sure both objects are present in the same device */
	status = krnlSendMessage( cryptHandle, RESOURCE_IMESSAGE_GETDEPENDENT, 
							  &device1, OBJECT_TYPE_DEVICE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( envelopeInfoPtr->iCryptContext, 
								RESOURCE_IMESSAGE_GETDEPENDENT, &device2, 
								OBJECT_TYPE_DEVICE );
	if( cryptStatusOK( status ) && ( device1 != device2 ) )
		status = CRYPT_ARGERROR_NUM1;

	return( status );
	}

/* Add enveloping information to an envelope */

int addEnvelopeInfo( ENVELOPE_INFO *envelopeInfoPtr,
					 const CRYPT_ATTRIBUTE_TYPE envInfo, const void *value,
					 const int valueLength )
	{
	CRYPT_HANDLE cryptHandle = *( CRYPT_HANDLE * ) value;
	ACTION_LIST *actionListPtr, **actionListPtrPtr, *hashActionPtr;
	ACTION_RESULT actionResult;
	ACTION_TYPE actionType;
	int type, status;

	/* If it's meta-information, remember the value */
	if( envInfo == CRYPT_ENVINFO_DATASIZE )
		{
		envelopeInfoPtr->payloadSize = *( int * ) value;
		return( CRYPT_OK );
		}
	if( envInfo == CRYPT_ENVINFO_CONTENTTYPE )
		{
		envelopeInfoPtr->contentType = *( int * ) value;
		return( CRYPT_OK );
		}
	if( envInfo == CRYPT_ENVINFO_DETACHEDSIGNATURE )
		{
		/* Turn a generic zero/nonzero boolean into TRUE or FALSE */
		envelopeInfoPtr->detachedSig = ( *( int * ) value ) ? TRUE : FALSE;
		return( CRYPT_OK );
		}

	/* If it's keyset information, just keep a record of it for later use */
	if( envInfo == CRYPT_ENVINFO_KEYSET_SIGCHECK || \
		envInfo == CRYPT_ENVINFO_KEYSET_ENCRYPT || \
		envInfo == CRYPT_ENVINFO_KEYSET_DECRYPT )
		return( addKeyset( envelopeInfoPtr, envInfo, cryptHandle ) );

	/* If it's extra data for the signature, record it with the signature
	   action */
	if( envInfo == CRYPT_ENVINFO_SIGNATURE_EXTRADATA )
		{
		/* Find the last signature action added and make sure it doesn't
		   already have extra data attached to it */
		actionListPtr = findAction( envelopeInfoPtr->postActionList,
									ACTION_SIGN );
		if( actionListPtr == NULL )
			return( CRYPT_ERROR_NOTINITED );
		while( actionListPtr->next != NULL && \
			   actionListPtr->next->action == ACTION_SIGN )
			actionListPtr = actionListPtr->next;
		if( actionListPtr->iExtraData != CRYPT_ERROR )
			return( CRYPT_ERROR_INITED );

		/* Increment its reference count and add it to the action */
		status = krnlSendNotifier( cryptHandle, RESOURCE_MESSAGE_INCREFCOUNT );
		if( cryptStatusOK( status ) )
			actionListPtr->iExtraData = cryptHandle;
		return( status );
		}
	if( envInfo == CRYPT_ENVINFO_TIMESTAMP_AUTHORITY )
		{
		/* Find the last signature action added and make sure it doesn't
		   already have extra data attached to it */
		actionListPtr = findAction( envelopeInfoPtr->postActionList,
									ACTION_SIGN );
		if( actionListPtr == NULL )
			return( CRYPT_ERROR_NOTINITED );
		while( actionListPtr->next != NULL && \
			   actionListPtr->next->action == ACTION_SIGN )
			actionListPtr = actionListPtr->next;
		if( actionListPtr->auxInfo != NULL )
			return( CRYPT_ERROR_INITED );

		/* Add the TSA URL */
		if( ( actionListPtr->auxInfo = malloc( valueLength + 1 ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		memcpy( actionListPtr->auxInfo, value, valueLength );
		( ( BYTE * ) actionListPtr->auxInfo )[ valueLength ] = '\0';

		return( CRYPT_OK );
		}

	/* If it's originator information, record it for the enveloped data 
	   header */
	if( envInfo == CRYPT_ENVINFO_ORIGINATOR )
		{
		/* If there's a session key present, make sure it's consistent with
		   the originator info */
		if( envelopeInfoPtr->iCryptContext != CRYPT_ERROR )
			{
			status = checkFortezzaUsage( cryptHandle, envelopeInfoPtr, 
										 CRYPT_ENVINFO_ORIGINATOR );
			if( cryptStatusError( status ) )
				return( status );
			}

		/* Increment its reference count and add it to the action */
		status = krnlSendNotifier( cryptHandle, RESOURCE_MESSAGE_INCREFCOUNT );
		if( cryptStatusError( status ) )
			return( status );
		envelopeInfoPtr->iOriginatorChain = cryptHandle;

		/* Since we're using Fortezza key management, we have to use Skipjack 
		   as the data encryption algorithm */
		envelopeInfoPtr->defaultAlgo = CRYPT_ALGO_SKIPJACK;

		return( status );
		}

#ifndef NO_COMPRESSION
	/* If it's compression information, set up the compression structures */
	if( envInfo == CRYPT_ENVINFO_COMPRESSION )
		{
		/* Initialize the compression */
#ifndef NO_PGP
		if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP )
			{
			/* PGP has a funny compression level based on DOS memory limits
			   (13-bit windows) and no zlib header (because it uses old
			   InfoZIP code).  Setting the windowSize to a negative value has
			   the undocumented result of not emitting zlib headers */
			if( deflateInit2( &envelopeInfoPtr->zStream, Z_DEFAULT_COMPRESSION,
								   Z_DEFLATED, -13, 8, Z_DEFAULT_STRATEGY ) != Z_OK )
				return( CRYPT_ERROR_MEMORY );
			}
		else
#endif /* NO_PGP */
		if( deflateInit( &envelopeInfoPtr->zStream, Z_DEFAULT_COMPRESSION ) != Z_OK )
			return( CRYPT_ERROR_MEMORY );
		envelopeInfoPtr->zStreamInited = TRUE;

		/* Add a compression action to the action list */
		findCheckLastAction( &envelopeInfoPtr->actionList, &actionListPtr,
							 ACTION_COMPRESS, CRYPT_ERROR );
		status = addAction( &envelopeInfoPtr->actionList, &actionListPtr,
							ACTION_COMPRESS, CRYPT_ERROR );
		return( status );
		}
#endif /* NO_COMPRESSION */

	/* If it's a password, derive a session key encryption context from it */
	if( envInfo == CRYPT_ENVINFO_PASSWORD )
		{
		CREATEOBJECT_INFO createInfo;

#ifndef NO_PGP
		/* PGP doesn't support multiple key exchange/conventional encryption
		   actions.  We don't need to check for an ACTION_KEYEXCHANGE
		   because an action of this type can never be added to a PGP
		   envelope */
		if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP && \
			( findAction( envelopeInfoPtr->preActionList,
						  ACTION_KEYEXCHANGE_PKC ) || \
			  findAction( envelopeInfoPtr->actionList,
						  ACTION_CRYPT ) ) )
			return( CRYPT_ERROR_INITED );
#endif /* NO_PGP */

		/* Create the appropriate encryption context */
		setMessageCreateObjectInfo( &createInfo, envelopeInfoPtr->defaultAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
								  &createInfo, OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			return( status );

		/* Derive the key into the context and add it to the action list */
		if( envelopeInfoPtr->type != CRYPT_FORMAT_PGP )
			{
			RESOURCE_DATA msgData;

			setResourceData( &msgData, ( void * ) value, valueLength );
			status = krnlSendMessage( createInfo.cryptHandle, 
								RESOURCE_IMESSAGE_SETATTRIBUTE_S, &msgData,
								CRYPT_CTXINFO_KEYING_VALUE );
			if( cryptStatusOK( status ) )
				{
				/* Find the insertion point in the list and make sure this
				   action isn't already present */
				actionResult = findCheckLastAction( &envelopeInfoPtr->preActionList,
										&actionListPtr, ACTION_KEYEXCHANGE, 
										createInfo.cryptHandle );
				if( actionResult == ACTION_RESULT_INITED )
					status = CRYPT_ERROR_INITED;

				/* Insert the new key exchange action into the list */
				if( cryptStatusOK( status ) )
					status = addAction( &envelopeInfoPtr->preActionList,
										&actionListPtr, ACTION_KEYEXCHANGE,
										createInfo.cryptHandle );
				}
			}
#ifndef NO_PGP
		else
			{
			/* If it's a PGP envelope, derive the key into the context and
			   add it to the action list.  Note that we add it to the main
			   action list as a general encryption action rather than a pre-
			   action-list key exchange action since PGP doesn't use
			   encrypted session keys */
			status = pgpPasswordToKey( createInfo.cryptHandle, value, 
									   valueLength );
			if( cryptStatusOK( status ) )
				{
				findCheckLastAction( &envelopeInfoPtr->actionList,
									 &actionListPtr, ACTION_CRYPT,
									 CRYPT_ERROR );
				status = addAction( &envelopeInfoPtr->actionList,
									&actionListPtr, ACTION_CRYPT,
									createInfo.cryptHandle );
				}
			}
#endif /* NO_PGP */
		if( cryptStatusError( status ) )
			krnlSendNotifier( createInfo.cryptHandle, 
							  RESOURCE_IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* It's a generic "add a context" action (ie one involving a signature
	   key, a PKC key, a conventional key, or a hash), check everything is
	   valid.  Since PGP only supports a very limited subset of cryptlibs
	   capabilities, we have to be extra careful in checking to make sure the
	   object we've been passed is allowed with PGP */
#ifndef NO_PGP
	if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP )
		{
		status = checkPGPusage( cryptHandle, envelopeInfoPtr, envInfo );
		if( cryptStatusError( status ) )
			return( status );
		}
#endif /* NO_PGP */
	if( envInfo == CRYPT_ENVINFO_PUBLICKEY || \
		envInfo == CRYPT_ENVINFO_PRIVATEKEY )
		{
		actionListPtrPtr = &envelopeInfoPtr->preActionList;
		actionType = ACTION_KEYEXCHANGE_PKC;
		}
	if( envInfo == CRYPT_ENVINFO_KEY )
		{
		/* Normally we add a key exchange action, however PGP doesn't support
		   this type of action so we add a general encryption action
		   instead */
#ifndef NO_PGP
		if( envelopeInfoPtr->type != CRYPT_FORMAT_PGP )
			{
#endif /* NO_PGP */
			actionListPtrPtr = &envelopeInfoPtr->preActionList;
			actionType = ACTION_KEYEXCHANGE;
#ifndef NO_PGP
			}
		else
			{
			if( findAction( envelopeInfoPtr->actionList, ACTION_CRYPT ) != NULL )
				/* We can't add more than one general encryption action */
				return( CRYPT_ERROR_INITED );
			actionListPtrPtr = &envelopeInfoPtr->actionList;
			actionType = ACTION_CRYPT;
			}
#endif /* NO_PGP */
		}
	if( envInfo == CRYPT_ENVINFO_SESSIONKEY )
		{
		/* We can't add more than one session key (in theory we could allow
		   this as it implies multiple layers of encryption, but in practice
		   we force the caller to explicitly do this through multiple levels
		   of enveloping because pushing multiple session keys is usually a
		   programming error rather than a desire to use two layers of triple
		   DES for that extra safety margin) */
		if( findAction( envelopeInfoPtr->actionList, ACTION_CRYPT ) != NULL )
			return( CRYPT_ERROR_INITED );
		actionListPtrPtr = &envelopeInfoPtr->actionList;
		actionType = ( envelopeInfoPtr->isDeenvelope ) ? -ACTION_CRYPT : ACTION_CRYPT;

		/* If there's originator info present, make sure it's consistent with
		   the new session key */
		if( envelopeInfoPtr->iOriginatorChain != CRYPT_ERROR )
			{
			status = checkFortezzaUsage( cryptHandle, envelopeInfoPtr, 
										 CRYPT_ENVINFO_SESSIONKEY );
			if( cryptStatusError( status ) )
				return( status );
			}
		}
	if( envInfo == CRYPT_ENVINFO_HASH )
		{
		actionListPtrPtr = &envelopeInfoPtr->actionList;
		actionType = ( envelopeInfoPtr->isDeenvelope ) ? -ACTION_HASH : ACTION_HASH;
		}
	if( envInfo == CRYPT_ENVINFO_SIGNATURE )
		{
		actionListPtrPtr = &envelopeInfoPtr->postActionList;
		actionType = ACTION_SIGN;
		}

	/* Find the insertion point for this action and make sure it isn't
	   already present */
	actionResult = findCheckLastAction( actionListPtrPtr, &actionListPtr,
										actionType, cryptHandle );
	if( actionResult == ACTION_RESULT_INITED )
		return( CRYPT_ERROR_INITED );
	if( actionResult == ACTION_RESULT_PRESENT )
		return( CRYPT_OK );

	/* Insert the action into the list */
	status = krnlSendMessage( cryptHandle, RESOURCE_IMESSAGE_GETATTRIBUTE,
							  &type, CRYPT_IATTRIBUTE_TYPE );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM1 : status );
	if( type == OBJECT_TYPE_CONTEXT && \
		( envInfo != CRYPT_ENVINFO_PUBLICKEY && \
		  envInfo != CRYPT_ENVINFO_PRIVATEKEY && \
		  envInfo != CRYPT_ENVINFO_SIGNATURE ) )
		{
		CRYPT_CONTEXT iNewContext;

		/* It's a non-PKC context (ie one whose state can change based on
		   user action), clone it for our own use */
		status = krnlSendMessage( cryptHandle, RESOURCE_MESSAGE_CLONE,
								  &iNewContext, 0 );
		if( cryptStatusOK( status ) )
			status = addAction( actionListPtrPtr, &actionListPtr, actionType,
								iNewContext );
		}
	else
		{
		/* It's a PKC context or certificate, increment its reference count */
		krnlSendNotifier( cryptHandle, RESOURCE_IMESSAGE_INCREFCOUNT );
		status = addAction( actionListPtrPtr, &actionListPtr, actionType,
							cryptHandle );
		if( cryptStatusError( status ) )
			krnlSendNotifier( cryptHandle, RESOURCE_IMESSAGE_DECREFCOUNT );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( actionType == ACTION_HASH )
		/* Remember that we need to hook the hash action up to a signature
		   action before we start enveloping data */
		actionListPtr->needsController = TRUE;

	/* If the newly-inserted action isn't a controlling action, we're done */
	if( actionType != ACTION_SIGN )
		return( status );

	/* Check if there's a subject hash action available */
	hashActionPtr = findAction( envelopeInfoPtr->actionList, ACTION_HASH );
	if( hashActionPtr == NULL )
		{
		CREATEOBJECT_INFO createInfo;

		/* Create a default hash action */
		setMessageCreateObjectInfo( &createInfo, envelopeInfoPtr->defaultHash );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
								  &createInfo, OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			return( status );

		/* Insert the hash action into the list.  We can pass a NULL context
		   to findCheckLastAction() because we've just verified that there
		   are no existing hash contexts present */
		findCheckLastAction( &envelopeInfoPtr->actionList, &hashActionPtr,
							 ACTION_HASH, CRYPT_ERROR );
		status = addAction( &envelopeInfoPtr->actionList, &hashActionPtr,
							ACTION_HASH, createInfo.cryptHandle );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( createInfo.cryptHandle, 
							  RESOURCE_IMESSAGE_DECREFCOUNT );
			return( status );
			}

		/* Remember that the action was added invisibly to the caller so we
		   don't return an error if they add it as well */
		hashActionPtr->addedAutomatically = TRUE;
		}
	else
		/* There's at least one hash action available, find the last one
		   which was added */
		findCheckLastAction( &envelopeInfoPtr->actionList, &hashActionPtr,
							 ACTION_HASH, CRYPT_ERROR );

	/* Connect the signature action to the subject hash action and remember
	   that this action now has a controlling action */
	actionListPtr->associatedAction = hashActionPtr;
	hashActionPtr->needsController = FALSE;

	return( CRYPT_OK );
	}
