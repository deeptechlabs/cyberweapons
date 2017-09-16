/****************************************************************************
*																			*
*					  cryptlib Encryption Context Routines					*
*						Copyright Peter Gutmann 1992-1999					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#include "cryptctx.h"

/* "Modern cryptography is nothing more than a mathematical framework for
	debating the implications of various paranoid delusions"
												- Don Alvarez */

/* Prototypes for functions in cryptcap.c */

int findCapabilityInfo( const CAPABILITY_INFO FAR_BSS **capabilityInfoPtr,
						const CRYPT_ALGO cryptAlgo,
						const CRYPT_MODE cryptMode );

/* Prototypes for functions in cryptkey.c */

BOOLEAN needsKey( const CRYPT_INFO *cryptInfoPtr );
int generateKey( CRYPT_INFO *cryptInfoPtr, int keyLength,
				 const BOOLEAN isAsync );

/****************************************************************************
*																			*
*					Encryption Context Management Functions					*
*																			*
****************************************************************************/

/* Create a deep clone of an encryption context.  This code is used when it's
   necessary to create a local copy of a context the caller has passed in */

static int contextMessageFunction( const CRYPT_CONTEXT cryptContext,
								   const RESOURCE_MESSAGE_TYPE message,
								   void *messageDataPtr,
								   const int messageValue,
								   const int errorCode );

static int cloneContext( CRYPT_CONTEXT *iDestContext,
						 const CRYPT_CONTEXT srcContext,
						 const BOOLEAN publicFieldsOnly )
	{
	CRYPT_INFO *srcInfoPtr, *destInfoPtr;
	CONTEXT_TYPE contextType;
	void *keyPtr = NULL, *privateDataPtr = NULL;
	int status = CRYPT_OK, tempStatus;

	*iDestContext = CRYPT_ERROR;

	getCheckInternalResource( srcContext, srcInfoPtr, RESOURCE_TYPE_CRYPT );
	contextType = srcInfoPtr->type;

	/* We need to preallocate all required memory so we can check for
	   allocation failures before we copy the source context because undoing
	   the shallow cloning of the context isn't easily possible */
	if( contextType == CONTEXT_CONV && srcInfoPtr->ctxConv.key != NULL )
		{
		const int size = krnlMemsize( srcInfoPtr->ctxConv.key );

		status = krnlMemalloc( &keyPtr, size );
		if( cryptStatusError( status ) )
			unlockResourceExit( srcInfoPtr, status );
		memcpy( keyPtr, srcInfoPtr->ctxConv.key, size );
		}
	if( contextType == CONTEXT_HASH && srcInfoPtr->ctxHash.hashInfo != NULL )
		{
		const int size = krnlMemsize( srcInfoPtr->ctxHash.hashInfo );

		tempStatus = krnlMemalloc( &privateDataPtr, size );
		if( cryptStatusError( tempStatus ) )
			status = tempStatus;
		else
			memcpy( privateDataPtr, srcInfoPtr->ctxHash.hashInfo, size );
		}
	if( contextType == CONTEXT_MAC && srcInfoPtr->ctxMAC.macInfo != NULL )
		{
		const int size = krnlMemsize( srcInfoPtr->ctxMAC.macInfo );

		tempStatus = krnlMemalloc( &privateDataPtr, size );
		if( cryptStatusError( tempStatus ) )
			status = tempStatus;
		else
			memcpy( privateDataPtr, srcInfoPtr->ctxMAC.macInfo, size );
		}

	/* If everything went OK, try to create the encryption context */
	if( cryptStatusOK( status ) )
		{
		const int contextFlags = ( needsSecureMemory( srcInfoPtr->type ) ? \
				RESOURCE_FLAG_SECUREMALLOC : 0 ) | RESOURCE_FLAG_INTERNAL;

		krnlCreateObject( status, destInfoPtr, RESOURCE_TYPE_CRYPT,
						  sizeof( CRYPT_INFO ), contextFlags,
						  contextMessageFunction );
		}
	if( !cryptStatusError( status ) )
		*iDestContext = status;
	else
		{
		/* Undo the previous mallocs and exit */
		if( keyPtr != NULL )
			krnlMemfree( keyPtr );
		if( privateDataPtr != NULL )
			krnlMemfree( privateDataPtr );
		unlockResourceExit( srcInfoPtr, status );
		}

	/* Now that all the things which could fail have been done, copy across
	   the shared fields (the expression mimics the offsetof() operator,
	   which isn't available with all compilers.  A more general-purpose
	   alternative is to use (NULL->fieldName - NULL) (with some casting),
	   but since we know the structure and field in advance we don't need to
	   do this).

	   Since this operation copies over a few items of instance-specific
	   information, we have to make sure we reset or re-initialise this
	   information after the block copy */
	memcpy( destInfoPtr, srcInfoPtr, ( size_t ) \
			( ( BYTE * ) &srcInfoPtr->_sharedEnd - ( BYTE * ) srcInfoPtr ) );
	if( contextType == CONTEXT_CONV )
		destInfoPtr->ctxConv.key = keyPtr;
	if( contextType == CONTEXT_PKC )
		{
		krnlSendNotifier( srcInfoPtr->ctxPKC.iDataCert,
						  RESOURCE_IMESSAGE_INCREFCOUNT );
		destInfoPtr->ctxPKC.iDataCert = srcInfoPtr->ctxPKC.iDataCert;
		}
	if( contextType == CONTEXT_HASH )
		destInfoPtr->ctxHash.hashInfo = privateDataPtr;
	if( contextType == CONTEXT_MAC )
		destInfoPtr->ctxMAC.macInfo = privateDataPtr;
	destInfoPtr->objectHandle = *iDestContext;

	/* Finally, copy the bignum fields if necessary.  We have to be careful
	   to only copy initialised bignum fields, and set fields which aren't
	   copied to NULL (this can happen when we're copying a private to a
	   public key context and only the public fields are being replicated) */
	if( contextType == CONTEXT_PKC )
		{
		/* Determine how many of the fields we should copy if we're only
		   cloning the public parts of the key.  Note that the copied pkcInfo
		   field will still contain the private components, but it's somewhat
		   difficult to erase these since they're stored in an opaque,
		   algorithm-specific data structure */
		const int lastComponent = ( publicFieldsOnly ) ? \
								  destInfoPtr->ctxPKC.lastPublicComponent : 8;
		const int lastMontCTX = ( publicFieldsOnly ) ? \
								destInfoPtr->ctxPKC.lastPublicMontCTX : 3;

		/* If we're only copying the public components, mark the key as a
		   public key */
		if( publicFieldsOnly )
			destInfoPtr->ctxPKC.isPublicKey = TRUE;

		/* Copy the components across */
		destInfoPtr->ctxPKC.param1 = BN_new();
		BN_copy( destInfoPtr->ctxPKC.param1, srcInfoPtr->ctxPKC.param1 );
		if( srcInfoPtr->ctxPKC.param2 != NULL && lastComponent >= 2 )
			{
			destInfoPtr->ctxPKC.param2 = BN_new();
			BN_copy( destInfoPtr->ctxPKC.param2, srcInfoPtr->ctxPKC.param2 );
			}
		else
			destInfoPtr->ctxPKC.param2 = NULL;
		if( srcInfoPtr->ctxPKC.param3 != NULL && lastComponent >= 3 )
			{
			destInfoPtr->ctxPKC.param3 = BN_new();
			BN_copy( destInfoPtr->ctxPKC.param3, srcInfoPtr->ctxPKC.param3 );
			}
		else
			destInfoPtr->ctxPKC.param3 = NULL;
		if( srcInfoPtr->ctxPKC.param4 != NULL && lastComponent >= 4 )
			{
			destInfoPtr->ctxPKC.param4 = BN_new();
			BN_copy( destInfoPtr->ctxPKC.param4, srcInfoPtr->ctxPKC.param4 );
			}
		else
			destInfoPtr->ctxPKC.param4 = NULL;
		if( srcInfoPtr->ctxPKC.param5 != NULL && lastComponent >= 5 )
			{
			destInfoPtr->ctxPKC.param5 = BN_new();
			BN_copy( destInfoPtr->ctxPKC.param5, srcInfoPtr->ctxPKC.param5 );
			}
		else
			destInfoPtr->ctxPKC.param5 = NULL;
		if( srcInfoPtr->ctxPKC.param6 != NULL && lastComponent >= 6 )
			{
			destInfoPtr->ctxPKC.param6 = BN_new();
			BN_copy( destInfoPtr->ctxPKC.param6, srcInfoPtr->ctxPKC.param6 );
			}
		else
			destInfoPtr->ctxPKC.param6 = NULL;
		if( srcInfoPtr->ctxPKC.param7 != NULL && lastComponent >= 7 )
			{
			destInfoPtr->ctxPKC.param7 = BN_new();
			BN_copy( destInfoPtr->ctxPKC.param7, srcInfoPtr->ctxPKC.param7 );
			}
		else
			destInfoPtr->ctxPKC.param7 = NULL;
		if( srcInfoPtr->ctxPKC.param8 != NULL && lastComponent >= 8 )
			{
			destInfoPtr->ctxPKC.param8 = BN_new();
			BN_copy( destInfoPtr->ctxPKC.param8, srcInfoPtr->ctxPKC.param8 );
			}
		else
			destInfoPtr->ctxPKC.param8 = NULL;

		/* Copy the MONT_CTX's across */
		if( srcInfoPtr->ctxPKC.montCTX1 != NULL && lastMontCTX >= 1 )
			{
			destInfoPtr->ctxPKC.montCTX1 = BN_MONT_CTX_new();
			BN_MONT_CTX_copy( destInfoPtr->ctxPKC.montCTX1,
							  srcInfoPtr->ctxPKC.montCTX1 );
			}
		else
			destInfoPtr->ctxPKC.montCTX1 = NULL;
		if( srcInfoPtr->ctxPKC.montCTX2 != NULL && lastMontCTX >= 2 )
			{
			destInfoPtr->ctxPKC.montCTX2 = BN_MONT_CTX_new();
			BN_MONT_CTX_copy( destInfoPtr->ctxPKC.montCTX2,
            				  srcInfoPtr->ctxPKC.montCTX2 );
			}
		else
			destInfoPtr->ctxPKC.montCTX2 = NULL;
		if( srcInfoPtr->ctxPKC.montCTX3 != NULL && lastMontCTX >= 3 )
			{
			destInfoPtr->ctxPKC.montCTX3 = BN_MONT_CTX_new();
			BN_MONT_CTX_copy( destInfoPtr->ctxPKC.montCTX3,
            				  srcInfoPtr->ctxPKC.montCTX3 );
			}
		else
			destInfoPtr->ctxPKC.montCTX3 = NULL;
		}

	/* Now that we've cloned the source context, decrement its reference
	   count if necessary */
	if( srcInfoPtr->refCount )
		srcInfoPtr->refCount--;

	unlockResourceExit2( srcInfoPtr, destInfoPtr, CRYPT_OK );
	}

/* Perform various basic compliance checks on a context */

static int checkContextCompliance( const CRYPT_INFO *cryptInfoPtr,
								   const RESOURCE_MESSAGE_CHECK_TYPE checkType,
								   const int paramErrorCode )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = cryptInfoPtr->capabilityInfo;
	const CRYPT_ALGO cryptAlgo = capabilityInfoPtr->cryptAlgo;

	/* If it's a check for a key generation capability (which is algorithm-
	   type independent), we check it before performing any algorithm-
	   specific checks */
	if( checkType == RESOURCE_MESSAGE_CHECK_KEYGEN )
		{
		if( cryptInfoPtr->type == CONTEXT_HASH )
			return( CRYPT_NOTAVAIL );	/* No key for hash algorithms */
		if( !needsKey( cryptInfoPtr ) )
			return( CRYPT_INITED );		/* Key already present */
		return( ( capabilityInfoPtr->generateKeyFunction != NULL ) ? \
				CRYPT_OK : paramErrorCode );
		}

	/* Perform general checks */
	if( needsKey( cryptInfoPtr ) )
		return( CRYPT_NOKEY );

	/* Check for hash, MAC, and conventional encryption contexts */
	if( checkType == RESOURCE_MESSAGE_CHECK_HASH )
		return( ( cryptInfoPtr->type == CONTEXT_HASH ) ? \
				CRYPT_OK : paramErrorCode );
	if( checkType == RESOURCE_MESSAGE_CHECK_MAC )
		return( ( cryptInfoPtr->type == CONTEXT_MAC ) ? \
				CRYPT_OK : paramErrorCode );
	if( checkType == RESOURCE_MESSAGE_CHECK_CRYPT )
		return( ( cryptInfoPtr->type != CONTEXT_CONV ) ? \
				paramErrorCode : CRYPT_OK );

	/* Make sure it's a PKC context */
	if( cryptInfoPtr->type != CONTEXT_PKC )
		return( paramErrorCode );

	/* Check that the algorithm complies and the capability is available */
	if( cryptAlgo == CRYPT_ALGO_DH )
		/* DH can never be used for encryption or signatures (if it is then
		   we call it Elgamal) */
		return( ( checkType == RESOURCE_MESSAGE_CHECK_PKC_KEYAGREE ) ? \
				CRYPT_OK : paramErrorCode );
	if( ( checkType == RESOURCE_MESSAGE_CHECK_PKC_ENCRYPT || \
		  checkType == RESOURCE_MESSAGE_CHECK_PKC_DECRYPT ) && \
		cryptAlgo == CRYPT_ALGO_DSA )
		return( paramErrorCode );	/* Must be an encryption algorithm */
	if( ( checkType == RESOURCE_MESSAGE_CHECK_PKC_ENCRYPT && \
		  capabilityInfoPtr->encryptFunction == NULL ) || \
		( checkType == RESOURCE_MESSAGE_CHECK_PKC_DECRYPT && \
		  capabilityInfoPtr->decryptFunction == NULL ) || \
		( checkType == RESOURCE_MESSAGE_CHECK_PKC_SIGN && \
		  capabilityInfoPtr->signFunction == NULL ) || \
		( checkType == RESOURCE_MESSAGE_CHECK_PKC_SIGCHECK && \
		  capabilityInfoPtr->sigCheckFunction == NULL ) )
		return( paramErrorCode );	/* Capability not supported */

	/* Check that it's a private key if this is required */
	if( ( checkType == RESOURCE_MESSAGE_CHECK_PKC_PRIVATE || \
		  checkType == RESOURCE_MESSAGE_CHECK_PKC_DECRYPT || \
		  checkType == RESOURCE_MESSAGE_CHECK_PKC_SIGN ) && \
		cryptInfoPtr->ctxPKC.isPublicKey )
		return( paramErrorCode );

	return( CRYPT_OK );
	}

/* Check whether two encryption contexts are identical.  This is generally
   used before cloneContext() to make sure that a context which is about to
   be cloned isn't a duplicate of an existing context (the "source context") */

static int compareContexts( const CRYPT_CONTEXT cryptContext1,
							const CRYPT_CONTEXT cryptContext2 )
	{
	CRYPT_INFO *cryptInfoPtr1, *cryptInfoPtr2;
	const CAPABILITY_INFO *capabilityInfo1, *capabilityInfo2;

	/* Handle null or non-initialised contexts.  Null contexts are regarded
	   as being identical to avoid having to special-case these in the
	   calling code */
	if( cryptContext1 == CRYPT_ERROR && cryptContext2 == CRYPT_ERROR )
		return( CRYPT_OK );	/* Special case for null contexts */
	getCheckInternalResource( cryptContext1, cryptInfoPtr1,
							  RESOURCE_TYPE_CRYPT );
	getCheckInternalResource2( cryptContext2, cryptInfoPtr2,
							   RESOURCE_TYPE_CRYPT, cryptInfoPtr1 );
	capabilityInfo1 = cryptInfoPtr1->capabilityInfo;
	capabilityInfo2 = cryptInfoPtr2->capabilityInfo;

	/* Compare the basic identification fields to determine whether the
	   contexts are identical */
	if( capabilityInfo1->cryptAlgo != capabilityInfo2->cryptAlgo || \
		capabilityInfo1->cryptMode != capabilityInfo2->cryptMode || \
		cryptInfoPtr1->type != cryptInfoPtr2->type )
		unlockResourceExit2( cryptInfoPtr1, cryptInfoPtr2, CRYPT_ERROR );

	/* Make sure the contexts have keys loaded (this is a sanity check rather
	   than part of the comparison, since comparing non-initialised contexts
	   doesn't make sense) */
	if( cryptInfoPtr1->type == CONTEXT_CONV && \
		!( cryptInfoPtr1->ctxConv.keySet && cryptInfoPtr2->ctxConv.keySet ) )
		unlockResourceExit2( cryptInfoPtr1, cryptInfoPtr2, CRYPT_ERROR );
	if( cryptInfoPtr1->type == CONTEXT_PKC && \
		!( cryptInfoPtr1->ctxPKC.keySet && cryptInfoPtr2->ctxPKC.keySet ) )
		unlockResourceExit2( cryptInfoPtr1, cryptInfoPtr2, CRYPT_ERROR );
	if( cryptInfoPtr1->type == CONTEXT_MAC && \
		!( cryptInfoPtr1->ctxMAC.keySet && cryptInfoPtr2->ctxMAC.keySet ) )
		unlockResourceExit2( cryptInfoPtr1, cryptInfoPtr2, CRYPT_ERROR );

	/* If it's a conventional algorithm, compare the derivation info and
		algorithm/keying info.  The latter is done via the key check value
		since this provides a canonical encoding of the algorithm and key
		details which is independent of the underlying implementation */
	if( cryptInfoPtr1->type == CONTEXT_CONV )
		{
		BYTE checkValue1[ KEY_CHECKVALUE_SIZE ];
		BYTE checkValue2[ KEY_CHECKVALUE_SIZE ];

		if( ( cryptInfoPtr1->ctxConv.keySetupIterations != \
			  cryptInfoPtr2->ctxConv.keySetupIterations ) || \
			( cryptInfoPtr1->ctxConv.keySetupAlgorithm != \
			  cryptInfoPtr2->ctxConv.keySetupAlgorithm ) )
			unlockResourceExit2( cryptInfoPtr1, cryptInfoPtr2, CRYPT_ERROR );
		calculateKeyCheckValue( cryptInfoPtr1, checkValue1 );
		calculateKeyCheckValue( cryptInfoPtr2, checkValue2 );
		if( !memcmp( checkValue1, checkValue2, KEY_CHECKVALUE_SIZE ) )
			/* The check values match */
			unlockResourceExit2( cryptInfoPtr1, cryptInfoPtr2, CRYPT_OK );
		}

	/* If it's a PKC, compare the key ID */
	if( cryptInfoPtr1->type == CONTEXT_PKC && \
		!memcmp( cryptInfoPtr1->ctxPKC.keyID, cryptInfoPtr2->ctxPKC.keyID,
				 KEYID_SIZE ) )
		unlockResourceExit2( cryptInfoPtr1, cryptInfoPtr2, CRYPT_OK );

	/* If it's a hash or MAC algorithm, compare the extended information if
	   there is any */
	if( cryptInfoPtr1->type == CONTEXT_HASH || \
		cryptInfoPtr1->type == CONTEXT_MAC )
		{
		const BOOLEAN param1 = ( cryptInfoPtr1->type == CONTEXT_HASH ) ? \
							   cryptInfoPtr1->ctxHash.algorithmParam1 : \
							   cryptInfoPtr1->ctxMAC.algorithmParam1;
		const BOOLEAN param2 = ( cryptInfoPtr2->type == CONTEXT_HASH ) ? \
							   cryptInfoPtr2->ctxHash.algorithmParam1 : \
							   cryptInfoPtr2->ctxMAC.algorithmParam1;

		if( param1 ^ param2 )
			/* One has info, the other doesn't */
			unlockResourceExit2( cryptInfoPtr1, cryptInfoPtr2, CRYPT_ERROR );
		if( !param1 || param1 == param2 )
			/* Neither have info or the info is the same */
			unlockResourceExit2( cryptInfoPtr1, cryptInfoPtr2, CRYPT_OK );
		}

	unlockResourceExit2( cryptInfoPtr1, cryptInfoPtr2, CRYPT_ERROR );
	}

/* Handle a message sent to an encryption context */

static int contextMessageFunction( const CRYPT_CONTEXT cryptContext,
								   const RESOURCE_MESSAGE_TYPE message,
								   void *messageDataPtr,
								   const int messageValue,
								   const int errorCode )
	{
	CRYPT_INFO *cryptInfoPtr;
	int status = errorCode;

	getCheckInternalResource( cryptContext, cryptInfoPtr, RESOURCE_TYPE_CRYPT );

	/* Process destroy object messages */
	if( message == RESOURCE_MESSAGE_DESTROY || \
		message == RESOURCE_MESSAGE_PARTIAL_DESTROY )
		{
		const contextType = cryptInfoPtr->type;

		/* If the context is busy, abort the async.operation.  We do this by
		   setting the abort flag (which is OK, since the context is about to
		   be destroyed anyway) and then waiting for the busy flag to be
		   cleared */
		cryptInfoPtr->doAbort = TRUE;
		krnlSendMessage( cryptContext, RESOURCE_MESSAGE_GETPROPERTY,
						 &status, RESOURCE_MESSAGE_PROPERTY_STATUS, 0 );
		while( status == CRYPT_BUSY )
			{
			/* Wait a bit before we check it again */
#ifdef __WIN32__
			Sleep( 250 );	/* Wait 1/4s */
#endif /* __WIN32__ */
			krnlSendMessage( cryptContext, RESOURCE_MESSAGE_GETPROPERTY,
							 &status, RESOURCE_MESSAGE_PROPERTY_STATUS, 0 );
			}

		/* If the object hasn't already been partially destroyed, perform any
		   algorithm-specific shutdown.  We continue even if this function
		   fails since there's not much which can be done in terms of error
		   recovery at this point */
		if( cryptInfoPtr->capabilityInfo != NULL )
			{
			if( cryptInfoPtr->capabilityInfo->endFunction != NULL )
				status = cryptInfoPtr->capabilityInfo->endFunction( cryptInfoPtr );
			cryptInfoPtr->capabilityInfo = NULL;
			}

		/* Perform context-type-specific cleanup */
		if( contextType == CONTEXT_PKC )
			{
			if( cryptInfoPtr->ctxPKC.param1 != NULL )
				BN_clear_free( cryptInfoPtr->ctxPKC.param1 );
			if( cryptInfoPtr->ctxPKC.param2 != NULL )
				BN_clear_free( cryptInfoPtr->ctxPKC.param2 );
			if( cryptInfoPtr->ctxPKC.param3 != NULL )
				BN_clear_free( cryptInfoPtr->ctxPKC.param3 );
			if( cryptInfoPtr->ctxPKC.param4 != NULL )
				BN_clear_free( cryptInfoPtr->ctxPKC.param4 );
			if( cryptInfoPtr->ctxPKC.param5 != NULL )
				BN_clear_free( cryptInfoPtr->ctxPKC.param5 );
			if( cryptInfoPtr->ctxPKC.param6 != NULL )
				BN_clear_free( cryptInfoPtr->ctxPKC.param6 );
			if( cryptInfoPtr->ctxPKC.param7 != NULL )
				BN_clear_free( cryptInfoPtr->ctxPKC.param7 );
			if( cryptInfoPtr->ctxPKC.param8 != NULL )
				BN_clear_free( cryptInfoPtr->ctxPKC.param8 );
			if( cryptInfoPtr->ctxPKC.montCTX1 != NULL )
				BN_MONT_CTX_free( cryptInfoPtr->ctxPKC.montCTX1 );
			if( cryptInfoPtr->ctxPKC.montCTX2 != NULL )
				BN_MONT_CTX_free( cryptInfoPtr->ctxPKC.montCTX2 );
			if( cryptInfoPtr->ctxPKC.montCTX3 != NULL )
				BN_MONT_CTX_free( cryptInfoPtr->ctxPKC.montCTX3 );

			/* If there's a certificate object containing X.509-related data
			   present, decrement its reference count */
			if( cryptInfoPtr->ctxPKC.iDataCert != CRYPT_ERROR )
				{
				krnlSendNotifier( cryptInfoPtr->ctxPKC.iDataCert,
								  RESOURCE_IMESSAGE_DECREFCOUNT );
				cryptInfoPtr->ctxPKC.iDataCert = CRYPT_ERROR;
				}
			}

		/* Zeroise the context-type-specific data storage */
		zeroise( &cryptInfoPtr->keyingInfo, sizeof( cryptInfoPtr->keyingInfo ) );
		cryptInfoPtr->type = CONTEXT_NONE;

		/* We've finished deleting the objects data, mark it as partially
		   destroyed, which ensures that any further attempts to access it
		   fail.  This avoids a race condition where other threads may try
		   to use the partially-destroyed object after we unlock it but
		   before we finish destroying it, note that we set the urgent flag
		   to ensure that the status change is processed immediately rather
		   than being queued until after the current (destroy) message has
		   been processed */
		status = CRYPT_SIGNALLED;
		krnlSendMessage( cryptContext,
						 RESOURCE_MESSAGE_SETPROPERTY | RESOURCE_MESSAGE_URGENT,
						 &status, RESOURCE_MESSAGE_PROPERTY_STATUS, 0 );
		unlockResource( cryptInfoPtr );
		if( message == RESOURCE_MESSAGE_PARTIAL_DESTROY )
			return( CRYPT_OK );

		/* Delete the objects locking variables and the object itself */
		deleteResourceLock( cryptInfoPtr );
		if( needsSecureMemory( contextType ) )
			krnlMemfree( ( void ** ) &cryptInfoPtr );
		else
			{
			zeroise( cryptInfoPtr, sizeof( CRYPT_INFO ) );
			free( cryptInfoPtr );
			}

		return( CRYPT_OK );
		}

	/* Process the increment/decrement object reference count message */
	if( message == RESOURCE_MESSAGE_INCREFCOUNT )
		{
		/* Increment the objects reference count */
		cryptInfoPtr->refCount++;

		status = CRYPT_OK;
		}
	if( message == RESOURCE_MESSAGE_DECREFCOUNT )
		{
		/* If we're already at a single reference, destroy the object */
		if( !cryptInfoPtr->refCount )
			krnlSendNotifier( cryptContext, RESOURCE_IMESSAGE_DESTROY );
		else
			/* Decrement the objects reference count */
			cryptInfoPtr->refCount--;

		status = CRYPT_OK;
		}

	/* Process messages which send data to the object */
	if( message == RESOURCE_MESSAGE_SETDATA )
		{
		status = CRYPT_OK;

		switch( messageValue )
			{
			case RESOURCE_MESSAGE_DATA_CERTIFICATE:
				if( cryptInfoPtr->type == CONTEXT_PKC )
					cryptInfoPtr->ctxPKC.iDataCert = *( ( int * ) messageDataPtr );
				else
					status = CRYPT_ERROR;	/* Internal error, should never happen */
				break;

			case RESOURCE_MESSAGE_DATA_DEVICE:
				cryptInfoPtr->iCryptDevice = *( ( int * ) messageDataPtr );
				break;

			default:
				status = errorCode;
			}
		}

	/* Process messages which get data from the object */
	if( message == RESOURCE_MESSAGE_GETDATA )
		{
		switch( messageValue )
			{
			case RESOURCE_MESSAGE_DATA_CONTEXT:
				*( ( int * ) messageDataPtr ) = cryptContext;
				status = CRYPT_OK;
				break;

			case RESOURCE_MESSAGE_DATA_CERTIFICATE:
				if( cryptInfoPtr->type == CONTEXT_PKC && \
					cryptInfoPtr->ctxPKC.iDataCert != CRYPT_ERROR )
					{
					*( ( int * ) messageDataPtr ) = cryptInfoPtr->ctxPKC.iDataCert;
					status = CRYPT_OK;
					}
				break;

			case RESOURCE_MESSAGE_DATA_DEVICE:
				if( cryptInfoPtr->iCryptDevice != CRYPT_ERROR )
					{
					*( ( int * ) messageDataPtr ) = cryptInfoPtr->iCryptDevice;
					status = CRYPT_OK;
					}
				break;

			case RESOURCE_MESSAGE_DATA_ISSUERANDSERIALNUMBER:
			case RESOURCE_MESSAGE_DATA_CERTSET:
			case RESOURCE_MESSAGE_DATA_ERRORINFO:
				if( cryptInfoPtr->type == CONTEXT_PKC && \
					cryptInfoPtr->ctxPKC.iDataCert != CRYPT_ERROR )
					/* Pass the message on down to the associated cert */
					status = krnlSendMessage( cryptInfoPtr->ctxPKC.iDataCert,
								RESOURCE_IMESSAGE_GETDATA,
								messageDataPtr, messageValue, errorCode );
				break;
			}

		if( cryptStatusError( status ) )
			*( ( int * ) messageDataPtr ) = CRYPT_ERROR;
		}

	/* Process messages which compare or clone the object */
	if( message == RESOURCE_MESSAGE_COMPARE )
		{
		status = errorCode;

		switch( messageValue )
			{
			case RESOURCE_MESSAGE_COMPARE_OBJECT:
				status = compareContexts( cryptContext,
								*( ( CRYPT_CONTEXT * ) messageDataPtr ) );
				break;

			case RESOURCE_MESSAGE_COMPARE_ISSUERANDSERIALNUMBER:
				if( cryptInfoPtr->type != CONTEXT_PKC || \
					cryptInfoPtr->ctxPKC.iDataCert == CRYPT_ERROR )
					/* There's no cert associated with this context, we can't
					   compare the issuerAndSerialNumber */
					status = CRYPT_ERROR;
				else
					/* Pass the message on down to the associated cert */
					status = krnlSendMessage( cryptInfoPtr->ctxPKC.iDataCert,
							RESOURCE_IMESSAGE_COMPARE, messageDataPtr,
							RESOURCE_MESSAGE_COMPARE_ISSUERANDSERIALNUMBER,
							errorCode );
				break;
			}
		}
	if( message == RESOURCE_MESSAGE_CLONE )
		status = cloneContext( messageDataPtr, cryptContext, messageValue );

	/* Process messages which check a context */
	if( message == RESOURCE_MESSAGE_CHECK )
		{
		/* First we check the context itself.  If this is OK and there's a
		   cert attached, we pass the call down to the attached cert */
		status = checkContextCompliance( cryptInfoPtr, messageValue,
										 errorCode );
		if( cryptStatusOK( status ) && cryptInfoPtr->type == CONTEXT_PKC && \
			cryptInfoPtr->ctxPKC.iDataCert != CRYPT_ERROR )
			status = krnlSendMessage( cryptInfoPtr->ctxPKC.iDataCert,
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
		unlockResource( cryptInfoPtr );	/* Undo RESOURCE_MESSAGE_LOCK lock */
		status = CRYPT_OK;
		}

	/* Process internal notification messages */
	if( message == RESOURCE_MESSAGE_CHANGENOTIFY && \
		messageValue == RESOURCE_MESSAGE_PROPERTY_STATUS )
		{
		/* If the context is still busy and we're trying to reset its status
		   from CRYPT_BUSY back to CRYPT_OK, set the abort flag to indicate
		   that the operation which is keeping it busy should be cancelled,
		   and return an error so that the busy status is maintained until
		   the context has processed the abort */
		if( !cryptInfoPtr->done )
			cryptInfoPtr->doAbort = TRUE;
		else
			/* The context finished whatever it was doing, reset the status
			   back to normal */
			status = CRYPT_OK;
		}

	/* Process object-specific messages */
	if( message == RESOURCE_MESSAGE_CTX_GENKEY || \
		message == RESOURCE_MESSAGE_CTX_GENKEY_ASYNC )
		{
		/* If it's a hash function, key generation isn't available */
		if( cryptInfoPtr->type == CONTEXT_HASH )
			status = CRYPT_NOTAVAIL;
		else
			/* We can't reload a key if we've already got one loaded (we have
			   to check for this after the hash check since hash contexts
			   always appear to have keys loaded) */
			if( !needsKey( cryptInfoPtr ) )
				status = CRYPT_INITED;
			else
				status = generateKey( cryptInfoPtr, messageValue,
					( message == RESOURCE_MESSAGE_CTX_GENKEY_ASYNC ) ? \
					TRUE : FALSE );
		}

	unlockResourceExit( cryptInfoPtr, status );
	}

/* Get built-in capability information for a context */

static int getCapabilityInfo( const CAPABILITY_INFO FAR_BSS **capabilityInfoPtr,
							  const CRYPT_ALGO cryptAlgo,
							  const CRYPT_MODE cryptMode )
	{
	CRYPT_ALGO localCryptAlgo = cryptAlgo;
	CRYPT_MODE localCryptMode = cryptMode;

	*capabilityInfoPtr = NULL;

	/* Handle any default settings for algorithm and mode */
	if( cryptAlgo == CRYPT_USE_DEFAULT )
		{
		/* If the mode is CRYPT_MODE_NONE, it's a hash or MAC context */
		if( cryptMode == CRYPT_MODE_NONE )
			localCryptAlgo = getOptionNumeric( CRYPT_OPTION_ENCR_HASH );
		else
			/* If the mode is CRYPT_MODE_PKC, it's a PKC context.  This
			   context is dependant on the key being loaded so there isn't
			   really any default setting we can use for it */
			if( cryptMode == CRYPT_MODE_PKC )
				return( CRYPT_BADPARM2 );
			else
				{
				/* It's a conventional encryption context */
				localCryptAlgo = getOptionNumeric( CRYPT_OPTION_ENCR_ALGO );
				if( cryptMode == CRYPT_USE_DEFAULT )
					localCryptMode = getOptionNumeric( CRYPT_OPTION_ENCR_MODE );
				}
		}
	if( localCryptMode == CRYPT_USE_DEFAULT )
		/* If it's a conventional algorithm, get the default mode to use */
		if( ( cryptAlgo >= CRYPT_ALGO_FIRST_CONVENTIONAL ) && \
			( cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL ) )
			localCryptMode = getOptionNumeric( CRYPT_OPTION_ENCR_MODE );
		else
			/* If it's anything else, set a mode appropriate to the algorithm
			   being used */
			if( ( cryptAlgo >= CRYPT_ALGO_FIRST_PKC ) && \
				( cryptAlgo <= CRYPT_ALGO_LAST_PKC ) )
				localCryptMode = CRYPT_MODE_PKC;
			else
				if( ( cryptAlgo >= CRYPT_ALGO_FIRST_HASH ) && \
					( cryptAlgo <= CRYPT_ALGO_LAST_MAC ) )
					localCryptMode = CRYPT_MODE_NONE;
				else
					return( CRYPT_ERROR );	/* Internal error, should never happen */

	/* Get a pointer to the capability information */
	return( findCapabilityInfo( capabilityInfoPtr, localCryptAlgo,
								localCryptMode ) );
	}

/* Create an encryption context.  This is a common function called by the
   cryptCreateContext() functions */

int createContext( CRYPT_CONTEXT *cryptContext,
				   const CAPABILITY_INFO *capabilityInfoPtr,
				   const void *cryptInfoEx, const int objectFlags )
	{
	const CRYPT_ALGO cryptAlgo = capabilityInfoPtr->cryptAlgo;
	const CONTEXT_TYPE contextType = \
		( ( cryptAlgo >= CRYPT_ALGO_FIRST_CONVENTIONAL ) && \
		  ( cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL ) ) ? CONTEXT_CONV : \
		( ( cryptAlgo >= CRYPT_ALGO_FIRST_PKC ) && \
		  ( cryptAlgo <= CRYPT_ALGO_LAST_PKC ) ) ? CONTEXT_PKC : \
		( ( cryptAlgo >= CRYPT_ALGO_FIRST_HASH ) && \
		  ( cryptAlgo <= CRYPT_ALGO_LAST_HASH ) ) ? CONTEXT_HASH : CONTEXT_MAC;
	CRYPT_INFO *cryptInfoPtr;
	int status;

	/* Clear the return values */
	*cryptContext = CRYPT_ERROR;

	/* Make sure the context can use the extended initialisation parameters
	   if they're present, and that the capability self-test went OK */
	if( cryptInfoEx != NULL && \
		( cryptAlgo == CRYPT_ALGO_RC5 || cryptAlgo == CRYPT_ALGO_SAFER ) )
		return( CRYPT_BADPARM2 );
	if( capabilityInfoPtr->selfTestStatus != CRYPT_OK )
		return( CRYPT_SELFTEST );

	/* Create the context and initialise the variables in it */
	krnlCreateObject( status, cryptInfoPtr, RESOURCE_TYPE_CRYPT,
					  sizeof( CRYPT_INFO ), ( needsSecureMemory( contextType ) ? \
					  RESOURCE_FLAG_SECUREMALLOC : 0 ) | objectFlags,
					  contextMessageFunction );
	if( cryptStatusError( status ) )
		return( status );
	*cryptContext = status;
	cryptInfoPtr->capabilityInfo = capabilityInfoPtr;
	cryptInfoPtr->type = contextType;
	cryptInfoPtr->objectHandle = *cryptContext;
	cryptInfoPtr->iCryptDevice = CRYPT_ERROR;
	cryptInfoPtr->iCryptDeviceHandle = CRYPT_ERROR;
	if( cryptInfoPtr->type == CONTEXT_PKC )
		{
		cryptInfoPtr->ctxPKC.iDataCert = CRYPT_ERROR;
		cryptInfoPtr->ctxPKC.keySizeBits = 0;

		/* Initialise the bignum information */
		cryptInfoPtr->ctxPKC.param1 = BN_new();
		cryptInfoPtr->ctxPKC.param2 = BN_new();
		cryptInfoPtr->ctxPKC.param3 = BN_new();
		cryptInfoPtr->ctxPKC.param4 = BN_new();
		cryptInfoPtr->ctxPKC.param5 = BN_new();
		cryptInfoPtr->ctxPKC.param6 = BN_new();
		cryptInfoPtr->ctxPKC.param7 = BN_new();
		cryptInfoPtr->ctxPKC.param8 = BN_new();
		}

	/* Perform any algorithm-specific initialization */
	if( capabilityInfoPtr->initFunction != NULL )
		{
		status = capabilityInfoPtr->initFunction( cryptInfoPtr, cryptInfoEx );
		if( cryptStatusError( status ) )
			{
			unlockResource( cryptInfoPtr );
			krnlSendNotifier( *cryptContext, RESOURCE_IMESSAGE_DESTROY );
			*cryptContext = CRYPT_ERROR;
			return( status );
			}
		}

	unlockResourceExit( cryptInfoPtr, CRYPT_OK );
	}

/* Create an encryption context */

CRET cryptCreateContextEx( CRYPT_CONTEXT CPTR cryptContext,
						   const CRYPT_ALGO cryptAlgo,
						   const CRYPT_MODE cryptMode,
						   const void CPTR cryptInfoEx )
	{
	const CAPABILITY_INFO *capabilityInfoPtr;
	int status;

	/* Perform basic error checking */
	if( checkBadPtrWrite( cryptContext, sizeof( CRYPT_CONTEXT ) ) )
		return( CRYPT_BADPARM1 );
	*cryptContext = CRYPT_ERROR;
	if( ( cryptAlgo <= CRYPT_ALGO_NONE || cryptAlgo >= CRYPT_ALGO_LAST ) && \
		cryptAlgo != CRYPT_USE_DEFAULT )
		return( CRYPT_BADPARM2 );
	if( ( cryptMode < CRYPT_MODE_NONE || cryptMode >= CRYPT_MODE_LAST ) && \
		cryptMode != CRYPT_USE_DEFAULT )
		return( CRYPT_BADPARM3 );
	if( cryptInfoEx != NULL && \
		checkBadPtrRead( cryptInfoEx, sizeof( int ) ) )	/* Min.cInfoEx size */
		return( CRYPT_BADPARM4 );

	/* Pass the call on to the lower-level create function */
	status = getCapabilityInfo( &capabilityInfoPtr, cryptAlgo, cryptMode );
	if( cryptStatusError( status ) )
		return( status );
	return( createContext( cryptContext, capabilityInfoPtr, cryptInfoEx, 0 ) );
	}

CRET cryptCreateContext( CRYPT_CONTEXT CPTR cryptContext,
						 const CRYPT_ALGO cryptAlgo,
						 const CRYPT_MODE cryptMode )
	{
	return( cryptCreateContextEx( cryptContext, cryptAlgo, cryptMode, NULL ) );
	}

/* Destroy an encryption context */

CRET cryptDestroyContext( const CRYPT_CONTEXT cryptContext )
	{
	return( cryptDestroyObject( cryptContext ) );
	}

/* Generic "destroy an object" function */

CRET cryptDestroyObject( const CRYPT_HANDLE cryptObject )
	{
	BOOLEAN isInternal;
	int status;

	/* Make sure the caller isn't trying to destroy an internal object */
	status = krnlSendMessage( cryptObject, RESOURCE_MESSAGE_GETPROPERTY,
							  &isInternal, RESOURCE_MESSAGE_PROPERTY_INTERNAL,
							  CRYPT_BADPARM1 );
	if( cryptStatusError( status ) )
		return( status );
	if( isInternal )
		return( CRYPT_BADPARM1 );

	/* Make the object internal, which marks it as invalid for any external
	   access (to the caller, it looks like it's been destroyed).  After
	   this, decrement its reference count (which may or may not actually
	   destroy it) */
	isInternal = TRUE;
	krnlSendMessage( cryptObject, RESOURCE_MESSAGE_SETPROPERTY, &isInternal,
					 RESOURCE_MESSAGE_PROPERTY_INTERNAL, 0 );
	return( krnlSendNotifier( cryptObject, RESOURCE_IMESSAGE_DECREFCOUNT ) );
	}

/* Get/set object properties.  These are just wrapper functions for the
   (user-accessible) object properties */

static int mapProperty( const CRYPT_PROPERTY_TYPE property )
	{
	switch( property )
		{
		case CRYPT_PROPERTY_OWNER:
			return( RESOURCE_MESSAGE_PROPERTY_OWNER );
		case CRYPT_PROPERTY_LOCKED:
			return( RESOURCE_MESSAGE_PROPERTY_LOCKED );
		case CRYPT_PROPERTY_FORWARDABLE:
			return( RESOURCE_MESSAGE_PROPERTY_FORWARDABLE );
		}

	return( CRYPT_ERROR );
	}

CRET cryptGetObjectProperty( const CRYPT_HANDLE cryptObject,
							 const CRYPT_PROPERTY_TYPE property,
							 int CPTR value )
	{
	const RESOURCE_MESSAGE_PROPERTYTYPE_TYPE resourceProperty = mapProperty( property );

	/* Perform basic error checking */
	if( resourceProperty == CRYPT_ERROR )
		return( CRYPT_BADPARM2 );
	if( checkBadPtrWrite( value, sizeof( int ) ) )
		return( CRYPT_BADPARM3 );
	*value = CRYPT_ERROR;

	return( krnlSendMessage( cryptObject, RESOURCE_MESSAGE_GETPROPERTY,
							 &value, resourceProperty, CRYPT_BADPARM1 ) );
	}

CRET cryptSetObjectProperty( const CRYPT_HANDLE cryptObject,
							 const CRYPT_PROPERTY_TYPE property,
							 const int value )
	{
	const RESOURCE_MESSAGE_PROPERTYTYPE_TYPE resourceProperty = mapProperty( property );

	/* Perform basic error checking */
	if( resourceProperty == CRYPT_ERROR && \
		property != CRYPT_PROPERTY_HIGHSECURITY)
		return( CRYPT_BADPARM2 );
	if( value == CRYPT_UNUSED )
		{
		if( property != CRYPT_PROPERTY_HIGHSECURITY && \
			property != CRYPT_PROPERTY_OWNER )
			return( CRYPT_BADPARM3 );
		}
	else
		if( value < 0 && !( property == CRYPT_PROPERTY_OWNER && \
							value == CRYPT_USE_DEFAULT ) )
			return( CRYPT_BADPARM3 );

	/* If we're setting a pseudoproperty, translate it into the appropriate
	   real properties */
	if( property == CRYPT_PROPERTY_HIGHSECURITY )
		{
		int resourceValue = getCurrentIdentity(), status;

		/* Make the object owned, non-forwardable, and locked */
		status = krnlSendMessage( cryptObject, RESOURCE_MESSAGE_SETPROPERTY,
								  &resourceValue, CRYPT_PROPERTY_OWNER,
								  CRYPT_BADPARM1 );
		if( cryptStatusOK( status ) )
			{
			resourceValue = 0;
			status = krnlSendMessage( cryptObject, RESOURCE_MESSAGE_SETPROPERTY,
									  &resourceValue, CRYPT_PROPERTY_FORWARDABLE,
									  CRYPT_BADPARM1 );
			}
		if( cryptStatusOK( status ) )
			{
			resourceValue = TRUE;
			status = krnlSendMessage( cryptObject, RESOURCE_MESSAGE_SETPROPERTY,
									  &resourceValue, CRYPT_PROPERTY_LOCKED,
									  CRYPT_BADPARM1 );
			}
		return( status );
		}

	/* If we're claiming the object, set its owner to the current identity */
	if( property == CRYPT_PROPERTY_OWNER && value == CRYPT_USE_DEFAULT )
		{
		const int ownerIdentity = getCurrentIdentity();

		return( krnlSendMessage( cryptObject, RESOURCE_MESSAGE_SETPROPERTY,
								 ( int * ) &ownerIdentity, resourceProperty,
								 CRYPT_BADPARM1 ) );
		}

	return( krnlSendMessage( cryptObject, RESOURCE_MESSAGE_SETPROPERTY,
							 ( int * ) &value, resourceProperty, 
							 CRYPT_BADPARM1 ) );
	}

/****************************************************************************
*																			*
*						Internal Context Management Functions				*
*																			*
****************************************************************************/

/* Internal create/destroy/query/encrypt/decrypt functions.  These skip the
   internal context check, and return slightly different error codes for
   parameter errors.  The reason for this is that they're only called by
   cryptlib internal functions so passing any type of parameter error back to
   the caller will cause problems.  For this reason we instead pass back
   CRYPT_BADDATA, since the only way we can get parameter errors (eg key too
   short/long) is if the encoded data which was passed on to the function was
   incorrect.  The internal functions also differ form the external ones in
   the following way:

   iCryptCreateContext() marks the context as being internal.

   iCryptQueryContext() returns an ICRYPT_QUERY_INFO record which contains
   much more information on the context than the CRYPT_QUERY_INFO record */

int iCryptCreateContextEx( CRYPT_CONTEXT *cryptContext,
						   const CRYPT_ALGO cryptAlgo,
						   const CRYPT_MODE cryptMode,
						   const void *cryptContextEx )
	{
	const CAPABILITY_INFO *capabilityInfoPtr;
	int status;

	/* Perform simplified error checking.  Unfortunately there's no nice
	   error code we can use, so we have to make do with CRYPT_BADPARM.  The
	   calling function should map this to something sensible anyway */
	*cryptContext = CRYPT_ERROR;
	if( ( ( cryptAlgo < CRYPT_ALGO_NONE || cryptAlgo >= CRYPT_ALGO_LAST ) && \
		  cryptAlgo != CRYPT_USE_DEFAULT ) || \
		( ( cryptMode < CRYPT_MODE_NONE || cryptMode >= CRYPT_MODE_LAST ) && \
		  cryptMode != CRYPT_USE_DEFAULT ) )
		return( CRYPT_BADPARM );

	/* Pass the call on to the lower-level create function */
	status = getCapabilityInfo( &capabilityInfoPtr, cryptAlgo, cryptMode );
	if( cryptStatusError( status ) )
		return( status );
	return( createContext( cryptContext, capabilityInfoPtr, cryptContextEx,
						   RESOURCE_FLAG_INTERNAL ) );
	}

int iCryptCreateContext( CRYPT_CONTEXT *cryptContext,
						 const CRYPT_ALGO cryptAlgo,
						 const CRYPT_MODE cryptMode )
	{
	return( iCryptCreateContextEx( cryptContext, cryptAlgo, cryptMode, NULL ) );
	}

int iCryptQueryContext( const CRYPT_CONTEXT cryptContext,
						ICRYPT_QUERY_INFO CPTR iCryptQueryInfo )
	{
	const CAPABILITY_INFO *capabilityInfoPtr;
	CRYPT_INFO *cryptInfoPtr;

	/* Perform simplified error checking */
	memset( iCryptQueryInfo, 0, sizeof( ICRYPT_QUERY_INFO ) );
	getCheckInternalResource( cryptContext, cryptInfoPtr, RESOURCE_TYPE_CRYPT );

	/* Fill in the information from the context */
	capabilityInfoPtr = cryptInfoPtr->capabilityInfo;
	iCryptQueryInfo->cryptAlgo = capabilityInfoPtr->cryptAlgo;
	iCryptQueryInfo->cryptMode = capabilityInfoPtr->cryptMode;
	if( cryptInfoPtr->type == CONTEXT_CONV )
		{
		iCryptQueryInfo->blockSize = capabilityInfoPtr->blockSize;
		iCryptQueryInfo->keySet = cryptInfoPtr->ctxConv.keySet;
		iCryptQueryInfo->maxIVsize = capabilityInfoPtr->maxIVsize;
		memcpy( iCryptQueryInfo->iv, cryptInfoPtr->ctxConv.iv,
				cryptInfoPtr->ctxConv.ivLength );
		iCryptQueryInfo->ivLength = cryptInfoPtr->ctxConv.ivLength;
		}
	if( cryptInfoPtr->type == CONTEXT_PKC )
		{
		iCryptQueryInfo->isPKCcontext = TRUE;
		iCryptQueryInfo->isPublicKey = cryptInfoPtr->ctxPKC.isPublicKey;
		iCryptQueryInfo->keySet = cryptInfoPtr->ctxPKC.keySet;
		iCryptQueryInfo->keySize = bitsToBytes( cryptInfoPtr->ctxPKC.keySizeBits );
		memcpy( iCryptQueryInfo->keyID, cryptInfoPtr->ctxPKC.keyID,
				KEYID_SIZE );
		}
	if( cryptInfoPtr->type == CONTEXT_HASH )
		{
		iCryptQueryInfo->blockSize = capabilityInfoPtr->blockSize;
		memcpy( iCryptQueryInfo->hashValue, cryptInfoPtr->ctxHash.hash,
				capabilityInfoPtr->blockSize );
		}
	if( cryptInfoPtr->type == CONTEXT_MAC )
		{
		iCryptQueryInfo->blockSize = capabilityInfoPtr->blockSize;
		iCryptQueryInfo->keySet = cryptInfoPtr->ctxMAC.keySet;
		memcpy( iCryptQueryInfo->hashValue, cryptInfoPtr->ctxMAC.mac,
				capabilityInfoPtr->blockSize );
		}

	unlockResourceExit( cryptInfoPtr, CRYPT_OK );
	}

int iCryptEncrypt( const CRYPT_CONTEXT cryptContext, void CPTR buffer,
				   const int length )
	{
	CRYPT_INFO *cryptInfoPtr;
	int status;

	/* Perform simplified error checking */
	getCheckInternalResource( cryptContext, cryptInfoPtr, RESOURCE_TYPE_CRYPT );
	if( ( cryptInfoPtr->type != CONTEXT_PKC && length < 0 ) || \
		( cryptInfoPtr->type == CONTEXT_CONV &&
		  length % cryptInfoPtr->capabilityInfo->blockSize ) )
		unlockResourceExit( cryptInfoPtr, CRYPT_BADDATA );

	/* If there's no IV set, generate one ourselves */
	if( cryptInfoPtr->type == CONTEXT_CONV && !cryptInfoPtr->ctxConv.ivSet && \
		needsIV( cryptInfoPtr->capabilityInfo->cryptMode ) )
		cryptInfoPtr->capabilityInfo->initIVFunction( cryptInfoPtr, NULL, 0 );

	/* Call the encryption routine for this algorithm/mode */
	status = cryptInfoPtr->capabilityInfo->encryptFunction( cryptInfoPtr, buffer, length );
	unlockResourceExit( cryptInfoPtr, status );
	}

int iCryptDecrypt( const CRYPT_CONTEXT cryptContext, void CPTR buffer,
				   const int length )
	{
	CRYPT_INFO *cryptInfoPtr;
	int status;

	/* Perform simplified error checking */
	getCheckInternalResource( cryptContext, cryptInfoPtr, RESOURCE_TYPE_CRYPT );
	if( ( cryptInfoPtr->type != CONTEXT_PKC && length < 0 ) || \
		( cryptInfoPtr->type == CONTEXT_CONV &&
		  length % cryptInfoPtr->capabilityInfo->blockSize ) )
		unlockResourceExit( cryptInfoPtr, CRYPT_BADDATA );

	/* Call the decryption routine for this algorithm/mode */
	status = cryptInfoPtr->capabilityInfo->decryptFunction( cryptInfoPtr, buffer, length );
	unlockResourceExit( cryptInfoPtr, status );
	}

/* Generic "destroy an object" function.  This is used for all internal
   objects since there's little point in artificially separating the
   different functions */

int iCryptDestroyObject( const CRYPT_HANDLE cryptObject )
	{
	/* Tell the object to destroy itself */
	return( krnlSendNotifier( cryptObject, RESOURCE_IMESSAGE_DESTROY ) );
	}

/****************************************************************************
*																			*
*							Encrypt/Decrypt Routines						*
*																			*
****************************************************************************/

/* Encrypt a block of memory */

CRET cryptEncrypt( const CRYPT_CONTEXT cryptContext, void CPTR buffer,
				   const int length )
	{
	CRYPT_INFO *cryptInfoPtr;
	int status;

	/* Perform basic error checking */
	getCheckResource( cryptContext, cryptInfoPtr, RESOURCE_TYPE_CRYPT,
					  CRYPT_BADPARM1 );
	if( checkBadPtrQ( buffer ) )
		unlockResourceExit( cryptInfoPtr, CRYPT_BADPARM2 );
	if( cryptInfoPtr->type == CONTEXT_PKC )
		{
		if( length != CRYPT_USE_DEFAULT )
			unlockResourceExit( cryptInfoPtr, CRYPT_BADPARM3 );
		}
	else
		if( length < 0 || ( cryptInfoPtr->type == CONTEXT_CONV && \
			length % cryptInfoPtr->capabilityInfo->blockSize ) )
			unlockResourceExit( cryptInfoPtr, CRYPT_BADPARM3 );
	if( needsKey( cryptInfoPtr ) )
		unlockResourceExit( cryptInfoPtr, CRYPT_NOKEY );

	/* If there's no IV set, generate one ourselves */
	if( cryptInfoPtr->type == CONTEXT_CONV && !cryptInfoPtr->ctxConv.ivSet && \
		needsIV( cryptInfoPtr->capabilityInfo->cryptMode ) )
		cryptInfoPtr->capabilityInfo->initIVFunction( cryptInfoPtr, NULL, 0 );

	/* Call the encryption/signature routine for this algorithm/mode */
	if( cryptInfoPtr->capabilityInfo->encryptFunction != NULL )
		status = cryptInfoPtr->capabilityInfo->encryptFunction( cryptInfoPtr,
															buffer, length );
	else
		status = cryptInfoPtr->capabilityInfo->signFunction( cryptInfoPtr,
															buffer, length );
	unlockResourceExit( cryptInfoPtr, status );
	}

/* Decrypt a block of memory */

CRET cryptDecrypt( const CRYPT_CONTEXT cryptContext, void CPTR buffer,
				   const int length )
	{
	CRYPT_INFO *cryptInfoPtr;
	int status;

	/* Perform basic error checking */
	getCheckResource( cryptContext, cryptInfoPtr, RESOURCE_TYPE_CRYPT,
					  CRYPT_BADPARM1 );
	if( checkBadPtrQ( buffer ) )
		unlockResourceExit( cryptInfoPtr, CRYPT_BADPARM2 );
	if( cryptInfoPtr->type == CONTEXT_PKC )
		{
		if( length != CRYPT_USE_DEFAULT )
			unlockResourceExit( cryptInfoPtr, CRYPT_BADPARM3 );
		}
	else
		if( length < 0 || ( cryptInfoPtr->type == CONTEXT_CONV && \
			length % cryptInfoPtr->capabilityInfo->blockSize ) )
			unlockResourceExit( cryptInfoPtr, CRYPT_BADPARM3 );
	if( needsKey( cryptInfoPtr ) )
		unlockResourceExit( cryptInfoPtr, CRYPT_NOKEY );

	/* Make sure the IV has been set */
	if( cryptInfoPtr->type == CONTEXT_CONV && !cryptInfoPtr->ctxConv.ivSet )
		unlockResourceExit( cryptInfoPtr, CRYPT_NOIV );

	/* Call the decryption routine for this algorithm/mode */
	if( cryptInfoPtr->capabilityInfo->decryptFunction != NULL )
		status = cryptInfoPtr->capabilityInfo->decryptFunction( cryptInfoPtr,
															buffer, length );
	else
		status = cryptInfoPtr->capabilityInfo->sigCheckFunction( cryptInfoPtr,
															buffer, length );
	unlockResourceExit( cryptInfoPtr, status );
	}
