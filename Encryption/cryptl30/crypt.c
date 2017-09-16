/****************************************************************************
*																			*
*					  cryptlib Encryption Context Routines					*
*						Copyright Peter Gutmann 1992-1999					*
*																			*
****************************************************************************/

/* "Modern cryptography is nothing more than a mathematical framework for
	debating the implications of various paranoid delusions"
												- Don Alvarez */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#include "cryptctx.h"
#ifdef INC_ALL
  #include "asn1.h"
#else
  #include "keymgmt/asn1.h"
#endif /* Compiler-specific includes */

/* The default size of the salt for PKCS #5v2 key derivation, needed when we
   set the CRYPT_CTXINFO_KEYING_VALUE */

#define PKCS5_SALT_SIZE		8	/* 64 bits */

/* Prototypes for functions in cryptkey.c */

BOOLEAN needsKey( const CRYPT_INFO *cryptInfoPtr );
int getOptimalKeysize( CRYPT_INFO *cryptInfoPtr,
					   const int requestedKeyLength );
int generateKey( CRYPT_INFO *cryptInfoPtr, int keyLength,
				 const BOOLEAN isAsync );
int loadKey( CRYPT_INFO *cryptInfoPtr, BYTE *key, const int keyLength );

/* Prototypes for functions in asn1keys.c */

int writePublicKey( STREAM *stream, const CRYPT_INFO *cryptInfoPtr );
int readSshPublicKey( STREAM *stream, CRYPT_INFO *cryptInfoPtr );

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Check that a capability info record is consistent.  This is a complex
   function which is called from an assert() macro, so we only need to define
   it when we're building a debug version */

#ifndef NDEBUG

BOOLEAN capabilityInfoOK( const CAPABILITY_INFO *capabilityInfoPtr )
	{
	CRYPT_ALGO cryptAlgo = capabilityInfoPtr->cryptAlgo;

	/* Check the algorithm and mode parameters */
	if( cryptAlgo < CRYPT_ALGO_NONE || cryptAlgo >= CRYPT_ALGO_LAST_MAC || \
		capabilityInfoPtr->algoName == NULL )
		return( FALSE );

	/* Make sure that the minimum functions are present */
	if( cryptAlgo == CRYPT_ALGO_RC4 )
		{
		if( capabilityInfoPtr->encryptOFBFunction == NULL || \
			capabilityInfoPtr->decryptOFBFunction == NULL )
			return( FALSE );
		}
	else
		if( ( capabilityInfoPtr->encryptFunction == NULL || \
			  capabilityInfoPtr->decryptFunction == NULL ) && \
			( capabilityInfoPtr->signFunction == NULL || \
			  capabilityInfoPtr->sigCheckFunction == NULL ) )
			return( FALSE );

	/* Make sure the algorithm/mode names will fit inside the query
	   information structure */
	if( strlen( capabilityInfoPtr->algoName ) > CRYPT_MAX_TEXTSIZE - 1 )
		return( FALSE );

	/* Make sure the algorithm/mode-specific parameters are consistent */
	if( capabilityInfoPtr->minKeySize > capabilityInfoPtr->keySize || \
		capabilityInfoPtr->maxKeySize < capabilityInfoPtr->keySize )
		return( FALSE );
	if( cryptAlgo >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
		cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL )
		{
		if( ( capabilityInfoPtr->blockSize < bitsToBytes( 8 ) || \
        	  capabilityInfoPtr->blockSize > CRYPT_MAX_IVSIZE ) || \
			( capabilityInfoPtr->minKeySize < bitsToBytes( 40 ) || \
			  capabilityInfoPtr->keySize < bitsToBytes( 40 ) || \
			  capabilityInfoPtr->keySize > CRYPT_MAX_KEYSIZE || \
			  capabilityInfoPtr->maxKeySize > CRYPT_MAX_KEYSIZE ) )
			return( FALSE );
		if( cryptAlgo != CRYPT_ALGO_RC4 && \
			( capabilityInfoPtr->initIVFunction == NULL || \
			  capabilityInfoPtr->blockSize < bitsToBytes( 64 ) ) )
			return( FALSE );
		if( capabilityInfoPtr->initKeyFunction == NULL )
			return( FALSE );
		if( ( capabilityInfoPtr->encryptCBCFunction != NULL && \
			  capabilityInfoPtr->decryptCBCFunction == NULL ) || \
			( capabilityInfoPtr->encryptCBCFunction == NULL && \
			  capabilityInfoPtr->decryptCBCFunction != NULL ) )
			return( FALSE );
		if( ( capabilityInfoPtr->encryptCFBFunction != NULL && \
			  capabilityInfoPtr->decryptCFBFunction == NULL ) || \
			( capabilityInfoPtr->encryptCFBFunction == NULL && \
			  capabilityInfoPtr->decryptCFBFunction != NULL ) )
			return( FALSE );
		if( ( capabilityInfoPtr->encryptOFBFunction != NULL && \
			  capabilityInfoPtr->decryptOFBFunction == NULL ) || \
			( capabilityInfoPtr->encryptOFBFunction == NULL && \
			  capabilityInfoPtr->decryptOFBFunction != NULL ) )
			return( FALSE );
		}
	if( cryptAlgo >= CRYPT_ALGO_FIRST_PKC && \
		cryptAlgo <= CRYPT_ALGO_LAST_PKC )
		{
		if( capabilityInfoPtr->blockSize || \
			( capabilityInfoPtr->minKeySize < bitsToBytes( 512 ) || \
			  capabilityInfoPtr->keySize < bitsToBytes( 512 ) || \
			  capabilityInfoPtr->keySize > CRYPT_MAX_PKCSIZE || \
			  capabilityInfoPtr->maxKeySize > CRYPT_MAX_PKCSIZE ) )
			return( FALSE );
		if( capabilityInfoPtr->initKeyFunction == NULL )
			return( FALSE );
		}
	if( cryptAlgo >= CRYPT_ALGO_FIRST_HASH && \
		cryptAlgo <= CRYPT_ALGO_LAST_HASH )
		{
		if( ( capabilityInfoPtr->blockSize < bitsToBytes( 64 ) || \
			  capabilityInfoPtr->blockSize > 256 ) || \
			( capabilityInfoPtr->minKeySize || capabilityInfoPtr->keySize || \
			  capabilityInfoPtr->maxKeySize ) )
			return( FALSE );
		}
	if( cryptAlgo >= CRYPT_ALGO_FIRST_MAC && \
		cryptAlgo <= CRYPT_ALGO_LAST_MAC )
		{
		if( ( capabilityInfoPtr->blockSize < bitsToBytes( 64 ) || \
			  capabilityInfoPtr->blockSize > 256 ) || \
			( capabilityInfoPtr->minKeySize < bitsToBytes( 40 ) || \
			  capabilityInfoPtr->keySize < bitsToBytes( 40 ) || \
			  capabilityInfoPtr->keySize > CRYPT_MAX_KEYSIZE || \
			  capabilityInfoPtr->maxKeySize > CRYPT_MAX_KEYSIZE ) )
			return( FALSE );
		if( capabilityInfoPtr->initKeyFunction == NULL )
			return( FALSE );
		}

	return( TRUE );
	}
#endif /* !NDEBUG */

/* Copy information from a capability record to a query record */

void copyCapabilityInfo( const CAPABILITY_INFO FAR_BSS *capabilityInfoPtr,
						 CRYPT_QUERY_INFO *cryptQueryInfo )
	{
	memset( cryptQueryInfo, 0, sizeof( CRYPT_QUERY_INFO ) );
	strcpy( cryptQueryInfo->algoName, capabilityInfoPtr->algoName );
	cryptQueryInfo->blockSize = capabilityInfoPtr->blockSize;
	cryptQueryInfo->minKeySize = capabilityInfoPtr->minKeySize;
	cryptQueryInfo->keySize = capabilityInfoPtr->keySize;
	cryptQueryInfo->maxKeySize = capabilityInfoPtr->maxKeySize;
	}

/* Find the capability record for a given encryption algorithm */

const CAPABILITY_INFO FAR_BSS *findCapabilityInfo( 
					const CAPABILITY_INFO FAR_BSS *capabilityInfoList,
					const CRYPT_ALGO cryptAlgo )
	{
	const CAPABILITY_INFO *capabilityInfoPtr;

	/* Find the capability corresponding to the requested algorithm/mode */
	for( capabilityInfoPtr = capabilityInfoList;
		 capabilityInfoPtr != NULL;
		 capabilityInfoPtr = capabilityInfoPtr->next )
		if( capabilityInfoPtr->cryptAlgo == cryptAlgo )
			return( capabilityInfoPtr );

	return( NULL );
	}

/* Load an IV, shared by most capabilities */

int loadIV( CRYPT_INFO *cryptInfoPtr, const void *iv, const int ivLength )
	{
	const int ivSize = ( ivLength == CRYPT_USE_DEFAULT ) ? \
					   cryptInfoPtr->capabilityInfo->blockSize : ivLength;

	/* Load the IV of the required length.  If the required IV size is less
	   than the maximum possible IV size, we pad it to the right with
	   zeroes */
	cryptInfoPtr->ctxConv.ivLength = ivSize;
	cryptInfoPtr->ctxConv.ivCount = 0;
	memset( cryptInfoPtr->ctxConv.iv, 0, CRYPT_MAX_IVSIZE );
	memcpy( cryptInfoPtr->ctxConv.iv, iv, ivSize );
	memcpy( cryptInfoPtr->ctxConv.currentIV, cryptInfoPtr->ctxConv.iv, 
			CRYPT_MAX_IVSIZE );
	cryptInfoPtr->ctxConv.ivSet = TRUE;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					Encryption Context Management Functions					*
*																			*
****************************************************************************/

/* Create a deep clone of a conventional encryption or hash/MAC context.  
   This code is used when it's necessary to create a local copy of a context 
   the caller has passed in */

static int contextMessageFunction( const CRYPT_CONTEXT cryptContext,
								   const RESOURCE_MESSAGE_TYPE message,
								   void *messageDataPtr,
								   const int messageValue );

static int cloneContext( CRYPT_CONTEXT *iDestContext,
						 const CRYPT_CONTEXT srcContext )
	{
	CRYPT_INFO *srcInfoPtr, *destInfoPtr;
	CONTEXT_TYPE contextType;
	void *keyPtr = NULL, *privateDataPtr = NULL;
	int status, actionFlags, subType;

	/* Get the action permissions for the source object */
	status = krnlSendMessage( srcContext, RESOURCE_IMESSAGE_GETATTRIBUTE,
							  &actionFlags, CRYPT_IATTRIBUTE_ACTIONPERMS );
	if( cryptStatusError( status ) )
		return( status );

	getCheckInternalResource( srcContext, srcInfoPtr, OBJECT_TYPE_CONTEXT );
	contextType = srcInfoPtr->type;
	assert( contextType == CONTEXT_CONV || \
			contextType == CONTEXT_HASH || \
			contextType == CONTEXT_MAC );
	subType = ( contextType == CONTEXT_CONV ) ? SUBTYPE_CTX_CONV : \
			  ( contextType == CONTEXT_HASH ) ? SUBTYPE_CTX_HASH : SUBTYPE_CTX_MAC;

	/* We need to preallocate all required memory so we can check for
	   allocation failures before we copy the source context because undoing
	   the shallow cloning of the context isn't easily possible */
	if( contextType == CONTEXT_CONV && srcInfoPtr->ctxConv.key != NULL )
		{
		const int size = krnlMemsize( srcInfoPtr->ctxConv.key );

		status = krnlMemalloc( &keyPtr, size );
		if( cryptStatusOK( status ) )
			memcpy( keyPtr, srcInfoPtr->ctxConv.key, size );
		}
	if( contextType == CONTEXT_HASH && srcInfoPtr->ctxHash.hashInfo != NULL )
		{
		const int size = krnlMemsize( srcInfoPtr->ctxHash.hashInfo );

		status = krnlMemalloc( &privateDataPtr, size );
		if( cryptStatusOK( status ) )
			memcpy( privateDataPtr, srcInfoPtr->ctxHash.hashInfo, size );
		}
	if( contextType == CONTEXT_MAC && srcInfoPtr->ctxMAC.macInfo != NULL )
		{
		const int size = krnlMemsize( srcInfoPtr->ctxMAC.macInfo );

		status = krnlMemalloc( &privateDataPtr, size );
		if( cryptStatusOK( status ) )
			memcpy( privateDataPtr, srcInfoPtr->ctxMAC.macInfo, size );
		}
	if( cryptStatusError( status ) )
		unlockResourceExit( srcInfoPtr, status );

	/* Create the encryption context object */
	status = krnlCreateObject( ( void ** ) &destInfoPtr, OBJECT_TYPE_CONTEXT, 
							   subType, sizeof( CRYPT_INFO ),
							   ( needsSecureMemory( srcInfoPtr->type ) ? \
								CREATEOBJECT_FLAG_SECUREMALLOC: 0 ),
							   actionFlags, contextMessageFunction );
	if( cryptStatusError( status ) )
		{
		/* Undo the previous mallocs and exit */
		if( keyPtr != NULL )
			krnlMemfree( keyPtr );
		if( privateDataPtr != NULL )
			krnlMemfree( privateDataPtr );
		unlockResourceExit( srcInfoPtr, status );
		}
	initResourceLock( destInfoPtr );
	lockResource( destInfoPtr );
	*iDestContext = destInfoPtr->objectHandle = status;

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
	if( contextType == CONTEXT_HASH )
		destInfoPtr->ctxHash.hashInfo = privateDataPtr;
	if( contextType == CONTEXT_MAC )
		destInfoPtr->ctxMAC.macInfo = privateDataPtr;

	unlockResource( srcInfoPtr );

	/* We've finished setting up the object-type-specific info, tell the 
	   kernel the object is ready for use and initialised */
	unlockResource( destInfoPtr );
	status = krnlSendMessage( *iDestContext, RESOURCE_IMESSAGE_SETATTRIBUTE, 
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusOK( status ) )
		{
		/* Since this is an internal-use-only object, lock down the action 
		   permissions so that only encryption and hash actions from internal
		   sources are allowed (assuming they were allowed to begin with).  
		   Keygen is disabled entirely (there should already be a key loaded), 
		   and signing isn't possible with a non-PKC object anyway */
		actionFlags = \
			MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_ENCRYPT, ACTION_PERM_NONE_EXTERNAL ) | \
			MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_DECRYPT, ACTION_PERM_NONE_EXTERNAL ) | \
			MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_HASH, ACTION_PERM_NONE_EXTERNAL );
		krnlSendMessage( *iDestContext, RESOURCE_IMESSAGE_SETATTRIBUTE,
						 &actionFlags, CRYPT_IATTRIBUTE_ACTIONPERMS );
		status = krnlSendMessage( *iDestContext, 
						RESOURCE_IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_UNUSED, 
						CRYPT_IATTRIBUTE_INITIALISED );
		if( cryptStatusError( status ) )
			krnlSendNotifier( *iDestContext, RESOURCE_IMESSAGE_DESTROY );
		}
	if( cryptStatusError( status ) )
		{
		*iDestContext = CRYPT_ERROR;
		return( status );
		}

	return( CRYPT_OK );
	}

/* Checks that a context meets the given requirements */

static int checkContext( CRYPT_INFO *cryptInfoPtr,
						 const RESOURCE_MESSAGE_CHECK_TYPE checkType )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = cryptInfoPtr->capabilityInfo;
	const CRYPT_ALGO cryptAlgo = capabilityInfoPtr->cryptAlgo;

	/* If it's a check for a key generation capability (which is algorithm-
	   type independent), we check it before performing any algorithm-
	   specific checks */
	if( checkType == RESOURCE_MESSAGE_CHECK_KEYGEN )
		{
		if( cryptInfoPtr->type == CONTEXT_HASH )
			return( CRYPT_ERROR_NOTAVAIL );	/* No key for hash algorithms */
		if( !needsKey( cryptInfoPtr ) )
			{
			setErrorInfo( cryptInfoPtr, CRYPT_CTXINFO_KEY, 
						  CRYPT_ERRTYPE_ATTR_PRESENT );
			return( CRYPT_ERROR_INITED );
			}
		return( ( capabilityInfoPtr->generateKeyFunction != NULL ) ? \
				CRYPT_OK : CRYPT_ARGERROR_OBJECT );
		}

	/* Perform general checks */
	if( needsKey( cryptInfoPtr ) )
		{
		setErrorInfo( cryptInfoPtr, CRYPT_CTXINFO_KEY, 
					  CRYPT_ERRTYPE_ATTR_ABSENT );
		return( CRYPT_ERROR_NOTINITED );
		}

	/* Check for hash, MAC, and conventional encryption contexts */
	if( checkType == RESOURCE_MESSAGE_CHECK_HASH )
		return( ( cryptInfoPtr->type == CONTEXT_HASH ) ? \
				CRYPT_OK : CRYPT_ARGERROR_OBJECT );
	if( checkType == RESOURCE_MESSAGE_CHECK_MAC )
		return( ( cryptInfoPtr->type == CONTEXT_MAC ) ? \
				CRYPT_OK : CRYPT_ARGERROR_OBJECT );
	if( checkType == RESOURCE_MESSAGE_CHECK_CRYPT )
		return( ( cryptInfoPtr->type != CONTEXT_CONV ) ? \
				CRYPT_ARGERROR_OBJECT : CRYPT_OK );

	/* Make sure it's a PKC context */
	if( cryptInfoPtr->type != CONTEXT_PKC )
		return( CRYPT_ARGERROR_OBJECT );
	if( checkType == RESOURCE_MESSAGE_CHECK_PKC ) 
		return( CRYPT_OK );

	/* Check for key-agreement algorithms */
	if( cryptAlgo == CRYPT_ALGO_DH || cryptAlgo == CRYPT_ALGO_KEA )
		/* DH can never be used for encryption or signatures (if it is then
		   we call it Elgamal) and KEA is explicitly for key agreement only */
		return( ( checkType == RESOURCE_MESSAGE_CHECK_PKC_KA_EXPORT || \
				  checkType == RESOURCE_MESSAGE_CHECK_PKC_KA_IMPORT ) ? \
				CRYPT_OK : CRYPT_ARGERROR_OBJECT );
	if( ( checkType == RESOURCE_MESSAGE_CHECK_PKC_KA_EXPORT || \
		  checkType == RESOURCE_MESSAGE_CHECK_PKC_KA_IMPORT ) )
		return( CRYPT_ARGERROR_OBJECT );	/* Must be a key agreement algorithm */

	/* Check that the algorithm complies and the capability is available */
	if( ( checkType == RESOURCE_MESSAGE_CHECK_PKC_ENCRYPT || \
		  checkType == RESOURCE_MESSAGE_CHECK_PKC_DECRYPT ) && \
		cryptAlgo == CRYPT_ALGO_DSA )
		return( CRYPT_ARGERROR_OBJECT );	/* Must be an encryption algorithm */
	if( ( checkType == RESOURCE_MESSAGE_CHECK_PKC_ENCRYPT && \
		  capabilityInfoPtr->encryptFunction == NULL ) || \
		( checkType == RESOURCE_MESSAGE_CHECK_PKC_DECRYPT && \
		  capabilityInfoPtr->decryptFunction == NULL ) || \
		( checkType == RESOURCE_MESSAGE_CHECK_PKC_SIGN && \
		  capabilityInfoPtr->signFunction == NULL ) || \
		( checkType == RESOURCE_MESSAGE_CHECK_PKC_SIGCHECK && \
		  capabilityInfoPtr->sigCheckFunction == NULL ) )
		return( CRYPT_ARGERROR_OBJECT );	/* Capability not supported */

	/* Check that it's a private key if this is required */
	if( ( checkType == RESOURCE_MESSAGE_CHECK_PKC_PRIVATE || \
		  checkType == RESOURCE_MESSAGE_CHECK_PKC_DECRYPT || \
		  checkType == RESOURCE_MESSAGE_CHECK_PKC_SIGN ) && \
		cryptInfoPtr->ctxPKC.isPublicKey )
		return( CRYPT_ARGERROR_OBJECT );

	return( CRYPT_OK );
	}

/* Handle data sent to or read from a context */

static int exitNotInited( CRYPT_INFO *cryptInfoPtr, 
						  const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	setErrorInfo( cryptInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_ABSENT );
	return( CRYPT_ERROR_NOTINITED );
	}

static int processContextData( CRYPT_INFO *cryptInfoPtr,
							   const RESOURCE_MESSAGE_TYPE message,
							   void *messageDataPtr,
							   const int messageValue )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = cryptInfoPtr->capabilityInfo;
	const CONTEXT_TYPE contextType = cryptInfoPtr->type;
	RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
	int *valuePtr = ( int * ) messageDataPtr;

	/* Process get/set/delete attribute messages */
	if( message == RESOURCE_MESSAGE_GETATTRIBUTE )
		{
		int value;

		switch( messageValue )
			{
			case CRYPT_ATTRIBUTE_ERRORTYPE:
				*valuePtr = cryptInfoPtr->errorType;
				return( CRYPT_OK );

			case CRYPT_ATTRIBUTE_ERRORLOCUS:
				*valuePtr = cryptInfoPtr->errorLocus;
				return( CRYPT_OK );

			case CRYPT_CTXINFO_ALGO:
				*valuePtr = capabilityInfoPtr->cryptAlgo;
				return( CRYPT_OK );

			case CRYPT_CTXINFO_MODE:
				assert( contextType == CONTEXT_CONV );
				*valuePtr = cryptInfoPtr->ctxConv.mode;
				return( CRYPT_OK );

			case CRYPT_CTXINFO_KEYSIZE:
				assert( contextType == CONTEXT_CONV || \
						contextType == CONTEXT_PKC || \
						contextType == CONTEXT_MAC );
				if( contextType == CONTEXT_CONV )
					value = cryptInfoPtr->ctxConv.userKeyLength;
				else
					if( contextType == CONTEXT_MAC )
						value = cryptInfoPtr->ctxMAC.userKeyLength;
					else
						value = bitsToBytes( cryptInfoPtr->ctxPKC.keySizeBits );
				if( !value )
					/* If a key hasn't been loaded yet, we return the default
					   key size */
					value = cryptInfoPtr->capabilityInfo->keySize;
				*valuePtr = value;
				return( CRYPT_OK );
			
			case CRYPT_CTXINFO_BLOCKSIZE:
				if( contextType == CONTEXT_CONV && \
					( cryptInfoPtr->ctxConv.mode == CRYPT_MODE_CFB || \
					  cryptInfoPtr->ctxConv.mode == CRYPT_MODE_OFB ) )
					*valuePtr = 1;	/* Block cipher in stream mode */
				else
					*valuePtr = capabilityInfoPtr->blockSize;
				return( CRYPT_OK );

			case CRYPT_CTXINFO_IVSIZE:
				assert( contextType == CONTEXT_CONV );
				if( !needsIV( cryptInfoPtr->ctxConv.mode ) || \
					cryptInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RC4 )
					return( CRYPT_ERROR_NOTAVAIL );
				*valuePtr = capabilityInfoPtr->blockSize;
				return( CRYPT_OK );

			case CRYPT_CTXINFO_KEYING_ALGO:
				assert( contextType == CONTEXT_CONV || \
						contextType == CONTEXT_MAC );
				if( contextType == CONTEXT_CONV )
					value = cryptInfoPtr->ctxConv.keySetupAlgorithm;
				else
					value = cryptInfoPtr->ctxMAC.keySetupAlgorithm;
				if( !value )
					return( exitNotInited( cryptInfoPtr, 
							CRYPT_CTXINFO_KEYING_ALGO ) );
				*valuePtr = value;
				return( CRYPT_OK );

			case CRYPT_CTXINFO_KEYING_ITERATIONS:
				assert( contextType == CONTEXT_CONV || \
						contextType == CONTEXT_MAC );
				if( contextType == CONTEXT_CONV )
					value = cryptInfoPtr->ctxConv.keySetupIterations;
				else
					value = cryptInfoPtr->ctxMAC.keySetupIterations;
				if( !value )
					return( exitNotInited( cryptInfoPtr, 
							CRYPT_CTXINFO_KEYING_ITERATIONS ) );
				*valuePtr = value;
				return( CRYPT_OK );

			case CRYPT_IATTRIBUTE_DEVICEOBJECT:
				*valuePtr = ( int ) cryptInfoPtr->deviceObject;
				return( CRYPT_OK );
			}

		assert( NOTREACHED );
		}
	if( message == RESOURCE_MESSAGE_GETATTRIBUTE_S )
		{
		STREAM stream;
		int status;

		switch( messageValue )
			{
			case CRYPT_CTXINFO_NAME_ALGO:
				return( attributeCopy( msgData, capabilityInfoPtr->algoName,
									   strlen( capabilityInfoPtr->algoName ) ) );

			case CRYPT_CTXINFO_NAME_MODE:
				assert( contextType == CONTEXT_CONV );
				switch( cryptInfoPtr->ctxConv.mode )
					{
					case CRYPT_MODE_ECB:
						return( attributeCopy( msgData, "ECB", 3 ) );
					case CRYPT_MODE_CBC:
						return( attributeCopy( msgData, "CBC", 3 ) );
					case CRYPT_MODE_CFB:
						return( attributeCopy( msgData, "CFB", 3 ) );
					case CRYPT_MODE_OFB:
						return( attributeCopy( msgData, "OFB", 3 ) );
					}
				assert( NOTREACHED );

			case CRYPT_CTXINFO_KEYING_SALT:
				assert( contextType == CONTEXT_CONV || \
						contextType == CONTEXT_MAC );
				if( contextType == CONTEXT_CONV )
					{
					if( !cryptInfoPtr->ctxConv.saltLength )
						return( exitNotInited( cryptInfoPtr, 
								CRYPT_CTXINFO_KEYING_SALT ) );
					return( attributeCopy( msgData, cryptInfoPtr->ctxConv.salt, 
										   cryptInfoPtr->ctxConv.saltLength ) );
					}
				if( !cryptInfoPtr->ctxMAC.saltLength )
					return( exitNotInited( cryptInfoPtr, 
							CRYPT_CTXINFO_KEYING_SALT ) );
				return( attributeCopy( msgData, cryptInfoPtr->ctxMAC.salt, 
									   cryptInfoPtr->ctxMAC.saltLength ) );

			case CRYPT_CTXINFO_IV:
				assert( contextType == CONTEXT_CONV );
				if( !needsIV( cryptInfoPtr->ctxConv.mode ) || \
					cryptInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RC4 )
					return( CRYPT_ERROR_NOTAVAIL );
				if( !cryptInfoPtr->ctxConv.ivSet )
					return( exitNotInited( cryptInfoPtr, CRYPT_CTXINFO_IV ) );
				return( attributeCopy( msgData, cryptInfoPtr->ctxConv.iv, 
									   cryptInfoPtr->ctxConv.ivLength ) );

			case CRYPT_CTXINFO_HASHVALUE:
				assert( contextType == CONTEXT_HASH || \
						contextType == CONTEXT_MAC );
				if( contextType == CONTEXT_HASH )
					{
					if( !cryptInfoPtr->ctxHash.done )
						return( CRYPT_ERROR_INCOMPLETE );
					return( attributeCopy( msgData, cryptInfoPtr->ctxHash.hash, 
										   capabilityInfoPtr->blockSize ) );
					}
				if( !cryptInfoPtr->ctxMAC.done )
					return( CRYPT_ERROR_INCOMPLETE );
				return( attributeCopy( msgData, cryptInfoPtr->ctxMAC.mac,
									   capabilityInfoPtr->blockSize ) );

			case CRYPT_CTXINFO_LABEL:
				if( !cryptInfoPtr->labelSize )
					return( exitNotInited( cryptInfoPtr, CRYPT_CTXINFO_LABEL ) );
				return( attributeCopy( msgData, cryptInfoPtr->label,
									   cryptInfoPtr->labelSize ) );
			
			case CRYPT_IATTRIBUTE_KEYID:
				assert( contextType == CONTEXT_PKC );
				return( attributeCopy( msgData, cryptInfoPtr->ctxPKC.keyID, 
									   KEYID_SIZE ) );

			case CRYPT_IATTRIBUTE_DOMAINPARAMS:
				assert( contextType == CONTEXT_PKC );
				return( attributeCopy( msgData, cryptInfoPtr->ctxPKC.domainParamPtr, 
									   cryptInfoPtr->ctxPKC.domainParamSize ) );

			case CRYPT_IATTRIBUTE_PUBLICVALUE:
				assert( contextType == CONTEXT_PKC );
				return( attributeCopy( msgData, cryptInfoPtr->ctxPKC.publicValuePtr, 
									   cryptInfoPtr->ctxPKC.publicValueSize ) );

			case CRYPT_IATTRIBUTE_PUBLICKEY:
				assert( contextType == CONTEXT_PKC );
				assert( cryptInfoPtr->ctxPKC.keySet );
				if( cryptInfoPtr->ctxPKC.publicKeyInfo != NULL )
					/* If the data is available in pre-encoded form, copy it 
					   out */
					return( attributeCopy( msgData, cryptInfoPtr->ctxPKC.publicKeyInfo,
										   cryptInfoPtr->ctxPKC.publicKeyInfoSize ) );

				/* Write the public key info to the message buffer */
				sMemOpen( &stream, msgData->data, msgData->length );
				status = writePublicKey( &stream, cryptInfoPtr );
				if( cryptStatusOK( status ) )
					msgData->length = stell( &stream );
				sMemDisconnect( &stream );
				return( status );
			}

		assert( NOTREACHED );
		}
	if( message == RESOURCE_MESSAGE_SETATTRIBUTE )
		{
		int ( *cryptFunction )( CRYPT_INFO *cryptInfoPtr, void *buffer, 
								int length ) = NULL;

		switch( messageValue )
			{
			case CRYPT_CTXINFO_MODE:
				assert( contextType == CONTEXT_CONV );
				switch( *valuePtr )
					{
					case CRYPT_MODE_ECB:
						cryptFunction = capabilityInfoPtr->encryptFunction;
						break;
					case CRYPT_MODE_CBC:
						cryptFunction = capabilityInfoPtr->encryptCBCFunction;
						break;
					case CRYPT_MODE_CFB:
						cryptFunction = capabilityInfoPtr->encryptCFBFunction;
						break;
					case CRYPT_MODE_OFB:
						cryptFunction = capabilityInfoPtr->encryptOFBFunction;
						break;
					default:
						assert( NOTREACHED );
					}
				if( cryptFunction == NULL )
					return( CRYPT_ERROR_NOTAVAIL );
				cryptInfoPtr->ctxConv.mode = *valuePtr;
				return( CRYPT_OK );

			case CRYPT_CTXINFO_KEYING_ALGO:
				assert( contextType == CONTEXT_CONV || \
						contextType == CONTEXT_MAC );
				if( contextType == CONTEXT_CONV )
					cryptInfoPtr->ctxConv.keySetupAlgorithm = *valuePtr;
				else
					cryptInfoPtr->ctxMAC.keySetupAlgorithm = *valuePtr;
				return( CRYPT_OK );

			case CRYPT_CTXINFO_KEYING_ITERATIONS:
				assert( contextType == CONTEXT_CONV || \
						contextType == CONTEXT_MAC );
				if( contextType == CONTEXT_CONV )
					cryptInfoPtr->ctxConv.keySetupIterations = *valuePtr;
				else
					cryptInfoPtr->ctxMAC.keySetupIterations = *valuePtr;
				return( CRYPT_OK );

			case CRYPT_IATTRIBUTE_INITIALISED:
				return( CRYPT_OK );

			case CRYPT_IATTRIBUTE_KEYSIZE:
				if( contextType == CONTEXT_CONV )	
					{
					cryptInfoPtr->ctxConv.keySet = TRUE;
					cryptInfoPtr->ctxConv.keyLength = *valuePtr;
					return( CRYPT_OK );
					}
				if( contextType == CONTEXT_PKC )
					{
					if( !cryptInfoPtr->labelSize )
						/* PKC context must have a key label set */
						return( exitNotInited( cryptInfoPtr, 
								CRYPT_CTXINFO_LABEL ) );
					cryptInfoPtr->ctxPKC.keySet = TRUE;
					cryptInfoPtr->ctxPKC.keySizeBits = bytesToBits( *valuePtr );
					return( CRYPT_OK );
					}
				if( contextType == CONTEXT_MAC )
					{
					cryptInfoPtr->ctxMAC.keySet = TRUE;
					cryptInfoPtr->ctxMAC.userKeyLength = *valuePtr;
					return( CRYPT_OK );
					}
				assert( NOTREACHED );

			case CRYPT_IATTRIBUTE_DEVICEOBJECT:
				cryptInfoPtr->deviceObject = *valuePtr;
				return( CRYPT_OK );
			}

		assert( NOTREACHED );
		}
	if( message == RESOURCE_MESSAGE_SETATTRIBUTE_S )
		{
		MECHANISM_DERIVE_INFO mechanismInfo;
		STREAM stream;
		int status;

		switch( messageValue )
			{
			case CRYPT_CTXINFO_KEYING_SALT:
				assert( contextType == CONTEXT_CONV || \
						contextType == CONTEXT_MAC );
				if( contextType == CONTEXT_CONV )
					{
					if( cryptInfoPtr->ctxConv.saltLength )
						{
						setErrorInfo( cryptInfoPtr, CRYPT_CTXINFO_KEYING_SALT,
									  CRYPT_ERRTYPE_ATTR_PRESENT );
						return( CRYPT_ERROR_INITED );
						}
					memcpy( cryptInfoPtr->ctxConv.salt, msgData->data, 
							msgData->length );
					cryptInfoPtr->ctxConv.saltLength = msgData->length;
					return( CRYPT_OK );
					}
				if( cryptInfoPtr->ctxMAC.saltLength )
					{
					setErrorInfo( cryptInfoPtr, CRYPT_CTXINFO_KEYING_SALT,
								  CRYPT_ERRTYPE_ATTR_PRESENT );
					return( CRYPT_ERROR_INITED );
					}
				memcpy( cryptInfoPtr->ctxMAC.salt, msgData->data, 
						msgData->length );
				cryptInfoPtr->ctxMAC.saltLength = msgData->length;
				return( CRYPT_OK );

			case CRYPT_CTXINFO_KEYING_VALUE:
				assert( contextType == CONTEXT_CONV || \
						contextType == CONTEXT_MAC );
				assert( needsKey( cryptInfoPtr ) );

				/* Set up various parameters if they're not already set */
				if( contextType == CONTEXT_CONV )
					{
					setMechanismDeriveInfo( &mechanismInfo, 
						cryptInfoPtr->ctxConv.userKey, 
							getOptimalKeysize( cryptInfoPtr, CRYPT_USE_DEFAULT ),
						msgData->data, msgData->length, 
						cryptInfoPtr->ctxConv.salt, cryptInfoPtr->ctxConv.saltLength,
						cryptInfoPtr->ctxConv.keySetupIterations );
					cryptInfoPtr->ctxConv.keySetupAlgorithm = CRYPT_ALGO_HMAC_SHA;
					}
				else
					{
					setMechanismDeriveInfo( &mechanismInfo, 
						cryptInfoPtr->ctxMAC.userKey, 
							getOptimalKeysize( cryptInfoPtr, CRYPT_USE_DEFAULT ),
						msgData->data, msgData->length, 
						cryptInfoPtr->ctxMAC.salt, cryptInfoPtr->ctxMAC.saltLength,
						cryptInfoPtr->ctxMAC.keySetupIterations );
					cryptInfoPtr->ctxMAC.keySetupAlgorithm = CRYPT_ALGO_HMAC_SHA;
					}
				if( !mechanismInfo.iterations )
					{
					krnlSendMessage( CRYPT_UNUSED, 
						RESOURCE_IMESSAGE_GETATTRIBUTE, &mechanismInfo.iterations, 
						CRYPT_OPTION_KEYING_ITERATIONS );
					if( contextType == CONTEXT_CONV )
						cryptInfoPtr->ctxConv.keySetupIterations = \
												mechanismInfo.iterations;
					else
						cryptInfoPtr->ctxMAC.keySetupIterations = \
												mechanismInfo.iterations;
					}
				if( !mechanismInfo.saltLength )
					{
					getNonce( mechanismInfo.salt, PKCS5_SALT_SIZE );
					if( contextType == CONTEXT_CONV )
						cryptInfoPtr->ctxConv.saltLength = PKCS5_SALT_SIZE;
					else
						cryptInfoPtr->ctxMAC.saltLength = PKCS5_SALT_SIZE;
					mechanismInfo.saltLength = PKCS5_SALT_SIZE;
					}

				/* Turn the user key into an encryption context key */
				status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
										  RESOURCE_IMESSAGE_DEV_DERIVE,
										  &mechanismInfo, MECHANISM_PKCS5 );
				if( cryptStatusError( status ) )
					return( status );

				/* Load the key into the context */
				return( loadKey( cryptInfoPtr, mechanismInfo.dataOut, 
								 mechanismInfo.dataOutLength ) );

			case CRYPT_CTXINFO_KEY:
				assert( contextType == CONTEXT_CONV || \
						contextType == CONTEXT_MAC );
				assert( needsKey( cryptInfoPtr ) );

				/* The kernel performs a general check on the size of this 
				   attribute but doesn't know about context-subtype-specific 
				   limits so we perform a context-specific check here */
				if( msgData->length < capabilityInfoPtr->minKeySize || \
					msgData->length > capabilityInfoPtr->maxKeySize )
					return( CRYPT_ARGERROR_NUM1 );

				/* Load the key into the context */
				return( loadKey( cryptInfoPtr, msgData->data, 
								 msgData->length ) );

			case CRYPT_CTXINFO_KEY_COMPONENTS:
				assert( contextType == CONTEXT_PKC );
				assert( needsKey( cryptInfoPtr ) );

				/* Make sure the supplied key data is valid */
				if( msgData->length != sizeof( CRYPT_PKCINFO_RSA ) && \
					msgData->length != sizeof( CRYPT_PKCINFO_DLP ) && \
					msgData->length != sizeof( PKCINFO_LOADINTERNAL ) )
					return( CRYPT_ARGERROR_NUM1 );

				/* We need to have a key label set before we can continue, 
				   however if we're creating a public-key context through an 
				   internal read (for example as part of importing a cert) 
				   there won't be one available so we don't require a label 
				   for internal loads of public keys */
				if( !cryptInfoPtr->labelSize && \
					( msgData->length != sizeof( PKCINFO_LOADINTERNAL ) || \
					  !cryptInfoPtr->ctxPKC.isPublicKey ) )
					return( exitNotInited( cryptInfoPtr, 
										   CRYPT_CTXINFO_LABEL ) );

				/* Load the key into the context */
				return( loadKey( cryptInfoPtr, msgData->data, 
								 msgData->length ) );

			case CRYPT_CTXINFO_IV:
				assert( contextType == CONTEXT_CONV );

				/* If it's a mode which doesn't use an IV, the load IV 
				   operation is meaningless */
				if( !needsIV( cryptInfoPtr->ctxConv.mode ) || \
					cryptInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RC4 )
					return( CRYPT_ERROR_NOTAVAIL );

				/* Make sure the data size is valid */
				if( msgData->length != capabilityInfoPtr->blockSize )
					return( CRYPT_ARGERROR_NUM1 );

				/* Load the IV */
				assert( capabilityInfoPtr->initIVFunction != NULL );
				capabilityInfoPtr->initIVFunction( cryptInfoPtr, 
										msgData->data, msgData->length );
				return( CRYPT_OK );

			case CRYPT_CTXINFO_LABEL:
				if( cryptInfoPtr->labelSize )
					{
					setErrorInfo( cryptInfoPtr, CRYPT_CTXINFO_LABEL,
								  CRYPT_ERRTYPE_ATTR_PRESENT );
					return( CRYPT_ERROR_INITED );
					}

				/* Check any container object the context is associated with
				   to make sure nothing with that label already exists in the 
				   container.  Since the label can be set before the key is
				   loaded (determining the type of the object), we check for 
				   both public and private key objects.  In addition, we 
				   can't send the message to the context because the kernel 
				   won't forward this message type (sending a get-key message 
				   to a context doesn't make sense) so we have to explicitly 
				   get the dependent device and send the get-key directly to 
				   it */
				if( contextType == CONTEXT_PKC )
					{
					CRYPT_HANDLE cryptHandle;

					status = krnlSendMessage( cryptInfoPtr->objectHandle, 
											  RESOURCE_IMESSAGE_GETDEPENDENT,
											  &cryptHandle, OBJECT_TYPE_DEVICE );
					if( cryptStatusOK( status ) )
						{
						MESSAGE_KEYMGMT_INFO getkeyInfo;

						setMessageKeymgmtInfo( &getkeyInfo, CRYPT_KEYID_NAME,
							msgData->data, msgData->length, NULL, 0,
							KEYMGMT_FLAG_CHECK_ONLY | KEYMGMT_FLAG_PUBLICKEY );
						status = krnlSendMessage( cryptInfoPtr->objectHandle, 
							RESOURCE_MESSAGE_KEY_GETKEY, &getkeyInfo, 0 );
						if( cryptStatusError( status ) )
							{
							getkeyInfo.flags = \
								KEYMGMT_FLAG_CHECK_ONLY | KEYMGMT_FLAG_PRIVATEKEY;
							status = krnlSendMessage( cryptInfoPtr->objectHandle, 
								RESOURCE_MESSAGE_KEY_GETKEY, &getkeyInfo, 0 );
							}
						if( cryptStatusOK( status ) )
							/* We found something with this label, we can't 
							   use it again */
							return( CRYPT_ERROR_DUPLICATE );
						}
					}

				/* Set the label */
				memcpy( cryptInfoPtr->label, msgData->data, msgData->length );
				cryptInfoPtr->labelSize = msgData->length;
				return( CRYPT_OK );

			case CRYPT_IATTRIBUTE_PUBLICKEY:
				assert( contextType == CONTEXT_PKC );

				/* Copy the data in and set up any other information we may 
				   need from it */
				if( ( cryptInfoPtr->ctxPKC.publicKeyInfo = \
										malloc( msgData->length ) ) == NULL )
					return( CRYPT_ERROR_MEMORY );
				memcpy( cryptInfoPtr->ctxPKC.publicKeyInfo, msgData->data, 
						msgData->length );
				cryptInfoPtr->ctxPKC.publicKeyInfoSize = msgData->length;
				calculateKeyID( cryptInfoPtr );
				return( CRYPT_OK );

			case CRYPT_IATTRIBUTE_SSH_PUBLICKEY:
				assert( contextType == CONTEXT_PKC );

				/* Read the SSH-format key data directly into the context */
				sMemConnect( &stream, msgData->data, msgData->length );
				status = readSshPublicKey( &stream, cryptInfoPtr );
				sMemDisconnect( &stream );
				return( status );
			}

		assert( NOTREACHED );
		}
	if( message == RESOURCE_MESSAGE_DELETEATTRIBUTE )
		{
		switch( messageValue )
			{
			case CRYPT_CTXINFO_KEYING_ALGO:
				assert( contextType == CONTEXT_CONV || \
						contextType == CONTEXT_MAC );
				if( contextType == CONTEXT_CONV )
					{
					if( !cryptInfoPtr->ctxConv.keySetupAlgorithm )
						return( CRYPT_ERROR_NOTFOUND );
					cryptInfoPtr->ctxConv.keySetupAlgorithm = CRYPT_ALGO_NONE;
					return( CRYPT_OK );
					}
				if( !cryptInfoPtr->ctxMAC.keySetupAlgorithm )
					return( CRYPT_ERROR_NOTFOUND );
				cryptInfoPtr->ctxMAC.keySetupAlgorithm = CRYPT_ALGO_NONE;
				return( CRYPT_OK );

			case CRYPT_CTXINFO_KEYING_ITERATIONS:
				assert( contextType == CONTEXT_CONV || \
						contextType == CONTEXT_MAC );
				if( contextType == CONTEXT_CONV )
					{
					if( !cryptInfoPtr->ctxConv.keySetupIterations )
						return( CRYPT_ERROR_NOTFOUND );
					cryptInfoPtr->ctxConv.keySetupIterations = 0;
					return( CRYPT_OK );
					}
				if( !cryptInfoPtr->ctxMAC.keySetupIterations )
					return( CRYPT_ERROR_NOTFOUND );
				cryptInfoPtr->ctxMAC.keySetupIterations = 0;
				return( CRYPT_OK );

			case CRYPT_CTXINFO_KEYING_SALT:
				assert( contextType == CONTEXT_CONV || \
						contextType == CONTEXT_MAC );
				if( contextType == CONTEXT_CONV )
					{
					if( !cryptInfoPtr->ctxConv.saltLength )
						return( CRYPT_ERROR_NOTFOUND );
					zeroise( cryptInfoPtr->ctxConv.salt, CRYPT_MAX_HASHSIZE );
					cryptInfoPtr->ctxConv.saltLength = 0;
					return( CRYPT_OK );
					}
				if( !cryptInfoPtr->ctxMAC.saltLength )
					return( CRYPT_ERROR_NOTFOUND );
				zeroise( cryptInfoPtr->ctxMAC.salt, CRYPT_MAX_HASHSIZE );
				cryptInfoPtr->ctxMAC.saltLength = 0;
				return( CRYPT_OK );

			case CRYPT_CTXINFO_LABEL:
				if( !cryptInfoPtr->labelSize )
					return( CRYPT_ERROR_NOTFOUND );
				zeroise( cryptInfoPtr->label, cryptInfoPtr->labelSize );
				cryptInfoPtr->labelSize = 0;
				return( CRYPT_OK );

			case CRYPT_CTXINFO_HASHVALUE:
				assert( contextType == CONTEXT_HASH || \
						contextType == CONTEXT_MAC );
				if( contextType == CONTEXT_HASH )
					{
					cryptInfoPtr->capabilityInfo->initFunction( cryptInfoPtr );
					zeroise( cryptInfoPtr->ctxHash.hash, CRYPT_MAX_HASHSIZE );
					cryptInfoPtr->ctxHash.done = FALSE;
					return( CRYPT_OK );
					}
				cryptInfoPtr->capabilityInfo->initFunction( cryptInfoPtr );
				zeroise( cryptInfoPtr->ctxMAC.mac, CRYPT_MAX_HASHSIZE );
				cryptInfoPtr->ctxMAC.done = FALSE;
				return( CRYPT_OK );
			}

		assert( NOTREACHED );
		}

	assert( NOTREACHED );
	return( 0 );	/* Get rid of compiler warning */
	}

/* Handle a message sent to an encryption context */

static int contextMessageFunction( const CRYPT_CONTEXT cryptContext,
								   const RESOURCE_MESSAGE_TYPE message,
								   void *messageDataPtr,
								   const int messageValue )
	{
	CRYPT_INFO *cryptInfoPtr;
	int status = CRYPT_ERROR;

	getCheckInternalResource( cryptContext, cryptInfoPtr, OBJECT_TYPE_CONTEXT );

	/* Process destroy object messages */
	if( message == RESOURCE_MESSAGE_DESTROY )
		{
		const CONTEXT_TYPE contextType = cryptInfoPtr->type;

		/* If the context is busy, abort the async.operation.  We do this by
		   setting the abort flag (which is OK, since the context is about to
		   be destroyed anyway) and then waiting for the busy flag to be
		   cleared */
		cryptInfoPtr->doAbort = TRUE;
		krnlSendMessage( cryptContext, RESOURCE_IMESSAGE_GETATTRIBUTE,
						 &status, CRYPT_IATTRIBUTE_STATUS );
		if( status & OBJECT_FLAG_BUSY )
			{
			/* Unlock the object so the background thread can access it.
			   Nothing else will get in because the object is in the 
			   signalled state */
			unlockResource( cryptInfoPtr );

			/* Wait awhile and check whether we've left the busy state */
			do
				{
#ifdef __WIN32__
				Sleep( 250 );	/* Wait 1/4s */
#endif /* __WIN32__ */
				krnlSendMessage( cryptContext, RESOURCE_IMESSAGE_GETATTRIBUTE,
								 &status, CRYPT_IATTRIBUTE_STATUS );
				}
			while( status & OBJECT_FLAG_BUSY );

			getCheckInternalResource( cryptContext, cryptInfoPtr, OBJECT_TYPE_CONTEXT );
			}

		/* Perform any algorithm-specific shutdown */
		if( cryptInfoPtr->capabilityInfo != NULL && \
			cryptInfoPtr->keyingInfoInited && \
			cryptInfoPtr->capabilityInfo->endFunction != NULL )
			cryptInfoPtr->capabilityInfo->endFunction( cryptInfoPtr );

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
			}

		/* Zeroise the context-type-specific information */
		cryptInfoPtr->capabilityInfo = NULL;
		cryptInfoPtr->type = CONTEXT_NONE;
		zeroise( &cryptInfoPtr->keyingInfo, sizeof( cryptInfoPtr->keyingInfo ) );
		cryptInfoPtr->keyingInfoInited = FALSE;

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

	/* Process attribute get/set/delete messages */
	if( isAttributeMessage( message ) )
		{
		status = processContextData( cryptInfoPtr, message,
									 messageDataPtr, messageValue );
		unlockResourceExit( cryptInfoPtr, status );
		}

	/* Process action messages */
	if( isActionMessage( message ) )
		{
		const CAPABILITY_INFO *capabilityInfoPtr = cryptInfoPtr->capabilityInfo;
		int ( *cryptFunction )( CRYPT_INFO *cryptInfoPtr, void *buffer, int length );

		switch( message )
			{
			case RESOURCE_MESSAGE_CTX_ENCRYPT:
				if( cryptInfoPtr->type == CONTEXT_CONV )
					switch( cryptInfoPtr->ctxConv.mode )
						{
						case CRYPT_MODE_ECB:
							assert( !( messageValue % capabilityInfoPtr->blockSize ) );
							cryptFunction = capabilityInfoPtr->encryptFunction;
							break;
						case CRYPT_MODE_CBC:
							assert( !( messageValue % capabilityInfoPtr->blockSize ) );
							cryptFunction = capabilityInfoPtr->encryptCBCFunction;
							break;
						case CRYPT_MODE_CFB:
							cryptFunction = capabilityInfoPtr->encryptCFBFunction;
							break;
						case CRYPT_MODE_OFB:
							cryptFunction = capabilityInfoPtr->encryptOFBFunction;
							break;
						default:
							assert( NOTREACHED );
						}
				else
					cryptFunction = capabilityInfoPtr->encryptFunction;
				assert( cryptFunction != NULL );
				status = cryptFunction( cryptInfoPtr, messageDataPtr, 
										messageValue );
				break;

			case RESOURCE_MESSAGE_CTX_DECRYPT:
				if( cryptInfoPtr->type == CONTEXT_CONV )
					switch( cryptInfoPtr->ctxConv.mode )
						{
						case CRYPT_MODE_ECB:
							assert( !( messageValue % capabilityInfoPtr->blockSize ) );
							cryptFunction = capabilityInfoPtr->decryptFunction;
							break;
						case CRYPT_MODE_CBC:
							assert( !( messageValue % capabilityInfoPtr->blockSize ) );
							cryptFunction = capabilityInfoPtr->decryptCBCFunction;
							break;
						case CRYPT_MODE_CFB:
							cryptFunction = capabilityInfoPtr->decryptCFBFunction;
							break;
						case CRYPT_MODE_OFB:
							cryptFunction = capabilityInfoPtr->decryptOFBFunction;
							break;
						default:
							assert( NOTREACHED );
						}
				else
					cryptFunction = capabilityInfoPtr->decryptFunction;
				assert( cryptFunction != NULL );
				status = cryptFunction( cryptInfoPtr, messageDataPtr, 
										messageValue );
				break;

			case RESOURCE_MESSAGE_CTX_SIGN:
				assert( capabilityInfoPtr->signFunction != NULL );
				status = capabilityInfoPtr->signFunction( cryptInfoPtr, 
											messageDataPtr, messageValue );
				break;

			case RESOURCE_MESSAGE_CTX_SIGCHECK:
				assert( capabilityInfoPtr->sigCheckFunction != NULL );
				status = capabilityInfoPtr->sigCheckFunction( cryptInfoPtr, 
											messageDataPtr, messageValue );
				break;

			case RESOURCE_MESSAGE_CTX_HASH:
				assert( capabilityInfoPtr->encryptFunction != NULL );
				status = capabilityInfoPtr->encryptFunction( cryptInfoPtr, 
											messageDataPtr, messageValue );
				break;

			default:
				assert( NOTREACHED );
			}
		unlockResourceExit( cryptInfoPtr, status );
		}

	/* Process messages which compare object properties or clone the object */
	if( message == RESOURCE_MESSAGE_COMPARE )
		{
		assert( messageValue == RESOURCE_MESSAGE_COMPARE_HASH || \
				messageValue == RESOURCE_MESSAGE_COMPARE_KEYID );

		if( messageValue == RESOURCE_MESSAGE_COMPARE_HASH )
			{
			const RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
			const int hashSize = cryptInfoPtr->capabilityInfo->blockSize;

			/* If it's a hash or MAC context, compare the hash value */
			if( cryptInfoPtr->type == CONTEXT_HASH )
				{
				if( !cryptInfoPtr->ctxHash.done )
					status = CRYPT_ERROR_INCOMPLETE;
				else
					if( msgData->length == hashSize && \
						!memcmp( msgData->data, cryptInfoPtr->ctxHash.hash, 
								 hashSize ) )
						status = CRYPT_OK;
				}
			if( cryptInfoPtr->type == CONTEXT_MAC )
				{
				if( !cryptInfoPtr->ctxMAC.done )
					status = CRYPT_ERROR_INCOMPLETE;
				else
					if( msgData->length == hashSize && \
						!memcmp( msgData->data, cryptInfoPtr->ctxMAC.mac, 
								 hashSize ) )
						status = CRYPT_OK;
				}
			}
		if( messageValue == RESOURCE_MESSAGE_COMPARE_KEYID )
			{
			/* If it's a PKC context, compare the key ID */
			if( cryptInfoPtr->type == CONTEXT_PKC && \
				!memcmp( cryptInfoPtr->ctxPKC.keyID, messageDataPtr, 
						 KEYID_SIZE ) )
				status = CRYPT_OK;
			}
		unlockResourceExit( cryptInfoPtr, status );
		}
	if( message == RESOURCE_MESSAGE_CLONE )
		{
		CRYPT_CONTEXT *iDestContext = ( CRYPT_CONTEXT * ) messageDataPtr;
		int dummy;

		*iDestContext = CRYPT_ERROR;

		/* Cloning of non-native contexts is somewhat complex because we 
		   usually can't clone a device object, so we have to detect requests
		   to clone these objects and increment their reference count 
		   instead.  This isn't a major problem because cryptlib always
		   creates native contexts for clonable algorithms, if the user
		   explicitly overrides this by using their own device-specific 
		   context then the usage will usually be create, add to envelope, 
		   destroy, so there's no need to clone the context anyway.  The
		   only time there's a potential problem is if they override the use
		   of native contexts by adding device contexts to multiple envelopes,
		   but in that case it's assumed they'll be aware of potential 
		   problems with this approach */
		status = krnlSendMessage( cryptContext, RESOURCE_IMESSAGE_GETDEPENDENT,
								  &dummy, OBJECT_TYPE_DEVICE );
		if( cryptStatusOK( status ) )
			{
			status = krnlSendNotifier( cryptContext, 
									   RESOURCE_IMESSAGE_INCREFCOUNT );
			if( cryptStatusOK( status ) )
				*iDestContext = cryptContext;
			}
		else
			status = cloneContext( messageDataPtr, cryptContext );
		unlockResourceExit( cryptInfoPtr, status );
		}

	/* Process messages which check a context */
	if( message == RESOURCE_MESSAGE_CHECK )
		{
		status = checkContext( cryptInfoPtr, messageValue );
		unlockResourceExit( cryptInfoPtr, status );
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
		unlockResource( cryptInfoPtr );	/* Undo RESOURCE_MESSAGE_LOCK lock */
		unlockResourceExit( cryptInfoPtr, CRYPT_OK );
		}

	/* Process internal notification messages */
	if( message == RESOURCE_MESSAGE_CHANGENOTIFY && \
		messageValue == CRYPT_IATTRIBUTE_STATUS )
		{
		/* If the context is still busy and we're trying to reset its status
		   from CRYPT_ERROR_BUSY back to CRYPT_OK, set the abort flag to 
		   indicate that the operation which is keeping it busy should be 
		   cancelled, and return an error so that the busy status is 
		   maintained until the context has processed the abort */
		if( !cryptInfoPtr->done )
			cryptInfoPtr->doAbort = TRUE;
		else
			/* The context finished whatever it was doing, reset the status
			   back to normal */
			status = CRYPT_OK;

		unlockResourceExit( cryptInfoPtr, status );
		}

	/* Process object-specific messages */
	if( message == RESOURCE_MESSAGE_CTX_GENKEY )
		{
		assert( cryptInfoPtr->type == CONTEXT_CONV || \
				cryptInfoPtr->type == CONTEXT_MAC ||
				cryptInfoPtr->type == CONTEXT_PKC );
		assert( needsKey( cryptInfoPtr ) );

		/* If it's a private key context, we need to have a key label set 
		   before we can continue */
		if( cryptInfoPtr->type == CONTEXT_PKC && !cryptInfoPtr->labelSize )
			{
			setErrorInfo( cryptInfoPtr, CRYPT_CTXINFO_LABEL, 
						  CRYPT_ERRTYPE_ATTR_ABSENT );
			unlockResourceExit( cryptInfoPtr, CRYPT_ERROR_NOTINITED );
			}

		/* Generate a new key into the context */
		status = generateKey( cryptInfoPtr, *( ( int * ) messageDataPtr ), 
							  messageValue );
		unlockResourceExit( cryptInfoPtr, status );
		}
	if( message == RESOURCE_MESSAGE_CTX_GENIV )
		{
		BYTE buffer[ CRYPT_MAX_IVSIZE ];

		assert( cryptInfoPtr->type == CONTEXT_CONV );
			
		/* If it's not a conventional encryption context or a mode which 
		   doesn't use an IV, the generate IV operation is meaningless */
		if( !needsIV( cryptInfoPtr->ctxConv.mode ) || \
			cryptInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RC4 )
			unlockResourceExit( cryptInfoPtr, CRYPT_ERROR_NOTAVAIL );

		/* Generate a new IV and load it */
		getNonce( buffer, CRYPT_MAX_IVSIZE );
		cryptInfoPtr->capabilityInfo->initIVFunction( cryptInfoPtr, buffer, 
													  CRYPT_USE_DEFAULT );
		unlockResourceExit( cryptInfoPtr, CRYPT_OK );
		}

	assert( NOTREACHED );
	return( 0 );	/* Get rid of compiler warning */
	}

/* Create an encryption context based on an encryption capability template.  
   This is a common function called by devices to create a context once 
   they've got the appropriate capability template */

int createContextFromCapability( CRYPT_CONTEXT *cryptContext,
								 const CAPABILITY_INFO *capabilityInfoPtr,
								 const int objectFlags )
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
	const int createFlags = objectFlags | \
							( needsSecureMemory( contextType ) ? \
							CREATEOBJECT_FLAG_SECUREMALLOC : 0 );
	int initStatus = CRYPT_OK, subType, status;
	int actionFlags = 0, actionPerms = ACTION_PERM_ALL;

	/* Clear the return values */
	*cryptContext = CRYPT_ERROR;

	/* Set up the initial permitted action flags */
	switch( contextType )
		{
		case CONTEXT_CONV:
			subType = SUBTYPE_CTX_CONV;
			if( capabilityInfoPtr->encryptFunction != NULL || \
				capabilityInfoPtr->encryptCBCFunction != NULL || \
				capabilityInfoPtr->encryptCFBFunction != NULL || \
				capabilityInfoPtr->encryptOFBFunction != NULL )
				actionFlags |= MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_ENCRYPT, 
											   ACTION_PERM_ALL );
			if( capabilityInfoPtr->decryptFunction != NULL || \
				capabilityInfoPtr->decryptCBCFunction != NULL || \
				capabilityInfoPtr->decryptCFBFunction != NULL || \
				capabilityInfoPtr->decryptOFBFunction != NULL )
				actionFlags |= MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_DECRYPT, 
											   ACTION_PERM_ALL );
			if( capabilityInfoPtr->generateKeyFunction != NULL )
				actionFlags |= MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_GENKEY, 
											   ACTION_PERM_ALL );
			break;

		case CONTEXT_PKC:
			/* The DLP-based PKC's have somewhat specialised usage 
			   requirements so we don't allow direct access by users.
			   Higher-level routines would typically want to turn off
			   external access to signature actions as well */
			if( cryptAlgo == CRYPT_ALGO_DSA || \
				cryptAlgo == CRYPT_ALGO_DH || \
				cryptAlgo == CRYPT_ALGO_KEA )
				actionPerms = ACTION_PERM_NONE_EXTERNAL;

			subType = SUBTYPE_CTX_PKC;
			if( capabilityInfoPtr->encryptFunction != NULL )
				actionFlags |= MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_ENCRYPT, 
											   actionPerms );
			if( capabilityInfoPtr->decryptFunction != NULL )
				actionFlags |= MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_DECRYPT, 
											   actionPerms );
			if( capabilityInfoPtr->signFunction != NULL )
				actionFlags |= MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_SIGN, 
											   actionPerms );
			if( capabilityInfoPtr->sigCheckFunction != NULL )
				actionFlags |= MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_SIGCHECK, 
											   actionPerms );
			if( capabilityInfoPtr->generateKeyFunction != NULL )
				actionFlags |= MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_GENKEY, 
											   actionPerms );
			break;

		case CONTEXT_HASH:
			subType = SUBTYPE_CTX_HASH;
			actionFlags = \
				MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_HASH, ACTION_PERM_ALL );
			break;

		case CONTEXT_MAC:
			subType = SUBTYPE_CTX_MAC;
			actionFlags = \
				MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_HASH, ACTION_PERM_ALL );
			if( capabilityInfoPtr->generateKeyFunction != NULL )
				actionFlags |= MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_GENKEY, 
											   ACTION_PERM_ALL );
			break;
		}

	/* Create the context and initialise the variables in it */
	status = krnlCreateObject( ( void ** ) &cryptInfoPtr, 
							   OBJECT_TYPE_CONTEXT, subType,
							   sizeof( CRYPT_INFO ), createFlags, 
							   actionFlags, contextMessageFunction );
	if( cryptStatusError( status ) )
		return( status );
	initResourceLock( cryptInfoPtr ); 
	lockResource( cryptInfoPtr ); 
	*cryptContext = cryptInfoPtr->objectHandle = status;
	cryptInfoPtr->capabilityInfo = capabilityInfoPtr;
	cryptInfoPtr->type = contextType;
	if( cryptInfoPtr->type == CONTEXT_PKC && \
		!( objectFlags & CREATEOBJECT_FLAG_DUMMY ) )
		{
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
	if( cryptInfoPtr->type == CONTEXT_CONV )
		/* Set the default encryption mode, which is always CBC if possible */
		cryptInfoPtr->ctxConv.mode = ( cryptAlgo == CRYPT_ALGO_RC4 ) ? \
									 CRYPT_MODE_OFB : CRYPT_MODE_CBC;

	/* Perform any algorithm-specific initialization */
	if( capabilityInfoPtr->initFunction != NULL && \
		!( objectFlags & CREATEOBJECT_FLAG_DUMMY ) )
		{
		initStatus = capabilityInfoPtr->initFunction( cryptInfoPtr );
		if( cryptStatusError( initStatus ) )
			/* The algorithm-specific init failed, make sure the object gets 
			   destroyed when we notify the kernel that the setup process is
			   complete */
			krnlSendNotifier( *cryptContext, RESOURCE_IMESSAGE_DESTROY );
		}
	if( cryptStatusOK( initStatus ) )
		cryptInfoPtr->keyingInfoInited = TRUE;

	/* We've finished setting up the object-type-specific info, tell the 
	   kernel the object is ready for use */
	unlockResource( cryptInfoPtr );
	status = krnlSendMessage( *cryptContext, RESOURCE_IMESSAGE_SETATTRIBUTE, 
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusError( initStatus ) )
		status = initStatus;
	if( cryptStatusError( status ) )
		{
		*cryptContext = CRYPT_ERROR;
		return( status );
		}
	if( cryptInfoPtr->type == CONTEXT_HASH )
		/* If it's a hash context there's no explicit keygen or load so we
		   need to send an "object initialised" message to get the kernel to
		   move it into the high state.  If this isn't done, any attempt to 
		   use the context will be blocked */
		krnlSendMessage( *cryptContext, RESOURCE_IMESSAGE_SETATTRIBUTE, 
						 MESSAGE_VALUE_UNUSED, CRYPT_IATTRIBUTE_INITIALISED );
	return( CRYPT_OK );
	}

/* Create an encryption context object */

int createContext( CREATEOBJECT_INFO *createInfo, 
				   const void *auxDataPtr, const int auxValue )
	{
	CRYPT_CONTEXT iCryptContext;
	const CAPABILITY_INFO FAR_BSS *capabilityInfoPtr;
	int status;

	assert( auxDataPtr != NULL );

	/* Perform basic error checking */
	if( createInfo->arg1 <= CRYPT_ALGO_NONE || \
		createInfo->arg1 >= CRYPT_ALGO_LAST )
		return( CRYPT_ARGERROR_NUM1 );

	/* Find the capability corresponding to the algorithm */
	capabilityInfoPtr = findCapabilityInfo( auxDataPtr, createInfo->arg1 );
	if( capabilityInfoPtr == NULL )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Pass the call on to the lower-level create function */
	status = createContextFromCapability( &iCryptContext, capabilityInfoPtr, 
										  auxValue );
	if( cryptStatusOK( status ) )
		createInfo->cryptHandle = iCryptContext;
	return( status );
	}
