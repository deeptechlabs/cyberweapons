/****************************************************************************
*																			*
*							cryptlib Keying Routines						*
*						Copyright Peter Gutmann 1992-1999					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#include "cryptctx.h"

/****************************************************************************
*																			*
*								Key Load Functions							*
*																			*
****************************************************************************/

/* Determine whether a context needs to have a key loaded */

BOOLEAN needsKey( const CRYPT_INFO *cryptInfoPtr )
	{
	if( cryptInfoPtr->type == CONTEXT_CONV )
		return( !cryptInfoPtr->ctxConv.keySet );
	if( cryptInfoPtr->type == CONTEXT_PKC )
		return( !cryptInfoPtr->ctxPKC.keySet );
	if( cryptInfoPtr->type == CONTEXT_MAC )
		return( !cryptInfoPtr->ctxMAC.keySet );
	return( FALSE );
	}

/* Load a key into a CRYPT_INFO structure.  This function is called by the
   various higher-level functions which move a key into a context */

int loadKey( CRYPT_INFO *cryptInfoPtr, BYTE *key, const int keyLength )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = cryptInfoPtr->capabilityInfo;
	int status;

	/* If it's a PKC context, load the PKC keying information */
	if( cryptInfoPtr->type == CONTEXT_PKC )
		{
		/* If we're loading from externally-supplied parameters, make sure 
		   the parameters make sense (algorithm-specific validity checks are 
		   performed at a lower level).  Although the checks are somewhat 
		   algorithm-specific, we have to do them at this point in order to 
		   avoid duplicating them in every plug-in PKC module, and because 
		   strictly speaking it's the job of the higher-level code to ensure 
		   the lower-level routines at least get fed approximately valid 
		   input */
		if( keyLength != sizeof( PKCINFO_LOADINTERNAL ) )
			if( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_RSA )
				{
				const CRYPT_PKCINFO_RSA *rsaKey = ( CRYPT_PKCINFO_RSA * ) key;

				if( rsaKey->isPublicKey != TRUE && rsaKey->isPublicKey != FALSE )
					return( CRYPT_ARGERROR_STR1 );
				if( rsaKey->nLen < 504 || rsaKey->nLen > MAX_PKCSIZE_BITS || \
					rsaKey->eLen < 2 || rsaKey->eLen > MAX_PKCSIZE_BITS )
					return( CRYPT_ARGERROR_STR1 );
				if( !rsaKey->isPublicKey )
					{
					if( rsaKey->dLen < 504 || rsaKey->dLen > MAX_PKCSIZE_BITS || \
						rsaKey->pLen < 240 || rsaKey->pLen > MAX_PKCSIZE_BITS || \
						rsaKey->qLen < 240 || rsaKey->qLen > MAX_PKCSIZE_BITS )
						return( CRYPT_ARGERROR_STR1 );
					if( !( rsaKey->e1Len == 0 && rsaKey->e2Len == 0 ) && \
						( rsaKey->uLen < 240 || rsaKey->uLen > MAX_PKCSIZE_BITS || \
						  rsaKey->e1Len < 240 || rsaKey->e1Len > MAX_PKCSIZE_BITS || \
						  rsaKey->e2Len < 240 || rsaKey->e2Len > MAX_PKCSIZE_BITS ) )
						return( CRYPT_ARGERROR_STR1 );
					}
				}
			else
				{
				const CRYPT_PKCINFO_DLP *dlpKey = ( CRYPT_PKCINFO_DLP * ) key;
	
				if( ( dlpKey->isPublicKey != TRUE && dlpKey->isPublicKey != FALSE ) )
					return( CRYPT_ARGERROR_STR1 );
				if( dlpKey->pLen < 510 || dlpKey->pLen > MAX_PKCSIZE_BITS || \
					dlpKey->qLen < 128 || dlpKey->qLen > MAX_PKCSIZE_BITS || \
					dlpKey->gLen < 2 || dlpKey->gLen > MAX_PKCSIZE_BITS || \
					dlpKey->yLen < 0 || dlpKey->yLen > MAX_PKCSIZE_BITS )
					/* y may be 0 if only x and the public params are available */
					return( CRYPT_ARGERROR_STR1 );
				if( !dlpKey->isPublicKey && \
					( dlpKey->xLen < 128 || dlpKey->xLen > MAX_PKCSIZE_BITS ) )
					return( CRYPT_ARGERROR_STR1 );
				}

		/* Load the keying info */
		status = capabilityInfoPtr->initKeyFunction( cryptInfoPtr, key, keyLength );
		if( cryptStatusOK( status ) )
			cryptInfoPtr->ctxPKC.keySet = TRUE;

		return( status );
		}

	/* Some conventional/MAC algorithms allow various key sizes depending on
	   how they're used.  We now perform a more rigorous check to make sure
	   that the key length is correct */
	if( capabilityInfoPtr->getKeysizeFunction != NULL && \
		keyLength > capabilityInfoPtr->getKeysizeFunction( cryptInfoPtr ) )
		{
		setErrorInfo( cryptInfoPtr, CRYPT_CTXINFO_KEY, 
					  CRYPT_ERRTYPE_ATTR_SIZE );
		return( CRYPT_ARGERROR_NUM1 );
		}

	/* If it's a MAC algorithm, load the key */
	if( cryptInfoPtr->type == CONTEXT_MAC )
		{
		status = capabilityInfoPtr->initKeyFunction( cryptInfoPtr, key, keyLength );
		if( cryptStatusOK( status ) )
			cryptInfoPtr->ctxMAC.keySet = TRUE;

		return( status );
		}

	/* It's a conventional encryption context, remember that we need to set
	   an IV before we encrypt anything */
	if( needsIV( cryptInfoPtr->ctxConv.mode ) && \
		cryptInfoPtr->capabilityInfo->cryptAlgo != CRYPT_ALGO_RC4 )
		cryptInfoPtr->ctxConv.ivSet = FALSE;
	else
		/* We don't need an IV, record it as being set */
		cryptInfoPtr->ctxConv.ivSet = TRUE;

	/* Perform the key setup */
	assert( capabilityInfoPtr->initKeyFunction != NULL );
	status = capabilityInfoPtr->initKeyFunction( cryptInfoPtr, key, keyLength );
	if( cryptStatusOK( status ) )
		cryptInfoPtr->ctxConv.keySet = TRUE;

	return( status );
	}

/****************************************************************************
*																			*
*							Key Generation Functions						*
*																			*
****************************************************************************/

/* Threaded key generation for those OS's which support threads.  The
   following function *must* be called as a thread */

#if defined( __WIN32__ ) || defined( __OS2__ ) || \
	( defined( __UNIX__ ) && defined( USE_THREADS ) ) || defined( __BEOS__ )

#define HAS_THREADS		/* Enable use of threads throughout this module */

THREADFUNC_DEFINE( threadKeygen, ptr )
	{
	CRYPT_INFO *cryptInfoPtr = ( CRYPT_INFO * ) ptr;
	int busyStatus = CRYPT_ERROR_BUSY;

	/* Mark the object as busy, perform the keygen, and set it back to non-
	   busy */
	krnlSendMessage( cryptInfoPtr->objectHandle, RESOURCE_IMESSAGE_SETATTRIBUTE,
					 &busyStatus, CRYPT_IATTRIBUTE_STATUS );
	cryptInfoPtr->asyncStatus = \
		cryptInfoPtr->capabilityInfo->generateKeyFunction( cryptInfoPtr,
										cryptInfoPtr->ctxPKC.keySizeBits );
	if( cryptStatusOK( cryptInfoPtr->asyncStatus ) )
		cryptInfoPtr->ctxPKC.keySet = TRUE;	/* There's now a key loaded */
	cryptInfoPtr->doAbort = FALSE;
	cryptInfoPtr->done = TRUE;
	krnlSendMessage( cryptInfoPtr->objectHandle, RESOURCE_IMESSAGE_SETATTRIBUTE,
					 MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	THREAD_EXIT();
	}
#endif /* Threaded keygen function */

/* Determine the optimal size for the generated key.  This isn't as easy as
   just taking the default key size since some algorithms have variable key
   sizes (Safer) or alternative key sizes where the default isn't necessarily
   the best choice (two-key vs three-key 3DES) */

int getOptimalKeysize( CRYPT_INFO *cryptInfoPtr,
					   const int requestedKeyLength )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = cryptInfoPtr->capabilityInfo;
	int keyLength, maxKeyLength;

	/* Determine the upper limit on the key size and make sure the requested
	   length is valid */
	if( capabilityInfoPtr->getKeysizeFunction != NULL )
		maxKeyLength = capabilityInfoPtr->getKeysizeFunction( cryptInfoPtr );
	else
		maxKeyLength = capabilityInfoPtr->maxKeySize;
	if( requestedKeyLength == CRYPT_USE_DEFAULT )
		{
		/* For PKC contexts where we're generating a new key, we want to use
		   the recommended (rather than the longest possible) key size,
		   whereas for conventional contexts we want to use the longest
		   possible size for the session key (this will be adjusted further
		   down if necessary for those algorithms where it's excessively
		   long) */
		keyLength = ( cryptInfoPtr->type == CONTEXT_PKC ) ? \
					capabilityInfoPtr->keySize : maxKeyLength;

		/* Although RC2 will handle keys of up to 1024 bits, it's never used
		   with this maximum size but (at least in non-crippled
		   implementations) always uses 128 bits, so we limit it to the
		   default rather than maximum possible size */
		if( capabilityInfoPtr->cryptAlgo == CRYPT_ALGO_RC2 )
			keyLength = capabilityInfoPtr->keySize;
		}
	else
		{
		if( requestedKeyLength < capabilityInfoPtr->minKeySize || \
			requestedKeyLength > maxKeyLength )
			{
			setErrorInfo( cryptInfoPtr, CRYPT_CTXINFO_KEY, 
						  CRYPT_ERRTYPE_ATTR_SIZE );
			return( CRYPT_ARGERROR_NUM1 );
			}
		keyLength = requestedKeyLength;
		}

	/* If we're generating a conventional/MAC key we need to limit the
	   maximum length in order to make it exportable via the smallest normal
	   (ie non-elliptic-curve) public key */
	if( cryptInfoPtr->type != CONTEXT_PKC && \
		keyLength > bitsToBytes( MAX_KEYSIZE_BITS ) )
		keyLength = bitsToBytes( MAX_KEYSIZE_BITS );

	return( keyLength );
	}

/* Generate a key into a CRYPT_INFO structure.  This low-level function is
   called by both the normal and async keygen functions, which set the keygen
   up as required (the only time there's any real difference is for PKC
   keygen) */

int generateKey( CRYPT_INFO *cryptInfoPtr, int keyLength,
				 const BOOLEAN isAsync )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = cryptInfoPtr->capabilityInfo;
	int status;

	/* Determine the best keysize for this algorithm */
	keyLength = getOptimalKeysize( cryptInfoPtr, keyLength );
	if( cryptStatusError( keyLength ) )
		return( keyLength );

	/* Public-key generation works differently than the generation of session
	   keys into a conventional encryption context */
	if( cryptInfoPtr->type == CONTEXT_PKC )
		{
#ifdef HAS_THREADS
		THREAD_HANDLE dummy;
#endif /* OS's with threads */

		if( capabilityInfoPtr->generateKeyFunction == NULL )
			return( CRYPT_ERROR_NOTAVAIL );

		/* Generate the key into the context if it's a synchronous
		   operation */
		if( !isAsync )
			{
			status = capabilityInfoPtr->generateKeyFunction( cryptInfoPtr,
												bytesToBits( keyLength ) );
			if( cryptStatusOK( status ) )
				/* There's now a key loaded */
				cryptInfoPtr->ctxPKC.keySet = TRUE;
			return( status );
			}

		/* It's an async keygen, if the OS supports it set the context state
		   for the async keygen and spawn the thread/process.  If the OS
		   doesn't support it, just drop through to the normal sync.keygen,
		   but set the async status to make it behave like an async keygen */
		cryptInfoPtr->doAbort = cryptInfoPtr->done = FALSE;
		cryptInfoPtr->asyncStatus = CRYPT_OK;
#ifdef HAS_THREADS
		cryptInfoPtr->ctxPKC.keySizeBits = bytesToBits( keyLength );
		status = THREAD_CREATE( threadKeygen, cryptInfoPtr );
		return( THREAD_STATUS( status ) );
#else
		cryptInfoPtr->asyncStatus = \
				capabilityInfoPtr->generateKeyFunction( cryptInfoPtr,
												bytesToBits( keyLength ) );
		if( cryptStatusOK( cryptInfoPtr->asyncStatus ) )
			/* There's now a key loaded */
			cryptInfoPtr->ctxPKC.keySet = TRUE;
		return( cryptInfoPtr->asyncStatus );
#endif /* Optional async keygen */
		}

	/* If the context is implemented in a crypto device, it may have the
	   capability to generate the key itself so if there's a keygen function
	   present we call this to generate the key directly into the context
	   rather than generating it ourselves and loading it in.  Note that to
	   export this key we'll need to use an exporting context which is also
	   located in the device, since we can't access it externally */
	if( capabilityInfoPtr->generateKeyFunction != NULL )
		{
		status = capabilityInfoPtr->generateKeyFunction( cryptInfoPtr,
												bytesToBits( keyLength ) );
		if( cryptStatusOK( status ) )
			/* There's now a key loaded */
			if( cryptInfoPtr->type == CONTEXT_CONV )
				cryptInfoPtr->ctxConv.keySet = TRUE;
			else
				cryptInfoPtr->ctxMAC.keySet = TRUE;
		return( status );
		}

	/* Generate a random session key into the context.  We always use
	   synchronous key generation even if the user has called the async
	   function because it's quick enough that it doesn't make any
	   difference.  In addition we load the random data directly into the
	   pagelocked encryption context and pass that in as the key buffer -
	   loadKey() won't copy the data if src == dest */
	if( cryptInfoPtr->type == CONTEXT_CONV )
		{
		RESOURCE_DATA msgData;

		setResourceData( &msgData, cryptInfoPtr->ctxConv.userKey, keyLength );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
								  CRYPT_IATTRIBUTE_RANDOM );
		if( cryptStatusOK( status ) )
			status = loadKey( cryptInfoPtr, cryptInfoPtr->ctxConv.userKey,
							  keyLength );
		}
	if( cryptInfoPtr->type == CONTEXT_MAC )
		{
		RESOURCE_DATA msgData;

		setResourceData( &msgData, cryptInfoPtr->ctxMAC.userKey, keyLength );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
								  CRYPT_IATTRIBUTE_RANDOM );
		if( cryptStatusOK( status ) )
			status = loadKey( cryptInfoPtr, cryptInfoPtr->ctxMAC.userKey,
							  keyLength );
		}

	return( status );
	}

/****************************************************************************
*																			*
*							Asynchronous Keying Functions					*
*																			*
****************************************************************************/

/* The asynchronous operations only make sense in environments which allow
   some form of background processing.  Ideally the synchronisation should be
   done with a semaphore, however since Win32 pseudocritical sections are
   very lightweight it's easier to use these to create a DIY semaphore.  The
   only downside for this is that if the user calls cryptDestroyContext()
   without first calling cryptAsyncCancel(), we have to do it for them.
   Since we're not using a real semaphore, we have to do a busy wait until
   the abort completes.  This isn't a serious problem since it very rarely
   happens and when it does we just sleep for awhile, check the DIY
   semaphore, and loop if the async.op.is still in progress.  This is a lot
   cheaper than performing a heavyweight semaphore check on every single use
   of a context.

   Overall there are three functions:

	cryptGenerateKeyAsync();
	cryptAsyncQuery();
	cryptAsyncCancel();

   These are implemented as:

	cryptGenerateKeyAsync() is:
		lock context resources;
		set busy flag;
		clear async status, abort flag;
		spawn thread to begin key generation;
		unlock context resources;

	cryptAsyncQuery() is:
		lock context resources;
		check if busy flag set;
		unlock context resources;
		return flag status;

	cryptAsyncCancel() is:
		lock context resources;
		set abort flag;
		unlock context resources;

   The async keygen function relies on the fact that the bnlib routines
   supply a callback which can be used to handle control flow in and out of
   the bnlib keygen functions.  The callout is used to check the abort flag,
   and the return value communicates whether the keygen should be aborted or
   not:

	while( !key ready )
		status = generate more bits of key( &callback );
		clean up;
		exit thread;

	callback is:
		check abort flag;
		if( abort flag set )
			return( ASYNC_ABORT );
		return( 0 );

   Most other functions are modified to return a busy signal if the busy
   flag is set.  Also, cryptDestroyContext() is modified as described above.

   The overall mechanism is somewhat ugly since it involves the caller
   polling cryptAsyncQuery() until it returns CRYPT_OK, however there isn't
   any nice way to handle the notification since both callbacks and some form
   of message-passing are very OS-specific.  A possible alternative is that
   the caller passes in some reference to a message port and the message that
   should be sent to it on completion.  Under Windoze this would be done with
   use PostMessage(), under Unix the "port" would be the address of a
   callback function:

	cryptGenerateKeyAsync( const CRYPT_CONTEXT cryptContext,
						   void *completionMessagePort,
						   int completionMessage );

   However this makes certain assumptions such as the fact the the Windows
   app has a message loop, so for now we use the cryptAsyncQuery() mechanism
   and let the caller build functionality on top of that if they require it */

/* The async callback function.  This is called by the bnlib routines and
   checks the abort flag, returning ASYNC_ABORT if the flag is set to tell
   the bnlib code to clean up and exit */

int keygenCallback( void *callbackArg )
	{
	CRYPT_INFO *cryptInfoPtr = callbackArg;

	if( cryptInfoPtr->doAbort )
		return( ASYNC_ABORT );
	return( 0 );
	}
