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
#ifdef INC_ALL
  #include "asn1objs.h"
  #include "sha.h"			/* Needed for PKCS #5 key derivation */
#else
  #include "keymgmt/asn1objs.h"
  #include "hash/sha.h"		/* Needed for PKCS #5 key derivation */
#endif /* Compiler-specific includes */

/* Prototypes for functions in lib_rand.c */

int getRandomData( BYTE *buffer, const int length );

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

/* Load a key into a CRYPT_INFO structure.  This low-level function bypasses
   a lot of checking which is unnecessary for internal calls */

static int loadKey( CRYPT_INFO *cryptInfoPtr, BYTE *key, const int keyLength )
	{
	const CAPABILITY_INFO *capabilityInfoPtr = cryptInfoPtr->capabilityInfo;
	int status;

	/* If it's a PKC context, load the PKC keying information */
	if( cryptInfoPtr->type == CONTEXT_PKC )
		{
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
		return( CRYPT_BADPARM3 );

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
	if( needsIV( capabilityInfoPtr->cryptMode ) )
		cryptInfoPtr->ctxConv.ivSet = FALSE;
	else
		/* We don't need an IV, record it as being set */
		cryptInfoPtr->ctxConv.ivSet = TRUE;

	/* Perform the key setup */
	status = capabilityInfoPtr->initKeyFunction( cryptInfoPtr, key, keyLength );
	if( cryptStatusOK( status ) )
		cryptInfoPtr->ctxConv.keySet = TRUE;

	return( status );
	}

/* Load a user key into an encryption context */

CRET cryptLoadKey( const CRYPT_CONTEXT cryptContext, const void CPTR userKey,
				   const int userKeyLength )
	{
	const CAPABILITY_INFO *capabilityInfoPtr;
	CRYPT_INFO *cryptInfoPtr;
	int status;

	/* Perform basic error checking */
	getCheckResource( cryptContext, cryptInfoPtr, RESOURCE_TYPE_CRYPT,
					  CRYPT_BADPARM1 );
	if( checkBadPtrRead( userKey, 5 ) )	/* 40 bits */
		unlockResourceExit( cryptInfoPtr, CRYPT_BADPARM2 );
	capabilityInfoPtr = cryptInfoPtr->capabilityInfo;
	if( cryptInfoPtr->type == CONTEXT_PKC )
		{
		if( userKeyLength != CRYPT_UNUSED )
			unlockResourceExit( cryptInfoPtr, CRYPT_BADPARM3 );
		}
	else
		if( userKeyLength < capabilityInfoPtr->minKeySize || \
			userKeyLength > capabilityInfoPtr->maxKeySize )
		unlockResourceExit( cryptInfoPtr, CRYPT_BADPARM3 );

	/* If it's a hash function the load key operation is meaningless */
	if( cryptInfoPtr->type == CONTEXT_HASH )
		unlockResourceExit( cryptInfoPtr, CRYPT_NOTAVAIL );

	/* We can't reload a key if we've already got one loaded (we have to
	   check for this after the hash check since hash contexts always appear
	   to have keys loaded) */
	if( !needsKey( cryptInfoPtr ) )
		unlockResourceExit( cryptInfoPtr, CRYPT_INITED );

	/* Load the key into the context */
	status = loadKey( cryptInfoPtr, ( BYTE * ) userKey, userKeyLength );
	unlockResourceExit( cryptInfoPtr, status );
	}

/****************************************************************************
*																			*
*							Key Generation Functions						*
*																			*
****************************************************************************/

/* Threaded key generation for those OS's which support threads.  The
   following function *must* be called as a thread */

#if defined( __WIN32__ ) || defined( __OS2__ ) || \
	( defined( __UNIX__ ) && defined( USE_THREADS ) )

THREADFUNC_DEFINE( threadKeygen, ptr )
	{
	CRYPT_INFO *cryptInfoPtr = ( CRYPT_INFO * ) ptr;
	int busyStatus = CRYPT_BUSY, okStatus = CRYPT_OK;

	/* Mark the object as busy, perform the keygen, and set it back to non-
	   busy */
	krnlSendMessage( cryptInfoPtr->objectHandle, RESOURCE_IMESSAGE_SETPROPERTY,
					 &busyStatus, RESOURCE_MESSAGE_PROPERTY_STATUS, 0 );
	cryptInfoPtr->asyncStatus = \
		cryptInfoPtr->capabilityInfo->generateKeyFunction( cryptInfoPtr,
										cryptInfoPtr->ctxPKC.keySizeBits );
	if( cryptStatusOK( cryptInfoPtr->asyncStatus ) )
		cryptInfoPtr->ctxPKC.keySet = TRUE;	/* There's now a key loaded */
	cryptInfoPtr->doAbort = FALSE;
	cryptInfoPtr->done = TRUE;
	krnlSendMessage( cryptInfoPtr->objectHandle, RESOURCE_IMESSAGE_SETPROPERTY,
					 &okStatus, RESOURCE_MESSAGE_PROPERTY_STATUS, 0 );
	THREAD_EXIT();
	}
#endif /* Threaded keygen function */

/* Determine the optimal size for the generated key.  This isn't as easy as
   just taking the default key size since some algorithms have variable key
   sizes (Safer) or alternative key sizes where the default isn't necessarily
   the best choice (two-key vs three-key 3DES) */

static int getOptimalKeysize( CRYPT_INFO *cryptInfoPtr,
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
			return( CRYPT_BADPARM2 );
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
#if defined( __WIN32__ ) || defined( __OS2__ ) || \
	( defined( __UNIX__ ) && defined( USE_THREADS ) )
		THREAD_HANDLE dummy;
#endif /* OS's with threads */

		if( capabilityInfoPtr->generateKeyFunction == NULL )
			return( CRYPT_NOTAVAIL );

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
#if defined( __WIN32__ ) || defined( __OS2__ ) || \
	( defined( __UNIX__ ) && defined( USE_THREADS ) )
		cryptInfoPtr->ctxPKC.keySizeBits = bytesToBits( keyLength );
		status = THREAD_CREATE( &threadKeygen, cryptInfoPtr );
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
		status = getRandomData( cryptInfoPtr->ctxConv.userKey, keyLength );
		if( cryptStatusOK( status ) )
			status = loadKey( cryptInfoPtr, cryptInfoPtr->ctxConv.userKey,
							  keyLength );
		}
	if( cryptInfoPtr->type == CONTEXT_MAC )
		{
		status = getRandomData( cryptInfoPtr->ctxMAC.userKey, keyLength );
		if( cryptStatusOK( status ) )
			status = loadKey( cryptInfoPtr, cryptInfoPtr->ctxMAC.userKey,
							  keyLength );
		}

	return( status );
	}

/* Generate a key into an encryption context */

CRET cryptGenerateKeyEx( const CRYPT_CONTEXT cryptContext,
						 const int userKeyLength )
	{
	return( krnlSendMessage( cryptContext, RESOURCE_MESSAGE_CTX_GENKEY, NULL,
							 userKeyLength, CRYPT_BADPARM1 ) );
	}

CRET cryptGenerateKey( const CRYPT_CONTEXT cryptContext )
	{
	return( krnlSendMessage( cryptContext, RESOURCE_MESSAGE_CTX_GENKEY, NULL,
							 CRYPT_USE_DEFAULT, CRYPT_BADPARM1 ) );
	}

/****************************************************************************
*																			*
*							Key Derivation Functions						*
*																			*
****************************************************************************/

/* Derive an encryption key from a variable-length user key.  This function
   works as follows:

   key[] = { 0 };
   state = hash( algorithm, mode, parameters, userKey );

   for count = 1 to iterations
	 for length = 1 to keyLength
	   state = hash( state );
	   key[ length ] ^= hash( state || userKey );

   The state acts as an RNG which ensures that the user key hashing is
   serialized (ie that any form of parallelization or precomputation isn't
   possible).

   This construct predates the appearance of HMAC, an alternative is to use

	   key[ length ] = HMAC ( userKey );
						 state

   but there seems little advantage in this.  In addition the fact that most
   HMAC's are limited to 64 bytes of keying material means that they can't be
   keyed with the user key, so the initial state can't also be generated
   using an HMAC */

static int deriveKey( CRYPT_INFO *cryptInfoPtr, const void *userKey,
					  const int userKeyLength, const CRYPT_ALGO hashAlgorithm,
					  const int keySetupIterations )
	{
	BYTE *hashInfo, *keyBuffer, *state, *temp;
	int hashInfoSize, hashInputSize, hashOutputSize, status;
	HASHFUNCTION hashFunction;
	BYTE buffer[ 50 ];
	STREAM stream;
	int keyLength, iterationCount;

	/* Get the hash algorithm information */
	if( !getHashParameters( hashAlgorithm, &hashFunction, &hashInputSize,
							&hashOutputSize, &hashInfoSize ) )
		return( CRYPT_ERROR );/* Internal error, should never occur */

	/* Determine the best keysize for this algorithm */
	keyLength = getOptimalKeysize( cryptInfoPtr, CRYPT_USE_DEFAULT );

	/* Allocate storage for the hash information, the RNG state information,
	   and the hash output temporary storage which is used to build up the
	   key.  Since the memory is pagelocked, we pack it all into a single
	   block of memory from which we suballocate the required chunks (this
	   should all fit into a 4K page.  Even if it's not locked it's being
	   constantly touched so shouldn't ever get paged) */
	if( ( status = krnlMemalloc( ( void ** ) &hashInfo, hashInfoSize + \
								 hashOutputSize + hashOutputSize ) ) != CRYPT_OK )
		return( status );
	state = hashInfo + hashInfoSize;
	temp = state + hashOutputSize;

	/* The key itself is generated directly into the context memory */
	if( cryptInfoPtr->type == CONTEXT_CONV )
		keyBuffer = cryptInfoPtr->ctxConv.userKey;
	else
		keyBuffer = cryptInfoPtr->ctxMAC.userKey;

	/* Generate the initial state information from the user key.  If we
	   hashed the key directly and then used it for a number of algorithms
	   then someone who could recover the key for one algorithm could
	   compromise it if used for other algorithms (for example recovering a
	   DES key would also recover half an IDEA key), so we hash the
	   contents of a KeyInformation record so that all the information
	   about the algorithm and mode being used influences the state.  This
	   means that a successful attack one an algorithm, mode, or
	   configuration won't allow the key for any other algorithm, mode, or
	   configuration to be recovered */
	sMemOpen( &stream, buffer, 50 );
	status = writeKeyInfoHeader( &stream, cryptInfoPtr, userKeyLength, 0 );
	if( cryptStatusError( status ) )
		{
		krnlMemfree( ( void ** ) &hashInfo );
		return( status );
		}
	hashFunction( hashInfo, NULL, buffer, sMemSize( &stream ), HASH_START );
	hashFunction( hashInfo, state, ( void * ) userKey, userKeyLength, HASH_END );
	sMemClose( &stream );

	/* Hash the variable-length input to a fixed-length output */
	memset( keyBuffer, 0, keyLength );
	for( iterationCount = 0; iterationCount < keySetupIterations; iterationCount++ )
		{
		int keyIndex, length;

		for( keyIndex = 0; keyIndex < keyLength; keyIndex += hashOutputSize )
			{
			int i;

			/* state = hash( state ); key[ n ] = hash( state, userKey ) */
			hashFunction( hashInfo, state, state, hashOutputSize, HASH_ALL );
			hashFunction( hashInfo, NULL, state, hashOutputSize, HASH_START );
			hashFunction( hashInfo, temp, ( void * ) userKey, userKeyLength, HASH_END );

			/* Copy as much of the hashed data as required to the output */
			length = keyLength - keyIndex;
			if( length > hashOutputSize ) 
				length = hashOutputSize;
			for( i = 0; i < length; i++ )
				keyBuffer[ i ] ^= temp[ i ];
			}
		}

	/* Copy the result into the encryption context.  Since the key is
	   generated directly into the context memory, we don't set the
	   clearBuffer flag */
	status = loadKey( cryptInfoPtr, keyBuffer, keyLength );
	if( cryptStatusOK( status ) && cryptInfoPtr->type == CONTEXT_CONV )
		{
		/* Remember the setup parameters */
		cryptInfoPtr->ctxConv.keySetupIterations = keySetupIterations;
		cryptInfoPtr->ctxConv.keySetupAlgorithm = hashAlgorithm;
		}

	/* Clean up */
	krnlMemfree( ( void ** ) &hashInfo );
	return( status );
	}

/* Derive a PKCS #5 key.  Uses SHA-1 for all functions (no other hash
   functions are currently defined) */

static void prfInit( SHA_CTX *shaInfo, void *processedKey,
					 int *processedKeyLength, const void *key,
					 const int keyLength )
	{
	BYTE hashBuffer[ SHA_CBLOCK ];
	int i;

	/* Set up the SHA-1 state */
	SHA1_Init( shaInfo );

	/* If the key size is larger than tha SHA data size, reduce it to the
	   SHA hash size before processing it (yuck.  You're required to do this
	   though) */
	if( keyLength > SHA_CBLOCK )
		{
		/* Hash the user key down to the hash size and use the hashed form of
		   the key */
		SHA1_Update( shaInfo, ( void * ) key, keyLength );
		SHA1_Final( processedKey, shaInfo );
		*processedKeyLength = SHA_DIGEST_LENGTH;

		/* Reset the SHA state */
		SHA1_Init( shaInfo );
		}
	else
		{
		/* Copy the key to internal storage */
		memcpy( processedKey, key, keyLength );
		*processedKeyLength = keyLength;
		}

	/* Perform the start of the inner hash using the zero-padded key XOR'd
	   with the ipad value */
	memset( hashBuffer, HMAC_IPAD, SHA_CBLOCK );
	memcpy( hashBuffer, processedKey, *processedKeyLength );
	for( i = 0; i < *processedKeyLength; i++ )
		hashBuffer[ i ] ^= HMAC_IPAD;
	SHA1_Update( shaInfo, hashBuffer, SHA_CBLOCK );
	memset( hashBuffer, 0, SHA_CBLOCK );
	}

static void prfEnd( SHA_CTX *shaInfo, void *hash, const void *processedKey,
					const int processedKeyLength )
	{
	BYTE hashBuffer[ SHA_CBLOCK ], digestBuffer[ SHA_DIGEST_LENGTH ];
	int i;

	/* Complete the inner hash and extract the digest */
	SHA1_Final( digestBuffer, shaInfo );

	/* Perform the of the outer hash using the zero-padded key XOR'd with the
	   opad value followed by the digest from the inner hash */
	memset( hashBuffer, HMAC_OPAD, SHA_CBLOCK );
	memcpy( hashBuffer, processedKey, processedKeyLength );
	for( i = 0; i < processedKeyLength; i++ )
		hashBuffer[ i ] ^= HMAC_OPAD;
	SHA1_Init( shaInfo );
	SHA1_Update( shaInfo, hashBuffer, SHA_CBLOCK );
	memset( hashBuffer, 0, SHA_CBLOCK );
	SHA1_Update( shaInfo, digestBuffer, SHA_DIGEST_LENGTH );
	memset( digestBuffer, 0, SHA_DIGEST_LENGTH );
	SHA1_Final( hash, shaInfo );
	}

static int pkcsDeriveKey( CRYPT_INFO *cryptInfoPtr, const void *userKey,
						  const int userKeyLength, const void *salt,
						  const int saltLength, const int keySetupIterations )
	{
	SHA_CTX shaInfo, initialShaInfo;
	BYTE processedKey[ SHA_CBLOCK ], block[ SHA_DIGEST_LENGTH ];
	BYTE countBuffer[ 4 ], *keyBuffer;
	int keyLength, keyIndex, processedKeyLength, blockCount = 1;

	/* Determine the best keysize for this algorithm */
	keyLength = getOptimalKeysize( cryptInfoPtr, CRYPT_USE_DEFAULT );

	/* The key itself is generated directly into the context memory */
	keyBuffer = ( cryptInfoPtr->type == CONTEXT_CONV ) ? \
				cryptInfoPtr->ctxConv.userKey : cryptInfoPtr->ctxMAC.userKey;

	/* Set up the block counter buffer.  This will never have more than the
	   last few bits set (8 bits = 5100 bytes of key) so we only change the
	   last byte */
	memset( countBuffer, 0, 4 );

	/* Initialise the SHA-1 information with the user key.  This is reused
	   for any future hashing since it's constant */
	prfInit( &initialShaInfo, processedKey, &processedKeyLength,
			 userKey, userKeyLength );

	/* Produce enough blocks of output to fill the key */
	for( keyIndex = 0; keyIndex < keyLength; keyIndex += SHA_DIGEST_LENGTH )
		{
		const int noKeyBytes = ( keyLength - keyIndex > SHA_DIGEST_LENGTH ) ? \
							   SHA_DIGEST_LENGTH : keyLength - keyIndex;
		int i;

		/* Calculate HMAC( salt || counter ) */
		countBuffer[ 3 ] = ( BYTE ) blockCount++;
		memcpy( &shaInfo, &initialShaInfo, sizeof( SHA_CTX ) );
		SHA1_Update( &shaInfo, ( BYTE * ) salt, saltLength );
		SHA1_Update( &shaInfo, countBuffer, 4 );
		prfEnd( &shaInfo, block, processedKey, processedKeyLength );
		memcpy( keyBuffer, block, noKeyBytes );

		/* Calculate HMAC( T1 ) ^ HMAC( T1 ) ^ ... HMAC( Tc ) */
		for( i = 0; i < keySetupIterations - 1; i++ )
			{
			int j;

			/* Generate the PRF output for the current iteration */
			memcpy( &shaInfo, &initialShaInfo, sizeof( SHA_CTX ) );
			SHA1_Update( &shaInfo, block, SHA_DIGEST_LENGTH );
			prfEnd( &shaInfo, block, processedKey, processedKeyLength );

			/* Xor the new PRF output into the existing PRF output */
			for( j = 0; j < noKeyBytes; j++ )
				keyBuffer[ j ] ^= block[ j ];
			}
		}

	return( CRYPT_OK );
	}

/* Derive a key from user-supplied keying material */

CRET cryptDeriveKeyEx( const CRYPT_CONTEXT cryptContext,
					   const void CPTR userKey, const int userKeyLength,
					   const CRYPT_ALGO algorithm, const int iterations )
	{
	CRYPT_INFO *cryptInfoPtr;
	CRYPT_ALGO hashAlgorithm = algorithm;
	int keySetupIterations = iterations, status;

	/* Perform basic error checking.  We check for the availability of the
	   hash algorithm and whether the iteration count has a sane value
	   because it may have come from a high-level object query function which
	   read corrupted data */
	getCheckResource( cryptContext, cryptInfoPtr, RESOURCE_TYPE_CRYPT,
					  CRYPT_BADPARM1 );
	if( checkBadPtrRead( userKey, 1 ) )
		unlockResourceExit( cryptInfoPtr, CRYPT_BADPARM2 );
	if( userKeyLength <= 0 )
		unlockResourceExit( cryptInfoPtr, CRYPT_BADPARM3 );
	if( keySetupIterations == CRYPT_USE_DEFAULT )
		keySetupIterations = getOptionNumeric( CRYPT_OPTION_KEYING_ITERATIONS );
	if( hashAlgorithm == CRYPT_USE_DEFAULT )
		hashAlgorithm = getOptionNumeric( CRYPT_OPTION_KEYING_ALGO );
	if( cryptStatusError( cryptQueryCapability( hashAlgorithm,
												CRYPT_MODE_NONE, NULL ) ) )
		unlockResourceExit( cryptInfoPtr, CRYPT_BADPARM4 );
	if( keySetupIterations < 1 || keySetupIterations > 20000 )
		unlockResourceExit( cryptInfoPtr, CRYPT_BADPARM5 );

	/* If it's a hash function or PKC, the derive key operation is
	   meaningless */
	if( cryptInfoPtr->type == CONTEXT_PKC || cryptInfoPtr->type == CONTEXT_HASH )
		unlockResourceExit( cryptInfoPtr, CRYPT_NOTAVAIL );

	/* We can't reload a key if we've already got one loaded (we have to
	   check for this after the hash check since hash contexts always appear
	   to have keys loaded) */
	if( !needsKey( cryptInfoPtr ) )
		unlockResourceExit( cryptInfoPtr, CRYPT_INITED );

#if 0
	status = pkcsDeriveKey( cryptInfoPtr, userKey, userKeyLength,
							"\x12\x34\x56\x78", 4, 5 );
#endif /* 0 */

	/* Turn the user key into an encryption context key */
	status = deriveKey( cryptInfoPtr, userKey, userKeyLength, hashAlgorithm,
						keySetupIterations );
	unlockResourceExit( cryptInfoPtr, status );
	}

CRET cryptDeriveKey( const CRYPT_CONTEXT cryptContext,
					 const void CPTR userKey, const int userKeyLength )
	{
	return( cryptDeriveKeyEx( cryptContext, userKey, userKeyLength,
							  CRYPT_USE_DEFAULT, CRYPT_USE_DEFAULT ) );
	}

/****************************************************************************
*																			*
*							Internal Keying Functions						*
*																			*
****************************************************************************/

/* Internal load/generate/derive functions.  These skip the internal resource
   check, and return slightly different error codes for parameter errors.
   The reason for this is that they're only called by cryptlib internal
   functions so passing any type of parameter error back to the caller will
   cause problems.  For this reason we instead pass back CRYPT_BADDATA, since
   the only way we can get parameter errors (eg key too short/long) is if the
   encoded data which was passed on to the function was incorrect.  The
   internal functions also differ form the external ones in the following
   way:

   iCryptLoadKey() clears the callers key buffer once the key is loaded,
   since it's only ever loaded from things like decrypted session keys.

   iCryptLoadIV() loads an IV into the context without checking that the
   algorithm requires it (this is used in some cases so as not to reveal any
   information on the algorithm type) */

int iCryptLoadKey( const CRYPT_CONTEXT cryptContext, const void *userKey,
				   const int userKeyLength )
	{
	const CAPABILITY_INFO *capabilityInfoPtr;
	CRYPT_INFO *cryptInfoPtr;
	int status;

	/* Perform simplified error checking */
	getCheckInternalResource( cryptContext, cryptInfoPtr, RESOURCE_TYPE_CRYPT );
	capabilityInfoPtr = cryptInfoPtr->capabilityInfo;
	if( ( cryptInfoPtr->type != CONTEXT_PKC && \
		  ( userKeyLength < capabilityInfoPtr->minKeySize || \
			userKeyLength > capabilityInfoPtr->maxKeySize ) ) || \
		cryptInfoPtr->type == CONTEXT_HASH )
		unlockResourceExit( cryptInfoPtr, CRYPT_BADDATA );

	/* We can't reload a key if we've already got one loaded */
	if( !( cryptInfoPtr->type == CONTEXT_PKC && \
		   userKeyLength == LOAD_INTERNAL_PRIVATE ) &&
		!needsKey( cryptInfoPtr ) )
		unlockResourceExit( cryptInfoPtr, CRYPT_INITED );

	/* Load the key into the context */
	status = loadKey( cryptInfoPtr, ( BYTE * ) userKey, userKeyLength );
	unlockResourceExit( cryptInfoPtr, status );
	}

int loadIV( CRYPT_INFO *cryptInfoPtr, const void *iv, const int ivLength );

int iCryptLoadIV( const CRYPT_CONTEXT cryptContext, const void *iv,
				  const int ivLength )
	{
	CRYPT_INFO *cryptInfoPtr;
	int status;

	/* Perform simplified error checking */
	getCheckInternalResource( cryptContext, cryptInfoPtr, RESOURCE_TYPE_CRYPT );
	if( cryptInfoPtr->type == CONTEXT_PKC || \
		cryptInfoPtr->type == CONTEXT_HASH || \
		cryptInfoPtr->type == CONTEXT_MAC || \
		( ivLength && ( ivLength < cryptInfoPtr->capabilityInfo->minIVsize ||
						ivLength > cryptInfoPtr->capabilityInfo->maxIVsize ) ) )
		unlockResourceExit( cryptInfoPtr, CRYPT_BADDATA );

	/* Load the IV into the context */
	status = cryptInfoPtr->capabilityInfo->initIVFunction( cryptInfoPtr, iv,
														   ivLength );
	unlockResourceExit( cryptInfoPtr, status );
	}

int iCryptDeriveKeyEx( const CRYPT_CONTEXT cryptContext, const void *userKey,
					   const int userKeyLength, const CRYPT_ALGO algorithm,
					   const int iterations )
	{
	CRYPT_INFO *cryptInfoPtr;
	int status;

	/* Perform simplified error checking.  We rely on the caller to map the
	   generic CRYPT_BADPARM into an appropriate error code */
	getCheckInternalResource( cryptContext, cryptInfoPtr, RESOURCE_TYPE_CRYPT );
	if( cryptStatusError( cryptQueryCapability( algorithm, CRYPT_MODE_NONE,
												NULL ) ) || \
		iterations < 10 || iterations > 20000 )
		unlockResourceExit( cryptInfoPtr, CRYPT_BADPARM );

	/* Turn the user key into an encryption context key */
	status = deriveKey( cryptInfoPtr, userKey, userKeyLength, algorithm,
						iterations );
	unlockResourceExit( cryptInfoPtr, status );
	}

int iCryptDeriveKey( const CRYPT_CONTEXT cryptContext, const void *userKey,
					 const int userKeyLength )
	{
	return( iCryptDeriveKeyEx( cryptContext, userKey, userKeyLength,
					getOptionNumeric( CRYPT_OPTION_KEYING_ALGO ),
					getOptionNumeric( CRYPT_OPTION_KEYING_ITERATIONS ) ) );
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

/* Asynchronous key generate operations.  These are just wrappers for the
   generateKey() function which is shared with the sync.key generation
   functions */

CRET cryptGenerateKeyAsyncEx( const CRYPT_CONTEXT cryptContext,
							  const int userKeyLength )
	{
	return( krnlSendMessage( cryptContext, RESOURCE_MESSAGE_CTX_GENKEY_ASYNC,
							 NULL, userKeyLength, CRYPT_BADPARM1 ) );
	}

CRET cryptGenerateKeyAsync( const CRYPT_CONTEXT cryptContext )
	{
	return( krnlSendMessage( cryptContext, RESOURCE_MESSAGE_CTX_GENKEY_ASYNC,
							 NULL, CRYPT_USE_DEFAULT, CRYPT_BADPARM1 ) );
	}

/* Query the status of an asynchronous operation.  This has more or less the
   same effect as calling any other operation (both will return CRYPT_BUSY if
   the context is busy), but this is a pure query function with no other side
   effects */

CRET cryptAsyncQuery( const CRYPT_CONTEXT cryptContext )
	{
	int status, objectStatus;

	/* Get the object status.  Since the get property message is a control
	   message, it'll always succeed if the object access is valid (that is,
	   it'll succeed even if the object status isn't CRYPT_OK) so we need to
	   explicitly check the object status rather than just using the returned
	   status.  An alternative would be to send some nop non-control message,
	   which would return the object status as the returned status */
	status = krnlSendMessage( cryptContext, RESOURCE_MESSAGE_GETPROPERTY,
							  &objectStatus, RESOURCE_MESSAGE_PROPERTY_STATUS,
							  CRYPT_BADPARM1 );
	return( cryptStatusError( status ) ? status : objectStatus );
	}

/* Cancel an asynchronous operation on a context */

CRET cryptAsyncCancel( const CRYPT_CONTEXT cryptContext )
	{
	int newStatus = CRYPT_OK;

	/* Reset the objects status to non-busy.  If the object is still busy
	   when the message is received, the abort flag will be set, otherwise
	   the message won't have any effect */
	return( krnlSendMessage( cryptContext, RESOURCE_MESSAGE_SETPROPERTY,
							 &newStatus, RESOURCE_MESSAGE_PROPERTY_STATUS,
							 CRYPT_BADPARM1 ) );
	}

/****************************************************************************
*																			*
*							IV Handling Functions							*
*																			*
****************************************************************************/

/* Load an IV into a CRYPT_INFO structure.  If the IV pointer passed in is
   null, it generates and loads a new IV, otherwise it loads the passed-in
   IV.  This low-level function doesn't check whether an IV is required since
   when exporting encrypted data objects we always include an IV regardless
   of the mode so as not to leak information on the mode being used */

int loadIV( CRYPT_INFO *cryptInfoPtr, const void *iv, const int ivLength )
	{
	const BYTE *ivPtr = iv;
	BYTE ivBuffer[ CRYPT_MAX_IVSIZE ];
	int ivSize = ivLength;

	/* Load the IV of the required length.  If the required IV size is less
	   than the maximum possible IV size, we pad it to the right with
	   zeroes */
	if( cryptInfoPtr->type != CONTEXT_CONV )
		return( CRYPT_ERROR );		/* Quick sanity check */
	if( ivPtr == NULL )
		{
		/* Generate a new IV */
		ivSize = cryptInfoPtr->capabilityInfo->ivSize;
		ivPtr = ivBuffer;
		getNonce( ivBuffer, ivSize );
		}
	cryptInfoPtr->ctxConv.ivLength = ivSize;
	cryptInfoPtr->ctxConv.ivCount = 0;
	memset( cryptInfoPtr->ctxConv.iv, 0, CRYPT_MAX_IVSIZE );
	memcpy( cryptInfoPtr->ctxConv.iv, ivPtr, ivSize );
	memcpy( cryptInfoPtr->ctxConv.currentIV, cryptInfoPtr->ctxConv.iv, 
			CRYPT_MAX_IVSIZE );
	cryptInfoPtr->ctxConv.ivSet = TRUE;

	return( CRYPT_OK );
	}

/* Load an IV into an encryption context.  In theory we could also check
   whether the IV has already been loaded and refuse to reload it, however
   it's possible by reloading the IV to reset the state of the context so
   that it can be used to encrypt another data block, so we leave this check
   out */

CRET cryptLoadIV( const CRYPT_CONTEXT cryptContext, const void CPTR iv,
				  const int ivLength )
	{
	CRYPT_INFO *cryptInfoPtr;

	/* Perform basic error checking */
	getCheckResource( cryptContext, cryptInfoPtr, RESOURCE_TYPE_CRYPT,
					  CRYPT_BADPARM1 );
	if( checkBadPtrRead( iv, 1 ) )
		unlockResourceExit( cryptInfoPtr, CRYPT_BADPARM2 );
	if( ivLength < cryptInfoPtr->capabilityInfo->minIVsize ||
		ivLength > cryptInfoPtr->capabilityInfo->maxIVsize )
		unlockResourceExit( cryptInfoPtr, CRYPT_BADPARM3 );

	/* If it's not a conventional encryption context or an mode which doesn't
	   use an IV, the load IV operation is meaningless */
	if( cryptInfoPtr->type != CONTEXT_CONV || \
		!needsIV( cryptInfoPtr->capabilityInfo->cryptMode ) )
		unlockResourceExit( cryptInfoPtr, CRYPT_NOTAVAIL );

	/* Load the IV */
	loadIV( cryptInfoPtr, iv, ivLength );
	unlockResourceExit( cryptInfoPtr, CRYPT_OK );
	}

/* Retrieve an IV from an encryption context */

CRET cryptRetrieveIV( const CRYPT_CONTEXT cryptContext, void CPTR iv )
	{
	CRYPT_INFO *cryptInfoPtr;

	/* Perform basic error checking */
	getCheckResource( cryptContext, cryptInfoPtr, RESOURCE_TYPE_CRYPT,
					  CRYPT_BADPARM1 );

	/* If it's not a conventional encryption context or an mode which doesn't
	   use an IV, the load IV operation is meaningless */
	if( cryptInfoPtr->type != CONTEXT_CONV || \
		!needsIV( cryptInfoPtr->capabilityInfo->cryptMode ) )
		unlockResourceExit( cryptInfoPtr, CRYPT_NOTAVAIL );

	/* Make sure the IV has been set */
	if( cryptInfoPtr->ctxConv.ivSet == FALSE )
		unlockResourceExit( cryptInfoPtr, CRYPT_NOIV );

	/* Copy the IV data of the required length to the output buffer */
	if( checkBadPtrWrite( iv , cryptInfoPtr->ctxConv.ivLength ) )
		unlockResourceExit( cryptInfoPtr, CRYPT_BADPARM2 );
	memcpy( iv, cryptInfoPtr->ctxConv.iv, cryptInfoPtr->ctxConv.ivLength );

	unlockResourceExit( cryptInfoPtr, CRYPT_OK );
	}
