/****************************************************************************
*																			*
*						cryptlib System Device Routines						*
*						Copyright Peter Gutmann 1995-1999					*
*																			*
****************************************************************************/

/* The random pool handling code in this module and the misc/rnd*.c modules 
   represent the cryptlib continuously seeded pseudorandom number generator 
   (CSPRNG) as described in my 1998 Usenix Security Symposium paper "The 
   generation of practically strong random numbers".

   The CSPRNG code is copyright Peter Gutmann (and various others) 1995-1999
   all rights reserved.  Redistribution of the CSPRNG modules and use in 
   source and binary forms, with or without modification, are permitted 
   provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice
	  and this permission notice in its entirety.

   2. Redistributions in binary form must reproduce the copyright notice in
	  the documentation and/or other materials provided with the distribution.

   3. A copy of any bugfixes or enhancements made must be provided to the
	  author, <pgut001@cs.auckland.ac.nz> to allow them to be added to the
	  baseline version of the code.

   ALTERNATIVELY, the code may be distributed under the terms of the GNU
   General Public License, version 2 or any later version published by the
   Free Software Foundation, in which case the provisions of the GNU GPL are
   required INSTEAD OF the above restrictions.

   Although not required under the terms of the GPL, it would still be nice 
   if you could make any changes available to the author to allow a 
   consistent code base to be maintained */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "cryptctx.h"
  #include "sha.h"
  #include "random.h"
  #include "device.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../cryptctx.h"
  #include "../hash/sha.h"
  #include "random.h"
  #include "device.h"
#else
  #include "crypt.h"
  #include "cryptctx.h"
  #include "hash/sha.h"
  #include "misc/random.h"
  #include "misc/device.h"
#endif /* Compiler-specific includes */

/* The EAY SHA code doesn't make the SHA compression function externally
   accessible, so we use RIPEMD-160 for now */

#define SHA1Transform( hash, data )	RIPEMD160Transform( hash, data )
#ifdef __WIN32__
  void __cdecl RIPEMD160Transform( LONG *H, const LONG *X );
#else
  void RIPEMD160Transform( LONG *H, const LONG *X );
#endif /* __WIN32__ */

/* If we don't have a defined randomness interface, complain */

#if !( defined( __MSDOS__ ) || defined( __WIN16__ ) || defined( __WIN32__ ) || \
	   defined( __OS2__ ) || defined( __BEOS__ ) || defined( __UNIX__ ) || \
	   defined( __MAC__ ) || defined( __TANDEM__ ) || defined( __IBM4758__ ) || \
	   defined( __VMCMS__ ) )
  #error You need to create OS-specific randomness-gathering functions in misc/rnd<os_name>.c
#endif /* Various OS-specific defines */

/* On Unix systems the randomness pool may be duplicated at any point if
   the process forks, so we need to perform a complex check to make sure
   we're running with a unique copy of the pool contents rather than a 
   clone of data held in another process.  The following function checks
   whether we've forked or not, which is used as a signal to adjust the
   pool contents */

#ifdef __UNIX__
  BOOLEAN checkForked( void );
#else
  #define checkForked()		FALSE
#endif /* __UNIX__ */

/* Convenience functions used by the system-specific randomness-polling 
   routines to send data to the randomness device.  These just accumulate as 
   close to RANDOM_BUFSIZE bytes of data as possible in a user-provided
   buffer and then forward them to the device object.  Note that 
   addRandomString() assumes the quantity of data being added is small (a 
   fixed-size struct or something similar), it shouldn't be used to add large 
   buffers full of data since information at the end of the buffer will be 
   lost (this will trigger an exception telling the caller to use a direct
   krnlSendMessage() instead) */

void addRandomString( BYTE *buffer, int *bufIndex, const void *value, 
					  const int valueLength )
	{
	assert( buffer != NULL );
	assert( *bufIndex >= 0 && *bufIndex <= RANDOM_BUFSIZE );
	assert( ( value != NULL && \
			  valueLength > 0 && valueLength <= RANDOM_BUFSIZE ) || \
			( value == NULL && valueLength == 0 ) );

	/* If the new data would overflow the accumulator or it's a flush, send
	   the data through to the device */
	if( ( *bufIndex + valueLength >= RANDOM_BUFSIZE ) || value == NULL )
		{
		RESOURCE_DATA msgData;

		setResourceData( &msgData, buffer, *bufIndex );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, RESOURCE_IMESSAGE_SETATTRIBUTE_S,
						 &msgData, CRYPT_IATTRIBUTE_RANDOM );
		*bufIndex = 0;

		/* If this is the flush call, clear the accumulator and exit */
		if( value == NULL )
			{
			zeroise( buffer, RANDOM_BUFSIZE );
			return;
			}
		}

	/* Add the data to the accumulator */
	memcpy( buffer + *bufIndex, value, min( valueLength, RANDOM_BUFSIZE ) );
	*bufIndex += valueLength;
	}

void addRandomLong( BYTE *buffer, int *bufIndex, const long value )
	{
	assert( buffer != NULL );
	assert( *bufIndex >= 0 && *bufIndex <= RANDOM_BUFSIZE );

	addRandomString( buffer, bufIndex, &value, sizeof( LONG ) );
	}

/****************************************************************************
*																			*
*						Random Pool Management Routines						*
*																			*
****************************************************************************/

/* The randomness code needs some extra header files to handle the pool */

#if defined( INC_ALL )
  #include "sha.h"
  #include "random.h"
#elif defined( INC_CHILD )
  #include "../hash/sha.h"
  #include "random.h"
#else
  #include "hash/sha.h"
  #include "misc/random.h"
#endif /* Compiler-specific includes */

/* Initialise a random pool */

static void initRandomPool( RANDOM_INFO *randomInfo )
	{
	memset( randomInfo, 0, sizeof( RANDOM_INFO ) );
	}

/* Stir up the data in the random buffer.  Given a circular buffer of length
   n bytes, we hash the 20 bytes at n with the 64 bytes at n - 20...n - 1 (to
   provide chaining across previous hashes) and n + 20...n + 64 (to have as
   much surrounding data as possible affect the current data) as the input 
   data block.  Then we move on to the next 20 bytes until the entire buffer 
   has been mixed.  We don't bother with data endianess-adjustment since 
   we're not really interested in the final output values, as long as they're 
   well-mixed */

static void mixRandomPool( RANDOM_INFO *randomInfo )
	{
#ifdef _BIG_WORDS
	LONG dataBuffer[ SHA_CBLOCK / 4 ];
#else
	BYTE dataBuffer[ SHA_CBLOCK ];
#endif /* BIG_WORDS */
	int hashIndex;

	/* Stir up the entire pool */
#ifdef _BIG_WORDS
	for( hashIndex = 0; hashIndex < RANDOMPOOL_SIZE; hashIndex += SHA_DIGEST_LENGTH )
		{
		LONG digestLong[ SHA_DIGEST_LENGTH / 4 ];
		BYTE *digestPtr;
		int dataBufIndex, poolIndex, i;

		/* If we're at the start of the pool then the first block we hash is 
		   at the end of the pool, otherwise it's the block immediately
		   preceding the current one */
		poolIndex = hashIndex ? hashIndex - SHA_DIGEST_LENGTH : \
					RANDOMPOOL_SIZE - SHA_DIGEST_LENGTH;

		/* Copy SHA_DIGEST_LENGTH bytes from position n - 19...n - 1 in the
		   circular pool into the hash data buffer */
		for( dataBufIndex = 0; dataBufIndex < SHA_DIGEST_LENGTH; dataBufIndex += 4 )
			dataBuffer[ dataBufIndex / 4 ] = \
				( ( LONG ) randomInfo->randomPool[ poolIndex++ % RANDOMPOOL_SIZE ] << 24 ) | \
				( ( LONG ) randomInfo->randomPool[ poolIndex++ % RANDOMPOOL_SIZE ] << 16 ) | \
				( ( LONG ) randomInfo->randomPool[ poolIndex++ % RANDOMPOOL_SIZE ] << 8 ) | \
				( ( LONG ) randomInfo->randomPool[ poolIndex++ % RANDOMPOOL_SIZE ] );

		/* Postconditions for chaining data copy */
		assert( dataBufIndex == SHA_DIGEST_LENGTH );/* Got 20 bytes... */
		assert( poolIndex >= SHA_DIGEST_LENGTH && \
				poolIndex <= RANDOMPOOL_SIZE );		/* ...from within pool... */
		assert( !hashIndex || \
				hashIndex == poolIndex );			/* ...before current pos.*/

		/* Copy SHA_CBLOCK - SHA_DIGEST_LENGTH bytes from position n + 20...
		   n + 64 from the circular pool into the hash data buffer */
		poolIndex = hashIndex + SHA_DIGEST_LENGTH;
		while( dataBufIndex < SHA_CBLOCK )
			{
			dataBuffer[ dataBufIndex / 4 ] = \
				( ( LONG ) randomInfo->randomPool[ poolIndex++ % RANDOMPOOL_SIZE ] << 24 ) | \
				( ( LONG ) randomInfo->randomPool[ poolIndex++ % RANDOMPOOL_SIZE ] << 16 ) | \
				( ( LONG ) randomInfo->randomPool[ poolIndex++ % RANDOMPOOL_SIZE ] << 8 ) | \
				( ( LONG ) randomInfo->randomPool[ poolIndex++ % RANDOMPOOL_SIZE ] );
			dataBufIndex += 4;
			}

		/* Postconditions for state data copy */
		assert( dataBufIndex == SHA_CBLOCK );		/* Got remain.44 bytes... */
		assert( poolIndex == hashIndex + SHA_CBLOCK );/* ...after current pos.*/

		/* Hash the data at position n...n + 19 in the circular pool using
		   the surrounding data extracted previously */
		digestPtr = randomInfo->randomPool + hashIndex;
		for( i = 0; i < SHA_DIGEST_LENGTH / 4; i++ )
			{
			digestLong[ i ] = mgetBLong( digestPtr );
			}
		SHA1Transform( digestLong, dataBuffer );
		digestPtr = randomInfo->randomPool + hashIndex;
		for( i = 0; i < SHA_DIGEST_LENGTH / 4; i++ )
			{
			mputBLong( digestPtr, digestLong[ i ] );
			}
		}
#else
	for( hashIndex = 0; hashIndex < RANDOMPOOL_SIZE; hashIndex += SHA_DIGEST_LENGTH )
		{
		int dataBufIndex, poolIndex;

		/* If we're at the start of the pool then the first block we hash is 
		   at the end of the pool, otherwise it's the block immediately
		   preceding the current one */
		poolIndex = hashIndex ? hashIndex - SHA_DIGEST_LENGTH : \
					RANDOMPOOL_SIZE - SHA_DIGEST_LENGTH;

		/* Copy SHA_DIGEST_LENGTH bytes from position n - 19...n - 1 in the
		   circular pool into the hash data buffer */
		for( dataBufIndex = 0; dataBufIndex < SHA_DIGEST_LENGTH; dataBufIndex++ )
			dataBuffer[ dataBufIndex ] = randomInfo->randomPool[ poolIndex++ ];

		/* Postconditions for chaining data copy */
		assert( dataBufIndex == SHA_DIGEST_LENGTH );/* Got 20 bytes... */
		assert( poolIndex >= SHA_DIGEST_LENGTH && \
				poolIndex <= RANDOMPOOL_SIZE );		/* ...from within pool... */
		assert( !hashIndex || \
				hashIndex == poolIndex );			/* ...before current pos.*/

		/* Copy SHA_CBLOCK - SHA_DIGEST_LENGTH bytes from position n + 20...
		   n + 64 from the circular pool into the hash data buffer */
		poolIndex = hashIndex + SHA_DIGEST_LENGTH;
		while( dataBufIndex < SHA_CBLOCK )
			dataBuffer[ dataBufIndex++ ] = \
						randomInfo->randomPool[ poolIndex++ % RANDOMPOOL_SIZE ];

		/* Postconditions for state data copy */
		assert( dataBufIndex == SHA_CBLOCK );		/* Got remain.44 bytes... */
		assert( poolIndex == hashIndex + SHA_CBLOCK );/* ...after current pos.*/

		/* Hash the data at position n...n + 19 in the circular pool using
		   the surrounding data extracted previously */
		SHA1Transform( ( LONG * ) ( randomInfo->randomPool + hashIndex ),
					   ( LONG * ) dataBuffer );
		}
#endif /* _BIG_WORDS */
	zeroise( dataBuffer, sizeof( dataBuffer ) );

	/* Postconditions for pool mixing */
	assert( hashIndex >= RANDOMPOOL_SIZE );		/* Entire pool was mixed */

	/* Increment the mix count and move the write position back to the start 
	   of the pool */
	if( randomInfo->randomPoolMixes < RANDOMPOOL_MIXES )
		randomInfo->randomPoolMixes++;
	randomInfo->randomPoolPos = 0;

	/* Postconditions for status update */
	assert( randomInfo->randomPoolMixes >= 1 );	/* Mixed at least once */
	assert( randomInfo->randomPoolPos == 0 );	/* Back to start of pool */
	}

/****************************************************************************
*																			*
*					Device Init/Shutdown/Device Control Routines			*
*																			*
****************************************************************************/

/* Mechanisms supported by the system device.  These are sorted in order of 
   frequency of use in order to make lookups a bit faster */

int derivePKCS5( void *dummy, MECHANISM_DERIVE_INFO *mechanismInfo );
int deriveSSL( void *dummy, MECHANISM_DERIVE_INFO *mechanismInfo );
int deriveTLS( void *dummy, MECHANISM_DERIVE_INFO *mechanismInfo );
int deriveCMP( void *dummy, MECHANISM_DERIVE_INFO *mechanismInfo );
int signPKCS1( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo );
int sigcheckPKCS1( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo );
int exportPKCS1( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo );
int importPKCS1( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo );
int exportCMS( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo );
int importCMS( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo );
int exportPrivateKey( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo );
int importPrivateKey( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo );

static const MECHANISM_FUNCTION_INFO mechanismFunctions[] = {
	{ RESOURCE_MESSAGE_DEV_EXPORT, MECHANISM_PKCS1, 
								( MECHANISM_FUNCTION ) exportPKCS1 },
	{ RESOURCE_MESSAGE_DEV_IMPORT, MECHANISM_PKCS1, 
								( MECHANISM_FUNCTION ) importPKCS1 },
	{ RESOURCE_MESSAGE_DEV_SIGN, MECHANISM_PKCS1, 
								( MECHANISM_FUNCTION ) signPKCS1 },
	{ RESOURCE_MESSAGE_DEV_SIGCHECK, MECHANISM_PKCS1, 
								( MECHANISM_FUNCTION ) sigcheckPKCS1 },
	{ RESOURCE_MESSAGE_DEV_EXPORT, MECHANISM_CMS, 
								( MECHANISM_FUNCTION ) exportCMS },
	{ RESOURCE_MESSAGE_DEV_IMPORT, MECHANISM_CMS, 
								( MECHANISM_FUNCTION ) importCMS },
	{ RESOURCE_MESSAGE_DEV_DERIVE, MECHANISM_PKCS5, 
								( MECHANISM_FUNCTION ) derivePKCS5 },
	{ RESOURCE_MESSAGE_DEV_DERIVE, MECHANISM_SSL, 
								( MECHANISM_FUNCTION ) deriveSSL },
	{ RESOURCE_MESSAGE_DEV_DERIVE, MECHANISM_TLS, 
								( MECHANISM_FUNCTION ) deriveTLS },
	{ RESOURCE_MESSAGE_DEV_DERIVE, MECHANISM_CMP, 
								( MECHANISM_FUNCTION ) deriveCMP },
	{ RESOURCE_MESSAGE_DEV_EXPORT, MECHANISM_PRIVATEKEYWRAP, 
								( MECHANISM_FUNCTION ) exportPrivateKey },
	{ RESOURCE_MESSAGE_DEV_IMPORT, MECHANISM_PRIVATEKEYWRAP, 
								( MECHANISM_FUNCTION ) importPrivateKey },
	{ RESOURCE_MESSAGE_NONE, MECHANISM_NONE, NULL }
	};

/* Object creation functions supported by the system device.  These are 
   sorted in order of frequency of use in order to make lookups a bit 
   faster */

int createContext( CREATEOBJECT_INFO *createInfo, const void *auxDataPtr, 
				   const int auxValue );
int createCertificate( CREATEOBJECT_INFO *createInfo, const void *auxDataPtr, 
					   const int auxValue );
int createEnvelope( CREATEOBJECT_INFO *createInfo, const void *auxDataPtr, 
					const int auxValue );
int createKeyset( CREATEOBJECT_INFO *createInfo, const void *auxDataPtr, 
				  const int auxValue );
int createDevice( CREATEOBJECT_INFO *createInfo, const void *auxDataPtr, 
				  const int auxValue );
int createSession( CREATEOBJECT_INFO *createInfo, const void *auxDataPtr, 
				   const int auxValue );

static const CREATEOBJECT_FUNCTION_INFO createObjectFunctions[] = {
	{ OBJECT_TYPE_CONTEXT, createContext }, 
	{ OBJECT_TYPE_CERTIFICATE, createCertificate }, 
	{ OBJECT_TYPE_ENVELOPE, createEnvelope },
	{ OBJECT_TYPE_KEYSET, createKeyset },
	{ OBJECT_TYPE_DEVICE, createDevice },
	{ OBJECT_TYPE_SESSION, createSession },
	{ OBJECT_TYPE_NONE, NULL }
	};

/* Initialise and shut down the system device */

static void shutdownDeviceFunction( DEVICE_INFO *deviceInfo )
	{
	/* Call any special-case shutdown functions */
	endRandomPolling();

	/* Delete the random data pool */
	if( deviceInfo->randomInfo != NULL )
		krnlMemfree( ( void ** ) &deviceInfo->randomInfo );
	}

static int initDeviceFunction( DEVICE_INFO *deviceInfo, const char *name,
							   const int nameLength )
	{
	STATIC_FN void initCapabilities( void );
	int status;

	UNUSED( name );

	/* Set up the random data pool */
	if( ( status = krnlMemalloc( ( void ** ) &deviceInfo->randomInfo,
								 sizeof( RANDOM_INFO ) ) ) != CRYPT_OK )
		return( status );
	initRandomPool( deviceInfo->randomInfo );
	initRandomPolling();

	/* Set up the capability information for this device and mark it as
	   active */
	initCapabilities();
	deviceInfo->flags = DEVICE_ACTIVE | DEVICE_LOGGEDIN;

	return( CRYPT_OK );
	}

/* Handle device control functions */

static int controlFunction( DEVICE_INFO *deviceInfo,
							const CRYPT_ATTRIBUTE_TYPE type,
							const void *data1, const int data1Length,
							const void *data2, const int data2Length )
	{
	RANDOM_INFO *randomInfo = deviceInfo->randomInfo;
	BYTE *buffer = ( BYTE * ) data1;
	int count = data1Length;

	assert( type == CRYPT_IATTRIBUTE_RANDOM || \
			type == CRYPT_IATTRIBUTE_RANDOM_QUALITY );

	/* Handle random data management */
	if( type == CRYPT_IATTRIBUTE_RANDOM )
		{
		/* Mix the incoming data into the pool.  This operation is resistant 
		   to chosen- and known-input attacks because the pool contents are
		   unknown to an attacker, so XOR'ing in known data won't help them.
		   In an attacker could determine pool contents by observing the
		   generator output (which is defeated by the postprocessing), we'd
		   have to perform an extra input mixing operation to defeat these
		   attacks */
		while( count-- )
			{
			if( randomInfo->randomPoolPos > RANDOMPOOL_SIZE - 1 ) 
				mixRandomPool( randomInfo ); 
			randomInfo->randomPool[ randomInfo->randomPoolPos++ ] ^= *buffer++; 
			}

		return( CRYPT_OK );
		}
	if( type == CRYPT_IATTRIBUTE_RANDOM_QUALITY )
		{
		if( randomInfo->randomQuality < 100 )
			randomInfo->randomQuality += data1Length;
		return( CRYPT_OK );
		}

#if 0
	/* Handle algorithm self-test */
	if( type == CRYPT_??? )
		{
		const CAPABILITY_INFO *capabilityInfoPtr = deviceInfo->capabilities;

		while( capabilityInfoPtr != NULL && \
			   capabilityInfoPtr->cryptAlgo != CRYPT_ALGO_NONE )
			{
			CRYPT_ALGO cryptAlgo = capabilityInfoPtr->cryptAlgo;

			assert( capabilityInfoPtr->selfTestFunction != NULL );

			/* Perform the self-test for this algorithm type and skip to the
			   next algorithm */
			status = capabilityInfoPtr->selfTestFunction();
			if( cryptStatusError( status ) )
				return( status );
			while( capabilityInfoPtr->cryptAlgo == cryptAlgo )
				capabilityInfoPtr = capabilityInfoPtr->next;
			}

		return( CRYPT_OK );
		}
#endif /* 0 */

	/* Anything else isn't handled */
	return( CRYPT_ARGERROR_VALUE );
	}

/****************************************************************************
*																			*
*						 	Misc.Device Interface Routines					*
*																			*
****************************************************************************/

/* Get a block of random data from the randomness pool in such a way that 
   compromise of the data doesn't compromise the pool, and vice versa.  This 
   is done by performing the (one-way) pool mixing operation on the pool, and 
   on a transformed version of the pool which becomes the key.  As an 
   additional precaution the key data is folded in half to ensure that not 
   even a hash of the previous contents is available.  No pool data ever 
   leaves the pool.
   
   This function performs a more paranoid version of the FIPS 140 continuous
   test on the pool contents, which will detect stuck-at faults and short
   cycles in the generator output.  In addition the higher-level message
   handler applies the FIPS 140 statistical tests to the output and will 
   retry the get if the output fails the tests (this is performed at the 
   higher level because it's then applied to all randomness sources used by
   cryptlib, not just the built-in one).
   
   Since the pool output is folded to mask the hash values, the output from
   each round of mixing is only half the pool size as defined below */

#define RANDOM_OUTPUTSIZE	( RANDOMPOOL_SIZE / 2 )

static int getRandomFunction( DEVICE_INFO *deviceInfo, void *buffer, 
							  const int length )
	{
	RANDOM_INFO *randomInfo = deviceInfo->randomInfo;
	RANDOM_INFO exportedRandomInfo;
	LONG sample;
	BYTE *bufPtr = buffer;
	int count;

	/* Clear the return value and make sure we fail the FIPS 140 tests on 
	   the output if there's a problem */
	zeroise( buffer, length );

	/* Precondition: We're not asking for more data than the maximum needed
	   in any cryptlib operation, which in this case is the size of a 
	   maximum-length PKC key */
	assert( length >= 1 && length <= CRYPT_MAX_PKCSIZE );

	/* Perform a failsafe check to make sure there's data available, this 
	   should only ever be called once per app because after the first 
	   blocking poll the programmer of the calling app will make sure there's
	   a slow poll done earlier on */
	if( randomInfo->randomQuality < 100 )
		slowPoll();

	/* Make sure any background randomness-gathering process has finished.  
	   Since the background poll will be injecting new data into the device,
	   we have to unlock it to avoid deadlock */
	unlockResource( deviceInfo );
	waitforRandomCompletion();
	lockResource( deviceInfo );

	/* If we still can't get any random information, let the user know */
	if( randomInfo->randomQuality < 100 )
		return( CRYPT_ERROR_RANDOM );

	/* If the process has forked, we need to restart the generator output
	   process, but we can't determine this until after we've already 
	   produced the output.  If we do need to restart, we do it from this
	   point */
restartPoint:

	/* Keep producing RANDOMPOOL_OUTPUTSIZE bytes of output until the request
	   is satisfied */
	for( count = 0; count < length; count += RANDOM_OUTPUTSIZE )
		{
		const int outputBytes = min( length - count, RANDOM_OUTPUTSIZE );
		int noRandomRetries, i;

		/* Precondition for output quantity: Either we're on the last output
		   block or we're producing the maximum-size output quantity, and
		   we're never trying to use more than half the pool contents */
		assert( length - count < RANDOM_OUTPUTSIZE || \
				outputBytes == RANDOM_OUTPUTSIZE );
		assert( outputBytes <= RANDOMPOOL_SIZE / 2 );

		/* Prepare to get data from the randomness pool.  Before we do this, 
		   we perform a final quick poll of the system to get any last bit of
		   entropy, and mix the entire pool.  If the pool hasn't been 
		   sufficiently mixed, we iterate until we've reached the minimum mix
		   count */
		do
			{
			fastPoll();
			mixRandomPool( randomInfo );
			randomInfo->randomPoolMixes++;
			}
		while( randomInfo->randomPoolMixes < RANDOMPOOL_MIXES );

		/* Precondition for drawing output from the generator: The pool is
		   sufficiently mixed and there's enough entropy present */
		assert( randomInfo->randomPoolMixes >= RANDOMPOOL_MIXES );
		assert( randomInfo->randomQuality >= 100 );

		for( noRandomRetries = 0; noRandomRetries < RANDOMPOOL_RETRIES; 
			 noRandomRetries++ )
			{
			const BYTE *samplePtr = randomInfo->randomPool;
			BOOLEAN repeatedOutput = FALSE;

			/* Initialise the copy of the random pool being used to generate 
			   the key and copy the main pool information across, 
			   transforming it as we go by flipping all the bits */
			initRandomPool( &exportedRandomInfo );
			for( i = 0; i < RANDOMPOOL_ALLOCSIZE; i++ )
				exportedRandomInfo.randomPool[ i ] = \
									randomInfo->randomPool[ i ] ^ 0xFF;

			/* Postcondition for the bit-flipping: The two pools differ and a
			   representative sample of pool bytes has the bits flipped as
			   expected */
			assert( memcmp( randomInfo->randomPool, 
							exportedRandomInfo.randomPool,
							RANDOMPOOL_ALLOCSIZE ) );
			assert( randomInfo->randomPool[ 0 ] == \
					( exportedRandomInfo.randomPool[ 0 ] ^ 0xFF ) &&
					randomInfo->randomPool[ 8 ] == \
					( exportedRandomInfo.randomPool[ 8 ] ^ 0xFF ) &&
					randomInfo->randomPool[ 16 ] == \
					( exportedRandomInfo.randomPool[ 16 ] ^ 0xFF ) &&
					randomInfo->randomPool[ 24 ] == \
					( exportedRandomInfo.randomPool[ 24 ] ^ 0xFF ) &&
					randomInfo->randomPool[ 32 ] == \
					( exportedRandomInfo.randomPool[ 32 ] ^ 0xFF ) );

			/* Mix the original and key pools so that neither can be 
			   recovered from the other */
			mixRandomPool( randomInfo );
			mixRandomPool( &exportedRandomInfo );

			/* Postcondition for the mixing: The two pools differ, and the
			   difference is more than just the bit flipping (this has a
			   1e-12 chance of a false positive and even that's only in the 
			   debug version) */
			assert( memcmp( randomInfo->randomPool, 
							exportedRandomInfo.randomPool, 
							RANDOMPOOL_ALLOCSIZE ) );
			assert( randomInfo->randomPool[ 0 ] != \
					( exportedRandomInfo.randomPool[ 0 ] ^ 0xFF ) ||
					randomInfo->randomPool[ 8 ] != \
					( exportedRandomInfo.randomPool[ 8 ] ^ 0xFF ) ||
					randomInfo->randomPool[ 16 ] == \
					( exportedRandomInfo.randomPool[ 16 ] ^ 0xFF ) ||
					randomInfo->randomPool[ 24 ] == \
					( exportedRandomInfo.randomPool[ 24 ] ^ 0xFF ) ||
					randomInfo->randomPool[ 32 ] == \
					( exportedRandomInfo.randomPool[ 32 ] ^ 0xFF ) );

			/* Precondition for sampling the output: It's a sample from the 
			   start of the pool */
			assert( samplePtr == randomInfo->randomPool );

			/* Check for stuck-at faults by comparing a short sample from the 
			   current output with samples from the previous 
			   RANDOMPOOL_SAMPLES outputs */
			sample = mgetLong( samplePtr );
			for( i = 0; i < RANDOMPOOL_SAMPLES; i++ )
				if( randomInfo->prevOutput[ i ] == sample )
					{
					repeatedOutput = TRUE;
					break;
					}
			if( !repeatedOutput )
				/* We aren't repeating any previous output, exit */
				break;
			}

		/* If we ran out of retries, we're repeating the same output data, 
		   fail */
		if( noRandomRetries >= RANDOMPOOL_RETRIES )
			{
			zeroise( &exportedRandomInfo, sizeof( RANDOM_INFO ) );

			/* Postcondition: Nulla vestigia retrorsum */
			assert( !memcmp( exportedRandomInfo.randomPool, 
							 "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16 ) );

			/* We can't trust the pool data any more so we set its quality 
			   estimate to zero.  Ideally we should flash lights and sound
			   klaxons as well, this is a catastrophic failure */
			randomInfo->randomQuality = 0;
			assert( NOTREACHED );
			return( CRYPT_ERROR_RANDOM );
			}

		/* Postcondition: We produced output without running out of retries */
		assert( noRandomRetries < RANDOMPOOL_RETRIES );

		/* Save a short sample from the current output for future checks */
		assert( randomInfo->prevOutputIndex >= 0 && \
				randomInfo->prevOutputIndex < RANDOMPOOL_SAMPLES );
		randomInfo->prevOutput[ randomInfo->prevOutputIndex++ ] = sample;
		randomInfo->prevOutputIndex %= RANDOMPOOL_SAMPLES;

		/* Copy the transformed data to the output buffer, folding it in half 
		   as we go to mask the original content */
		for( i = 0; i < outputBytes; i++ )
			bufPtr[ i ] = exportedRandomInfo.randomPool[ i ] ^ \
						  exportedRandomInfo.randomPool[ RANDOM_OUTPUTSIZE + i ];
		bufPtr += outputBytes;

		/* Postcondition: We're filling the output buffer, and we drew at 
		   most half the transformed output from the export pool */
		assert( ( bufPtr > ( BYTE * ) buffer ) && \
				( bufPtr <= ( BYTE * ) buffer + length ) );
		assert( i <= RANDOMPOOL_SIZE / 2 );
		}

	/* Check whether the process forked while we were generating output.  If
	   it did, force a complete remix of the pool and restart the output
	   generation process */
	if( checkForked() )
		{
		randomInfo->randomPoolMixes = 0;
		bufPtr = buffer;
		goto restartPoint;
		}

	/* Clean up */
	zeroise( &exportedRandomInfo, sizeof( RANDOM_INFO ) );

	/* Postcondition: Nulla vestigia retrorsum */
	assert( !memcmp( exportedRandomInfo.randomPool, 
					 "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16 ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Random Pool External Interface					*
*																			*
****************************************************************************/

/* Add random data to the random pool - this is due to be replaced by some 
   sort of device control mechanism */

C_RET cryptAddRandom( C_IN void C_PTR randomData, C_IN int randomDataLength )
	{
	BYTE *randomDataPtr = ( BYTE * ) randomData;

	/* Perform basic error checking */
	if( randomData == NULL )
		{
		if( randomDataLength != CRYPT_RANDOM_FASTPOLL && \
			randomDataLength != CRYPT_RANDOM_SLOWPOLL )
			return( CRYPT_ERROR_PARAM1 );
		}
	else
		{
		if( randomDataLength <= 0 )
			return( CRYPT_ERROR_PARAM2 );
		if( checkBadPtrRead( randomData, randomDataLength ) )
			return( CRYPT_ERROR_PARAM1 );
		}

	/* If we're adding data to the pool, add it now and exit.  Since the data
	   is of unknown provenance (and empirical evidence indicates that it 
	   won't be random at all) we give it a weight of zero for estimation
	   purposes */
	if( randomData != NULL )
		{
		RESOURCE_DATA msgData;

#ifndef NDEBUG	/* For debugging tests only */
{
int kludge = 100;
#ifndef __MAC__
printf( "Kludging randomness, file " __FILE__ ", line %d.\n", __LINE__ );
#endif /* __MAC__ */
krnlSendMessage( SYSTEM_OBJECT_HANDLE, RESOURCE_IMESSAGE_SETATTRIBUTE,
				 &kludge, CRYPT_IATTRIBUTE_RANDOM_QUALITY );
}
#endif /* NDEBUG */

		setResourceData( &msgData, randomDataPtr, randomDataLength );
		return( krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								 RESOURCE_IMESSAGE_SETATTRIBUTE_S,
								 &msgData, CRYPT_IATTRIBUTE_RANDOM ) );
		}

	/* Perform either a fast or slow poll for random system data */
	if( randomDataLength == CRYPT_RANDOM_FASTPOLL )
		fastPoll();
	else
		slowPoll();

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Device Capability Routines						*
*																			*
****************************************************************************/

/* The parameters of most encryption algorithms are traditionally specified
   in bits, so we define a shorter form of the bitsToBytes() macro to reduce
   the amount of blackspace */

#define bits(x)	bitsToBytes(x)

/* The loadIV() function is shared among all the built-in capabilities */

int loadIV( CRYPT_INFO *cryptInfoPtr, const void *iv, const int ivLength );

/* The functions used to implement the Blowfish encryption routines */

int blowfishSelfTest( void );
int blowfishInit( CRYPT_INFO *cryptInfo );
int blowfishEnd( CRYPT_INFO *cryptInfo );
int blowfishInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int blowfishEncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int blowfishDecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int blowfishEncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int blowfishDecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int blowfishEncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int blowfishDecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int blowfishEncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int blowfishDecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the CAST-128 encryption routines */

int castSelfTest( void );
int castInit( CRYPT_INFO *cryptInfo );
int castEnd( CRYPT_INFO *cryptInfo );
int castInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int castEncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int castDecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int castEncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int castDecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int castEncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int castDecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int castEncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int castDecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the DES encryption routines */

int desSelfTest( void );
int desInit( CRYPT_INFO *cryptInfo );
int desEnd( CRYPT_INFO *cryptInfo );
int desInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int desEncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desDecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desEncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desDecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desEncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desDecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desEncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int desDecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the triple DES encryption routines */

int des3SelfTest( void );
int des3Init( CRYPT_INFO *cryptInfo );
int des3End( CRYPT_INFO *cryptInfo );
int des3InitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int des3EncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3DecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3EncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3DecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3EncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3DecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3EncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int des3DecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the IDEA encryption routines */

int ideaSelfTest( void );
int ideaInit( CRYPT_INFO *cryptInfo );
int ideaEnd( CRYPT_INFO *cryptInfo );
int ideaInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int ideaEncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaDecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaEncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaDecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaEncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaDecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaEncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int ideaDecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement RC2 encryption routines */

int rc2SelfTest( void );
int rc2Init( CRYPT_INFO *cryptInfo );
int rc2End( CRYPT_INFO *cryptInfo );
int rc2InitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int rc2EncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc2DecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc2EncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc2DecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc2EncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc2DecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc2EncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc2DecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the RC4 encryption routines */

int rc4SelfTest( void );
int rc4Init( CRYPT_INFO *cryptInfo );
int rc4End( CRYPT_INFO *cryptInfo );
int rc4InitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int rc4Encrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement RC5 encryption routines */

int rc5SelfTest( void );
int rc5Init( CRYPT_INFO *cryptInfo );
int rc5End( CRYPT_INFO *cryptInfo );
int rc5InitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int rc5EncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc5DecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc5EncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc5DecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc5EncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc5DecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc5EncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rc5DecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the SAFER and SAFER_SK encryption
   routines */

int saferSelfTest( void );
int saferInit( CRYPT_INFO *cryptInfo );
int saferEnd( CRYPT_INFO *cryptInfo );
int saferInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int saferGetKeysize( CRYPT_INFO *cryptInfo );
int saferEncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int saferDecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int saferEncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int saferDecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int saferEncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int saferDecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int saferEncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int saferDecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the Skipjack encryption routines */

int skipjackSelfTest( void );
int skipjackInit( CRYPT_INFO *cryptInfo );
int skipjackEnd( CRYPT_INFO *cryptInfo );
int skipjackInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int skipjackEncryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int skipjackDecryptECB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int skipjackEncryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int skipjackDecryptCBC( CRYPT_INFO *cryptInfo, void *buffer, int length );
int skipjackEncryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int skipjackDecryptCFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int skipjackEncryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );
int skipjackDecryptOFB( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the Diffie-Hellman key exchange routines */

int dhSelfTest( void );
int dhInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int dhGenerateKey( CRYPT_INFO *cryptInfo, const int keySizeBits );
int dhEncrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );
int dhDecrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the DSA encryption routines */

int dsaSelfTest( void );
int dsaInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int dsaGenerateKey( CRYPT_INFO *cryptInfo, const int keySizeBits );
int dsaSign( CRYPT_INFO *cryptInfo, void *buffer, int length );
int dsaSigCheck( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the Elgamal encryption routines */

int elgamalSelfTest( void );
int elgamalInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int elgamalGenerateKey( CRYPT_INFO *cryptInfo, const int keySizeBits );
int elgamalEncrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );
int elgamalDecrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );
int elgamalSign( CRYPT_INFO *cryptInfo, void *buffer, int length );
int elgamalSigCheck( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the RSA encryption routines */

int rsaSelfTest( void );
int rsaInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int rsaGenerateKey( CRYPT_INFO *cryptInfo, const int keySizeBits );
int rsaEncrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );
int rsaDecrypt( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the MD2 hash routines */

int md2SelfTest( void );
int md2Init( CRYPT_INFO *cryptInfo );
int md2End( CRYPT_INFO *cryptInfo );
int md2Hash( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the MD4 hash routines */

int md4SelfTest( void );
int md4Init( CRYPT_INFO *cryptInfo );
int md4End( CRYPT_INFO *cryptInfo );
int md4Hash( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the MD5 hash routines */

int md5SelfTest( void );
int md5Init( CRYPT_INFO *cryptInfo );
int md5End( CRYPT_INFO *cryptInfo );
int md5Hash( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the MDC2 hash routines */

int mdc2SelfTest( void );
int mdc2Init( CRYPT_INFO *cryptInfo );
int mdc2End( CRYPT_INFO *cryptInfo );
int mdc2Hash( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the RIPEMD-160 hash routines */

int ripemd160SelfTest( void );
int ripemd160Init( CRYPT_INFO *cryptInfo );
int ripemd160End( CRYPT_INFO *cryptInfo );
int ripemd160Hash( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the SHA hash routines */

int shaSelfTest( void );
int shaInit( CRYPT_INFO *cryptInfo );
int shaEnd( CRYPT_INFO *cryptInfo );
int shaHash( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the HMAC-MD5 MAC routines */

int hmacMD5SelfTest( void );
int hmacMD5Init( CRYPT_INFO *cryptInfo );
int hmacMD5End( CRYPT_INFO *cryptInfo );
int hmacMD5InitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int hmacMD5Hash( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the HMAC-RIPEMD-160 MAC routines */

int hmacRIPEMD160SelfTest( void );
int hmacRIPEMD160Init( CRYPT_INFO *cryptInfo );
int hmacRIPEMD160End( CRYPT_INFO *cryptInfo );
int hmacRIPEMD160InitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int hmacRIPEMD160Hash( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The functions used to implement the HMAC-SHA MAC routines */

int hmacSHASelfTest( void );
int hmacSHAInit( CRYPT_INFO *cryptInfo );
int hmacSHAEnd( CRYPT_INFO *cryptInfo );
int hmacSHAInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int hmacSHAHash( CRYPT_INFO *cryptInfo, void *buffer, int length );

/* The encryption library intrinsic capability list */

static CAPABILITY_INFO FAR_BSS capabilities[] = {
	/* The DES capabilities */
	{ CRYPT_ALGO_DES, bits( 64 ), "DES",
		bits( 40 ), bits( 64 ), bits( 64 ), 
		desSelfTest, desInit, desEnd, loadIV, desInitKey, NULL, NULL, 
		desEncryptECB, desDecryptECB, desEncryptCBC, desDecryptCBC, 
		desEncryptCFB, desDecryptCFB, desEncryptOFB, desDecryptOFB },

	/* The triple DES capabilities.  Unlike the other algorithms, the minimum
	   key size here is 64 + 8 bits (nominally 56 + 1 bits) because using a
	   key any shorter is (a) no better than single DES, and (b) will result
	   in a key load error since the second key will be an all-zero weak
	   key.  We also give the default key size as 192 bits instead of 128 to
	   make sure that anyone using a key of the default size ends up with
	   three-key 3DES rather than two-key 3DES */
	{ CRYPT_ALGO_3DES, bits( 64 ), "3DES", 
		bits( 64 + 8 ), bits( 192 ), bits( 192 ), 
		des3SelfTest, des3Init, des3End, loadIV, des3InitKey, NULL, NULL, 
		des3EncryptECB, des3DecryptECB, des3EncryptCBC, des3DecryptCBC, 
		des3EncryptCFB, des3DecryptCFB, des3EncryptOFB, des3DecryptOFB },

#ifndef NO_IDEA
	/* The IDEA capabilities */
	{ CRYPT_ALGO_IDEA, bits( 64 ), "IDEA", 
		bits( 40 ), bits( 128 ), bits( 128 ), 
		ideaSelfTest, ideaInit, ideaEnd, loadIV, ideaInitKey, NULL, NULL, 
		ideaEncryptECB, ideaDecryptECB, ideaEncryptCBC, ideaDecryptCBC, 
		ideaEncryptCFB, ideaDecryptCFB, ideaEncryptOFB, ideaDecryptOFB },
#endif /* NO_IDEA */

#ifndef NO_CAST
	/* The CAST-128 capabilities */
	{ CRYPT_ALGO_CAST, bits( 64 ), "CAST-128",
		bits( 40 ), bits( 128 ), bits( 128 ), 
		castSelfTest, castInit, castEnd, loadIV, castInitKey, NULL, NULL, 
		castEncryptECB, castDecryptECB, castEncryptCBC, castDecryptCBC, 
		castEncryptCFB, castDecryptCFB, castEncryptOFB, castDecryptOFB },
#endif /* NO_CAST */

#ifndef NO_RC2
	/* The RC2 capabilities */
	{ CRYPT_ALGO_RC2, bits( 64 ), "RC2",
		bits( 40 ), bits( 128 ), bits( 1024 ), 
		rc2SelfTest, rc2Init, rc2End, loadIV, rc2InitKey, NULL, NULL, 
		rc2EncryptECB, rc2DecryptECB, rc2EncryptCBC, rc2DecryptCBC, 
		rc2EncryptCFB, rc2DecryptCFB, rc2EncryptOFB, rc2DecryptOFB },
#endif /* NO_RC2 */

#ifndef NO_RC4
	/* The RC4 capabilities */
	{ CRYPT_ALGO_RC4, bits( 8 ), "RC4",
		bits( 40 ), bits( 128 ), 256, 
		rc4SelfTest, rc4Init, rc4End, NULL, rc4InitKey, NULL, NULL, 
		NULL, NULL, NULL, NULL, NULL, NULL, rc4Encrypt, rc4Encrypt },
#endif /* NO_RC4 */

#ifndef NO_RC5
	/* The RC5 capabilities */
	{ CRYPT_ALGO_RC5, bits( 64 ), "RC5",
		bits( 40 ), bits( 128 ), bits( 832 ), 
		rc5SelfTest, rc5Init, rc5End, loadIV, rc5InitKey, NULL, NULL, 
		rc5EncryptECB, rc5DecryptECB, rc5EncryptCBC, rc5DecryptCBC, 
		rc5EncryptCFB, rc5DecryptCFB, rc5EncryptOFB, rc5DecryptOFB },
#endif /* NO_RC5 */

#ifndef NO_SAFER
	/* The SAFER capabilities */
	{ CRYPT_ALGO_SAFER, bits( 64 ), "SAFER",
		bits( 40 ), bits( 64 ), bits( 128 ), 
		saferSelfTest, saferInit, saferEnd, loadIV, saferInitKey, NULL, saferGetKeysize, 
		saferEncryptECB, saferDecryptECB, saferEncryptCBC, saferDecryptCBC, 
		saferEncryptCFB, saferDecryptCFB, saferEncryptOFB, saferDecryptOFB },
#endif /* NO_SAFER */

	/* The Blowfish capabilities */
	{ CRYPT_ALGO_BLOWFISH, bits( 64 ), "Blowfish",
		bits( 40 ), bits( 128 ), bits( 448 ), 
		blowfishSelfTest, blowfishInit, blowfishEnd, loadIV, blowfishInitKey, NULL, NULL, 
		blowfishEncryptECB, blowfishDecryptECB, blowfishEncryptCBC, blowfishDecryptCBC, 
		blowfishEncryptCFB, blowfishDecryptCFB, blowfishEncryptOFB, blowfishDecryptOFB },

#ifndef NO_SKIPJACK
	/* The Skipjack capabilities */
	{ CRYPT_ALGO_SKIPJACK, bits( 64 ), "Skipjack",
		bits( 80 ), bits( 80 ), bits( 80 ), 
		skipjackSelfTest, skipjackInit, skipjackEnd, loadIV, skipjackInitKey, NULL, NULL, 
		skipjackEncryptECB, skipjackDecryptECB, skipjackEncryptCBC, skipjackDecryptCBC, 
		skipjackEncryptCFB, skipjackDecryptCFB, skipjackEncryptOFB, skipjackDecryptOFB },
#endif /* NO_SKIPJACK */

	/* The MD2 capabilities */
	{ CRYPT_ALGO_MD2, bits( 128 ), "MD2", 
		bits( 0 ), bits( 0 ), bits( 0 ), 
		md2SelfTest, md2Init, md2End, NULL, NULL, NULL, NULL, md2Hash, md2Hash },

#ifndef NO_MD4
	/* The MD4 capabilities */
	{ CRYPT_ALGO_MD4, bits( 128 ), "MD4",
		bits( 0 ), bits( 0 ), bits( 0 ), 
		md4SelfTest, md4Init, md4End, NULL, NULL, NULL, NULL, md4Hash, md4Hash },
#endif /* NO_MD4 */

	/* The MD5 capabilities */
	{ CRYPT_ALGO_MD5, bits( 128 ), "MD5",
		bits( 0 ), bits( 0 ), bits( 0 ), 
		md5SelfTest, md5Init, md5End, NULL, NULL, NULL, NULL, md5Hash, md5Hash },

	/* The SHA capabilities */
	{ CRYPT_ALGO_SHA, bits( 160 ), "SHA",
		bits( 0 ), bits( 0 ), bits( 0 ), 
		shaSelfTest, shaInit, shaEnd, NULL, NULL, NULL, NULL, shaHash, shaHash },

	/* The RIPEMD-160 capabilities */
	{ CRYPT_ALGO_RIPEMD160, bits( 160 ), "RIPEMD-160",
		bits( 0 ), bits( 0 ), bits( 0 ), 
		ripemd160SelfTest, ripemd160Init, ripemd160End, NULL, NULL, NULL, NULL, 
		ripemd160Hash, ripemd160Hash },

#ifndef NO_MDC2
	/* The MDC-2 capabilities */
	{ CRYPT_ALGO_MDC2, bits( 128 ), "MDC-2",
		bits( 0 ), bits( 0 ), bits( 0 ), 
		mdc2SelfTest, mdc2Init, mdc2End, NULL, NULL, NULL, NULL, mdc2Hash, mdc2Hash },
#endif /* NO_MDC2 */

#ifndef NO_HMAC_MD5
	/* The HMAC-MD5 capabilities */
	{ CRYPT_ALGO_HMAC_MD5, bits( 128 ), "HMAC-MD5",
		bits( 40 ), bits( 128 ), CRYPT_MAX_KEYSIZE, 
		hmacMD5SelfTest, hmacMD5Init, hmacMD5End, NULL, hmacMD5InitKey,
		NULL, NULL, hmacMD5Hash, hmacMD5Hash },
#endif /* NO_HMAC_MD5 */

	/* The HMAC-SHA capabilities */
	{ CRYPT_ALGO_HMAC_SHA, bits( 160 ), "HMAC-SHA",
		bits( 40 ), bits( 128 ), CRYPT_MAX_KEYSIZE, 
		hmacSHASelfTest, hmacSHAInit, hmacSHAEnd, NULL, hmacSHAInitKey,
		NULL, NULL, hmacSHAHash, hmacSHAHash },

#ifndef NO_HMAC_RIPEMD160
	/* The HMAC-RIPEMD160 capabilities */
	{ CRYPT_ALGO_HMAC_RIPEMD160, bits( 160 ), "HMAC-RIPEMD160",
		bits( 40 ), bits( 128 ), CRYPT_MAX_KEYSIZE, 
		hmacRIPEMD160SelfTest, hmacRIPEMD160Init, hmacRIPEMD160End, NULL, hmacRIPEMD160InitKey,
		NULL, NULL, hmacRIPEMD160Hash, hmacRIPEMD160Hash },
#endif /* NO_HMAC_RIPEMD160 */

	/* The Diffie-Hellman capabilities */
	{ CRYPT_ALGO_DH, bits( 0 ), "Diffie-Hellman",
		bits( 512 ), bits( 1024 ), CRYPT_MAX_PKCSIZE, 
		dhSelfTest, NULL, NULL, NULL, dhInitKey, dhGenerateKey, NULL, 
		dhEncrypt, dhDecrypt },

	/* The RSA capabilities */
	{ CRYPT_ALGO_RSA, bits( 0 ), "RSA",
		bits( 512 ), bits( 1024 ), CRYPT_MAX_PKCSIZE, 
		rsaSelfTest, NULL, NULL, NULL, rsaInitKey, rsaGenerateKey, NULL, 
		rsaEncrypt, rsaDecrypt, NULL, NULL, NULL, NULL, NULL, NULL, 
		rsaDecrypt, rsaEncrypt },

	/* The DSA capabilities */
	{ CRYPT_ALGO_DSA, bits( 0 ), "DSA",
		bits( 512 ), bits( 1024 ), CRYPT_MAX_PKCSIZE, 
		dsaSelfTest, NULL, NULL, NULL, dsaInitKey, dsaGenerateKey, NULL, 
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
		dsaSign, dsaSigCheck },

#ifndef NO_ELGAMAL
	/* The ElGamal capabilities */
	{ CRYPT_ALGO_ELGAMAL, bits( 0 ), "Elgamal",
		bits( 512 ), bits( 1024 ), CRYPT_MAX_PKCSIZE, 
		elgamalSelfTest, NULL, NULL, NULL, elgamalInitKey, elgamalGenerateKey, NULL, 
		elgamalEncrypt, elgamalDecrypt, NULL, NULL, NULL, NULL, NULL, NULL, 
		elgamalSign, elgamalSigCheck },
#endif /* NO_ELGAMAL */

	/* Vendors may want to use their own algorithms which aren't part of the
	   general cryptlib suite.  The following includes the ability to include
	   vendor-specific algorithm capabilities defined in the file
	   vendalgo.c */
#ifdef USE_VENDOR_ALGOS
	#include "vendalgo.c"
#endif /* USE_VENDOR_ALGOS */

	/* The end-of-list marker */
	{ CRYPT_ALGO_NONE }
	};

/* Initialise the capability info */

static void initCapabilities( void )
	{
	CAPABILITY_INFO *prevCapabilityInfoPtr = NULL;
	int i;

	/* Perform a consistency check on the encryption mode values, which
	   are used to index a table of per-mode function pointers */
	assert( CRYPT_MODE_CBC == CRYPT_MODE_ECB + 1 && \
			CRYPT_MODE_CFB == CRYPT_MODE_CBC + 1 && \
			CRYPT_MODE_OFB == CRYPT_MODE_CFB + 1 && \
			CRYPT_MODE_LAST == CRYPT_MODE_OFB + 1 );

	for( i = 0; capabilities[ i ].cryptAlgo != CRYPT_ALGO_NONE; i++ )
		{
		assert( capabilityInfoOK( &capabilities[ i ] ) );
		if( prevCapabilityInfoPtr != NULL )
			prevCapabilityInfoPtr->next = &capabilities[ i ];
		prevCapabilityInfoPtr = &capabilities[ i ];
		}
	}

/****************************************************************************
*																			*
*						 	Device Access Routines							*
*																			*
****************************************************************************/

/* Set up the function pointers to the device methods */

int setDeviceSystem( DEVICE_INFO *deviceInfo )
	{
	deviceInfo->initDeviceFunction = initDeviceFunction;
	deviceInfo->shutdownDeviceFunction = shutdownDeviceFunction;
	deviceInfo->controlFunction = controlFunction;
	deviceInfo->getRandomFunction = getRandomFunction;
	deviceInfo->capabilityInfo = capabilities;
	deviceInfo->createObjectFunctions = createObjectFunctions;
	deviceInfo->mechanismFunctions = mechanismFunctions;

	return( CRYPT_OK );
	}
