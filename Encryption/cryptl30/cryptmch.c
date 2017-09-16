/****************************************************************************
*																			*
*						  cryptlib Mechanism Routines						*
*						Copyright Peter Gutmann 1992-1999					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "asn1objs.h"
#else
  #include "keymgmt/asn1objs.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* The length of the input data for PKCS #1 transformations is usually 
   determined by the key size, however sometimes we can be passed data which 
   has been zero-padded (for example data coming from an ASN.1 INTEGER in 
   which the high bit is a sign bit) making it longer than the key size, or 
   which has zero high byte(s), making it shorter than the key size.  The 
   best place to handle this is somewhat uncertain, it's an encoding issue 
   so it probably shouldn't be visible to the raw crypto routines, but 
   putting it at the mechanism layer removes the algorithm-independence of
   that layer, and putting it at the mid-level sign/key-exchange routine
   layer both removes the algorithm-independence and requires duplication of
   the code for signatures and encryption.  The best place to put it seems to
   be at the mechanism layer, since an encoding issue really shouldn't be
   visible at the crypto layer, and because it would require duplicating the
   handling every time a new PKC implementation is plugged in.

   The intent of the size adjustment is to make the data size match the key
   length.  If it's longer, we try to strip leading zero bytes.  If it's
   shorter, we pad it with zero bytes to match the key size.  The result is
   either the data adjusted to match the key size, or CRYPT_ERROR_BADDATA if
   this isn't possible */

static int adjustPKCS1Data( BYTE *outData, const BYTE *inData, 
							const int inLength, const int keySize )
	{
	int length = inLength;

	/* If it's of the correct size, exit */
	if( length == keySize )
		{
		memcpy( outData, inData, keySize );
		return( CRYPT_OK );
		}

	/* If it's too long, try and strip leading zero bytes.  If it's still too
	   long, complain */
	while( length > keySize && !*inData )
		{
		length--;
		inData++;
		}
	if( length > keySize )
		return( CRYPT_ERROR_BADDATA );

	/* We've adjusted the size to account for zero-padding during encoding, 
	   now we have to move the data into a fixed-length format to match the 
	   key size.  To do this we copy the payload into the output buffer with
	   enough leading-zero bytes to bring the total size up to the key size */
	memset( outData, 0, 16 );
	memcpy( outData + ( keySize - length ), inData, length );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Key Derivation Mechanisms						*
*																			*
****************************************************************************/

/* HMAC-based PRF used for PKCS #5 v2 and TLS */

#define HMAC_DATASIZE		64

static void prfInit( HASHFUNCTION hashFunction, void *hashState, 
					 const int hashSize, void *processedKey, 
					 int *processedKeyLength, const void *key, 
					 const int keyLength )
	{
	BYTE hashBuffer[ HMAC_DATASIZE ], *keyPtr = processedKey;
	int i;

	/* If the key size is larger than tha SHA data size, reduce it to the
	   SHA hash size before processing it (yuck.  You're required to do this
	   though) */
	if( keyLength > HMAC_DATASIZE )
		{
		/* Hash the user key down to the hash size and use the hashed form of
		   the key */
		hashFunction( NULL, processedKey, ( void * ) key, keyLength, HASH_ALL );
		*processedKeyLength = hashSize;
		}
	else
		{
		/* Copy the key to internal storage */
		memcpy( processedKey, key, keyLength );
		*processedKeyLength = keyLength;
		}

	/* Perform the start of the inner hash using the zero-padded key XOR'd
	   with the ipad value */
	memset( hashBuffer, HMAC_IPAD, HMAC_DATASIZE );
	for( i = 0; i < *processedKeyLength; i++ )
		hashBuffer[ i ] ^= *keyPtr++;
	hashFunction( hashState, NULL, hashBuffer, HMAC_DATASIZE, HASH_START );
	zeroise( hashBuffer, HMAC_DATASIZE );
	}

static void prfEnd( HASHFUNCTION hashFunction, void *hashState, 
					const int hashSize, void *hash, 
					const void *processedKey, const int processedKeyLength )
	{
	BYTE hashBuffer[ HMAC_DATASIZE ], digestBuffer[ CRYPT_MAX_HASHSIZE ];
	int i;

	/* Complete the inner hash and extract the digest */
	hashFunction( hashState, digestBuffer, NULL, 0, HASH_END );

	/* Perform the outer hash using the zero-padded key XOR'd with the opad 
	   value followed by the digest from the inner hash */
	memset( hashBuffer, HMAC_OPAD, HMAC_DATASIZE );
	memcpy( hashBuffer, processedKey, processedKeyLength );
	for( i = 0; i < processedKeyLength; i++ )
		hashBuffer[ i ] ^= HMAC_OPAD;
	hashFunction( hashState, NULL, hashBuffer, HMAC_DATASIZE, HASH_START );
	zeroise( hashBuffer, HMAC_DATASIZE );
	hashFunction( hashState, hash, digestBuffer, hashSize, HASH_END );
	zeroise( digestBuffer, CRYPT_MAX_HASHSIZE );
	}

/* Perform PKCS #5 v2 derivation */

int derivePKCS5( void *dummy, MECHANISM_DERIVE_INFO *mechanismInfo )
	{
	HASHFUNCTION hashFunction;
	BYTE hashInfo[ MAX_HASHINFO_SIZE ], initialHashInfo[ MAX_HASHINFO_SIZE ];
	BYTE processedKey[ HMAC_DATASIZE ], block[ CRYPT_MAX_HASHSIZE ];
	BYTE countBuffer[ 4 ];
	BYTE *dataOutPtr = mechanismInfo->dataOut;
	int hashSize, keyIndex, processedKeyLength, blockCount = 1;

	UNUSED( dummy );

	/* Sanity check the input data */
	assert( mechanismInfo->dataIn != NULL );
	assert( mechanismInfo->dataInLength >= 1 );
	assert( mechanismInfo->dataOut != NULL );
	assert( mechanismInfo->dataOutLength >= 4 && \
			mechanismInfo->dataOutLength <= 512 );
	assert( mechanismInfo->saltLength >= 4 && \
			mechanismInfo->saltLength <= 512 );
	assert( mechanismInfo->iterations >= 1 );

	/* Set up the block counter buffer.  This will never have more than the
	   last few bits set (8 bits = 5100 bytes of key) so we only change the
	   last byte */
	memset( countBuffer, 0, 4 );

	/* Initialise the SHA-1 information with the user key.  This is reused
	   for any future hashing since it's constant */
	getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );
	prfInit( hashFunction, initialHashInfo, hashSize, 
			 processedKey, &processedKeyLength,
			 mechanismInfo->dataIn, mechanismInfo->dataInLength );

	/* Produce enough blocks of output to fill the key */
	for( keyIndex = 0; keyIndex < mechanismInfo->dataOutLength; 
		 keyIndex += hashSize, dataOutPtr += hashSize )
		{
		const int noKeyBytes = \
			( mechanismInfo->dataOutLength - keyIndex > hashSize ) ? \
			hashSize : mechanismInfo->dataOutLength - keyIndex;
		int i;

		/* Calculate HMAC( salt || counter ) */
		countBuffer[ 3 ] = ( BYTE ) blockCount++;
		memcpy( hashInfo, initialHashInfo, MAX_HASHINFO_SIZE );
		hashFunction( hashInfo, NULL, mechanismInfo->salt,
					  mechanismInfo->saltLength, HASH_CONTINUE );
		hashFunction( hashInfo, NULL, countBuffer, 4, HASH_CONTINUE );
		prfEnd( hashFunction, hashInfo, hashSize, block, processedKey, 
				processedKeyLength );
		memcpy( dataOutPtr, block, noKeyBytes );

		/* Calculate HMAC( T1 ) ^ HMAC( T1 ) ^ ... HMAC( Tc ) */
		for( i = 0; i < mechanismInfo->iterations - 1; i++ )
			{
			int j;

			/* Generate the PRF output for the current iteration */
			memcpy( hashInfo, initialHashInfo, MAX_HASHINFO_SIZE );
			hashFunction( hashInfo, NULL, block, hashSize, HASH_CONTINUE );
			prfEnd( hashFunction, hashInfo, hashSize, block, processedKey, 
					processedKeyLength );

			/* Xor the new PRF output into the existing PRF output */
			for( j = 0; j < noKeyBytes; j++ )
				dataOutPtr[ j ] ^= block[ j ];
			}
		}
	zeroise( hashInfo, MAX_HASHINFO_SIZE );
	zeroise( initialHashInfo, MAX_HASHINFO_SIZE );
	zeroise( processedKey, HMAC_DATASIZE );
	zeroise( block, CRYPT_MAX_HASHSIZE );

	return( CRYPT_OK );
	}

/* Perform SSL key derivation */

int deriveSSL( void *dummy, MECHANISM_DERIVE_INFO *mechanismInfo )
	{
	HASHFUNCTION md5HashFunction, shaHashFunction;
	BYTE hashInfo[ MAX_HASHINFO_SIZE ], hash[ CRYPT_MAX_HASHSIZE ];
	BYTE counterData[ 16 ];
	int md5HashSize, shaHashSize, counter = 0, keyIndex;

	UNUSED( dummy );

	/* Sanity check the input data */
	assert( mechanismInfo->dataIn != NULL );
	assert( mechanismInfo->dataInLength >= 48 && \
			mechanismInfo->dataInLength <= 512 );
	assert( mechanismInfo->dataOutLength >= 48 && \
			mechanismInfo->dataOutLength <= 512 );
	assert( mechanismInfo->saltLength == 64 );
	assert( mechanismInfo->iterations == 1 );

	getHashParameters( CRYPT_ALGO_MD5, &md5HashFunction, &md5HashSize );
	getHashParameters( CRYPT_ALGO_SHA, &shaHashFunction, &shaHashSize );

	/* Produce enough blocks of output to fill the key */
	for( keyIndex = 0; keyIndex < mechanismInfo->dataOutLength; 
		 keyIndex += md5HashSize )
		{
		const int noKeyBytes = \
			( mechanismInfo->dataOutLength - keyIndex > md5HashSize ) ? \
			md5HashSize : mechanismInfo->dataOutLength - keyIndex;
		int i;

		/* Set up the counter data */
		for( i = 0; i <= counter; i++ )
			counterData[ i ] = 'A' + counter;
		counter++;

		/* Calculate SHA1( 'A'/'BB'/'CCC'/... || keyData || salt ) */
		shaHashFunction( hashInfo, NULL, counterData, counter, HASH_START );
		shaHashFunction( hashInfo, NULL, mechanismInfo->dataIn, 
						 mechanismInfo->dataInLength, HASH_CONTINUE );
		shaHashFunction( hashInfo, hash, mechanismInfo->salt, 
						 mechanismInfo->saltLength, HASH_END );

		/* Calculate MD5( keyData || SHA1-hash ) */
		md5HashFunction( hashInfo, NULL, mechanismInfo->dataIn, 
						 mechanismInfo->dataInLength, HASH_START );
		md5HashFunction( hashInfo, hash, hash, shaHashSize, HASH_START );

		/* Copy the result to the output */
		memcpy( ( BYTE * )( mechanismInfo->dataOut ) + keyIndex, hash, noKeyBytes );
		}
	zeroise( hashInfo, MAX_HASHINFO_SIZE );
	zeroise( hash, CRYPT_MAX_HASHSIZE );

	return( CRYPT_OK );
	}

/* Perform TLS key derivation */

int deriveTLS( void *dummy, MECHANISM_DERIVE_INFO *mechanismInfo )
	{
	HASHFUNCTION md5HashFunction, shaHashFunction;
	BYTE md5HashInfo[ MAX_HASHINFO_SIZE ];
	BYTE md5InitialHashInfo[ MAX_HASHINFO_SIZE ];
	BYTE md5AnHashInfo[ MAX_HASHINFO_SIZE ];
	BYTE shaHashInfo[ MAX_HASHINFO_SIZE ];
	BYTE shaInitialHashInfo[ MAX_HASHINFO_SIZE ];
	BYTE shaAnHashInfo[ MAX_HASHINFO_SIZE ];
	BYTE md5ProcessedKey[ HMAC_DATASIZE ], shaProcessedKey[ HMAC_DATASIZE ];
	BYTE md5A[ CRYPT_MAX_HASHSIZE ], shaA[ CRYPT_MAX_HASHSIZE ];
	BYTE md5Hash[ CRYPT_MAX_HASHSIZE ], shaHash[ CRYPT_MAX_HASHSIZE ];
	BYTE *md5DataOutPtr = mechanismInfo->dataOut;
	BYTE *shaDataOutPtr = mechanismInfo->dataOut;
	const BYTE *dataEndPtr = ( BYTE * ) mechanismInfo->dataOut + \
							 mechanismInfo->dataOutLength;
	void *s1, *s2;
	const int sLen = ( mechanismInfo->dataInLength + 1 ) / 2;
	int md5ProcessedKeyLength, shaProcessedKeyLength;
	int md5HashSize, shaHashSize, counter = 0, keyIndex;

	UNUSED( dummy );

	/* Sanity check the input data */
	assert( mechanismInfo->dataIn != NULL );
	assert( mechanismInfo->dataInLength >= 48 && \
			mechanismInfo->dataInLength <= 512 );
	assert( mechanismInfo->dataOutLength >= 48 && \
			mechanismInfo->dataOutLength <= 512 );
	assert( mechanismInfo->saltLength > 64 );
	assert( mechanismInfo->iterations == 1 );

	getHashParameters( CRYPT_ALGO_MD5, &md5HashFunction, &md5HashSize );
	getHashParameters( CRYPT_ALGO_SHA, &shaHashFunction, &shaHashSize );

	/* Find the start of the two halves of the keying info used for the 
	   HMAC'ing.  The size of each half is given by 
	   ceil( dataInLength / 2 ), so there's a one-byte overlap if the input
	   is an odd number of bytes long */
	s1 = mechanismInfo->dataIn;
	s2 = ( BYTE * ) mechanismInfo->dataIn + ( mechanismInfo->dataInLength - sLen );

	/* The two hash functions have different block sizes which would require
	   complex buffering to handle leftover bytes from SHA-1, a simpler
	   method is to zero the output data block and XOR in the values from 
	   each hash mechanism using separate output location indices for MD5 and
	   SHA-1 */
	memset( mechanismInfo->dataOut, 0, mechanismInfo->dataOutLength );

	/* Initialise the MD5 and SHA-1 information with the keying info.  These
	   are reused for any future hashing since they're constant */
	prfInit( md5HashFunction, md5InitialHashInfo, md5HashSize, 
			 md5ProcessedKey, &md5ProcessedKeyLength, s1, sLen );
	prfInit( shaHashFunction, shaInitialHashInfo, shaHashSize, 
			 shaProcessedKey, &shaProcessedKeyLength, s2, sLen );

	/* Calculate A1 = HMAC( salt ) */
	memcpy( md5HashInfo, md5InitialHashInfo, MAX_HASHINFO_SIZE );
	md5HashFunction( md5HashInfo, NULL, mechanismInfo->salt, 
					 mechanismInfo->saltLength, HASH_CONTINUE );
	prfEnd( md5HashFunction, md5HashInfo, md5HashSize, md5A, 
			md5ProcessedKey, md5ProcessedKeyLength );
	memcpy( shaHashInfo, shaInitialHashInfo, MAX_HASHINFO_SIZE );
	shaHashFunction( shaHashInfo, NULL, mechanismInfo->salt, 
					 mechanismInfo->saltLength, HASH_CONTINUE );
	prfEnd( shaHashFunction, shaHashInfo, shaHashSize, shaA, 
			shaProcessedKey, shaProcessedKeyLength );

	/* Produce enough blocks of output to fill the key.  We use the MD5 hash
	   size as the loop increment since this produces the smaller output
	   block */
	for( keyIndex = 0; keyIndex < mechanismInfo->dataOutLength; 
		 keyIndex += md5HashSize )
		{
		const int md5NoKeyBytes = \
					min( ( dataEndPtr - md5DataOutPtr ), md5HashSize );
		const int shaNoKeyBytes = \
					min( ( dataEndPtr - shaDataOutPtr ), shaHashSize );
		int i;		/* Spurious ()'s needed for broken compilers */

		/* Calculate HMAC( An || salt ) */
		memcpy( md5HashInfo, md5InitialHashInfo, MAX_HASHINFO_SIZE );
		md5HashFunction( md5HashInfo, NULL, md5A, md5HashSize, HASH_CONTINUE );
		memcpy( md5AnHashInfo, md5HashInfo, MAX_HASHINFO_SIZE );
		md5HashFunction( md5HashInfo, NULL, mechanismInfo->salt, 
						 mechanismInfo->saltLength, HASH_CONTINUE );
		prfEnd( md5HashFunction, md5HashInfo, md5HashSize, md5Hash, 
				md5ProcessedKey, md5ProcessedKeyLength );
		memcpy( shaHashInfo, shaInitialHashInfo, MAX_HASHINFO_SIZE );
		shaHashFunction( shaHashInfo, NULL, shaA, shaHashSize, HASH_CONTINUE );
		memcpy( shaAnHashInfo, shaHashInfo, MAX_HASHINFO_SIZE );
		shaHashFunction( shaHashInfo, NULL, mechanismInfo->salt, 
						 mechanismInfo->saltLength, HASH_CONTINUE );
		prfEnd( shaHashFunction, shaHashInfo, shaHashSize, shaHash, 
				shaProcessedKey, shaProcessedKeyLength );

		/* Calculate An+1 = HMAC( An ) */
		memcpy( md5HashInfo, md5AnHashInfo, MAX_HASHINFO_SIZE );
		prfEnd( md5HashFunction, md5HashInfo, md5HashSize, md5A, 
				md5ProcessedKey, md5ProcessedKeyLength );
		memcpy( shaHashInfo, shaAnHashInfo, MAX_HASHINFO_SIZE );
		prfEnd( shaHashFunction, shaHashInfo, shaHashSize, shaA, 
				shaProcessedKey, shaProcessedKeyLength );

		/* Copy the result to the output */
		for( i = 0; i < md5NoKeyBytes; i++ )
			md5DataOutPtr[ i ] ^= md5Hash[ i ];
		for( i = 0; i < shaNoKeyBytes; i++ )
			shaDataOutPtr[ i ] ^= shaHash[ i ];
		md5DataOutPtr += md5NoKeyBytes;
		shaDataOutPtr += shaNoKeyBytes;
		}
	zeroise( md5HashInfo, MAX_HASHINFO_SIZE );
	zeroise( md5InitialHashInfo, MAX_HASHINFO_SIZE );
	zeroise( md5AnHashInfo, MAX_HASHINFO_SIZE );
	zeroise( shaHashInfo, MAX_HASHINFO_SIZE );
	zeroise( shaInitialHashInfo, MAX_HASHINFO_SIZE );
	zeroise( shaAnHashInfo, MAX_HASHINFO_SIZE );
	zeroise( md5ProcessedKey, HMAC_DATASIZE );
	zeroise( shaProcessedKey, HMAC_DATASIZE );
	zeroise( md5A, CRYPT_MAX_HASHSIZE );
	zeroise( shaA, CRYPT_MAX_HASHSIZE );

	return( CRYPT_OK );
	}

/* Perform CMP/Entrust key derivation */

int deriveCMP( void *dummy, MECHANISM_DERIVE_INFO *mechanismInfo )
	{
	HASHFUNCTION hashFunction;
	BYTE hashInfo[ MAX_HASHINFO_SIZE ];
	int hashSize, iterations = mechanismInfo->iterations - 1;

	UNUSED( dummy );

	/* Sanity check the input data */
	assert( mechanismInfo->dataIn != NULL );
	assert( mechanismInfo->dataInLength >= 1 && \
			mechanismInfo->dataInLength <= 512 );
	assert( mechanismInfo->dataOut != NULL );
	assert( mechanismInfo->dataOutLength == 20 );
	assert( mechanismInfo->saltLength >= 1 && \
			mechanismInfo->saltLength <= 512 );
	assert( mechanismInfo->iterations >= 1 );

	/* Calculate SHA1( password || salt ) */
	getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );
	hashFunction( hashInfo, NULL, mechanismInfo->dataIn, 
				  mechanismInfo->dataInLength, HASH_START );
	hashFunction( hashInfo, mechanismInfo->dataOut, mechanismInfo->salt, 
				  mechanismInfo->saltLength, HASH_END );

	/* Iterate the hashing the required number of times */
	while( iterations-- )
		hashFunction( NULL, mechanismInfo->dataOut, mechanismInfo->dataOut, 
					  hashSize, HASH_START );
	zeroise( hashInfo, MAX_HASHINFO_SIZE );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Signature Mechanisms 						*
*																			*
****************************************************************************/

/* Perform PKCS #1 signing */

int signPKCS1( void *dummy, MECHANISM_SIGN_INFO *mechanismInfo )
	{
	STREAM stream;
	int payloadSize, length, i, status;

	UNUSED( dummy );

	/* Sanity check the input data */
	assert( ( mechanismInfo->signature == NULL && \
			  mechanismInfo->signatureLength == 0 ) || \
			( mechanismInfo->signatureLength >= 64 ) );
	assert( mechanismInfo->hash != NULL );
	assert( mechanismInfo->hashLength >= 16 );
	assert( mechanismInfo->hashAlgo >= CRYPT_ALGO_FIRST_HASH && \
			mechanismInfo->hashAlgo <= CRYPT_ALGO_LAST_HASH );
	assert( mechanismInfo->hashContext == CRYPT_UNUSED );

	/* Clear the return value */
	if( mechanismInfo->signature != NULL )
		memset( mechanismInfo->signature, 0, 
				mechanismInfo->signatureLength );

	/* Get various algorithm parameters */
	payloadSize = sizeofMessageDigest( mechanismInfo->hashAlgo, 
									   mechanismInfo->hashLength );
	status = krnlSendMessage( mechanismInfo->signContext, 
							  RESOURCE_IMESSAGE_GETATTRIBUTE, &length, 
							  CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* If this is just a length check, we're done */
	if( mechanismInfo->signature == NULL )
		{
		CRYPT_ALGO signAlgo;

		/* In the case of the DLP-based PKC's the signature length is just an 
		   estimate since it can change by up to two bytes depending on 
		   whether the signature values have the high bit set or not, which 
		   requires zero-padding of the ASN.1-encoded integers.  This is 
		   rather nasty because it means we can't tell how large a signature 
		   will be without actually creating it.

		   The 10 bytes at the start are for the ASN.1 SEQUENCE and 2 * INTEGER 
		   encoding */
		status = krnlSendMessage( mechanismInfo->signContext,
								  RESOURCE_IMESSAGE_GETATTRIBUTE, &signAlgo, 
								  CRYPT_CTXINFO_ALGO );
		if( cryptStatusError( status ) )
			return( status );
		if( signAlgo == CRYPT_ALGO_ELGAMAL )
			length = 10 + ( 2 * ( length + 1 ) );

		mechanismInfo->signatureLength = length;
		return( CRYPT_OK );
		}

	/* Encode the payload using the format given in PKCS #1.  The format for
	   signed data is [ 0 ][ 1 ][ 0xFF padding ][ 0 ][ payload ] which is
	   created by the following code */
	sMemOpen( &stream, mechanismInfo->signature, 
			  mechanismInfo->signatureLength );
	sputc( &stream, 0 );
	sputc( &stream, 1 );
	for( i = 0; i < length - ( payloadSize + 3 ); i++ )
		sputc( &stream, 0xFF );
	sputc( &stream, 0 );
	writeMessageDigest( &stream, mechanismInfo->hashAlgo, mechanismInfo->hash, 
						mechanismInfo->hashLength );
	sMemDisconnect( &stream );

	/* Sign the data */
	status = krnlSendMessage( mechanismInfo->signContext, 
							  RESOURCE_IMESSAGE_CTX_SIGN, 
							  mechanismInfo->signature, length );
	if( cryptStatusError( status ) )
		return( status );
	mechanismInfo->signatureLength = length;

	return( CRYPT_OK );
	}

int sigcheckPKCS1( void *dummy, MECHANISM_SIGN_INFO *mechanismInfo )
	{
	CRYPT_ALGO recoveredHashAlgo;
	STREAM stream;
	BYTE decryptedSignature[ CRYPT_MAX_PKCSIZE ];
	BYTE recoveredHash[ CRYPT_MAX_HASHSIZE ];
	int length, recoveredHashSize, status;

	UNUSED( dummy );

	/* Sanity check the input data */
	assert( mechanismInfo->signatureLength >= 60 );
	assert( mechanismInfo->hash != NULL );
	assert( mechanismInfo->hashLength >= 16 );
	assert( mechanismInfo->hashAlgo >= CRYPT_ALGO_FIRST_HASH && \
			mechanismInfo->hashAlgo <= CRYPT_ALGO_LAST_HASH );
	assert( mechanismInfo->hashContext == CRYPT_UNUSED );

	/* Format the input data as required for the sig check to work */
	status = krnlSendMessage( mechanismInfo->signContext, 
							  RESOURCE_IMESSAGE_GETATTRIBUTE, &length,
							  CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusOK( status ) )
		status = adjustPKCS1Data( decryptedSignature, 
					mechanismInfo->signature, mechanismInfo->signatureLength, 
					length );
	if( cryptStatusError( status ) )
		return( status );

	/* Recover the signed data */
	status = krnlSendMessage( mechanismInfo->signContext, 
							  RESOURCE_IMESSAGE_CTX_SIGCHECK, 
							  decryptedSignature, length );
	if( cryptStatusError( status ) )
		return( status );

	/* Undo the PKCS #1 padding.  The PKCS format for signed data is
	   [ 0 ][ 1 ][ 0xFF padding ][ 0 ][ payload ] which is checked for by the
	   following code.  Note that some implementations may have bignum code
	   which zero-truncates the result which produces a CRYPT_ERROR_BADDATA
	   error, it's the responsibility of the lower-level crypto layer to 
	   reformat the data to return a correctly-formatted result if 
	   necessary */
	sMemConnect( &stream, decryptedSignature, length );
	if( sgetc( &stream ) || sgetc( &stream ) != 1 )
		status = CRYPT_ERROR_BADDATA;
	else
		{
		int ch, i;

		for( i = 0; i < length - 3; i++ )
			if( ( ch = sgetc( &stream ) ) != 0xFF )
				break;
		if( ch != 0 || \
			cryptStatusError( \
				readMessageDigest( &stream, &recoveredHashAlgo, 
								   recoveredHash, &recoveredHashSize ) ) )
			status = CRYPT_ERROR_BADDATA;
		}
	sMemClose( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Finally, make sure the two hash values match */
	if( mechanismInfo->hashAlgo != recoveredHashAlgo || 
		mechanismInfo->hashLength != recoveredHashSize || \
		memcmp( mechanismInfo->hash, recoveredHash, recoveredHashSize ) )
		status = CRYPT_ERROR_SIGNATURE;

	/* Clean up */
	zeroise( recoveredHash, recoveredHashSize );
	return( status );
	}

/****************************************************************************
*																			*
*							Key Wrap/Unwrap Mechanisms						*
*																			*
****************************************************************************/

/* Perform PKCS #1 data wrapping/unwrapping */

int exportPKCS1( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	STATIC_FN int extractKeyData( const CRYPT_CONTEXT iCryptContext, 
								  void *keyData );
	RESOURCE_DATA msgData;
	BYTE *wrappedData = mechanismInfo->wrappedData;
	int payloadSize, length, padSize, status;

	UNUSED( dummy );

	/* Sanity check the input data */
	assert( ( mechanismInfo->wrappedData == NULL && \
			  mechanismInfo->wrappedDataLength == 0 ) || \
			( mechanismInfo->wrappedDataLength >= 64 && \
			  mechanismInfo->wrappedDataLength >= mechanismInfo->keyDataLength ) );
	assert( mechanismInfo->keyDataLength >= 8 || \
			mechanismInfo->keyContext != CRYPT_UNUSED );
	assert( mechanismInfo->auxContext == CRYPT_UNUSED );

	/* Clear the return value */
	if( mechanismInfo->wrappedData != NULL )
		memset( mechanismInfo->wrappedData, 0, 
				mechanismInfo->wrappedDataLength );

	/* Get the payload details, either as data passed in by the caller or 
	   from the key context */
	if( mechanismInfo->keyContext == CRYPT_UNUSED )
		payloadSize = mechanismInfo->keyDataLength;
	else
		{
		status = krnlSendMessage( mechanismInfo->keyContext, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE, 
								  &payloadSize, CRYPT_CTXINFO_KEYSIZE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine PKCS #1 padding parameters and make sure the key is long 
	   enough to encrypt the payload.  PKCS #1 requires that the maximum 
	   payload size be 11 bytes less than the length (to give a minimum of 8 
	   bytes of random padding) */
	status = krnlSendMessage( mechanismInfo->wrapContext, 
							  RESOURCE_IMESSAGE_GETATTRIBUTE,
							  &length, CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusError( status ) )
		return( status );
	padSize = length - ( payloadSize + 3 );
	if( payloadSize > length - 11 )
		return( CRYPT_ERROR_OVERFLOW );

	/* If this is just a length check, we're done */
	if( mechanismInfo->wrappedData == NULL )
		{
		CRYPT_ALGO cryptAlgo;

		/* Determine how long the encrypted value will be.  In the case of 
		   Elgamal it's just an estimate since it can change by up to two 
		   bytes depending on whether the values have the high bit set or 
		   not, which requires zero-padding of the ASN.1-encoded integers.  
		   This is rather nasty because it means we can't tell how large an 
		   encrypted value will be without actually creating it.

		   The 10 bytes at the start are for the ASN.1 SEQUENCE (4) and 
		   2 * INTEGER (2*3) encoding */
		krnlSendMessage( mechanismInfo->wrapContext, 
						 RESOURCE_IMESSAGE_GETATTRIBUTE, &length, 
						 CRYPT_CTXINFO_KEYSIZE );
		krnlSendMessage( mechanismInfo->wrapContext, 
						 RESOURCE_IMESSAGE_GETATTRIBUTE, &cryptAlgo, 
						 CRYPT_CTXINFO_ALGO );
		if( cryptAlgo == CRYPT_ALGO_ELGAMAL )
			length = 10 + ( 2 * ( length + 1 ) );

		mechanismInfo->wrappedDataLength = length;
		return( CRYPT_OK );
		}

	/* Encode the payload using the format given in PKCS #1.  The format for
	   encrypted data is [ 0 ][ 2 ][ nonzero random padding ][ 0 ][ payload ]
	   which is done by the following code.  Note that the random padding is
	   a nice place for a subliminal channel, especially with large public
	   key sizes where you can communicate more information in the padding
	   than in the payload */
	wrappedData[ 0 ] = 0;
	wrappedData[ 1 ] = 2;
	setResourceData( &msgData, wrappedData + 2, padSize );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_IATTRIBUTE_RANDOM_NZ );
	wrappedData[ 2 + padSize ] = 0;
	if( cryptStatusError( status ) )
		{
		zeroise( wrappedData, mechanismInfo->wrappedDataLength );
		return( status );
		}

	/* Copy the payload in at the last possible moment, then encrypt it */
	if( mechanismInfo->keyContext != CRYPT_UNUSED )
		status = extractKeyData( mechanismInfo->keyContext,
								 wrappedData + 2 + padSize + 1 );
	else
		memcpy( wrappedData  + 2 + padSize + 1, mechanismInfo->keyData, 
				payloadSize );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( mechanismInfo->wrapContext, 
								  RESOURCE_IMESSAGE_CTX_ENCRYPT,
								  wrappedData, length );
	if( cryptStatusError( status ) )
		{
		zeroise( wrappedData, mechanismInfo->wrappedDataLength );
		return( status );
		}
	
	/* For DLP-based PKC's the output length isn't the same as the key 
	   size, so we adjust the return value as required */
	mechanismInfo->wrappedDataLength = ( status > length ) ? status : length;

	return( CRYPT_OK );
	}

/* Perform PKCS #1 data unwrapping */

int importPKCS1( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	STREAM stream;
	BYTE decryptedData[ CRYPT_MAX_PKCSIZE ];
	int length, status;

	UNUSED( dummy );

	/* Sanity check the input data */
	assert( mechanismInfo->wrappedDataLength >= 60 );
	assert( mechanismInfo->keyDataLength >= 8 );
	assert( mechanismInfo->auxContext == CRYPT_UNUSED );

	/* Clear the return value */
	memset( mechanismInfo->keyData, 0, mechanismInfo->keyDataLength );

	/* Format the input data as required for the decrypt to work */
	status = krnlSendMessage( mechanismInfo->wrapContext, 
							  RESOURCE_IMESSAGE_GETATTRIBUTE, &length,
							  CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusOK( status ) )
		/* DLP-based key wrapping differs somewhat from RSA-based wrapping
		   in that it produces 2n + delta bytes of structured data instead of
		   n bytes of unstructured data, to handle this we check the input
		   data length and only adjust the data if it looks like it's
		   unstructured data */
		if( length > mechanismInfo->wrappedDataLength - 32 )
			status = adjustPKCS1Data( decryptedData, 
					mechanismInfo->wrappedData, mechanismInfo->wrappedDataLength, 
					length );
		else
			{
			if( length > CRYPT_MAX_PKCSIZE )
				/* The import key mechanism doesn't currently expect quite 
				   this much data.  This is just a temporary workaround, we 
				   should really replace the straight PKCS #1 mechanism with 
				   a DLP-key-wrap-specific alternative */
				return( CRYPT_ERROR_FAILED );

			memcpy( decryptedData, mechanismInfo->wrappedData, 
					mechanismInfo->wrappedDataLength );
			}
	if( cryptStatusError( status ) )
		return( status );

	/* Decrypt the encrypted key */
	status = krnlSendMessage( mechanismInfo->wrapContext, 
							  RESOURCE_IMESSAGE_CTX_DECRYPT, 
							  decryptedData, length );
	if( cryptStatusError( status ) )
		{
		zeroise( decryptedData, CRYPT_MAX_PKCSIZE );
		return( status );
		}

	/* Undo the PKCS #1 padding.  The PKCS format for encrypted data is
	   [ 0 ][ 2 ][ random nonzero padding ][ 0 ][ payload ] with a minimum of
	   8 bytes padding, which is checked for by the following code.  Note 
	   that some implementations may have bignum code which zero-truncates 
	   the result which produces a CRYPT_ERROR_BADDATA error, it's the 
	   responsibility of the lower-level crypto layer to reformat the data to 
	   return a correctly-formatted result if necessary */
	sMemConnect( &stream, decryptedData, length );
	if( sgetc( &stream ) || sgetc( &stream ) != 2 )
		status = CRYPT_ERROR_BADDATA;
	else
		{
		int ch, i;

		for( i = 0; i < length - 3; i++ )
			if( ( ch = sgetc( &stream ) ) == 0 )
				break;
		if( ch != 0 || i < 8 )
			status = CRYPT_ERROR_BADDATA;
		else
			length -= 2 + i + 1;	/* [ 0 ][ 2 ] + padding + [ 0 ] */
		}
	if( cryptStatusError( status ) )
		{
		sMemClose( &stream );
		zeroise( decryptedData, CRYPT_MAX_PKCSIZE );
		return( CRYPT_ERROR_BADDATA );
		}

	/* Return the result to the caller */
	memcpy( mechanismInfo->keyData, stream.buffer + stream.bufPos, length );
	mechanismInfo->keyDataLength = length;
	zeroise( decryptedData, CRYPT_MAX_PKCSIZE );
	sMemClose( &stream );

	return( CRYPT_OK );
	}

/* Perform CMS data wrapping.  Returns an error code or the number of output 
   bytes */

#define CMS_KEYBLOCK_HEADERSIZE		4

static int cmsGetPadSize( const CRYPT_CONTEXT iExportContext, 
						  const int payloadSize )
	{
	int blockSize, totalSize, status;

	status = krnlSendMessage( iExportContext, RESOURCE_IMESSAGE_GETATTRIBUTE,
							  &blockSize, CRYPT_CTXINFO_IVSIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Determine the padding size, which is the amount of padding required to
	   bring the total data size up to a multiple of the block size with a
	   minimum size of two blocks */
	totalSize = roundUp( payloadSize, blockSize );
	if( totalSize < blockSize * 2 )
		totalSize = blockSize * 2;
	
	return( totalSize - payloadSize );
	}

int exportCMS( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	STATIC_FN int extractKeyData( const CRYPT_CONTEXT iCryptContext, 
								  void *keyData );
	BYTE *keyBlockPtr = ( BYTE * ) mechanismInfo->wrappedData;
	int payloadSize, padSize, status = CRYPT_OK;

	UNUSED( dummy );

	/* Sanity check the input data */
	assert( ( mechanismInfo->wrappedData == NULL && \
			  mechanismInfo->wrappedDataLength == 0 ) || \
			( mechanismInfo->wrappedDataLength >= 16 && \
			  mechanismInfo->wrappedDataLength >= mechanismInfo->keyDataLength ) );
	assert( mechanismInfo->keyDataLength >= 8 || \
			mechanismInfo->keyContext != CRYPT_UNUSED );
	assert( mechanismInfo->auxContext == CRYPT_UNUSED );

	/* Clear the return value */
	memset( mechanismInfo->wrappedData, 0, 
			mechanismInfo->wrappedDataLength );

	/* Get the payload details, either as data passed in by the caller or 
	   from the key context */
	if( mechanismInfo->keyContext == CRYPT_UNUSED )
		payloadSize = mechanismInfo->keyDataLength;
	else
		{
		status = krnlSendMessage( mechanismInfo->keyContext, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE, 
								  &payloadSize, CRYPT_CTXINFO_KEYSIZE );
		if( cryptStatusError( status ) )
			return( status );
		}
	payloadSize += CMS_KEYBLOCK_HEADERSIZE;
	padSize = cmsGetPadSize( mechanismInfo->wrapContext, payloadSize );

	/* If this is just a length check, we're done */
	if( mechanismInfo->wrappedData == NULL )
		{
		mechanismInfo->wrappedDataLength = payloadSize + padSize;
		return( CRYPT_OK );
		}

	/* Pad the payload out with a random nonce if required */
	if( padSize > 0 )
		getNonce( keyBlockPtr  + payloadSize, padSize );

	/* Format the key block: [length][check value][key][padding], copy the 
	   payload in at the last possible moment, then perform two passes of 
	   encryption retaining the IV from the first pass for the second pass */
	keyBlockPtr[ 0 ] = payloadSize - CMS_KEYBLOCK_HEADERSIZE;
	if( mechanismInfo->keyContext != CRYPT_UNUSED )
		status = extractKeyData( mechanismInfo->keyContext, 
								 keyBlockPtr + CMS_KEYBLOCK_HEADERSIZE );
	else
		memcpy( keyBlockPtr + CMS_KEYBLOCK_HEADERSIZE, 
				mechanismInfo->keyData, payloadSize );
	keyBlockPtr[ 1 ] = keyBlockPtr[ CMS_KEYBLOCK_HEADERSIZE ] ^ 0xFF;
	keyBlockPtr[ 2 ] = keyBlockPtr[ CMS_KEYBLOCK_HEADERSIZE + 1 ] ^ 0xFF;
	keyBlockPtr[ 3 ] = keyBlockPtr[ CMS_KEYBLOCK_HEADERSIZE + 2 ] ^ 0xFF;
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( mechanismInfo->wrapContext, 
								  RESOURCE_IMESSAGE_CTX_ENCRYPT,
								  mechanismInfo->wrappedData, 
								  payloadSize + padSize );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( mechanismInfo->wrapContext, 
								  RESOURCE_IMESSAGE_CTX_ENCRYPT,
								  mechanismInfo->wrappedData, 
								  payloadSize + padSize );
	if( cryptStatusError( status ) )
		{
		zeroise( mechanismInfo->wrappedData, 
				 mechanismInfo->wrappedDataLength );
		return( status );
		}
	mechanismInfo->wrappedDataLength = payloadSize + padSize;

	return( CRYPT_OK );
	}

/* Perform CMS data unwrapping */

int importCMS( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	RESOURCE_DATA msgData;
	BYTE buffer[ CRYPT_MAX_KEYSIZE + 16 ], ivBuffer[ CRYPT_MAX_IVSIZE ];
	BYTE *dataEndPtr = buffer + mechanismInfo->wrappedDataLength;
	int blockSize, status;

	UNUSED( dummy );

	/* Sanity check the input data */
	assert( mechanismInfo->wrappedDataLength >= 16 );
	assert( mechanismInfo->keyDataLength >= 8 );
	assert( mechanismInfo->auxContext == CRYPT_UNUSED );

	/* Clear the return value */
	memset( mechanismInfo->keyData, 0, CRYPT_MAX_KEYSIZE );

	/* Make sure the data is a multiple of the cipher block size */
	status = krnlSendMessage( mechanismInfo->wrapContext, 
							  RESOURCE_IMESSAGE_GETATTRIBUTE, &blockSize, 
							  CRYPT_CTXINFO_IVSIZE );
	if( cryptStatusError( status ) )
		return( status );
	if( mechanismInfo->wrappedDataLength & ( blockSize - 1 ) )
		return( CRYPT_ERROR_BADDATA );

	/* Save the current IV for the inner decryption */
	setResourceData( &msgData, ivBuffer, CRYPT_MAX_IVSIZE );
	krnlSendMessage( mechanismInfo->wrapContext, 
					 RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
					 CRYPT_CTXINFO_IV );

	/* Using the n-1'th ciphertext block as the new IV, decrypt the n'th block.
	   Then, using the decrypted n'th ciphertext block as the IV, decrypt the
	   remainder of the ciphertext blocks */
	memcpy( buffer, mechanismInfo->wrappedData,
			mechanismInfo->wrappedDataLength );
	setResourceData( &msgData, dataEndPtr - 2 * blockSize, blockSize );
	krnlSendMessage( mechanismInfo->wrapContext,
					 RESOURCE_IMESSAGE_SETATTRIBUTE_S, &msgData,
					 CRYPT_CTXINFO_IV );
	status = krnlSendMessage( mechanismInfo->wrapContext,
							  RESOURCE_IMESSAGE_CTX_DECRYPT,
							  dataEndPtr - blockSize, blockSize );
	if( cryptStatusOK( status ) )
		{
		setResourceData( &msgData, dataEndPtr - blockSize, blockSize );
		krnlSendMessage( mechanismInfo->wrapContext,
						 RESOURCE_IMESSAGE_SETATTRIBUTE_S, &msgData,
						 CRYPT_CTXINFO_IV );
		status = krnlSendMessage( mechanismInfo->wrapContext,
								  RESOURCE_IMESSAGE_CTX_DECRYPT, buffer,
								  mechanismInfo->wrappedDataLength - blockSize );
		}
	if( cryptStatusError( status ) )
		{
		zeroise( buffer, CRYPT_MAX_KEYSIZE + 16 );
		return( status );
		}

	/* Using the original IV, decrypt the inner data */
	setResourceData( &msgData, ivBuffer, blockSize );
	krnlSendMessage( mechanismInfo->wrapContext, 
					 RESOURCE_IMESSAGE_SETATTRIBUTE_S, &msgData, 
					 CRYPT_CTXINFO_IV );
	status = krnlSendMessage( mechanismInfo->wrapContext, 
							  RESOURCE_IMESSAGE_CTX_DECRYPT, buffer, 
							  mechanismInfo->wrappedDataLength );

	/* Make sure everything is in order and copy the recovered key to the
	   output */
	if( cryptStatusOK( status ) )
		{
		if( buffer[ 0 ] < bitsToBytes( MIN_KEYSIZE_BITS ) || \
			buffer[ 0 ] > bitsToBytes( MAX_KEYSIZE_BITS ) || \
			buffer[ 0 ] > mechanismInfo->keyDataLength )
			status = CRYPT_ERROR_BADDATA;
		if( buffer[ 1 ] != ( buffer[ CMS_KEYBLOCK_HEADERSIZE ] ^ 0xFF ) || \
			buffer[ 2 ] != ( buffer[ CMS_KEYBLOCK_HEADERSIZE + 1 ] ^ 0xFF ) || \
			buffer[ 3 ] != ( buffer[ CMS_KEYBLOCK_HEADERSIZE + 2 ] ^ 0xFF ) )
			status = CRYPT_ERROR_WRONGKEY;
		}
	if( cryptStatusOK( status ) )
		{
		memcpy( mechanismInfo->keyData, buffer + CMS_KEYBLOCK_HEADERSIZE, 
				buffer[ 0 ] );
		mechanismInfo->keyDataLength = buffer[ 0 ];
		}
	zeroise( buffer, CRYPT_MAX_KEYSIZE + 16 );

	return( status );
	}

/* Perform private key wrapping/unwrapping */

int exportPrivateKey( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	STATIC_FN int exportPrivateKeyData( STREAM *stream, 
										const CRYPT_CONTEXT iCryptContext );
	STREAM stream;
	int payloadSize, padSize, status;

	UNUSED( dummy );

	/* Sanity check the input data */
	assert( ( mechanismInfo->wrappedData == NULL && \
			  mechanismInfo->wrappedDataLength == 0 ) || \
			( mechanismInfo->wrappedDataLength >= 16 ) );
	assert( mechanismInfo->keyData == NULL );
	assert( mechanismInfo->keyDataLength == 0 );
	assert( mechanismInfo->auxContext == CRYPT_UNUSED );

	/* Clear the return value */
	if( mechanismInfo->wrappedData != NULL )
		memset( mechanismInfo->wrappedData, 0, 
				mechanismInfo->wrappedDataLength );

	/* Get the payload details */
	sMemOpen( &stream, NULL, 0 );
	status = exportPrivateKeyData( &stream, mechanismInfo->keyContext );
	payloadSize = ( int ) stell( &stream );
	sMemClose( &stream );
	padSize = cmsGetPadSize( mechanismInfo->wrapContext, payloadSize );
	if( cryptStatusError( status ) )
		return( status );

	/* If this is just a length check, we're done */
	if( mechanismInfo->wrappedData == NULL )
		{
		mechanismInfo->wrappedDataLength = payloadSize + padSize;
		return( CRYPT_OK );
		}

	/* Write the private key data, PKCS #5-pad it, and encrypt it */
	sMemOpen( &stream, mechanismInfo->wrappedData, 
			  mechanismInfo->wrappedDataLength );
	status = exportPrivateKeyData( &stream, mechanismInfo->keyContext );
	if( cryptStatusOK( status ) )
		{
		int i;

		for( i = 0; i < padSize; i++ )
			sputc( &stream, padSize );
		status = krnlSendMessage( mechanismInfo->wrapContext, 
								  RESOURCE_IMESSAGE_CTX_ENCRYPT, 
								  mechanismInfo->wrappedData, 
								  payloadSize + padSize );
		}
	if( cryptStatusError( status ) )
		sMemClose( &stream );
	else
		{
		sMemDisconnect( &stream );
		mechanismInfo->wrappedDataLength = payloadSize + padSize;
		}

	return( status );
	}

int importPrivateKey( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	STATIC_FN int importPrivateKeyData( STREAM *stream, 
										const CRYPT_CONTEXT iCryptContext );
	void *buffer;
	int blockSize, status;

	UNUSED( dummy );

	/* Sanity check the input data */
	assert( mechanismInfo->wrappedData != NULL );
	assert( mechanismInfo->wrappedDataLength >= 16 );
	assert( mechanismInfo->keyData == NULL );
	assert( mechanismInfo->keyDataLength == 0 );
	assert( mechanismInfo->auxContext == CRYPT_UNUSED );

	/* Make sure the data has a sane length and is a multiple of the cipher
	   block size (since we force the use of the CBC mode we know it has to 
	   have this property) */
	status = krnlSendMessage( mechanismInfo->wrapContext, 
							  RESOURCE_IMESSAGE_GETATTRIBUTE, &blockSize, 
							  CRYPT_CTXINFO_IVSIZE );
	if( cryptStatusError( status ) )
		return( status );
	if( ( mechanismInfo->wrappedDataLength >= MAX_PRIVATE_KEYSIZE ) || \
		( mechanismInfo->wrappedDataLength & ( blockSize - 1 ) ) )
		return( CRYPT_ERROR_BADDATA );

	/* Copy the encrypted private key data to a temporary buffer, decrypt it, 
	   and read it into the context.  If we get a corrupted-data error then 
	   it's far more likely to be because we decrypted with the wrong key 
	   than because any data was corrupted, so we convert it to a wrong-key 
	   error */
	if( ( status = krnlMemalloc( &buffer, MAX_PRIVATE_KEYSIZE ) ) != CRYPT_OK )
		return( status );
	memcpy( buffer, mechanismInfo->wrappedData, 
			mechanismInfo->wrappedDataLength );
	status = krnlSendMessage( mechanismInfo->wrapContext, 
							  RESOURCE_IMESSAGE_CTX_DECRYPT, buffer, 
							  mechanismInfo->wrappedDataLength );
	if( cryptStatusOK( status ) )
		{
		STREAM stream;

		sMemConnect( &stream, buffer, mechanismInfo->wrappedDataLength );
		status = importPrivateKeyData( &stream, mechanismInfo->keyContext );
		if( status == CRYPT_ERROR_BADDATA )
			status = CRYPT_ERROR_WRONGKEY;
		sMemClose( &stream );
		}
	krnlMemfree( &buffer );

	return( status );
	}

/****************************************************************************
*																			*
*							Key Extract Functions							*
*																			*
****************************************************************************/

/* Extract a key from a context.  This is a somewhat ugly set of functions 
   which need to bypass the kernel's security checking and are the only ones
   which can do this.  Like trusted downgraders in other security models, 
   this is an unavoidable requirement in the complete-isolation model - some 
   bypass mechanism needs to be present in order to allow a key to be 
   exported from an encryption action object */

#include "cryptctx.h"

static int extractKeyData( const CRYPT_CONTEXT iCryptContext, void *keyData )
	{
	CRYPT_INFO *cryptInfoPtr;

	getCheckInternalResource( iCryptContext, cryptInfoPtr, OBJECT_TYPE_CONTEXT );
	if( cryptInfoPtr->type == CONTEXT_CONV )
		memcpy( keyData, cryptInfoPtr->ctxConv.userKey, 
				cryptInfoPtr->ctxConv.userKeyLength );
	else
		memcpy( keyData, cryptInfoPtr->ctxMAC.userKey, 
				cryptInfoPtr->ctxMAC.userKeyLength );
	unlockResourceExit( cryptInfoPtr, CRYPT_OK );
	}

/* Prototypes for functions in asn1keys.c */

int readPrivateKey( STREAM *stream, CRYPT_INFO *cryptInfoPtr );
int writePrivateKey( STREAM *stream, const CRYPT_INFO *cryptInfoPtr );

static int exportPrivateKeyData( STREAM *stream, 
								 const CRYPT_CONTEXT iCryptContext )
	{
	CRYPT_CONTEXT iPrivateKeyContext;
	CRYPT_INFO *cryptInfoPtr;
	int status;

	/* We may have been passed something else with a context attached, get the
	   context itself */
	status = krnlSendMessage( iCryptContext, RESOURCE_MESSAGE_GETDEPENDENT,
							  &iPrivateKeyContext, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that we've been given a PKC context with a private key
	   loaded (this has already been checked at a higher level, but we
	   perform a sanity check here to be sage) */
	getCheckInternalResource( iPrivateKeyContext, cryptInfoPtr, 
							  OBJECT_TYPE_CONTEXT );
	if( cryptInfoPtr->type != CONTEXT_PKC || !cryptInfoPtr->ctxPKC.keySet || \
		cryptInfoPtr->ctxPKC.isPublicKey )
		unlockResourceExit( cryptInfoPtr, CRYPT_ARGERROR_OBJECT );

	status = writePrivateKey( stream, cryptInfoPtr );
	unlockResourceExit( cryptInfoPtr, status );
	}

static int importPrivateKeyData( STREAM *stream,
								 const CRYPT_CONTEXT iCryptContext )
	{
	CRYPT_INFO *cryptInfoPtr;
	int status;

	getCheckInternalResource( iCryptContext, cryptInfoPtr, OBJECT_TYPE_CONTEXT );
	status = readPrivateKey( stream, cryptInfoPtr );
	unlockResourceExit( cryptInfoPtr, status );
	}
