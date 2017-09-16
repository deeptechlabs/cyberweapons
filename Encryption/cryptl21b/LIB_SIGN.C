/****************************************************************************
*																			*
*							cryptlib Signature Routines						*
*						Copyright Peter Gutmann 1993-1999					*
*																			*
****************************************************************************/

#include <string.h>
#include <stdlib.h>
#include "crypt.h"
#include "cryptctx.h"
#ifdef INC_ALL
  #include "asn1.h"
  #include "asn1objs.h"
  #include "asn1oid.h"
#else
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1objs.h"
  #include "keymgmt/asn1oid.h"
#endif /* Compiler-specific includes */

/* Prototypes for functions in keymgmt/cms.c */

int readSignerInfo( STREAM *stream, CRYPT_ALGO *hashAlgorithm,
					void **iAndSStart, void **attributes, int *attributeSize,
					void **signature );
int writeSignerInfo( STREAM *stream, CRYPT_CERTIFICATE certificate,
					 const CRYPT_ALGO hashAlgorithm,
					 const void *attributes, const int attributeSize,
					 const void *signature, const int signatureSize );

/* The following routines try to keep the amount of time in which sensitive
   information is present in buffers to an absolute minimum (although the
   buffers are pagelocked on most OS's, there are some systems where this
   isn't possible).  The code is structured to keep the operations which
   create and those which use sensitive information in memory as close
   together as possible and to clear the memory as soon as it's used.  For
   this reason the structure is somewhat unusual, with everything in one
   linear block of code with jumps to clearly-defined locations to exit the
   current nesting level in the case of errors.  This is necessary to ensure
   that the approriate cleanup operations are performed at each level, and
   that the in-memory data is destroyed as soon as possible - the prime goal
   is to destroy the data as soon as we can.  Security-conscious code isn't
   necessary cleanly-structured code */

/****************************************************************************
*																			*
*							Low-level Signature Functions 					*
*																			*
****************************************************************************/

/* Sign data using PKCS #1 formatting.  Returns an error code or the number
   of output bytes */

static int pkcs1Sign( BYTE *data, CRYPT_INFO *pkcInfoPtr,
					  const CRYPT_INFO *hashInfoPtr, const int padSignature )
	{
	const CRYPT_ALGO hashAlgo = hashInfoPtr->capabilityInfo->cryptAlgo;
	const int hashSize = hashInfoPtr->capabilityInfo->blockSize;
	STREAM stream;
	MESSAGE_DIGEST hash;
	int payloadSize, length, i, status;

	/* Create the message digest and find its size */
	newMessageDigest( &hash, hashAlgo, hashInfoPtr->ctxHash.hash, hashSize );
	payloadSize = sizeofMessageDigest( &hash );
	length = bitsToBytes( pkcInfoPtr->ctxPKC.keySizeBits );

	/* Encode the payload using the format given in PKCS #1.  The format for
	   signed data is [ 0 ][ 1 ][ 0xFF padding ][ 0 ][ payload ] which is
	   created by the following code */
	sMemOpen( &stream, data, CRYPT_MAX_PKCSIZE );
	sputc( &stream, 0 );
	sputc( &stream, 1 );
	for( i = 0; i < length - ( payloadSize + 3 ); i++ )
		sputc( &stream, 0xFF );
	sputc( &stream, 0 );
	writeMessageDigest( &stream, &hash, DEFAULT_TAG );
	deleteMessageDigest( &hash );
	sMemDisconnect( &stream );

	/* Sign the data */
	status = pkcInfoPtr->capabilityInfo->signFunction( pkcInfoPtr, data,
													   length );
	if( cryptStatusError( status ) )
		return( status );

	/* Sometimes (about 1/256 times) the signature size will be less than the
	   modulus size, which causes problems for functions which rely on the
	   length remaining constant between the length query and sign data
	   calls.  In addition PKCS #1 requires that values be zero-padded to the
	   modulus size (although this makes the result non-DER compliant).
	   Because of this we zero-pad the result if necessary unless it's an
	   X.509 signature, which should probably be DER rather than PKCS #1
	   compliant */
	if( status < length && padSignature )
		{
		const int delta = length - status;

		memmove( data + delta, data, status );
		memset( data, 0, delta );
		}

	return( length );
	}

/* Create a signature */

static int createSignature( void *signature, int *signatureLength,
							CRYPT_INFO *pkcInfoPtr,
							const CRYPT_INFO *hashInfoPtr,
							const SIGNATURE_TYPE signatureType )
	{
	const CRYPT_ALGO hashAlgo = hashInfoPtr->capabilityInfo->cryptAlgo;
	const int hashSize = hashInfoPtr->capabilityInfo->blockSize;
	BYTE dataToSign[ CRYPT_MAX_PKCSIZE ];
	int status = CRYPT_OK;

	/* If we're just doing a length check, write dummy data to a null stream
	   and return its length */
	if( signature == NULL )
		{
		STREAM nullStream;
		int length;

		/* Determine how long the signature will be.  In the case of DSA it's
		   just an estimate since it can change by up to two bytes depending
		   on whether the signature values have the high bit set or not, which
		   requires zero-padding of the ASN.1-encoded integers.  This is
		   rather nasty because it means we can't tell how large a signature
		   will be without actually creating it.

		   The 6 bytes at the start are for the ASN.1 SEQUENCE and 2 * INTEGER
		   encoding */
		if( pkcInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DSA )
			length = 6 + ( 2 * ( hashSize + 1 ) );
		else
			length = bitsToBytes( pkcInfoPtr->ctxPKC.keySizeBits );

		sMemOpen( &nullStream, NULL, 0 );
		status = writeSignature( &nullStream, pkcInfoPtr, hashAlgo,
								 dataToSign, length, signatureType );
		*signatureLength = sMemSize( &nullStream );
		sMemClose( &nullStream );

		return( status );
		}

	/* Turn the hash information into a message digest record and find out
	   how much space we need to allocate to it in the signature record (with
	   a slight exception for DSA).  There's no need for a length check as
	   there is for the key export function since even the largest hash fits
	   easily within the shortest PKC key cryptlib allows.  In addition we
	   can ignore a CRYPT_INCOMPLETE error if we're only doing a data size
	   check */
	if( pkcInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DSA )
		{
		/* DSA is only defined for hash algorithms with a block size of 160
		   bits */
		if( hashSize != 20 )
			return( CRYPT_BADPARM4 );

		/* Sign the data.  We set the length to 0 since it's implicit with
		   DSA */
		memcpy( dataToSign, hashInfoPtr->ctxHash.hash, hashSize );
		status = pkcInfoPtr->capabilityInfo->signFunction( pkcInfoPtr,
														   dataToSign, 0 );
		}
	else
		status = pkcs1Sign( dataToSign, pkcInfoPtr, hashInfoPtr,
							( signatureType != SIGNATURE_X509 ) ? TRUE : FALSE );

	/* Write the signature record to the output and clean up */
	if( !cryptStatusError( status ) )
		{
		STREAM outputStream;

		sMemOpen( &outputStream, signature, STREAMSIZE_UNKNOWN );
		status = writeSignature( &outputStream, pkcInfoPtr, hashAlgo,
								 dataToSign, status, signatureType );
		*signatureLength = sMemSize( &outputStream );
		sMemDisconnect( &outputStream );
		}

	/* Clean up */
	zeroise( dataToSign, CRYPT_MAX_PKCSIZE );
	return( status );
	}

/* Check a signature */

static int checkSignature( const void *signature, CRYPT_INFO *pkcInfoPtr,
						   const CRYPT_INFO *hashInfoPtr,
						   const SIGNATURE_TYPE signatureType )
	{
	const CRYPT_ALGO hashAlgo = hashInfoPtr->capabilityInfo->cryptAlgo;
	OBJECT_INFO signatureInfo;
	BYTE decryptedSignature[ CRYPT_MAX_PKCSIZE ];
	STREAM stream;
	const int hashSize = hashInfoPtr->capabilityInfo->blockSize;
	int length = bitsToBytes( pkcInfoPtr->ctxPKC.keySizeBits ), status;

	/* Read the signature record up to the start of the signature itself */
	memset( &signatureInfo, 0, sizeof( OBJECT_INFO ) );
	sMemConnect( &stream, ( void * ) signature, STREAMSIZE_UNKNOWN );
	status = readSignature( &stream, &signatureInfo, signatureType );
	if( cryptStatusOK( status ) )
		{
		/* Make sure we've been given the correct hash algorithm.  CMS
		   specifies the algorithm at the start of the signed data rather than
		   in the signature algorithm OID, so the check is done elsewhere */
		if( signatureType != SIGNATURE_CMS && \
			hashAlgo != signatureInfo.hashAlgo )
			status = CRYPT_BADSIG;
		}
	if( cryptStatusError( status ) )
		goto endCheckSignature;

	/* Make sure we've been given the correct key if the signature format
	   supports this type of check */
	if( signatureType == SIGNATURE_CRYPTLIB && \
		memcmp( pkcInfoPtr->ctxPKC.keyID, signatureInfo.keyID, KEYID_SIZE ) )
		{
		status = CRYPT_WRONGKEY;
		goto endCheckSignature;
		}

	/* DSA signatures are handled somewhat specially */
	if( pkcInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DSA )
		{
		/* DSA is only defined for hash algorithms with a block size of 160
		   bits */
		if( hashSize != 20 )
			return( CRYPT_BADPARM4 );

		/* Check the signature validity using the encoded signature data and
		   hash */
		memcpy( decryptedSignature, hashInfoPtr->ctxHash.hash, hashSize );
		memcpy( decryptedSignature + hashSize, sMemBufPtr( &stream ),
				6 + ( 2 * ( hashSize + 1 ) ) );
		status = pkcInfoPtr->capabilityInfo->sigCheckFunction( pkcInfoPtr,
										decryptedSignature, CRYPT_UNUSED );
		}
	else
		{
		/* Recover the data by encrypting the signature with the public key */
		memcpy( decryptedSignature, sMemBufPtr( &stream ), length );
		length = pkcInfoPtr->capabilityInfo->sigCheckFunction( pkcInfoPtr,
										decryptedSignature, length );
		if( cryptStatusError( length ) )
			status = length;
		else
			{
			MESSAGE_DIGEST hash;
			STREAM inputStream;
			int ch, i;

			newMessageDigest( &hash, CRYPT_ALGO_NONE, NULL, 0 );

			/* Undo the PKCS #1 padding.  The PKCS format for signed data is
			   [ 0 ][ 1 ][ 0xFF padding ][ 0 ][ payload ] which is checked
			   for by the following code.  Since the bignum code performs
			   zero-truncation, we never see the leading zero so the first
			   byte should always be a 1 */
			sMemConnect( &inputStream, decryptedSignature, length );
			if( sgetc( &inputStream ) != 1 )
				{
				status = CRYPT_BADDATA;
				goto endCheckSignatureInfo;
				}
			for( i = 0; i < length - 3; i++ )
				if( ( ch = sgetc( &inputStream ) ) != 0xFF )
					break;
			if( ch != 0 || readMessageDigest( &inputStream, &hash ) < 0 )
				{
				status = CRYPT_BADDATA;
				goto endCheckSignatureInfo;
				}

			/* Finally, make sure the two hash values match */
			if( hashAlgo != hash.type || \
				memcmp(	hash.data, hashInfoPtr->ctxHash.hash, hashSize ) )
				status = CRYPT_BADSIG;

			/* Clean up */
endCheckSignatureInfo:
			deleteMessageDigest( &hash );
			sMemClose( &inputStream );
			}
		}

endCheckSignature:
	zeroise( &signatureInfo, sizeof( OBJECT_INFO ) );
	sMemDisconnect( &stream );
	return( status );
	}

/****************************************************************************
*																			*
*							X.509-style Signature Functions 				*
*																			*
****************************************************************************/

/* Create/check an X.509-style signature.  These work with objects of the
   form:

	signedObject ::= SEQUENCE {
		object				ANY,
		signatureAlgorithm	AlgorithmIdentifier,
		signature			BIT STRING
		}

  The signature checking is somewhat complex since the information needed to
  obtain the key required to check the signature on an object is contained
  inside the object which is being checked.  For this reason we recognise a
  signContext of CRYPT_ERROR to mean that we should check the object without
  trying to check the signature on it.  The idea is that we first call the
  function will a null context pointer to get information on the object, then
  unpack it to find the signers key and load the information into a PKC
  context, then call it a second time to perform the actual check.

  These functions are for internal use only and don't perform the extensive
  parameter checking or support the get-object-size functionality of the more
  general cryptCreate/CheckSignature() functions */

int createX509signature( void *signedObject, int *signedObjectLength,
						 const void *object, const int objectLength,
						 CRYPT_CONTEXT signContext, const CRYPT_ALGO hashAlgo )
	{
	CRYPT_CONTEXT iHashContext;
	CRYPT_INFO *signInfoPtr, *hashInfoPtr;
	STREAM stream;
#if INT_MAX > 32767
	const BOOLEAN largeObject = ( objectLength > 64000 ) ? TRUE : FALSE;
	BYTE *signatureStart = ( BYTE * ) signedObject + \
						   ( ( largeObject ) ? 5 : 4 ) + objectLength;
#else
	BYTE *signatureStart = ( BYTE * ) signedObject + 4 + objectLength;
#endif /* 32-bit ints */
	int signatureLength, delta, status;

	getCheckInternalResource( signContext, signInfoPtr, RESOURCE_TYPE_CRYPT );

	/* Hash the data to be signed */
	status = iCryptCreateContext( &iHashContext, hashAlgo, CRYPT_ALGO_NONE );
	if( cryptStatusError( status ) )
		return( status );
	iCryptEncrypt( iHashContext, ( void * ) object, objectLength );
	iCryptEncrypt( iHashContext, ( void * ) object, 0 );

	/* Create the wrapped-up signed object.  This gets somewhat ugly because
	   the only way we can find out how long the signature will be is by
	   actually creating it, since the ASN.1 encoding constraints mean the
	   size can vary by a few bytes depending on what values the integers
	   which make up the signature take.  Because of this, we first generate
	   the signature a reasonable distance back from the start of the buffer,
	   write the header and data to sign at the start, and finally move the
	   signature down to the end of the header.  Because the combination of
	   data to sign and signature are virtually always in the range 256-64K
	   bytes, the data move is almost never performed */
	getCheckInternalResource2( iHashContext, hashInfoPtr,
							   RESOURCE_TYPE_CRYPT, signInfoPtr );
	status = createSignature( signatureStart, &signatureLength, signInfoPtr,
							  hashInfoPtr, SIGNATURE_X509 );
	unlockResource( hashInfoPtr );
	iCryptDestroyObject( iHashContext );
	if( cryptStatusError( status ) )
		unlockResourceExit( signInfoPtr, status );
	sMemConnect( &stream, signedObject, STREAMSIZE_UNKNOWN );
	writeSequence( &stream, signatureLength + objectLength );
	swrite( &stream, object, objectLength );
#if INT_MAX > 32767
	if( largeObject )
		delta = ( objectLength + signatureLength < 65536L ) ? 1 : 0;
	else
#endif /* 32-bit ints */
	delta = ( objectLength + signatureLength < 128 ) ? 2 : \
			( objectLength + signatureLength < 256 ) ? 1 : 0;
	if( delta )
		/* This only ever really happens for CRL's with a single cert
		   and no extensions */
		memmove( sMemBufPtr( &stream ), sMemBufPtr( &stream ) + delta,
				 signatureLength );

	*signedObjectLength = sMemSize( &stream ) + signatureLength;
	sMemDisconnect( &stream );

	unlockResourceExit( signInfoPtr, status );
	}

int checkX509signature( const void *signedObject, void **object,
						int *objectLength, CRYPT_CONTEXT sigCheckContext )
	{
	CRYPT_CONTEXT iHashContext;
	CRYPT_INFO *sigCheckInfoPtr, *hashInfoPtr;
	CRYPT_ALGO sigAlgo, hashAlgo;
	STREAM stream;
	BYTE *objectPtr;
	int status, length, dummy;

	/* Check the start of the object */
	sMemConnect( &stream, ( void * ) signedObject, STREAMSIZE_UNKNOWN );
	status = readSequence( &stream, &dummy );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}

	/* Record the start and size of the signed object */
	objectPtr = sMemBufPtr( &stream );
	status = readSequence( &stream, &length );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	sSkip( &stream, length );		/* Move past the object */
	length += status;				/* Include length of header */
	if( objectLength != NULL )
		*objectLength = length;
	if( object != NULL )
		*object = objectPtr;

	/* If we're just performing a general check on the object, exit now */
	if( sigCheckContext == CRYPT_ERROR )
		{
		sMemDisconnect( &stream );
		return( CRYPT_OK );
		}

	getCheckInternalResource( sigCheckContext, sigCheckInfoPtr, RESOURCE_TYPE_CRYPT );

	/* Create a hash context from the algorithm identifier of the signature */
	status = readAlgorithmIdentifier( &stream, &sigAlgo, &hashAlgo, NULL, NULL );
	if( cryptStatusOK( status ) && \
		sigCheckInfoPtr->capabilityInfo->cryptAlgo != sigAlgo )
		/* The signature algorithm isn't what we expected, the best we can do
		   is report a certificate data error */
		status = CRYPT_BADDATA;
	if( !cryptStatusError( status ) )
		status = iCryptCreateContext( &iHashContext, hashAlgo, CRYPT_ALGO_NONE );
	if( cryptStatusError( status ) )
		unlockResourceExit( sigCheckInfoPtr, status );

	/* Hash the signed data and check the signature on the object */
	iCryptEncrypt( iHashContext, objectPtr, length );
	iCryptEncrypt( iHashContext, objectPtr, 0 );
	getCheckInternalResource2( iHashContext, hashInfoPtr,
							   RESOURCE_TYPE_CRYPT, sigCheckInfoPtr );
	status = checkSignature( objectPtr + length, sigCheckInfoPtr,
							 hashInfoPtr, SIGNATURE_X509 );
	unlockResource( hashInfoPtr );

	/* Clean up */
	iCryptDestroyObject( iHashContext );
	unlockResourceExit( sigCheckInfoPtr, status );
	}

/****************************************************************************
*																			*
*							Create/Check a Signature 						*
*																			*
****************************************************************************/

/* Create/check a signature */

CRET cryptCreateSignature( void CPTR signature, int CPTR signatureLength,
						   const CRYPT_CONTEXT signContext,
						   const CRYPT_CONTEXT hashContext )
	{
	CRYPT_INFO *hashInfoPtr, *pkcInfoPtr;
	int status;

	/* Perform basic error checking */
	if( signature != NULL )
		{
		if( checkBadPtrWrite( signature, MIN_CRYPT_OBJECTSIZE ) )
			return( CRYPT_BADPARM1 );
		memset( signature, 0, MIN_CRYPT_OBJECTSIZE );
		}
	if( checkBadPtrWrite( signatureLength, sizeof( int ) ) )
		return( CRYPT_BADPARM2 );
	*signatureLength = 0;
	status = krnlSendMessage( signContext, RESOURCE_MESSAGE_CHECK, NULL,
							  RESOURCE_MESSAGE_CHECK_PKC_SIGN, CRYPT_BADPARM3 );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( hashContext, RESOURCE_MESSAGE_CHECK, NULL,
								  RESOURCE_MESSAGE_CHECK_HASH, CRYPT_BADPARM4 );
	if( cryptStatusError( status ) )
		return( status );
	getCheckResource( signContext, pkcInfoPtr, RESOURCE_TYPE_CRYPT,
					  CRYPT_BADPARM3 );
	getCheckResource2( hashContext, hashInfoPtr, RESOURCE_TYPE_CRYPT,
					   CRYPT_BADPARM4, pkcInfoPtr );
	if( !hashInfoPtr->ctxHash.done )
		unlockResourceExit2( hashInfoPtr, pkcInfoPtr, CRYPT_INCOMPLETE );

	/* Call the low-level signature create function to create the signature */
	status = createSignature( signature, signatureLength, pkcInfoPtr,
							  hashInfoPtr, SIGNATURE_CRYPTLIB );
	unlockResourceExit2( hashInfoPtr, pkcInfoPtr, status );
	}

/* Check a signature on a block of data */

CRET cryptCheckSignature( const void CPTR signature,
						  const CRYPT_HANDLE sigCheckKey,
						  const CRYPT_CONTEXT hashContext )
	{
	CRYPT_CONTEXT context;
	CRYPT_INFO *hashInfoPtr, *cryptInfoPtr;
	int status;

	/* Perform basic error checking */
	if( checkBadPtrRead( signature, MIN_CRYPT_OBJECTSIZE ) )
		return( CRYPT_BADPARM1 );
	status = krnlSendMessage( sigCheckKey, RESOURCE_MESSAGE_CHECK, NULL,
							  RESOURCE_MESSAGE_CHECK_PKC_SIGCHECK, CRYPT_BADPARM2 );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( hashContext, RESOURCE_MESSAGE_CHECK, NULL,
								  RESOURCE_MESSAGE_CHECK_HASH, CRYPT_BADPARM3 );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( sigCheckKey, RESOURCE_MESSAGE_GETDATA,
								  &context, RESOURCE_MESSAGE_DATA_CONTEXT,
								  CRYPT_BADPARM2 );
	if( cryptStatusError( status ) )
		return( status );
	getCheckInternalResource( context, cryptInfoPtr, RESOURCE_TYPE_CRYPT );
	getCheckResource2( hashContext, hashInfoPtr, RESOURCE_TYPE_CRYPT,
					   CRYPT_BADPARM3, cryptInfoPtr );
	if( !hashInfoPtr->ctxHash.done )
		unlockResourceExit2( hashInfoPtr, cryptInfoPtr, CRYPT_INCOMPLETE );

	/* Call the low-level signature check function to check the signature */
	status = checkSignature( signature, cryptInfoPtr, hashInfoPtr,
							 SIGNATURE_CRYPTLIB );
	unlockResourceExit2( hashInfoPtr, cryptInfoPtr, status );
	}

/****************************************************************************
*																			*
*							Extended Create/Check a Signature 				*
*																			*
****************************************************************************/

/* Create a CMS signature */

static int createSignatureCMS( void *signature, int *signatureLength,
							   CRYPT_INFO *pkcInfoPtr,
							   CRYPT_INFO *hashInfoPtr,
							   const CRYPT_CERTIFICATE extraData )
	{
	CRYPT_CERTIFICATE iCmsAttributes = extraData;
	CRYPT_INFO cmsHashInfo;
	HASHFUNCTION hashFunction;
	STREAM stream;
	BYTE temp, encodedAttributes[ 256 ];
	BYTE dataSignature[ CRYPT_MAX_PKCSIZE ];
	const CRYPT_ALGO hashAlgo = hashInfoPtr->capabilityInfo->cryptAlgo;
	int hashInfoSize, hashInputSize, hashOutputSize;
	int encodedAttributeSize, dataSignatureSize, length, status;

	/* Get the hash algorithm information and copy the relevant details
	   across to the CMS hashInfo */
	if( !getHashParameters( hashAlgo, &hashFunction, &hashInputSize,
							&hashOutputSize, &hashInfoSize ) )
		return( CRYPT_ERROR );/* Internal error, should never occur */
	memset( &cmsHashInfo, 0, sizeof( CRYPT_INFO ) );
	cmsHashInfo.capabilityInfo = hashInfoPtr->capabilityInfo;

	/* If there are no attributes included as extra data, generate them
	   ourselves */
	if( extraData == CRYPT_USE_DEFAULT )
		{
		status = iCryptCreateCert( &iCmsAttributes,
								   CRYPT_CERTTYPE_CMS_ATTRIBUTES );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Add the hash as a messageDigest attibute, replacing any existing value
	   if necessary */
	iCryptDeleteCertComponent( iCmsAttributes, CRYPT_CERTINFO_CMS_MESSAGEDIGEST );
	status = iCryptAddCertComponent( iCmsAttributes,
					CRYPT_CERTINFO_CMS_MESSAGEDIGEST, hashInfoPtr->ctxHash.hash,
					hashInfoPtr->capabilityInfo->blockSize );
	if( cryptStatusError( status ) )
		return( status );

	/* Export the attributes into an encoded signedAttributes data block,
	   replace the IMPLICIT [ 0 ] tag at the start with a SET OF tag to allow
	   the attributes to be hashed, hash them into the CMS hashInfo, and
	   replace the original tag */
	status = iCryptExportCert( encodedAttributes, &encodedAttributeSize,
							   iCmsAttributes );
	if( cryptStatusError( status ) )
		return( status );
	temp = encodedAttributes[ 0 ];
	encodedAttributes[ 0 ] = BER_SET;
	hashFunction( NULL, cmsHashInfo.ctxHash.hash, encodedAttributes,
				  encodedAttributeSize, HASH_ALL );
	encodedAttributes[ 0 ] = temp;

	/* Create the signature */
	status = createSignature( ( signature == NULL ) ? NULL : dataSignature,
				&dataSignatureSize, pkcInfoPtr, &cmsHashInfo, SIGNATURE_CMS );
	zeroise( &cmsHashInfo, sizeof( CRYPT_INFO ) );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the signerInfo record */
	sMemOpen( &stream, signature, STREAMSIZE_UNKNOWN );
	status = writeSignerInfo( &stream, pkcInfoPtr->ctxPKC.iDataCert, hashAlgo,
							  encodedAttributes, encodedAttributeSize,
							  dataSignature, dataSignatureSize );
	length = sMemSize( &stream );
	sMemDisconnect( &stream );
	if( !cryptStatusError( status ) )
		*signatureLength = length;

	/* Destroy the attributes if they were generated internally */
	if( iCmsAttributes != extraData )
		iCryptDestroyObject( iCmsAttributes );

	return( status );
	}

/* Check a CMS signature */

static int checkSignatureCMS( const void *signature, CRYPT_INFO *pkcInfoPtr,
							  CRYPT_INFO *hashInfoPtr,
							  CRYPT_CERTIFICATE *extraData,
							  CRYPT_HANDLE iSigCheckKey )
	{
	CRYPT_CERTIFICATE iCmsAttributes;
	CRYPT_ALGO signatureHashAlgorithm;
	CRYPT_INFO cmsHashInfo;
	HASHFUNCTION hashFunction;
	STREAM stream;
	BYTE hashValue[ CRYPT_MAX_HASHSIZE ];
	const BYTE setTag[] = { BER_SET };
	const CRYPT_ALGO hashAlgo = hashInfoPtr->capabilityInfo->cryptAlgo;
	void *hashInfo, *iAndSStart, *encodedAttributes, *dataSignature;
	int hashInfoSize, hashInputSize, hashOutputSize;
	int encodedAttributeSize, hashValueSize, status;

	/* Get the hash algorithm information and copy the relevant details
	   across to the CMS hashInfo */
	if( !getHashParameters( hashAlgo, &hashFunction, &hashInputSize,
							&hashOutputSize, &hashInfoSize ) )
		return( CRYPT_ERROR );/* Internal error, should never occur */
	memset( &cmsHashInfo, 0, sizeof( CRYPT_INFO ) );
	cmsHashInfo.capabilityInfo = hashInfoPtr->capabilityInfo;

	/* Unpack the SignerInfo record and make sure that the supplied key is
	   the correct one for the sig check and the supplied hash context
	   matches the algorithm used in the signature */
	sMemConnect( &stream, signature, STREAMSIZE_UNKNOWN );
	status = readSignerInfo( &stream, &signatureHashAlgorithm,
							 &iAndSStart, &encodedAttributes,
							 &encodedAttributeSize, &dataSignature );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	if( krnlSendMessage( iSigCheckKey, RESOURCE_IMESSAGE_COMPARE,
			iAndSStart, RESOURCE_MESSAGE_COMPARE_ISSUERANDSERIALNUMBER, 0 ) != CRYPT_OK )
		return( CRYPT_WRONGKEY );
	if( signatureHashAlgorithm != hashAlgo )
		return( CRYPT_BADPARM3 );

	/* Hash the signedAttributes data block, substituting a SET OF tag for
	   the IMPLICIT [ 0 ] tag at the start */
	if( ( hashInfo = malloc( hashInfoSize ) ) == NULL )
		return( CRYPT_NOMEM );
	hashFunction( hashInfo, NULL, ( BYTE * ) setTag, sizeof( BYTE ), HASH_START );
	hashFunction( hashInfo, cmsHashInfo.ctxHash.hash,
		( ( BYTE * ) encodedAttributes ) + 1, encodedAttributeSize - 1, HASH_END );
	zeroise( hashInfo, hashInfoSize );
	free( hashInfo );

	/* Check the signature */
	status = checkSignature( dataSignature, pkcInfoPtr, &cmsHashInfo,
							 SIGNATURE_CMS );
	zeroise( &cmsHashInfo, sizeof( CRYPT_INFO ) );
	if( cryptStatusError( status ) )
		return( status );

	/* Import the attributes and make sure the data hash value given in the
	   signed attributes matches the user-supplied hash */
	status = iCryptImportCert( encodedAttributes, &iCmsAttributes, NULL );
	if( cryptStatusError( status ) )
		return( status );
	status = iCryptGetCertComponent( iCmsAttributes,
				CRYPT_CERTINFO_CMS_MESSAGEDIGEST, hashValue, &hashValueSize );
	if( cryptStatusOK( status ) && \
		( hashValueSize != hashInfoPtr->capabilityInfo->blockSize || \
		  memcmp( hashValue, hashInfoPtr->ctxHash.hash, hashValueSize ) ) )
		status = CRYPT_BADSIG;
	if( cryptStatusError( status ) )
		{
		iCryptDestroyObject( iCmsAttributes );
		return( status );
		}

	/* If the user wants to look at the attributes, make them externally
	   visible, otherwise delete them */
	if( extraData != NULL )
		{
		const int isInternal = FALSE;

		krnlSendMessage( iCmsAttributes, RESOURCE_IMESSAGE_SETPROPERTY,
						 ( int * ) &isInternal,
						 RESOURCE_MESSAGE_PROPERTY_INTERNAL, 0 );
		*extraData = iCmsAttributes;
		}
	else
		iCryptDestroyObject( iCmsAttributes );

	return( status );
	}

/* Create/check an extended signature type, either a cryptlib signature or a
   CMS-style signature */

CRET cryptCreateSignatureEx( void CPTR signature, int CPTR signatureLength,
							 const CRYPT_FORMAT_TYPE formatType,
							 const CRYPT_CONTEXT signContext,
							 const CRYPT_CONTEXT hashContext,
							 const CRYPT_HANDLE extraData )
	{
	CRYPT_INFO *hashInfoPtr, *pkcInfoPtr;
	int status;

	/* Perform basic error checking */
	if( signature != NULL )
		{
		if( checkBadPtrWrite( signature, MIN_CRYPT_OBJECTSIZE ) )
			return( CRYPT_BADPARM1 );
		memset( signature, 0, MIN_CRYPT_OBJECTSIZE );
		}
	if( checkBadPtrWrite( signatureLength, sizeof( int ) ) )
		return( CRYPT_BADPARM2 );
	*signatureLength = 0;
	if( formatType <= CRYPT_FORMAT_NONE || formatType >= CRYPT_FORMAT_LAST )
		return( CRYPT_BADPARM3 );
	if( formatType == CRYPT_FORMAT_PGP )
		return( CRYPT_ERROR );	/* Not supported yet */
	getCheckResource( signContext, pkcInfoPtr, RESOURCE_TYPE_CRYPT,
					  CRYPT_BADPARM4 );
	if( pkcInfoPtr->type != CONTEXT_PKC || pkcInfoPtr->ctxPKC.isPublicKey )
		unlockResourceExit( pkcInfoPtr, CRYPT_BADPARM4 );
	if( !pkcInfoPtr->ctxPKC.keySet )
		unlockResourceExit( pkcInfoPtr, CRYPT_NOKEY );
	if( formatType == CRYPT_FORMAT_CMS || \
		formatType == CRYPT_FORMAT_SMIME )
		{
		int certType;

		/* Make sure the signing context has a cert attached to it */
		status = cryptGetCertComponentNumeric( signContext,
										CRYPT_CERTINFO_CERTTYPE, &certType );
		if( cryptStatusError( status ) ||
			( certType != CRYPT_CERTTYPE_CERTIFICATE && \
			  certType != CRYPT_CERTTYPE_CERTCHAIN ) )
			unlockResourceExit( pkcInfoPtr, CRYPT_BADPARM4 );

		/* Make sure the extra data object is in order */
		if( extraData != CRYPT_USE_DEFAULT )
			{
			status = cryptGetCertComponentNumeric( extraData,
										CRYPT_CERTINFO_CERTTYPE, &certType );
			if( cryptStatusError( status ) || \
				certType != CRYPT_CERTTYPE_CMS_ATTRIBUTES )
				return( CRYPT_BADPARM6 );
			}
		}
	getCheckResource2( hashContext, hashInfoPtr, RESOURCE_TYPE_CRYPT,
					   CRYPT_BADPARM5, pkcInfoPtr );
	if( hashInfoPtr->type != CONTEXT_HASH )
		unlockResourceExit2( hashInfoPtr, pkcInfoPtr, CRYPT_BADPARM5 );
	if( !hashInfoPtr->ctxHash.done )
		unlockResourceExit2( hashInfoPtr, pkcInfoPtr, CRYPT_INCOMPLETE );
	if( formatType == CRYPT_FORMAT_CRYPTLIB && extraData != CRYPT_USE_DEFAULT )
		unlockResourceExit2( hashInfoPtr, pkcInfoPtr, CRYPT_BADPARM6 );

	/* Call the low-level signature create function to create the signature */
	if( formatType == CRYPT_FORMAT_CRYPTLIB )
		status = createSignature( signature, signatureLength, pkcInfoPtr,
								  hashInfoPtr, SIGNATURE_CRYPTLIB );
	else
		{
		status = createSignatureCMS( signature, signatureLength,
									 pkcInfoPtr, hashInfoPtr, extraData );
		if( status < CRYPT_BADPARM2 && status > CRYPT_BADPARM5 )
			/* Remap the error code to take into account the missing
			   formatType parameter */
			status--;
		}

	/* Clean up */
	unlockResourceExit2( hashInfoPtr, pkcInfoPtr, status );
	}

static CRYPT_FORMAT_TYPE getFormatType( const void *data )
	{
	CRYPT_FORMAT_TYPE formatType = CRYPT_FORMAT_NONE;
	STREAM stream;
	int length, status;

	/* Figure out what we've got.  A cryptlib signature begins:
		cryptlibSignature ::= SEQUENCE {
			version		INTEGER (3),
			keyID [ 0 ]	OCTET STRING
	   while a CMS signature begins:
		cmsSignature ::= SEQUENCE {
			version		INTEGER (1),
			digestAlgo	SET OF {
	   which allows us to determine which type of object we have */
	sMemConnect( &stream, data, 50 );
	status = readSequence( &stream, &length );
	if( !cryptStatusError( status ) )
		{
		long version;

		if( !cryptStatusError( readShortInteger( &stream, &version ) ) )
			formatType = ( version == 1 ) ? CRYPT_FORMAT_CMS : \
						 ( version == 3 ) ? CRYPT_FORMAT_CRYPTLIB : \
						 CRYPT_FORMAT_NONE;
		}
	sMemDisconnect( &stream );

	return( formatType  );
	}

CRET cryptCheckSignatureEx( void CPTR signature,
							const CRYPT_HANDLE sigCheckKey,
							const CRYPT_CONTEXT hashContext,
							CRYPT_HANDLE *extraData )
	{
	CRYPT_FORMAT_TYPE formatType;
	CRYPT_CONTEXT context;
	CRYPT_INFO *hashInfoPtr, *pkcInfoPtr;
	int status;

	/* Perform basic error checking */
	if( signature != NULL && checkBadPtrRead( signature, MIN_CRYPT_OBJECTSIZE ) )
		return( CRYPT_BADPARM1 );
	if( ( formatType = getFormatType( signature ) ) == CRYPT_FORMAT_NONE )
		return( CRYPT_BADDATA );
	status = krnlSendMessage( sigCheckKey, RESOURCE_MESSAGE_GETDATA, &context,
							  RESOURCE_MESSAGE_DATA_CONTEXT, CRYPT_BADPARM2 );
	if( cryptStatusError( status ) )
		return( status );
	getCheckInternalResource( context, pkcInfoPtr, RESOURCE_TYPE_CRYPT );
	if( pkcInfoPtr->type != CONTEXT_PKC )
		unlockResourceExit( pkcInfoPtr, CRYPT_BADPARM2 );
	if( !pkcInfoPtr->ctxPKC.keySet )
		unlockResourceExit( pkcInfoPtr, CRYPT_NOKEY );
	if( formatType == CRYPT_FORMAT_CMS )
		{
		int certType;

		/* Make sure the sig check key includes a cert */
		status = cryptGetCertComponentNumeric( sigCheckKey,
										CRYPT_CERTINFO_CERTTYPE, &certType );
		if( cryptStatusError( status ) ||
			( certType != CRYPT_CERTTYPE_CERTIFICATE && \
			  certType != CRYPT_CERTTYPE_CERTCHAIN ) )
			unlockResourceExit( pkcInfoPtr, CRYPT_BADPARM2 );
		}
	getCheckResource2( hashContext, hashInfoPtr, RESOURCE_TYPE_CRYPT,
					   CRYPT_BADPARM3, pkcInfoPtr );
	if( hashInfoPtr->type != CONTEXT_HASH )
		unlockResourceExit2( hashInfoPtr, pkcInfoPtr, CRYPT_BADPARM3 );
	if( !hashInfoPtr->ctxHash.done )
		unlockResourceExit2( hashInfoPtr, pkcInfoPtr, CRYPT_INCOMPLETE );

	/* Call the low-level signature check function to check the signature */
	if( formatType == CRYPT_FORMAT_CRYPTLIB )
		{
		if( extraData != NULL )
			unlockResourceExit2( hashInfoPtr, pkcInfoPtr, CRYPT_BADPARM4 );
		status = checkSignature( signature, pkcInfoPtr, hashInfoPtr,
								 SIGNATURE_CRYPTLIB );
		}
	else
		{
		if( extraData != NULL )
			{
			if( checkBadPtrWrite( extraData, sizeof( int ) ) )
				return( CRYPT_BADPARM5 );
			*extraData = CRYPT_ERROR;
			}
		status = checkSignatureCMS( signature, pkcInfoPtr, hashInfoPtr,
									extraData, sigCheckKey );
		}

	unlockResourceExit2( hashInfoPtr, pkcInfoPtr, status );
	}

/* Internal versions of the above.  These skip a lot of the checking done by
   the external versions since they're only called by cryptlib internal
   functions which have already checked the parameters for validity */

int iCryptCreateSignatureEx( void *signature, int *signatureLength,
							 const CRYPT_FORMAT_TYPE formatType,
							 const CRYPT_CONTEXT iSignContext,
							 const CRYPT_CONTEXT iHashContext,
							 const CRYPT_HANDLE iExtraData )
	{
	CRYPT_INFO *pkcInfoPtr, *hashInfoPtr;
	int status;

	/* Perform simplified error checking */
	*signatureLength = 0;
	getCheckInternalResource( iSignContext, pkcInfoPtr, RESOURCE_TYPE_CRYPT );
	getCheckInternalResource2( iHashContext, hashInfoPtr,
							   RESOURCE_TYPE_CRYPT, pkcInfoPtr );

	/* Call the low-level signature create function to create the signature */
	if( formatType == CRYPT_FORMAT_CRYPTLIB )
		status = createSignature( signature, signatureLength, pkcInfoPtr,
								  hashInfoPtr, SIGNATURE_CRYPTLIB );
	else
		{
		status = createSignatureCMS( signature, signatureLength,
									 pkcInfoPtr, hashInfoPtr, iExtraData );
		if( status <= CRYPT_BADPARM2 && status >= CRYPT_BADPARM5 )
			/* Remap the error code to take into account the missing
			   formatType parameter */
			status--;
		}
	unlockResourceExit2( pkcInfoPtr, hashInfoPtr, status );
	}

int iCryptCheckSignatureEx( const void *signature,
							const CRYPT_HANDLE iSigCheckKey,
							const CRYPT_CONTEXT iHashContext,
							CRYPT_HANDLE *extraData )
	{
	CRYPT_FORMAT_TYPE formatType;
	CRYPT_CONTEXT context;
	CRYPT_INFO *pkcInfoPtr, *hashInfoPtr;
	int status;

	/* Perform basic error checking */
	if( ( formatType = getFormatType( signature ) ) == CRYPT_FORMAT_NONE )
		return( CRYPT_BADDATA );
	status = krnlSendMessage( iSigCheckKey, RESOURCE_IMESSAGE_GETDATA,
							  &context, RESOURCE_MESSAGE_DATA_CONTEXT,
							  CRYPT_SIGNALLED );
	if( cryptStatusError( status ) )
		return( status );
	getCheckInternalResource( context, pkcInfoPtr, RESOURCE_TYPE_CRYPT );
	getCheckInternalResource2( iHashContext, hashInfoPtr,
							   RESOURCE_TYPE_CRYPT, pkcInfoPtr );

	/* Call the low-level signature check function to check the signature */
	if( formatType == CRYPT_FORMAT_CRYPTLIB )
		status = checkSignature( signature, pkcInfoPtr, hashInfoPtr,
								 SIGNATURE_CRYPTLIB );
	else
		{
		if( extraData != NULL )
			*extraData = CRYPT_ERROR;
		status = checkSignatureCMS( signature, pkcInfoPtr, hashInfoPtr,
									extraData, iSigCheckKey );
		}

	unlockResourceExit2( pkcInfoPtr, hashInfoPtr, status );
	}
