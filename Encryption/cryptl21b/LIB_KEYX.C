/****************************************************************************
*																			*
*						  cryptlib Key Exchange Routines					*
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

/* Prototypes for functions in lib_rand.c */

int getRandomData( BYTE *buffer, const int length );
int getNonzeroRandomData( BYTE *buffer, const int length );

/* Prototypes for functions in lib_kg.c */

int getDLExpSize( const int primeSize );

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
*								Key Wrapping Functions						*
*																			*
****************************************************************************/

/* Encrypt data using PKCS #1 formatting.  Returns an error code or the
   number of output bytes */

static int pkcs1Encrypt( BYTE *data, const CRYPT_INFO *cryptInfoPtr,
						 const void *payload, const int payloadSize,
						 const RECIPIENT_TYPE recipientType )
	{
	const CRYPT_INFO *sessionKeyInfoPtr = ( CRYPT_INFO * ) payload;
	const int length = bitsToBytes( cryptInfoPtr->ctxPKC.keySizeBits );
	const int padSize = length - ( payloadSize + 3 );
	int keyOffset = 0, status;

	/* Make sure the key is long enough to encrypt the payload.  PKCS #1
	   requires that the maximum payload size be 11 bytes less than the
	   length (to give a minimum of 8 bytes of random padding) */
	if( payloadSize > length - 11 )
		return( CRYPT_OVERFLOW );

	/* Encode the payload using the format given in PKCS #1.  The format for
	   encrypted data is [ 0 ][ 2 ][ nonzero random padding ][ 0 ][ payload ]
	   which is done by the following code.  Note that the random padding is
	   a nice place for a subliminal channel, especially with large public
	   key sizes where you can communicate more information in the padding
	   than in the payload */
	data[ 0 ] = 0;
	data[ 1 ] = 2;
	status = getNonzeroRandomData( data + 2, padSize );
	data[ 2 + padSize ] = 0;
	if( cryptStatusError( status ) )
		return( status );

	/* If the payload is structured data, write it now */
	if( recipientType == RECIPIENT_CRYPTLIB )
		{
		STREAM stream;

		/* Write the keying information into the buffer after the end of the
		   PKCS #1 padding */
		sMemConnect( &stream, data + 2 + padSize + 1, payloadSize );
		status = writeKeyInfo( &stream, sessionKeyInfoPtr, &keyOffset, FALSE,
							   RECIPIENT_CRYPTLIB );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Since the key offset is given from the start of the buffer, we need to
	   adjust it to take the padding into account */
	keyOffset += 2 + padSize + 1;

	/* Copy the payload in at the last possible moment, then encrypt it */
	if( recipientType != RECIPIENT_RAW )
		memcpy( data + keyOffset, sessionKeyInfoPtr->ctxConv.userKey,
				sessionKeyInfoPtr->ctxConv.userKeyLength );
	else
		memcpy( data + keyOffset, payload, payloadSize );
	status = cryptInfoPtr->capabilityInfo->encryptFunction( \
							( CRYPT_INFO * ) cryptInfoPtr, data, length );
	if( cryptStatusError( status ) )
		return( status );

	/* Sometimes (about 1/256 times) the encrypted size will be less than the
	   modulus size, which causes problems for functions which rely on the
	   length remaining constant between the length query and encrypt data
	   calls.  In addition PKCS #1 requires that values be zero-padded to the
	   modulus size (although this makes the result non-DER compliant).
	   Because of this we zero-pad the result if necessary */
	if( status < length )
		{
		const int delta = length - status;

		memmove( data + delta, data, status );
		memset( data, 0, delta );
		}

	return( length );
	}

/* Decrypt data using PKCS #1 formatting */

static int pkcs1Decrypt( void *data, const int dataLength,
						 CRYPT_INFO *cryptInfoPtr, void *payload,
						 const RECIPIENT_TYPE recipientType )
	{
	CRYPT_CONTEXT *iCryptContext = ( CRYPT_CONTEXT * ) payload;
	STREAM stream;
	int length, ch, i, status;

	/* Extract the encrypted key from the buffer and decrypt it */
	status = cryptInfoPtr->capabilityInfo->decryptFunction( cryptInfoPtr,
															data, dataLength );
	if( cryptStatusError( status ) )
		return( status );
	length = status;

	/* Undo the PKCS #1 padding.  The PKCS format for encrypted data is
	   [ 0 ][ 2 ][ random nonzero padding ][ 0 ][ payload ] with a minimum of
	   8 bytes padding, which is checked for by the following code.  Since
	   the bignum code performs zero-truncation, we never see the leading
	   zero so the first byte should always be a 2 */
	sMemConnect( &stream, data, length );
	if( sgetc( &stream ) != 2 )
		return( CRYPT_BADDATA );
	for( i = 0; i < length - 3; i++ )
		if( ( ch = sgetc( &stream ) ) == 0 )
			break;
	if( ch != 0 || i < 8 )
		return( CRYPT_BADDATA );
	length -= 1 + i + 1;	/* [ 2 ] + padding + [ 0 ] */

	/* Create an encryption context loaded with keying information from the
	   decrypted buffer contents.  If it's a cryptlib record we can recreate
	   the session key context from it, if it's CMS we rely on the caller
	   having created the context for us */
	if( recipientType == RECIPIENT_CRYPTLIB )
		{
		status = readKeyInfo( &stream, iCryptContext );
		if( cryptStatusError( status ) )
			/* Make sure we never return a leftover handle if the import
			   failed */
			*iCryptContext = CRYPT_ERROR;
		}
	else
		if( recipientType == RECIPIENT_RAW )
			memcpy( payload, stream.buffer + stream.bufPos, length );
		else
			status = iCryptLoadKey( *iCryptContext, stream.buffer +
									stream.bufPos, length );
	sMemClose( &stream );

	return( cryptStatusError( status ) ? status : CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Low-level Key Export Functions					*
*																			*
****************************************************************************/

/* Export a conventionally encrypted session key */

static int exportConventionalKey( void *encryptedKey, int *encryptedKeyLength,
								  CRYPT_INFO *cryptInfoPtr,
								  const CRYPT_INFO *sessionKeyInfoPtr,
								  const RECIPIENT_TYPE recipientType )
	{
	STREAM stream;
	BYTE *buffer;
	int status, keyOffset;

	/* Load an IV into the exporting context.  This is somewhat nasty in that
	   a side-effect of calling cryptExportKey() is to load an IV into the
	   context which isn't really part of the functions job description.  The
	   alternative is to require the user to explicitly load an IV before
	   calling cryptExportKey(), which is equally nasty (they'll never
	   remember).  The lesser of the two evils is to load the IV here and
	   assume that anyone messing with the low-level cryptLoadIV() function
	   will read the docs which warn about the side-effects of
	   cryptExportKey() (anyone who needs to call cryptLoadIV() probably won't
	   be using the mid-level functions anyway).

	   Note that we always load a new IV when we export a key because the
	   caller may be using the context to exchange multiple keys.  Since each
	   exported key requires its own IV, we perform an unconditional reload
	   rather than relying on the ivSet flag.  In addition we have to do the
	   load explicitly at this point (rather than having it done automatically
	   when we encrypt the session key) since we need to have an IV present
	   when we write the data, even if it's just a dummy write */
	if( cryptInfoPtr->capabilityInfo->initIVFunction != NULL )
		cryptInfoPtr->capabilityInfo->initIVFunction( cryptInfoPtr, NULL, 0 );

	/* If we're just doing a length check, write the data to a null stream
	   and return its length */
	if( encryptedKey == NULL )
		{
		STREAM nullStream;
		BYTE dummyBuffer[ CRYPT_MAX_PKCSIZE ];	/* See note below */

		sMemOpen( &nullStream, NULL, 0 );
		status = writeKEKInfo( &nullStream, cryptInfoPtr, dummyBuffer,
							   sizeofKeyInfo( sessionKeyInfoPtr, TRUE,
							   recipientType ), recipientType );
		*encryptedKeyLength = sMemSize( &nullStream );
		sMemClose( &nullStream );

		return( status );
		}

	/* Initialise various things (the use of CRYPT_MAX_PKCSIZE isn't
	   strictly appropriate here, but it's a good indication of the amount
	   of memory needed) */
	if( ( status = krnlMemalloc( ( void ** ) &buffer, CRYPT_MAX_PKCSIZE ) ) != CRYPT_OK )
		return( status );
	sMemOpen( &stream, buffer, CRYPT_MAX_PKCSIZE );

	/* Write the key information into the buffer and encrypt it */
	status = writeKeyInfo( &stream, sessionKeyInfoPtr, &keyOffset, TRUE,
						   recipientType );
	if( cryptStatusOK( status ) )
		{
		/* Copy the key in at the last possible moment, then encrypt it */
		memcpy( buffer + keyOffset, sessionKeyInfoPtr->ctxConv.userKey,
				sessionKeyInfoPtr->ctxConv.userKeyLength );
		status = cryptInfoPtr->capabilityInfo->encryptFunction( cryptInfoPtr,
											buffer, sMemSize( &stream ) );
		}

	/* Now write the encrypted key to the output stream */
	if( cryptStatusOK( status ) )
		{
		STREAM outputStream;

		sMemOpen( &outputStream, encryptedKey, STREAMSIZE_UNKNOWN );
		status = writeKEKInfo( &outputStream, cryptInfoPtr, buffer,
							   sMemSize( &stream ), recipientType );
		*encryptedKeyLength = sMemSize( &outputStream );
		sMemDisconnect( &outputStream );
		}

	/* Clean up */
	sMemClose( &stream );
	krnlMemfree( ( void ** ) &buffer );
	return( status );
	}

/* Export a public-key encrypted session key */

static int exportPublicKey( void *encryptedKey, int *encryptedKeyLength,
							const CRYPT_INFO *cryptInfoPtr,
							const CRYPT_INFO *sessionKeyInfoPtr,
							const void *auxInfo, const int auxInfoLength,
							const RECIPIENT_TYPE recipientType )
	{
	BYTE *buffer;
	const int payloadSize = ( recipientType == RECIPIENT_CRYPTLIB ) ? \
							sizeofKeyInfo( sessionKeyInfoPtr, FALSE,
								RECIPIENT_CRYPTLIB ) : \
							sessionKeyInfoPtr->ctxConv.userKeyLength;
	int status;

	/* If we're just doing a length check, write the data to a null stream
	   and return its length */
	if( encryptedKey == NULL )
		{
		STREAM nullStream;
		BYTE dummyBuffer[ CRYPT_MAX_PKCSIZE ];

		/* Since the encrypted key hasn't been evaluated yet there's nothing
		   to write, so we write a dummy value in its place */
		sMemOpen( &nullStream, NULL, 0 );
		status = writeKeyTransInfo( &nullStream, cryptInfoPtr, dummyBuffer,
							bitsToBytes( cryptInfoPtr->ctxPKC.keySizeBits ),
							auxInfo, auxInfoLength, recipientType );
		if( cryptStatusOK( status ) )
			*encryptedKeyLength = sMemSize( &nullStream );
		sMemClose( &nullStream );

		return( status );
		}

	/* Allocate a secure buffer and encrypt the data in the PKCS #1 format */
	if( ( status = krnlMemalloc( ( void ** ) &buffer, CRYPT_MAX_PKCSIZE ) ) != CRYPT_OK )
		return( status );
	status = pkcs1Encrypt( buffer, cryptInfoPtr, sessionKeyInfoPtr,
						   payloadSize, recipientType );

	/* Now write the encrypted key to the output stream */
	if( !cryptStatusError( status ) )
		{
		STREAM outputStream;

		sMemOpen( &outputStream, encryptedKey, STREAMSIZE_UNKNOWN );
		status = writeKeyTransInfo( &outputStream, cryptInfoPtr, buffer,
									status, auxInfo, auxInfoLength,
									recipientType );
		if( cryptStatusOK( status ) )
			*encryptedKeyLength = sMemSize( &outputStream );
		sMemDisconnect( &outputStream );
		}

	/* Clean up */
	krnlMemfree( ( void ** ) &buffer );
	return( status );
	}

/* Export a key agreement key */

static int exportKeyAgreeKey( void *encryptedKey, int *encryptedKeyLength,
							  const CRYPT_INFO *cryptInfoPtr,
							  const CRYPT_INFO *sessionKeyInfoPtr )
	{
	BYTE buffer[ CRYPT_MAX_PKCSIZE ];
	const int length = bitsToBytes( cryptInfoPtr->ctxPKC.keySizeBits );
	int status;

	/* If we're just doing a length check, write the data to a null stream
	   and return its length */
	if( encryptedKey == NULL )
		{
		STREAM nullStream;
		BYTE dummyBuffer[ CRYPT_MAX_PKCSIZE ];

		/* Since the DH public value hasn't been evaluated yet there's
		   nothing to write, so we write a dummy value in its place.  This
		   gets a bit complex since the y value is actually treated as part
		   of the DH key but isn't created until the export has been
		   performed, so we load a dummy y value for the export */
		sMemOpen( &nullStream, NULL, 0 );
		*dummyBuffer = ( BYTE ) '\x80';
		BN_bin2bn( dummyBuffer, length, cryptInfoPtr->ctxPKC.dhParam_y );
		status = writeKeyAgreeInfo( &nullStream, cryptInfoPtr,
									sessionKeyInfoPtr );
		BN_clear( cryptInfoPtr->ctxPKC.dhParam_y );
		if( cryptStatusOK( status ) )
			*encryptedKeyLength = sMemSize( &nullStream );
		sMemClose( &nullStream );

		return( status );
		}

	/* The DH output is generated from the implicit x which was generated
	   when the key was loaded */
	status = cryptInfoPtr->capabilityInfo->encryptFunction( \
						( CRYPT_INFO * ) cryptInfoPtr, buffer, CRYPT_UNUSED );

	/* Now write the encrypted key to the output stream */
	if( !cryptStatusError( status ) )
		{
		STREAM outputStream;

		sMemOpen( &outputStream, encryptedKey, STREAMSIZE_UNKNOWN );
		status = writeKeyAgreeInfo( &outputStream, cryptInfoPtr,
									sessionKeyInfoPtr );
		if( cryptStatusOK( status ) )
			*encryptedKeyLength = sMemSize( &outputStream );
		sMemDisconnect( &outputStream );
		}

	/* Clean up */
	zeroise( buffer, CRYPT_MAX_PKCSIZE );
	return( status );
	}

/****************************************************************************
*																			*
*							Low-level Key Import Functions					*
*																			*
****************************************************************************/

/* Import a conventionally encrypted session key */

static int importConventionalKey( void *encryptedKey,
								  CRYPT_INFO *cryptInfoPtr,
								  CRYPT_CONTEXT *iSessionKeyContext )
	{
	OBJECT_INFO cryptObjectInfo;
	STREAM stream;
	BYTE *buffer, iv[ CRYPT_MAX_IVSIZE ];
	int ivSize, status;

	/* Read the encrypted key record up to the start of the encrypted key and
	   make sure we'll be using the correct type of encryption context to
	   decrypt it.  Checking the algorithm-specific parameters for the
	   encryption context is a bit too complex since they're processed
	   internally by the library routines when the context is created and may
	   not be present in an easily-accessible form.  If the caller has queried
	   the object to get the parameters to create the context then they'll be
	   set up correctly anyway, and the key decrypt will catch any errors if
	   they're not */
	sMemConnect( &stream, encryptedKey, STREAMSIZE_UNKNOWN );
	status = readKEKInfo( &stream, &cryptObjectInfo, iv, &ivSize );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	if( cryptInfoPtr->capabilityInfo->cryptAlgo != cryptObjectInfo.cryptAlgo || \
		cryptInfoPtr->capabilityInfo->cryptMode != cryptObjectInfo.cryptMode )
		return( CRYPT_BADPARM2 );

	/* Extract the encrypted key from the buffer and decrypt it */
	if( ( status = krnlMemalloc( ( void ** ) &buffer, CRYPT_MAX_PKCSIZE ) ) != CRYPT_OK )
		return( status );
	if( cryptInfoPtr->capabilityInfo->initIVFunction != NULL )
		cryptInfoPtr->capabilityInfo->initIVFunction( cryptInfoPtr, iv,
													  ivSize );
	memcpy( buffer, cryptObjectInfo.dataStart, cryptObjectInfo.dataLength );
	status = cryptInfoPtr->capabilityInfo->decryptFunction( cryptInfoPtr,
										buffer, cryptObjectInfo.dataLength );

	/* Create an encryption context loaded with keying information from the
	   decrypted buffer contents */
	if( cryptStatusOK( status ) )
		{
		sMemConnect( &stream, buffer, cryptObjectInfo.dataLength );
		status = readKeyInfo( &stream, iSessionKeyContext );
		sMemClose( &stream );
		if( cryptStatusError( status ) )
			{
			/* If the data is unrecognisable then it's more likely to be due
			   to an incorrect decryption key than to actual data corruption,
			   so we convert the error code appropriately */
			if( status == CRYPT_BADDATA )
				status = CRYPT_WRONGKEY;
			*iSessionKeyContext = CRYPT_ERROR;
			}
		}
	krnlMemfree( ( void ** ) &buffer );

	return( status );
	}

/* Import a public-key encrypted session key */

static int importPublicKey( void *encryptedKey, CRYPT_INFO *cryptInfoPtr,
							CRYPT_CONTEXT *iSessionKeyContext,
							CRYPT_CONTEXT iImportCryptContext )
	{
	OBJECT_INFO cryptObjectInfo;
	RECIPIENT_TYPE recipientType = RECIPIENT_CRYPTLIB;
	STREAM stream;
	BYTE *buffer;
	int status;

	/* Read the encrypted key record up to the start of the encrypted key and
	   make sure we've been given the correct key */
	sMemConnect( &stream, encryptedKey, STREAMSIZE_UNKNOWN );
	status = readKeyTransInfo( &stream, &cryptObjectInfo );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	if( cryptObjectInfo.formatType == CRYPT_FORMAT_CMS )
		{
		recipientType = RECIPIENT_CMS;	/* It's a CMS key record */
		if( krnlSendMessage( iImportCryptContext, RESOURCE_IMESSAGE_COMPARE,
				cryptObjectInfo.iAndSStart,
				RESOURCE_MESSAGE_COMPARE_ISSUERANDSERIALNUMBER, 0 ) != CRYPT_OK )
			status = CRYPT_WRONGKEY;
		}
	else
		if( memcmp( cryptInfoPtr->ctxPKC.keyID, cryptObjectInfo.keyID,
					KEYID_SIZE ) )
			status = CRYPT_WRONGKEY;
	if( cryptStatusError( status ) )
		return( status );

	/* Allocate storage for the decrypted key, copy it into the buffer, and
	   decrypt it */
	if( ( status = krnlMemalloc( ( void ** ) &buffer, CRYPT_MAX_PKCSIZE ) ) != CRYPT_OK )
		return( status );
	memcpy( buffer, cryptObjectInfo.dataStart, cryptObjectInfo.dataLength );
	status = pkcs1Decrypt( buffer, cryptObjectInfo.dataLength, cryptInfoPtr,
						   iSessionKeyContext, recipientType );
	krnlMemfree( ( void ** ) &buffer );
	return( status );
	}

/* Import a key agreement session key */

static int importKeyAgreeKey( void *encryptedKey, CRYPT_INFO *cryptInfoPtr,
							  CRYPT_CONTEXT *iSessionKeyContext )
	{
	CRYPT_CONTEXT iImportContext;
	CRYPT_INFO *importInfoPtr;
	OBJECT_INFO cryptObjectInfo;
	STREAM stream;
	BYTE *buffer;
	int status;

	/* Read the key agreement record.  Due to the somewhat peculiar concept
	   of what constitutes a public key for DH, this doesn't really work as
	   well as the standard key wrap algorithms since what we're reading are
	   the components of a complete context.  As a result the initiator and
	   responder for the DH exchange end up with the following:

							Initiator				Responder

	   cryptInfoPtr			p, g, x(I), y(I)		-

	   iImportContext		p, g, y(R)				p, g, y(I)

	   If we're doing the import for the responder, we copy the values from
	   the import context into the responder context and perform a key load,
	   which generates the responders x value and key ID.  This is a horrible
	   kludge, what we should be doing is passing the import context back to
	   the user but this isn't possible because cryptImportKey() passes the
	   import context by value.

	   If we're doing the import for the initiator, we just check that the
	   key used by the responder was the same as the one used by the
	   initiator */
	sMemConnect( &stream, encryptedKey, STREAMSIZE_UNKNOWN );
	status = readKeyAgreeInfo( &stream, &cryptObjectInfo, &iImportContext,
							   iSessionKeyContext );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	getCheckInternalResource( iImportContext, importInfoPtr, RESOURCE_TYPE_CRYPT );
	if( !cryptInfoPtr->ctxPKC.keySet )
		{
		BIGNUM *tmp;

		/* Swap the newly-read parameters in the import context with the
		   uninitialised values in the import context */
		tmp = cryptInfoPtr->ctxPKC.dhParam_p;
		cryptInfoPtr->ctxPKC.dhParam_p = importInfoPtr->ctxPKC.dhParam_p;
		importInfoPtr->ctxPKC.dhParam_p = tmp;
		tmp = cryptInfoPtr->ctxPKC.dhParam_g;
		cryptInfoPtr->ctxPKC.dhParam_g = importInfoPtr->ctxPKC.dhParam_g;
		importInfoPtr->ctxPKC.dhParam_g = tmp;
		tmp = cryptInfoPtr->ctxPKC.dhParam_yPrime;
		cryptInfoPtr->ctxPKC.dhParam_yPrime = importInfoPtr->ctxPKC.dhParam_yPrime;
		importInfoPtr->ctxPKC.dhParam_yPrime = tmp;

		/* Perform an internal load */
		status = cryptInfoPtr->capabilityInfo->initKeyFunction( \
								cryptInfoPtr, NULL, LOAD_INTERNAL_PUBLIC );
		if( cryptStatusOK( status ) )
			cryptInfoPtr->ctxPKC.keySet = TRUE;
		}
	else
		/* Make sure the responders key was the same as the intiators key */
		if( memcmp( cryptInfoPtr->ctxPKC.keyID, importInfoPtr->ctxPKC.keyID,
					KEYID_SIZE ) )
			status = CRYPT_WRONGKEY;
		else
			{
			BIGNUM *tmp;

			tmp = cryptInfoPtr->ctxPKC.dhParam_yPrime;
			cryptInfoPtr->ctxPKC.dhParam_yPrime = importInfoPtr->ctxPKC.dhParam_yPrime;
			importInfoPtr->ctxPKC.dhParam_yPrime = tmp;
			}
	iCryptDestroyObject( iImportContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Generate the shared secret value and load it into the session key
	   context */
	if( ( status = krnlMemalloc( ( void ** ) &buffer, CRYPT_MAX_PKCSIZE ) ) != CRYPT_OK )
		return( status );
	status = cryptInfoPtr->capabilityInfo->decryptFunction( cryptInfoPtr,
													buffer, CRYPT_UNUSED );
	if( !cryptStatusError( status ) )
		status = iCryptDeriveKey( *iSessionKeyContext, buffer, status );
	krnlMemfree( ( void ** ) &buffer );

	/* Clean up */
	if( cryptStatusError( status ) )
		{
		/* The conventional encryption context will have been created when we
		   read the key agreement info so we need to delete it before we
		   exit */
		iCryptDestroyObject( *iSessionKeyContext );
		*iSessionKeyContext = CRYPT_ERROR;
		}
	return( status );
	}

/****************************************************************************
*																			*
*							Import/Export a Session Key						*
*																			*
****************************************************************************/

/* Import an encrypted session key */

CRET cryptImportKey( void CPTR encryptedKey,
					 const CRYPT_CONTEXT importKey,
					 CRYPT_CONTEXT CPTR sessionKeyContext )
	{
	CRYPT_CONTEXT iSessionKeyContext = *sessionKeyContext;
	CRYPT_INFO *cryptInfoPtr;
	OBJECT_INFO objectInfo;
	STREAM stream;
	RESOURCE_MESSAGE_CHECK_TYPE checkType;
	RECIPIENT_TYPE recipientType = RECIPIENT_CRYPTLIB;
	BOOLEAN isKeyAgree;
	int originalOwner = CRYPT_UNUSED, status;

	/* Perform basic error checking */
	if( checkBadPtrRead( encryptedKey, MIN_CRYPT_OBJECTSIZE ) )
		return( CRYPT_BADPARM1 );
	sMemConnect( &stream, ( void * ) encryptedKey, STREAMSIZE_UNKNOWN );
	status = queryObject( &stream, &objectInfo );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	if( objectInfo.formatType == CRYPT_FORMAT_CMS )
		recipientType = RECIPIENT_CMS;
	getCheckResource( importKey, cryptInfoPtr, RESOURCE_TYPE_CRYPT,
					  CRYPT_BADPARM2 );
	isKeyAgree = ( cryptInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DH ) ? \
				 TRUE : FALSE;
	if( cryptInfoPtr->type == CONTEXT_PKC )
		checkType = ( isKeyAgree ) ? RESOURCE_MESSAGE_CHECK_PKC_KEYAGREE : \
									 RESOURCE_MESSAGE_CHECK_PKC_DECRYPT;
	else
		checkType = RESOURCE_MESSAGE_CHECK_CRYPT;
	status = krnlSendMessage( importKey, RESOURCE_MESSAGE_CHECK, NULL,
							  checkType, CRYPT_BADPARM2 );
	if( isKeyAgree && status == CRYPT_NOKEY )
		/* For key agreement keys the fact that there's no key loaded is OK
		   since the key parameters are read from the exchanged object */
		status = CRYPT_OK;
	if( cryptStatusError( status ) )
		unlockResourceExit( cryptInfoPtr, status );
	if( checkBadPtrWrite( sessionKeyContext, sizeof( CRYPT_CONTEXT ) ) )
		unlockResourceExit( cryptInfoPtr, CRYPT_BADPARM3 );

	/* If it's a CMS exported key then the session key context has to be set
	   up by the caller since CMS can't communicate session key information
	   as part of the exported key, make sure it's OK and handle object
	   security */
	if( recipientType == RECIPIENT_CMS )
		{
		int owner;

		/* Make sure the context is a conventional encryption context without
		   a key loaded */
		status = krnlSendMessage( *sessionKeyContext, RESOURCE_MESSAGE_CHECK,
						NULL, RESOURCE_MESSAGE_CHECK_CRYPT, CRYPT_BADPARM3 );
		if( status == CRYPT_OK )
			status = CRYPT_INITED;	/* We shouldn't have a key loaded */
		if( cryptStatusError( status ) && status != CRYPT_NOKEY )
			unlockResourceExit( cryptInfoPtr, status );

		/* If the importing key is owned, bind the session key context to the
		   same thread before we load a key into it.  We also need to save
		   the original owner so we can undo the binding later if things fail */
		krnlSendMessage( *sessionKeyContext, RESOURCE_MESSAGE_GETPROPERTY,
						 &originalOwner, RESOURCE_MESSAGE_PROPERTY_OWNER, 0 );
		status = krnlSendMessage( importKey, RESOURCE_MESSAGE_GETPROPERTY,
								  &owner, RESOURCE_MESSAGE_PROPERTY_OWNER,
								  CRYPT_BADPARM3 );
		if( cryptStatusOK( status ) && owner != CRYPT_UNUSED )
			krnlSendMessage( *sessionKeyContext, RESOURCE_MESSAGE_SETPROPERTY,
							 &owner, RESOURCE_MESSAGE_PROPERTY_OWNER, 0 );
		}
	else
		/* Clear the return value */
		*sessionKeyContext = CRYPT_ERROR;

	/* Import it as appropriate */
	if( cryptInfoPtr->type == CONTEXT_PKC )
		{
		if( isKeyAgree )
			status = importKeyAgreeKey( encryptedKey, cryptInfoPtr,
										&iSessionKeyContext );
		else
			status = importPublicKey( encryptedKey, cryptInfoPtr,
									  &iSessionKeyContext, importKey );
		}
	else
		status = importConventionalKey( encryptedKey, cryptInfoPtr,
										&iSessionKeyContext );
	if( recipientType == RECIPIENT_CRYPTLIB )
		{
		/* If the import succeeded, handle object security */
		if( cryptStatusOK( status ) )
			{
			const int isInternal = FALSE;
			int owner;

			/* If the importing key is bound to a thread, bind the imported
			   key to the thread as well.  If this fails and the session key
			   was created internally, we don't return the imported key to
			   the caller since it would be returned in a potentially unbound
			   state */
			status = krnlSendMessage( importKey, RESOURCE_MESSAGE_GETPROPERTY,
									  &owner, RESOURCE_MESSAGE_PROPERTY_OWNER,
									  CRYPT_BADPARM2 );
			if( cryptStatusError( status ) )
				{
				iCryptDestroyObject( iSessionKeyContext );
				unlockResourceExit( cryptInfoPtr, status );
				}
			krnlSendMessage( iSessionKeyContext, RESOURCE_IMESSAGE_SETPROPERTY,
							 &owner, RESOURCE_MESSAGE_PROPERTY_OWNER, 0 );

			/* Make the context externally visible */
			krnlSendMessage( iSessionKeyContext, RESOURCE_IMESSAGE_SETPROPERTY,
							 ( int * ) &isInternal,
							 RESOURCE_MESSAGE_PROPERTY_INTERNAL, 0 );
			*sessionKeyContext = iSessionKeyContext;
			}
		}
	else
		/* If the import failed, return the session key context to its
		   original owner */
		if( cryptStatusError( status ) )
			krnlSendMessage( *sessionKeyContext, RESOURCE_MESSAGE_SETPROPERTY,
							 &originalOwner, RESOURCE_MESSAGE_PROPERTY_OWNER, 0 );

	unlockResourceExit( cryptInfoPtr, status );
	}

/* Export an encrypted session key */

CRET cryptExportKey( void CPTR encryptedKey, int CPTR encryptedKeyLength,
					 const CRYPT_HANDLE exportKey,
					 const CRYPT_CONTEXT sessionKeyContext )
	{
	CRYPT_CONTEXT context;
	CRYPT_INFO *cryptInfoPtr, *sessionKeyInfoPtr;
	RESOURCE_MESSAGE_CHECK_TYPE checkType;
	BOOLEAN isKeyAgree;
	int status;

	/* Perform basic error checking */
	if( encryptedKey != NULL )
		{
		if( checkBadPtrWrite( encryptedKey, MIN_CRYPT_OBJECTSIZE ) )
			return( CRYPT_BADPARM1 );
		memset( encryptedKey, 0, MIN_CRYPT_OBJECTSIZE );
		}
	if( checkBadPtrWrite( encryptedKeyLength, sizeof( int ) ) )
		return( CRYPT_BADPARM2 );
	*encryptedKeyLength = 0;

	/* Get and check the exporting key */
	status = krnlSendMessage( exportKey, RESOURCE_MESSAGE_GETDATA, &context,
							  RESOURCE_MESSAGE_DATA_CONTEXT, CRYPT_BADPARM3 );
	if( cryptStatusError( status ) )
		return( status );
	getCheckInternalResource( context, cryptInfoPtr, RESOURCE_TYPE_CRYPT );
	isKeyAgree = ( cryptInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DH ) ? \
				 TRUE : FALSE;
	if( cryptInfoPtr->type == CONTEXT_PKC )
		checkType = ( isKeyAgree ) ? RESOURCE_MESSAGE_CHECK_PKC_KEYAGREE : \
									 RESOURCE_MESSAGE_CHECK_PKC_ENCRYPT;
	else
		checkType = RESOURCE_MESSAGE_CHECK_CRYPT;
	status = krnlSendMessage( exportKey, RESOURCE_MESSAGE_CHECK, NULL,
							  checkType, CRYPT_BADPARM3 );
	if( cryptStatusError( status ) )
		unlockResourceExit( cryptInfoPtr, status );

	/* Get and check the exported key */
	getCheckResource2( sessionKeyContext, sessionKeyInfoPtr,
					   RESOURCE_TYPE_CRYPT, CRYPT_BADPARM4, cryptInfoPtr );
	checkType = ( sessionKeyInfoPtr->type == CONTEXT_CONV ) ? \
				RESOURCE_MESSAGE_CHECK_CRYPT : RESOURCE_MESSAGE_CHECK_MAC;
	status = krnlSendMessage( sessionKeyContext, RESOURCE_MESSAGE_CHECK,
							  NULL, checkType, CRYPT_BADPARM4 );
	if( isKeyAgree && status == CRYPT_NOKEY )
		/* If we're using a key agreement algorithm it doesn't matter if
		   the session key context has a key loaded or not */
		status = CRYPT_OK;
	if( cryptStatusError( status ) )
		unlockResourceExit2( cryptInfoPtr, sessionKeyInfoPtr, status );

	/* Export it as appropriate */
	if( cryptInfoPtr->type == CONTEXT_PKC )
		{
		if( isKeyAgree )
			status = exportKeyAgreeKey( encryptedKey, encryptedKeyLength,
										cryptInfoPtr, sessionKeyInfoPtr );
		else
			status = exportPublicKey( encryptedKey, encryptedKeyLength,
									  cryptInfoPtr, sessionKeyInfoPtr,
									  NULL, 0, RECIPIENT_CRYPTLIB );
		}
	else
		status = exportConventionalKey( encryptedKey, encryptedKeyLength,
										cryptInfoPtr, sessionKeyInfoPtr,
										RECIPIENT_CRYPTLIB );

	unlockResourceExit2( cryptInfoPtr, sessionKeyInfoPtr, status );
	}

/****************************************************************************
*																			*
*						Extended Import/Export a Session Key				*
*																			*
****************************************************************************/

/* Determine the type of an object.  A cryptlib encrypted key begins:
		recipientInfo ::= SEQUENCE {
			version		INTEGER (2),
   or
		keyAgreementKey ::= [ 1 ] {
			publicKey	SEQUENCE {
   while a CMS encrypted key begins:
		recipientInfo ::= SEQUENCE {
			version		INTEGER (0),
   which allows us to determine which type of object we have.  Both KEK keys
   begin
		kekRecipientInfo ::= [ 2 ] {
			version		INTEGER (4) */

#if 0	/* Since cryptImportKey() and cryptImportKeyEx() currently do the
		   same thing, this function isn't needed at the moment */

static CRYPT_FORMAT_TYPE getFormatType( const void *data )
	{
	CRYPT_FORMAT_TYPE formatType;
	STREAM stream;
	int status;

	sMemConnect( &stream, data, 50 );
	if( peekTag( &stream ) == BER_SEQUENCE )
		{
		int dummy;

		/* cryptlib or CMS RecipientInfo */
		status = readSequence( &stream, &dummy );
		if( !cryptStatusError( status ) )
			{
			long version;

			if( !cryptStatusError( readShortInteger( &stream, &version ) ) )
				if( version == 0 )
					formatType = CRYPT_FORMAT_SMIME;
				else
					if( version == 2 )
						formatType = CRYPT_FORMAT_CRYPTLIB;
			}
		}
	else
		{
		long value;
		int dummy;

		if( checkReadCtag( &stream, 1, TRUE ) )
			{
			/* cryptlib KeyAgreement, CMS KeyAgreeRecipientInfo */
			readLength( &stream, &value );
			if( !cryptStatusError( readSequence( &stream, &dummy ) ) )
				formatType = CRYPT_FORMAT_CRYPTLIB;
			}
		else
			/* cryptlib or CMS KEKRecipientInfo */
			if( checkReadCtag( &stream, 2, TRUE ) )
				{
				readLength( &stream, &value );
				if( !cryptStatusError( readShortInteger( &stream, &value ) ) && \
					value == 4 )
					formatType = CRYPT_FORMAT_CRYPTLIB;
				}
		}
	sMemDisconnect( &stream );
	return( formatType );
	}
#endif /* 0 */

/* Get the issuerAndSerialNumber for a certificate */

static int getIssuerAndSerialNumber( CRYPT_HANDLE iCryptHandle,
									 BYTE **bufferPtr, int *lengthPtr )
	{
	RESOURCE_DATA msgData;
	BYTE *buffer = *bufferPtr;
	int status;

	/* Find out how large the data will be and allocate a buffer for it if
	   necessary */
	setResourceData( &msgData, NULL, 0 );
	status = krnlSendMessage( iCryptHandle, RESOURCE_IMESSAGE_GETDATA,
					&msgData, RESOURCE_MESSAGE_DATA_ISSUERANDSERIALNUMBER,
					CRYPT_BADPARM3 );
	if( cryptStatusOK( status ) && msgData.length > 1024 && \
		( buffer = malloc( msgData.length ) ) == NULL )
		status = CRYPT_NOMEM;
	if( cryptStatusError( status ) )
		return( status );

	/* Copy the data into the buffer */
	setResourceData( &msgData, buffer, 0 );
	status = krnlSendMessage( iCryptHandle, RESOURCE_IMESSAGE_GETDATA,
					&msgData, RESOURCE_MESSAGE_DATA_ISSUERANDSERIALNUMBER,
					CRYPT_BADPARM3 );
	if( cryptStatusError( status ) && msgData.length > 1024 )
		{
		free( buffer );
		return( status );
		}
	*bufferPtr = msgData.data;
	*lengthPtr = msgData.length;

	return( CRYPT_OK );
	}

/* Import/export an extended encrypted key, either a cryptlib key or a CMS
   key */

CRET cryptImportKeyEx( void CPTR encryptedKey,
					   const CRYPT_CONTEXT importKey,
					   CRYPT_CONTEXT CPTR sessionKeyContext )
	{
	/* Currently cryptImportKey() and cryptImportKeyEx() do the same thing */
	return( cryptImportKey( encryptedKey, importKey, sessionKeyContext ) );
	}

CRET cryptExportKeyEx( void CPTR encryptedKey, int CPTR encryptedKeyLength,
					   const CRYPT_FORMAT_TYPE formatType,
					   const CRYPT_HANDLE exportKey,
					   const CRYPT_CONTEXT sessionKeyContext )
	{
	CRYPT_CONTEXT context;
	CRYPT_INFO *cryptInfoPtr, *sessionKeyInfoPtr;
	const RECIPIENT_TYPE recipientType = \
			( formatType == CRYPT_FORMAT_CRYPTLIB ) ? RECIPIENT_CRYPTLIB : \
			( formatType == CRYPT_FORMAT_CMS || \
			  formatType == CRYPT_FORMAT_SMIME ) ? RECIPIENT_CMS : RECIPIENT_NONE;
	BYTE auxDataBuffer[ 1024 ], *auxData = auxDataBuffer;
	RESOURCE_MESSAGE_CHECK_TYPE checkType;
	BOOLEAN isKeyAgree;
	int auxDataLength = 1024, status;

	/* Perform basic error checking */
	if( encryptedKey != NULL )
		{
		if( checkBadPtrWrite( encryptedKey, MIN_CRYPT_OBJECTSIZE ) )
			return( CRYPT_BADPARM1 );
		memset( encryptedKey, 0, MIN_CRYPT_OBJECTSIZE );
		}
	if( checkBadPtrWrite( encryptedKeyLength, sizeof( int ) ) )
		return( CRYPT_BADPARM2 );
	*encryptedKeyLength = 0;
	if( formatType <= CRYPT_FORMAT_NONE || formatType >= CRYPT_FORMAT_LAST )
		return( CRYPT_BADPARM3 );
	if( formatType == CRYPT_FORMAT_PGP )
		return( CRYPT_BADPARM3 );	/* Not supported yet */

	/* Get and check the exporting key */
	status = krnlSendMessage( exportKey, RESOURCE_MESSAGE_GETDATA, &context,
							  RESOURCE_MESSAGE_DATA_CONTEXT, CRYPT_BADPARM3 );
	if( cryptStatusError( status ) )
		return( status );
	getCheckInternalResource( context, cryptInfoPtr, RESOURCE_TYPE_CRYPT );
	isKeyAgree = ( cryptInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_DH ) ? \
				 TRUE : FALSE;
	if( cryptInfoPtr->type == CONTEXT_PKC )
		checkType = ( isKeyAgree ) ? RESOURCE_MESSAGE_CHECK_PKC_KEYAGREE : \
									 RESOURCE_MESSAGE_CHECK_PKC_ENCRYPT;
	else
		checkType = RESOURCE_MESSAGE_CHECK_CRYPT;
	status = krnlSendMessage( exportKey, RESOURCE_MESSAGE_CHECK, NULL,
							  checkType, CRYPT_BADPARM3 );
	if( cryptStatusError( status ) )
		unlockResourceExit( cryptInfoPtr, status );

	/* Get and check the exported key */
	getCheckResource2( sessionKeyContext, sessionKeyInfoPtr,
					   RESOURCE_TYPE_CRYPT, CRYPT_BADPARM4, cryptInfoPtr );
	checkType = ( sessionKeyInfoPtr->type == CONTEXT_CONV ) ? \
				RESOURCE_MESSAGE_CHECK_CRYPT : RESOURCE_MESSAGE_CHECK_MAC;
	status = krnlSendMessage( sessionKeyContext, RESOURCE_MESSAGE_CHECK,
							  NULL, checkType, CRYPT_BADPARM4 );
	if( isKeyAgree )
		{
		/* If we're using a key agreement algorithm it doesn't matter if
		   the session key context has a key loaded or not, but the format
		   has to be cryptlib */
		if( status == CRYPT_NOKEY )
			status = CRYPT_OK;
		if( formatType == CRYPT_FORMAT_CMS || \
			formatType == CRYPT_FORMAT_SMIME )
			status = CRYPT_BADPARM3;
		}
	if( cryptStatusError( status ) )
		unlockResourceExit2( cryptInfoPtr, sessionKeyInfoPtr, status );

	/* If we're exporting a key in CMS format using a public key we need to
	   obtain the issuerAndSerialNumber */
	if( ( formatType == CRYPT_FORMAT_CMS || \
		  formatType == CRYPT_FORMAT_SMIME ) && cryptInfoPtr->type == CONTEXT_PKC )
		{
		status = getIssuerAndSerialNumber( exportKey, &auxData,
										   &auxDataLength );
		if( cryptStatusError( status ) )
			unlockResourceExit2( cryptInfoPtr, sessionKeyInfoPtr, status );
		}

	/* Export it as appropriate */
	if( cryptInfoPtr->type == CONTEXT_PKC )
		{
		if( isKeyAgree )
			status = exportKeyAgreeKey( encryptedKey, encryptedKeyLength,
										cryptInfoPtr, sessionKeyInfoPtr );
		else
			status = exportPublicKey( encryptedKey, encryptedKeyLength,
									  cryptInfoPtr, sessionKeyInfoPtr,
									  auxData, auxDataLength, recipientType );
		}
	else
		status = exportConventionalKey( encryptedKey, encryptedKeyLength,
										cryptInfoPtr, sessionKeyInfoPtr,
										recipientType );

	/* Clean up */
	if( auxData != auxDataBuffer )
		free( auxData );
	unlockResourceExit2( cryptInfoPtr, sessionKeyInfoPtr, status );
	}

/* Internal versions of the above.  These skip a lot of the checking done by
   the external versions since they're only called by cryptlib internal
   functions which have already checked the parameters for validity */

int iCryptImportKeyEx( void *encryptedKey, const CRYPT_CONTEXT iImportKey,
					   CRYPT_CONTEXT *iSessionKeyContext )
	{
	CRYPT_INFO *cryptInfoPtr;
	int status;

	/* Perform simplified error checking */
	getCheckInternalResource( iImportKey, cryptInfoPtr, RESOURCE_TYPE_CRYPT );

	/* Import it as appropriate.  We don't handle key agreement at this
	   level */
	if( cryptInfoPtr->type == CONTEXT_PKC )
		status = importPublicKey( encryptedKey, cryptInfoPtr,
								  iSessionKeyContext, iImportKey );
	else
		status = importConventionalKey( encryptedKey, cryptInfoPtr,
										iSessionKeyContext );

	unlockResourceExit( cryptInfoPtr, status );
	}

int iCryptExportKeyEx( void *encryptedKey, int *encryptedKeyLength,
					   const CRYPT_FORMAT_TYPE formatType,
					   const CRYPT_CONTEXT iExportKey,
					   const CRYPT_CONTEXT iSessionKeyContext )
	{
	CRYPT_CONTEXT context;
	CRYPT_INFO *cryptInfoPtr, *sessionKeyInfoPtr;
	const RECIPIENT_TYPE recipientType = \
			( formatType == CRYPT_FORMAT_CRYPTLIB ) ? RECIPIENT_CRYPTLIB : \
			( formatType == CRYPT_FORMAT_CMS || \
			  formatType == CRYPT_FORMAT_SMIME ) ? RECIPIENT_CMS : RECIPIENT_NONE;
	BYTE auxDataBuffer[ 1024 ], *auxData = auxDataBuffer;
	int auxDataLength = 1024, status;

	*encryptedKeyLength = 0;

	/* Perform simplified error checking */
	status = krnlSendMessage( iExportKey, RESOURCE_IMESSAGE_GETDATA, &context,
							  RESOURCE_MESSAGE_DATA_CONTEXT, CRYPT_BADPARM3 );
	if( cryptStatusError( status ) )
		return( status );
	getCheckInternalResource( context, cryptInfoPtr, RESOURCE_TYPE_CRYPT );
	getCheckInternalResource2( iSessionKeyContext, sessionKeyInfoPtr,
							   RESOURCE_TYPE_CRYPT, cryptInfoPtr );

	/* If we're exporting a key in CMS format using a public key we need to
	   obtain the issuerAndSerialNumber */
	if( ( formatType == CRYPT_FORMAT_CMS || \
		  formatType == CRYPT_FORMAT_SMIME ) && cryptInfoPtr->type == CONTEXT_PKC )
		{
		status = getIssuerAndSerialNumber( iExportKey, &auxData,
										   &auxDataLength );
		if( cryptStatusError( status ) )
			unlockResourceExit2( cryptInfoPtr, sessionKeyInfoPtr, status );
		}

	/* Export it as appropriate.  We don't handle key agreement at this
	   level */
	if( cryptInfoPtr->type == CONTEXT_PKC )
		status = exportPublicKey( encryptedKey, encryptedKeyLength,
								  cryptInfoPtr, sessionKeyInfoPtr,
								  auxData, auxDataLength, recipientType );
	else
		status = exportConventionalKey( encryptedKey, encryptedKeyLength,
										cryptInfoPtr, sessionKeyInfoPtr,
										recipientType );

	/* Clean up */
	if( auxData != auxDataBuffer )
		free( auxData );
	unlockResourceExit2( cryptInfoPtr, sessionKeyInfoPtr, status );
	}

/* Raw data wrapping/unwrapping.  This is used by various protocols which
   don't explicitly work with keys but which move generic secret data around,
   examples being the SSH 256-bit shared secret and the SSL premaster
   secret */

int exportEncryptedSecret( void *data, int *dataLength,
						   const CRYPT_CONTEXT iExportKey,
						   const void *payload, const int payloadSize )
	{
	CRYPT_CONTEXT context;
	CRYPT_INFO *cryptInfoPtr;
	int status;

	*dataLength = 0;

	/* Perform simplified error checking */
	status = krnlSendMessage( iExportKey, RESOURCE_IMESSAGE_GETDATA, &context,
							  RESOURCE_MESSAGE_DATA_CONTEXT, CRYPT_BADPARM3 );
	if( cryptStatusError( status ) )
		return( status );
	getCheckInternalResource( context, cryptInfoPtr, RESOURCE_TYPE_CRYPT );

	/* Encrypt the payload */
	status = pkcs1Encrypt( data, cryptInfoPtr, payload, payloadSize,
						   RECIPIENT_RAW );
	if( !cryptStatusError( status ) )
		{
		*dataLength = status;
		status = CRYPT_OK;
		}

	unlockResourceExit( cryptInfoPtr, status );
	}

int importEncryptedSecret( void *data, const int dataLength,
						   const CRYPT_CONTEXT iImportKey, void *payload )
	{
	CRYPT_INFO *cryptInfoPtr;
	int status;

	/* Perform simplified error checking */
	getCheckInternalResource( iImportKey, cryptInfoPtr, RESOURCE_TYPE_CRYPT );

	/* Decrypt the payload */
	status = pkcs1Decrypt( data, dataLength, cryptInfoPtr, payload,
						   RECIPIENT_RAW );

	unlockResourceExit( cryptInfoPtr, status );
	}

/****************************************************************************
*																			*
*								Object Query Function						*
*																			*
****************************************************************************/

/* Query an object.  This is just a wrapper which provides an external
   interface for queryObject() */

CRET cryptQueryObject( const void CPTR object,
					   CRYPT_OBJECT_INFO CPTR cryptObjectInfo )
	{
	OBJECT_INFO objectInfo;
	STREAM stream;
	int status;

	/* Perform basic error checking */
	if( checkBadPtrRead( object, MIN_CRYPT_OBJECTSIZE ) )
		return( CRYPT_BADPARM1 );
	if( checkBadPtrWrite( cryptObjectInfo, sizeof( CRYPT_OBJECT_INFO ) ) )
		return( CRYPT_BADPARM2 );
	memset( cryptObjectInfo, 0, sizeof( CRYPT_OBJECT_INFO ) );

	/* Query the object.  This is just a wrapper for the lower-level
	   queryObject() function */
	sMemConnect( &stream, ( void * ) object, STREAMSIZE_UNKNOWN );
	status = queryObject( &stream, &objectInfo );
	sMemDisconnect( &stream );

	/* Copy the externally-visible fields across, setting any unused numeric
	   fields to CRYPT_ERROR */
	if( cryptStatusOK( status ) )
		{
		cryptObjectInfo->objectType = objectInfo.type;
		cryptObjectInfo->objectSize = ( int ) objectInfo.size;
		cryptObjectInfo->cryptAlgo = objectInfo.cryptAlgo;
		cryptObjectInfo->cryptMode = objectInfo.cryptMode;
		if( objectInfo.type == CRYPT_OBJECT_ENCRYPTED_KEY )
			{
			cryptObjectInfo->keySetupAlgo = objectInfo.keySetupAlgo;
			cryptObjectInfo->keySetupIterations = objectInfo.keySetupIterations;
			}
		else
			{
			cryptObjectInfo->keySetupAlgo = CRYPT_ERROR;
			cryptObjectInfo->keySetupIterations = CRYPT_ERROR;
			}
		if( objectInfo.type == CRYPT_OBJECT_SIGNATURE )
			cryptObjectInfo->hashAlgo = objectInfo.hashAlgo;
		else
			cryptObjectInfo->hashAlgo = CRYPT_ERROR;
		cryptObjectInfo->cryptContextExInfo = objectInfo.cryptContextExInfo;
		memcpy( cryptObjectInfo->_contextInfo, objectInfo.keyID, KEYID_SIZE );
		}

	return( status );
	}
