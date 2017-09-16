/****************************************************************************
*																			*
*						 ASN.1 Object Management Routines					*
*						Copyright Peter Gutmann 1992-1999					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) || defined( INC_CHILD )
  #include "asn1.h"
  #include "asn1objs.h"
  #include "asn1oid.h"
#else
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1objs.h"
  #include "keymgmt/asn1oid.h"
#endif /* Compiler-specific includes */

/* Context-specific tags for the KEK record */

enum { CTAG_KK_DA };

/* Context-specific tags for the KeyTrans record */

enum { CTAG_KT_SKI };

/* Context-specific tags for the KeyAgree/Fortezza record */

enum { CTAG_KA_ORIG, CTAG_KA_UKM };

/* Context-specific tags for the RecipientInfo record.  KeyTrans has no tag
   (actually it has an implied 0 tag because of CMS misdesign, so the other
   tags start at 1) */

enum { CTAG_RI_KEYAGREE = 1, CTAG_RI_KEK, CTAG_RI_PWRI };

/* Context-specific tags for the SignerInfo record */

enum { CTAG_SI_SKI };

/* CMS version numbers for various objects */

#define KEYTRANS_VERSION		0
#define PWRI_VERSION			0
#define KEYTRANS_EX_VERSION		2
#define KEK_VERSION				4
#define SIGNATURE_VERSION		1
#define SIGNATURE_EX_VERSION	3

/****************************************************************************
*																			*
*							Message Digest Routines							*
*																			*
****************************************************************************/

/* Determine the encoded size of a message digest value */

int sizeofMessageDigest( const CRYPT_ALGO hashAlgo, const int hashSize )
	{
	return( ( int ) sizeofObject( sizeofAlgoID( hashAlgo ) + \
								  ( int ) sizeofObject( hashSize ) ) );
	}

/* Write a message digest value */

int writeMessageDigest( STREAM *stream, const CRYPT_ALGO hashAlgo, 
						const void *hash, const int hashSize )
	{
	writeSequence( stream, sizeofAlgoID( hashAlgo ) + \
				   ( int ) sizeofObject( hashSize ) );
	writeAlgoID( stream, hashAlgo );
	return( writeOctetString( stream, hash, hashSize, DEFAULT_TAG ) );
	}

/* Read a message digest value */

int readMessageDigest( STREAM *stream, CRYPT_ALGO *hashAlgo, void *hash, 
					   int *hashSize )
	{
	int readDataLength, length, status;

	/* Read the identifier field */
	status = readSequence( stream, &length );
	readDataLength = status + length;
	if( !cryptStatusError( status ) )
		status = readAlgoID( stream, hashAlgo );
	if( !cryptStatusError( status ) )
		status = readOctetString( stream, hash, hashSize, CRYPT_MAX_HASHSIZE );

	return( cryptStatusError( status ) ? status : readDataLength );
	}

/****************************************************************************
*																			*
*					Conventionally-Encrypted Key Routines					*
*																			*
****************************************************************************/

/* The OID for the PKCS #5 v2.0 key derivation function */

#define OID_PBKDF2	MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x05\x0C" )

/* Write a PBKDF2 key derivation record */

static int writeKeyDerivationInfo( STREAM *stream, 
								   const CRYPT_CONTEXT iCryptContext )
	{
	RESOURCE_DATA msgData;
	BYTE salt[ CRYPT_MAX_HASHSIZE ];
	int keySetupIterations, derivationInfoSize, status;

	/* Get the key derivation information */
	status = krnlSendMessage( iCryptContext, RESOURCE_IMESSAGE_GETATTRIBUTE,
							  &keySetupIterations, 
							  CRYPT_CTXINFO_KEYING_ITERATIONS );
	if( status == CRYPT_ERROR_NOTFOUND )
		/* If the key wasn't derived from a password, don't go any further */
		return( CRYPT_OK );
	if( cryptStatusOK( status ) )
		{
		setResourceData( &msgData, salt, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( iCryptContext, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_KEYING_SALT );
		}
	if( cryptStatusError( status ) )
		return( status );
	derivationInfoSize = ( int ) sizeofObject( msgData.length ) + \
						 sizeofShortInteger( ( long ) keySetupIterations );

	/* Write the PBKDF2 information */
	writeConstructed( stream, sizeofOID( OID_PBKDF2 ) +
					  ( int ) sizeofObject( derivationInfoSize ), CTAG_KK_DA );
	writeOID( stream, OID_PBKDF2 );
	writeSequence( stream, derivationInfoSize );
	writeOctetString( stream, msgData.data, msgData.length, DEFAULT_TAG );
	writeShortInteger( stream, keySetupIterations, DEFAULT_TAG );
	zeroise( salt, CRYPT_MAX_HASHSIZE );

	return( sGetStatus( stream ) );
	}

/* Read a PBKDF2 key derivation record */

static int readKeyDerivationInfo( STREAM *stream, QUERY_INFO *queryInfo )
	{
	long value;
	int length, status;

	/* Read the outer wrapper and key derivation algorithm OID */
	status = readConstructed( stream, NULL, CTAG_KK_DA );
	if( !cryptStatusError( status ) )
		status = readOID( stream, OID_PBKDF2 );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the PBKDF2 parameters, limiting the salt and iteration count to
	   sane values */
	readSequence( stream, &length );
	status = readOctetString( stream, queryInfo->salt, 
						&queryInfo->saltLength, CRYPT_MAX_HASHSIZE );
	if( cryptStatusError( status ) )
		return( status );
	length -= status;
	status = readShortInteger( stream, &value );
	if( cryptStatusError( status ) )
		return( status );
	if( value > 20000 )
		return( CRYPT_ERROR_BADDATA );
	queryInfo->keySetupIterations = ( int ) value;
	queryInfo->keySetupAlgo = CRYPT_ALGO_HMAC_SHA;
	length -= status;
	if( length > 0 )
		sSkip( stream, length );

	return( sGetStatus( stream ) );
	}

/* Write a KEKRecipientInfo (= PasswordRecipientInfo) record */

int writeKEKInfo( STREAM *stream, const CRYPT_CONTEXT iCryptContext,
				  const BYTE *encryptedKey, const int encryptedKeyLength )
	{
	STREAM localStream;
	BYTE derivationInfo[ CRYPT_MAX_HASHSIZE + 32 ], kekInfo[ 64 ];
	int derivationInfoSize, kekInfoSize, status;

	/* Determine the size of the derivation info and KEK info.  To save
	   evaluating it twice in a row and because it's short, we just write
	   it to local buffers */
	sMemOpen( &localStream, derivationInfo, CRYPT_MAX_HASHSIZE + 32 );
	status = writeKeyDerivationInfo( &localStream, iCryptContext );
	derivationInfoSize = ( int ) stell( &localStream );
	sMemDisconnect( &localStream );
	if( cryptStatusError( status ) )
		return( status );
	sMemOpen( &localStream, kekInfo, 64 );
	status = writeContextCryptAlgoID( &localStream, iCryptContext );
	kekInfoSize = ( int ) stell( &localStream );
	sMemDisconnect( &localStream );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the algorithm identifiers and encrypted key */
	writeConstructed( stream, sizeofShortInteger( PWRI_VERSION ) +
					  derivationInfoSize + kekInfoSize + 
					  ( int ) sizeofObject( encryptedKeyLength ), 
					  CTAG_RI_PWRI );
	writeShortInteger( stream, PWRI_VERSION, DEFAULT_TAG );
	if( derivationInfoSize )
		swrite( stream, derivationInfo, derivationInfoSize );
	swrite( stream, kekInfo, kekInfoSize );
	writeOctetString( stream, encryptedKey, encryptedKeyLength, DEFAULT_TAG );

	return( sGetStatus( stream ) );
	}

/* Read a KEKRecipientInfo (= PasswordRecipientInfo) record */

int readKEKInfo( STREAM *stream, QUERY_INFO *queryInfo, void *iv, 
				 int *ivSize )
	{
	long value;
	int status;

	/* Clear return value */
	memset( queryInfo, 0, sizeof( QUERY_INFO ) );

	/* Read the header */
	status = readConstructed( stream, NULL, CTAG_RI_PWRI );
	if( !cryptStatusError( status ) )
		status = readShortInteger( stream, &value );
	if( !cryptStatusError( status ) && value != PWRI_VERSION )
		sSetError( stream, CRYPT_ERROR_BADDATA );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the optional KEK derivation info and KEK algorithm info */
	if( peekTag( stream ) == MAKE_CTAG( CTAG_KK_DA ) )
		status = readKeyDerivationInfo( stream, queryInfo );
	if( !cryptStatusError( status ) )
		status = readCryptAlgoID( stream, &queryInfo->cryptAlgo, 
								  &queryInfo->cryptMode, iv, ivSize );
	if( cryptStatusError( status ) )
		return( status );

	/* Finally, read the start of the encrypted key.  We never read the data
	   itself since it's passed directly to the decrypt function */
	if( readTag( stream ) != BER_OCTETSTRING )
		sSetError( stream, CRYPT_ERROR_BADDATA );
	readLength( stream, &value );
	if( value < bitsToBytes( MIN_KEYSIZE_BITS ) )
		{
		/* We shouldn't be using a key this short, we can't actually load it
		   anyway but a CRYPT_ERROR_BADDATA at this point provides more 
		   meaningful information to the caller */
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( CRYPT_ERROR_BADDATA );
		}
	queryInfo->dataStart = sMemBufPtr( stream );
	queryInfo->dataLength = ( int ) value;

	return( sGetStatus( stream ) );
	}

/****************************************************************************
*																			*
*						Public-key Encrypted Key Routines					*
*																			*
****************************************************************************/

/* Write a KeyTransRecipientInfo record */

int writeKeyTransInfo( STREAM *stream, const CRYPT_CONTEXT iCryptContext,
					   const BYTE *buffer, const int length,
					   const void *auxInfo, const int auxInfoLength,
					   const RECIPIENT_TYPE recipientType )
	{
	const int dataLength = \
				sizeofContextAlgoID( iCryptContext, CRYPT_ALGO_NONE ) + \
				( int ) sizeofObject( length );

	if( recipientType == RECIPIENT_CRYPTLIB )
		{
		RESOURCE_DATA msgData;
		BYTE keyID[ CRYPT_MAX_HASHSIZE ];

		setResourceData( &msgData, keyID, CRYPT_MAX_HASHSIZE );
		krnlSendMessage( iCryptContext, RESOURCE_IMESSAGE_GETATTRIBUTE_S, 
						 &msgData, CRYPT_IATTRIBUTE_KEYID );
		writeSequence( stream, sizeofShortInteger( KEYTRANS_EX_VERSION ) +
					   ( int ) sizeofObject( msgData.length ) + dataLength );
		writeShortInteger( stream, KEYTRANS_EX_VERSION, DEFAULT_TAG );
		writeOctetString( stream, msgData.data, msgData.length, CTAG_KT_SKI );
		}
	else
		{
		writeSequence( stream, sizeofShortInteger( KEYTRANS_VERSION ) +
					   auxInfoLength + dataLength );
		writeShortInteger( stream, KEYTRANS_VERSION, DEFAULT_TAG );
		swrite( stream, auxInfo, auxInfoLength );
		}
	writeContextAlgoID( stream, iCryptContext, CRYPT_ALGO_NONE );
	writeOctetString( stream, buffer, length, DEFAULT_TAG );

	return( sGetStatus( stream ) );
	}

/* Read a KeyTransRecipientInfo record */

int readKeyTransInfo( STREAM *stream, QUERY_INFO *queryInfo )
	{
	long value;
	int status;

	/* Clear return value */
	memset( queryInfo, 0, sizeof( QUERY_INFO ) );
	queryInfo->formatType = CRYPT_FORMAT_CRYPTLIB;

	/* Read the header and version number */
	status = readSequence( stream, NULL );
	if( cryptStatusError( status ) )
		return( status );
	status = readShortInteger( stream, &value );
	if( !cryptStatusError( status ) && \
		( value < 0 || value > KEYTRANS_EX_VERSION ) )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		status = CRYPT_ERROR_BADDATA;
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Read the key ID and PKC algorithm information */
	if( value != KEYTRANS_EX_VERSION )
		{
		int length;

		queryInfo->formatType = CRYPT_FORMAT_CMS;
		queryInfo->iAndSStart = sMemBufPtr( stream );
		status = readSequence( stream, &length );
		if( !cryptStatusError( status ) )
			{
			queryInfo->iAndSLength = status + length;
			sSkip( stream, length );
			}
		}
	else
		status = readOctetStringTag( stream, queryInfo->keyID, 
						&queryInfo->keyIDlength, CRYPT_MAX_HASHSIZE, 
						MAKE_CTAG_PRIMITIVE( CTAG_KT_SKI ) );
	if( !cryptStatusError( status ) )
		status = readAlgoID( stream, &queryInfo->cryptAlgo );
	if( cryptStatusError( status ) )
		return( status );

	/* Finally, read the start of the encrypted key.  We never read the data
	   itself since it's passed directly to the PKC decrypt function */
	if( readTag( stream ) != BER_OCTETSTRING )
		sSetError( stream, CRYPT_ERROR_BADDATA );
	readLength( stream, &value );
	queryInfo->dataStart = sMemBufPtr( stream );
	queryInfo->dataLength = ( int ) value;

	return( sGetStatus( stream ) );
	}

/****************************************************************************
*																			*
*								Key Agreement Routines						*
*																			*
****************************************************************************/

/* Write a KeyAgreeRecipientInfo (=FortezzaRecipientInfo) record */

int writeKeyAgreeInfo( STREAM *stream, const CRYPT_CONTEXT iCryptContext,
					   const void *wrappedKey, const int wrappedKeyLength,
					   const void *ukm, const int ukmLength,
					   const void *auxInfo, const int auxInfoLength )
	{
	RESOURCE_DATA msgData;
	BYTE rKeyID[ 1024 ];
	int rKeyIDlength, recipientKeyInfoSize, status;

	/* Get the recipients key ID and determine how large the recipient key 
	   info will be */
	setResourceData( &msgData, rKeyID, 1024 );
	status = krnlSendMessage( iCryptContext, 
							  RESOURCE_MESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER );
	if( cryptStatusError( status ) )
		return( status );
	rKeyIDlength = msgData.length;
	recipientKeyInfoSize = ( int ) ( \
							sizeofObject( sizeofObject( rKeyIDlength ) ) + \
							sizeofObject( wrappedKeyLength ) );

	/* Write the FortezzaRecipientInfo header and version number */
	writeConstructed( stream, sizeofShortInteger( 3 ) + 
					  ( int ) sizeofObject( sizeofObject( auxInfoLength ) ) +
					  ( int ) sizeofObject( sizeofObject( ukmLength ) ) +
					  sizeofOID( ALGOID_FORTEZZA_KEYWRAP ) +
					  ( int ) sizeofObject( sizeofObject( recipientKeyInfoSize ) ),
					  CTAG_RI_KEYAGREE );
	writeShortInteger( stream, 3, DEFAULT_TAG );
	
	/* Write the originator's keyIdentifier, UKM, and Fortezza key wrap OID */
	writeConstructed( stream, ( int ) sizeofObject( auxInfoLength ), 
					  CTAG_KA_ORIG );
	writeOctetString( stream, auxInfo, auxInfoLength, 0 );
	writeConstructed( stream, ( int ) sizeofObject( ukmLength ), 
					  CTAG_KA_UKM );
	writeOctetString( stream, ukm, ukmLength, DEFAULT_TAG );
	swrite( stream, ALGOID_FORTEZZA_KEYWRAP, 
			sizeofOID( ALGOID_FORTEZZA_KEYWRAP ) );

	/* Write the recipient keying info */
	writeSequence( stream, ( int ) sizeofObject( recipientKeyInfoSize ) );
	writeSequence( stream, recipientKeyInfoSize );
	writeConstructed( stream, ( int ) sizeofObject( rKeyIDlength ), 0 );
	writeOctetString( stream, rKeyID, rKeyIDlength, DEFAULT_TAG );
	writeOctetString( stream, wrappedKey, wrappedKeyLength, DEFAULT_TAG );

	return( sGetStatus( stream ) );
	}

/* Read a key agreement record */

int readKeyAgreeInfo( STREAM *stream, QUERY_INFO *queryInfo,
					  CRYPT_CONTEXT *iKeyAgreeContext )
	{
	CRYPT_CONTEXT iLocalKeyAgreeContext;
	long value;
	int status;

	/* Clear return values */
	memset( queryInfo, 0, sizeof( QUERY_INFO ) );
	if( iKeyAgreeContext != NULL )
		*iKeyAgreeContext = CRYPT_ERROR;

	/* Read the header and version number */
	status = readConstructed( stream, NULL, CTAG_RI_KEYAGREE );
	if( !cryptStatusError( status ) )
		status = readShortInteger( stream, &value );
	if( cryptStatusError( status ) || value != 3 )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( CRYPT_ERROR_BADDATA );
		}

	/* Read the public key information and encryption algorithm information */
	status = readPublicKey( stream, &iLocalKeyAgreeContext, 
							READKEY_OPTION_NONE );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're doing a query we're not interested in the key agreement
	   context so we just copy out the information we need and destroy it */
	if( iKeyAgreeContext == NULL )
		{
		RESOURCE_DATA msgData;

		setResourceData( &msgData, queryInfo->keyID, 
						 queryInfo->keyIDlength );
		status = krnlSendMessage( iLocalKeyAgreeContext, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
								  CRYPT_IATTRIBUTE_KEYID );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( iLocalKeyAgreeContext, 
									  RESOURCE_IMESSAGE_GETATTRIBUTE, 
									  &queryInfo->cryptAlgo, 
									  CRYPT_CTXINFO_ALGO );
		krnlSendNotifier( iLocalKeyAgreeContext, RESOURCE_IMESSAGE_DECREFCOUNT );
		if( cryptStatusError( status ) )
			return( status );
		}
	else
		/* Make the key agreement context externally visible */
		*iKeyAgreeContext = iLocalKeyAgreeContext;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Signature Routines							*
*																			*
****************************************************************************/

/* Write a signature */

int writeSignature( STREAM *stream, const CRYPT_CONTEXT iSignContext,
					const CRYPT_ALGO hashAlgo, const BYTE *signature,
					const int signatureLength,
					const SIGNATURE_TYPE signatureType )
	{
	/* If it's an X.509 signature, write the algorithm identifier and
	   signature data wrapped in a BIT STRING */
	if( signatureType == SIGNATURE_X509 )
		{
		/* Write the hash+signature algorithm identifier and BIT STRING
		   wrapper */
		writeContextAlgoID( stream, iSignContext, hashAlgo );
		writeTag( stream, BER_BITSTRING );
		writeLength( stream, signatureLength + 1 );
		sputc( stream, 0 );		/* Write bit remainder octet */
		return( writeRawObject( stream, signature, signatureLength ) );
		}

	/* Write the signature identification information and signature data
	   wrapped as an OCTET STRING */
	if( signatureType == SIGNATURE_CRYPTLIB )
		{
		RESOURCE_DATA msgData;
		BYTE keyID[ CRYPT_MAX_HASHSIZE ];

		/* Get the key ID */
		setResourceData( &msgData, keyID, CRYPT_MAX_HASHSIZE );
		krnlSendMessage( iSignContext, RESOURCE_IMESSAGE_GETATTRIBUTE_S,
						 &msgData, CRYPT_IATTRIBUTE_KEYID );

		/* Write the header */
		writeSequence( stream, sizeofShortInteger( SIGNATURE_EX_VERSION ) +
					   ( int ) sizeofObject( msgData.length ) +
					   sizeofContextAlgoID( iSignContext, CRYPT_ALGO_NONE ) +
					   sizeofAlgoID( hashAlgo ) +
					   ( int ) sizeofObject( signatureLength ) );

		/* Write the version, key ID and algorithm identifier */
		writeShortInteger( stream, SIGNATURE_EX_VERSION, DEFAULT_TAG );
		writeOctetString( stream, msgData.data, msgData.length, CTAG_SI_SKI );
		writeAlgoID( stream, hashAlgo );
		writeContextAlgoID( stream, iSignContext, CRYPT_ALGO_NONE );
		}
	else
		{
		assert( signatureType == SIGNATURE_CMS );

		/* Write the signature algorithm identifier */
		writeContextAlgoID( stream, iSignContext, CRYPT_ALGO_NONE );
		}
	return( writeOctetString( stream, signature, signatureLength, DEFAULT_TAG ) );
	}

/* Read a signature */

int readSignature( STREAM *stream, QUERY_INFO *queryInfo,
				   const SIGNATURE_TYPE signatureType )
	{
	long value;
	int length, status;

	/* If it's an X.509 signature, it's just a signature+hash algorithm ID */
	if( signatureType == SIGNATURE_X509 )
		{
		/* Read the signature and hash algorithm information and start of the
		   signature */
		status = readAlgoIDex( stream, &queryInfo->cryptAlgo,
							   &queryInfo->hashAlgo, NULL );
		if( cryptStatusOK( status ) && readTag( stream ) != BER_BITSTRING )
			sSetError( stream, CRYPT_ERROR_BADDATA );
		readLength( stream, &value );
		sgetc( stream );		/* Read bit remainder octet */
		queryInfo->dataStart = sMemBufPtr( stream );
		queryInfo->dataLength = ( int ) value - 1;
		return( sGetStatus( stream ) );
		}

	/* If it's CMS signer information, read the issuer ID and hash algorithm
	   identifier and skip the authenticated attributes if there are any
	   present after remembering where they start */
	if( signatureType == SIGNATURE_CMS_SIGNATUREINFO )
		{
		/* Read the header */
		status = readSequence( stream, NULL );
		if( !cryptStatusError( status ) )
			status = readShortInteger( stream, &value );
		if( !cryptStatusError( status ) && value != SIGNATURE_VERSION )
			status = CRYPT_ERROR_BADDATA;
		if( cryptStatusError( status ) )
			{
			sSetError( stream, status );
			return( status );
			}

		/* Read the issuer and serial number and hash algorithm ID */
		queryInfo->iAndSStart = sMemBufPtr( stream );
		status = readSequence( stream, &length );
		if( !cryptStatusError( status ) )
			{
			queryInfo->iAndSLength = status + length;
			sSkip( stream, length );
			status = readAlgoID( stream, &queryInfo->hashAlgo );
			queryInfo->dataStart = sMemBufPtr( stream );
			}
		if( cryptStatusError( status ) )
			return( status );

		/* Skip the authenticated attributes if there are any present */
		if( peekTag( stream ) == MAKE_CTAG( 0 ) )
			readUniversal( stream );
		}

	/* If it's a cryptlib signature, read the key ID */
	if( signatureType == SIGNATURE_CRYPTLIB )
		{
		/* Read the header */
		status = readSequence( stream, NULL );
		if( !cryptStatusError( status ) )
			status = readShortInteger( stream, &value );
		if( !cryptStatusError( status ) && value != SIGNATURE_EX_VERSION )
			status = CRYPT_ERROR_BADDATA;
		if( cryptStatusError( status ) )
			{
			sSetError( stream, status );
			return( status );
			}

		/* Read the key ID and hash algorithm identifier */
		status = readOctetStringTag( stream, queryInfo->keyID, 
									 &queryInfo->keyIDlength, 
									 CRYPT_MAX_HASHSIZE, 
									 MAKE_CTAG_PRIMITIVE( CTAG_SI_SKI ) );
		if( !cryptStatusError( status ) )
			status = readAlgoID( stream, &queryInfo->hashAlgo );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Read the CMS/cryptlib signature algorithm and start of the signature */
	status = readAlgoID( stream, &queryInfo->cryptAlgo );
	if( cryptStatusOK( status ) && readTag( stream ) != BER_OCTETSTRING )
		sSetError( stream, CRYPT_ERROR_BADDATA );
	readLength( stream, &value );
	if( signatureType == SIGNATURE_CRYPTLIB || \
		signatureType == SIGNATURE_CMS )
		{
		/* CMS signature info sets the data pointer to the start of the
		   authenticated attributes */
		queryInfo->dataStart = sMemBufPtr( stream );
		queryInfo->dataLength = ( int ) value;
		}
	return( sGetStatus( stream ) );
	}

/****************************************************************************
*																			*
*								Object Query Routines						*
*																			*
****************************************************************************/

/* Read the type and start of a cryptlib object */

static int readObjectType( STREAM *stream, CRYPT_OBJECT_TYPE *objectType,
						   long *length, CRYPT_FORMAT_TYPE *formatType )
	{
	const long streamPos = stell( stream );
	int readDataLength, tag;

	*formatType = CRYPT_FORMAT_CRYPTLIB;
	tag = readTag( stream );
	readDataLength = readLength( stream, length ) + 1;
	*length += readDataLength;	/* Include size of tag in total length */
	if( tag == BER_SEQUENCE )
		{
		long value;

		/* This could be a signature or a PKC-encrypted key.  Read the
		   length and see what follows */
		readShortInteger( stream, &value );
		if( value == KEYTRANS_VERSION || value == KEYTRANS_EX_VERSION )
			*objectType = CRYPT_OBJECT_PKCENCRYPTED_KEY;
		else
			if( value == SIGNATURE_VERSION || value == SIGNATURE_EX_VERSION )
				*objectType = CRYPT_OBJECT_SIGNATURE;
			else
				{
				*objectType = CRYPT_OBJECT_NONE;
				sSetError( stream, CRYPT_ERROR_BADDATA );
				}
		if( value == KEYTRANS_VERSION || value == SIGNATURE_VERSION )
			*formatType = CRYPT_FORMAT_CMS;
		}
	else
		{
		switch( tag )
			{
			case MAKE_CTAG( CTAG_RI_KEYAGREE ):
				*objectType = CRYPT_OBJECT_KEYAGREEMENT;
				break;

			case MAKE_CTAG( CTAG_RI_PWRI ):
				*objectType = CRYPT_OBJECT_ENCRYPTED_KEY;
				break;

			default:
				*objectType = CRYPT_OBJECT_NONE;
				sSetError( stream, CRYPT_ERROR_BADDATA );
			}
		}
	sseek( stream, streamPos );

	return( sGetStatus( stream ) );
	}

/* Low-level object query function.  This is used by a number of library
   routines to get information on objects at a lower level than that provided
   by cryptQueryObject() (for example the enveloping functions use it to
   determine whether there is enough data available to allow a full
   cryptQueryObject()).  At this level the stream error code (which is
   independant of the crypt error code returned by the ASN.1 routines) is
   available to provide more information via sGetError().

   Note that this function doens't perform a full check of all the fields in
   an object, all it does is extract enough information from the start to
   satisfy the query, and confirm that there's enough data in the stream to
   contain the rest of the non-payload portion of the object.  The
   appropriate import function checks the validity of the entire object, but
   has side-effects such as creating encryption contexts and/or performing
   signature checks as part of the import function.  It's not really possible
   to check the validity of the octet or bit string which makes up an
   encrypted session key or signature without actually performing the import,
   so once we've read the rest of the header we just make sure the final
   octet or bit string is complete without checking its validity */

int queryObject( STREAM *stream, QUERY_INFO *queryInfo )
	{
	CRYPT_FORMAT_TYPE formatType;
	CRYPT_OBJECT_TYPE objectType;
	BYTE dummyIV[ CRYPT_MAX_IVSIZE ];
	long length;
	int startPos = ( int ) stell( stream ), dummy, status;

	/* Clear the return value and determine the object type */
	memset( queryInfo, 0, sizeof( QUERY_INFO ) );
	status = readObjectType( stream, &objectType, &length, &formatType );
	if( cryptStatusError( status ) )
		return( status );

	/* Call the appropriate routine to find out more about the object */
	switch( objectType )
		{
		case CRYPT_OBJECT_ENCRYPTED_KEY:
			status = readKEKInfo( stream, queryInfo, dummyIV, &dummy );
			break;

		case CRYPT_OBJECT_PKCENCRYPTED_KEY:
			status = readKeyTransInfo( stream, queryInfo );
			break;

		case CRYPT_OBJECT_KEYAGREEMENT:
			status = readKeyAgreeInfo( stream, queryInfo, NULL );
			break;

		case CRYPT_OBJECT_SIGNATURE:
			status = readSignature( stream, queryInfo,
						( formatType == CRYPT_FORMAT_CRYPTLIB ) ? \
						SIGNATURE_CRYPTLIB : SIGNATURE_CMS_SIGNATUREINFO );
			break;

		default:
			assert( NOTREACHED );
		}
	if( !cryptStatusError( status ) )
		{
		queryInfo->formatType = formatType;
		queryInfo->type = objectType;
		queryInfo->size = length;
		status = CRYPT_OK;	/* The readXXX() fns.return a byte count */
		}

	/* Sometimes there's extra information (such as an encrypted key or
	   signature) which we don't read since it's passed directly to the
	   decrypt function, so if there's any unread data left in the header we
	   seek over it to make sure everything we need is in the buffer.  Since
	   a length-limited stream is used by the enveloping routines, we return
	   an underflow error if the object isn't entirely present */
	if( cryptStatusOK( status ) && \
		length > stell( stream ) - startPos && \
		sSkip( stream, length - ( stell( stream ) - startPos ) ) != CRYPT_OK )
		status = CRYPT_ERROR_UNDERFLOW;

	/* Return to the start of the object in case the caller wants to read it
	   from the stream following the query */
	sseek( stream, startPos );

	return( status );
	}
