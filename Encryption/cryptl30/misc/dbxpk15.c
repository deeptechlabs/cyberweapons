/****************************************************************************
*																			*
*						  cryptlib PKCS #15 Routines						*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

/* The format used to protect the private key components is a standard
   cryptlib envelope, however for various reasons the required enveloping
   functionality is duplicated here:

	1. It's somewhat inelegant to use the heavyweight enveloping routines to
	   wrap up 100 bytes of data.
	2. The enveloping code is enormous and complex, especially when extra
	   sections like zlib and PGP and S/MIME support are factored in.  This
	   makes it difficult to compile a stripped-down version of cryptlib,
	   since private key storage will require all the enveloping code to be
	   included.
	3. Since the enveloping code is general-purpose, it doesn't allow very
	   precise control over the data being processed.  Specifically, it's
	   necessary to write the private key components to a buffer which is
	   then copied to the envelope, leaving two copies in unprotected memory
	   for some amount of time.  In contrast if we do the buffer management
	   ourselves we can write the data to a buffer and immediately encrypt
	   it.

   For these reasons this module includes the code to process minimal
   (password-encrypted data) envelopes */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "keyset.h"
  #include "asn1.h"
  #include "asn1objs.h"
  #include "asn1oid.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "keyset.h"
  #include "../keymgmt/asn1.h"
  #include "../keymgmt/asn1objs.h"
  #include "../keymgmt/asn1oid.h"
#else
  #include "crypt.h"
  #include "misc/keyset.h"
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1objs.h"
  #include "keymgmt/asn1oid.h"
#endif /* Compiler-specific includes */

/* A PKCS #15 file can contain multiple key and cert objects, before we do
   anything with the file we scan it and build an in-memory index of what's 
   present.  When we perform an update we just flush the in-memory 
   information to disk.

   Each file can contain information for multiple personalities (although 
   it's extremely unlikely to contain more than one or two), we allow a 
   maximum of MAX_PKCS15_OBJECTS per file in order to discourage them from 
   being used as general-purpose public-key keysets, which they're not really 
   intended for.  A setting of 32 objects consumes ~4K of memory (32 x ~128), 
   so we choose that as the limit */

#define MAX_PKCS15_OBJECTS	32

/* Usually a PKCS #15 personality consists of a collection of related PKCS 
   #15 objects (typically a public and private key and a cert), but sometimes
   we have personalities which consist only of a cert and little other 
   information (for example a trusted CA root cert, which contains no user-
   supplied information such as a label).  The following types of personality
   are handled for PKCS #15 files */

typedef enum {
	PKCS15_SUBTYPE_NONE,			/* Non-personality */
	PKCS15_SUBTYPE_NORMAL,			/* Standard personality, keys+optional cert */
	PKCS15_SUBTYPE_CERT,			/* Standalone cert */
	PKCS15_SUBTYPE_DATA,			/* Pre-encoded cryptlib config data */
	PKCS15_SUBTYPE_LAST
	} PKCS15_SUBTYPE;

/* The following structure contains the the information for one personality, 
   which covers one or more of a private key, public key, and cert */

typedef struct {
	/* General information on the personality: The subtype, a local unique 
	   identifier which is easier to manage than the iD, the PKCS #15
	   object label, and the PKCS #15 object ID and key ID (which is usually
	   the same as the object ID) */
	PKCS15_SUBTYPE type;			/* Personality subtype */
	int index;						/* Unique value for this personality */
	char label[ CRYPT_MAX_TEXTSIZE ];/* PKCS #15 object label */
	int labelLength;
	BYTE iD[ CRYPT_MAX_HASHSIZE ], keyID[ CRYPT_MAX_HASHSIZE ];
	int iDlength, keyIDlength;		/* PKCS #15 object ID and key ID */

	/* Certificate-related ID information: Hash of the issuer name, subject
	   name, and issuerAndSerialNumber */
	BYTE iAndSID[ KEYID_SIZE ], subjectNameID[ KEYID_SIZE ];
	BYTE issuerNameID[ KEYID_SIZE ];
	int iAndSIDlength, subjectNameIDlength, issuerNameIDlength;

	/* Key/cert object data */
	void *pubKeyData, *privKeyData, *certData;	/* Encoded object data */
	int pubKeyDataSize, privKeyDataSize, certDataSize;
	int pubKeyOffset, privKeyOffset, certOffset;
									/* Offset of payload in data */
	int pubKeyUsage, privKeyUsage;	/* Permitted usage for the key */
	int trustedUsage;				/* Usage which key is trusted for */
	BOOLEAN implicitTrust;			/* Whether cert is implicitly trusted */

	/* Data object data */
	void *dataData;					/* Encoded object data */
	int dataDataSize, dataOffset;
	} PKCS15_INFO;

/* The types of object we can find in a PKCS #15 file.  These are also used
   as context-specific object tags */

typedef enum { PKCS15_OBJECT_PRIVKEY, PKCS15_OBJECT_PUBKEY, 
			   PKCS15_OBJECT_TRUSTEDPUBKEY, PKCS15_OBJECT_SECRETKEY,
			   PKCS15_OBJECT_CERT, PKCS15_OBJECT_TRUSTEDCERT,
			   PKCS15_OBJECT_USEFULCERT, PKCS15_OBJECT_DATA,
			   PKCS15_OBJECT_AUTH, PKCS15_OBJECT_LAST } PKCS15_OBJECT_TYPE;

/* The types of key identifiers we can find attached to an object */

enum { PKCS15_KEYID_NONE, PKCS15_KEYID_ISSUERANDSERIALNUMBER, 
	   PKCS15_KEYID_SUBJECTKEYIDENTIFIER, PKCS15_KEYID_ISSUERANDSERIALNUMBERHASH, 
	   PKCS15_KEYID_SUBJECTKEYHASH, PKCS15_KEYID_ISSUERKEYHASH,
	   PKCS15_KEYID_ISSUERNAMEHASH, PKCS15_KEYID_SUBJECTNAMEHASH };

/* Context-specific tags for the PublicKeyInfo record */

enum { CTAG_PK_CERTIFICATE, CTAG_PK_CERTCHAIN };

/* Context-specific tag for the EncryptedData record (this is normally
   defined in env_asn1.c) */

#define CTAG_CI_ENCRYPTED	1

/* Context-specific tags for the PKCS #15 object record */

enum { CTAG_OB_SUBCLASSATTR, CTAG_OB_TYPEATTR };

/* Context-specific tags for the PKCS #15 object value record */

enum { CTAG_OV_DIRECT, CTAG_OV_DUMMY, CTAG_OV_DIRECTPROTECTED };

/* Context-specific tags for the PKCS #15 class attributes record */

enum { CTAG_CA_DUMMY, CTAG_CA_TRUSTED, CTAG_CA_IDENTIFIERS };

/* OID information used to read a PKCS #15 file */

static const OID_SELECTION keyFileOIDselection[] = {
	{ OID_PKCS15_CONTENTTYPE, 0, 0, CRYPT_OK },
	{ NULL, 0, 0, 0 }
	};

static const OID_SELECTION privKeyDataOIDselection[] = {
	{ OID_CMS_ENVELOPEDDATA, 0, 2, CRYPT_OK },
	{ NULL, 0, 0, 0 }
	};

static const OID_SELECTION dataOIDselection[] = {
	{ OID_CMS_DATA, CRYPT_UNUSED, CRYPT_UNUSED, CRYPT_OK },
	{ NULL, 0, 0, 0 }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Locate an object based on an ID.  Since PKCS #15 uses more key ID types
   than are used by the rest of cryptlib, we extend the standard range with
   PKCS15-only types */

#define CRYPT_KEYIDEX_PKCS15ID			CRYPT_KEYID_LAST
#define CRYPT_KEYIDEX_SUBJECTNAMEID		( CRYPT_KEYID_LAST + 1 )

static PKCS15_INFO *findEntry( const PKCS15_INFO *pkcs15info,
							   const CRYPT_KEYID_TYPE keyIDtype,
							   const void *keyID, const int keyIDlength )
	{
	int i;

	assert( keyID != NULL );
	assert( keyIDlength >= 0 );

	/* If there's no ID to search on, don't try and do anything (this can 
	   occur when we're trying to build a chain and the necessary chaining
	   data isn't present) */
	if( keyIDlength == 0 )
		return( NULL );

	/* Try and locate the appropriate object in the PKCS #15 collection */
	for( i = 0; i < MAX_PKCS15_OBJECTS; i++ )
		switch( keyIDtype )
			{
			case CRYPT_KEYID_NAME:
			case CRYPT_KEYID_EMAIL:
				if( matchSubstring( keyID, keyIDlength, 
									pkcs15info[ i ].label, 
									pkcs15info[ i ].labelLength ) )
					return( ( PKCS15_INFO * ) &pkcs15info[ i ] );
				break;

			case CRYPT_IKEYID_KEYID:
				if( keyIDlength == pkcs15info[ i ].keyIDlength && \
					!memcmp( keyID, pkcs15info[ i ].keyID, keyIDlength ) )
					return( ( PKCS15_INFO * ) &pkcs15info[ i ] );
				break;

			case CRYPT_IKEYID_ISSUERID:
				if( keyIDlength == pkcs15info[ i ].iAndSIDlength && \
					!memcmp( keyID, pkcs15info[ i ].iAndSID, keyIDlength ) )
					return( ( PKCS15_INFO * ) &pkcs15info[ i ] );
				break;

			case CRYPT_KEYIDEX_PKCS15ID:
				if( keyIDlength == pkcs15info[ i ].iDlength && \
					!memcmp( keyID, pkcs15info[ i ].iD, keyIDlength ) )
					return( ( PKCS15_INFO * ) &pkcs15info[ i ] );
				break;

			case CRYPT_KEYIDEX_SUBJECTNAMEID:
				if( keyIDlength == pkcs15info[ i ].subjectNameIDlength && \
					!memcmp( keyID, pkcs15info[ i ].subjectNameID, keyIDlength ) )
					return( ( PKCS15_INFO * ) &pkcs15info[ i ] );
				break;

			default:
				assert( NOTREACHED );
			}

	return( NULL );
	}

/* Free object entries */

static void pkcs15freeEntry( PKCS15_INFO *pkcs15info )
	{
	if( pkcs15info->pubKeyData != NULL )
		{
		zeroise( pkcs15info->pubKeyData, pkcs15info->pubKeyDataSize );
		free( pkcs15info->pubKeyData );
		}
	if( pkcs15info->privKeyData != NULL )
		{
		zeroise( pkcs15info->privKeyData, pkcs15info->privKeyDataSize );
		free( pkcs15info->privKeyData );
		}
	if( pkcs15info->certData != NULL )
		{
		zeroise( pkcs15info->certData, pkcs15info->certDataSize );
		free( pkcs15info->certData );
		}
	if( pkcs15info->dataData != NULL )
		{
		zeroise( pkcs15info->dataData, pkcs15info->dataDataSize );
		free( pkcs15info->dataData );
		}
	zeroise( pkcs15info, sizeof( PKCS15_INFO ) );
	}

void pkcs15Free( PKCS15_INFO *pkcs15info )
	{
	int i;

	for( i = 0; i < MAX_PKCS15_OBJECTS; i++ )
		pkcs15freeEntry( &pkcs15info[ i ] );
	}

/* Get the hash of various certificate name fields */

static int getCertID( const CRYPT_HANDLE iCryptHandle, 
					  CRYPT_ATTRIBUTE_TYPE nameType, BYTE *nameID )
	{
	RESOURCE_DATA msgData;
	BYTE idBuffer[ 1024 ], *idBufPtr = idBuffer;
	int status;

	setResourceData( &msgData, NULL, 0 );
	status = krnlSendMessage( iCryptHandle, RESOURCE_IMESSAGE_GETATTRIBUTE_S,
							  &msgData, nameType );
	if( cryptStatusError( status ) )
		return( CRYPT_ARGERROR_NUM1 );
	if( msgData.length > 1024 && \
		( idBufPtr = malloc( msgData.length ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	msgData.data = idBufPtr;
	status = krnlSendMessage( iCryptHandle, RESOURCE_IMESSAGE_GETATTRIBUTE_S, 
							  &msgData, nameType );
	if( cryptStatusOK( status ) )
		{
		HASHFUNCTION hashFunction;
		int hashSize;

		/* Get the hash algorithm information and hash the name to get a name 
		   ID */
		getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );
		hashFunction( NULL, nameID, idBufPtr, msgData.length, HASH_ALL );
		}
	if( idBufPtr != idBuffer )
		free( idBufPtr );
	return( status );
	}

/****************************************************************************
*																			*
*							Read/Write PKCS #15 Attributes					*
*																			*
****************************************************************************/

/* When writing attributes it's useful to have a fixed-size buffer rather 
   than having to mess around with all sorts of variable-length structures,
   the following value defines the maximum size of the data we can write
   (that is, the I/O stream is opened with this size and generates a
   CRYPT_ERROR_OVERFLOW if we go beyond this).  The maximum-length buffer
   contents are two CRYPT_MAX_TEXTSIZE strings and a few odd bits and pieces
   so this is plenty */

#define KEYATTR_BUFFER_SIZE		256

/* The access flags for various types of key objects.  For a public key we
   set 'extractable', for a private key we set 'sensitive', 
   'alwaysSensitive', and 'neverExtractable' */

#define KEYATTR_ACCESS_PUBLIC	0x02	/* 00010b */
#define KEYATTR_ACCESS_PRIVATE	0x0D	/* 01101b */

/* PKCS #15 key usage flags, a complex mixture of PKCS #11 and some bits of
   X.509 */

#define PKCS15_USAGE_ENCRYPT		0x0001
#define PKCS15_USAGE_DECRYPT		0x0002
#define PKCS15_USAGE_SIGN			0x0004
#define PKCS15_USAGE_SIGNRECOVER	0x0008
#define PKCS15_USAGE_WRAP			0x0010
#define PKCS15_USAGE_UNWRAP			0x0020
#define PKCS15_USAGE_VERIFY			0x0040
#define PKCS15_USAGE_VERIFYRECOVER	0x0080
#define PKCS15_USAGE_DERIVE			0x0100
#define PKCS15_USAGE_NONREPUDIATION	0x0200

/* PKCS #15 flags which can't be set for public keys.  We use this as a mask 
   to derive public-key flags from private key ones */

#define PUBKEY_USAGE_MASK	~( PKCS15_USAGE_DECRYPT | PKCS15_USAGE_SIGN | \
							   PKCS15_USAGE_SIGNRECOVER | PKCS15_USAGE_UNWRAP )

/* Translate the PKCS #15 usage flags into cryptlib permitted actions.  The
   PKCS #11 use of the 'derive' flag to mean 'allow key agreement' is a bit 
   of a kludge, we map it to allowing keyagreement export and import and if
   there are further constraints they'll be handled by the attached cert.  
   The PKCS #15 nonRepudiation flag doesn't have any definition, so we can't
   do anything with it */

static int getPermittedActions( const int usageFlags )
	{
	int actionFlags = 0;

	if( usageFlags & PKCS15_USAGE_ENCRYPT )
		actionFlags |= MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_ENCRYPT, 
									   ACTION_PERM_NONE_EXTERNAL );
	if( usageFlags & PKCS15_USAGE_DECRYPT )
		actionFlags |= MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_DECRYPT, 
									   ACTION_PERM_NONE_EXTERNAL );
	if( usageFlags & PKCS15_USAGE_SIGN )
		actionFlags |= MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_SIGN, 
									   ACTION_PERM_NONE_EXTERNAL );
	if( usageFlags & PKCS15_USAGE_VERIFY )
		actionFlags |= MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_SIGCHECK, 
									   ACTION_PERM_NONE_EXTERNAL );
	if( usageFlags & PKCS15_USAGE_DERIVE )
		actionFlags |= MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_ENCRYPT, 
									   ACTION_PERM_NONE_EXTERNAL ) | \
					   MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_DECRYPT, 
									   ACTION_PERM_NONE_EXTERNAL );

	return( !actionFlags ? CRYPT_ERROR_PERMISSION : actionFlags );
	}

/* Read a sequence of PKCS #15 key identifiers */

static int readKeyIdentifiers( STREAM *stream, PKCS15_INFO *pkcs15info,
							   int length )
	{
	int status = CRYPT_OK;

	while( !cryptStatusError( status ) && length > 0 )
		{
		HASHFUNCTION hashFunction;
		void *iAndSPtr;
		long value;
		int hashSize, payloadLength, iAndSLength;

		/* Read each identifier type and copy the useful ones into the PKCS
		   #15 info */
		status = readSequence( stream, &payloadLength );
		length -= status + payloadLength;
		status = readShortInteger( stream, &value );
		if( cryptStatusError( status ) )
			break;
		switch( value )
			{
			case PKCS15_KEYID_ISSUERANDSERIALNUMBER:
				/* Get the hash algorithm information */
				getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );

				/* Hash the full issuerAndSerialNumber to get an iAndSID */
				iAndSPtr = sMemBufPtr( stream );
				readSequence( stream, &iAndSLength );
				status = sSkip( stream, iAndSLength );
				if( cryptStatusError( status ) )
					break;
				hashFunction( NULL, ( BYTE * ) pkcs15info->iAndSID, iAndSPtr,
							  ( int ) sizeofObject( iAndSLength ), HASH_ALL );
				pkcs15info->iAndSIDlength = hashSize;
				break;

			case PKCS15_KEYID_SUBJECTKEYIDENTIFIER:
				status = readOctetString( stream, pkcs15info->keyID, 
								&pkcs15info->keyIDlength, KEYID_SIZE );
				break;

			case PKCS15_KEYID_ISSUERANDSERIALNUMBERHASH:
				/* If we've already got the iAndSID by hashing the 
				   issuerAndSerialNumber, use that version instead */
				if( pkcs15info->iAndSIDlength )
					{
					readUniversal( stream );
					continue;
					}
				status = readOctetString( stream, pkcs15info->iAndSID, 
								&pkcs15info->iAndSIDlength, KEYID_SIZE );
				break;

			case PKCS15_KEYID_ISSUERNAMEHASH:
				status = readOctetString( stream, pkcs15info->issuerNameID, 
								&pkcs15info->issuerNameIDlength, KEYID_SIZE );
				break;

			case PKCS15_KEYID_SUBJECTNAMEHASH:
				status = readOctetString( stream, pkcs15info->subjectNameID, 
								&pkcs15info->subjectNameIDlength, KEYID_SIZE );
				break;

			default:
				readUniversal( stream );
			}
		}

	return( status );
	}

/* Read an object's attributes */

static int readObjectAttributes( STREAM *objectStream, PKCS15_INFO *pkcs15info,
								 const PKCS15_OBJECT_TYPE type )
	{
	STREAM stream;
	void *objectData;
	long length;
	int tag, objectLength, payloadLength, status;

	/* Clear the return value */
	memset( pkcs15info, 0, sizeof( PKCS15_INFO ) );

	/* Read the object into memory */
	tag = readTag( objectStream );
	readLength( objectStream, &length );
	if( sGetStatus( objectStream ) != CRYPT_OK || \
		length < 8 || length > 8192 )
		return( CRYPT_ERROR_BADDATA );
	objectLength = ( int ) sizeofObject( length );
	if( ( objectData = malloc( objectLength ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	sMemConnect( &stream, objectData, objectLength );
	writeTag( &stream, tag );		/* Reconstruct already-read tag+len */
	writeLength( &stream, length );
	status = sread( objectStream, sMemBufPtr( &stream ), ( int ) length );
	if( cryptStatusError( status ) )
		{
		sMemClose( &stream );
		free( objectData );
		return( status );
		}

	/* Process the PKCS15CommonObjectAttributes */
	status = readSequence( &stream, &payloadLength );
	if( !cryptStatusError( status ) && payloadLength > 0 )
		{
		/* Read the label if it's present and skip anything else */
		if( peekTag( &stream ) == BER_STRING_UTF8 )
			{
			status = readOctetStringTag( &stream, 
						( BYTE * ) pkcs15info->label, &pkcs15info->labelLength, 
						CRYPT_MAX_TEXTSIZE, BER_STRING_UTF8 );
			payloadLength -= status;
			}
		if( !cryptStatusError( status ) && payloadLength > 0 )
			sSkip( &stream, payloadLength );
		}
	if( cryptStatusError( status ) )
		{
		sMemClose( &stream );
		free( objectData );
		return( status );
		}

	/* Process the PKCS15CommonXXXAttributes */
	readSequence( &stream, &payloadLength );
	if( type == PKCS15_OBJECT_DATA )
		{
		/* It's a data object, make sure it's one of ours */
		status = readOID( &stream, OID_CRYPTLIB_CONFIGDATA );
		if( !cryptStatusError( status ) )
			{
			payloadLength -= status;
			if( payloadLength > 0 )
				sSkip( &stream, payloadLength );
			}
		}
	else
		{
		/* It's a key or cert object, read the ID and assorted flags */
		status = readOctetString( &stream, pkcs15info->iD, 
								  &pkcs15info->iDlength, CRYPT_MAX_HASHSIZE );
		if( cryptStatusError( status ) )
			{
			sMemClose( &stream );
			free( objectData );
			return( status );
			}
		payloadLength -= status;
		if( type == PKCS15_OBJECT_PUBKEY || type == PKCS15_OBJECT_PRIVKEY )
			{
			int usageFlags;
														/* Usage flags */
			payloadLength -= readBitString( &stream, &usageFlags );
			if( peekTag( &stream ) == BER_BOOLEAN )		/* Native flag */
				payloadLength -= readUniversal( &stream );
			if( payloadLength > 0 &&					/* Access flags */
				peekTag( &stream ) == BER_BITSTRING )
				payloadLength -= readUniversal( &stream );
			if( type == PKCS15_OBJECT_PUBKEY )
				pkcs15info->pubKeyUsage = usageFlags;
			else
				pkcs15info->privKeyUsage = usageFlags;
			}
		else
			if( type == PKCS15_OBJECT_CERT )
				{
				if( peekTag( &stream ) == BER_BOOLEAN )	/* Authority flag */
					payloadLength -= readUniversal( &stream );
				if( payloadLength > 0 &&				/* Identifier */
					peekTag( &stream ) == BER_SEQUENCE )
					payloadLength -= readUniversal( &stream );
				if( payloadLength > 0 &&				/* Thumbprint */
					peekTag( &stream ) == MAKE_CTAG( CTAG_CA_DUMMY ) )
					payloadLength -= readUniversal( &stream );
				if( !cryptStatusError( status ) && payloadLength > 0 &&
					peekTag( &stream ) == MAKE_CTAG( CTAG_CA_TRUSTED ) )
					{									/* Trusted usage */
					int trustedLength;

					status = readConstructed( &stream, &trustedLength, 
											  CTAG_CA_TRUSTED );
					if( cryptStatusOK( status ) )
						status = readBitString( &stream, &pkcs15info->trustedUsage );
					payloadLength -= ( int ) sizeofObject( trustedLength );
					}
				if( !cryptStatusError( status ) && payloadLength > 0 && \
					peekTag( &stream ) == MAKE_CTAG( CTAG_CA_IDENTIFIERS ) )
					{									/* Identifiers */
					int identifierLength;

					status = readConstructed( &stream, &identifierLength,
											  CTAG_CA_IDENTIFIERS );
					if( !cryptStatusError( status ) )
						status = readKeyIdentifiers( &stream, pkcs15info, 
													 identifierLength );
					payloadLength -= ( int ) sizeofObject( length );
					}
				if( !cryptStatusError( status ) && payloadLength > 0 && \
					peekTag( &stream ) == BER_BOOLEAN )	/* Implicit trust */
					status = readBoolean( &stream, &pkcs15info->implicitTrust );
				}
		if( payloadLength > 0 )
			sSkip( &stream, payloadLength );
		if( cryptStatusOK( status ) )
			status = sGetStatus( &stream );
		}
	if( cryptStatusError( status ) )
		{
		sMemClose( &stream );
		free( objectData );
		return( status );
		}

	/* For now we use the iD as the keyID, this may be overridden later if 
	   there's a real keyID present */
	memcpy( pkcs15info->keyID, pkcs15info->iD, pkcs15info->iDlength );
	pkcs15info->keyIDlength = pkcs15info->iDlength;

	/* Skip the public/private key attributes if present */
	if( peekTag( &stream ) == MAKE_CTAG( CTAG_OB_SUBCLASSATTR ) )
		readUniversal( &stream );
	
	/* Process the type attributes, which just consists of remembering where 
	   the payload starts */
	status = readConstructed( &stream, NULL, CTAG_OB_TYPEATTR );
	if( !cryptStatusError( status ) )
		status = readSequence( &stream, &payloadLength );
	if( !cryptStatusError( status ) )
		{
		switch( type )
			{
			case PKCS15_OBJECT_PUBKEY:
				readConstructed( &stream, &payloadLength, CTAG_OV_DIRECT );
				pkcs15info->pubKeyData = objectData;
				pkcs15info->pubKeyDataSize = objectLength;
				pkcs15info->pubKeyOffset = ( int ) stell( &stream );
				break;

			case PKCS15_OBJECT_PRIVKEY:
				pkcs15info->privKeyData = objectData;
				pkcs15info->privKeyDataSize = objectLength;
				pkcs15info->privKeyOffset = ( int ) stell( &stream );
				break;

			case PKCS15_OBJECT_CERT:
			case PKCS15_OBJECT_TRUSTEDCERT:
			case PKCS15_OBJECT_USEFULCERT:
				pkcs15info->certData = objectData;
				pkcs15info->certDataSize = objectLength;
				pkcs15info->certOffset = ( int ) stell( &stream );
				break;

			case PKCS15_OBJECT_DATA:
				pkcs15info->dataData = objectData;
				pkcs15info->dataDataSize = objectLength;
				pkcs15info->dataOffset = ( int ) stell( &stream );
				break;
			}
		status = sSkip( &stream, payloadLength );
		}
	if( cryptStatusError( status ) )
		{
		sMemClose( &stream );
		free( objectData );
		return( status );
		}

	return( CRYPT_OK );
	}

/* Write atributes to a buffer */

static int writeKeyAttributes( void *privKeyAttributes, 
							   int *privKeyAttributeSize,
							   void *pubKeyAttributes, 
							   int *pubKeyAttributeSize,
							   PKCS15_INFO *pkcs15info,
							   const CRYPT_HANDLE cryptHandle )
	{
	RESOURCE_DATA msgData;
	STREAM stream;
	int keyUsage = 0, value, status;
	int commonAttributeSize, commonKeyAttributeSize;

	/* Get various pieces of information from the object.  The information
	   may already have been set up earlier on so we only set it if this is
	   a newly-added key */
	if( !pkcs15info->labelLength )
		{
		setResourceData( &msgData, pkcs15info->label, CRYPT_MAX_TEXTSIZE );
		status = krnlSendMessage( cryptHandle, RESOURCE_IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_LABEL );
		if( cryptStatusError( status ) )
			return( status );
		pkcs15info->labelLength = msgData.length;
		setResourceData( &msgData, pkcs15info->iD, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( cryptHandle, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_KEYID );
		if( cryptStatusError( status ) )
			return( status );
		pkcs15info->iDlength = msgData.length;
		memcpy( pkcs15info->keyID, pkcs15info->iD, pkcs15info->iDlength );
		pkcs15info->keyIDlength = pkcs15info->iDlength;
		}

	/* Figure out the PKCS #15 key usage flags.  This gets complicated 
	   because they're a mixture of parts of X.509 and PKCS #11 flags (and
	   the X.509 -> PKCS #15 mapping isn't perfect, see for example key 
	   agreement), so we have to build them up from bits and pieces pulled in 
	   from all over the place.
	   
	   One point to note is that the action flags for an object can change
	   over time under the influence of another object.  For example when a
	   raw private key is initially written and unless something else has 
	   told it otherwise, it'll have all permissible actions enabled.  When a
	   certificate for the key is later added, the permissible actions for 
	   the key may be constrained by the certificate, so the private key 
	   flags will change when the object is re-written to the keyset */
	if( cryptStatusOK( krnlSendMessage( cryptHandle, RESOURCE_IMESSAGE_CHECK, 
								NULL, RESOURCE_MESSAGE_CHECK_PKC_ENCRYPT ) ) )
		keyUsage = PKCS15_USAGE_ENCRYPT;
	if( cryptStatusOK( krnlSendMessage( cryptHandle, RESOURCE_IMESSAGE_CHECK, 
								NULL, RESOURCE_MESSAGE_CHECK_PKC_DECRYPT ) ) )
		keyUsage |= PKCS15_USAGE_DECRYPT;
	if( cryptStatusOK( krnlSendMessage( cryptHandle, RESOURCE_IMESSAGE_CHECK, 
								NULL, RESOURCE_MESSAGE_CHECK_PKC_SIGN ) ) )
		keyUsage |= PKCS15_USAGE_SIGN;
	if( cryptStatusOK( krnlSendMessage( cryptHandle, RESOURCE_IMESSAGE_CHECK, 
								NULL, RESOURCE_MESSAGE_CHECK_PKC_SIGCHECK ) ) )
		keyUsage |= PKCS15_USAGE_VERIFY;
	if( cryptStatusOK( krnlSendMessage( cryptHandle, RESOURCE_IMESSAGE_CHECK, 
								NULL, RESOURCE_MESSAGE_CHECK_PKC_KA_EXPORT ) ) || \
		cryptStatusOK( krnlSendMessage( cryptHandle, RESOURCE_IMESSAGE_CHECK, 
								NULL, RESOURCE_MESSAGE_CHECK_PKC_KA_IMPORT ) ) )
		keyUsage |= PKCS15_USAGE_DERIVE;	/* I don't think so Tim */
	status = krnlSendMessage( cryptHandle, RESOURCE_IMESSAGE_GETATTRIBUTE, &value,
							  CRYPT_CERTINFO_KEYUSAGE );
	if( cryptStatusOK( status ) && \
		( value & CRYPT_KEYUSAGE_NONREPUDIATION ) )
		/* This may be a raw key a cert with no keyUsage present, so a 
		   failure to read the usage attribute isn't a problem */
		keyUsage |= PKCS15_USAGE_NONREPUDIATION;
	if( !keyUsage )
		return( CRYPT_ERROR_PERMISSION );	/* No easy way to report this one */

	/* We've now got the usage allowed by the object we've been passed, 
	   however if it's a non-private-key object it'll only allow the public-
	   key half of any operation so we have to adjust the usage further to 
	   match the existing private-key operations to allowed public-key ones */
	if( cryptStatusError( krnlSendMessage( cryptHandle, 
									RESOURCE_IMESSAGE_CHECK, NULL, 
									RESOURCE_MESSAGE_CHECK_PKC_PRIVATE ) ) )
		{
		if( keyUsage & PKCS15_USAGE_ENCRYPT ) 
			keyUsage |= pkcs15info->privKeyUsage & PKCS15_USAGE_DECRYPT;
		if( keyUsage & PKCS15_USAGE_VERIFY ) 
			keyUsage |= pkcs15info->privKeyUsage & PKCS15_USAGE_SIGN;
		}

	/* Determine how big the private key attribute collections will be */
	commonAttributeSize = ( int) sizeofObject( pkcs15info->labelLength );
	commonKeyAttributeSize = ( int ) sizeofObject( pkcs15info->iDlength ) + \
							 sizeofBitString( keyUsage ) + \
							 sizeofBoolean() + 
							 sizeofBitString( KEYATTR_ACCESS_PRIVATE );

	/* Write the private key attributes */
	sMemOpen( &stream, privKeyAttributes, KEYATTR_BUFFER_SIZE );
	writeSequence( &stream, commonAttributeSize );
	writeCharacterString( &stream, ( BYTE * ) pkcs15info->label,
						  pkcs15info->labelLength, BER_STRING_UTF8 );
	writeSequence( &stream, commonKeyAttributeSize );
	writeOctetString( &stream, pkcs15info->iD, pkcs15info->iDlength, 
					  DEFAULT_TAG );
	writeBitString( &stream, keyUsage, DEFAULT_TAG );
	writeBoolean( &stream, FALSE, DEFAULT_TAG );
	writeBitString( &stream, KEYATTR_ACCESS_PRIVATE, DEFAULT_TAG );
	*privKeyAttributeSize = ( int ) stell( &stream );
	sMemDisconnect( &stream );

	/* Determine how big the public key attribute collections will be */
	keyUsage &= PUBKEY_USAGE_MASK;
	commonKeyAttributeSize = ( int ) sizeofObject( pkcs15info->iDlength ) + \
							 sizeofBitString( keyUsage ) + \
							 sizeofBoolean() + 
							 sizeofBitString( KEYATTR_ACCESS_PUBLIC );

	/* Write the public key attributes */
	sMemOpen( &stream, pubKeyAttributes, KEYATTR_BUFFER_SIZE );
	writeSequence( &stream, commonAttributeSize );
	writeCharacterString( &stream, ( BYTE * ) pkcs15info->label,
						  pkcs15info->labelLength, BER_STRING_UTF8 );
	writeSequence( &stream, commonKeyAttributeSize );
	writeOctetString( &stream, pkcs15info->iD, pkcs15info->iDlength, 
					  DEFAULT_TAG );
	writeBitString( &stream, keyUsage, DEFAULT_TAG );
	writeBoolean( &stream, FALSE, DEFAULT_TAG );
	writeBitString( &stream, KEYATTR_ACCESS_PUBLIC, DEFAULT_TAG );
	*pubKeyAttributeSize = ( int ) stell( &stream );
	sMemDisconnect( &stream );

	return( CRYPT_OK );
	}

static int writeCertAttributes( void *certAttributes, 
								int *certAttributeSize,
							    PKCS15_INFO *pkcs15info,
								const CRYPT_HANDLE cryptHandle )
	{
	STREAM stream;
	BOOLEAN trustedImplicit = FALSE;
	int isCA, trustedUsage, status;
	int commonAttributeSize, commonCertAttributeSize;
	int keyIdentifierDataSize, trustedUsageSize;

	/* Get various pieces of information from the object.  If we're adding a
	   standalone cert then the iD won't have been set up yet, so we need to 
	   read this as well.  Since the cert could be a data-only cert, we
	   create the ID ourselves from the encoded public key components rather
	   than trying to read an associated context's keyID attribute */
	status = krnlSendMessage( cryptHandle, RESOURCE_IMESSAGE_GETATTRIBUTE,
							  &isCA, CRYPT_CERTINFO_CA );
	if( status == CRYPT_ERROR_NOTFOUND )
		{
		isCA = FALSE;
		status = CRYPT_OK;
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( cryptHandle, 
							RESOURCE_IMESSAGE_GETATTRIBUTE, &trustedUsage, 
							CRYPT_CERTINFO_TRUSTED_USAGE );
		if( status == CRYPT_ERROR_NOTFOUND )
			{
			/* If there's no trusted usage defined, don't store a trust
			   setting */
			trustedUsage = CRYPT_UNUSED;
			status = CRYPT_OK;
			}
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( cryptHandle, 
							RESOURCE_IMESSAGE_GETATTRIBUTE, &trustedImplicit, 
							CRYPT_CERTINFO_TRUSTED_IMPLICIT );
		if( status == CRYPT_ERROR_NOTFOUND )
			{
			/* If it's not implicitly trusted, don't store a trust setting */
			trustedImplicit = FALSE;
			status = CRYPT_OK;
			}
		}
	if( cryptStatusError( status ) )
		return( status );
	if( !pkcs15info->iDlength )
		{
		status = getCertID( cryptHandle, CRYPT_IATTRIBUTE_SPKI, 
							pkcs15info->iD );
		if( cryptStatusError( status ) )
			return( status );
		pkcs15info->iDlength = KEYID_SIZE;
		}

	/* Calculate the various name ID's for the cert */
	status = getCertID( cryptHandle, CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER, 
						pkcs15info->iAndSID );
	if( cryptStatusOK( status ) )
		status = getCertID( cryptHandle, CRYPT_IATTRIBUTE_SUBJECT, 
							pkcs15info->subjectNameID );
	if( cryptStatusOK( status ) )
		status = getCertID( cryptHandle, CRYPT_IATTRIBUTE_ISSUER, 
							pkcs15info->issuerNameID );
	if( cryptStatusError( status ) )
		return( status );
	pkcs15info->iAndSIDlength = pkcs15info->subjectNameIDlength = \
		pkcs15info->issuerNameIDlength = KEYID_SIZE;
	trustedUsageSize = ( trustedUsage != CRYPT_UNUSED ) ? \
					   sizeofBitString( trustedUsage ) : 0;
	keyIdentifierDataSize = ( int ) sizeofObject( \
				sizeofShortInteger( PKCS15_KEYID_ISSUERANDSERIALNUMBERHASH ) +
				sizeofObject( pkcs15info->iAndSIDlength ) ) + \
							( int ) sizeofObject( \
				sizeofShortInteger( PKCS15_KEYID_SUBJECTNAMEHASH ) +
				sizeofObject( pkcs15info->subjectNameIDlength ) ) + \
							( int ) sizeofObject( \
				sizeofShortInteger( PKCS15_KEYID_ISSUERNAMEHASH ) +
				sizeofObject( pkcs15info->issuerNameIDlength ) );

	/* Determine how big the attribute collection will be */
	commonAttributeSize = pkcs15info->labelLength ? \
						  ( int) sizeofObject( pkcs15info->labelLength ) : 0;
	commonCertAttributeSize = ( int ) sizeofObject( pkcs15info->iDlength ) + \
							  ( isCA ? sizeofBoolean() : 0 ) + \
							  ( int ) sizeofObject( keyIdentifierDataSize + \
							  ( ( trustedUsage != CRYPT_UNUSED ) ? \
								( int ) sizeofObject( trustedUsageSize ) : 0 ) );

	/* Write the cert attributes */
	sMemOpen( &stream, certAttributes, KEYATTR_BUFFER_SIZE );
	writeSequence( &stream, commonAttributeSize );
	if( commonAttributeSize )
		writeCharacterString( &stream, ( BYTE * ) pkcs15info->label,
							  pkcs15info->labelLength, BER_STRING_UTF8 );
	writeSequence( &stream, commonCertAttributeSize );
	writeOctetString( &stream, pkcs15info->iD, pkcs15info->iDlength, 
					  DEFAULT_TAG );
	if( isCA )
		writeBoolean( &stream, TRUE, DEFAULT_TAG );
	if( trustedUsage != CRYPT_UNUSED )
		{
		writeConstructed( &stream, trustedUsageSize, CTAG_CA_TRUSTED );
		writeBitString( &stream, trustedUsage, DEFAULT_TAG );
		}
	writeConstructed( &stream, keyIdentifierDataSize, CTAG_CA_IDENTIFIERS );
	writeSequence( &stream, 
				   sizeofShortInteger( PKCS15_KEYID_ISSUERANDSERIALNUMBERHASH ) +
				   sizeofObject( pkcs15info->iAndSIDlength ) );
	writeShortInteger( &stream, PKCS15_KEYID_ISSUERANDSERIALNUMBERHASH,
					   DEFAULT_TAG );
	writeOctetString( &stream, pkcs15info->iAndSID, 
					  pkcs15info->iAndSIDlength, DEFAULT_TAG );
	writeSequence( &stream, 
				   sizeofShortInteger( PKCS15_KEYID_SUBJECTNAMEHASH ) +
				   sizeofObject( pkcs15info->subjectNameIDlength ) );
	writeShortInteger( &stream, PKCS15_KEYID_SUBJECTNAMEHASH, DEFAULT_TAG );
	writeOctetString( &stream, pkcs15info->subjectNameID, 
					  pkcs15info->subjectNameIDlength, DEFAULT_TAG );
	writeSequence( &stream, 
				   sizeofShortInteger( PKCS15_KEYID_ISSUERNAMEHASH ) +
				   sizeofObject( pkcs15info->issuerNameIDlength ) );
	writeShortInteger( &stream, PKCS15_KEYID_ISSUERNAMEHASH, DEFAULT_TAG );
	writeOctetString( &stream, pkcs15info->issuerNameID, 
					  pkcs15info->issuerNameIDlength, DEFAULT_TAG );
	*certAttributeSize = ( int ) stell( &stream );
	sMemDisconnect( &stream );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						PKCS #15 Init/Shutdown Functions					*
*																			*
****************************************************************************/

/* Flush a PKCS #15 collection to a stream */

static int pkcs15Flush( STREAM *stream, const PKCS15_INFO *pkcs15info )
	{
	int pubKeySize = 0, privKeySize = 0, certSize = 0, dataSize = 0;
	int i;

	/* Determine the overall size of the objects */
	for( i = 0; i < MAX_PKCS15_OBJECTS; i++ )
		switch( pkcs15info[ i ].type )
			{
			case PKCS15_SUBTYPE_NONE:
				break;

			case PKCS15_SUBTYPE_NORMAL:
				pubKeySize += pkcs15info[ i ].pubKeyDataSize;
				privKeySize += pkcs15info[ i ].privKeyDataSize;
				/* Drop through */
			case PKCS15_SUBTYPE_CERT:
				certSize += pkcs15info[ i ].certDataSize;
				break;

			case PKCS15_SUBTYPE_DATA:
				dataSize += ( int ) sizeofObject( \
						sizeofObject( \
							sizeofObject( pkcs15info[ i ].labelLength ) ) + 
						sizeofObject( \
							sizeofOID( OID_CRYPTLIB_CONFIGDATA ) ) + 
						sizeofObject( \
							sizeofObject( pkcs15info[ i ].dataDataSize ) ) );
				break;

			default:
				assert( NOTREACHED );
			}

	/* Write the header information and each public key, private key, and 
	   cert */
	writeCMSheader( stream, OID_PKCS15_CONTENTTYPE, \
		sizeofShortInteger( 0 ) + 
		( pubKeySize ? \
			( int ) sizeofObject( sizeofObject( \
									sizeofObject( \
									  sizeofObject( pubKeySize ) ) ) ) : 0 ) + 
		( privKeySize ? \
			( int ) sizeofObject( sizeofObject( \
									sizeofObject( \
									  sizeofObject( privKeySize ) ) ) ) : 0 ) + 
		( certSize ? \
			( int ) sizeofObject( sizeofObject( \
									sizeofObject( \
									  sizeofObject( certSize ) ) ) ) : 0 ) +
		( dataSize ? \
			( int ) sizeofObject( sizeofObject( \
									sizeofObject( \
									  sizeofObject( dataSize ) ) ) ) : 0 ) );
	writeShortInteger( stream, 0, DEFAULT_TAG );
	if( privKeySize )
		{
		writeConstructed( stream, ( int ) sizeofObject( \
											sizeofObject( \
											  sizeofObject( privKeySize ) ) ), 
						  PKCS15_OBJECT_PRIVKEY );
		writeSequence( stream, ( int ) sizeofObject( \
											sizeofObject( privKeySize ) ) );
		writeConstructed( stream, ( int ) sizeofObject( privKeySize ), 
						  CTAG_OV_DIRECT );
		writeSequence( stream, privKeySize );
		for( i = 0; i < MAX_PKCS15_OBJECTS; i++ )
			if( pkcs15info[ i ].privKeyDataSize )
				swrite( stream, pkcs15info[ i ].privKeyData, 
						pkcs15info[ i ].privKeyDataSize );
		}
	if( pubKeySize )
		{
		writeConstructed( stream, ( int ) sizeofObject( \
											sizeofObject( \
											  sizeofObject( pubKeySize ) ) ), 
						  PKCS15_OBJECT_PUBKEY );
		writeSequence( stream, ( int ) sizeofObject( \
											sizeofObject( pubKeySize ) ) );
		writeConstructed( stream, ( int ) sizeofObject( pubKeySize ), 
						  CTAG_OV_DIRECT );
		writeSequence( stream, pubKeySize );
		for( i = 0; i < MAX_PKCS15_OBJECTS; i++ )
			if( pkcs15info[ i ].pubKeyDataSize )
				swrite( stream, pkcs15info[ i ].pubKeyData, 
						pkcs15info[ i ].pubKeyDataSize );
		}
	if( certSize )
		{
		writeConstructed( stream, ( int ) sizeofObject( \
											sizeofObject( \
											  sizeofObject( certSize ) ) ), 
						  PKCS15_OBJECT_CERT );
		writeSequence( stream, ( int ) sizeofObject( \
											sizeofObject( certSize ) ) );
		writeConstructed( stream, ( int ) sizeofObject( certSize ), 
						  CTAG_OV_DIRECT );
		writeSequence( stream, certSize );
		for( i = 0; i < MAX_PKCS15_OBJECTS; i++ )
			if( ( pkcs15info[ i ].type == PKCS15_SUBTYPE_NORMAL && \
				  pkcs15info[ i ].certDataSize ) || \
				( pkcs15info[ i ].type == PKCS15_SUBTYPE_CERT ) )
				swrite( stream, pkcs15info[ i ].certData, 
						pkcs15info[ i ].certDataSize );
		}
	if( dataSize )
		{
		const PKCS15_INFO *pkcs15infoPtr = &pkcs15info[ 0 ];
		const int labelSize = ( int ) sizeofObject( pkcs15infoPtr->labelLength );

		assert( pkcs15infoPtr->type == PKCS15_SUBTYPE_DATA );

		writeConstructed( stream, ( int ) sizeofObject( \
											sizeofObject( \
											  sizeofObject( dataSize ) ) ), 
						  PKCS15_OBJECT_DATA );
		writeSequence( stream, ( int ) sizeofObject( \
											sizeofObject( dataSize ) ) );
		writeConstructed( stream, ( int ) sizeofObject( dataSize ), 
						  CTAG_OV_DIRECT );
		writeSequence( stream, dataSize );
		writeSequence( stream, ( int ) sizeofObject( labelSize ) + \
					   ( int ) sizeofObject( sizeofOID( OID_CRYPTLIB_CONFIGDATA ) ) +
					   ( int ) sizeofObject( \
								 sizeofObject( pkcs15infoPtr->dataDataSize ) ) );
		writeSequence( stream, labelSize );
		writeCharacterString( stream, ( BYTE * ) pkcs15info->label,
							  pkcs15info->labelLength, BER_STRING_UTF8 );
		writeSequence( stream, sizeofOID( OID_CRYPTLIB_CONFIGDATA ) );
		writeOID( stream, OID_CRYPTLIB_CONFIGDATA );
		writeConstructed( stream, 
						  ( int ) sizeofObject( pkcs15infoPtr->dataDataSize ), 
						  CTAG_OB_TYPEATTR );
		writeSequence( stream, pkcs15infoPtr->dataDataSize );
		swrite( stream, pkcs15infoPtr->dataData, pkcs15infoPtr->dataDataSize );
		}

	return( sflush( stream ) );
	}

/* A PKCS #15 keyset can contain multiple keys and whatnot, so when we open
   it we scan it and record various pieces of information about it which we
   can use later when we need to access it */

static int initKeysetFunction( KEYSET_INFO *keysetInfo, const char *name,
							   const char *arg1, const char *arg2,
							   const char *arg3, const CRYPT_KEYOPT_TYPE options )
	{
	PKCS15_INFO *pkcs15info, pkcs15objectInfo;
	STREAM *stream = &keysetInfo->keysetFile.stream;
	long outerEndPos;
	int status;

	assert( name == NULL ); assert( arg1 == NULL ); 
	assert( arg2 == NULL ); assert( arg3 == NULL );

	/* Allocate the PKCS #15 object info */
	if( ( pkcs15info = malloc( sizeof( PKCS15_INFO ) * \
							   MAX_PKCS15_OBJECTS ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memset( pkcs15info, 0, sizeof( PKCS15_INFO ) * MAX_PKCS15_OBJECTS );
	keysetInfo->keyData = pkcs15info;

	/* If this is a newly-created keyset, there's nothing left to do */
	if( options == CRYPT_KEYOPT_CREATE )
		return( CRYPT_OK );

	/* Skip the header */
	status = readCMSheader( stream, keyFileOIDselection, &outerEndPos );
	if( cryptStatusError( status ) )
		return( status );
	outerEndPos += stell( stream );

	/* Scan all the objects in the file.  We allow a bit of slop to handle
	   incorrect length encodings (16 bytes = roughly min.object size) */
	while( cryptStatusOK( status ) && stell( stream ) < outerEndPos - 16 )
		{
		const PKCS15_OBJECT_TYPE type = EXTRACT_CTAG( readTag( stream ) );
		int innerEndPos;

		/* Read the [n] EXPLICIT SEQUENCE [0] EXPLICIT SEQUENCE wrapper to
		   find out what we're dealing with */
		if( type < 0 || type >= PKCS15_OBJECT_LAST )
			return( CRYPT_ERROR_BADDATA );
		readLength( stream, NULL );
		status = readSequence( stream, NULL );
		if( !cryptStatusError( status ) )
			status = readConstructed( stream, NULL, CTAG_OV_DIRECT );
		if( !cryptStatusError( status ) )
			status = readSequence( stream, &innerEndPos );
		if( cryptStatusError( status ) )
			return( status );
		innerEndPos += stell( stream );

		/* Scan all objects of this type, again allowing for slop */
		while( stell( stream ) < innerEndPos - 16 )
			{
			PKCS15_INFO *pkcs15infoPtr;

			/* Read the current object */
			status = readObjectAttributes( stream, &pkcs15objectInfo, type );
			if( cryptStatusError( status ) )
				break;

			/* Find out where to add the object data */
			pkcs15infoPtr = findEntry( pkcs15info, CRYPT_KEYIDEX_PKCS15ID,
									   pkcs15objectInfo.iD, 
									   pkcs15objectInfo.iDlength );
			if( pkcs15infoPtr == NULL )
				{
				int i;

				/* This personality isn't present yet, find out where we can 
				   add the object data and copy the fixed information 
				   over */
				for( i = 0; i < MAX_PKCS15_OBJECTS; i++ )
					if( pkcs15info[ i ].type == PKCS15_SUBTYPE_NONE )
						break;
				if( i == MAX_PKCS15_OBJECTS )
					{
					status = CRYPT_ERROR_OVERFLOW;
					break;
					}
				pkcs15info[ i ] = pkcs15objectInfo;
				pkcs15infoPtr = &pkcs15info[ i ];
				pkcs15infoPtr->index = i;
				}

			/* If any new ID information has become available, copy it over.  
			   The keyID defaults to the iD, so we only copy the newly-read 
			   keyID over if it's something other than the existing iD */
			if( pkcs15infoPtr->iDlength != pkcs15objectInfo.keyIDlength || \
				memcmp( pkcs15infoPtr->iD, pkcs15objectInfo.keyID, 
						pkcs15objectInfo.keyIDlength ) )
				{
				memcpy( pkcs15infoPtr->keyID, pkcs15objectInfo.keyID,
						pkcs15objectInfo.keyIDlength );
				pkcs15infoPtr->keyIDlength = pkcs15objectInfo.keyIDlength;
				}
			if( pkcs15objectInfo.iAndSIDlength )
				{
				memcpy( pkcs15infoPtr->iAndSID, pkcs15objectInfo.iAndSID,
						pkcs15objectInfo.iAndSIDlength );
				pkcs15infoPtr->iAndSIDlength = pkcs15objectInfo.iAndSIDlength;
				}
			if( pkcs15objectInfo.subjectNameIDlength )
				{
				memcpy( pkcs15infoPtr->subjectNameID, 
						pkcs15objectInfo.subjectNameID,
						pkcs15objectInfo.subjectNameIDlength );
				pkcs15infoPtr->subjectNameIDlength = \
						pkcs15objectInfo.subjectNameIDlength;
				}
			if( pkcs15objectInfo.issuerNameIDlength )
				{
				memcpy( pkcs15infoPtr->issuerNameID, 
						pkcs15objectInfo.issuerNameID,
						pkcs15objectInfo.issuerNameIDlength );
				pkcs15infoPtr->issuerNameIDlength = \
						pkcs15objectInfo.issuerNameIDlength;
				}

			/* Copy the payload over */
			switch( type )
				{
				case PKCS15_OBJECT_PUBKEY:
					pkcs15infoPtr->type = PKCS15_SUBTYPE_NORMAL;
					pkcs15infoPtr->pubKeyData = pkcs15objectInfo.pubKeyData;
					pkcs15infoPtr->pubKeyDataSize = pkcs15objectInfo.pubKeyDataSize;
					pkcs15infoPtr->pubKeyOffset = pkcs15objectInfo.pubKeyOffset;
					pkcs15infoPtr->pubKeyUsage = pkcs15objectInfo.pubKeyUsage;
					break;

				case PKCS15_OBJECT_PRIVKEY:
					pkcs15infoPtr->type = PKCS15_SUBTYPE_NORMAL;
					pkcs15infoPtr->privKeyData = pkcs15objectInfo.privKeyData;
					pkcs15infoPtr->privKeyDataSize = pkcs15objectInfo.privKeyDataSize;
					pkcs15infoPtr->privKeyOffset = pkcs15objectInfo.privKeyOffset;
					pkcs15infoPtr->privKeyUsage = pkcs15objectInfo.privKeyUsage;
					break;

				case PKCS15_OBJECT_CERT:
				case PKCS15_OBJECT_TRUSTEDCERT:
				case PKCS15_OBJECT_USEFULCERT:
					if( pkcs15infoPtr->type == PKCS15_SUBTYPE_NONE )
						pkcs15infoPtr->type = PKCS15_SUBTYPE_CERT;
					pkcs15infoPtr->certData = pkcs15objectInfo.certData;
					pkcs15infoPtr->certDataSize = pkcs15objectInfo.certDataSize;
					pkcs15infoPtr->certOffset = pkcs15objectInfo.certOffset;
					break;

				case PKCS15_OBJECT_DATA:
					pkcs15infoPtr->type = PKCS15_SUBTYPE_DATA;
					pkcs15infoPtr->dataData = pkcs15objectInfo.dataData;
					pkcs15infoPtr->dataDataSize = pkcs15objectInfo.dataDataSize;
					pkcs15infoPtr->dataOffset = pkcs15objectInfo.dataOffset;
					break;
				}
			}
		}

	return( status );
	}

/* Shut down the PKCS #15 state, flushing information to disk if necessary */

static void shutdownKeysetFunction( KEYSET_INFO *keysetInfo )
	{
	/* If the contents have been changed, commit the changes to disk */
	if( keysetInfo->isDirty )
		{
		sseek( &keysetInfo->keysetFile.stream, 0 );
		pkcs15Flush( &keysetInfo->keysetFile.stream, keysetInfo->keyData );
		}

	/* Free the PKCS #15 object info */
	if( keysetInfo->keyData != NULL )
		{
		pkcs15Free( keysetInfo->keyData );
		zeroise( keysetInfo->keyData, keysetInfo->keyDataSize );
		free( keysetInfo->keyData );
		}
	}

/****************************************************************************
*																			*
*									Read a Key								*
*																			*
****************************************************************************/

/* Read the decryption information for the encrypted private key and use it
   to import the encrypted private components into an existing PKC context */

static int readEncryptedKey( STREAM *stream, 
							 const CRYPT_CONTEXT iPrivKeyContext,
							 const char *password, const int passwordLength )
	{
	CREATEOBJECT_INFO createInfo, createInfoSessionKey;
	MECHANISM_WRAP_INFO mechanismInfo;
	CRYPT_ALGO cryptAlgo;
	CRYPT_MODE cryptMode;
	RESOURCE_DATA msgData;
	QUERY_INFO queryInfo;
	BYTE iv[ CRYPT_MAX_IVSIZE ];
	void *encryptedKey;
	long length;
	int ivSize, status;

	/* Read the header for the SET OF EncryptionInfo */
	if( cryptStatusError( readSet( stream, NULL ) ) )
		return( CRYPT_ERROR_BADDATA );

	/* Query the exported key information to determine the parameters
	   required to reconstruct the decryption key */
	status = queryObject( stream, &queryInfo );
	if( cryptStatusError( status ) )
		return( status );
	if( queryInfo.type != CRYPT_OBJECT_ENCRYPTED_KEY )
		return( CRYPT_ERROR_BADDATA );
	encryptedKey = sMemBufPtr( stream );
	readUniversal( stream );	/* Skip the exported key */

	/* Read the session key information and create a context from it */
	status = readCMSencrHeader( stream, dataOIDselection, &length,
								&cryptAlgo, &cryptMode, iv, &ivSize );
	if( cryptStatusOK( status ) )
		{
		setMessageCreateObjectInfo( &createInfoSessionKey, cryptAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
								  &createInfoSessionKey, OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfoSessionKey.cryptHandle, 
								  RESOURCE_IMESSAGE_SETATTRIBUTE,
								  &cryptMode, CRYPT_CTXINFO_MODE );
	if( cryptStatusOK( status ) )
		{
		setResourceData( &msgData, iv, ivSize );
		status = krnlSendMessage( createInfoSessionKey.cryptHandle, 
								  RESOURCE_IMESSAGE_SETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_IV );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Create an encryption context and derive the user password into it
	   using the given parameters, and import the session key.  If there's an
	   error in the parameters stored with the exported key, we'll get an arg
	   or attribute error when we try to set the attribute so we translate it 
	   into an error code which is appropriate for the situation (algorithm 
	   and mode checking is already perform by queryObject(), so any problems
	   which make it into the create/set/load functions are likely to be 
	   rather obscure) */
	setMessageCreateObjectInfo( &createInfo, queryInfo.cryptAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfoSessionKey.cryptHandle, 
								  RESOURCE_IMESSAGE_SETATTRIBUTE,
								  &queryInfo.cryptMode, CRYPT_CTXINFO_MODE );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( createInfo.cryptHandle, 
								  RESOURCE_IMESSAGE_SETATTRIBUTE, 
								  &queryInfo.keySetupAlgo, 
								  CRYPT_CTXINFO_KEYING_ALGO );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( createInfo.cryptHandle, 
									  RESOURCE_IMESSAGE_SETATTRIBUTE, 
									  &queryInfo.keySetupIterations, 
									  CRYPT_CTXINFO_KEYING_ITERATIONS );
		if( cryptStatusOK( status ) )
			{
			setResourceData( &msgData, queryInfo.salt, queryInfo.saltLength );
			status = krnlSendMessage( createInfo.cryptHandle, 
									  RESOURCE_IMESSAGE_SETATTRIBUTE_S, 
									  &msgData, CRYPT_CTXINFO_KEYING_SALT );
			}
		if( cryptStatusOK( status ) )
			{
			setResourceData( &msgData, ( void * ) password, passwordLength );
			status = krnlSendMessage( createInfo.cryptHandle, 
									  RESOURCE_IMESSAGE_SETATTRIBUTE_S, 
									  &msgData, CRYPT_CTXINFO_KEYING_VALUE );
			}
		if( cryptStatusOK( status ) )
			status = iCryptImportKeyEx( encryptedKey, createInfo.cryptHandle,
										createInfoSessionKey.cryptHandle );
		krnlSendNotifier( createInfo.cryptHandle, 
						  RESOURCE_IMESSAGE_DECREFCOUNT );
		}
	memset( &queryInfo, 0, sizeof( QUERY_INFO ) );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfoSessionKey.cryptHandle, 
						  RESOURCE_IMESSAGE_DECREFCOUNT );
		return( cryptArgError( status ) ? \
				CRYPT_ERROR_BADDATA : status );
		}

	/* Import the encrypted key into the PKC context */
	setMechanismWrapInfo( &mechanismInfo, sMemBufPtr( stream ), length, 
						  NULL, 0, iPrivKeyContext, 
						  createInfoSessionKey.cryptHandle, CRYPT_UNUSED );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_DEV_IMPORT, &mechanismInfo,
							  MECHANISM_PRIVATEKEYWRAP );
	clearMechanismInfo( &mechanismInfo );
	krnlSendNotifier( createInfoSessionKey.cryptHandle, 
					  RESOURCE_IMESSAGE_DECREFCOUNT );

	return( status );
	}

/* Read key data from a PKCS #15 collection */

static int getItemFunction( KEYSET_INFO *keysetInfo, 
							CRYPT_HANDLE *iCryptHandle, 
							const CRYPT_KEYID_TYPE keyIDtype, 
							const void *keyID,  const int keyIDlength, 
							void *auxInfo, int *auxInfoLength, 
							const int flags )
	{
	CRYPT_CERTIFICATE iDataCert = CRYPT_ERROR;
	CRYPT_CONTEXT iCryptContext;
	const PKCS15_INFO *pkcs15infoPtr;
	RESOURCE_DATA msgData;
	STREAM stream;
	const BOOLEAN publicComponentsOnly = \
					( flags & KEYMGMT_FLAG_PUBLICKEY ) ? TRUE : FALSE;
	int pubkeyActionFlags, privkeyActionFlags, status;

	/* If we're being asked for encoded configuration information, return it
	   and exit */
	if( iCryptHandle == NULL )
		{
		assert( keyIDtype == CRYPT_KEYID_NONE );
		assert( keyID == NULL ); assert( keyIDlength == 0 );

		/* Return the pre-encoded config data.  This is rather an abuse of the
		   interface, but it saves having to define a special-case keyset
		   function for the task */
		pkcs15infoPtr = keysetInfo->keyData;
		if( pkcs15infoPtr->type != PKCS15_SUBTYPE_DATA )
			return( CRYPT_ERROR_NOTFOUND );
		if( auxInfo != NULL )
			memcpy( auxInfo, ( BYTE * ) pkcs15infoPtr->dataData + \
										pkcs15infoPtr->dataOffset, 
					pkcs15infoPtr->dataDataSize - pkcs15infoPtr->dataOffset );
		return( pkcs15infoPtr->dataDataSize - pkcs15infoPtr->dataOffset );
		}

	assert( iCryptHandle != NULL );
	assert( keyIDtype == CRYPT_KEYID_NAME || \
			keyIDtype == CRYPT_KEYID_EMAIL || \
			keyIDtype == CRYPT_IKEYID_KEYID || \
			keyIDtype == CRYPT_IKEYID_ISSUERID );
	assert( keyID != NULL ); assert( keyIDlength >= 1 );

	/* Clear the return values */
	*iCryptHandle = CRYPT_ERROR;

	/* Locate the appropriate object in the PKCS #15 collection and make sure
	   the components we need are present: Either a public key or a cert for
	   any read, and a private key as well as a public key for a private-key 
	   read */
	pkcs15infoPtr = findEntry( keysetInfo->keyData, keyIDtype, keyID, keyIDlength );
	if( pkcs15infoPtr == NULL || \
		( pkcs15infoPtr->pubKeyData == NULL && \
		  pkcs15infoPtr->certData == NULL ) )
		return( CRYPT_ERROR_NOTFOUND );	/* Not enough to get public key */
	if( !publicComponentsOnly && ( pkcs15infoPtr->pubKeyData == NULL || \
		pkcs15infoPtr->privKeyData == NULL ) )
		return( CRYPT_ERROR_NOTFOUND );	/* Not enough to get private key */

	/* Get the permitted usage flags for each object type we'll be 
	   instantiating.  If there's a public key present we apply its usage 
	   flags to whichever PKC context we create, even if it's done indirectly 
	   via the cert import.  Since the private key can also perform the 
	   actions of the public key, we set its action flags to the union of the 
	   two */
	if( pkcs15infoPtr->pubKeyData != NULL )
		{
		pubkeyActionFlags = getPermittedActions( pkcs15infoPtr->pubKeyUsage );
		if( cryptStatusError( pubkeyActionFlags ) )
			return( pubkeyActionFlags );
		}
	if( !publicComponentsOnly )
		{
		privkeyActionFlags = getPermittedActions( pkcs15infoPtr->privKeyUsage );
		if( cryptStatusError( privkeyActionFlags ) )
			return( privkeyActionFlags );
		privkeyActionFlags |= pubkeyActionFlags;
		}

	/* If we're just checking whether an object exists, return now.  If all 
	   we want is the key label, copy it back to the caller and exit */
	if( flags & KEYMGMT_FLAG_CHECK_ONLY )
		return( CRYPT_OK );
	if( flags & KEYMGMT_FLAG_LABEL_ONLY )
		{
		*auxInfoLength = pkcs15infoPtr->labelLength;
		if( auxInfo != NULL )
			memcpy( auxInfo, pkcs15infoPtr->label, 
					pkcs15infoPtr->labelLength );
		return( CRYPT_OK );
		}

	/* If we're only interested in the public components, read whatever's
	   there and exit */
	if( publicComponentsOnly )
		{
		if( pkcs15infoPtr->certData != NULL )
			status = iCryptImportCertIndirect( &iCryptContext, 
								keysetInfo->objectHandle, keyIDtype, keyID, 
								keyIDlength, CERTIMPORT_NORMAL );
		else
			{
			sMemConnect( &stream, ( BYTE * ) pkcs15infoPtr->pubKeyData + \
						 pkcs15infoPtr->pubKeyOffset, 
						 pkcs15infoPtr->pubKeyDataSize );
			status = readPublicKey( &stream, &iCryptContext, 
									READKEY_OPTION_NONE );
			sMemDisconnect( &stream );
			}
		if( !cryptStatusError( status ) && pkcs15infoPtr->pubKeyData != NULL )
			status = krnlSendMessage( iCryptContext, 
						RESOURCE_IMESSAGE_SETATTRIBUTE, &pubkeyActionFlags, 
						CRYPT_IATTRIBUTE_ACTIONPERMS );
		if( !cryptStatusError( status ) )
			*iCryptHandle = iCryptContext;
		return( status );
		}

	/* Make sure the user has supplied a password */
	if( auxInfo == NULL )
		return( CRYPT_ERROR_WRONGKEY );

	assert( pkcs15infoPtr->pubKeyData != NULL && \
			pkcs15infoPtr->privKeyData != NULL );

	/* Read the public components into a PKC context and optional data-only 
	   cert if there's cert information present.  Note that we can't take
	   advantage of the fact that there's another copy of the public key in
	   the cert to read both at once since this returns an initialised context
	   which can't be updated with the private key in the two-step read
	   required for PKCS #15 files */
	sMemConnect( &stream, ( BYTE * ) pkcs15infoPtr->pubKeyData + \
				 pkcs15infoPtr->pubKeyOffset, pkcs15infoPtr->pubKeyDataSize );
	status = readPublicKey( &stream, &iCryptContext, 
							READKEY_OPTION_DEFERREDLOAD );
	sMemDisconnect( &stream );
	if( cryptStatusOK( status ) && pkcs15infoPtr->certData != NULL )
		status = iCryptImportCertIndirect( &iDataCert, 
								keysetInfo->objectHandle, keyIDtype, keyID, 
								keyIDlength, CERTIMPORT_DATA_ONLY );
	if( cryptStatusError( status ) )
		return( status );

	/* Set the key label.  We have to do this before we load the key or the
	   key load will be blocked by the kernel */
	setResourceData( &msgData, ( void * ) pkcs15infoPtr->label, 
					 pkcs15infoPtr->labelLength );
	krnlSendMessage( iCryptContext, RESOURCE_IMESSAGE_SETATTRIBUTE_S,
					 &msgData, CRYPT_CTXINFO_LABEL );

	/* Read the private key header fields and import the private key */
	sMemConnect( &stream, ( BYTE * ) pkcs15infoPtr->privKeyData + \
				 pkcs15infoPtr->privKeyOffset, 
				 pkcs15infoPtr->privKeyDataSize );
	if( readTag( &stream ) != MAKE_CTAG( CTAG_OV_DIRECTPROTECTED ) )
		status = CRYPT_ERROR_BADDATA;
	else
		{
		BYTE *tagPtr;

		/* The protected data is a [2] IMPLICIT SEQUENCE rather than a
		   straight SEQUENCE so we need to fiddle the tag for the read to
		   work */
		sseek( &stream, 0 );
		tagPtr = sMemBufPtr( &stream );
		*tagPtr = BER_SEQUENCE;
		status = readCMSheader( &stream, privKeyDataOIDselection, NULL );
		*tagPtr = MAKE_CTAG( CTAG_OV_DIRECTPROTECTED );
		}
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		krnlSendNotifier( iCryptContext, RESOURCE_IMESSAGE_DECREFCOUNT );
		if( iDataCert != CRYPT_ERROR )
			krnlSendNotifier( iDataCert, RESOURCE_IMESSAGE_DECREFCOUNT );
		return( status );
		}
	status = readEncryptedKey( &stream, iCryptContext, auxInfo, 
							   *auxInfoLength );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCryptContext, RESOURCE_IMESSAGE_DECREFCOUNT );
		if( iDataCert != CRYPT_ERROR )
			krnlSendNotifier( iDataCert, RESOURCE_IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Connect the data-only certificate object to the context if it exists.  
	   This is an internal object used only by the context so we tell the 
	   kernel to mark it as owned by the context only */
	if( iDataCert != CRYPT_ERROR )
		krnlSendMessage( iCryptContext, RESOURCE_IMESSAGE_SETDEPENDENT,
						 &iDataCert, FALSE );

	/* Set the permitted action flags and the key label */
	status = krnlSendMessage( iCryptContext, RESOURCE_IMESSAGE_SETATTRIBUTE,
							  &privkeyActionFlags, 
							  CRYPT_IATTRIBUTE_ACTIONPERMS );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCryptContext, RESOURCE_MESSAGE_DECREFCOUNT );
		return( status );
		}

	*iCryptHandle = iCryptContext;
	return( CRYPT_OK );
	}

/* Fetch a sequence of certs.  This is called indirectly by the certificate 
   code to fetch the next cert in a chain, if the key ID is nonzero we fetch 
   the first cert and set the state info, if the key ID is zero we fetch the 
   next cert based on the previously stored state info */

static int getNextCertFunction( KEYSET_INFO *keysetInfo,
								CRYPT_CERTIFICATE *iCertificate,
								int *stateInfo,
								const CRYPT_KEYID_TYPE keyIDtype,
								const void *keyID, const int keyIDlength,
								const CERTIMPORT_TYPE options )
	{
	CREATEOBJECT_INFO createInfo;
	const PKCS15_INFO *pkcs15infoPtr = keysetInfo->keyData;
	int status;

	assert( ( *stateInfo >= 0 && *stateInfo < MAX_PKCS15_OBJECTS ) || \
			*stateInfo == CRYPT_ERROR );

	/* If we're continuing from a previous fetch, set the key ID to the nameID
	   of the previous certs issuer */
	if( keyIDtype == CRYPT_KEYID_NONE )
		{
		/* If the previous cert was the last one, there's nothing left to fetch */
		if( *stateInfo == CRYPT_ERROR )
			return( CRYPT_ERROR_NOTFOUND );

		/* Find the cert for which the subjectNameID matches this certs 
		   issuerNameID */
		pkcs15infoPtr = findEntry( pkcs15infoPtr, CRYPT_KEYIDEX_SUBJECTNAMEID, 
							pkcs15infoPtr[ *stateInfo ].issuerNameID, 
							pkcs15infoPtr[ *stateInfo ].issuerNameIDlength );
		}
	else
		pkcs15infoPtr = findEntry( pkcs15infoPtr, keyIDtype, keyID, 
								   keyIDlength );
	if( pkcs15infoPtr == NULL )
		{
		*stateInfo = CRYPT_ERROR;
		return( CRYPT_ERROR_NOTFOUND );
		}
	*stateInfo = pkcs15infoPtr->index;

	/* Import the cert */
	setMessageCreateObjectInfo( &createInfo, options );
	createInfo.createIndirect = TRUE;
	createInfo.strArg1 = ( BYTE * ) pkcs15infoPtr->certData + \
						 pkcs15infoPtr->certOffset;
	createInfo.strArgLen1 = pkcs15infoPtr->certDataSize - \
							pkcs15infoPtr->certOffset;
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		*iCertificate = createInfo.cryptHandle;
	return( status );
	}

/****************************************************************************
*																			*
*									Write a Key								*
*																			*
****************************************************************************/

/* Determine the tag to use when encoding a given key type */

static int getKeyTypeTag( const CRYPT_CONTEXT cryptContext )
	{
	CRYPT_ALGO cryptAlgo;
	int status;

	status = krnlSendMessage( cryptContext, RESOURCE_IMESSAGE_GETATTRIBUTE,
							  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );
	switch( cryptAlgo )
		{
		case CRYPT_ALGO_RSA:
			return( DEFAULT_TAG );

		case CRYPT_ALGO_DH:
			return( 1 );

		case CRYPT_ALGO_DSA:
			return( 2 );

		case CRYPT_ALGO_KEA:
			return( 3 );
		}

	assert( NOTREACHED );
	return( 0 );	/* Get rid of compiler warning */
	}

/* Generate a session key and write the wrapped key in the form
   SET OF {	[ 0 ] (EncryptedKey) } */

static int writeWrappedSessionKey( STREAM *stream,
								   CRYPT_CONTEXT iSessionKeyContext,
								   const char *password, 
								   const int passwordLength )
	{
	CREATEOBJECT_INFO createInfo;
	CRYPT_ALGO cryptAlgo;
	int iterations, exportedKeySize, status;

	/* In the interests of luser-proofing, we're really paranoid and force
	   the use of non-weak algorithms and modes of operation.  In addition
	   since OIDs are only defined for a limited subset of algorithms, we
	   also default to a guaranteed available algorithm if no OID is defined
	   for the one requested */
	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
					 &cryptAlgo, CRYPT_OPTION_ENCR_ALGO );
	if( isWeakCryptAlgo( cryptAlgo ) ||
		cryptStatusError( sizeofAlgoIDex( cryptAlgo,
									( CRYPT_ALGO ) CRYPT_MODE_CBC, 0 ) ) )
		cryptAlgo = CRYPT_ALGO_3DES;
	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
					 &iterations, CRYPT_OPTION_KEYING_ITERATIONS );
	if( iterations < 500 )
		iterations = 500;

	/* Create an encryption context and derive the user password into it */
	setMessageCreateObjectInfo( &createInfo, cryptAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( createInfo.cryptHandle, 
							  RESOURCE_IMESSAGE_SETATTRIBUTE, &iterations, 
							  CRYPT_CTXINFO_KEYING_ITERATIONS );
	if( cryptStatusOK( status ) )
		{
		RESOURCE_DATA msgData;

		setResourceData( &msgData, ( void * ) password, passwordLength );
		status = krnlSendMessage( createInfo.cryptHandle, 
								  RESOURCE_IMESSAGE_SETATTRIBUTE_S, 
								  &msgData, CRYPT_CTXINFO_KEYING_VALUE );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, 
						  RESOURCE_IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Determine the size of the exported key and write the encrypted data
	   content field */
	if( cryptStatusOK( status ) )
		status = iCryptExportKeyEx( NULL, &exportedKeySize, CRYPT_FORMAT_CMS,
									iSessionKeyContext, createInfo.cryptHandle, 
									CRYPT_UNUSED );
	if( cryptStatusOK( status ) )
		{
		writeSet( stream, exportedKeySize );
		status = iCryptExportKeyEx( stream->buffer + stream->bufPos,
									&exportedKeySize, CRYPT_FORMAT_CMS,
									iSessionKeyContext, createInfo.cryptHandle, 
									CRYPT_UNUSED );
		sSkip( stream, exportedKeySize );
		}

	/* Clean up */
	krnlSendNotifier( createInfo.cryptHandle, RESOURCE_IMESSAGE_DECREFCOUNT );
	return( status );
	}

/* Add key data to a PKCS #15 collection.  Because of the nature of PKCS #15 
   we have to be able to cleanly handle the addition of arbitrary collections
   of objects, which leads to some rather convoluted logic for deciding what
   needs updating and under which conditions.  The actions taken are:

	key only:	if present
					return( CRYPT_ERROR_DUPLICATE )
				else 
					add;
	cert only:	if present
					return( CRYPT_ERROR_DUPLICATE );
				elif( matching key present )
					add, update key data;
				elif( trusted cert )
					add as trusted cert;
				else
					error;
	key+cert:	if key present and cert present
					return( CRYPT_ERROR_DUPLICATE );
				if key present -> don't add key;
				if cert present -> don't add cert;
				add whatever's left; */

typedef enum {
	CERTADD_UPDATE_EXISTING,/* Update existing key info with a cert */
	CERTADD_NORMAL,			/* Add a cert for which no key info present */
	CERTADD_STANDALONE_CERT	/* Add a standalone cert not assoc'd with a key */
	} CERTADD_TYPE;

static int pkcs15AddCert( PKCS15_INFO *pkcs15infoPtr,
						  const CRYPT_CERTIFICATE cryptCert,
						  const void *pubKeyAttributes,
						  const int pubKeyAttributeSize,
						  const void *privKeyAttributes,
						  const int privKeyAttributeSize,
						  const CERTADD_TYPE certAddType )
	{
	RESOURCE_DATA msgData;
	STREAM stream;
	BYTE certAttributes[ KEYATTR_BUFFER_SIZE ];
	void *newPrivKeyData = NULL, *newPubKeyData = NULL;
	const int keyTypeTag = getKeyTypeTag( cryptCert );
	int newPrivKeyDataSize, newPubKeyDataSize;
	int newPrivKeyOffset, newPubKeyOffset;
	int privKeyInfoSize, pubKeyInfoSize;
	int certAttributeSize, status;

	/* If we've been passed a standalone cert, it has to be implicitly 
	   trusted in order to be added */
	if( certAddType == CERTADD_STANDALONE_CERT )
		{
		int value;

		status = krnlSendMessage( cryptCert, RESOURCE_IMESSAGE_GETATTRIBUTE,
								  &value, CRYPT_CERTINFO_TRUSTED_IMPLICIT );
		if( cryptStatusError( status ) || !value )
			return( CRYPT_ARGERROR_NUM1 );

		/* Set the personality type to cert-only */
		pkcs15infoPtr->type = PKCS15_SUBTYPE_CERT;
		}

	/* Write the cert attributes */
	status = writeCertAttributes( certAttributes, &certAttributeSize,
								  pkcs15infoPtr, cryptCert );
	if( cryptStatusError( status ) )
		return( status );

	/* Find out how big the PKCS #15 data will be and allocate room for it.  
	   Since the cert will affect the key attributes, we need to rewrite the 
	   key information once we've done the cert, so we allocate room for both 
	   the cert and the rewritten key data */
	if( certAddType == CERTADD_UPDATE_EXISTING )
		{
		pubKeyInfoSize = pkcs15infoPtr->pubKeyDataSize - \
						 pkcs15infoPtr->pubKeyOffset;
		newPubKeyDataSize = pubKeyAttributeSize + \
							( int ) sizeofObject( \
									  sizeofObject( \
										sizeofObject( pubKeyInfoSize ) ) );
		newPubKeyData = malloc( ( int ) sizeofObject( newPubKeyDataSize ) );
		privKeyInfoSize = pkcs15infoPtr->privKeyDataSize - \
						  pkcs15infoPtr->privKeyOffset;
		newPrivKeyDataSize = privKeyAttributeSize + \
							 ( int ) sizeofObject( \
									  sizeofObject( privKeyInfoSize ) );
		newPrivKeyData = malloc( ( int ) sizeofObject( newPrivKeyDataSize ) );
		if( ( newPubKeyData == NULL ) || ( newPrivKeyData == NULL ) )
			return( CRYPT_ERROR_MEMORY );
		}
	setResourceData( &msgData, NULL, 0 );
	status = krnlSendMessage( cryptCert, RESOURCE_IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_ENC_CERT );
	if( cryptStatusOK( status ) )
		{
		pkcs15infoPtr->certDataSize = ( int ) sizeofObject( \
										certAttributeSize + \
										sizeofObject( \
											sizeofObject( msgData.length ) ) );
		pkcs15infoPtr->certData = malloc( pkcs15infoPtr->certDataSize );
		if( pkcs15infoPtr->certData == NULL )
			status = CRYPT_ERROR_MEMORY;
		}
	if( cryptStatusOK( status ) )
		{
		sMemOpen( &stream, pkcs15infoPtr->certData, 
				  pkcs15infoPtr->certDataSize );
		writeSequence( &stream, certAttributeSize + \
					   ( int ) sizeofObject( sizeofObject( msgData.length ) ) );
		swrite( &stream, certAttributes, certAttributeSize );
		writeConstructed( &stream, ( int ) sizeofObject( msgData.length ), 
						  CTAG_OB_TYPEATTR );
		writeSequence( &stream, msgData.length );
		pkcs15infoPtr->certOffset = stell( &stream );
		msgData.data = sMemBufPtr( &stream );
		status = krnlSendMessage( cryptCert, RESOURCE_IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_ENC_CERT );
		sMemDisconnect( &stream );
		}
	if( cryptStatusError( status ) )
		{
		/* Undo what we've done so far without changing the existing PKCS #15 
		   data */
		if( newPubKeyData != NULL )
			free( newPubKeyData );
		if( newPrivKeyData != NULL )
			free( newPrivKeyData );
		if( pkcs15infoPtr->certData != NULL )
			free( pkcs15infoPtr->certData );
		pkcs15infoPtr->certData = NULL;
		pkcs15infoPtr->certDataSize = pkcs15infoPtr->certOffset = 0;
		return( status );
		}

	/* If it's a standalone cert, we're done */
	if( certAddType != CERTADD_UPDATE_EXISTING )
		return( CRYPT_OK );

	/* The corresponding key is already present, we need to update the key 
	   info since adding the certificate may have changed the attributes. 
	   First we write the new attributes and append the existing key info */
	sMemOpen( &stream, newPubKeyData, 
			  ( int ) sizeofObject( newPubKeyDataSize ) );
	writeConstructed( &stream, newPubKeyDataSize, keyTypeTag );
	swrite( &stream, pubKeyAttributes, pubKeyAttributeSize );
	writeConstructed( &stream, 
					  ( int ) sizeofObject( sizeofObject( pubKeyInfoSize ) ), 
					  CTAG_OB_TYPEATTR );
	writeSequence( &stream, ( int ) sizeofObject( pubKeyInfoSize ) );
	writeConstructed( &stream, pubKeyInfoSize, CTAG_OV_DIRECT );
	newPubKeyOffset = stell( &stream );
	swrite( &stream, ( BYTE * ) pkcs15infoPtr->pubKeyData +
			pkcs15infoPtr->pubKeyOffset, pubKeyInfoSize );
	sMemDisconnect( &stream );
	sMemOpen( &stream, newPrivKeyData, 
			  ( int ) sizeofObject( newPrivKeyDataSize ) );
	writeConstructed( &stream, newPrivKeyDataSize, keyTypeTag );
	swrite( &stream, privKeyAttributes, privKeyAttributeSize );
	writeConstructed( &stream, ( int ) sizeofObject( privKeyInfoSize ), 
					  CTAG_OB_TYPEATTR );
	writeSequence( &stream, privKeyInfoSize );
	newPrivKeyOffset = stell( &stream );
	swrite( &stream, ( BYTE * ) pkcs15infoPtr->privKeyData +
			pkcs15infoPtr->privKeyOffset, privKeyInfoSize );
	sMemDisconnect( &stream );

	/* Replace the old data with the newly-written data */
	zeroise( pkcs15infoPtr->pubKeyData, pkcs15infoPtr->pubKeyDataSize );
	free( pkcs15infoPtr->pubKeyData );
	pkcs15infoPtr->pubKeyData = newPubKeyData;
	pkcs15infoPtr->pubKeyDataSize = ( int ) sizeofObject( newPubKeyDataSize );
	pkcs15infoPtr->pubKeyOffset = newPubKeyOffset;
	zeroise( pkcs15infoPtr->privKeyData, pkcs15infoPtr->privKeyDataSize );
	free( pkcs15infoPtr->privKeyData );
	pkcs15infoPtr->privKeyData = newPrivKeyData;
	pkcs15infoPtr->privKeyDataSize = ( int ) sizeofObject( newPrivKeyDataSize );
	pkcs15infoPtr->privKeyOffset = newPrivKeyOffset;

	return( CRYPT_OK );
	}

static int pkcs15AddCertChain( PKCS15_INFO *pkcs15info,
							   const CRYPT_CERTIFICATE iCryptCert )
	{
	BOOLEAN seenNonDuplicate = FALSE;
	int status;

	/* See if there are certs in the chain beyond the first one, which we've
	   already added.  Getting a data not found error is OK since it just 
	   means that there are no more certs present */
	krnlSendMessage( iCryptCert, RESOURCE_IMESSAGE_SETATTRIBUTE, 
					 MESSAGE_VALUE_CURSORFIRST, 
					 CRYPT_CERTINFO_CURRENT_CERTIFICATE );
	status = krnlSendMessage( iCryptCert, RESOURCE_IMESSAGE_SETATTRIBUTE, 
							  MESSAGE_VALUE_CURSORNEXT, 
							  CRYPT_CERTINFO_CURRENT_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ERROR_NOTFOUND ) ? CRYPT_OK : status );

	/* Walk up the chain checking each cert to see whether we need to add 
	   it */
	do
		{
		PKCS15_INFO *pkcs15infoPtr;
		BYTE iAndSID [ CRYPT_MAX_HASHSIZE ];
		int i;

		/* Check whether this cert is present */
		status = getCertID( iCryptCert, CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER, 
							iAndSID );
		if( cryptStatusError( status ) )
			continue;
		if( findEntry( pkcs15info, CRYPT_IKEYID_ISSUERID, iAndSID, 
					   KEYID_SIZE ) != NULL )
			continue;

		/* We've found a cert which isn't present yet, try and add it */
		for( i = 0; i < MAX_PKCS15_OBJECTS; i++ )
			if( pkcs15info[ i ].type == PKCS15_SUBTYPE_NONE )
				break;
		if( i == MAX_PKCS15_OBJECTS )
			return( CRYPT_ERROR_OVERFLOW );
		pkcs15infoPtr = &pkcs15info[ i ];
		pkcs15infoPtr->index = i;
		pkcs15infoPtr->type = PKCS15_SUBTYPE_NORMAL;
		status = pkcs15AddCert( pkcs15infoPtr, iCryptCert, NULL, 0,
								NULL, 0, CERTADD_NORMAL );

		/* A cert being added may already be present, however we can't fail
		   immediately because there may be further certs in the chain, so we 
		   keep track of whether we've successfully added at least one cert 
		   and clear data duplicate errors */
		if( status == CRYPT_OK )
			seenNonDuplicate = TRUE;
		else
			if( status == CRYPT_ERROR_DUPLICATE )
				status = CRYPT_OK;
		}
	while( cryptStatusOK( status ) && \
		   krnlSendMessage( iCryptCert, RESOURCE_IMESSAGE_SETATTRIBUTE, 
							MESSAGE_VALUE_CURSORNEXT,
							CRYPT_CERTINFO_CURRENT_CERTIFICATE ) == CRYPT_OK );
	if( cryptStatusOK( status ) && !seenNonDuplicate )
		/* We reached the end of the chain without finding anything we could
		   add, return a data duplicate error */
		status = CRYPT_ERROR_DUPLICATE;
	return( status );
	}

static int setItemFunction( KEYSET_INFO *keysetInfo, 
							const CRYPT_HANDLE cryptHandle,
							const char *password, const int passwordLength )
	{
	CRYPT_CONTEXT iSessionKeyContext;
	CRYPT_ALGO cryptAlgo;
	MECHANISM_WRAP_INFO mechanismInfo;
	CREATEOBJECT_INFO createInfo;
	PKCS15_INFO *pkcs15infoPtr;
	RESOURCE_DATA msgData;
	STREAM stream;
	BYTE iD[ CRYPT_MAX_HASHSIZE ];
	BYTE pubKeyAttributes[ KEYATTR_BUFFER_SIZE ];
	BYTE privKeyAttributes[ KEYATTR_BUFFER_SIZE ];
	BOOLEAN certPresent = FALSE, contextPresent;
	BOOLEAN pkcs15certPresent = FALSE, pkcs15keyPresent = FALSE;
	BOOLEAN isCertChain = FALSE;
	void *dataPtr, *headerPtr;
	int pubKeyAttributeSize, pubKeyDataSize;
	int privKeyAttributeSize, privKeyDataSize;
	int privKeyInfoSize;
	int keyTypeTag, iDsize, value, status;

	/* If we're being sent pre-encoded configuration information, add it to
	   the PKCS #15 data and exit */
	if( cryptHandle == CRYPT_UNUSED )
		{
		/* Remember the pre-encoded config data */
		pkcs15infoPtr = keysetInfo->keyData;
		assert( pkcs15infoPtr->type == PKCS15_SUBTYPE_NONE );
		if( ( pkcs15infoPtr->dataData = malloc( passwordLength ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		memcpy( pkcs15infoPtr->dataData, password, passwordLength );
		pkcs15infoPtr->dataDataSize = passwordLength;

		/* Set the fixed identification information used by the config data */
		pkcs15infoPtr->type = PKCS15_SUBTYPE_DATA;
		memcpy( pkcs15infoPtr->label, "cryptlib Configuration Information", 34 );
		pkcs15infoPtr->labelLength = 34;

		return( CRYPT_OK );
		}

	/* Check the object, extract ID information from it, and determine 
	   whether it's a standalone cert (which produces a PKCS #15 cert object) 
	   or a context (which produces PKCS #15 public and private key objects
	   and optionally a PKCS #15 cert object) */
	status = krnlSendMessage( cryptHandle, RESOURCE_MESSAGE_CHECK, NULL,
							  RESOURCE_MESSAGE_CHECK_PKC );
	if( cryptStatusOK( status ) )
		{
		setResourceData( &msgData, iD, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( cryptHandle, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_KEYID );
		iDsize = msgData.length;
		}
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM1 : status );
	contextPresent = cryptStatusOK( krnlSendMessage( cryptHandle, 
						RESOURCE_IMESSAGE_CHECK, NULL,
						RESOURCE_MESSAGE_CHECK_PKC_PRIVATE ) ) ? TRUE : FALSE;

	/* If there's a cert present, make sure it's something which can be 
	   stored.  We don't treat the wrong type as an error since we can still 
	   store the public/private key components even if we don't store the 
	   cert */
	status = krnlSendMessage( cryptHandle, RESOURCE_IMESSAGE_GETATTRIBUTE, 
							  &value, CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusOK( status ) && \
		( value == CRYPT_CERTTYPE_CERTIFICATE || \
		  value == CRYPT_CERTTYPE_CERTCHAIN ) )
		{
		/* If it's a cert chain, remember this for later since we may
		   need to store multiple certs */
		if( value == CRYPT_CERTTYPE_CERTCHAIN )
			isCertChain = TRUE;

		/* If the cert isn't signed, we can't store it in this state */
		status = krnlSendMessage( cryptHandle, RESOURCE_IMESSAGE_GETATTRIBUTE, 
								  &value, CRYPT_CERTINFO_IMMUTABLE );
		if( cryptStatusError( status ) || !value )
			return( CRYPT_ERROR_NOTINITED );
		certPresent = TRUE;
		}

	/* Find out where we can add data and what needs to be added */
	pkcs15infoPtr = findEntry( keysetInfo->keyData, CRYPT_KEYIDEX_PKCS15ID, 
							   iD, iDsize );
	if( pkcs15infoPtr != NULL )
		{
		BOOLEAN unneededCert, unneededKey;

		/* Determine what actually needs to be added */		
		if( pkcs15infoPtr->pubKeyData != NULL )
			pkcs15keyPresent = TRUE;
		if( pkcs15infoPtr->certData != NULL )
			pkcs15certPresent = TRUE;

		/* Make sure we can update at least one of the PKCS #15 objects in 
		   the personality */
		unneededKey = contextPresent & pkcs15keyPresent;
		unneededCert = certPresent & pkcs15certPresent;
		if( ( unneededKey && !certPresent ) ||		/* Key only, duplicate */ 
			( unneededCert && !contextPresent ) ||	/* Cert only, duplicate */
			( unneededKey && unneededCert ) )		/* Key+cert, duplicate */
			{
			/* If it's anything other than a cert chain, we can't add 
			   anything */
			if( !isCertChain )
				return( CRYPT_ERROR_DUPLICATE );

			/* It's a cert chain, there may be new certs present, try and add
			   them */
			status = krnlSendNotifier( cryptHandle, RESOURCE_MESSAGE_LOCK );
			if( cryptStatusError( status ) )
				return( status );
			status = pkcs15AddCertChain( pkcs15infoPtr, cryptHandle );
			krnlSendNotifier( cryptHandle, RESOURCE_MESSAGE_UNLOCK );
			return( status );
			}
		}
	else
		{
		int i;

		/* Find out where we can add the new key data */
		pkcs15infoPtr = keysetInfo->keyData;
		for( i = 0; i < MAX_PKCS15_OBJECTS; i++ )
			if( pkcs15infoPtr[ i ].type == PKCS15_SUBTYPE_NONE )
				break;
		if( i == MAX_PKCS15_OBJECTS )
			return( CRYPT_ERROR_OVERFLOW );
		pkcs15infoPtr = &pkcs15infoPtr[ i ];
		pkcs15infoPtr->index = i;
		}
	pkcs15infoPtr->type = PKCS15_SUBTYPE_NORMAL;

	/* If we're adding a private key, make sure there's a password present.
	   Conversely, if there's a password present make sure we're adding a
	   private key */
	if( contextPresent && !pkcs15keyPresent && password == NULL )
		return( CRYPT_ARGERROR_STR1 );
	if( password != NULL && !contextPresent )
		return( CRYPT_ARGERROR_NUM1 );

	/* We're ready to go, lock the object for our exclusive use */
	status = krnlSendNotifier( cryptHandle, RESOURCE_MESSAGE_LOCK );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the attribute information.  We have to rewrite the key 
	   information when we add a non-standalone cert even if we don't change
	   the key because adding a cert can affect key attributes */
	keyTypeTag = getKeyTypeTag( cryptHandle );
	if( ( certPresent && pkcs15keyPresent ) ||		/* Updating existing */
		( contextPresent && !pkcs15keyPresent ) )	/* Adding new */
		status = writeKeyAttributes( privKeyAttributes, &privKeyAttributeSize,
									 pubKeyAttributes, &pubKeyAttributeSize,
									 pkcs15infoPtr, cryptHandle );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( cryptHandle, RESOURCE_MESSAGE_UNLOCK );
		return( status );
		}

	/* Write the cert if necessary.  We do this one first because it's the
	   easiest to back out of */
	if( certPresent && !pkcs15certPresent )
		{
		/* Select the leaf cert in case it's a cert chain */
		krnlSendMessage( cryptHandle, RESOURCE_IMESSAGE_SETATTRIBUTE, 
						 MESSAGE_VALUE_CURSORFIRST, 
						 CRYPT_CERTINFO_CURRENT_CERTIFICATE );

		/* Write the cert information.  There may be further certs in the 
		   chain but we don't try and do anything with these until after the 
		   rest of the key information has been added */
		status = pkcs15AddCert( pkcs15infoPtr, cryptHandle, pubKeyAttributes,
						pubKeyAttributeSize, privKeyAttributes, 
						privKeyAttributeSize, pkcs15keyPresent ? \
							CERTADD_UPDATE_EXISTING : contextPresent ? \
							CERTADD_NORMAL : CERTADD_STANDALONE_CERT );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( cryptHandle, RESOURCE_MESSAGE_UNLOCK );
			return( status );
			}

		/* If there's no context to add we return now, however if we've been 
		   given a cert chain with further certs in it we try and add these as 
		   well before we exit */
		if( !contextPresent || pkcs15keyPresent )
			{
			if( isCertChain )
				status = pkcs15AddCertChain( pkcs15infoPtr, cryptHandle );
			krnlSendNotifier( cryptHandle, RESOURCE_MESSAGE_UNLOCK );
			return( status );
			}
		}

	/* Find out how large the encoded public data will be and allocate 
	   storage for it */
	setResourceData( &msgData, NULL, 0 );
	status = krnlSendMessage( cryptHandle, RESOURCE_IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_PUBLICKEY );
	pubKeyDataSize = msgData.length;
	if( cryptStatusOK( status ) )
		{
		pkcs15infoPtr->pubKeyDataSize = ( int ) sizeofObject( \
									pubKeyAttributeSize + \
									sizeofObject( \
									  sizeofObject( \
										sizeofObject( pubKeyDataSize ) ) ) );
		if( ( pkcs15infoPtr->pubKeyData = \
						malloc( pkcs15infoPtr->pubKeyDataSize ) ) == NULL )
			status = CRYPT_ERROR_MEMORY;
		}
	if( cryptStatusError( status ) )
		{
		pkcs15freeEntry( pkcs15infoPtr );
		krnlSendNotifier( cryptHandle, RESOURCE_MESSAGE_UNLOCK );
		return( status );
		}

	/* Write the public key data */
	sMemOpen( &stream, pkcs15infoPtr->pubKeyData, 
			  pkcs15infoPtr->pubKeyDataSize );
	writeConstructed( &stream, pubKeyAttributeSize + \
					  ( int ) sizeofObject( \
								sizeofObject( \
								  sizeofObject( pubKeyDataSize ) ) ), 
					  keyTypeTag );
	swrite( &stream, pubKeyAttributes, pubKeyAttributeSize );
	writeConstructed( &stream, 
					  ( int ) sizeofObject( sizeofObject( pubKeyDataSize ) ), 
					  CTAG_OB_TYPEATTR );
	writeSequence( &stream, ( int ) sizeofObject( pubKeyDataSize ) );
	writeConstructed( &stream, pubKeyDataSize, CTAG_OV_DIRECT );
	pkcs15infoPtr->pubKeyOffset = stell( &stream );
	setResourceData( &msgData, sMemBufPtr( &stream ), pubKeyDataSize );
	status = krnlSendMessage( cryptHandle, RESOURCE_IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_PUBLICKEY );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		{
		pkcs15freeEntry( pkcs15infoPtr );
		krnlSendNotifier( cryptHandle, RESOURCE_MESSAGE_UNLOCK );
		return( status );
		}

	/* Create a session key context and generate a key and IV into it.  The IV
	   would be generated automatically later on when we encrypt data for the
	   first time, but we do it explicitly here to catch any possible errors
	   at a point where recovery is easier.  In the interests of luser-
	   proofing we're really paranoid and force the use of non-weak algorithms 
	   and modes of operation.  In addition since OIDs are only defined for a 
	   limited subset of algorithms, we also default to a guaranteed available 
	   algorithm if no OID is defined for the one requested */
	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
					 &cryptAlgo, CRYPT_OPTION_ENCR_ALGO );
	if( isWeakCryptAlgo( cryptAlgo ) ||
		cryptStatusError( sizeofAlgoIDex( cryptAlgo,
									( CRYPT_ALGO ) CRYPT_MODE_CBC, 0 ) ) )
		cryptAlgo = CRYPT_ALGO_3DES;
	setMessageCreateObjectInfo( &createInfo, cryptAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle,
								  RESOURCE_IMESSAGE_CTX_GENKEY, 
								  MESSAGE_VALUE_DEFAULT, FALSE );
	if( cryptStatusOK( status ) )
		status = krnlSendNotifier( createInfo.cryptHandle, 
								   RESOURCE_IMESSAGE_CTX_GENIV );
	if( cryptStatusError( status ) )
		{
		pkcs15freeEntry( pkcs15infoPtr );
		krnlSendNotifier( createInfo.cryptHandle, 
						  RESOURCE_IMESSAGE_DECREFCOUNT );
		krnlSendNotifier( cryptHandle, RESOURCE_MESSAGE_UNLOCK );
		return( status );
		}
	iSessionKeyContext = createInfo.cryptHandle;

	/* Calculate the eventual encrypted key size and allocate storage for it */
	setMechanismWrapInfo( &mechanismInfo, NULL, 0, NULL, 0, cryptHandle, 
						  iSessionKeyContext, CRYPT_UNUSED );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_DEV_EXPORT, &mechanismInfo,
							  MECHANISM_PRIVATEKEYWRAP );
	privKeyInfoSize = mechanismInfo.wrappedDataLength;
	clearMechanismInfo( &mechanismInfo );
	if( cryptStatusOK( status ) )
		{
		pkcs15infoPtr->privKeyDataSize = privKeyAttributeSize + 
										 privKeyInfoSize + 512;
		if( ( pkcs15infoPtr->privKeyData = \
					malloc( pkcs15infoPtr->privKeyDataSize ) ) == NULL )
			status = CRYPT_ERROR_MEMORY;
		}
	if( cryptStatusError( status ) )
		{
		pkcs15freeEntry( pkcs15infoPtr );
		krnlSendNotifier( iSessionKeyContext, RESOURCE_IMESSAGE_DECREFCOUNT );
		krnlSendNotifier( cryptHandle, RESOURCE_MESSAGE_UNLOCK );
		return( status );
		}

	/* Since we can't write the header and attributes until we write the 
	   encrypted private key, we leave enough space at the start to contain 
	   this information and write the private key after that */
	sMemOpen( &stream, pkcs15infoPtr->privKeyData, 
			  pkcs15infoPtr->privKeyDataSize );
	sseek( &stream, 200 + privKeyAttributeSize );
	dataPtr = sMemBufPtr( &stream );

	/* Write the encryption information with a gap at the start for the CMS 
	   header.  Since we're using KEKRecipientInfo, we use a version of 2 
	   rather than 0  */
	writeShortInteger( &stream, 2, DEFAULT_TAG );
	status = writeWrappedSessionKey( &stream, iSessionKeyContext, password, 
									 passwordLength );
	if( cryptStatusOK( status ) )
		status = writeCMSencrHeader( &stream, OID_CMS_DATA, privKeyInfoSize, 
									 iSessionKeyContext );
	if( cryptStatusError( status ) )
		{
		sMemClose( &stream );
		pkcs15freeEntry( pkcs15infoPtr );
		krnlSendNotifier( iSessionKeyContext, RESOURCE_IMESSAGE_DECREFCOUNT );
		krnlSendNotifier( cryptHandle, RESOURCE_MESSAGE_UNLOCK );
		return( status );
		}

	/* Export the encrypted private key */
	setMechanismWrapInfo( &mechanismInfo, sMemBufPtr( &stream ), 
						  privKeyInfoSize, NULL, 0, cryptHandle, 
						  iSessionKeyContext, CRYPT_UNUSED );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_DEV_EXPORT, &mechanismInfo,
							  MECHANISM_PRIVATEKEYWRAP );
	sSkip( &stream, mechanismInfo.wrappedDataLength );
	clearMechanismInfo( &mechanismInfo );
	krnlSendNotifier( iSessionKeyContext, RESOURCE_IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		sMemClose( &stream );
		pkcs15freeEntry( pkcs15infoPtr );
		krnlSendNotifier( cryptHandle, RESOURCE_MESSAGE_UNLOCK );
		return( status );
		}
	privKeyDataSize = ( int ) stell( &stream ) - ( 200 + privKeyAttributeSize );

	/* Kludge the CMS header onto the start of the data */
	sseek( &stream, 100 + privKeyAttributeSize );
	headerPtr = sMemBufPtr( &stream );
	writeCMSheader( &stream, OID_CMS_ENVELOPEDDATA, privKeyDataSize );
	*( ( BYTE * ) headerPtr ) = MAKE_CTAG( CTAG_OV_DIRECTPROTECTED );
	memmove( sMemBufPtr( &stream ), dataPtr, privKeyDataSize );
	privKeyDataSize += ( int ) stell( &stream ) - ( 100 + privKeyAttributeSize );

	/* Now that we've written the private key data and know how long it is,
	   move back to the start and write the attributes and outer header, then 
	   move the private key information down to the end.  Finally, adjust the 
	   private key size value to reflect the true size (rather than the 
	   allocated buffer size) */
	sseek( &stream, 0 );
	writeConstructed( &stream, privKeyAttributeSize + \
					  ( int ) sizeofObject( sizeofObject( privKeyDataSize ) ), 
					  keyTypeTag );
	swrite( &stream, privKeyAttributes, privKeyAttributeSize );
	writeConstructed( &stream, ( int ) sizeofObject( privKeyDataSize ), 
					  CTAG_OB_TYPEATTR );
	writeSequence( &stream, privKeyDataSize );
	pkcs15infoPtr->privKeyOffset = stell( &stream );
	memmove( sMemBufPtr( &stream ), headerPtr, privKeyDataSize );
	pkcs15infoPtr->privKeyDataSize = pkcs15infoPtr->privKeyOffset + \
									 privKeyDataSize;
	sMemDisconnect( &stream );

	/* If we've been given a cert chain, try and add any further certs which
	   may be present in it.  Once we've done that, we can unlock the 
	   object to allow others access */
	if( isCertChain )
		status = pkcs15AddCertChain( pkcs15infoPtr, cryptHandle );
	krnlSendNotifier( cryptHandle, RESOURCE_MESSAGE_UNLOCK );

	return( status );
	}

/****************************************************************************
*																			*
*									Delete a Key							*
*																			*
****************************************************************************/

static int deleteItemFunction( KEYSET_INFO *keysetInfo, 
							   const CRYPT_KEYID_TYPE keyIDtype, 
							   const void *keyID, 
							   const int keyIDlength )
	{
	PKCS15_INFO *pkcs15infoPtr;

	assert( keyIDtype == CRYPT_KEYID_NAME || \
			keyIDtype == CRYPT_KEYID_EMAIL || \
			keyIDtype == CRYPT_IKEYID_KEYID || \
			keyIDtype == CRYPT_IKEYID_ISSUERID );
	assert( keyID != NULL ); assert( keyIDlength >= 1 );

	/* Locate the appropriate object in the PKCS #15 collection */
	pkcs15infoPtr = findEntry( keysetInfo->keyData, keyIDtype, keyID, 
							   keyIDlength );
	if( pkcs15infoPtr == NULL )
		return( CRYPT_ERROR_NOTFOUND );

	/* Clear this entry */
	pkcs15freeEntry( pkcs15infoPtr );

	return( CRYPT_OK );
	}

int setAccessMethodPKCS15( KEYSET_INFO *keysetInfo )
	{
	/* Set the access method pointers */
	keysetInfo->initKeysetFunction = initKeysetFunction;
	keysetInfo->shutdownKeysetFunction = shutdownKeysetFunction;
	keysetInfo->getItemFunction = getItemFunction;
	keysetInfo->setItemFunction = setItemFunction;
	keysetInfo->getNextCertFunction = getNextCertFunction;
	keysetInfo->deleteItemFunction = deleteItemFunction;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Key File Identification Routines					*
*																			*
****************************************************************************/

#ifndef NO_PGP
  #if defined( INC_ALL )
	#include "pgp.h"
  #elif defined( INC_CHILD )
	#include "../envelope/pgp.h"
  #else
	#include "envelope/pgp.h"
  #endif /* Compiler-specific includes */
#endif /* NO_PGP */

/* Identify a flat-file keyset without changing the stream position.  We have
   to return the keyset type as an int rather than a KEYSET_SUBTYPE because
   of complex header file nesting issues */

int getKeysetType( STREAM *stream )
	{
	KEYSET_SUBTYPE type = KEYSET_SUBTYPE_ERROR;
#ifndef NO_PGP
	BOOLEAN isPGP = FALSE;
	int length;
#endif /* NO_PGP */
	long objectLength, position = stell( stream );
	int value;

	/* Try and guess the basic type */
	value = sgetc( stream );
	if( value != BER_SEQUENCE )
#ifdef NO_PGP
		{
		sseek( stream, position );
		return( KEYSET_SUBTYPE_ERROR );
		}
#else
		if( getCTB( value ) != PGP_CTB_PUBKEY && \
			getCTB( value ) != PGP_CTB_SECKEY )
			{
			sseek( stream, position );
			return( KEYSET_SUBTYPE_ERROR );
			}
		else
			isPGP = TRUE;

	/* If it looks like a PGP keyring, make sure the start of the file looks
	   OK */
	if( isPGP )
		{
		/* Try and establish the file type based on the initial CTB */
		if( getCTB( value ) == PGP_CTB_PUBKEY )
			type = KEYSET_SUBTYPE_PGP_PUBLIC;
		if( getCTB( value ) == PGP_CTB_SECKEY )
			type = KEYSET_SUBTYPE_PGP_PRIVATE;

		/* Perform a sanity check to make sure the rest looks like a PGP
		   keyring */
		length = ( int ) pgpGetLength( stream, value );
		if( type == KEYSET_SUBTYPE_PGP_PUBLIC )
			{
			if( length < 64 || length > 1024  )
				type = KEYSET_SUBTYPE_ERROR;
			}
		else
			if( length < 200 || length > 4096 )
				type = KEYSET_SUBTYPE_ERROR;
		value = sgetc( stream );
		if( value != PGP_VERSION_2 && value != PGP_VERSION_3 )
			type = KEYSET_SUBTYPE_ERROR;
		sseek( stream, position );
		return( type );
		}
#endif /* NO_PGP */

	/* Read the length of the object.  This should be between 64 and 32K 
	   bytes in size (we have to allow for very tiny files to handle PKCS #15 
	   files which contain only config data) */
	if( cryptStatusError( readLength( stream, &objectLength ) ) || \
		objectLength < 64 || objectLength > 32768 )
		{
		sseek( stream, position );
		return( KEYSET_SUBTYPE_ERROR );
		}

	/* Check for the PKCS #12 version number */
	if( peekTag( stream ) == BER_INTEGER )
		{
		long value;

		if( cryptStatusError( readShortInteger( stream, &value ) ) || \
			value != 3 )
			{
			sseek( stream, position );
			return( KEYSET_SUBTYPE_ERROR );
			}
		type = KEYSET_SUBTYPE_PKCS12;
		}
	else
		/* Check for a PKCS #15 file */
		if( !cryptStatusError( readOID( stream, OID_PKCS15_CONTENTTYPE ) ) )
			type = KEYSET_SUBTYPE_PKCS15;

	sseek( stream, position );
	return( type );
	}
