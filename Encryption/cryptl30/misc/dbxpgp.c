/****************************************************************************
*																			*
*							  PGP Key Read Routines							*
*						Copyright Peter Gutmann 1992-1998					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "pgp.h"
  #include "keyset.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../envelope/pgp.h"
  #include "keyset.h"
#else
  #include "crypt.h"
  #include "envelope/pgp.h"
  #include "misc/keyset.h"
#endif /* Compiler-specific includes */

/* Since the key-related information can consume a sizeable amount of memory, 
   we allocate storage for them dynamically.  This also keeps them in one 
   place for easy sanitization */

typedef struct {
	/* A copy of the ID used to identify the key for PGP and smart card 
	   reads, and the cached key.  The ID is used to identify repeated reads 
	   of the same key (for example if an incorrect password is used), which 
	   allows the cached key to be reused */
	BYTE cachedKeyID[ CRYPT_MAX_TEXTSIZE ];
	int cachedKeyIDlength;
	BYTE cachedKey[ MAX_PRIVATE_KEYSIZE ];
	BOOLEAN cachedKeyPresent;

	/* Key components (in PGP format) */
	BYTE n[ PGP_MAX_MPISIZE ], e[ PGP_MAX_MPISIZE ], d[ PGP_MAX_MPISIZE ];
	BYTE p[ PGP_MAX_MPISIZE ], q[ PGP_MAX_MPISIZE ], u[ PGP_MAX_MPISIZE ];
	int nLen, eLen, dLen, pLen, qLen, uLen;

	/* Key components (in cryptlib format) */
	CRYPT_PKCINFO_RSA rsaKey;

	/* userID for this key */
	char userID[ PGP_MAX_USERIDSIZE ];
	} PGP_INFO;

/****************************************************************************
*																			*
*								Read Byte/Word/Long 						*
*																			*
****************************************************************************/

/* Routines to read BYTE, WORD, LONG */

static BYTE fgetByte( STREAM *stream )
	{
	return( ( BYTE ) sgetc( stream ) );
	}

static WORD fgetWord( STREAM *stream )
	{
	WORD value;

	value = ( ( WORD ) sgetc( stream ) ) << 8;
	value |= ( WORD ) sgetc( stream );
	return( value );
	}

static LONG fgetLong( STREAM *stream )
	{
	LONG value;

	value = ( ( LONG ) sgetc( stream ) ) << 24;
	value |= ( ( LONG ) sgetc( stream ) ) << 16;
	value |= ( ( LONG ) sgetc( stream ) ) << 8;
	value |= ( LONG ) sgetc( stream );
	return( value );
	}

/****************************************************************************
*																			*
*							PGP Keyring Read Routines						*
*																			*
****************************************************************************/

/* Skip to the start of the next key packet */

static void skipToKeyPacket( STREAM *stream )
	{
	int ctb;

	/* Skip any following non-key packets */
	while( ctb = fgetByte( stream ), sGetStatus( stream ) == CRYPT_OK && \
		   getCTB( ctb ) != PGP_CTB_PUBKEY && getCTB( ctb ) != PGP_CTB_SECKEY )
		{
		int length = ( int ) pgpGetLength( stream, ctb );

		/* If we get an impossibly large packet, assume we're in trouble and
		   set the EOF status */
		if( length > 5000 )
			sSetError( stream, CRYPT_ERROR_UNDERFLOW );
		else
			/* Skip the current packet */
			sSkip( stream, length );
		}

	/* Finally, put back the last CTB we read unless we've reached the end
	   of the file */
	if( sGetStatus( stream ) == CRYPT_OK )
		sungetc( stream );
	}

/* Generate a cryptlib-style key ID for the PGP key and check it against the
   given key ID.  This will really suck with large public keyrings since it
   requires creating a context for each key we check, but there's no easy
   way around this */

static BOOLEAN matchKeyID( PGP_INFO *pgpInfo, const BYTE *requiredID,
						   const int requiredIDlength )
	{
	CRYPT_PKCINFO_RSA *rsaKeyPtr = &pgpInfo->rsaKey;
	CREATEOBJECT_INFO createInfo;
	RESOURCE_DATA msgData;
	BYTE keyID[ KEYID_SIZE ];
	int status;

	assert( requiredIDlength == KEYID_SIZE );

	/* Generate the key ID */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_RSA );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( FALSE );
	setResourceData( &msgData, "PGP dummy label", 15 );
	krnlSendMessage( createInfo.cryptHandle, RESOURCE_IMESSAGE_SETATTRIBUTE_S,
					 &msgData, CRYPT_CTXINFO_LABEL );
	cryptInitComponents( rsaKeyPtr, CRYPT_KEYTYPE_PUBLIC );
	cryptSetComponent( rsaKeyPtr->n, pgpInfo->n, pgpInfo->nLen );
	cryptSetComponent( rsaKeyPtr->e, pgpInfo->e, pgpInfo->eLen );
	setResourceData( &msgData, rsaKeyPtr, sizeof( CRYPT_PKCINFO_RSA ) );
	status = krnlSendMessage( createInfo.cryptHandle, 
							  RESOURCE_IMESSAGE_SETATTRIBUTE_S, &msgData, 
							  CRYPT_CTXINFO_KEY_COMPONENTS );
	if( cryptStatusOK( status ) )
		{
		setResourceData( &msgData, keyID, KEYID_SIZE );
		status = krnlSendMessage( createInfo.cryptHandle, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
								  CRYPT_IATTRIBUTE_KEYID );
		}
	cryptDestroyComponents( rsaKeyPtr );
	krnlSendNotifier( createInfo.cryptHandle, RESOURCE_IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( FALSE );

	/* Check if it's the same as the key ID we're looking for */
	return( !memcmp( requiredID, keyID, requiredIDlength ) ? TRUE : FALSE );
	}

/* Read a key and check whether it matches the required user ID */

static int readKey( PGP_INFO *pgpInfo, STREAM *stream,
					const CRYPT_KEYID_TYPE keyIDtype, 
					const void *keyID, const int keyIDlength, 
					const char *password, const int passwordLength, 
					void *keyData, const int flags )
	{
	STREAM keyStream;
	BOOLEAN isEncrypted, gotUserID = FALSE, foundKey = FALSE;
	BOOLEAN isPublicKey = TRUE;
	WORD checkSum, packetChecksum;
	BYTE keyIV[ PGP_IDEA_IVSIZE ];
	int ctb, length, i, status = CRYPT_OK;

	/* If we're reading a full key packet, read the keyring headers */
	if( stream != NULL )
		{
		/* Skip CTB, packet length, and version byte */
		ctb = sgetc( stream );
		if( getCTB( ctb ) == PGP_CTB_SECKEY )
			isPublicKey = FALSE;
		else
			if( getCTB( ctb ) != PGP_CTB_PUBKEY )
				return( sGetStatus( stream ) != CRYPT_OK ? \
						CRYPT_ERROR_NOTFOUND : CRYPT_ERROR_BADDATA );
		length = ( int ) pgpGetLength( stream, ctb );
		if( ( i = fgetByte( stream ) ) != PGP_VERSION_2 && i != PGP_VERSION_3 )
			{
			/* Unknown version number, skip this packet */
			sungetc( stream );
			skipToKeyPacket( stream );
			return( -1000 );
			}

		/* Read the timestamp and validity period and make sure what's left
		   will fit into the buffer */
		fgetLong( stream );
		fgetWord( stream );
		length -= PGP_SIZE_BYTE + PGP_SIZE_LONG + PGP_SIZE_WORD;
		if( length > MAX_PRIVATE_KEYSIZE )
			return( CRYPT_ERROR_BADDATA );

		/* Read the rest of the record into the memory buffer */
		if( sread( stream, keyData, length ) != CRYPT_OK )
			return( sGetStatus( stream ) );
		}
	else
		/* If we're rereading a cached key from a memory stream it'll be a
		   private key */
		isPublicKey = FALSE;

	/* Read the public key components */
	sMemConnect( &keyStream, keyData, STREAMSIZE_UNKNOWN );
	if( ( i = fgetByte( &keyStream ) ) != PGP_ALGO_RSA )
		{
		/* Unknown PKE algorithm type, skip this packet */
		skipToKeyPacket( stream );
		return( -1000 );
		}
	if( ( pgpInfo->nLen = pgpReadMPI( &keyStream, pgpInfo->n ) ) == CRYPT_ERROR || \
		( pgpInfo->eLen = pgpReadMPI( &keyStream, pgpInfo->e ) ) == CRYPT_ERROR )
		{
		skipToKeyPacket( stream );
		return( -1000 );
		}

	/* If it's a private keyring, read in the private key components */
	if( !isPublicKey )
		{
		/* Handle decryption info for secret components if necessary */
		isEncrypted = ( ctb = fgetByte( &keyStream ) ) == PGP_ALGO_IDEA;
		if( isEncrypted )
			for( i = 0; i < PGP_IDEA_IVSIZE; i++ )
				keyIV[ i ] = sgetc( &keyStream );

		/* Read in private key components and checksum */
		if( ( pgpInfo->dLen = pgpReadMPI( &keyStream, pgpInfo->d ) ) == CRYPT_ERROR || \
			( pgpInfo->pLen = pgpReadMPI( &keyStream, pgpInfo->p ) ) == CRYPT_ERROR || \
			( pgpInfo->qLen = pgpReadMPI( &keyStream, pgpInfo->q ) ) == CRYPT_ERROR || \
			( pgpInfo->uLen = pgpReadMPI( &keyStream, pgpInfo->u ) ) == CRYPT_ERROR )
			{
			skipToKeyPacket( stream );
			return( -1000 );
			}
		packetChecksum = fgetWord( &keyStream );
		}
	sMemDisconnect( &keyStream );

	/* If it's a full keyring stream, check for a keyID/userID match */
	if( stream != NULL )
		{
		/* If we're searching by key ID, check whether this is the packet we
		   want */
		if( keyIDtype == CRYPT_IKEYID_KEYID )
			if( matchKeyID( pgpInfo, keyID, keyIDlength ) )
				foundKey = TRUE;
			else
				{
				/* These aren't the keys you're looking for... you may go
				   about your business... move along, move along */
				skipToKeyPacket( stream );
				return( -1000 );
				}

		/* Read the userID packet(s).  We also make sure we get at least one
		   userID if we've already got a match based on a key ID */
		while( !foundKey || !gotUserID )
			{
			/* Skip keyring trust and signature packets */
			ctb = fgetByte( stream );
			while( getCTB( ctb ) == PGP_CTB_TRUST || \
				   getCTB( ctb ) == PGP_CTB_SIGNATURE )
				{
				/* Skip the packet */
				length = ( int ) pgpGetLength( stream, ctb );
				sSkip( stream, length );
				ctb = fgetByte( stream );
				}

			/* Check if we've got a userID packet now */
			if( getCTB( ctb ) != PGP_CTB_USERID )
				{
				sungetc( stream );

				/* If we saw at least one userID, everything was OK.  Before
				   we exit we move to the next key packet so we can continue
				   looking for keys if required */
				if( gotUserID )
					{
					skipToKeyPacket( stream );
					return( foundKey ? CRYPT_OK : -1000 );
					}

				/* We still don't have a userID CTB, complain */
				skipToKeyPacket( stream );
				return( -1000 );
				}
			length = ( int ) pgpGetLength( stream, ctb );
			for( i = 0; i < length && i < PGP_MAX_USERIDSIZE; i++ )
				pgpInfo->userID[ i ] = fgetByte( stream );
			pgpInfo->userID[ i ] = '\0';
			if( i > length )
				sSkip( stream, i - length );/* Skip excessively long userID */
			gotUserID = TRUE;

			/* Check if it's the one we want */
			if( keyIDtype != CRYPT_IKEYID_KEYID && \
				matchSubstring( ( char * ) keyID, keyIDlength, 
								pgpInfo->userID, strlen( pgpInfo->userID ) ) )
				foundKey = TRUE;
			}
		}

	/* If it's just a check or label read, we're done */
	if( flags & ( KEYMGMT_FLAG_CHECK_ONLY | KEYMGMT_FLAG_LABEL_ONLY ) )
		return( status );

	/* Process the secret-key fields if necessary */
	if( flags & KEYMGMT_FLAG_PRIVATEKEY )
		{
		/* Decrypt the secret-key fields if necessary */
		if( isEncrypted )
			{
			CREATEOBJECT_INFO createInfo;
			static const int cryptMode = CRYPT_MODE_CFB;

			/* If no password is supplied, let the caller know they need a
			   password */
			if( password == NULL )
				{
				if( stream != NULL )
					skipToKeyPacket( stream );
				return( CRYPT_ERROR_WRONGKEY );
				}

			/* Convert the user password into an IDEA encryption context */
			setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_IDEA );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
									  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
									  &createInfo, OBJECT_TYPE_CONTEXT );
			if( cryptStatusOK( status ) )
				status = krnlSendMessage( createInfo.cryptHandle, 
									  RESOURCE_IMESSAGE_SETATTRIBUTE, 
									  ( void * ) &cryptMode, CRYPT_CTXINFO_MODE );
			if( cryptStatusOK( status ) )
				status = pgpPasswordToKey( createInfo.cryptHandle, password,
										   passwordLength );
			if( cryptStatusOK( status ) )
				{
				RESOURCE_DATA msgData;

				setResourceData( &msgData, keyIV, PGP_IDEA_IVSIZE );
				status = krnlSendMessage( createInfo.cryptHandle, 
										  RESOURCE_IMESSAGE_SETATTRIBUTE_S, 
										  &msgData, CRYPT_CTXINFO_IV );
				}
			if( cryptStatusError( status ) )
				return( status );

			/* Decrypt the secret-key fields */
			krnlSendMessage( createInfo.cryptHandle, 
							 RESOURCE_IMESSAGE_CTX_DECRYPT,
							 pgpInfo->d, bitsToBytes( pgpInfo->dLen ) );
			krnlSendMessage( createInfo.cryptHandle, 
							 RESOURCE_IMESSAGE_CTX_DECRYPT,
							 pgpInfo->p, bitsToBytes( pgpInfo->pLen ) );
			krnlSendMessage( createInfo.cryptHandle, 
							 RESOURCE_IMESSAGE_CTX_DECRYPT,
							 pgpInfo->q, bitsToBytes( pgpInfo->qLen ) );
			krnlSendMessage( createInfo.cryptHandle, 
							 RESOURCE_IMESSAGE_CTX_DECRYPT,
							 pgpInfo->u, bitsToBytes( pgpInfo->uLen ) );
			krnlSendNotifier( createInfo.cryptHandle, 
							  RESOURCE_IMESSAGE_DECREFCOUNT );
			}

		/* Make sure all was OK */
		checkSum = pgpChecksumMPI( pgpInfo->d, pgpInfo->dLen );
		checkSum += pgpChecksumMPI( pgpInfo->p, pgpInfo->pLen );
		checkSum += pgpChecksumMPI( pgpInfo->q, pgpInfo->qLen );
		checkSum += pgpChecksumMPI( pgpInfo->u, pgpInfo->uLen );
		if( checkSum != packetChecksum )
			status = isEncrypted ? CRYPT_ERROR_WRONGKEY : CRYPT_ERROR_BADDATA;
		}

	/* If it's a full keyring stream, move on to the next key packet so we
	   can continue looking for keys if required */
	if( stream != NULL )
		skipToKeyPacket( stream );
	return( status );
	}

/* Create an encryption context from the PGP key info */

static int createKey( CRYPT_CONTEXT *iCryptContext, PGP_INFO *pgpInfo,
					  const int flags )
	{
	CRYPT_PKCINFO_RSA *rsaKey;
	CREATEOBJECT_INFO createInfo;
	RESOURCE_DATA msgData;
	char *userID = pgpInfo->userID;
	int userIDsize = min( strlen( userID ), CRYPT_MAX_TEXTSIZE );
	int status;

	/* If there's no user ID present, use a dummy value.  This isn't really
	   important, the only reason we're setting a label at all is to avoid 
	   having the key load code complain about the absence of a label */
	if( userIDsize == 0 )
		{
		userID = "PGP private key";
		userIDsize = 15;
		}

	/* Load the key into the encryption context */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_RSA );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	setResourceData( &msgData, pgpInfo->userID, userIDsize );
	krnlSendMessage( createInfo.cryptHandle, RESOURCE_IMESSAGE_SETATTRIBUTE_S,
					 &msgData, CRYPT_CTXINFO_LABEL );
	rsaKey = &pgpInfo->rsaKey;
	if( flags & KEYMGMT_FLAG_PUBLICKEY )
		{
		/* Set up the RSA public-key fields */
		cryptInitComponents( rsaKey, CRYPT_KEYTYPE_PUBLIC );
		cryptSetComponent( rsaKey->n, pgpInfo->n, pgpInfo->nLen );
		cryptSetComponent( rsaKey->e, pgpInfo->e, pgpInfo->eLen );
		}
	else
		{
		/* Set up the RSA private-key fields */
		cryptInitComponents( rsaKey, CRYPT_KEYTYPE_PRIVATE );
		cryptSetComponent( rsaKey->n, pgpInfo->n, pgpInfo->nLen );
		cryptSetComponent( rsaKey->e, pgpInfo->e, pgpInfo->eLen );
		cryptSetComponent( rsaKey->d, pgpInfo->d, pgpInfo->dLen );
		cryptSetComponent( rsaKey->p, pgpInfo->p, pgpInfo->pLen );
		cryptSetComponent( rsaKey->q, pgpInfo->q, pgpInfo->qLen );
		cryptSetComponent( rsaKey->u, pgpInfo->u, pgpInfo->uLen );
		}
	setResourceData( &msgData, rsaKey, sizeof( CRYPT_PKCINFO_RSA ) );
	status = krnlSendMessage( createInfo.cryptHandle, 
							  RESOURCE_IMESSAGE_SETATTRIBUTE_S, 
							  &msgData, CRYPT_CTXINFO_KEY_COMPONENTS );
	cryptDestroyComponents( rsaKey );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, 
						  RESOURCE_IMESSAGE_DECREFCOUNT );
		return( status );
		}
	*iCryptContext = createInfo.cryptHandle;

	return( CRYPT_OK );
	}

/* Get a public or private key from a file or memory buffer and return it in
   an encryption context */

static int getItemFunction( KEYSET_INFO *keysetInfo,
							CRYPT_HANDLE *iCryptHandle, 
							const CRYPT_KEYID_TYPE keyIDtype, 
							const void *keyID,  const int keyIDlength, 
							void *auxInfo, int *auxInfoLength, 
							const int flags )
	{
	STREAM *stream = &keysetInfo->keysetFile.stream;
	PGP_INFO *pgpInfo = ( PGP_INFO * ) keysetInfo->keyData;
	BOOLEAN cachedKeyPresent = FALSE;
	int status = CRYPT_OK;

	/* If the key we're looking for matches the cached key, reread it from 
	   cache */
	if( pgpInfo->cachedKeyPresent && keyID != NULL && \
		pgpInfo->cachedKeyIDlength == keyIDlength && \
		!memcmp( pgpInfo->cachedKeyID, keyID, keyIDlength ) )
		cachedKeyPresent = TRUE;

	/* We're about to overwrite the cached key, mark it as absent */
	pgpInfo->cachedKeyPresent = FALSE;
	memset( pgpInfo->cachedKeyID, 0, CRYPT_MAX_TEXTSIZE );
	pgpInfo->cachedKeyIDlength = 0;

	/* Try and find the required key in the file */
	do
		status = readKey( pgpInfo, ( cachedKeyPresent ) ? NULL : \
						  &keysetInfo->keysetFile.stream, keyIDtype, 
						  keyID, keyIDlength, auxInfo, *auxInfoLength, 
						  pgpInfo->cachedKey, flags );
	while( stream != NULL && status == -1000 );

	/* If the read succeeded, remember the key ID information */
	if( status == CRYPT_OK || status == CRYPT_ERROR_WRONGKEY )
		{
		/* Remember that we have a cached key present, and save the key 
		   ID if there's one being used */
		pgpInfo->cachedKeyPresent = TRUE;
		if( keyID != NULL )
			{
			pgpInfo->cachedKeyIDlength = min( keyIDlength, CRYPT_MAX_TEXTSIZE );
			memcpy( pgpInfo->cachedKeyID, keyID, pgpInfo->cachedKeyIDlength );
			}
		}

	/* If it's just a check or label read, we're done */
	if( flags & KEYMGMT_FLAG_CHECK_ONLY )
		return( status );
	if( flags & KEYMGMT_FLAG_LABEL_ONLY )
		{
		const int userIDsize = min( strlen( pgpInfo->userID ), 
									CRYPT_MAX_TEXTSIZE );
		if( userIDsize == 0 )
			{
			/* No userID present, return a generic label */
			*auxInfoLength = 15;
			if( auxInfo != NULL )
				memcpy( auxInfo, "PGP private key", 15 );
			}
		else
			{
			*auxInfoLength = userIDsize;
			if( auxInfo != NULL )
				memcpy( auxInfo, pgpInfo->userID, userIDsize );
			}
		return( CRYPT_OK );
		}

	/* Import the key data into a context */
	if( cryptStatusOK( status ) )
		status = createKey( iCryptHandle, pgpInfo, flags );

	/* Clean up */
	zeroise( pgpInfo->n, PGP_MAX_MPISIZE ); 
	zeroise( pgpInfo->e, PGP_MAX_MPISIZE );
	zeroise( pgpInfo->d, PGP_MAX_MPISIZE );
	zeroise( pgpInfo->p, PGP_MAX_MPISIZE );
	zeroise( pgpInfo->q, PGP_MAX_MPISIZE );
	zeroise( pgpInfo->u, PGP_MAX_MPISIZE );

	return( status );
	}

/* PGP keyrings can be arbitrarily large so we don't try to do any
   preprocessing, all we do at this point is allocate the key info */

static int initKeysetFunction( KEYSET_INFO *keysetInfo, const char *name,
							   const char *arg1, const char *arg2,
							   const char *arg3, const CRYPT_KEYOPT_TYPE options )
	{
	assert( name == NULL ); assert( arg1 == NULL ); 
	assert( arg2 == NULL ); assert( arg3 == NULL );

	/* Allocate memory for the key info */
	if( ( keysetInfo->keyData = malloc( sizeof( PGP_INFO ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memset( keysetInfo->keyData, 0, sizeof( PGP_INFO ) );
	keysetInfo->keyDataSize = sizeof( PGP_INFO );

	return( CRYPT_OK );
	}

static void shutdownKeysetFunction( KEYSET_INFO *keysetInfo )
	{
	if( keysetInfo->keyData != NULL )
		{
		zeroise( keysetInfo->keyData, sizeof( PGP_INFO ) );
		free( keysetInfo->keyData );
		keysetInfo->keyData = NULL;
		}
	}

int setAccessMethodPGP( KEYSET_INFO *keysetInfo )
	{
	/* Set the access method pointers */
	keysetInfo->initKeysetFunction = initKeysetFunction;
	keysetInfo->shutdownKeysetFunction = shutdownKeysetFunction;
	keysetInfo->getItemFunction = getItemFunction;

	return( CRYPT_OK );
	}
