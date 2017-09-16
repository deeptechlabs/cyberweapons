/****************************************************************************
*																			*
*					 cryptlib PGP De-enveloping Routines					*
*					 Copyright Peter Gutmann 1996-1997						*
*																			*
****************************************************************************/

#include <assert.h>	/*!!!!!!!!!!!!*/
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "envelope.h"
  #include "pgp.h"
#elif defined( INC_CHILD )
  #include "../envelope/envelope.h"
  #include "../envelope/pgp.h"
#else
  #include "envelope/envelope.h"
  #include "envelope/pgp.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*						Low-level De-enveloping Functions					*
*																			*
****************************************************************************/

/* Get information on a PGP data packet.  This will check that there's enough
   data left to get the packet information and decrypt the packet header if
   necessary */

static int getPacketInfo( STREAM *stream, ENVELOPE_INFO *envelopeInfoPtr,
						  long *length )
	{
	int bytesLeft = envelopeInfoPtr->bufPos - stell( stream );
	BYTE ctb;

	/* We always need at least two more bytes to do anything */
	if( bytesLeft < 2 )
		return( CRYPT_ERROR_UNDERFLOW );

	/* Make sure there's enough data left to retrieve the packet header, and
	   if there is, read the CTB */
	if( envelopeInfoPtr->iCryptContext != CRYPT_ERROR )
		{
		/* Because we can't tell how much we have to decrypt until we've
		   decrypted the first byte, but we can't stop halfway through a
		   header, we assume a worst-case scenario of needing 5 bytes for the
		   header */
		if( bytesLeft < 5 )
			return( CRYPT_ERROR_UNDERFLOW );
		ctb = sgetc( stream );
		}
	else
		{
		/* Peek at the ctb and figure out whether we've got enough data left
		   to read the header */
		ctb = sgetc( stream );
		if( bytesLeft < ( ctb & 3 ) + 1 )
			{
			sungetc( stream );
			return( CRYPT_ERROR_UNDERFLOW );
			}
		}

	/* If the data is encrypted, decrypt the CTB and length */
	if( envelopeInfoPtr->iCryptContext != CRYPT_ERROR )
		{
		krnlSendMessage( envelopeInfoPtr->iCryptContext, 
						 RESOURCE_IMESSAGE_CTX_DECRYPT, &ctb, 1 );
		if( ( ctb & 3 ) != 3 )
			krnlSendMessage( envelopeInfoPtr->iCryptContext, 
							 RESOURCE_IMESSAGE_CTX_DECRYPT, 
							 stream->buffer + stream->bufPos, ctb & 3 );
		}

	/* Now that the header is present as plaintext, parse it */
	*length = pgpGetLength( stream, ctb );

	return( ctb & ~3 );
	}

/* Make sure there's enough data available to continue and decrypt it so we
   can process it if necessary */

static int checkDecryptData( STREAM *stream, ENVELOPE_INFO *envelopeInfoPtr,
							 const int length )
	{
	/* Make sure there's enough data present to continue */
	if( envelopeInfoPtr->bufPos - stell( stream ) < length )
		return( CRYPT_ERROR_UNDERFLOW );

	/* Decrypt it if necessary */
	if( envelopeInfoPtr->iCryptContext != CRYPT_ERROR )
		krnlSendMessage( envelopeInfoPtr->iCryptContext, 
						 RESOURCE_IMESSAGE_CTX_DECRYPT, 
						 stream->buffer + stream->bufPos, length );

	return( CRYPT_OK );
	}

/* Add information about an object to an envelopes content information list */

static int addContentListItem( STREAM *stream,
							   ENVELOPE_INFO *envelopeInfoPtr,
							   const int ctb )
	{
	CONTENT_LIST *contentListItem;
	void *object;
	int length;

	/* Find the size of the object, allocate a buffer for it, and copy it
	   across.  The session key object is detected by the abscence of any
	   other keying object rather than by finding a concrete object type, so
	   if we are passed a null stream we add a session key pseudo-object */
	if( stream != NULL )
		{
		length = ( int ) pgpGetLength( stream, ctb );
		if( !length || length > 2048 )
			return( CRYPT_ERROR_BADDATA );
		if( ( object = malloc( length ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		sread( stream, object, length );
		}

	/* Allocate memory for the new content list item */
	if( ( contentListItem = malloc( sizeof( CONTENT_LIST ) ) ) == NULL )
		{
		if( stream != NULL )
			free( object );
		return( CRYPT_ERROR_MEMORY );
		}
	memset( contentListItem, 0, sizeof( CONTENT_LIST ) );

	/* If it's a session key pseudo-object, the only thing we can set is the
	   required resource since everything else must be supplied by the
	   caller */
	if( stream == NULL )
		contentListItem->envInfo = CRYPT_ENVINFO_SESSIONKEY;
	else
		{
		/* Copy information on the item across */
		contentListItem->object = object;
		contentListItem->objectSize = length;
		}

	/* Link it into the list */
	if( envelopeInfoPtr->contentList == NULL )
		envelopeInfoPtr->contentList = contentListItem;
	else
		{
		CONTENT_LIST *contentListPtr = envelopeInfoPtr->contentList;

		/* Find the end of the list and add the new item */
		while( contentListPtr->next != NULL )
			contentListPtr = contentListPtr->next;
		contentListPtr->next = contentListItem;
		}

	return( CRYPT_OK );
	}

/* Load a PGP-style IV into a context */

static int loadPGPIV( const CRYPT_CONTEXT iCryptContext, BYTE *iv )
	{
	RESOURCE_DATA msgData;
	BYTE ivBuffer[ PGP_IDEA_IVSIZE ];

	/* Process the IV.  PGP uses a bizarre way of handling IV's which resyncs
	   the data on some boundaries, and doesn't actually use an IV but
	   instead prefixes the data with 8 bytes of random information followed
	   by two bytes of key check after which there's a resync boundary which
	   requires reloading the IV.  An exception is the encrypted private key,
	   which does use an IV (although this can also be regarded as an 8-byte
	   prefix), however there's no key check or resync.  Ick.

	   Because of the strange IV handling requirements we can't just load an
	   IV from the first bytes because we need to actually decrypt the data 
	   so we can compare the last two bytes with the end of the decrypted 
	   IV+check block.  In addition we need to remember the original 
	   ciphertext so we can reload the IV from the end of the IV+check bytes */
	memset( ivBuffer, 0, PGP_IDEA_IVSIZE );
	setResourceData( &msgData, ivBuffer, PGP_IDEA_IVSIZE );
	krnlSendMessage( iCryptContext, RESOURCE_IMESSAGE_SETATTRIBUTE, 
					 &msgData, CRYPT_CTXINFO_IV );
	memcpy( ivBuffer, iv + 2, PGP_IDEA_IVSIZE );
	krnlSendMessage( iCryptContext, RESOURCE_IMESSAGE_CTX_DECRYPT, iv, 
					 PGP_IDEA_IVSIZE + 2 );
	if( ( iv[ 6 ] != iv[ 8 ] ) || ( iv[ 7 ] != iv[ 9 ] ) )
		return( CRYPT_ERROR_WRONGKEY );
	return( krnlSendMessage( iCryptContext, RESOURCE_IMESSAGE_SETATTRIBUTE, 
							 &msgData, CRYPT_CTXINFO_IV ) );
	}

/* Process the non-data portions of a PGP message.  This is a complex event-
   driven state machine, but instead of reading along a (hypothetical
   Turing-machine) tape, someone has taken the tape and cut it into bits and
   keeps feeding them to us and saying "See what you can do with this" (and
   occasionally "Where's the bloody spoons?").  The following code implements
   this state machine:

				initial				_NONE		(possibly also NONE->COPR)
	   _		/  |  \
	 /	 \	  /    |    \
	|	PKC key    |     |			_PKC
	|	 info      |     |
	 \__ /	  \    |     |
				encr.    |			_ENCR		(possibly also ENCR->SIGNED)
				data     |						(possibly also ENCR->PLAIN)
				   |     |
				copr.    |			_COPR
				data    /
			  /   |  /
			 |	signed				_SIGNED
			 |	 data
			  \	   |
				plaintext			_PLAINTEXT

   Since PGP uses sequential discrete packets rather than the nested objects
   encountered in the ASN.1-encoded data format, the parsing code is made
   somewhat simpler because (for example) the PKC info is just an unconnected
   sequence of packets rather than a SEQUENCE or SET OF as for cryptlib and
   PKCS #7 */

int pgpProcessPreamble( ENVELOPE_INFO *envelopeInfoPtr )
	{
	PGP_DEENV_STATE state = envelopeInfoPtr->pgpDeenvState;
	STREAM stream;
	int ctb, length, streamPos = 0, status = CRYPT_OK;
	long packetLength;

	/* If we've finished processing the start of the message, header, don't
	   do anything */
	if( state == PGP_DEENVSTATE_DONE )
		return( CRYPT_OK );

	sMemConnect( &stream, envelopeInfoPtr->buffer, envelopeInfoPtr->bufPos );

	/* Keep consuming information until we run out of input or reach the
	   plaintext data packet */
	while( TRUE )
		{
		/* Read the initial CTB and figure out what we've got */
		if( state == PGP_DEENVSTATE_NONE )
			{
			ctb = getPacketInfo( &stream, envelopeInfoPtr, &packetLength );

			/* Remember where we are and move on to the next state */
			streamPos = stell( &stream );
			switch( ctb )
				{
				case PGP_CTB_PKE:
					state = PGP_DEENVSTATE_PKC;
					break;

				case PGP_CTB_ENCR:
					state = PGP_DEENVSTATE_ENCR;
					break;

				case PGP_CTB_SIGNATURE:
					state = PGP_DEENVSTATE_SIGNED;
					break;

				default:
					status = CRYPT_ERROR_BADDATA;
				}

			/* If it's an unknown packet type, exit */
			if( status == CRYPT_ERROR_BADDATA )
				break;
			}

		/* Read and remember a key exchange object from a PKC-encrypted key
		   record */
		if( state == PGP_DEENVSTATE_PKC )
			{
			/* Add the object to the content information list */
			status = addContentListItem( &stream, envelopeInfoPtr,
/*!!!!!!!*/ PGP_CTB_PKE );
			if( cryptStatusError( status ) )
				break;

			/* Remember where we are and move on to the next state */
			ctb = getPacketInfo( &stream, envelopeInfoPtr, &packetLength );
			streamPos = stell( &stream );
/* !!!!! What if we run out of input data? !!!!!! */
			if( ctb == PGP_CTB_ENCR )
				state = PGP_DEENVSTATE_ENCR;
			else
				if( ctb != PGP_CTB_PKE )
					{
					status = CRYPT_ERROR_BADDATA;
					break;
					}
			}

		/* Process the start of an encrypted data packet */
		if( state == PGP_DEENVSTATE_ENCR )
			{
			BYTE iv[ PGP_IDEA_IVSIZE + 2 ];
			ACTION_LIST *actionListPtr;

			/* If there aren't any non-session-key keying resource objects
			   present, we can't go any further until we get a session key */
			actionListPtr = findAction( envelopeInfoPtr->actionList, ACTION_CRYPT );
			if( actionListPtr == NULL )
				{
				/* There's no session key object present, add a pseudo-object
				   which takes the place of the session key object to the
				   content list.  Since all the information on the session key
				   is supplied externally, we can't tell anything about it
				   other than that it's required, which is flagged by the
				   pseudo-object (for 2.x we know it'll have to be IDEA, but
				   for 5.x it could be 3DES or CAST as well) */
				if( envelopeInfoPtr->contentList == NULL )
					{
					status = addContentListItem( NULL, envelopeInfoPtr, 0 );
					if( cryptStatusError( status ) )
						break;
					}

				/* We can't continue until we're given some sort of keying
				   resource */
				status = CRYPT_ENVELOPE_RESOURCE;
				break;
				}

			/* Read and process PGP's peculiar two-stage IV */
			if( sread( &stream, iv, PGP_IDEA_IVSIZE + 2 ) != CRYPT_OK )
				{
				status = CRYPT_ERROR_UNDERFLOW;
				break;
				}
			status = loadPGPIV( actionListPtr->iCryptHandle, iv );
			if( cryptStatusError( status ) )
				break;
			envelopeInfoPtr->iCryptContext = actionListPtr->iCryptHandle;

			/* Remember where we are and move on to the next state */
			ctb = getPacketInfo( &stream, envelopeInfoPtr, &packetLength );
			streamPos = stell( &stream );
/* !!!!! What if we run out of input data? !!!!!! */
			if( ctb == PGP_CTB_COPR )
				state = PGP_DEENVSTATE_COPR;
			else
				{
				status = CRYPT_ERROR_BADDATA;
				break;
				}
			}


		/* Process the start of the compressed data packet */
		if( state == PGP_DEENVSTATE_COPR )
			{
			/* Make sure we can process the 1-byte compression info */
			status = checkDecryptData( &stream, envelopeInfoPtr, 1 );
			if( cryptStatusOK( status ) && \
				sgetc( &stream ) != PGP_ALGO_ZIP )
				status = CRYPT_ERROR_BADDATA;
			if( cryptStatusError( status ) )
				break;

			/* Remember where we are and move on to the next state */
			streamPos = stell( &stream );
/* !!!!!! What if next state isn't 'done'? !!!!!! */
			state = PGP_DEENVSTATE_DONE;
			}

		/* If we've reached the end of the header, exit */
		if( state == PGP_DEENVSTATE_DONE )
			break;
		}
	envelopeInfoPtr->pgpDeenvState = state;

	/* Consume the input we've processed so far by moving everything past the
	   current position down to the start of the memory buffer */
	length = envelopeInfoPtr->bufPos - streamPos;
	if( length && streamPos )
		memmove( envelopeInfoPtr->buffer, envelopeInfoPtr->buffer + streamPos,
				 length );
	envelopeInfoPtr->bufPos = length;

	/* If all went OK but we're still not out of the header information,
	   return an underflow error */
	if( cryptStatusOK( status ) && state != PGP_DEENVSTATE_DONE )
		status = CRYPT_ERROR_UNDERFLOW;

	/* Clean up */
	sMemDisconnect( &stream );
	return( status );
	}

int pgpProcessPostamble( ENVELOPE_INFO *envelopeInfoPtr )
	{
	UNUSED( envelopeInfoPtr );

	return( CRYPT_OK );
	}
