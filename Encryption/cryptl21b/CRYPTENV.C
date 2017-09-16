/****************************************************************************
*																			*
*						cryptlib Enveloping Routines						*
*					  Copyright Peter Gutmann 1996-1999						*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "asn1oid.h"
  #include "envelope.h"
#else
  #include "keymgmt/asn1oid.h"
  #include "envelope/envelope.h"
#endif /* Compiler-specific includes */

/* The minimum and default sizes for envelopes and for the auxiliary buffer
   used as a staging area for assembling information.  Under DOS and Win16
   they're smaller because of memory and int size limitations */

#define MIN_ENVELOPE_SIZE			8192
#if defined( __MSDOS16__ )
  #define DEFAULT_ENVELOPE_SIZE		8192
#elif defined( __WIN16__ )
  #define DEFAULT_ENVELOPE_SIZE		16384
#else
  #define DEFAULT_ENVELOPE_SIZE		32768
#endif /* OS-specific envelope size defines */
#define DEFAULT_AUXBUFFER_SIZE		8192

/* Prototypes for functions in envelope/resource.c */

void deleteActionList( ACTION_LIST *actionListPtr );
void deleteContentList( CONTENT_LIST *contentListPtr );
int addDefaultKeyset( ENVELOPE_INFO *envelopeInfoPtr,
					  const CRYPT_ENVINFO_TYPE keysetFunction );

/****************************************************************************
*																			*
*							General Envelope API Functions					*
*																			*
****************************************************************************/

/* Handle a message sent to an envelope */

static int envelopeMessageFunction( const CRYPT_ENVELOPE cryptEnvelope,
									const RESOURCE_MESSAGE_TYPE message,
									void *messageDataPtr,
									const int messageValue,
									const int errorCode )
	{
	ENVELOPE_INFO *envelopeInfoPtr;
	int status = errorCode;

	UNUSED( messageDataPtr );
	if( messageValue );		/* Get rid of compiler warning */
	getCheckInternalResource( cryptEnvelope, envelopeInfoPtr, RESOURCE_TYPE_ENVELOPE );

	/* Process destroy object messages */
	if( message == RESOURCE_MESSAGE_DESTROY )
		{
		/* Delete the action and content lists */
		deleteActionList( envelopeInfoPtr->preActionList );
		deleteActionList( envelopeInfoPtr->actionList );
		deleteActionList( envelopeInfoPtr->postActionList );
		deleteContentList( envelopeInfoPtr->contentList );

		/* Delete the zlib compression state information if necessary */
		if( envelopeInfoPtr->zStreamInited )
			deflateEnd( &envelopeInfoPtr->zStream );

		/* Handle the keyset cleanup by calling the internal keyset close
		   function */
		if( envelopeInfoPtr->iSigCheckKeyset != CRYPT_ERROR )
			iCryptDestroyObject( envelopeInfoPtr->iSigCheckKeyset );
		if( envelopeInfoPtr->iEncryptionKeyset != CRYPT_ERROR )
			iCryptDestroyObject( envelopeInfoPtr->iEncryptionKeyset );
		if( envelopeInfoPtr->iDecryptionKeyset != CRYPT_ERROR )
			iCryptDestroyObject( envelopeInfoPtr->iDecryptionKeyset );

		/* Clean up other envelope objects */
		if( envelopeInfoPtr->iCertChain != CRYPT_ERROR )
			iCryptDestroyObject( envelopeInfoPtr->iCertChain );

		/* Clear and free the buffers if necessary */
		if( envelopeInfoPtr->buffer != NULL )
			{
			zeroise( envelopeInfoPtr->buffer, envelopeInfoPtr->bufSize );
			free( envelopeInfoPtr->buffer );
			}
		if( envelopeInfoPtr->auxBuffer != NULL )
			{
			zeroise( envelopeInfoPtr->auxBuffer, envelopeInfoPtr->auxBufSize );
			free( envelopeInfoPtr->auxBuffer );
			}

		/* We've finished deleting the objects data, mark it as partially
		   destroyed, which ensures that any further attempts to access it
		   fail.  This avoids a race condition where other threads may try
		   to use the partially-destroyed object after we unlock it but
		   before we finish destroying it, note that we set the urgent flag
		   to ensure that the status change is processed immediately rather
		   than being queued until after the current (destroy) message has
		   been processed */
		status = CRYPT_SIGNALLED;
		krnlSendMessage( cryptEnvelope,
						 RESOURCE_MESSAGE_SETPROPERTY | RESOURCE_MESSAGE_URGENT,
						 &status, RESOURCE_MESSAGE_PROPERTY_STATUS, 0 );

		/* Delete the objects locking variables and the object itself */
		unlockResource( envelopeInfoPtr );
		deleteResourceLock( envelopeInfoPtr );
		zeroise( envelopeInfoPtr, sizeof( ENVELOPE_INFO ) );
		free( envelopeInfoPtr );

		return( CRYPT_OK );
		}

	/* Process the increment/decrement object reference count message */
	if( message == RESOURCE_MESSAGE_INCREFCOUNT )
		{
		/* Increment the objects reference count */
		envelopeInfoPtr->refCount++;

		status = CRYPT_OK;
		}
	if( message == RESOURCE_MESSAGE_DECREFCOUNT )
		{
		/* If we're already at a single reference, destroy the object */
		if( !envelopeInfoPtr->refCount )
			krnlSendNotifier( cryptEnvelope, RESOURCE_IMESSAGE_DESTROY );
		else
			/* Decrement the objects reference count */
			envelopeInfoPtr->refCount--;

		status = CRYPT_OK;
		}

	unlockResourceExit( envelopeInfoPtr, status );
	}

/* Create/destroy an envelope */

static int createEnvelope( CRYPT_ENVELOPE *envelope,
						   const CRYPT_FORMAT_TYPE type,
						   const int bufferSize, const BOOLEAN isDeenvelope )
	{
	int addEnvelopeInfo( ENVELOPE_INFO *envelopeInfoPtr,
						 const CRYPT_ENVINFO_TYPE envInfo, const void *value,
						 const int valueLength );
	int addDeenvelopeInfo( ENVELOPE_INFO *envelopeInfoPtr,
						   const CRYPT_ENVINFO_TYPE envInfo,
						   const void *value, const int valueLength );
	ENVELOPE_INFO *envelopeInfoPtr;
	CRYPT_FORMAT_TYPE envType = type;
	int envBufSize = bufferSize, status;

	/* Perform basic error checking */
	if( checkBadPtrWrite( envelope, sizeof( CRYPT_ENVELOPE ) ) )
		return( CRYPT_BADPARM1 );
	*envelope = CRYPT_ERROR;
	if( envType == CRYPT_USE_DEFAULT )
		envType = CRYPT_FORMAT_CRYPTLIB;
	if( envType <= CRYPT_FORMAT_NONE || envType >= CRYPT_FORMAT_LAST )
		return( CRYPT_BADPARM2 );
	if( envBufSize == CRYPT_USE_DEFAULT )
		envBufSize = DEFAULT_ENVELOPE_SIZE;
	if( envBufSize < MIN_ENVELOPE_SIZE )
		return( CRYPT_BADPARM3 );

	/* Create the envelope object */
	krnlCreateObject( status, envelopeInfoPtr, RESOURCE_TYPE_ENVELOPE,
					  sizeof( ENVELOPE_INFO ), 0, envelopeMessageFunction );
	if( cryptStatusError( status ) )
		return( status );
	*envelope = status;

	/* Allocate the buffer and auxiliary buffer (for enveloping only).
	   Because these can be fairly large and aren't as critical as the data
	   stored in an encryption context, we don't try to pagelock them */
	if( ( envelopeInfoPtr->buffer = malloc( envBufSize ) ) != NULL && \
		( !isDeenvelope &&
		  ( envelopeInfoPtr->auxBuffer = malloc( DEFAULT_AUXBUFFER_SIZE ) ) == NULL ) )
		free( envelopeInfoPtr->buffer );
	if( envelopeInfoPtr->buffer == NULL || \
		( !isDeenvelope && envelopeInfoPtr->auxBuffer == NULL ) )
		{
		unlockResource( envelopeInfoPtr );
		krnlSendNotifier( *envelope, RESOURCE_IMESSAGE_DESTROY );
		return( CRYPT_NOMEM );
		}
	memset( envelopeInfoPtr->buffer, 0, envBufSize );
	envelopeInfoPtr->bufSize = envBufSize;
	if( !isDeenvelope )
		{
		memset( envelopeInfoPtr->auxBuffer, 0, DEFAULT_AUXBUFFER_SIZE );
		envelopeInfoPtr->auxBufSize = DEFAULT_AUXBUFFER_SIZE;
		}
	envelopeInfoPtr->type = envType;

	/* Set up any internal objects to contain invalid handles */
	envelopeInfoPtr->iCryptContext = envelopeInfoPtr->iCertChain = CRYPT_ERROR;
	envelopeInfoPtr->iSigCheckKeyset = envelopeInfoPtr->iEncryptionKeyset = \
		envelopeInfoPtr->iDecryptionKeyset = CRYPT_ERROR;
	envelopeInfoPtr->payloadSize = CRYPT_UNUSED;

	/* Set up the default algorithm information */
	if( !isDeenvelope )
		if( envType == CRYPT_FORMAT_CRYPTLIB )
			{
			/* Remember the current default settings for use with the
			   cryptlib native envelope type.  We force the use of the CBC
			   encryption mode because this is the safest and in general the
			   most efficient encryption mode, especially on 80x86 systems
			   where the entire mode is implemented in assembly language.
			   It's also the safest mode for key exchange actions (unlike CFB
			   and OFB it doesn't allow an attacker to change bits to force a
			   weak algorithm, and is safe to use because the encrypted key
			   is padded to a multiple of 64 bytes to avoid traffic analysis
			   so there are no problems with the block size).  Finally, it's
			   the only mode defined for most of the CMS algorithms */
			envelopeInfoPtr->defaultHash = getOptionNumeric( CRYPT_OPTION_ENCR_HASH );
			envelopeInfoPtr->defaultAlgo = getOptionNumeric( CRYPT_OPTION_ENCR_ALGO );
			envelopeInfoPtr->defaultMode = \
				( envelopeInfoPtr->defaultAlgo == CRYPT_ALGO_RC4 ) ? \
				CRYPT_MODE_STREAM : CRYPT_MODE_CBC;
			}
		else
			if( envType == CRYPT_FORMAT_CMS || envType == CRYPT_FORMAT_SMIME )
				{
				/* Set the CMS default algorithms */
				envelopeInfoPtr->defaultHash = CRYPT_ALGO_SHA;
				envelopeInfoPtr->defaultAlgo = CRYPT_ALGO_3DES;
				envelopeInfoPtr->defaultMode = CRYPT_MODE_CBC;
				}
			else
				{
				/* Set the PGP default algorithms */
				envelopeInfoPtr->defaultHash = CRYPT_ALGO_MD5;
				envelopeInfoPtr->defaultAlgo = CRYPT_ALGO_IDEA;
				envelopeInfoPtr->defaultMode = CRYPT_MODE_CFB;
				}

	/* Set up the processing state information */
	envelopeInfoPtr->state = STATE_PREDATA;
	envelopeInfoPtr->envState = ENVSTATE_NONE;
	envelopeInfoPtr->deenvState = DEENVSTATE_NONE;
	envelopeInfoPtr->pgpEnvState = PGP_ENVSTATE_NONE;
	envelopeInfoPtr->pgpDeenvState = PGP_DEENVSTATE_NONE;
	if( isDeenvelope )
		envelopeInfoPtr->isDeenvelope = TRUE;

	/* Set up the enveloping/deenveloping function pointers */
	if( envType == CRYPT_FORMAT_CRYPTLIB || envType == CRYPT_FORMAT_CMS || \
		envType == CRYPT_FORMAT_SMIME )
		{
		int emitPreamble( ENVELOPE_INFO *envelopeInfoPtr );
		int emitPostamble( ENVELOPE_INFO *envelopeInfoPtr );
		int processPreamble( ENVELOPE_INFO *envelopeInfoPtr );
		int processPostamble( ENVELOPE_INFO *envelopeInfoPtr );
		int processExtraData( ENVELOPE_INFO *envelopeInfoPtr,
							  const void *buffer, const int length );
		int copyToEnvelope( ENVELOPE_INFO *envelopeInfoPtr,
							const BYTE *buffer, const int length );
		int copyFromEnvelope( ENVELOPE_INFO *envelopeInfoPtr, BYTE *buffer,
							  int length );
		int copyToDeenvelope( ENVELOPE_INFO *envelopeInfoPtr,
							  const BYTE *buffer, int length );
		int copyFromDeenvelope( ENVELOPE_INFO *envelopeInfoPtr, BYTE *buffer,
								int length );

		envelopeInfoPtr->emitPreamble = emitPreamble;
		envelopeInfoPtr->emitPostamble = emitPostamble;
		envelopeInfoPtr->processPreamble = processPreamble;
		envelopeInfoPtr->processPostamble = processPostamble;
		envelopeInfoPtr->processExtraData = processExtraData;
		envelopeInfoPtr->copyToEnvelope = copyToEnvelope;
		envelopeInfoPtr->copyFromEnvelope = copyFromEnvelope;
		envelopeInfoPtr->copyToDeenvelope = copyToDeenvelope;
		envelopeInfoPtr->copyFromDeenvelope = copyFromDeenvelope;
		}
	else
		{
		int pgpProcessPreamble( ENVELOPE_INFO *envelopeInfoPtr );
		int pgpProcessPostamble( ENVELOPE_INFO *envelopeInfoPtr );

		envelopeInfoPtr->processPreamble = pgpProcessPreamble;
		envelopeInfoPtr->processPostamble = pgpProcessPostamble;
		}
	envelopeInfoPtr->addInfo = ( isDeenvelope ) ? addDeenvelopeInfo : \
												  addEnvelopeInfo;

	unlockResourceExit( envelopeInfoPtr, CRYPT_OK );
	}

CRET cryptCreateEnvelopeEx( CRYPT_ENVELOPE CPTR envelope,
							const CRYPT_FORMAT_TYPE envelopeType,
							const int bufferSize )
	{
	return( createEnvelope( envelope, envelopeType, bufferSize, FALSE ) );
	}

CRET cryptCreateEnvelope( CRYPT_ENVELOPE CPTR envelope )
	{
	return( createEnvelope( envelope, CRYPT_USE_DEFAULT,
							DEFAULT_ENVELOPE_SIZE, FALSE ) );
	}

CRET cryptCreateDeenvelopeEx( CRYPT_ENVELOPE CPTR envelope,
							  const int bufferSize )
	{
	return( createEnvelope( envelope, CRYPT_USE_DEFAULT, bufferSize, TRUE ) );
	}

CRET cryptCreateDeenvelope( CRYPT_ENVELOPE CPTR envelope )
	{
	return( createEnvelope( envelope, CRYPT_FORMAT_CRYPTLIB,
							DEFAULT_ENVELOPE_SIZE, TRUE ) );
	}

CRET cryptDestroyEnvelope( const CRYPT_ENVELOPE envelope )
	{
	ENVELOPE_INFO *envelopeInfoPtr;
	const int isInternal = TRUE;
	int envelopeStatus = CRYPT_OK, status;

	/* Envelope deletion has an extra complication in that instead of simply
	   decrementing its reference count like other objects, we check to see
	   whether the envelope still needs operations performed on it to resolve
	   the state of the data within it (for example if the caller pushes data
	   but doesn't flush it, there will be a few bytes left which can't be
	   popped).  We can't perform this check in the delete function because
	   this may be called from other sections of the code, so we have to do
	   it here.

	   For enveloping, destroying the envelope while it's in any state other
	   than STATE_PREDATA or STATE_FINISHED is regarded as an error.

	   For de-enveloping we have to be more careful, since deenveloping
	   information required to resolve the envelope state could be
	   unavailable, so we shouldn't return an error if something like a
	   signature check remains to be done.  What we therefore do is check to
	   see whether we've processed any data yet and report an error if
	   there's any data left in the envelope or if we destroy it in the
	   middle of processing data */
	getCheckResource( envelope, envelopeInfoPtr, RESOURCE_TYPE_ENVELOPE,
					  CRYPT_BADPARM1 );
	if( envelopeInfoPtr->isDeenvelope )
		{
		/* If we've got to the point of processing data in the envelope and
		   there's either more to come or some left to pop, we shouldn't be
		   destroying it yet */
		if( envelopeInfoPtr->state == STATE_DATA || \
			( ( envelopeInfoPtr->state == STATE_POSTDATA || \
				envelopeInfoPtr->state == STATE_FINISHED ) && \
			  envelopeInfoPtr->dataLeft ) )
			envelopeStatus = CRYPT_INCOMPLETE;
		}
	else
		/* If we're in the middle of processing data, we shouldn't be
		   destroying the envelope yet */
		if( envelopeInfoPtr->state != STATE_PREDATA && \
			envelopeInfoPtr->state != STATE_FINISHED )
			envelopeStatus = CRYPT_INCOMPLETE;

	/* Make the envelope internal, which marks it as invalid for any external
	   access (to the caller, it looks like it's been destroyed).  After
	   this, decrement its reference count (which may or may not actually
	   destroy it).  Before we do this, we have to unlock the envelope, since
	   decrementing the reference count may destroy the object */
	krnlSendMessage( envelope, RESOURCE_MESSAGE_SETPROPERTY, ( int * ) &isInternal,
					 RESOURCE_MESSAGE_PROPERTY_INTERNAL, 0 );
	unlockResource( envelopeInfoPtr );
	status = krnlSendNotifier( envelope, RESOURCE_IMESSAGE_DECREFCOUNT );

	return( cryptStatusError( envelopeStatus ) ? envelopeStatus : status );
	}

/* Push data into an envelope */

CRET cryptPushData( const CRYPT_ENVELOPE envelope, const void CPTR buffer,
					const int length, int CPTR bytesCopied )
	{
	ENVELOPE_INFO *envelopeInfoPtr;
	int status;

	/* Perform basic error checking */
	getCheckResource( envelope, envelopeInfoPtr, RESOURCE_TYPE_ENVELOPE,
					  CRYPT_BADPARM1 );
	if( !length )
		{
		/* If it's a flush, make sure we're in a state where this is valid.
		   We can only perform a flush on enveloping if we're in the data or
		   postdata state, on deenveloping a flush can happen at any time */
		if( envelopeInfoPtr->state == STATE_FINISHED )
			unlockResourceExit( envelopeInfoPtr, CRYPT_OK );
		if( !envelopeInfoPtr->isDeenvelope && \
			( envelopeInfoPtr->state != STATE_DATA && \
			  envelopeInfoPtr->state != STATE_POSTDATA ) )
			unlockResourceExit( envelopeInfoPtr, CRYPT_INCOMPLETE );
		}
	else
		{
		if( checkBadPtrRead( buffer, length ) )
			unlockResourceExit( envelopeInfoPtr, CRYPT_BADPARM2 );
		if( length < 0 )
			unlockResourceExit( envelopeInfoPtr, CRYPT_BADPARM3 );
		if( checkBadPtrWrite( bytesCopied, sizeof( int ) ) )
			unlockResourceExit( envelopeInfoPtr, CRYPT_BADPARM4 );
		*bytesCopied = 0;
		}
	if( envelopeInfoPtr->state == STATE_FINISHED )
		unlockResourceExit( envelopeInfoPtr, CRYPT_COMPLETE );
	if( envelopeInfoPtr->errorState != CRYPT_OK )
		unlockResourceExit( envelopeInfoPtr, envelopeInfoPtr->errorState );

	/* If we're de-enveloping data, call the dedicated code to do this */
	if( envelopeInfoPtr->isDeenvelope )
		{
		BYTE *bufPtr = ( BYTE * ) buffer;
		int bytesIn = length;

		/* If we haven't started processing data yet, handle the initial data
		   specially */
		if( envelopeInfoPtr->state == STATE_PREDATA )
			{
			/* Since we're processing out-of-band information, just copy it in
			   directly */
			if( bytesIn )
				{
				int bytesToCopy = min( envelopeInfoPtr->bufSize - envelopeInfoPtr->bufPos,
									   bytesIn );
				if( bytesToCopy )
					{
					memcpy( envelopeInfoPtr->buffer + envelopeInfoPtr->bufPos,
							bufPtr, bytesToCopy );
					envelopeInfoPtr->bufPos += bytesToCopy;
					bytesIn -= bytesToCopy;
					*bytesCopied = bytesToCopy;
					bufPtr += bytesToCopy;
					}
				}

			/* Process the preamble */
			status = envelopeInfoPtr->processPreamble( envelopeInfoPtr );
			if( cryptStatusError( status ) )
				{
				if( status != CRYPT_UNDERFLOW )	/* Can recover from this */
					envelopeInfoPtr->errorState = status;
				unlockResourceExit( envelopeInfoPtr, status );
				}

			/* Move on to the data-processing state */
			envelopeInfoPtr->state = STATE_DATA;
			}

		/* If we're in the main data processing state, add the data and
		   perform any necessary actions on it */
		if( envelopeInfoPtr->state == STATE_DATA )
			{
			/* If there's data to be copied, copy it into the envelope (if
			   we've come from the predata state, we may have zero bytes to
			   copy if everything was consumed by the preamble processing,
			   or there may be room to copy more in if the preamble
			   processing consumed some of what was present) */
			if( bytesIn )
				{
				/* Copy the data to the envelope */
				*bytesCopied += envelopeInfoPtr->copyToDeenvelope( envelopeInfoPtr,
														bufPtr, bytesIn );
				status = cryptStatusError( *bytesCopied ) ? \
						 *bytesCopied : CRYPT_OK;
				if( cryptStatusError( status ) )
					{
					if( status != CRYPT_UNDERFLOW )	/* Can recover from this */
						envelopeInfoPtr->errorState = status;
					unlockResourceExit( envelopeInfoPtr, status );
					}
				bytesIn -= *bytesCopied;
				bufPtr += *bytesCopied;
				}

			/* If we've reached the end of the payload (either by having seen
			   the EOC octets with the indefinite encoding or by having
			   reached the end of the single segment with the definite
			   encoding), move on to the postdata state */
			if( envelopeInfoPtr->endOfContents || \
				( envelopeInfoPtr->payloadSize != CRYPT_UNUSED && \
				  !envelopeInfoPtr->segmentSize ) )
				{
				envelopeInfoPtr->state = STATE_POSTDATA;
				envelopeInfoPtr->deenvState = DEENVSTATE_NONE;
				}
			}

		/* If we're past the main data-processing state, process the
		   postamble */
		if( envelopeInfoPtr->state == STATE_POSTDATA )
			{
			/* Since we're processing trailer information, just copy it in
			   directly */
			if( bytesIn )
				{
#if 0
				int bytesToCopy = min( envelopeInfoPtr->bufSize - envelopeInfoPtr->bufPos,
									   bytesIn );
				if( bytesToCopy )
					{
					memcpy( envelopeInfoPtr->buffer + envelopeInfoPtr->bufPos,
							bufPtr, bytesToCopy );
					envelopeInfoPtr->bufPos += bytesToCopy;
					bytesIn -= bytesToCopy;
					*bytesCopied += bytesToCopy;
					}
#else
				const int bytesToCopy = \
					min( envelopeInfoPtr->bufSize - envelopeInfoPtr->dataLeft,
						 bytesIn );
				if( bytesToCopy )
					{
					memcpy( envelopeInfoPtr->buffer + envelopeInfoPtr->dataLeft,
							bufPtr, bytesToCopy );
					envelopeInfoPtr->bufPos = envelopeInfoPtr->dataLeft + \
											  bytesToCopy;
					bytesIn -= bytesToCopy;
					*bytesCopied += bytesToCopy;
					}
#endif /* 0 */
				}

			/* Process the postamble */
			status = envelopeInfoPtr->processPostamble( envelopeInfoPtr );
			if( cryptStatusError( status ) )
				{
				if( status != CRYPT_UNDERFLOW )	/* Can recover from this */
					envelopeInfoPtr->errorState = status;
				unlockResourceExit( envelopeInfoPtr, status );
				}

			/* If the routine returns OK_SPECIAL then it's processed enough
			   of the postamble for the caller to continue, but there's more
			   to go so we shouldn't change the overall state yet */
			if( status == OK_SPECIAL )
				status = CRYPT_OK;
			else
				/* We've processed all data, we're done unless it's a
				   detached sig with the data supplied out-of-band */
				envelopeInfoPtr->state = ( envelopeInfoPtr->detachedSig ) ? \
										 STATE_EXTRADATA : STATE_FINISHED;

			/* At this point we always exit since the out-of-band data has to
			   be processed in a separate push */
			unlockResourceExit( envelopeInfoPtr, status );
			}

		/* If there's extra out-of-band data present, process it separately */
		if( envelopeInfoPtr->state == STATE_EXTRADATA )
			{
			/* If this is a flush, it could be a flush for the actual data or
			   a flush for the out-of-band data.  To distinguish between the
			   two, we use the deenveloping state, which will have been set to
			   DEENVSTATE_DONE when processing of the main data was completed.
			   The first time we pass this point, we reset the state to
			   DEENVSTATE_NONE.  If it's a flush, it was a flush for the main
			   data and we exit.  After this, the flush is for the out-of-band
			   data */
			if( envelopeInfoPtr->deenvState == DEENVSTATE_DONE )
				{
				envelopeInfoPtr->deenvState = DEENVSTATE_NONE;
				if( !length )
					unlockResourceExit( envelopeInfoPtr, CRYPT_OK );
				}

			/* This is just raw data so we feed it directly to the processing
			   function */
			status = envelopeInfoPtr->processExtraData( envelopeInfoPtr,
														buffer, length );
			if( cryptStatusOK( status ) )
				{
				if( bytesCopied != NULL )
					*bytesCopied = length;
				if( !length )
					envelopeInfoPtr->state = STATE_FINISHED;
				}
			}

		unlockResourceExit( envelopeInfoPtr, status );
		}

	/* PGP enveloping isn't supported yet */
	if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP )
		unlockResourceExit( envelopeInfoPtr, CRYPT_NOPERM );

	/* If we haven't started processing data yet, handle the initial data
	   specially */
	if( envelopeInfoPtr->state == STATE_PREDATA )
		{
		/* Emit the header information into the envelope */
		status = envelopeInfoPtr->emitPreamble( envelopeInfoPtr );
		if( cryptStatusError( status ) )
			{
			if( status != CRYPT_OVERFLOW )
				envelopeInfoPtr->errorState = status;
			unlockResourceExit( envelopeInfoPtr, status );
			}
		envelopeInfoPtr->state = STATE_DATA;
		}

	/* If we're in the main data processing state, add the data and perform
	   any necessary actions on it */
	if( envelopeInfoPtr->state == STATE_DATA )
		{
		/* If this was a flush, move on to the postdata state */
		if( !length )
			{
			envelopeInfoPtr->state = STATE_POSTDATA;
			envelopeInfoPtr->envState = ENVSTATE_NONE;
			}
		else
			{
			/* Copy the data to the envelope buffer, taking blocking
			   requirements into account */
			status = envelopeInfoPtr->copyToEnvelope( envelopeInfoPtr,
													  buffer, length );
			if( bytesCopied != NULL )
				*bytesCopied = status;
			if( cryptStatusError( status ) )
				{
				envelopeInfoPtr->errorState = status;
				unlockResourceExit( envelopeInfoPtr, status );
				}
			}
		}

	/* If we're past the main data-processing state, emit the postamble */
	if( envelopeInfoPtr->state == STATE_POSTDATA )
		{
		status = envelopeInfoPtr->emitPostamble( envelopeInfoPtr );
		if( cryptStatusError( status ) )
			{
			if( status != CRYPT_NORANDOM && status != CRYPT_OVERFLOW )
				envelopeInfoPtr->errorState = status;
			unlockResourceExit( envelopeInfoPtr, status );
			}
		envelopeInfoPtr->state = STATE_FINISHED;
		}

	unlockResourceExit( envelopeInfoPtr, CRYPT_OK );
	}

/* Pop data from an envelope */

CRET cryptPopData( const CRYPT_ENVELOPE envelope, void CPTR buffer,
				   const int length, int CPTR bytesCopied )
	{
	ENVELOPE_INFO *envelopeInfoPtr;
	int bytesOut;

	/* Perform basic error checking */
	getCheckResource( envelope, envelopeInfoPtr, RESOURCE_TYPE_ENVELOPE,
					  CRYPT_BADPARM1 );
	if( checkBadPtrWrite( buffer, length ) )
		unlockResourceExit( envelopeInfoPtr, CRYPT_BADPARM2 );
	if( length <= 0 )
		unlockResourceExit( envelopeInfoPtr, CRYPT_BADPARM3 );
	memset( buffer, 0, min( length, 16 ) );
	if( checkBadPtrWrite( bytesCopied, sizeof( int ) ) )
		unlockResourceExit( envelopeInfoPtr, CRYPT_BADPARM4 );
	*bytesCopied = 0;
	if( envelopeInfoPtr->errorState != CRYPT_OK )
		unlockResourceExit( envelopeInfoPtr, envelopeInfoPtr->errorState );

	if( envelopeInfoPtr->isDeenvelope )
		{
		/* If we haven't reached the data yet, force a push to try and get to
		   the data.  We can end up with this condition if the caller pushes
		   in deenveloping information and then immediately tries to pop data
		   without an intervening push to resolve the state of the data in
		   the envelope */
		if( envelopeInfoPtr->state == STATE_PREDATA )
			{
			int status;

			status = cryptPushData( envelope, NULL, 0, NULL );
			if( cryptStatusError( status ) )
				unlockResourceExit( envelopeInfoPtr, status );

			/* If we still haven't got anywhere, return an underflow error */
			if( envelopeInfoPtr->state == STATE_PREDATA )
				unlockResourceExit( envelopeInfoPtr, CRYPT_UNDERFLOW );
			}

		/* Copy the data from the envelope to the output */
		bytesOut = envelopeInfoPtr->copyFromDeenvelope( envelopeInfoPtr,
														buffer, length );
		if( cryptStatusError( bytesOut ) )
			{
			envelopeInfoPtr->errorState = bytesOut;
			unlockResourceExit( envelopeInfoPtr, bytesOut );
			}
		*bytesCopied = bytesOut;
		}
	else
		{
		/* Copy the data from the envelope to the output */
		bytesOut = envelopeInfoPtr->copyFromEnvelope( envelopeInfoPtr,
													  buffer, length );
		if( cryptStatusError( bytesOut ) )
			{
			envelopeInfoPtr->errorState = bytesOut;
			unlockResourceExit( envelopeInfoPtr, bytesOut );
			}
		*bytesCopied = bytesOut;
		}

	unlockResourceExit( envelopeInfoPtr, CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Enveloping Information Query Functions				*
*																			*
****************************************************************************/

/* Get enveloping/deenvloping information from an envelope */

CRET cryptGetEnvComponentNumeric( const CRYPT_ENVELOPE envelope,
								  const CRYPT_ENVINFO_TYPE envInfoType,
								  int CPTR envInfo )
	{
	ENVELOPE_INFO *envelopeInfoPtr;
	int status = CRYPT_OK;

	/* Perform basic error checking */
	getCheckResource( envelope, envelopeInfoPtr, RESOURCE_TYPE_ENVELOPE,
					  CRYPT_BADPARM1 );
	if( envInfoType == CRYPT_ENVINFO_CURRENT_COMPONENT || \
		envInfoType == CRYPT_ENVINFO_SIGNATURE_RESULT || \
		envInfoType == CRYPT_ENVINFO_SIGNATURE || \
		envInfoType == CRYPT_ENVINFO_SIGNATURE_EXTRADATA )
		{
		if( !envelopeInfoPtr->isDeenvelope )
			unlockResourceExit( envelopeInfoPtr, CRYPT_BADPARM1 );

		/* The following check isn't strictly necessary since we can get some
		   information as soon as it's available, but it leads to less
		   confusion (for example without this check we can get signer info
		   long before we can get the signature results, which could be mis-
		   interpreted to mean the signature is bad) and forces the caller to
		   do things cleanly */
		if( envelopeInfoPtr->usage == ACTION_SIGN && \
			envelopeInfoPtr->state != STATE_FINISHED )
			unlockResourceExit( envelopeInfoPtr, CRYPT_INCOMPLETE );
		}
	else
		if( envInfoType != CRYPT_ENVINFO_CONTENTTYPE && \
			envInfoType != CRYPT_ENVINFO_DETACHEDSIGNATURE )
			unlockResourceExit( envelopeInfoPtr, CRYPT_BADPARM2 );
	if( checkBadPtrWrite( envInfo, sizeof( int ) ) )
		unlockResourceExit( envelopeInfoPtr, CRYPT_BADPARM3 );
	*envInfo = CRYPT_ERROR;

	/* If we're querying something which resides in the content list, make
	   sure there's a content list present.  If it's present but nothing is
	   selected, select the first entry */
	if( ( envInfoType == CRYPT_ENVINFO_CURRENT_COMPONENT || \
		  envInfoType == CRYPT_ENVINFO_SIGNATURE_RESULT || \
		  envInfoType == CRYPT_ENVINFO_SIGNATURE_EXTRADATA ) && \
		envelopeInfoPtr->contentListCurrent == NULL )
		{
		if( envelopeInfoPtr->contentList == NULL )
			unlockResourceExit( envelopeInfoPtr, CRYPT_DATA_NOTFOUND );
		envelopeInfoPtr->contentListCurrent = envelopeInfoPtr->contentList;
		}

	/* Handle the various information types */
	if( envInfoType == CRYPT_ENVINFO_CURRENT_COMPONENT )
		{
		/* At this point we need some special handling for some types of
		   data.  PGP doesn't follow the usual model of encrypting a session
		   key with a user key and then encrypting the data with the session
		   key, but instead encrypts the data directly with the raw key and
		   assumes that if it finds an encrypted data packet that it should
		   take a password, turn it into a user key, and use that to decrypt
		   it.  For this reason if we're deenveloping PGP data and the lower-
		   level routines tell us we need a session key, we report this to
		   the user as requiring password information.  The envelope
		   management routines are intelligent enough to know about the fact
		   that for PGP a password becomes a session key */
		if( envelopeInfoPtr->type == CRYPT_FORMAT_PGP && \
			envelopeInfoPtr->contentListCurrent->envInfo == CRYPT_ENVINFO_SESSIONKEY )
			*envInfo = CRYPT_ENVINFO_PASSWORD;
		else
			*envInfo = envelopeInfoPtr->contentListCurrent->envInfo;
		}
	if( envInfoType == CRYPT_ENVINFO_CONTENTTYPE )
		{
		if( envelopeInfoPtr->contentType == CRYPT_CERTINFO_NONE )
			status = CRYPT_DATA_NOTFOUND;
		else
			*envInfo = envelopeInfoPtr->contentType;
		}
	if( envInfoType == CRYPT_ENVINFO_DETACHEDSIGNATURE )
		{
		/* If this isn't a signed data or we haven't sorted out the content
		   details yet, we don't know whether it's a detached sig or not */
		if( envelopeInfoPtr->usage != ACTION_SIGN || \
			envelopeInfoPtr->contentType == CRYPT_CERTINFO_NONE )
			status = CRYPT_DATA_NOTFOUND;
		else
			*envInfo = envelopeInfoPtr->detachedSig;
		}
	if( envInfoType == CRYPT_ENVINFO_SIGNATURE_RESULT )
		{
		CRYPT_HANDLE iCryptKey = CRYPT_UNUSED;
		const CONTENT_LIST *contentListItem = envelopeInfoPtr->contentListCurrent;
		const BOOLEAN certChainPresent = \
			( ( contentListItem->formatType == CRYPT_FORMAT_CMS || \
				contentListItem->formatType == CRYPT_FORMAT_SMIME ) && \
			   envelopeInfoPtr->iCertChain != CRYPT_ERROR ) ? TRUE : FALSE;

		/* Make sure the content list item is of the appropriate type, and if
		   we've already done this one don't process it a second time.  This
		   check is also performed by the addInfo() code, but we duplicate it
		   here to avoid having to do an unnecessary key fetch for non-CMS
		   signatures */
		if( contentListItem->envInfo != CRYPT_ENVINFO_SIGNATURE )
			unlockResourceExit( envelopeInfoPtr, CRYPT_DATA_NOTFOUND );
		if( contentListItem->processed )
			{
			*envInfo = contentListItem->processingResult;
			unlockResourceExit( envelopeInfoPtr, CRYPT_OK );
			}

		/* Make sure there's a keyset available to pull the key from and get
		   the owner ID.  Since CMS signatures usually carry their own cert
		   chains, we don't perform this check if there's a cert chain
		   available */
		if( !certChainPresent )
			{
			if( envelopeInfoPtr->iSigCheckKeyset == CRYPT_ERROR && \
				cryptStatusError( addDefaultKeyset( envelopeInfoPtr,
								  CRYPT_ENVINFO_KEYSET_SIGCHECK ) ) )
				unlockResourceExit( envelopeInfoPtr, CRYPT_ENVELOPE_RESOURCE );

			/* Try and get the key information */
			status = getKeyFromID( envelopeInfoPtr->iSigCheckKeyset,
								   &iCryptKey, contentListItem->keyID,
								   ( void * ) CRYPT_UNUSED, NULL );
			if( cryptStatusError( status ) )
				unlockResourceExit( envelopeInfoPtr, status );
			}

		/* Push the public key into the envelope, which performs the
		   signature check */
		status = envelopeInfoPtr->addInfo( envelopeInfoPtr,
										   CRYPT_ENVINFO_SIGNATURE,
										   &iCryptKey, 0 );
		*envInfo = status;
		status = CRYPT_OK;
		}
	if( envInfoType == CRYPT_ENVINFO_SIGNATURE )
		{
		CRYPT_HANDLE iCryptHandle;
		const int isInternal = FALSE;

		if( envelopeInfoPtr->iCertChain != CRYPT_ERROR )
			iCryptHandle = envelopeInfoPtr->iCertChain;
		else
			if( envelopeInfoPtr->contentListCurrent != NULL && \
				envelopeInfoPtr->contentListCurrent->iSigCheckKey != CRYPT_ERROR )
				iCryptHandle = envelopeInfoPtr->contentListCurrent->iSigCheckKey;
			else
				unlockResourceExit( envelopeInfoPtr, CRYPT_DATA_NOTFOUND );

		/* Make the information externally visible */
		krnlSendNotifier( iCryptHandle, RESOURCE_IMESSAGE_INCREFCOUNT );
		krnlSendMessage( iCryptHandle, RESOURCE_IMESSAGE_SETPROPERTY,
						 ( int * ) &isInternal, RESOURCE_MESSAGE_PROPERTY_INTERNAL, 0 );
		*envInfo = iCryptHandle;
		}
	if( envInfoType == CRYPT_ENVINFO_SIGNATURE_EXTRADATA )
		{
		if( envelopeInfoPtr->contentListCurrent->iExtraData == CRYPT_ERROR )
			status = CRYPT_DATA_NOTFOUND;
		else
			{
			const int isInternal = FALSE;

			/* Make the information externally visible */
			krnlSendNotifier( envelopeInfoPtr->contentListCurrent->iExtraData,
							  RESOURCE_IMESSAGE_INCREFCOUNT );
			krnlSendMessage( envelopeInfoPtr->contentListCurrent->iExtraData,
							 RESOURCE_IMESSAGE_SETPROPERTY, ( int * ) &isInternal,
							 RESOURCE_MESSAGE_PROPERTY_INTERNAL, 0 );
			*envInfo = envelopeInfoPtr->contentListCurrent->iExtraData;
			}
		}

	unlockResourceExit( envelopeInfoPtr, status );
	}

/* Get the name associated with a decryption key and trigger decryption
   processing (this is a kludge which is due to be replaced when a cleaner
   way to do it can be found) */

CRET cryptGetResourceOwnerName( const CRYPT_ENVELOPE envelope, void CPTR name )
	{
	ENVELOPE_INFO *envelopeInfoPtr;
	CRYPT_CONTEXT iCryptContext;
	CONTENT_LIST *contentListItem;
	char nameBuffer[ CRYPT_MAX_TEXTSIZE + 1 ];
	int status;

	/* Perform basic error checking */
	getCheckResource( envelope, envelopeInfoPtr, RESOURCE_TYPE_ENVELOPE,
					  CRYPT_BADPARM1 );
	if( !envelopeInfoPtr->isDeenvelope )
		unlockResourceExit( envelopeInfoPtr, CRYPT_BADPARM1 );
	if( checkBadPtrWrite( name, 2 ) )	/* One char + terminator */
		unlockResourceExit( envelopeInfoPtr, CRYPT_BADPARM2 );
	if( envelopeInfoPtr->contentListCurrent == NULL )
		{
		if( envelopeInfoPtr->contentList == NULL )
			unlockResourceExit( envelopeInfoPtr, CRYPT_DATA_NOTFOUND );
		envelopeInfoPtr->contentListCurrent = envelopeInfoPtr->contentList;
		}
	contentListItem = envelopeInfoPtr->contentListCurrent;
	*( ( char * ) name ) = '\x0';
	if( contentListItem->envInfo != CRYPT_ENVINFO_PRIVATEKEY )
		unlockResourceExit( envelopeInfoPtr, CRYPT_NOTAVAIL );

	/* Make sure there's a keyset available to pull the key from */
	if( envelopeInfoPtr->iDecryptionKeyset == CRYPT_ERROR && \
		cryptStatusError( addDefaultKeyset( envelopeInfoPtr,
						  CRYPT_ENVINFO_KEYSET_DECRYPT ) ) )
		unlockResourceExit( envelopeInfoPtr, CRYPT_ENVELOPE_RESOURCE );

	/* Try and get the key information */
	status = getKeyFromID( envelopeInfoPtr->iDecryptionKeyset, &iCryptContext,
						   contentListItem->keyID, NULL, nameBuffer );
	if( status == CRYPT_OK || status == CRYPT_WRONGKEY )
		{
		if( checkBadPtrWrite( name, strlen( nameBuffer ) + 1 ) )
			status = CRYPT_BADPARM2;
		else
			strcpy( name, nameBuffer );
		}

	/* If we managed to get the private key (it wasn't protected by a
	   password), push it into the envelope.  If the call succeeds, this will
	   import the session key and delete the required resource list */
	if( cryptStatusOK( status ) )
		{
		status = envelopeInfoPtr->addInfo( envelopeInfoPtr,
										   CRYPT_ENVINFO_PRIVATEKEY,
										   &iCryptContext, 0 );
		iCryptDestroyObject( iCryptContext );
		}

	unlockResourceExit( envelopeInfoPtr, status );
	}

/* Move the envelope component cursor */

static int moveCursor( ENVELOPE_INFO *envelopeInfoPtr, const int value )
	{
	if( envelopeInfoPtr->contentList == NULL )
		return( CRYPT_DATA_NOTFOUND );	/* Nothing to move the cursor to */

	switch( value )
		{
		case CRYPT_CURSOR_FIRST:
			envelopeInfoPtr->contentListCurrent = envelopeInfoPtr->contentList;
			break;

		case CRYPT_CURSOR_PREVIOUS:
			if( envelopeInfoPtr->contentListCurrent == NULL || \
				envelopeInfoPtr->contentListCurrent == envelopeInfoPtr->contentList )
				return( CRYPT_DATA_NOTFOUND );
			else
				{
				CONTENT_LIST *contentListPtr = envelopeInfoPtr->contentList;

				/* Find the previous element in the list */
				while( contentListPtr->next != envelopeInfoPtr->contentListCurrent )
					contentListPtr = contentListPtr->next;
				envelopeInfoPtr->contentListCurrent = contentListPtr;
				}
			break;

		case CRYPT_CURSOR_NEXT:
			if( envelopeInfoPtr->contentListCurrent == NULL || \
				envelopeInfoPtr->contentListCurrent->next == NULL )
				return( CRYPT_DATA_NOTFOUND );
			envelopeInfoPtr->contentListCurrent = envelopeInfoPtr->contentListCurrent->next;
			break;

		case CRYPT_CURSOR_LAST:
			envelopeInfoPtr->contentListCurrent = envelopeInfoPtr->contentList;
			while( envelopeInfoPtr->contentListCurrent->next != NULL )
				envelopeInfoPtr->contentListCurrent = envelopeInfoPtr->contentListCurrent->next;
			break;

		default:
			return( CRYPT_BADPARM3 );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					Enveloping Information Management Functions				*
*																			*
****************************************************************************/

/* Add enveloping/deenvloping information to an envelope */

CRET cryptAddEnvComponentNumeric( const CRYPT_ENVELOPE envelope,
								  const CRYPT_ENVINFO_TYPE envInfoType,
								  const int envInfo )
	{
	ENVELOPE_INFO *envelopeInfoPtr;
	RESOURCE_MESSAGE_CHECK_TYPE checkType = RESOURCE_MESSAGE_CHECK_NONE;
	RESOURCE_TYPE objectType = RESOURCE_TYPE_CRYPT;
	int status = CRYPT_OK;

	/* Perform basic error checking */
	getCheckResource( envelope, envelopeInfoPtr, RESOURCE_TYPE_ENVELOPE,
					  CRYPT_BADPARM1 );

	/* In general we can't add new enveloping information once we've started
	   processing data */
	if( envInfoType != CRYPT_ENVINFO_CURRENT_COMPONENT && \
		envelopeInfoPtr->state != STATE_PREDATA )
		{
		if( !envelopeInfoPtr->isDeenvelope )
			/* We can't add new information once we've started enveloping */
			status = CRYPT_INITED;
		else
			/* We can only add signature check information once we've started
			   de-enveloping */
			if( envInfoType != CRYPT_ENVINFO_SIGNATURE )
				status = CRYPT_INITED;
		if( cryptStatusError( status ) )
			unlockResourceExit( envelopeInfoPtr, status );
		}

	/* Since the information may not be used for quite some time after it's
	   added, we do some preliminary checking here to allow us to return an
	   error code immediately rather than from some deeply-buried function an
	   indeterminate time in the future */
	switch( envInfoType )
		{
		case CRYPT_ENVINFO_DATASIZE:
			if( envelopeInfoPtr->isDeenvelope )
				status = CRYPT_BADPARM2;
			else
				if( envInfo < 0 )
					status = CRYPT_BADPARM3;
				else
					if( envelopeInfoPtr->payloadSize != CRYPT_UNUSED )
						status = CRYPT_INITED;
			break;

		case CRYPT_ENVINFO_COMPRESSION:
			if( envelopeInfoPtr->usage == ACTION_NONE )
				envelopeInfoPtr->usage = ACTION_COMPRESS;
			else
				if( envelopeInfoPtr->usage != ACTION_COMPRESS )
					status = CRYPT_INITED;
			break;

		case CRYPT_ENVINFO_CONTENTTYPE:
			if( envelopeInfoPtr->isDeenvelope || \
				envelopeInfoPtr->type == CRYPT_FORMAT_SMIME )
				status = CRYPT_BADPARM2;
			else
				if( envInfo < CRYPT_CONTENT_DATA || \
					envInfo > CRYPT_CONTENT_LAST )
					status = CRYPT_BADPARM3;
				else
					if( envelopeInfoPtr->contentType )
						status = CRYPT_INITED;
			break;

		case CRYPT_ENVINFO_DETACHEDSIGNATURE:
			if( envelopeInfoPtr->isDeenvelope )
				status = CRYPT_BADPARM2;
			break;

		case CRYPT_ENVINFO_CURRENT_COMPONENT:
			if( !envelopeInfoPtr->isDeenvelope )
				status = CRYPT_BADPARM2;
			else
				if( envInfo > CRYPT_CURSOR_FIRST || \
					envInfo < CRYPT_CURSOR_LAST )
					status = CRYPT_BADPARM2;
			break;

		case CRYPT_ENVINFO_KEY:
		case CRYPT_ENVINFO_SESSIONKEY:
			checkType = RESOURCE_MESSAGE_CHECK_CRYPT;
			if( envelopeInfoPtr->usage == ACTION_NONE )
				envelopeInfoPtr->usage = ACTION_CRYPT;
			else
				if( envelopeInfoPtr->usage != ACTION_CRYPT )
					status = CRYPT_INITED;
			break;

		case CRYPT_ENVINFO_SIGNATURE:
			checkType = ( envelopeInfoPtr->isDeenvelope ) ? \
						RESOURCE_MESSAGE_CHECK_PKC_SIGCHECK : \
						RESOURCE_MESSAGE_CHECK_PKC_SIGN;
			if( envelopeInfoPtr->usage == ACTION_NONE )
				envelopeInfoPtr->usage = ACTION_SIGN;
			else
				if( envelopeInfoPtr->usage != ACTION_SIGN )
					status = CRYPT_INITED;
			break;

		case CRYPT_ENVINFO_SIGNATURE_EXTRADATA:
			if( envelopeInfoPtr->isDeenvelope || \
				( envelopeInfoPtr->type != CRYPT_FORMAT_CMS && \
				  envelopeInfoPtr->type != CRYPT_FORMAT_SMIME ) )
				status = CRYPT_BADPARM2;
			else
				if( envelopeInfoPtr->usage != ACTION_SIGN )
					status = CRYPT_NOTINITED;
			break;

		case CRYPT_ENVINFO_PUBLICKEY:
			checkType = RESOURCE_MESSAGE_CHECK_PKC_ENCRYPT;
			if( envelopeInfoPtr->usage == ACTION_NONE )
				envelopeInfoPtr->usage = ACTION_CRYPT;
			else
				if( envelopeInfoPtr->usage != ACTION_CRYPT )
					status = CRYPT_INITED;
			break;

		case CRYPT_ENVINFO_PRIVATEKEY:
			checkType = RESOURCE_MESSAGE_CHECK_PKC_DECRYPT;
			if( envelopeInfoPtr->usage == ACTION_NONE )
				envelopeInfoPtr->usage = ACTION_CRYPT;
			else
				if( envelopeInfoPtr->usage != ACTION_CRYPT )
					status = CRYPT_INITED;
			break;

		case CRYPT_ENVINFO_HASH:
			checkType = RESOURCE_MESSAGE_CHECK_HASH;
			if( envelopeInfoPtr->usage == ACTION_NONE )
				envelopeInfoPtr->usage = ACTION_SIGN;
			else
				if( envelopeInfoPtr->usage != ACTION_SIGN )
					status = CRYPT_INITED;
			break;

		case CRYPT_ENVINFO_KEYSET_ENCRYPT:
			checkType = RESOURCE_MESSAGE_CHECK_PKC_ENCRYPT;
			objectType = RESOURCE_TYPE_KEYSET;
			if( envelopeInfoPtr->isDeenvelope )
				status = CRYPT_BADPARM2;
			else
				if( envelopeInfoPtr->iEncryptionKeyset != CRYPT_ERROR )
					status = CRYPT_INITED;
			break;

		case CRYPT_ENVINFO_KEYSET_DECRYPT:
			checkType = RESOURCE_MESSAGE_CHECK_PKC_DECRYPT;
			objectType = RESOURCE_TYPE_KEYSET;
			if( !envelopeInfoPtr->isDeenvelope )
				status = CRYPT_BADPARM2;
			else
				if( envelopeInfoPtr->iDecryptionKeyset != CRYPT_ERROR )
					status = CRYPT_INITED;
			break;

		case CRYPT_ENVINFO_KEYSET_SIGCHECK:
			checkType = RESOURCE_MESSAGE_CHECK_PKC_SIGCHECK;
			objectType = RESOURCE_TYPE_KEYSET;
			if( !envelopeInfoPtr->isDeenvelope )
				status = CRYPT_BADPARM2;
			else
				if( envelopeInfoPtr->iSigCheckKeyset != CRYPT_ERROR )
					status = CRYPT_INITED;
			break;

		default:
			status = CRYPT_BADPARM2;
		}
	if( cryptStatusError( status ) )
		unlockResourceExit( envelopeInfoPtr, status );
	if( checkType != RESOURCE_MESSAGE_CHECK_NONE )
		{
		int type;

		/* Check the object as appropriate */
		status = krnlSendMessage( envInfo, RESOURCE_MESSAGE_CHECK, NULL,
								  checkType, CRYPT_BADPARM3 );
		if( cryptStatusError( status ) )
			unlockResourceExit( envelopeInfoPtr, status );

		/* Make sure the object is of the correct type */
		status = krnlSendMessage( envInfo, RESOURCE_MESSAGE_GETPROPERTY,
					&type, RESOURCE_MESSAGE_PROPERTY_TYPE, CRYPT_BADPARM3 );
		if( cryptStatusError( status ) )
			unlockResourceExit( envelopeInfoPtr, status );
		if( envInfoType == CRYPT_ENVINFO_SIGNATURE || \
			envInfoType == CRYPT_ENVINFO_PUBLICKEY || \
			envInfoType == CRYPT_ENVINFO_PRIVATEKEY )
			{
			/* Public-key objects can be encryption contexts or certificates */
			if( type != objectType && type != RESOURCE_TYPE_CERTIFICATE )
				status = CRYPT_BADPARM3;

			/* If we're using CMS enveloping, the object must have a cert of
			   the correct type associated with it */
			if( cryptStatusOK( status ) && \
				( envelopeInfoPtr->type == CRYPT_FORMAT_CMS || \
				  envelopeInfoPtr->type == CRYPT_FORMAT_SMIME ) )
				{
				int certType;

				status = cryptGetCertComponentNumeric( envInfo,
										CRYPT_CERTINFO_CERTTYPE, &certType );
				if( cryptStatusError( status ) ||
					( certType != CRYPT_CERTTYPE_CERTIFICATE && \
					  certType != CRYPT_CERTTYPE_CERTCHAIN ) )
					status = CRYPT_BADPARM3;
				}
			}
		else
			if( type != objectType )
				status = CRYPT_BADPARM3;
		}
	else
		/* If it's additional signature information, make sure the object is
		   CMS attributes */
		if( envInfo == CRYPT_ENVINFO_SIGNATURE_EXTRADATA )
			{
			int certType;

			status = cryptGetCertComponentNumeric( envInfo,
										CRYPT_CERTINFO_CERTTYPE, &certType );
			if( cryptStatusError( status ) ||
				certType != CRYPT_CERTTYPE_CMS_ATTRIBUTES )
				status = CRYPT_BADPARM3;
			}
	if( cryptStatusError( status ) )
		unlockResourceExit( envelopeInfoPtr, status );

	/* If it's meta-information, process it now */
	if( envInfoType == CRYPT_ENVINFO_CURRENT_COMPONENT )
		{
		status = moveCursor( envelopeInfoPtr, envInfo );
		unlockResourceExit( envelopeInfoPtr, status );
		}

	/* Add it to the envelope */
	status = envelopeInfoPtr->addInfo( envelopeInfoPtr, envInfoType,
									   &envInfo, 0 );
	unlockResourceExit( envelopeInfoPtr, status );
	}

CRET cryptAddEnvComponentString( const CRYPT_ENVELOPE envelope,
								 const CRYPT_ENVINFO_TYPE envInfoType,
								 const void CPTR envInfo,
								 const int envInfoLength )
	{
	ENVELOPE_INFO *envelopeInfoPtr;
	int status = CRYPT_OK;

	/* Perform basic error checking */
	getCheckResource( envelope, envelopeInfoPtr, RESOURCE_TYPE_ENVELOPE,
					  CRYPT_BADPARM1 );
	if( envInfoType != CRYPT_ENVINFO_PASSWORD )
		unlockResourceExit( envelopeInfoPtr, CRYPT_BADPARM2 );
	if( checkBadPtrRead( envInfo, envInfoLength ) || \
		checkBadPassword( envInfo ) )
		unlockResourceExit( envelopeInfoPtr, CRYPT_BADPARM3 );
	if( envInfoLength < 2 )
		unlockResourceExit( envelopeInfoPtr, CRYPT_BADPARM4 );
	if( envelopeInfoPtr->usage == ACTION_NONE )
		envelopeInfoPtr->usage = ACTION_CRYPT;
	else
		if( envelopeInfoPtr->usage != ACTION_CRYPT )
			unlockResourceExit( envelopeInfoPtr, CRYPT_INITED );

	/* In general we can't add new enveloping information once we've started
	   processing data */
	if( envelopeInfoPtr->state != STATE_PREDATA && \
		!envelopeInfoPtr->isDeenvelope )
		/* We can't add new information once we've started enveloping */
		unlockResourceExit( envelopeInfoPtr, CRYPT_INITED );

	/* Add it to the envelope */
	status = envelopeInfoPtr->addInfo( envelopeInfoPtr, envInfoType,
									   envInfo, envInfoLength );
	unlockResourceExit( envelopeInfoPtr, status );
	}
