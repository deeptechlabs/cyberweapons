/****************************************************************************
*																			*
*					cryptlib OCTET STRING En/Decoding Routines				*
*					   Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

#include <string.h>
#if defined( INC_ALL )
  #include "asn1.h"
  #include "envelope.h"
#elif defined( INC_CHILD )
  #include "../keymgmt/asn1.h"
  #include "envelope.h"
#else
  #include "keymgmt/asn1.h"
  #include "envelope/envelope.h"
#endif /* Compiler-specific includes */

/*			 .... NO! ...				   ... MNO! ...
		   ..... MNO!! ...................... MNNOO! ...
		 ..... MMNO! ......................... MNNOO!! .
		.... MNOONNOO!	 MMMMMMMMMMPPPOII!	 MNNO!!!! .
		 ... !O! NNO! MMMMMMMMMMMMMPPPOOOII!! NO! ....
			...... ! MMMMMMMMMMMMMPPPPOOOOIII! ! ...
		   ........ MMMMMMMMMMMMPPPPPOOOOOOII!! .....
		   ........ MMMMMOOOOOOPPPPPPPPOOOOMII! ...
			....... MMMMM..	   OPPMMP	 .,OMI! ....
			 ...... MMMM::	 o.,OPMP,.o	  ::I!! ...
				 .... NNM:::.,,OOPM!P,.::::!! ....
				  .. MMNNNNNOOOOPMO!!IIPPO!!O! .....
				 ... MMMMMNNNNOO:!!:!!IPPPPOO! ....
				   .. MMMMMNNOOMMNNIIIPPPOO!! ......
				  ...... MMMONNMMNNNIIIOO!..........
			   ....... MN MOMMMNNNIIIIIO! OO ..........
			......... MNO! IiiiiiiiiiiiI OOOO ...........
		  ...... NNN.MNO! . O!!!!!!!!!O . OONO NO! ........
		   .... MNNNNNO! ...OOOOOOOOOOO .  MMNNON!........
		   ...... MNNNNO! .. PPPPPPPPP .. MMNON!........
			  ...... OO! ................. ON! .......
				 ................................

   Be very careful when modifying this code, the data manipulation it
   performs is somewhat tricky */

#if defined( __TURBOC__ ) && !defined( __BORLANDC__ )	/*!!!!!!!!!!*/
#define memcpy	xmemcpy		/* Call our safe memcpy() wrapper */
void *xmemcpy( void *dest, const void *src, size_t length );
#endif /* __TURBOC__ && !__BORLANDC__ */				/*!!!!!!!!!!*/

/****************************************************************************
*																			*
*						OCTET STRING Encoding Routines						*
*																			*
****************************************************************************/

/* Determine the quantization level and length threshold for the length
   encoding of constructed indefinite-length strings.  The length encoding
   is the actual length if <= 127, or a one-byte length-of-length followed by
   the length if > 127 */

#if INT_MAX > 32767

#define lengthOfLength( length )	( ( length < 128 ) ? 1 : \
									  ( length < 256 ) ? 2 : \
									  ( length < 65536 ) ? 3 : 4 )

#define findThreshold( length )		( ( length < 128 ) ? 127 : \
									  ( length < 256 ) ? 255 : \
									  ( length < 65536 ) ? 65535 : INT_MAX )
#else

#define lengthOfLength( length )	( ( length < 128 ) ? 1 : \
									  ( length < 256 ) ? 2 : 3 )

#define findThreshold( length )		( ( length < 128 ) ? 127 : \
									  ( length < 256 ) ? 255 : INT_MAX )
#endif /* 32-bit ints */

/* Begin a new segment in the buffer */

static int beginSegment( ENVELOPE_INFO *envelopeInfoPtr )
	{
	const int lLen = lengthOfLength( envelopeInfoPtr->bufSize );
	const int headerLen = lLen + 1;
	int offset = envelopeInfoPtr->bufPos;

	/* Make sure there's enough room in the buffer to accomodate the start of
	   a new segment.  In the worst case this is 4 bytes (outer OCTET STRING)
	   + 7 bytes (blockBuffer contents).  Although in practice we could
	   eliminate this condition, it would require tracking a lot of state
	   information which records which data had been encoded into the buffer
	   and whether the blockBuffer data had been copied into the buffer, so
	   to keep it simple we require enough room to do everything at once */
	if( envelopeInfoPtr->bufSize - offset < headerLen + envelopeInfoPtr->blockBufferPos )
		return( CRYPT_ERROR_OVERFLOW );

	/* If we're encoding data with a definite length, there's no real segment
	   boundary apart from the artificial ones created by encryption
	   blocking */
	if( envelopeInfoPtr->payloadSize != CRYPT_UNUSED )
		envelopeInfoPtr->segmentStart = envelopeInfoPtr->segmentDataStart = offset;
	else
		{
		/* Begin a new segment after the end of the current segment.  We
		   always leave enough room for the largest allowable length field
		   because we may have a short segment at the end of the buffer which
		   is moved to the start of the buffer after data is copied out,
		   turning it into a longer segment.  For this reason we rely on the
		   completeSegment() code to get the length right and move any data
		   down as required */
		envelopeInfoPtr->buffer[ offset ] = BER_OCTETSTRING;
		envelopeInfoPtr->bufPos += 1 + lLen;
		offset = envelopeInfoPtr->bufPos;
		envelopeInfoPtr->segmentStart = offset - lLen;
		envelopeInfoPtr->segmentDataStart = offset;
		}

	/* Now copy anything left in the block buffer to the start of the new
	   segment.  We know everything will fit because we've checked earlier on
	   that the header and blockbuffer contents will fit into the remaining
	   space */
	if( envelopeInfoPtr->blockBufferPos )
		{
		memcpy( envelopeInfoPtr->buffer + envelopeInfoPtr->bufPos,
				envelopeInfoPtr->blockBuffer, envelopeInfoPtr->blockBufferPos );
		envelopeInfoPtr->bufPos += envelopeInfoPtr->blockBufferPos;
		envelopeInfoPtr->blockBufferPos = 0;
		}

	/* We've started the new segment, mark it as incomplete */
	envelopeInfoPtr->segmentComplete = FALSE;

	return( CRYPT_OK );
	}

/* Complete a segment of data in the buffer.  This is incredibly complicated
   because we need to take into account the indefinite-length encoding (which
   has a variable-size length field) and the quantization to the cipher block
   size.  In particular the indefinite-length encoding means we can never
   encode a block with a size of 130 bytes (we get tag + length + 127 = 129,
   then tag + length-of-length + length + 128 = 131), and the same for the
   next boundary at 256 bytes */

static BOOLEAN encodeSegmentHeader( ENVELOPE_INFO *envelopeInfoPtr,
									const BOOLEAN isEncrypted )
	{
	BYTE *bufPtr = envelopeInfoPtr->buffer;
	const int segmentDataStart = envelopeInfoPtr->segmentDataStart;
	int segmentStart = envelopeInfoPtr->segmentStart;
	int dLen = envelopeInfoPtr->bufPos - segmentDataStart;
	int lLen, oldLLen = 1 + ( segmentDataStart - segmentStart ), qTot;
	int threshold, remainder = 0;
	BOOLEAN needsPadding = envelopeInfoPtr->needsPadding;

	/* If we're adding PKCS #5 padding, try and add one blocks worth of
	   pseudo-data.  This adjusted data length is then fed into the block
	   size quantisation process, after which any odd-sized remainder is
	   ignored, and the necessary padding bytes are added to account for the
	   difference between the actual and padded size */
	if( needsPadding )
		{
		/* Check whether the padding will fit onto the end of the data.  This
		   check isn't completely accurate since the length encoding might
		   shrink by one or two bytes and allow a little extra data to be
		   squeezed in, however the extra data could cause the length
		   encoding to expand again, requiring a complex adjustment process.
		   To make things easier we ignore this possibility at the expense of
		   emitting one more segment than is necessary in a few very rare
		   cases */
		if( envelopeInfoPtr->segmentDataStart + dLen + \
			envelopeInfoPtr->blockSize < envelopeInfoPtr->bufSize )
			dLen += envelopeInfoPtr->blockSize;
		else
			needsPadding = FALSE;
		}

	/* Now that we've made any necessary adjustments to the data length,
	   determine the length of the length encoding (which may have grown or
	   shrunk since we initially calculated it when we began the segment) and
	   any combined data lengths based on it */
	if( envelopeInfoPtr->payloadSize != CRYPT_UNUSED )
		lLen = oldLLen = 0;	/* No header between segments */
	else
		lLen = 1 + lengthOfLength( dLen );
	qTot = lLen + dLen;

	/* Quantize and adjust the length if we're encrypting in a block mode */
	if( isEncrypted )
		{
		qTot = dLen & envelopeInfoPtr->blockSizeMask;
		threshold = findThreshold( qTot );
		if( qTot <= threshold && dLen > threshold )
			lLen--;
		remainder = dLen - qTot;
		dLen = qTot;	/* Data length has now shrunk to quantised size */
		}
	assert( lLen >= 0 );
	assert( remainder >= 0 && remainder < 8 );

	/* If there's not enough data present to do anything, tell the caller we
	   couldn't do anything */
	if( !qTot )
		return( FALSE );
	assert( dLen >= 0 );

	/* If the length encoding has shrunk (either due to the cipher block size
	   quantization shrinking the segment or because we've wrapped up a
	   segment at less than the original projected length), move the data
	   down.  The complete segment starts at ( segmentStart - 1 ), in the
	   worst case the shrinking can cover several bytes if we go from a > 255
	   byte segment to a <= 127 byte one */
	if( lLen < oldLLen )
		{
		int delta = oldLLen - lLen;

		memmove( bufPtr + segmentStart - 1 + lLen,
				 bufPtr + segmentDataStart,
				 envelopeInfoPtr->bufPos - segmentDataStart );
		envelopeInfoPtr->bufPos -= delta;
		envelopeInfoPtr->segmentDataStart -= delta;
		}
	assert( envelopeInfoPtr->bufPos >= 0 );
	assert( envelopeInfoPtr->segmentDataStart + dLen <= envelopeInfoPtr->bufSize );

	/* If we need to add PKCS #5 block padding, try and do so now.  Since the
	   extension of the data length to allow for padding data is performed by
	   adding one block of pseudo-data and letting the block quantisation
	   system take care of any discrepancies, we can calculate the padding
	   amount as the difference between any remainder after quantisation and
	   the block size */
	if( needsPadding )
		{
		const int padSize = envelopeInfoPtr->blockSize - remainder;
		int i;

		/* Add the block padding and set the remainder to zero, since we're
		   now at an even block boundary */
		for( i = 0; i < padSize; i++ )
			envelopeInfoPtr->buffer[ envelopeInfoPtr->bufPos + i ] = padSize;
		envelopeInfoPtr->bufPos += padSize;
		envelopeInfoPtr->needsPadding = FALSE;
		remainder = 0;
		}

	/* Move any leftover bytes into the block buffer */
	if( remainder )
		{
		memcpy( envelopeInfoPtr->blockBuffer,
				bufPtr + envelopeInfoPtr->bufPos - remainder, remainder );
		envelopeInfoPtr->blockBufferPos = remainder;
		envelopeInfoPtr->bufPos -= remainder;
		}

	/* If we're using the definite length form, exit */
	if( envelopeInfoPtr->payloadSize != CRYPT_UNUSED )
		return( TRUE );

	/* Encode the length at the start of the data */
	if( dLen < 128 )
		bufPtr[ segmentStart ] = dLen;
	else
		{
		lLen -= 2;	/* Tag + length of length */
		bufPtr[ segmentStart++ ] = 0x80 | lLen;
#if INT_MAX > 32767
		if( lLen > 3 )
			{
			bufPtr[ segmentStart++ ] = dLen >> 24;
			dLen &= 0xFFFFFFL;
			}
		if( lLen > 2 )
			{
			bufPtr[ segmentStart++ ] = dLen >> 16;
			dLen &= 0xFFFFL;
			}
#endif /* 32-bit ints */
		if( lLen > 1 )
			{
			bufPtr[ segmentStart++ ] = dLen >> 8;
			dLen &= 0xFF;
			}
		bufPtr[ segmentStart ] = dLen;
		}

	return( TRUE );
	}

static int completeSegment( ENVELOPE_INFO *envelopeInfoPtr, 
							const BOOLEAN forceCompletion )
	{
	/* If we're enveloping data using indefinite encoding and we're not at 
	   the end of the data, don't emit a subsegment containing less then 10 
	   bytes of data.  This is to protect against users who write code which 
	   performs byte-at-a-time enveloping, at least we can quantize the data 
	   amount to make it slightly more efficient.  As a side-effect, it 
	   avoids occasional inefficiencies at boundaries where one or two bytes 
	   may still be hanging around from a previous data block, since they'll 
	   be coalesced into the following block */
	if( !forceCompletion && !envelopeInfoPtr->isDeenvelope && \
		envelopeInfoPtr->payloadSize == CRYPT_UNUSED && \
		( envelopeInfoPtr->bufPos - envelopeInfoPtr->segmentDataStart ) < 10 )
		{
		/* We can't emit any of the small subsegment, however there may be 
		   (non-)data preceding this which we can hand over so we set the
		   segment data end value to the start of the segment (the complete 
		   segment starts at ( segmentStart - 1 )) */
		envelopeInfoPtr->segmentDataEnd = envelopeInfoPtr->segmentStart - 1;
		return( CRYPT_OK );
		}

	/* Wrap up the segment */
	if( !encodeSegmentHeader( envelopeInfoPtr, ( BOOLEAN )	/* VC++ fix */
					( envelopeInfoPtr->iCryptContext != CRYPT_ERROR ) ? \
					TRUE : FALSE ) )
		/* Not enough data to complete segment */
		return( CRYPT_ERROR_UNDERFLOW );
	if( envelopeInfoPtr->iCryptContext != CRYPT_ERROR )
		{
		int status;

		status = krnlSendMessage( envelopeInfoPtr->iCryptContext,
						RESOURCE_IMESSAGE_CTX_ENCRYPT,
						envelopeInfoPtr->buffer + \
								envelopeInfoPtr->segmentDataStart,
						envelopeInfoPtr->bufPos - \
								envelopeInfoPtr->segmentDataStart );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Remember how much data is now available to be read out */
	envelopeInfoPtr->segmentDataEnd = envelopeInfoPtr->bufPos;

	/* Mark this segment as being completed */
	envelopeInfoPtr->segmentComplete = TRUE;

	return( CRYPT_OK );
	}

/* Move all segments remaining in the buffer down to the start after the
   data there has been copied out */

static void moveSegments( ENVELOPE_INFO *envelopeInfoPtr, const int length,
						  const int remainder )
	{
	/* Move the data down in the buffer if necessary */
	if( remainder )
		memmove( envelopeInfoPtr->buffer, envelopeInfoPtr->buffer + length,
				 remainder );
	envelopeInfoPtr->bufPos = remainder;

	/* Update the segment location information.  Note that the segment start
	   values track the start position of the last completed segment and
	   aren't updated until we begin a new segment, so they may go negative
	   when the data from the last completed segment is moved past the start
	   of the buffer */
	envelopeInfoPtr->segmentStart -= length;
	envelopeInfoPtr->segmentDataStart -= length;
	envelopeInfoPtr->segmentDataEnd -= length;
	assert( envelopeInfoPtr->segmentDataEnd >= 0 );
	}

/* Copy data into the envelope.  Returns the number of bytes copied, or an
   overflow error if we're trying to flush data and there isn't room to
   perform the flush (this somewhat peculiar case is because the caller
   expects to have 0 bytes copied in this case) */

int copyToEnvelope( ENVELOPE_INFO *envelopeInfoPtr, const BYTE *buffer,
					const int length )
	{
	ACTION_LIST *hashActionPtr;
	BOOLEAN needCompleteSegment = FALSE;
	BYTE *bufPtr;
	int bytesToCopy, status;

	/* If we're trying to copy into a full buffer, return a count of 0 bytes
	   unless we're trying to flush the buffer (the calling routine may
	   convert this to an overflow error if necessary) */
	if( envelopeInfoPtr->bufPos == envelopeInfoPtr->bufSize )
		return( ( length ) ? 0 : CRYPT_ERROR_OVERFLOW );

	/* If we're generating a detached signature, just hash the data and
	   exit.  We don't have to check for problems with the context at this 
	   point since they'll be detected when we try and read the hash value */
	if( envelopeInfoPtr->detachedSig )
		{
		for( hashActionPtr = envelopeInfoPtr->hashActions;
			 hashActionPtr != NULL && hashActionPtr->action == ACTION_HASH;
			 hashActionPtr = hashActionPtr->next )
			{
			status = krnlSendMessage( hashActionPtr->iCryptHandle, 
									  RESOURCE_IMESSAGE_CTX_HASH, 
									  ( void * ) buffer, length );
			if( cryptStatusError( status ) )
				return( status );
			}
		return( length );
		}

	/* If we're flushing data, wrap up the segment and exit */
	if( !length )
		{
		BOOLEAN needNewSegment = envelopeInfoPtr->needsPadding;

#ifndef NO_COMPRESSION
		/* If we're using compression, flush any remaining data out of the
		   zStream */
		if( envelopeInfoPtr->zStreamInited )
			{
			/* If we've just completed a segment, begin a new one.  This
			   action is slightly anomalous in that normally a flush can't
			   add more data to the envelope and so we'd never need to start
			   a new segment during a flush, however since we can have
			   arbitrarily large amounts of data trapped in subspace via zlib
			   we need to be able to handle starting new segments at this 
			   point */
			if( envelopeInfoPtr->segmentComplete )
				{
				status = beginSegment( envelopeInfoPtr );
				if( cryptStatusError( status ) )
					return( status );
				if( envelopeInfoPtr->bufPos == envelopeInfoPtr->bufSize )
					return( CRYPT_ERROR_OVERFLOW );
				}

			/* Flush any remaining compressed data into the envelope buffer */
			bytesToCopy = envelopeInfoPtr->bufSize - envelopeInfoPtr->bufPos;
			envelopeInfoPtr->zStream.next_in = NULL;
			envelopeInfoPtr->zStream.avail_in = 0;
			envelopeInfoPtr->zStream.next_out = envelopeInfoPtr->buffer + \
												envelopeInfoPtr->bufPos;
			envelopeInfoPtr->zStream.avail_out = bytesToCopy;
			status = deflate( &envelopeInfoPtr->zStream, Z_FINISH );
			if( status != Z_STREAM_END && status != Z_OK )
				/* There was some problem other than the output buffer being
				   full */
				return( CRYPT_ERROR_FAILED );

			/* Adjust the status information based on the data flushed out
			   of the zStream.  We don't need to check for the output buffer
			   being full because this case is already handled by the check
			   of the deflate() return value */
			envelopeInfoPtr->bufPos += bytesToCopy - \
									   envelopeInfoPtr->zStream.avail_out;
			assert( envelopeInfoPtr->bufPos >= 0 && \
					envelopeInfoPtr->bufPos <= envelopeInfoPtr->bufSize );

			/* If we didn't finish flushing data because the output buffer is 
			   full, complete the segment and tell the caller they need to pop 
			   some data */
			if( status == Z_OK )
				{
				status = completeSegment( envelopeInfoPtr, TRUE );
				return( cryptStatusError( status ) ? \
						status : CRYPT_ERROR_OVERFLOW );
				}
			}
#endif /* NO_COMPRESSION */

		/* If we're encrypting data with a block cipher, we need to add PKCS
		   #5 padding at the end of the last block */
		if( envelopeInfoPtr->blockSize > 1 )
			{
			envelopeInfoPtr->needsPadding = TRUE;
			if( envelopeInfoPtr->segmentComplete )
				/* The current segment has been wrapped up, we need to begin
				   a new segment to contain the padding */
				needNewSegment = TRUE;
			}

		/* If we're carrying over the padding requirement from a previous
		   block (which happens if there was data left after the previous
		   segment was completed or if the addition of padding would have
		   overflowed the buffer when the segment was completed, in other
		   words if the needPadding flag is still set from the previous
		   call), we need to begin a new block before we can try and add the
		   padding */
		if( needNewSegment )
			{
			status = beginSegment( envelopeInfoPtr );
			if( cryptStatusError( status ) )
				return( status );
			if( envelopeInfoPtr->bufPos == envelopeInfoPtr->bufSize )
				return( CRYPT_ERROR_OVERFLOW );
			}

		/* Complete the segment if necessary */
		if( !envelopeInfoPtr->segmentComplete || envelopeInfoPtr->needsPadding )
			{
			status = completeSegment( envelopeInfoPtr, TRUE );
			if( cryptStatusError( status ) )
				return( status );
			}
		if( envelopeInfoPtr->needsPadding )
			return( CRYPT_ERROR_OVERFLOW );

		/* We've finished processing everything, complete each hash action */
		for( hashActionPtr = envelopeInfoPtr->hashActions;
			 hashActionPtr != NULL && hashActionPtr->action == ACTION_HASH;
			 hashActionPtr = hashActionPtr->next )
			{
			status = krnlSendMessage( hashActionPtr->iCryptHandle, 
									  RESOURCE_IMESSAGE_CTX_HASH, "", 0 );
			if( cryptStatusError( status ) )
				return( status );
			}

		return( 0 );
		}

	/* If we've just completed a segment, begin a new one before we add any
	   data */
	if( envelopeInfoPtr->segmentComplete )
		{
		status = beginSegment( envelopeInfoPtr );
		if( cryptStatusError( status ) || \
			envelopeInfoPtr->bufPos == envelopeInfoPtr->bufSize )
			return( 0 );	/* 0 bytes copied */
		}

	/* Copy over as much as we can fit into the buffer */
	bufPtr = envelopeInfoPtr->buffer + envelopeInfoPtr->bufPos;
	bytesToCopy = envelopeInfoPtr->bufSize - envelopeInfoPtr->bufPos;
#ifndef NO_COMPRESSION
	if( envelopeInfoPtr->zStreamInited )
		{
		/* Compress the data into the envelope buffer */
		envelopeInfoPtr->zStream.next_in = ( BYTE * ) buffer;
		envelopeInfoPtr->zStream.avail_in = length;
		envelopeInfoPtr->zStream.next_out = bufPtr;
		envelopeInfoPtr->zStream.avail_out = bytesToCopy;
		status = deflate( &envelopeInfoPtr->zStream, Z_NO_FLUSH );
		if( status != Z_OK )
			return( CRYPT_ERROR );

		/* Adjust the status information based on the data copied into the
		   zStream and flushed from the zStream into the buffer */
		envelopeInfoPtr->bufPos += bytesToCopy - \
								   envelopeInfoPtr->zStream.avail_out;
		bytesToCopy = length - envelopeInfoPtr->zStream.avail_in;

		/* If the buffer is full (there's no more room left for further
		   input) we need to close off the segment */
		if( envelopeInfoPtr->zStream.avail_out == 0 )
			needCompleteSegment = TRUE;
		}
	else
#endif /* NO_COMPRESSION */
		{
		/* We're not using compression */
		if( bytesToCopy > length )
			bytesToCopy = length;
		memcpy( bufPtr, buffer, bytesToCopy );
		envelopeInfoPtr->bufPos += bytesToCopy;

		/* Hash the data if necessary.  We don't have to check for problems 
		   with the context at this point since they'll be detected when we 
		   try and read the hash value */
		for( hashActionPtr = envelopeInfoPtr->hashActions;
			 hashActionPtr != NULL && hashActionPtr->action == ACTION_HASH;
			 hashActionPtr = hashActionPtr->next )
			krnlSendMessage( hashActionPtr->iCryptHandle, 
							 RESOURCE_IMESSAGE_CTX_HASH, bufPtr, bytesToCopy );

		/* If the buffer is full (ie we've been fed more input data than we
		   could copy into the buffer) we need to close off the segment */
		if( bytesToCopy < length )
			needCompleteSegment = TRUE;
		}
	assert( envelopeInfoPtr->bufPos >= 0 );

	/* Close off the segment if necessary */
	if( needCompleteSegment )
		{
		status = completeSegment( envelopeInfoPtr, FALSE );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( bytesToCopy );
	}

/* Copy data from the envelope and begin a new segment in the newly-created
   room.  If called with a zero length value this will create a new segment
   without moving any data.  Returns the number of bytes copied */

int copyFromEnvelope( ENVELOPE_INFO *envelopeInfoPtr, BYTE *buffer,
					  int length )
	{
	BYTE *bufPtr = envelopeInfoPtr->buffer;
	int remainder;

	/* If the caller wants more data than there is available in the set of
	   completed segments, try to wrap up the next segment to make more data
	   available */
	if( length > envelopeInfoPtr->segmentDataEnd )
		{
		/* Try and complete the segment if necessary.  This may not be
		   possible if we're using a block encryption mode and there isn't
		   enough room at the end of the buffer to encrypt a full block.  If
		   we're generating a detached sig, the data is communicated out-of-
		   band, so there's no segmenting */
		if( !envelopeInfoPtr->detachedSig && \
			!envelopeInfoPtr->segmentComplete )
			{
			int status = completeSegment( envelopeInfoPtr, FALSE );
			if( cryptStatusError( status ) )
				return( status );
			}

		/* Return all the data we've got */
		length = min( length, envelopeInfoPtr->segmentDataEnd );
		}
	remainder = envelopeInfoPtr->bufPos - length;
	assert( remainder >= 0 );

	/* Copy the data out and move any remaining data down to the start of the
	   buffer  */
	if( length )
		{
		memcpy( buffer, bufPtr, length );
		moveSegments( envelopeInfoPtr, length, remainder );
		}

	return( length );
	}

/****************************************************************************
*																			*
*						OCTET STRING Decoding Routines						*
*																			*
****************************************************************************/

/* Handle the EOC and PKCS #5 block padding if necessary */

static int processEOC( ENVELOPE_INFO *envelopeInfoPtr )
	{
	/* If we're using a block cipher, undo the PKCS #5 padding which is
	   present at the end of the block */
	if( envelopeInfoPtr->blockSize > 1 )
		{
		const int padSize = \
					envelopeInfoPtr->buffer[ envelopeInfoPtr->bufPos - 1 ];

		if( padSize > 8 )
			/* Data corrupted or wrong key used */
			return( CRYPT_ERROR_BADDATA );
		envelopeInfoPtr->bufPos -= padSize;
		assert( envelopeInfoPtr->bufPos >= 0 );
		}

	/* Remember that we've reached the end of the payload and where the 
	   payload ends ("This was the end of the river all right") */
	envelopeInfoPtr->endOfContents = TRUE;
	envelopeInfoPtr->dataLeft = envelopeInfoPtr->bufPos;

	return( CRYPT_OK );
	}

/* Decode the header for the next segment in the buffer.  Returns the number
   of bytes consumed, or an underflow error if more data is required */

static int getNextSegment( ENVELOPE_INFO *envelopeInfoPtr, const BYTE *buffer,
						   const int length )
	{
	SEGHDR_STATE state = envelopeInfoPtr->segHdrState;
	long segmentLength = envelopeInfoPtr->segHdrSegLength;
	int count = envelopeInfoPtr->segHdrCount, index;

	/* If we've already processed the entire payload, don't do anything
	   (this can happen when we're using the definite encoding form, since
	   the EOC flag is set elsewhere as soon as the entire payload has been
	   copied to the buffer) */
	if( envelopeInfoPtr->endOfContents )
		return( 0 );

	/* If we're using the definite encoding form, there's a single segment
	   equal in length to the entire payload */
	if( envelopeInfoPtr->payloadSize != CRYPT_UNUSED )
		{
		envelopeInfoPtr->segmentSize = envelopeInfoPtr->payloadSize;
		return( 0 );
		}

	/* Process each data byte until we've either parsed the entire header or
	   run out of input */
	for( index = 0; index < length && state != SEGHDRSTATE_DONE; index++ )
		{
		SEGHDR_STATE oldState = state;

		switch( state )
			{
			case SEGHDRSTATE_NONE:
				/* Check for OCTET STRING or start or end-of-contents
				   octets */
				if( buffer[ index ] == BER_OCTETSTRING )
					state = SEGHDRSTATE_LEN_OF_LEN;
				if( !buffer[ index ] )
					state = SEGHDRSTATE_END;
				break;

			case SEGHDRSTATE_LEN_OF_LEN:
				/* We've seen the OCTET STRING header, check for the short
				   length or length-of-length */
				count = buffer[ index ];
				if( !( count & 0x80 ) )
					{
					segmentLength = count;
					state = SEGHDRSTATE_DONE;
					}
				else
					{
					/* It's a long segment, get the length-of-length
					   information and reset the first-time flag to make sure
					   we decrypt the length data */
					count &= 0x7F;
					if( count < 1 || count > 4 )
						/* "Nobody will ever need more than 640K" */
						return( CRYPT_ERROR_BADDATA );
					state = SEGHDRSTATE_LEN;
					}
				break;

			case SEGHDRSTATE_LEN:
				/* We're processing a long-format length field, get the next
				   part of the length */
				segmentLength <<= 8;
				segmentLength |= buffer[ index ];
				count--;

				/* If we've got all the data, make sure the segment length is
				   valid and return to the initial state */
				if( !count )
					{
					if( segmentLength < 0x80 )
						return( CRYPT_ERROR_BADDATA );
					state = SEGHDRSTATE_DONE;
					}
				break;

			case SEGHDRSTATE_END:
				/* We've seen the first end-of-contents octet, check for
				   the second one */
				if( !buffer[ index ] )
					{
					int status;

					status = processEOC( envelopeInfoPtr );
					if( cryptStatusError( status ) )
						return( status );
					state = SEGHDRSTATE_DONE;
					}
				break;

			default:
				assert( NOTREACHED );
			}

		/* If the state hasn't changed when it should have, there's a
		   problem */
		if( state == oldState && state != SEGHDRSTATE_LEN )
			return( CRYPT_ERROR_BADDATA );
		}

	/* If we got the final length, update the appropriate segment length
	   value */
	if( state == SEGHDRSTATE_DONE )
		{
		envelopeInfoPtr->segmentSize = segmentLength;
		envelopeInfoPtr->segHdrSegLength = 0L;
		envelopeInfoPtr->segHdrCount = 0;
		envelopeInfoPtr->segHdrState = SEGHDRSTATE_NONE;
		}
	else
		{
		/* Copy the local state information back into the envelope
		   structure */
		envelopeInfoPtr->segHdrSegLength = segmentLength;
		envelopeInfoPtr->segHdrCount = count;
		envelopeInfoPtr->segHdrState = state;
		}

	return( index );
	}

/* Copy possibly encrypted data into the envelope with special handling for
   block encryption modes.  Returns the number of bytes copied */

static int copyData( ENVELOPE_INFO *envelopeInfoPtr, const BYTE *buffer,
					 const int length )
	{
	BYTE *bufPtr = envelopeInfoPtr->buffer + envelopeInfoPtr->bufPos;
	int bytesToCopy;

	/* Figure out how much we can copy across.  First we calculate the
	   minimum of the amount of data passed in and the amount remaining in
	   the current segment */
	bytesToCopy = ( int ) min( envelopeInfoPtr->segmentSize, length );

	/* Now we check if this is affected by the total free space remaining in
	   the buffer.  If we're processing data blocks we can have two cases,
	   one in which the limit is the amount of buffer space available and the
	   other in which the limit is the amount of data available.  If the
	   limit is set by the available data, we don't have to worry about
	   flushing extra data out of the block buffer into the main buffer, but
	   if the limit is set by the available buffer space we have to reduce
	   the amount we can copy in based on any extra data which will be
	   flushed out of the block buffer.

	   There are two possible approaches which can be used when the block
	   buffer is involved.  The first one copies as much as we can into the
	   buffer and, if that isn't enough, maxes out the block buffer with as
	   much remaining data as possible.  The second only copies in as much as
	   can fit into the buffer, even if there's room in the block buffer for
	   a few more bytes.  The second approach is preferable because although
	   either will give the impression of a not-quite-full buffer into which
	   no more data can be copied, the second minimizes the amount of data
	   which is moved into and out of the block buffer.

	   The first approach may seem slightly more logical, but will only
	   cause confusion in the long run.  Consider copying (say) 43 bytes to
	   a 43-byte buffer.  The first time this will succeed, after which there
	   will be 40 bytes in the buffer (reported to the caller) and 3 in the
	   block buffer.  If the caller tries to copy in 3 more bytes to "fill"
	   the main buffer, they'll again vanish into the block buffer.  A second
	   call with three more bytes will copy 2 bytes and return with 1
	   uncopied.  In effect this method of using the block buffer extends the
	   blocksize-quantized main buffer by the size of the block buffer, which
	   at a glance seems to make sense but will only cause confusion because
	   data appears to vanish into the buffer */
	bytesToCopy = min( bytesToCopy, \
		( envelopeInfoPtr->bufSize - envelopeInfoPtr->bufPos ) - envelopeInfoPtr->blockBufferPos );
	assert( bytesToCopy >= 0 );

	/* If we're given a zero length, return now.  This can happen if all
	   input is consumed in processing the headers (we're passed a zero
	   length) */
	if( bytesToCopy == 0 )
		return( 0 );

	/* If its a block encryption mode we need to provide special handling for
	   odd data lengths which don't match the block size */
	if( envelopeInfoPtr->blockSize > 1 )
		{
		int bytesCopied = 0, quantizedBytesToCopy;

		/* If the new data will fit into the block buffer, copy it in now and
		   return */
		if( envelopeInfoPtr->blockBufferPos + bytesToCopy < \
			envelopeInfoPtr->blockSize )
			{
			memcpy( envelopeInfoPtr->blockBuffer + envelopeInfoPtr->blockBufferPos,
					buffer, bytesToCopy );
			envelopeInfoPtr->blockBufferPos += bytesToCopy;

			/* Adjust the segment size based on what we've consumed */
			envelopeInfoPtr->segmentSize -= bytesToCopy;

			return( bytesToCopy );
			}

		/* If there isn't room in the main buffer for even one more block,
		   exit without doing anything.  This leads to slightly anomalous
		   behaviour where, with no room for a complete block in the main
		   buffer, copying in a data length smaller than the block buffer
		   will lead to the data being absorbed by the block buffer due to
		   the previous section of code, but copying in a length larger than
		   the block buffer will result in no data at all being absorbed,
		   even if there is still room in the block buffer */
		if( envelopeInfoPtr->bufSize - envelopeInfoPtr->bufPos < \
			envelopeInfoPtr->blockSize )
			return( 0 );	/* No room for even one more block */

		/* There's room for at least one more block in the buffer.  First,
		   if there are leftover bytes in the block buffer move them into
		   the main buffer */
		if( envelopeInfoPtr->blockBufferPos )
			{
			memcpy( bufPtr, envelopeInfoPtr->blockBuffer,
					envelopeInfoPtr->blockBufferPos );
			bytesCopied = envelopeInfoPtr->blockBufferPos;
			}

		/* Determine how many bytes we can copy into the buffer to fill it
		   to the nearest available block size */
		quantizedBytesToCopy = ( bytesToCopy + bytesCopied ) & \
							   envelopeInfoPtr->blockSizeMask;
		quantizedBytesToCopy -= bytesCopied;
		assert( quantizedBytesToCopy >= 1 );

		/* Now copy across a number of bytes which is a multiple of the block
		   size and decrypt them */
		memcpy( bufPtr + bytesCopied, buffer, quantizedBytesToCopy );
		envelopeInfoPtr->bufPos += bytesCopied + quantizedBytesToCopy;
		envelopeInfoPtr->segmentSize -= bytesToCopy;
		krnlSendMessage( envelopeInfoPtr->iCryptContext, 
						 RESOURCE_IMESSAGE_CTX_DECRYPT, bufPtr,
						 bytesCopied + quantizedBytesToCopy );

		/* If the payload has a definite length and we've reached its end,
		   set the EOC flag to make sure we don't go any further */
		if( envelopeInfoPtr->payloadSize != CRYPT_UNUSED && \
			!envelopeInfoPtr->segmentSize )
			{
			int status;

			status = processEOC( envelopeInfoPtr );
			if( cryptStatusError( status ) )
				return( status );
			}
		else
			{
			/* Copy any remainder (the difference between the amount to copy
			   and the blocksize-quantized amount) into the block buffer */
			if( bytesToCopy - quantizedBytesToCopy )
				memcpy( envelopeInfoPtr->blockBuffer, buffer + quantizedBytesToCopy,
						bytesToCopy - quantizedBytesToCopy );
			envelopeInfoPtr->blockBufferPos = bytesToCopy - quantizedBytesToCopy;
			}

		return( bytesToCopy );
		}

	/* It's unencrypted or encrypted with a stream cipher, just copy over as
	   much of the segment as we can and decrypt it if necessary */
	if( bytesToCopy > envelopeInfoPtr->bufSize - envelopeInfoPtr->bufPos )
		bytesToCopy = envelopeInfoPtr->bufSize - envelopeInfoPtr->bufPos;
	memcpy( envelopeInfoPtr->buffer + envelopeInfoPtr->bufPos, buffer,
			bytesToCopy );
	envelopeInfoPtr->bufPos += bytesToCopy;
	envelopeInfoPtr->segmentSize -= bytesToCopy;
	if( envelopeInfoPtr->iCryptContext != CRYPT_ERROR )
		krnlSendMessage( envelopeInfoPtr->iCryptContext, 
						 RESOURCE_IMESSAGE_CTX_DECRYPT, bufPtr, bytesToCopy );

	/* If the payload has a definite length and we've reached its end, set
	   the EOC flag to make sure we don't go any further */
	if( envelopeInfoPtr->payloadSize != CRYPT_UNUSED && \
		!envelopeInfoPtr->segmentSize )
		{
		const int status = processEOC( envelopeInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( bytesToCopy );
	}

/* Copy data into the de-enveloping envelope.  Returns the number of bytes
   copied */

int copyToDeenvelope( ENVELOPE_INFO *envelopeInfoPtr, const BYTE *buffer,
					  int length )
	{
	BYTE *bufPtr = ( BYTE * ) buffer;
	int oldLength = length, bytesCopied;

	/* If we're trying to copy into a full buffer, return a count of 0 bytes
	   (the calling routine may convert this to an overflow error if
	   necessary) */
	if( envelopeInfoPtr->bufPos == envelopeInfoPtr->bufSize )
		return( 0 );

	/* If we're verifying a detached signature, just hash the data and exit.  
	   We don't have to check for problems with the context at this point 
	   since they'll be detected when we try and read the hash value */
	if( envelopeInfoPtr->detachedSig )
		{
		ACTION_LIST *hashActionPtr;

		for( hashActionPtr = envelopeInfoPtr->hashActions;
			 hashActionPtr != NULL && hashActionPtr->action == ACTION_HASH;
			 hashActionPtr = hashActionPtr->next )
			krnlSendMessage( hashActionPtr->iCryptHandle, 
							 RESOURCE_IMESSAGE_CTX_HASH, ( void * ) buffer, 
							 length );
		return( length );
		}

	/* Keep processing data until either we run out of input or we can't copy
	   in any more data.  The code sequence within this loop acts as a simple
	   FSM so that if we exit at any point then the next call to this
	   function will resume where we left off */
	do
		{
		int status;

		/* If there's no segment information available, we need to process a
		   segment header before we can handle any data */
		if( !envelopeInfoPtr->segmentSize )
			{
			status = getNextSegment( envelopeInfoPtr, bufPtr, length );
			if( cryptStatusError( status ) )
				return( status );
			bufPtr += status;
			length -= status;
			if( envelopeInfoPtr->endOfContents || !length )
				break;		/* EOC reached or all data consumed, exit */
			}

		/* Copy the (possibly encrypted) data into the envelope */
		bytesCopied = copyData( envelopeInfoPtr, bufPtr, length );
		if( cryptStatusError( bytesCopied ) )
			return( bytesCopied );
		bufPtr += bytesCopied;
		length -= bytesCopied;
		assert( envelopeInfoPtr->bufPos <= envelopeInfoPtr->bufSize );
		assert( length >= 0 );
		assert( envelopeInfoPtr->segmentSize >= 0 );
		}
	while( length > 0 && bytesCopied );

	return( oldLength - length );
	}

/* Copy data from the de-enveloping envelope.  Returns the number of bytes
   copied */

int copyFromDeenvelope( ENVELOPE_INFO *envelopeInfoPtr, BYTE *buffer,
						int length )
	{
	BYTE *bufPtr = envelopeInfoPtr->buffer;
	int bytesToCopy = length, bytesCopied, remainder;

	/* If we're verifying a detached sig, the data is communicated out-of-
	   band so there's nothing to copy out */
	if( envelopeInfoPtr->detachedSig )
		return( 0 );

	/* Copy out as much of the data as we can, making sure we don't overrun
	   into any following data */
	if( bytesToCopy > envelopeInfoPtr->bufPos )
		bytesToCopy = envelopeInfoPtr->bufPos;
	if( envelopeInfoPtr->dataLeft && bytesToCopy > envelopeInfoPtr->dataLeft )
		bytesToCopy = envelopeInfoPtr->dataLeft;

	/* If we're using a block encryption mode and we haven't seen the end-of-
	   contents yet and there's no data waiting in the block buffer
	   (which would mean that there's more data to come), we can't copy out
	   the last block because it might contain padding */
	if( envelopeInfoPtr->blockSize > 1 && !envelopeInfoPtr->endOfContents && \
		!envelopeInfoPtr->blockBufferPos )
		{
		bytesToCopy -= envelopeInfoPtr->blockSize;
		if( bytesToCopy <= 0 )
			return( 0 );
		}

	/* If we've seen the end-of-contents octets and there's no payload left
	   to copy out, or if we've ended up with nothing to copy (eg due to
	   blocking requirements), exit */
	if( ( envelopeInfoPtr->endOfContents && !envelopeInfoPtr->dataLeft ) || \
		!bytesToCopy )
		return( 0 );

	/* If we're using compression, copy the data from the buffer to the 
	   output via the zStream */
#ifndef NO_COMPRESSION
	if( envelopeInfoPtr->zStreamInited )
		{
		int status;

		/* Decompress the data into the output buffer */
		envelopeInfoPtr->zStream.next_in = bufPtr;
		envelopeInfoPtr->zStream.avail_in = bytesToCopy;
		envelopeInfoPtr->zStream.next_out = buffer;
		envelopeInfoPtr->zStream.avail_out = length;
		status = inflate( &envelopeInfoPtr->zStream, Z_SYNC_FLUSH );
		if( status != Z_OK && status != Z_STREAM_END )
			return( CRYPT_ERROR );

		/* Adjust the status information based on the data copied from the
		   buffer into the zStream (bytesCopied) and the data flushed from
		   the zStream to the output (bytesToCopy) */
		bytesCopied = bytesToCopy - envelopeInfoPtr->zStream.avail_in;
		bytesToCopy = length - envelopeInfoPtr->zStream.avail_out;
		}
	else
#endif /* NO_COMPRESSION */
		{
		ACTION_LIST *hashActionPtr;

		/* Hash the payload data if necessary.  We don't have to check for 
		   problems with the context at this point since they'll be detected 
		   when we try and read the hash value */
		for( hashActionPtr = envelopeInfoPtr->hashActions;
			 hashActionPtr != NULL && hashActionPtr->action == ACTION_HASH;
			 hashActionPtr = hashActionPtr->next )
			krnlSendMessage( hashActionPtr->iCryptHandle, 
							 RESOURCE_IMESSAGE_CTX_HASH, bufPtr, bytesToCopy );

		/* We're not using compression, copy the data across directly */
		memcpy( buffer, bufPtr, bytesToCopy );
		bytesCopied = bytesToCopy;
		}

	/* Move any remaining data down to the start of the buffer  */
	remainder = envelopeInfoPtr->bufPos - bytesCopied;
	if( remainder )
		memmove( bufPtr, bufPtr + bytesCopied, remainder );
	envelopeInfoPtr->bufPos = remainder;

	/* If there's data following the payload, adjust the end-of-payload
	   pointer to reflect the data we've just copied out */
	if( envelopeInfoPtr->dataLeft )
		envelopeInfoPtr->dataLeft -= bytesCopied;

	return( bytesToCopy );
	}
