/****************************************************************************
*																			*
*						   ASN.1 Core Library Routines						*
*						Copyright Peter Gutmann 1992-1999					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "asn1.h"
#else
  #include "crypt.h"
  #include "keymgmt/asn1.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Calculate the size of the encoded length octets */

static int calculateLengthSize( const long length )
	{
	if( length < 128 )
		/* Use short form of length octets */
		return( 1 );
	else
		/* Use long form of length octets: length-of-length followed by
		   32, 24, 16, or 8-bit length */
		return( 1 + ( ( length > 0xFFFFFFL ) ? 4 : \
					  ( length > 0xFFFF ) ? 3 : ( length > 0xFF ) ? 2 : 1 ) );
	}

/* Determine the encoded size of an object given only a length.  This can be
   used for a number of simple objects and avoids having to create an object
   only to destroy it after a single call to a sizeof() routine.  This is
   implemented as a function rather than a macro since the macro form would
   evaluate the length argument a great many times.

   The function checks for a length < 0 since this is frequently called with
   the output of another function which may return an error code */

long sizeofObject( const long length )
	{
	return( ( length < 0 ) ? length : \
			sizeof( BYTE ) + calculateLengthSize( length ) + length );
	}

/****************************************************************************
*																			*
*							ASN.1 Output Routines							*
*																			*
****************************************************************************/

/* Write the length octets for an ASN.1 data type */

void writeLength( STREAM *stream, long length )
	{
	/* Check if we can use the short form of length octets */
	if( length < 128 )
		sputc( stream, ( BYTE ) length );
	else
		{
		int noLengthOctets = ( length > 0xFFFFFFL ) ? 4 : \
							 ( length > 0xFFFFL ) ? 3 : \
							 ( length > 0xFF ) ? 2 : 1;

		/* Write number of length octets */
		sputc( stream, ( BYTE ) ( 0x80 | noLengthOctets ) );

		/* Write the length octets themselves */
		if( noLengthOctets > 3 )
			sputc( stream, ( BYTE ) ( length >> 24 ) );
		if( noLengthOctets > 2 )
			sputc( stream, ( BYTE ) ( length >> 16 ) );
		if( noLengthOctets > 1 )
			sputc( stream, ( BYTE ) ( length >> 8 ) );
		sputc( stream, ( BYTE ) length );
		}
	}

/* Write a (non-bignum) numeric value - used by several routines */

static void writeNumeric( STREAM *stream, const long integer )
	{
	BOOLEAN needsLZ = TRUE;
	BYTE buffer[ 5 ];
	int length = 0;

	/* Determine the number of bytes necessary to encode the integer and
	   encode it into a temporary buffer */
	if( integer < 0 )
		buffer[ length++ ] = 0;
	if( integer > 0x00FFFFFFL )
		{
		buffer[ length++ ] = ( BYTE ) ( integer >> 24 );
		needsLZ = FALSE;
		}
	if( integer >= 0x00800000L && needsLZ )
		buffer[ length++ ] = 0;
	if( integer > 0x0000FFFFL )
		{
		buffer[ length++ ] = ( BYTE ) ( integer >> 16 );
		needsLZ = FALSE;
		}
	if( integer >= 0x00008000L && needsLZ )
		buffer[ length++ ] = 0;
	if( integer > 0x000000FFL )
		{
		buffer[ length++ ] = ( BYTE ) ( integer >> 8 );
		needsLZ = FALSE;
		}
	if( integer >= 0x00000080L && needsLZ )
		buffer[ length++ ] = 0;
	buffer[ length++ ] = ( BYTE ) integer;

	/* Write the length and integer */
	writeLength( stream, length );
	swrite( stream, buffer, length );
	zeroise( buffer, sizeof( buffer ) );
	}

/* Write a short integer value */

int writeShortInteger( STREAM *stream, const long integer, const int tag )
	{
	/* Write the identifier and numeric fields */
	writeTag( stream, ( tag == DEFAULT_TAG ) ? \
			  BER_INTEGER : BER_CONTEXT_SPECIFIC | tag );
	writeNumeric( stream, integer );
	return( sGetStatus( stream ) );
	}

/* Write a bignum integer value */

int writeInteger( STREAM *stream, const BYTE *integer,
				  const int integerLength, const int tag )
	{
	const BOOLEAN leadingZero = integerLength && ( *integer & 0x80 ) ? 1 : 0;

	/* Write the identifier field */
	writeTag( stream, ( tag == DEFAULT_TAG ) ? \
			  BER_INTEGER : BER_CONTEXT_SPECIFIC | tag );

	/* Write it as a big-endian long value.  We have to be careful about how
	   we handle values with the high bit set since the internal format is
	   unsigned while ASN.1 values are signed */
	writeLength( stream, integerLength + leadingZero );
	if( leadingZero )
		sputc( stream, 0 );
	swrite( stream, integer, integerLength );

	return( sGetStatus( stream ) );
	}

/* Write an enumerated value */

int writeEnumerated( STREAM *stream, const int enumerated, const int tag )
	{
	/* Write the identifier and numeric fields */
	writeTag( stream, ( tag == DEFAULT_TAG ) ? \
			  BER_ENUMERATED : BER_CONTEXT_SPECIFIC | tag );
	writeNumeric( stream, ( long ) enumerated );
	return( sGetStatus( stream ) );
	}

/* Write a null value */

int writeNull( STREAM *stream, const int tag )
	{
	/* Write the identifier and null length octet */
	writeTag( stream, ( tag == DEFAULT_TAG ) ? \
			  BER_NULL : BER_CONTEXT_SPECIFIC | tag );
	sputc( stream, 0 );
	return( sGetStatus( stream ) );
	}

/* Write a boolean value */

int writeBoolean( STREAM *stream, const BOOLEAN boolean, const int tag )
	{
	/* Write the identifier and boolean value */
	writeTag( stream, ( tag == DEFAULT_TAG ) ? \
			  BER_BOOLEAN : BER_CONTEXT_SPECIFIC | tag );
	sputc( stream, 1 );							/* Length is one byte */
	sputc( stream, boolean ? 0xFF : 0 );
	return( sGetStatus( stream ) );
	}

/* Write an octet string */

int writeOctetString( STREAM *stream, const BYTE *string, const int length,
					  const int tag )
	{
	/* Write the identifier and string fields */
	writeTag( stream, ( tag == DEFAULT_TAG ) ? \
			  BER_OCTETSTRING : BER_CONTEXT_SPECIFIC | tag );
	writeLength( stream, length );
	swrite( stream, string, length );
	return( sGetStatus( stream ) );
	}

/* Write a character string.  This handles any of the myriad ASN.1 character
   string types.  The handling of the tag works somewhat differently here to
   the usual manner in that since the function is polymorphic, the tag 
   defines the character string type and is always used (there's no 
   DEFAULT_TAG like the other functions use) */

int writeCharacterString( STREAM *stream, const BYTE *string,
						  const int length, const int tag )
	{
	writeTag( stream, tag );
	writeLength( stream, length );
	swrite( stream, string, length );
	return( sGetStatus( stream ) );
	}

/* Write a bit string */

int writeBitString( STREAM *stream, const int bitString, const int tag )
	{
	BYTE buffer[ 5 ];
	int data = bitString, value = 0, noBits = 0, i;

	/* ASN.1 bitstrings start at bit 0, so we need to reverse the order of
	  the bits before we write it out */
	for( i = 0; i < 16; i++ )
		{
		/* Update the number of significant bits */
		if( data )
			noBits++;

		/* Reverse the bits */
		value <<= 1;
		if( data & 1 )
			value |= 1;
		data >>= 1;
		}

	/* Write the data as an ASN.1 BITSTRING */
	buffer[ 0 ] = ( tag == DEFAULT_TAG ) ? BER_BITSTRING : \
				  BER_CONTEXT_SPECIFIC | tag;
	buffer[ 1 ] = 1 + ( ( noBits + 7 ) >> 3 );
	buffer[ 2 ] = ~( ( noBits - 1 ) & 7 ) & 7;
	buffer[ 3 ] = value >> 8;
	buffer[ 4 ] = value & 0xFF;
	return( swrite( stream, buffer, 3 + ( ( noBits + 7 ) >> 3 ) ) );
	}

/* Write a canonical UTCTime and GeneralizedTime value */

int writeUTCTime( STREAM *stream, const time_t time, const int tag )
	{
	struct tm *timeInfo = gmtime( &time );
	char buffer[ 20 ];

	/* Print the main time fields */
	sprintf( buffer, "%02d%02d%02d%02d%02d%02dZ", timeInfo->tm_year % 100,
			 timeInfo->tm_mon + 1, timeInfo->tm_mday, timeInfo->tm_hour,
			 timeInfo->tm_min, timeInfo->tm_sec );

	/* Write the identifier and length fields */
	writeTag( stream, ( tag == DEFAULT_TAG ) ? \
			  BER_TIME_UTC : BER_CONTEXT_SPECIFIC | tag );
	writeLength( stream, 13 );

	/* Write the time string */
	swrite( stream, ( BYTE * ) buffer, 13 );
	return( sGetStatus( stream ) );
	}

int writeGeneralizedTime( STREAM *stream, const time_t time, const int tag )
	{
	struct tm *timeInfo = gmtime( &time );
	char buffer[ 20 ];

	/* Print the main time fields */
	sprintf( buffer, "%04d%02d%02d%02d%02d%02dZ", timeInfo->tm_year + 1900,
			 timeInfo->tm_mon + 1, timeInfo->tm_mday, timeInfo->tm_hour,
			 timeInfo->tm_min, timeInfo->tm_sec );

	/* Write the identifier and length fields */
	writeTag( stream, ( tag == DEFAULT_TAG ) ? \
			  BER_TIME_GENERALIZED : BER_CONTEXT_SPECIFIC | tag );
	writeLength( stream, 15 );

	/* Write the time string */
	swrite( stream, ( BYTE * ) buffer, 15 );
	return( sGetStatus( stream ) );
	}

/****************************************************************************
*																			*
*							ASN.1 Input Routines							*
*																			*
****************************************************************************/

#if 0		/* Only needed for tags > 32, which nothing seems to use */

/* Read a value in 7-bit flagged format */

static int readFlagged( STREAM *stream, long *flaggedValue )
	{
	long value = 0L;
	int readDataLength = 1, count = 4;
	BYTE data;

	/* Read the high octets (if any) with flag bits set, followed by
	   the final octet */
	data = sgetc( stream );
	while( count-- && ( data & 0x80 ) )
		{
		int ch;

		value <<= 7;
		value |= data & 0x7F;
		ch = sgetc( stream );
		if( ch == CRYPT_EMPTY || ch == CRYPT_DATA_READ )
			return( CRYPT_ERROR_BADDATA );
		data = ch;
		readDataLength++;
		}
	*flaggedValue = value | data;
	if( count <= 0 )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( CRYPT_ERROR_BADDATA );
		}

	return( readDataLength );
	}
#endif /* 0 */

/* Undo a read for when we're looking ahead for a certain tagged type.  Note
   that care must be taken when calling this to ensure that the cause for the
   initial read failing wasn't an EOF, because unreading the data will reset
   the EOF indicator */

int unreadTag( STREAM *stream )
	{
	/* This code isn't very general-purpose in that it assumes that the tag
	   will fit into a single octet.  However since we're only going to use
	   this to undo lookahead for context-specific tags of optional types,
	   this should be safe */
	sungetc( stream );
	return( 1 );
	}

/* Get a tag without actually reading it, useful for when there are a series
   of complex OPTIONAL values which can be handled in a switch statement */

int peekTag( STREAM *stream )
	{
	int tag;

	/* Make sure we're not at the end of the stream (an unreadTag() at this
	   point would have the side-effect of clearing the EOF marker) */
	if( sIsEmpty( stream ) )
		return( CRYPT_ERROR_UNDERFLOW );

	/* Read the tag and push it back into the stream */
	tag = readTag( stream );
	unreadTag( stream );

	return( tag );
	}

/* Read and check the type of a tag */

BOOLEAN checkReadTag( STREAM *stream, const int tag )
	{
	/* Make sure we're not at the end of the stream (an unreadTag() at this
	   point would have the side-effect of clearing the EOF marker) */
	if( sIsEmpty( stream ) )
		return( FALSE );

	/* Read the tag and check if it's the correct type */
	if( readTag( stream ) != tag )
		{
		unreadTag( stream );
		return( FALSE );
		}
	return( TRUE );
	}

/* Read and check the type of a context-specific tag */

BOOLEAN checkReadCtag( STREAM *stream, const int identifier,
					   const BOOLEAN isConstructed )
	{
	const int tag = BER_CONTEXT_SPECIFIC | \
					( isConstructed ? BER_CONSTRUCTED : 0 ) | identifier;

	/* Make sure we're not at the end of the stream (an unreadTag() at this
	   point would have the side-effect of clearing the EOF marker) */
	if( sIsEmpty( stream ) )
		return( 0 );

	/* Read the tag and check if it's the correct type */
	if( readTag( stream ) != tag )
		{
		unreadTag( stream );
		return( FALSE );
		}
	return( TRUE );
	}

/* Check for constructed end-of-item octets */

BOOLEAN checkEOC( STREAM *stream )
	{
	int tag;

	/* Make sure we're not at the end of the stream (an unreadTag() at this
	   point would have the side-effect of clearing the EOF marker) */
	if( sIsEmpty( stream ) )
		return( FALSE );

	/* Read the tag and check for an EOC octet pair */
	tag = readTag( stream );
	if( tag )
		{
		unreadTag( stream );
		return( FALSE );
		}
	if( readTag( stream ) )
		{
		/* After finding an EOC tag we need to have a length of zero */
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( FALSE );
		}

	return( TRUE );
	}

/* Read the length octets for an ASN.1 data type */

int readLength( STREAM *stream, long *length )
	{
	int readDataLength = 1;
	BYTE data;

	if( length != NULL )
		*length = 0;	/* Clear return value */
	data = sgetc( stream );
	if( !( data & 0x80 ) )
		{
		/* Data is encoded in short form */
		if( length != NULL )
			*length = ( long ) data;
		}
	else
		{
		/* Data is encoded in long form.  First get the octet count */
		int noLengthOctets = data & 0x7F;
		long localLength = 0;

		/* Now read the length octets themselves */
		while( noLengthOctets-- > 0 )	/* Terminates after max.127 iterations */
			{
			localLength <<= 8;
			localLength |= ( unsigned int ) sgetc( stream );
			readDataLength++;
			}
		if( localLength < 0 )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( CRYPT_ERROR_BADDATA );
			}
		if( length != NULL )
			*length = localLength;
		}

	if( sGetStatus( stream ) != CRYPT_OK )
		return( sGetStatus( stream ) );
	return( readDataLength );
	}

/* Read a short (<= 256 bytes) raw object without decoding it.  This is used
   to read short data blocks like object identifiers which are only ever
   handled in encoded form */

int readRawObject( STREAM *stream, BYTE *buffer, int *bufferLength,
				   const int maxLength, const int expectedTag )
	{
	int remainder = 0, tag, length, offset = 2;

	/* Clear return value */
	*buffer = '\0';
	*bufferLength = 0;

	/* Read the identifier field and length.  Since we need to remember each
	   byte as it is read we can't just call readLength() for the length,
	   but since we only need to handle lengths which can be encoded in one
	   or two bytes this isn't much of a problem */
	tag = readTag( stream );
	if( expectedTag != CRYPT_UNUSED && expectedTag != tag )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( sGetStatus( stream ) );
		}
	length = sgetc( stream );
	if( length & 0x80 )
		{
		if( ( length & 0x7F ) > 1 )
			{
			/* If the object is longer than 256 bytes, we can't handle it */
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( sGetStatus( stream ) );
			}
		buffer[ 2 ] = sgetc( stream );
		offset++;
		}
	buffer[ 0 ] = tag;
	buffer[ 1 ] = length;

	/* Read in the object, limiting the size to the maximum buffer size */
	if( length > maxLength - offset )
		{
		remainder = length - ( maxLength - offset );
		length = maxLength - offset;
		}
	sread( stream, buffer + offset, length );
	*bufferLength = offset + length;

	/* Read in any remaining data if necessary */
	if( remainder )
		sSkip( stream, remainder );

	if( sGetStatus( stream ) != CRYPT_OK )
		return( sGetStatus( stream ) );
	return( offset + length + remainder );
	}

/* Read a (short) numeric value - used by several routines */

static int readNumeric( STREAM *stream, long *value )
	{
	int readDataLength;
	long length;

	/* Clear return value */
	*value = 0L;

	/* Read the length field */
	readDataLength = readLength( stream, &length );
	readDataLength += ( int ) length;

	/* Make sure it's a short value and read the data */
	if( length > sizeof( long ) )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( CRYPT_ERROR_BADDATA );
		}
	while( length-- > 0 )	/* Terminates after sizeof( long ) iterations */
		*value = ( *value <<= 8 ) | sgetc( stream );

	if( sGetStatus( stream ) != CRYPT_OK )
		return( sGetStatus( stream ) );
	return( readDataLength );
	}

/* Read a bignum integer value */

int readIntegerTag( STREAM *stream, BYTE *integer, int *integerLength,
					const int maxLength, const int tag )
	{
	int readDataLength = 0, remainder = 0, status;
	long length;

	/* Clear return value */
	*integerLength = 0;

	/* Read the identifier field if necessary */
	if( tag != NO_TAG )
		{
		if( readTag( stream ) != selectTag( tag, BER_INTEGER ) )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( sGetStatus( stream ) );
			}
		readDataLength++;
		}

	/* Read the length field */
	readDataLength += readLength( stream, &length );
	readDataLength += ( int ) length;

	/* ASN.1 encoded values are signed while the internal representation is
	   unsigned, so we skip any leading zero bytes needed to encode a value
	   which has the high bit set */
	if( sgetc( stream ) )
		sungetc( stream );	/* It's not zero, put it back */
	else
		length--;			/* Skip the zero byte */
	*integerLength = ( int ) length;

	/* Now read in the numeric value, limiting the size to the maximum buffer
	   size */
	if( length > maxLength )
		{
		remainder = ( int ) length - maxLength;
		length = maxLength;
		}
	if( length && \
		( status = sread( stream, integer, ( int ) length ) ) != CRYPT_OK )
		return( status );

	/* Read in any remaining data */
	if( remainder )
		sSkip( stream, remainder );

	if( sGetStatus( stream ) != CRYPT_OK )
		return( sGetStatus( stream ) );
	return( readDataLength );
	}

/* Read a universal type and discard it (used to skip unknown or unwanted
   types) */

int readUniversalData( STREAM *stream )
	{
	long length;
	int readDataLength = readLength( stream, &length );

	readDataLength += ( int ) length;
	if( length )
		sSkip( stream, ( int ) length );

	if( sGetStatus( stream ) != CRYPT_OK )
		return( sGetStatus( stream ) );
	return( readDataLength );
	}

int readUniversal( STREAM *stream )
	{
	readTag( stream );
	return( readUniversalData( stream ) + 1 );
	}

/* Read a short integer value */

int readShortIntegerTag( STREAM *stream, long *value, const int tag )
	{
	int readDataLength = 0;

	/* Clear return value */
	*value = 0L;

	/* Read the identifier field if necessary */
	if( tag != NO_TAG )
		{
		if( readTag( stream ) != selectTag( tag, BER_INTEGER ) )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( sGetStatus( stream ) );
			}
		readDataLength++;
		}

	/* Read the numeric field */
	readDataLength += readNumeric( stream, value );

	if( sGetStatus( stream ) != CRYPT_OK )
		return( sGetStatus( stream ) );
	return( readDataLength );
	}

/* Read an enumerated value.  This is encoded like an ASN.1 integer so we
   just read it as such.  The return value can cause problems with the IBM
   OS/2 compiler which uses variable-length enums based on the enum range
   (it's allowed to do this according to ANSI, although it's pretty silly in
   a 32-bit environment), so you can't assign the result directly to an enum
   but need to go via a separate integer variable */

int readEnumeratedTag( STREAM *stream, int *enumeration, const int tag )
	{
	long value;
	int readDataLength = 0;

	/* Clear return value */
	*enumeration = 0;

	/* Read the identifier field if necessary */
	if( tag != NO_TAG )
		{
		if( readTag( stream ) != selectTag( tag, BER_ENUMERATED ) )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( sGetStatus( stream ) );
			}
		readDataLength++;
		}

	/* Read the numeric field and extract the enumerated type */
	readDataLength += readNumeric( stream, &value );
	*enumeration = ( int ) value;

	if( sGetStatus( stream ) != CRYPT_OK )
		return( sGetStatus( stream ) );
	return( readDataLength );
	}

/* Read a null value */

int readNullTag( STREAM *stream, const int tag )
	{
	int readDataLength = 0;

	/* Read the identifier if necessary */
	if( tag != NO_TAG )
		{
		if( readTag( stream ) != selectTag( tag, BER_NULL ) )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( sGetStatus( stream ) );
			}
		readDataLength++;
		}

	/* Skip the length octet */
	if( sgetc( stream ) )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( sGetStatus( stream ) );
		}

	if( sGetStatus( stream ) != CRYPT_OK )
		return( sGetStatus( stream ) );
	return( readDataLength + 1 );
	}

/* Read a boolean value */

int readBooleanTag( STREAM *stream, BOOLEAN *boolean, const int tag )
	{
	int readDataLength = 0;

	/* Read the identifier if necessary */
	if( tag != NO_TAG )
		{
		if( readTag( stream ) != selectTag( tag, BER_BOOLEAN ) )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( sGetStatus( stream ) );
			}
		readDataLength++;
		}

	/* Skip length octet and read boolean value */
	if( sgetc( stream ) != 1 )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( sGetStatus( stream ) );
		}
	*boolean = sgetc( stream ) ? TRUE : FALSE;

	if( sGetStatus( stream ) != CRYPT_OK )
		return( sGetStatus( stream ) );
	return( readDataLength + 2 );
	}

/* Read an octet string value */

int readOctetStringTag( STREAM *stream, BYTE *string, int *stringLength,
						const int maxLength, const int tag )
	{
	int readDataLength = 0, remainder = 0;
	long length;

	/* Clear return value */
	*stringLength = 0;

	/* Read the identifier field if necessary */
	if( tag != NO_TAG )
		{
		if( readTag( stream ) != selectTag( tag, BER_OCTETSTRING ) )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( sGetStatus( stream ) );
			}
		readDataLength++;
		}

	/* Now read in the string, limiting the size to the maximum buffer size */
	readDataLength += readLength( stream, &length );
	if( length > maxLength )
		{
		remainder = ( int ) length - maxLength;
		length = maxLength;
		}
	sread( stream, string, ( int ) length );
	*stringLength = ( int ) length;

	/* Read in any remaining data */
	if( remainder )
		sSkip( stream, remainder );

	if( sGetStatus( stream ) != CRYPT_OK )
		return( sGetStatus( stream ) );
	return( readDataLength + ( int ) length );
	}

/* Read a bit string */

int readBitStringTag( STREAM *stream, int *bitString, const int tag )
	{
	unsigned int data, mask = 0x80;
	int readDataLength = 0, length, flag = 1, value = 0, noBits, i;

	/* Read the identifier field if necessary */
	if( tag != NO_TAG )
		{
		if( readTag( stream ) != selectTag( tag, BER_BITSTRING ) )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( sGetStatus( stream ) );
			}
		readDataLength++;
		}

	/* Make sure we have a bitstring with between 0 and 16 bits */
	length = sgetc( stream ) - 1;
	noBits = sgetc( stream );
	readDataLength += 2;
	if( length < 0 || length > 2 || noBits < 0 || noBits > 7 )
		return( CRYPT_ERROR_BADDATA );
	if( !length )
		return( 0 );
	noBits = ( length * 8 ) - noBits;

	/* ASN.1 bitstrings start at bit 0, so we need to reverse the order of
	   the bits */
	data = sgetc( stream );
	if( noBits > 8 )
		{
		data = ( data << 8 ) | sgetc( stream );
		mask = 0x8000;
		}
	for( i = 0; i < noBits; i++ )
		{
		if( data & mask )
			value |= flag;
		flag <<= 1;
		data <<= 1;
		}
	*bitString = value;

	if( sGetStatus( stream ) != CRYPT_OK )
		return( sGetStatus( stream ) );
	return( readDataLength + ( int ) length );
	}

/* Read a UTCTime and GeneralizedTime value */

static int getDigits( STREAM *stream )
	{
	int result, ch = sgetc( stream );

	if( isdigit( ch ) )
		{
		result = ( ch - '0' ) * 10;
		ch = sgetc( stream );
		if( isdigit( ch ) )
			return( result + ( ch - '0' ) );
		}

	return( -1 );
	}

static int readTime( STREAM *stream, time_t *timePtr, const BOOLEAN isUTCTime )
	{
	struct tm theTime;
	long length;
	int readDataLength, value = 0, status = CRYPT_OK;

	*timePtr = 0;

	/* Read the length field and make sure it's of the correct size.  There's
	   only one encoding allowed, in theory the encoded value could range in
	   length from 11 to 17 bytes for UTCTime and 13 to 19 bytes for
	   GeneralizedTime.  In practice we also have to allow 11-byte UTCTime's
	   since an obsolete encoding rule allowed the time to be encoded without
	   seconds, and Sweden Post haven't realised that this has changed yet */
	readDataLength = readLength( stream, &length );
	if( ( isUTCTime && length != 13 && length != 11 ) || \
		( !isUTCTime && length != 15 ) )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( sGetStatus( stream ) );
		}
	readDataLength += ( int ) length;

	/* Decode the time fields.  Ideally we should use sscanf(), but there
	   are too many dodgy versions of this around */
	memset( &theTime, 0, sizeof( struct tm ) );
	theTime.tm_isdst = -1;		/* Get system to adjust for DST */
	if( !isUTCTime )
		value = ( getDigits( stream ) - 19 ) * 100;	/* Read the century */
	theTime.tm_year = getDigits( stream ) + value;
	theTime.tm_mon = getDigits( stream ) - 1;
	theTime.tm_mday = getDigits( stream );
	theTime.tm_hour = getDigits( stream );
	theTime.tm_min = getDigits( stream );
	length -= ( isUTCTime ) ? 10 : 12;

	/* Read any extra fields if necessary */
	if( length )
		{
		int ch = sgetc( stream );

		/* Read the seconds field if there is one present */
		if( length >= 2 && isdigit( ch ) )
			{
			sungetc( stream );
			theTime.tm_sec = getDigits( stream );
			length -= 2;
			if( length )
				ch = sgetc( stream );
			}

#if 0	/* The allowed UTCTime and GeneralizedTime formats don't provide for
		   the following */
		/* Read the time differential if there is one.  Since the
		   differential is given as the difference between GMT and the local
		   time, the sign of the amount to add is the opposite of the
		   differential sign (eg GMT-0500 means add 5 hours to get GMT) */
		if( length == 5 && ( ch == '-' || ch == '+' ) )
			{
			int sign = ( ch == '-' ) ? 1 : -1;
			int hourOffset, minuteOffset;

			hourOffset = getDigits( stream );
			minuteOffset = getDigits( stream );
			if( ( minuteOffset | hourOffset ) == -1 )
				status = CRYPT_ERROR_BADDATA;
			theTime.tm_hour += hourOffset * sign;
			theTime.tm_min += minuteOffset * sign;
			}
		else
			/* If there's anything left, the data format is wrong */
			if( length && !( length == 1 && ch == 'Z' ) )
				status = CRYPT_ERROR_BADDATA;
#else
		if( length != 1 || ch != 'Z' )
			status = CRYPT_ERROR_BADDATA;
#endif /* 0 */
		}

	/* Make sure there were no format errors */
	if( ( theTime.tm_year | theTime.tm_mon | theTime.tm_mon | \
		  theTime.tm_mday | theTime.tm_hour | theTime.tm_min | \
		  theTime.tm_sec ) < 0 )
		status = CRYPT_ERROR_BADDATA;

	/* Finally, convert it to the local time.  Since the UTCTime format
	   doesn't take centuries into account (and you'd think that when the ISO
	   came up with the worlds least efficient time encoding format they
	   could have spared another two bytes to fully specify the year), we
	   have to adjust by one century for years < 50 (and hope there aren't
	   any Y2K bugs in mktime()) if the format is UTCTime.  Note that there
	   are some implementations which currently roll over a century from 1970
	   (the Unix/ISO/ANSI C epoch), but hopefully these will be fixed by
	   2050.

		"The time is out of joint; o cursed spite,
		 That ever I was born to set it right"	- Shakespeare, "Hamlet" */
	if( isUTCTime && theTime.tm_year < 50 )
		theTime.tm_year += 100;
	if( status == CRYPT_OK )
		{
		time_t utcTime = mktime( &theTime );

		if( utcTime == -1 )
			status = CRYPT_ERROR_BADDATA;
		else
			{
			const time_t localTime = time( NULL );
			struct tm *gm_tm;
			time_t gmTime;

			/* Conver the UTC time to local time.  This is complicated by the
			   fact that although the C standard library can convert from
			   local time -> UTC, it can't convert the time back, so we
			   calculate the local offset from UTC and adjust the time as
			   appropriate.  Since we can't assume that time_t is signed, we
			   have to treat a negative and positive offset separately.  An
			   extra complication is added by daylight savings time 
			   adjustment, some systems adjust for DST by default, some don't,
			   and some allow you to set it in the Control Panel so it varies
			   from machine to machine (thanks Bill!), so we have to make it 
			   explicit as part of the conversion process */
			gm_tm = gmtime( &localTime );
			gm_tm->tm_isdst = -1;		/* Force correct DST adjustment */
			gmTime = mktime( gm_tm );
			if( localTime < gmTime )
				*timePtr = utcTime - ( gmTime - localTime );
			else
				*timePtr = utcTime + ( localTime - gmTime );
			}
		}
	if( status == CRYPT_ERROR_BADDATA )
		sSetError( stream, CRYPT_ERROR_BADDATA );
	if( sGetStatus( stream ) != CRYPT_OK )
		return( sGetStatus( stream ) );
	return( readDataLength );
	}

int readUTCTimeTag( STREAM *stream, time_t *time, const int tag )
	{
	int readDataLength = 0;

	/* Read the identifier field if necessary */
	if( tag != NO_TAG )
		{
		if( readTag( stream ) != selectTag( tag, BER_TIME_UTC ) )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( sGetStatus( stream ) );
			}
		readDataLength++;
		}

	/* Read the time fields */
	readDataLength += readTime( stream, time, TRUE );
	if( sGetStatus( stream ) != CRYPT_OK )
		return( sGetStatus( stream ) );
	return( readDataLength );
	}

int readGeneralizedTimeTag( STREAM *stream, time_t *time, const int tag )
	{
	int readDataLength = 0;

	/* Read the identifier field if necessary */
	if( tag != NO_TAG )
		{
		if( readTag( stream ) != selectTag( tag, BER_TIME_GENERALIZED ) )
			{
			sSetError( stream, CRYPT_ERROR_BADDATA );
			return( sGetStatus( stream ) );
			}
		readDataLength++;
		}

	/* Read the time fields */
	readDataLength += readTime( stream, time, FALSE );
	if( sGetStatus( stream ) != CRYPT_OK )
		return( sGetStatus( stream ) );
	return( readDataLength );
	}

/****************************************************************************
*																			*
*					Utility Routines for Constructed Objects				*
*																			*
****************************************************************************/

/* Read the start of an encapsulating SEQUENCE and SET */

static int readObjectHeader( STREAM *stream, int *length, int tag )
	{
	int readDataLength;
	long dataLength;

	if( length != NULL )
		*length = 0;	/* Clear return value */
	if( readTag( stream ) != tag )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( sGetStatus( stream ) );
		}
	readDataLength = readLength( stream, &dataLength ) + 1;
	if( length != NULL )
		*length = ( int ) dataLength;

	if( sGetStatus( stream ) != CRYPT_OK )
		return( sGetStatus( stream ) );
	return( readDataLength );
	}

int readSequence( STREAM *stream, int *length )
	{
	return( readObjectHeader( stream, length, BER_SEQUENCE ) );
	}

int readSet( STREAM *stream, int *length )
	{
	return( readObjectHeader( stream, length, BER_SET ) );
	}

int readConstructed( STREAM *stream, int *length, const int tag )
	{
	return( readObjectHeader( stream, length, MAKE_CTAG( tag ) ) );
	}

/* Write the start of an encapsulating SEQUENCE, SET, or generic tagged 
   constructed object.  The default type for the generic object is assumed
   to be a SEQUENCE */

int writeSequence( STREAM *stream, const int length )
	{
	writeTag( stream, BER_SEQUENCE );
	writeLength( stream, length );
	return( sGetStatus( stream ) );
	}

int writeSet( STREAM *stream, const int length )
	{
	writeTag( stream, BER_SET );
	writeLength( stream, length );
	return( sGetStatus( stream ) );
	}

int writeConstructed( STREAM *stream, const int length, const int tag )
	{
	writeTag( stream, ( tag == DEFAULT_TAG ) ? \
			  BER_SEQUENCE : MAKE_CTAG( tag ) );
	writeLength( stream, length );
	return( sGetStatus( stream ) );
	}

/* Recursively dig into an ASN.1 object to get its length.  This code is
   a stripped-down version of the ASN.1 checking code in keymgmt/certchk.c,
   see that module for more information */

#define MAX_NESTING_LEVEL	50
#define LENGTH_MAGIC		177545L

typedef struct {
	int id;						/* Identifier */
	int tag;					/* Tag */
	long length;				/* Data length */
	BOOLEAN indefinite;			/* Item has indefinite length */
	int headerSize;				/* Size of tag+length */
	} ASN1_ITEM;

static int getItem( STREAM *stream, ASN1_ITEM *item )
	{
	int tag, length;

	memset( item, 0, sizeof( ASN1_ITEM ) );
	item->indefinite = FALSE;
	tag = sgetc( stream );
	item->headerSize = 1;
	item->id = tag & ~BER_SHORT_ID_MASK;
	tag &= BER_SHORT_ID_MASK;
	if( tag == BER_SHORT_ID_MASK )
		{
		int value;

		/* Long tag encoded as sequence of 7-bit values.  This doesn't try to
		   handle tags > INT_MAX, it'd be pretty peculiar ASN.1 if it had to
		   use tags this large */
		tag = 0;
		do
			{
			value = sgetc( stream );
			tag = ( tag << 7 ) | ( value & 0x7F );
			item->headerSize++;
			}
		while( value & 0x80 && sGetStatus( stream ) == CRYPT_OK );
		}
	item->tag = tag;
	if( sGetStatus( stream ) != CRYPT_OK )
		return( sGetStatus( stream ) );
	length = sgetc( stream );
	item->headerSize++;
	if( length & 0x80 )
		{
		int i;

		length &= 0x7F;
		if( length > 4 )
			/* Object has a bad length field, usually because we've lost sync
			   in the decoder or run into garbage */
			return( CRYPT_ERROR_BADDATA );
		item->headerSize += length;
		item->length = 0;
		if( !length )
			item->indefinite = TRUE;
		for( i = 0; i < length; i++ )
			{
			int ch = sgetc( stream );

			item->length = ( item->length << 8 ) | ch;
			}
		}
	else
		item->length = length;

	return( CRYPT_OK );
	}

static int checkASN1( STREAM *stream, long length, const int isIndefinite,
					  const int level );

static int checkASN1object( STREAM *stream, const ASN1_ITEM *item,
							const int level )
	{

	/* Perform a sanity check */
	if( ( item->tag != BER_NULL ) && ( item->length < 0 ) )
		/* Object has a bad length field, usually because we've lost sync in
		   the decoder or run into garbage */
		return( CRYPT_ERROR_BADDATA );

	/* If it's a non-zero-length item, handle it as appropriate */
	if( item->length || item->indefinite )
		{
		/* If it's constructed, parse the nested object(s) */
		if( ( item->id & BER_CONSTRUCTED_MASK ) == BER_CONSTRUCTED )
			return( checkASN1( stream, item->length, item->indefinite,
							   level + 1 ) );

		/* It's primitive */
		sSkip( stream, item->length );
		return( CRYPT_OK );
		}

	/* At this point we have a zero-length object which should be an error,
	   however PKCS #10 has the attribute-encoding problem which produces
	   these objects so we can't complain about them */
	return( CRYPT_OK );
	}

static int checkASN1( STREAM *stream, long length, const int isIndefinite,
					  const int level )
	{
	ASN1_ITEM item;
	long lastPos = stell( stream );
	BOOLEAN seenEOC = FALSE;

	/* Sanity-check the nesting level */
	if( level > MAX_NESTING_LEVEL )
		return( CRYPT_ERROR_BADDATA );

	/* Special-case for zero-length objects */
	if( !length && !isIndefinite )
		return( CRYPT_OK );

	while( getItem( stream, &item ) == CRYPT_OK )
		{
		/* If the length isn't known and the item has a definite length, set
		   the length to the items length */
		if( length == LENGTH_MAGIC && !item.indefinite )
			length = item.headerSize + item.length;

		/* Check whether this is an EOC for an indefinite item */
		if( !item.indefinite && ( item.id | item.tag ) == BER_RESERVED )
			seenEOC = TRUE;
		else
			{
			int status;

			status = checkASN1object( stream, &item, level + 1 );
			if( cryptStatusError( status ) )
				return( status );
			}

		/* If it was an indefinite-length object (no length was ever set) and
		   we've come back to the top level, exit */
		if( length == LENGTH_MAGIC )
			return( 0 );

		length -= stell( stream ) - lastPos;
		lastPos = stell( stream );
		if( isIndefinite )
			{
			if( seenEOC )
				return( CRYPT_OK );
			}
		else
			if( length <= 0 )
				return( ( length < 0 ) ? CRYPT_ERROR_BADDATA : CRYPT_OK );
		}

	return( CRYPT_OK );
	}

int getObjectLength( const void *objectPtr, const int objectLength )
	{
	STREAM stream;
	long length;
	int dataLength, status;

	sMemConnect( &stream, objectPtr, objectLength );
	readTag( &stream );
	status = readLength( &stream, &length ) + 1;
	if( !cryptStatusError( status ) )
		{
		if( length )
			dataLength = ( int ) length + status;
		else
			{
			/* The object has an indefinite length, burrow down into it to 
			   find its actual length */
			sseek( &stream, 0 );
			status = checkASN1( &stream, LENGTH_MAGIC, FALSE, 1 );
			dataLength = ( int ) stell( &stream );
			}
		}
	sMemDisconnect( &stream );
	return( cryptStatusError( status ) ? status : dataLength );
	}
