/****************************************************************************
*																			*
*						 cryptlib Internal API Routines						*
*						Copyright Peter Gutmann 1992-1998					*
*																			*
****************************************************************************/

/* NSA motto: In God we trust... all others we monitor.
														-- Stanley Miller */
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "md2.h"
  #include "md4.h"
  #include "md5.h"
  #include "ripemd.h"
  #include "sha.h"
#else
  #include "hash/md2.h"
  #include "hash/md4.h"
  #include "hash/md5.h"
  #include "hash/ripemd.h"
  #include "hash/sha.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Internal API Functions						*
*																			*
****************************************************************************/

/* Determine the parameters for a particular hash algorithm */

BOOLEAN getHashParameters( const CRYPT_ALGO hashAlgorithm,
						   HASHFUNCTION *hashFunction, int *hashInputSize,
						   int *hashOutputSize, int *hashInfoSize )
	{
	void md2HashBuffer( void *hashInfo, BYTE *outBuffer, BYTE *inBuffer, \
						int length, const HASH_STATE hashState );
	void md4HashBuffer( void *hashInfo, BYTE *outBuffer, BYTE *inBuffer, \
						int length, const HASH_STATE hashState );
	void md5HashBuffer( void *hashInfo, BYTE *outBuffer, BYTE *inBuffer, \
						int length, const HASH_STATE hashState );
	void ripemd160HashBuffer( void *hashInfo, BYTE *outBuffer, BYTE *inBuffer, \
							  int length, const HASH_STATE hashState );
	void shaHashBuffer( void *hashInfo, BYTE *outBuffer, BYTE *inBuffer, \
						int length, const HASH_STATE hashState );

	switch( hashAlgorithm )
		{
		case CRYPT_ALGO_MD2:
			*hashFunction = md2HashBuffer;
			*hashInputSize = MD2_DATASIZE;
			*hashOutputSize = MD2_DIGESTSIZE;
			*hashInfoSize = sizeof( MD2_INFO );
			break;

#ifndef NO_MD4
		case CRYPT_ALGO_MD4:
			*hashFunction = md4HashBuffer;
			*hashInputSize = MD4_DATASIZE;
			*hashOutputSize = MD4_DIGESTSIZE;
			*hashInfoSize = sizeof( MD4_INFO );
			break;
#endif /* NO_MD4 */

		case CRYPT_ALGO_MD5:
			*hashFunction = md5HashBuffer;
			*hashInputSize = MD5_CBLOCK;
			*hashOutputSize = MD5_DIGEST_LENGTH;
			*hashInfoSize = sizeof( MD5_CTX );
			break;

		case CRYPT_ALGO_RIPEMD160:
			*hashFunction = ripemd160HashBuffer;
			*hashInputSize = RIPEMD160_DATASIZE;
			*hashOutputSize = RIPEMD160_DIGESTSIZE;
			*hashInfoSize = sizeof( RIPEMD160_INFO );
			break;

		case CRYPT_ALGO_SHA:
			*hashFunction = shaHashBuffer;
			*hashInputSize = SHA_CBLOCK;
			*hashOutputSize = SHA_DIGEST_LENGTH;
			*hashInfoSize = sizeof( SHA_CTX );
			break;

		default:
			return( FALSE );	/* API error, should never occur */
		}

	return( TRUE );
	}

/* Byte-reverse an array of 16- and 32-bit words to/from network byte order
   to account for processor endianness.  These routines assume the given
   count is a multiple of 16 or 32 bits.  They are safe even for CPU's with
   a word size > 32 bits since on a little-endian CPU the important 32 bits
   are stored first, so that by zeroizing the first 32 bits and oring the
   reversed value back in we don't need to rely on the processor only writing
   32 bits into memory */

void longReverse( LONG *buffer, int count )
	{
#if defined( _BIG_WORDS )
	BYTE *bufPtr = ( BYTE * ) buffer, temp;

	count /= 4;		/* sizeof( LONG ) != 4 */
	while( count-- )
		{
  #if 0
		LONG temp;

		/* This code is cursed */
		temp = value = *buffer & 0xFFFFFFFFUL;
		value = ( ( value & 0xFF00FF00UL ) >> 8  ) | \
				( ( value & 0x00FF00FFUL ) << 8 );
		value = ( ( value << 16 ) | ( value >> 16 ) ) ^ temp;
		*buffer ^= value;
		buffer = ( LONG * ) ( ( BYTE * ) buffer + 4 );
  #endif /* 0 */
		/* There's really no nice way to do this - the above code generates
		   misaligned accesses on processors with a word size > 32 bits, so
		   we have to work at the byte level (either that or turn misaligned
		   access warnings off by trapping the signal the access corresponds
		   to.  However a context switch per memory access is probably
		   somewhat slower than the current byte-twiddling mess) */
		temp = bufPtr[ 3 ];
		bufPtr[ 3 ] = bufPtr[ 0 ];
		bufPtr[ 0 ] = temp;
		temp = bufPtr[ 2 ];
		bufPtr[ 2 ] = bufPtr[ 1 ];
		bufPtr[ 1 ] = temp;
		bufPtr += 4;
		}
#elif defined( __WIN32__ )
	/* The following code which makes use of bswap is significantly faster
	   than what the compiler would otherwise generate.  This code is used
	   such a lot that it's worth the effort */
__asm {
	mov ecx, count
	mov edx, buffer
	shr ecx, 2
swapLoop:
	mov eax, [edx]
	bswap eax
	mov [edx], eax
	add edx, 4
	dec ecx
	jnz swapLoop
	}
#else
	LONG value;

	count /= sizeof( LONG );
	while( count-- )
		{
		value = *buffer;
		value = ( ( value & 0xFF00FF00UL ) >> 8  ) | \
				( ( value & 0x00FF00FFUL ) << 8 );
		*buffer++ = ( value << 16 ) | ( value >> 16 );
		}
#endif /* _BIG_WORDS */
	}

void wordReverse( WORD *buffer, int count )
	{
	WORD value;

	count /= sizeof( WORD );
	while( count-- )
		{
		value = *buffer;
		*buffer++ = ( value << 8 ) | ( value >> 8 );
		}
	}

/* Match a given substring against a string in a case-insensitive manner */

#if defined( __UNIX__ )

int strnicmp( const char *src, const char *dest, const int length )
	{
	return( strncasecmp( src, dest, length ) );
	}

int stricmp( const char *src, const char *dest )
	{
	return( strcasecmp( src, dest ) );
	}

#elif !( defined( __WINDOWS__ ) || defined( __MSDOS__ ) || \
		 defined( __OS2__ ) ) || defined( NT_DRIVER )

int strnicmp( const char *src, const char *dest, int length )
	{
	char srcCh, destCh;

	while( length-- )
		{
		/* Need to be careful with toupper() side-effects */
		srcCh = *src++;
		srcCh = toupper( srcCh );
		destCh = *dest++;
		destCh = toupper( destCh );

		if( srcCh != destCh )
			return( srcCh - destCh );
		}

	return( 0 );
	}

int stricmp( const char *src, const char *dest )
	{
	int length = strlen( src );

	if( length != strlen( dest ) )
		return( 1 );	/* Lengths differ */
	return( strnicmp( src, dest, length ) );
	}
#endif /* !( __WINDOWS__ || __MSDOS__ || __OS2__ ) || NT_DRIVER */

BOOLEAN matchSubstring( const char *subString, const char *string )
	{
	char firstChar = toupper( subString[ 0 ] );
	int subStringlength = strlen( subString ), i;

	/* Check trivial cases */
	if( subString == NULL || string == NULL )
		return( FALSE );
	if( strlen( string ) < ( size_t ) subStringlength )
		return( FALSE );

	/* Perform a case-insensitive match for the required substring in the
	   user ID */
	for( i = 0; string[ i ]; i++ )
		if( ( toupper( string[ i ] ) == firstChar ) &&
			!strnicmp( subString, string + i, subStringlength ) )
				return( TRUE );

	return( FALSE );
	}

/****************************************************************************
*																			*
*							Base64 En/Decoding Functions					*
*																			*
****************************************************************************/

/* Some interfaces can't handle binary data, so we base64-encode it using the
   following encode/decode tables (from RFC 1113) */

#define BPAD		'='		/* Padding for odd-sized output */
#define BERR		0xFF	/* Illegal char marker */
#define BEOF		0x7F	/* EOF marker (padding char or EOL) */

static char binToAscii[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static unsigned char asciiToBin[] =
	{ BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BEOF, BERR, BERR, BEOF, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, 0x3E, BERR, BERR, BERR, 0x3F,
	  0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
	  0x3C, 0x3D, BERR, BERR, BERR, BEOF, BERR, BERR,
	  BERR, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
	  0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
	  0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
	  0x17, 0x18, 0x19, BERR, BERR, BERR, BERR, BERR,
	  BERR, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
	  0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
	  0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
	  0x31, 0x32, 0x33, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR,
	  BERR, BERR, BERR, BERR, BERR, BERR, BERR, BERR
	};

/* The size of lines for PEM-type formatting.  This is only used for encoding,
   for decoding we adjust to whatever size the sender has used */

#define TEXT_LINESIZE	64
#define BINARY_LINESIZE	48

/* The EOL convention used when encoding a certificate object */

#if defined( __MSDOS16__ ) || defined( __MSDOS32__ ) || \
	defined( __WINDOWS__ ) || defined( __OS2__ )
  #define EOL		"\r\n"
  #define EOL_LEN	2
#elif defined( __UNIX__ ) || defined( __BEOS__ ) || defined( __AMIGA__ )
  #define EOL		"\n"
  #define EOL_LEN	1
#elif defined( __MAC__ )
  #define EOL		"\r"
  #define EOL_LEN	1
#else
  #error You need to add the OS-specific define to enable end-of-line handling
#endif /* OS-specific EOL markers */

/* Basic single-char en/decode functions */

#define encode(data)	binToAscii[ data ]
#define decode(data)	asciiToBin[ data ]

/* The headers and trailers used for base64-encoded certificate objects.
   Since the zero-th value is a non-value, we include a dummy entry at the
   start */

static const char *headerTbl[] = {
	NULL,
	"-----BEGIN CERTIFICATE-----" EOL,
	"-----BEGIN ATTRIBUTE CERTIFICATE-----" EOL,
	"-----BEGIN CERTIFICATE CHAIN-----" EOL,
	"-----BEGIN NEW CERTIFICATE REQUEST-----" EOL,
	"-----BEGIN CRL-----"  EOL
	};
static const char *trailerTbl[] = {
	NULL,
	"-----END CERTIFICATE-----" EOL,
	"-----END ATTRIBUTE CERTIFICATE-----" EOL,
	"-----END CERTIFICATE CHAIN-----" EOL,
	"-----END NEW CERTIFICATE REQUEST-----" EOL,
	"-----END CRL-----" EOL
	};

/* The header used for base64 S/MIME certificate chains */

static const char *smimeHeaderTbl[] = {
	NULL, NULL, NULL,
	"Content-Type: application/pkcs7-mime; smime-type=certs-only; "
		"name=smime.p7c" EOL
	"Content-Disposition: attachment; filename=smime.p7c" EOL
	"Content-Transfer-Encoding: base64" EOL EOL,
	"Content-Type: application/pkcs10; name=smime.p10" EOL
	"Content-Disposition: attachment; filename=smime.p10" EOL
	"Content-Transfer-Encoding: base64" EOL EOL
	};

/* Check whether a data item has a header which identifies it as some form of
   PEM-style encoded certificate object and return the start position of the
   encoded data.  Since there are so many variants possible, we don't perform
   a very strict check because there'll always be some new variants which
   isn't handled.  The exact object type can be determined by the lower-level
   routines */

int base64checkHeader( const char *data )
	{
	int index = 0;

	/* Sometimes the object can be preceded by a few blank lines - we're
	   fairly lenient with this */
	while( data[ index ] == '\r' || data[ index ] == '\n' )
		index++;

	/* We always have to start with 5 dashes and 'BEGIN '.  After this there
	   can be all sorts of stuff, but it has to end with another five dashes
	   and a newline */
	if( strncmp( data + index, "-----BEGIN ", 11 ) )
		return( 0 );
	index += 11;
	while( index < 40 && data[ index ] != '-' )
		index++;
	if( index == 40 || strncmp( data + index, "-----", 5 ) )
		return( 0 );
	index += 5;
	if( data[ index ] == '\n' )
		index++;
	else
		if( data[ index ] == '\r' )
			{
			index++;
			if( data[ index ] == '\n' )
				index++;
			}
		else
			return( 0 );

	return( index );
	}

/* Check whether a data item has a header which identifies it as some form of
   S/MIME certificate data.  This gets quite complex because there are many
   possible variations in the headers.  Some early S/MIME agents used a
   content type of "application/x-pkcs7-mime",
   "application/x-pkcs7-signature", and "application/x-pkcs10", while newer
   ones use the same without the "x-" at the start.  Older agents would put
   the filename in the Content-Type "name" parameter while newer ones put it
   in the optional Content-Disposition "filename" parameter (actually for
   backwards-compatibility most newer ones tend to include both).  The
   Content-Description is optional.  The general header format (all
   whitespace is optional) is:

	Content-Type: application/{x-} \
		pkcs7-mime{; name=|; smime-type= \
					 enveloped-data|signed-data|certs-only}
		pkcs7-signature{; name=}
		pkcs10{; name=}
	Content-Disposition: attachment{; filename=}
	Content-Transfer-Encoding: base64
	Content-Description: S/MIME {Cryptographic Signature|???}

   The result is that we have to create a somewhat nontrivial parser to
   handle all the variations.

   In addition Netscape have their own MIME data types for certificates:

	Content-Type: application/x-x509-{user-cert|ca-cert|email-cert}

   (probably with other bits as well, details unknown) which we also handle,
   although the exact cert type is ignored since it's up to the cert handling
   routines to sort this out via authenticated attributes rather than using
   the unauthenticated MIME content type */

/* Various nonspecific parsing routines */

static char *skipWhitespace( char *dataPtr )
	{
	if( dataPtr == NULL )
		return( NULL );
	while( *dataPtr == ' ' || *dataPtr == '\t' )
		dataPtr++;
	return( dataPtr );
	}

static char *skipEOL( char *dataPtr )
	{
	if( dataPtr == NULL )
		return( NULL );

	/* Skip a LF or a CR with optional LF */
	if( *dataPtr == '\n' )
		return( dataPtr + 1 );
	return( dataPtr + ( ( dataPtr[ 1 ] == '\n' ) ? 2 : 1 ) );
	}

static char *skipToNextToken( char *dataPtr )
	{
	if( dataPtr == NULL )
		return( NULL );

	/* If this is the end of the line, don't to anything */
	if( *dataPtr == '\r' || *dataPtr == '\n' )
		return( dataPtr );

	/* Skip to the start of the next token after the current one.  This
	   parses ";{ }{EOL }}" */
	if( *dataPtr != ';' )
		return( NULL );
	dataPtr = skipWhitespace( dataPtr + 1 );
	if( *dataPtr == '\r' || *dataPtr == '\n' )
		{
		/* The line is continued, skip the EOL and whitespace */
		dataPtr = skipEOL( dataPtr );
		if( *dataPtr != ' ' && *dataPtr != '\t' )
			return( NULL );	/* Should have whitespace after continuation */
		dataPtr = skipWhitespace( dataPtr );
		}

	return( dataPtr );
	}

static char *skipCurrentToken( char *dataPtr )
	{
	BOOLEAN isQuoted = FALSE;

	if( dataPtr == NULL )
		return( NULL );

	while( *dataPtr != '\n' && *dataPtr != '\r' )
		{
		if( !isQuoted && *dataPtr == ';' )
			/* If we reach an unquoted semicolon, we're at the end of the
			   token */
			return( skipToNextToken( dataPtr ) );
		if( *dataPtr == '"' )
			isQuoted = !isQuoted;
		dataPtr++;
		}

	return( isQuoted ? NULL : skipToNextToken( dataPtr ) );
	}

static char *skipLine( char *dataPtr )
	{
	BOOLEAN continuation;

	if( dataPtr == NULL )
		return( NULL );

	/* MIME headers can be continued over multiple lines.  If there's a
	   semicolon at the end of the current line, we continue to the next
	   one */
	do
		{
		continuation = FALSE;
		while( *dataPtr != '\r' && *dataPtr != '\n' )
			{
			if( ( *dataPtr & 0x7F ) < ' ' )
				return( NULL );	/* Sanity check */
			continuation = ( *dataPtr == ';' );
			dataPtr++;
			}
		if( continuation )
			dataPtr = skipToNextToken( dataPtr - 1 );
		}
	while( continuation );

	/* Check for a single EOL */
	return( skipEOL( dataPtr ) );
	}

/* Parse the various MIME header lines */

static char *parseContentType( char *dataPtr )
	{
	/* Look for "application/{x-}pkcs{7-mime|7-signature|10}" */
	dataPtr = skipWhitespace( dataPtr );
	if( strncmp( dataPtr, "application/", 12 ) )
		return( 0 );
	dataPtr += 12;
	if( !strncmp( dataPtr, "x-", 2 ) )
		dataPtr += 2;	/* Skip old-style "x-" header */
	if( !strncmp( dataPtr, "pkcs7-mime", 10 ) )
		dataPtr += 10;
	else
		if( !strncmp( dataPtr, "pkcs7-signature", 15 ) )
			dataPtr += 15;
		else
			if( !strncmp( dataPtr, "pkcs10", 6 ) )
				dataPtr += 6;
			else
				return( NULL );
	dataPtr = skipToNextToken( dataPtr );
	if( dataPtr == NULL || *dataPtr == '\r' || *dataPtr == '\r' )
		/* If that's all there is, return */
		return( skipEOL( dataPtr ) );

	/* Check for an optional old-style name attribute */
	if( !strncmp( dataPtr, "name=", 5 ) )
		{
		dataPtr = skipCurrentToken( skipWhitespace( dataPtr + 5 ) );
		if( dataPtr == NULL || *dataPtr == '\r' || *dataPtr == '\r' )
			/* If that's all there is, return */
			return( skipEOL( dataPtr ) );
		}

	/* Check for an SMIME type */
	if( strncmp( dataPtr, "smime-type=", 11 ) )
		return( NULL );
	dataPtr = skipWhitespace( dataPtr + 11 );
	if( strncmp( dataPtr, "signed-data", 11 ) && \
		strncmp( dataPtr, "certs-only", 10 ) )
		return( NULL );

	return( skipLine( dataPtr ) );
	}

static char *parseContentDisposition( char *dataPtr )
	{
	/* Look for "attachment" */
	dataPtr = skipWhitespace( dataPtr );
	if( !strncmp( dataPtr, "attachment", 10 ) )
		return( skipLine( dataPtr + 10 ) );
	if( !strncmp( dataPtr, "inline", 6 ) )
		return( skipLine( dataPtr + 6 ) );
	return( 0 );
	}

static char *parseContentTransferEncoding( char *dataPtr )
	{
	/* Look for "base64" */
	dataPtr = skipWhitespace( dataPtr );
	if( strncmp( dataPtr, "base64", 6 ) )
		return( 0 );
	return( skipLine( dataPtr + 6 ) );
	}

/* Check an S/MIME header.  Returns the length of the header */

int smimeCheckHeader( const char *data )
	{
	BOOLEAN seenContentType = FALSE, seenContentDisposition = FALSE;
	BOOLEAN seenContentTransferEncoding = FALSE;
	char *dataPtr = ( char * ) data;

	/* Sometimes the object can be preceded by a few blank lines - we're
	   fairly lenient with this */
	while( *dataPtr == '\r' || *dataPtr == '\n' )
		dataPtr++;

	/* Make sure there's a MIME content-type header there */
	if( *data != 'C' )
		return( 0 );
	while( *dataPtr != '\r' && *dataPtr != '\n' )
		{
		/* Check for the different types of content header which are
		   allowed */
		if( strncmp( dataPtr, "Content-", 8 ) )
			return( 0 );
		dataPtr += 8;
		if( !strncmp( dataPtr, "Type:", 5 ) )
			{
			if( seenContentType )
				return( FALSE );
			seenContentType = TRUE;

			/* Check for one of the Netscape cert types */
			dataPtr = skipWhitespace( dataPtr + 5 );
			if( !strncmp( dataPtr, "application/x-x509-", 19 ) )
				dataPtr = skipLine( dataPtr + 19 );
			else
				dataPtr = parseContentType( dataPtr );
			}
		else
			if( !strncmp( dataPtr, "Disposition:", 12 ) )
				{
				if( seenContentDisposition )
					return( FALSE );
				seenContentDisposition = TRUE;
				dataPtr = parseContentDisposition( dataPtr + 12 );
				}
			else
				if( !strncmp( dataPtr, "Transfer-Encoding:", 18 ) )
					{
					if( seenContentTransferEncoding )
						return( FALSE );
					seenContentTransferEncoding = TRUE;
					dataPtr = parseContentTransferEncoding( dataPtr + 18 );
					}
				else
					if( !strncmp( dataPtr, "Description:", 12 ) )
						{
						if( seenContentTransferEncoding )
							return( FALSE );
						dataPtr = skipLine( dataPtr + 12 );
						}
					else
						return( 0 );
		if( dataPtr == NULL )
			return( 0 );
		}

	/* Skip trailing blank lines */
	while( *dataPtr == '\r' || *dataPtr == '\n' )
		dataPtr++;
	return( ( int ) ( dataPtr - ( char * ) data ) );
	}

/* Encode a block of binary data into the base64 format, returning the total
   number of output bytes */

int base64encode( char *outBuffer, const void *inBuffer, const int count,
				  const CRYPT_CERTTYPE_TYPE certType,
				  const CRYPT_CERTFORMAT_TYPE format )
	{
	int srcIndex = 0, destIndex = 0, lineCount = 0, remainder = count % 3;
	BYTE *inBufferPtr = ( BYTE * ) inBuffer;

	/* If it's a certificate object, add the header */
	if( certType != CRYPT_CERTTYPE_NONE )
		{
		const char *headerPtr = \
			( format < CRYPT_CERTFORMAT_SMIME_CERTIFICATE ) ? \
			headerTbl[ certType ] : smimeHeaderTbl[ certType ];

		strcpy( outBuffer, headerPtr );
		destIndex = strlen( headerPtr );
		}

	/* Encode the data */
	while( srcIndex < count )
		{
		/* If we've reached the end of a line of binary data and it's a
		   certificate, add the EOL marker */
		if( certType != CRYPT_CERTTYPE_NONE && lineCount == BINARY_LINESIZE )
			{
			strcpy( outBuffer + destIndex, EOL );
			destIndex += EOL_LEN;
			lineCount = 0;
			}
		lineCount += 3;

		/* Encode a block of data from the input buffer */
		outBuffer[ destIndex++ ] = encode( inBufferPtr[ srcIndex ] >> 2 );
		outBuffer[ destIndex++ ] = encode( ( ( inBufferPtr[ srcIndex ] << 4 ) & 0x30 ) |
										   ( ( inBufferPtr[ srcIndex + 1 ] >> 4 ) & 0x0F ) );
		srcIndex++;
		outBuffer[ destIndex++ ] = encode( ( ( inBufferPtr[ srcIndex ] << 2 ) & 0x3C ) |
										   ( ( inBufferPtr[ srcIndex + 1 ] >> 6 ) & 0x03 ) );
		srcIndex++;
		outBuffer[ destIndex++ ] = encode( inBufferPtr[ srcIndex++ ] & 0x3F );
		}

	/* Go back and add padding and correctly encode the last char if we've
	   encoded too many characters */
	if( remainder == 2 )
		{
		/* There were only 2 bytes in the last group */
		outBuffer[ destIndex - 1 ] = BPAD;
		outBuffer[ destIndex - 2 ] = \
					encode( ( inBufferPtr[ srcIndex - 2 ] << 2 ) & 0x3C );
		}
	else
		if( remainder == 1 )
			{
			/* There was only 1 byte in the last group */
			outBuffer[ destIndex - 2 ] = outBuffer[ destIndex - 1 ] = BPAD;
			outBuffer[ destIndex - 3 ] = \
					encode( ( inBufferPtr[ srcIndex - 3 ] << 4 ) & 0x30 );
			}

	/* If it's a certificate object, add the trailer */
	if( certType != CRYPT_CERTTYPE_NONE )
		{
		strcpy( outBuffer + destIndex, EOL );
		if( format < CRYPT_CERTFORMAT_SMIME_CERTIFICATE )
			{
			strcpy( outBuffer + destIndex + EOL_LEN, trailerTbl[ certType ] );
			destIndex += strlen( trailerTbl[ certType ] );
			}
		}
	else
		{
		/* It's not a certificate, truncate the unnecessary padding and add
		   der terminador */
		destIndex -= ( 3 - remainder ) % 3;
		outBuffer[ destIndex ] = '\0';
		}

	/* Return a count of encoded bytes */
	return( destIndex );
	}

/* Decode a block of binary data from the base64 format, returning the total
   number of decoded bytes */

static int fixedBase64decode( void *outBuffer, const char *inBuffer,
							  const int count )
	{
	int srcIndex = 0, destIndex = 0;
	BYTE *outBufferPtr = outBuffer;

	/* Decode the base64 string as a fixed-length continuous string without
	   padding or newlines */
	while( srcIndex < count )
		{
		BYTE c0, c1, c2 = 0, c3 = 0;
		const int delta = count - srcIndex;

		/* Decode a block of data from the input buffer */
		c0 = decode( inBuffer[ srcIndex++ ] );
		c1 = decode( inBuffer[ srcIndex++ ] );
		if( delta > 2 )
			{
			c2 = decode( inBuffer[ srcIndex++ ] );
			if( delta > 3 )
				c3 = decode( inBuffer[ srcIndex++ ] );
			}
		if( ( c0 | c1 | c2 | c3 ) == BERR )
			return( 0 );

		/* Copy the decoded data to the output buffer */
		outBufferPtr[ destIndex++ ] = ( c0 << 2 ) | ( c1 >> 4 );
		if( delta > 2 )
			{
			outBufferPtr[ destIndex++ ] = ( c1 << 4 ) | ( c2 >> 2);
			if( delta > 3 )
				outBufferPtr[ destIndex++ ] = ( c2 << 6 ) | ( c3 );
			}
		}

	/* Return count of decoded bytes */
	return( destIndex );
	}

int base64decode( void *outBuffer, const char *inBuffer, const int count,
				  const CRYPT_CERTFORMAT_TYPE format )
	{
	int srcIndex = 0, destIndex = 0, lineCount = 0, lineSize = 0;
	BYTE c0, c1, c2, c3, *outBufferPtr = outBuffer;

	/* If it's not a certificate, it's a straight base64 string and we can
	   use the simplified decoding routines */
	if( format == CRYPT_CERTFORMAT_NONE )
		return( fixedBase64decode( outBuffer, inBuffer, count ) );

	/* Decode the certificate body */
	while( TRUE )
		{
		BYTE cx;

		/* Depending on implementations, the length of the base64-encoded
		   line can vary from 60 to 72 chars, we ajust for this by checking
		   for an EOL and setting the line length to this size */
		if( !lineSize && \
			( inBuffer[ srcIndex ] == '\r' || inBuffer[ srcIndex ] == '\n' ) )
			lineSize = lineCount;

		/* If we've reached the end of a line of text, look for the EOL
		   marker.  There's one problematic special case here where, if the
		   encoding has produced bricktext, the end of the data will coincide
		   with the EOL.  For CRYPT_CERTFORMAT_TEXT_CERTIFICATE this will give
		   us '-----END' on the next line which is easy to check for, but for
		   CRYPT_CERTFORMAT_SMIME_CERTIFICATE what we end up with depends on
		   the calling code, it could truncate immediately at the end of the
		   data (which it isn't supposed to) so we get '\0', it could truncate
		   after the EOL (so we get EOL + '\0'), it could continue with a
		   futher content type after a blank line (so we get EOL + EOL), or
		   it could truncate without the '\0' so we get garbage, which is the
		   callers problem.  Because of this we look for all of these
		   situations and, if any are found, set c0 to BEOF and advance
		   srcIndex by 4 to take into account the adjustment for overshoot
		   which occurs when we break out of the loop */
		if( lineCount == lineSize )
			{
			/* Check for '\0' at the end of the data */
			if( format == CRYPT_CERTFORMAT_SMIME_CERTIFICATE && \
				!inBuffer[ srcIndex ] )
				{
				c0 = BEOF;
				srcIndex += 4;
				break;
				}

			/* Check for EOL */
			if( inBuffer[ srcIndex ] == '\n' )
				srcIndex++;
			else
				if( inBuffer[ srcIndex ] == '\r' )
					{
					srcIndex++;
					if( inBuffer[ srcIndex ] == '\n' )
						srcIndex++;
					}
			lineCount = 0;

			/* Check for '\0' or EOL (S/MIME) or '----END' (text) after EOL */
			if( ( format == CRYPT_CERTFORMAT_SMIME_CERTIFICATE && \
				  ( !inBuffer[ srcIndex ] || inBuffer[ srcIndex ] == '\n' ||
					inBuffer[ srcIndex ] == '\r' ) ) || \
				( format == CRYPT_CERTFORMAT_TEXT_CERTIFICATE && \
				  !strncmp( inBuffer + srcIndex, "-----END ", 9 ) ) )
				{
				c0 = BEOF;
				srcIndex += 4;
				break;
				}
			}

		/* Decode a block of data from the input buffer */
		c0 = decode( inBuffer[ srcIndex++ ] );
		c1 = decode( inBuffer[ srcIndex++ ] );
		c2 = decode( inBuffer[ srcIndex++ ] );
		c3 = decode( inBuffer[ srcIndex++ ] );
		cx = c0 | c1 | c2 | c3;
		if( c0 == BEOF || cx == BEOF )
			/* We need to check c0 separately since hitting an EOF at c0 may
			   cause later chars to be decoded as BERR */
			break;
		else
			if( cx == BERR )
				return( 0 );
		lineCount += 4;

		/* Copy the decoded data to the output buffer */
		outBufferPtr[ destIndex++ ] = ( c0 << 2 ) | ( c1 >> 4 );
		outBufferPtr[ destIndex++ ] = ( c1 << 4 ) | ( c2 >> 2);
		outBufferPtr[ destIndex++ ] = ( c2 << 6 ) | ( c3 );
		}

	/* Handle the truncation of data at the end.  Due to the 3 -> 4 encoding,
	   we have the following mapping: 0 chars -> nothing, 1 char -> 2 + 2 pad,
	   2 chars = 3 + 1 pad */
	if( c0 == BEOF )
		/* No padding, move back 4 chars */
		srcIndex -= 4;
	else
		{
		/* 2 chars padding, decode 1 from 2 */
		outBufferPtr[ destIndex++ ] = ( c0 << 2 ) | ( c1 >> 4 );
		if( c2 != BEOF )
			/* 1 char padding, decode 2 from 3 */
			outBufferPtr[ destIndex++ ] = ( c1 << 4 ) | ( c2 >> 2);
		}

	/* Make sure the certificate trailer is present */
	if( format == CRYPT_CERTFORMAT_TEXT_CERTIFICATE )
		{
		if( inBuffer[ srcIndex ] == '\n' )
			srcIndex++;
		else
			if( inBuffer[ srcIndex ] == '\r' )
				{
				srcIndex++;
				if( inBuffer[ srcIndex ] == '\n' )
					srcIndex++;
				}
		if( strncmp( inBuffer + srcIndex, "-----END ", 9 ) )
			return( 0 );
		}

	/* Return count of decoded bytes */
	return( destIndex );
	}

/* Calculate the size of a quantity of data once it's en/decoded as a
   certificate */

int base64decodeLen( const char *data )
	{
	char *dataPtr = ( char * ) data, ch;

	/* Skip ahead until we find the end of the decodable data */
	do
		ch = *dataPtr++;
	while( decode( ch ) != BERR );

	/* Return a rough estimate of how much room the decoded data will occupy.
	   This ignores the EOL size so it always overestimates, but a strict
	   value isn't necessary since the user never sees it anyway */
	return( ( ( int ) ( dataPtr - ( char * ) data ) * 3 ) / 4 );
	}

int base64encodeLen( const int dataLength,
					 const CRYPT_CERTTYPE_TYPE certType,
					 const CRYPT_CERTFORMAT_TYPE format )
	{
	int length = roundUp( ( dataLength * 4 ) / 3, 4 );

	/* Calculate extra length due to EOL's */
	length += ( ( roundUp( dataLength, BINARY_LINESIZE ) / BINARY_LINESIZE ) * EOL_LEN );

	/* Calculate length due to delimiters */
	if( format < CRYPT_CERTFORMAT_SMIME_CERTIFICATE )
		length += strlen( headerTbl[ certType ] ) + \
				  strlen( trailerTbl[ certType ] );
	else
		length += strlen( smimeHeaderTbl[ certType ] );

	return( length );
	}
