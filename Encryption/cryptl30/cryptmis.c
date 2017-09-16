/****************************************************************************
*																			*
*							cryptlib Misc Routines							*
*						Copyright Peter Gutmann 1992-1999					*
*																			*
****************************************************************************/

/* NSA motto: In God we trust... all others we monitor.
														-- Stanley Miller */
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "md2.h"
  #include "md4.h"
  #include "md5.h"
  #include "ripemd.h"
  #include "sha.h"
  #include "stream.h"
#else
  #include "hash/md2.h"
  #include "hash/md4.h"
  #include "hash/md5.h"
  #include "hash/ripemd.h"
  #include "hash/sha.h"
  #include "keymgmt/stream.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Internal API Functions						*
*																			*
****************************************************************************/

/* Determine the parameters for a particular hash algorithm */

void getHashParameters( const CRYPT_ALGO hashAlgorithm,
						HASHFUNCTION *hashFunction, int *hashSize )
	{
	void md2HashBuffer( void *hashInfo, BYTE *outBuffer, BYTE *inBuffer, \
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
			*hashSize = MD2_DIGESTSIZE;
			return;

		case CRYPT_ALGO_MD5:
			*hashFunction = md5HashBuffer;
			*hashSize = MD5_DIGEST_LENGTH;
			return;

		case CRYPT_ALGO_RIPEMD160:
			*hashFunction = ripemd160HashBuffer;
			*hashSize = RIPEMD160_DIGESTSIZE;
			return;

		case CRYPT_ALGO_SHA:
			*hashFunction = shaHashBuffer;
			*hashSize = SHA_DIGEST_LENGTH;
			return;
		}

	assert( NOTREACHED );
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

/* Get a random (but not necessarily unpredictable) nonce.  It doesn't matter
   much what it is, as long as it's completely different for each call */

void getNonce( void *nonce, int nonceLength )
	{
	static BOOLEAN nonceDataInitialised = FALSE;
	static BYTE nonceData[ CRYPT_MAX_HASHSIZE ];
	HASHFUNCTION hashFunction;
	BYTE *noncePtr = nonce;
	int hashSize;

	/* Get the hash algorithm information and seed the nonce data with a 
	   value which is guaranteed to be different each time (unless the entire 
	   program is rerun more than twice a second, which is doubtful) */
	getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );
	if( !nonceDataInitialised )
		{
		time( ( time_t * ) nonceData );
		nonceDataInitialised = TRUE;
		}

	/* Shuffle the pool and copy it to the output buffer until it's full */
	while( nonceLength > 0 )
		{
		const int count = ( nonceLength > hashSize ) ? hashSize : nonceLength;

		/* Hash the data and copy the appropriate amount of data to the output
		   buffer */
		hashFunction( NULL, nonceData, nonceData, hashSize, HASH_ALL );
		memcpy( noncePtr, nonceData, count );

		/* Move on to the next block of the output buffer */
		noncePtr += hashSize;
		nonceLength -= hashSize;
		}
	}

/* Perform the FIPS-140 statistical checks which are feasible on a byte 
   string.  The full suite of tests assumes an infinite source of values (and
   time) is available, the following is a scaled-down version used to sanity-
   check keys and other short random data blocks */

BOOLEAN checkEntropy( const BYTE *data, const int dataLength )
	{
	int bitCount[ 4 ] = { 0 }, noOnes, i;

	for( i = 0; i < dataLength; i++ )
		{
		const int value = data[ i ];

		bitCount[ value & 3 ]++;
		bitCount[ ( value >> 2 ) & 3 ]++;
		bitCount[ ( value >> 4 ) & 3 ]++;
		bitCount[ value >> 6 ]++;
		}

	/* Monobit test: Make sure at least 1/4 of the bits are ones and 1/4 are
	   zeroes */
	noOnes = bitCount[ 1 ] + bitCount[ 2 ] + ( 2 * bitCount[ 3 ] );
	if( noOnes < dataLength * 2 || noOnes > dataLength * 6 )
		return( FALSE );

	/* Poker test (almost): Make sure each bit pair is present at least 
	   1/16 of the time.  The FIPS 140 version uses 4-bit values, but the
	   numer of samples available from the keys is far too small for this */
	if( ( bitCount[ 0 ] < dataLength / 2 ) || \
		( bitCount[ 1 ] < dataLength / 2 ) || \
		( bitCount[ 2 ] < dataLength / 2 ) || \
		( bitCount[ 3 ] < dataLength / 2 ) )
		return( FALSE );

	return( TRUE );
	}

/* Copy a string attribute to external storage, with various range checks
   to follow the cryptlib semantics */

int attributeCopy( RESOURCE_DATA *msgData, const void *attribute, 
				   const int attributeLength )
	{
	if( msgData->data != NULL )
		{
		assert( attribute != NULL );
		assert( attributeLength > 0 );

		if( attributeLength > msgData->length || \
			checkBadPtrWrite( msgData->data, attributeLength ) )
			return( CRYPT_ARGERROR_STR1 );
		memcpy( msgData->data, attribute, attributeLength );
		}
	msgData->length = attributeLength;

	return( CRYPT_OK );
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
		 defined( __OS2__ ) || defined( __IBM4758__ ) || \
		 defined( __TANDEM__ ) ) || defined( NT_DRIVER )

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
#endif /* !( __WINDOWS__ || __MSDOS__ || __OS2__ || __IBM4758__ ) || NT_DRIVER */

BOOLEAN matchSubstring( const char *subString, const int subStringLength,
						const char *string, const int stringLength )
	{
	char firstChar = toupper( subString[ 0 ] );
	int i;

	/* Perform a case-insensitive match for the required substring in the
	   string */
	for( i = 0; i <= stringLength - subStringLength; i++ )
		if( ( toupper( string[ i ] ) == firstChar ) &&
			!strnicmp( subString, string + i, subStringLength ) )
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

static const char binToAscii[] = \
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const BYTE asciiToBin[] =
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

/* Check whether a data item has a header which identifies it as some form of
   PEM-style encoded certificate object and return the start position of the
   encoded data.  Since there are so many variants possible, we don't perform
   a very strict check because there'll always be some new variants which
   isn't handled.  The exact object type can be determined by the lower-level
   routines */

int base64checkHeader( const char *data, const int dataLength )
	{
	STREAM stream;
	char buffer[ 64 ];
	int ch, i;

	sMemConnect( &stream, data, dataLength );

	/* Sometimes the object can be preceded by a few blank lines - we're
	   fairly lenient with this */
	do
		ch = sgetc( &stream );
	while( ch == '\r' || ch == '\n' );
	buffer[ 0 ] = ch;

	/* We always have to start with 5 dashes and 'BEGIN '.  After this there
	   can be all sorts of stuff, but it has to end with another five dashes
	   and a newline */
	if( cryptStatusError( sread( &stream, buffer + 1, 10 ) ) || \
		memcmp( buffer, "-----BEGIN ", 11 ) )
		{
		sMemDisconnect( &stream );
		return( 0 );
		}
	for( i = 0; i < 40; i++ )
		if( sgetc( &stream ) == '-' )
			break;
	if( i == 40 )
		{
		sMemDisconnect( &stream );
		return( 0 );
		}
	if( cryptStatusError( sread( &stream, buffer, 4 ) ) || \
		memcmp( buffer, "----", 4 ) )
		{
		sMemDisconnect( &stream );
		return( 0 );
		}
	ch = sgetc( &stream );
	if( ch != '\n' )
		{
		if( ch == '\r' )
			{
			if( sgetc( &stream ) != '\n' )
				sungetc( &stream );
			}
		else
			{
			sMemDisconnect( &stream );
			return( 0 );
			}
		}

	/* Return the start position of the payload */
	i = stell( &stream );
	sMemDisconnect( &stream );
	return( cryptStatusError( i ) ? 0 : i );
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

static void skipWhitespace( STREAM *stream )
	{
	int ch;

	do
		ch = sgetc( stream );
	while( ch == ' ' || ch == '\t' );
	sungetc( stream );
	}

static void skipEOL( STREAM *stream )
	{
	int ch;

	/* Skip a LF or CR with optional LF */
	ch = sgetc( stream );
	if( ch == '\n' )
		return;
	if( ch == '\r' && \
		sgetc( stream ) == '\n' )
		return;
	sungetc( stream );
	}

static BOOLEAN skipToNextToken( STREAM *stream )
	{
	int ch = sgetc( stream );

	/* If this is the end of the line, don't to anything */
	if( ch == '\r' || ch == '\n' )
		{
		sungetc( stream );
		return( TRUE );
		}

	/* Skip to the start of the next token after the current one.  This
	   parses ";{ }{EOL }}" */
	if( ch != ';' )
		return( FALSE );
	skipWhitespace( stream );
	ch = sgetc( stream );
	if( ch != '\r' && ch != '\n' )
		{
		sungetc( stream );
		return( TRUE );
		}
	skipEOL( stream );		/* Line is continued, skip EOL and whitespace */
	ch = sgetc( stream );
	if( ch != ' ' && ch != '\t' )
		return( FALSE );	/* Should have whitespace after continuation */
	skipWhitespace( stream );

	return( TRUE );
	}

static BOOLEAN skipCurrentToken( STREAM *stream )
	{
	BOOLEAN isQuoted = FALSE;
	int ch = sgetc( stream );

	while( ch != '\n' && ch != '\r' )
		{
		if( !isQuoted && ch == ';' )
			{
			/* If we reach an unquoted semicolon, we're at the end of the
			   token */
			sungetc( stream );
			return( skipToNextToken( stream ) );
			}
		if( ch == '"' )
			isQuoted = !isQuoted;
		ch = sgetc( stream );
		}
	sungetc( stream );

	return( isQuoted ? FALSE : skipToNextToken( stream ) );
	}

static BOOLEAN skipLine( STREAM *stream )
	{
	BOOLEAN continuation;
	int ch = sgetc( stream );

	/* MIME headers can be continued over multiple lines.  If there's a
	   semicolon at the end of the current line, we continue to the next
	   one */
	do
		{
		continuation = FALSE;
		while( ch != '\r' && ch != '\n' )
			{
			if( ( ch & 0x7F ) < ' ' )
			continuation = ( ch == ';' );
			ch = sgetc( stream );
			}
		if( continuation )
			{
			sungetc( stream );
			if( !skipToNextToken( stream ) )
				return( FALSE );
			ch = sgetc( stream );
			}
		}
	while( continuation );
	sungetc( stream );

	/* Check for a single EOL */
	skipEOL( stream );
	return( TRUE );
	}

/* Parse the various MIME header lines */

static BOOLEAN parseContentType( STREAM *stream )
	{
	char buffer[ 64 ];
	int ch;

	/* Look for "application/{x-}pkcs{7-mime|7-signature|10}" */
	skipWhitespace( stream );
	if( cryptStatusError( sread( stream, buffer, 12 ) ) || \
		memcmp( buffer, "application/", 12 ) )
		return( FALSE );
	if( sgetc( stream ) == 'x' )
		{
		/* Skip old-style "x-" header */
		if( sgetc( stream ) != '-' )
			return( FALSE );
		
		/* Check for one of the Netscape cert types */
		if( sgetc( stream ) == 'x' )
			{
			/* "x509-"*/
			if( cryptStatusError( sread( stream, buffer, 4 ) ) || \
				memcmp( buffer, "509-", 4 ) )
				return( FALSE );
			return( skipLine( stream ) );
			}
		sungetc( stream );
		}
	else
		sungetc( stream );
	if( cryptStatusError( sread( stream, buffer, 4 ) ) || \
		memcmp( buffer, "pkcs", 4 ) )
		return( FALSE );
	ch = sgetc( stream );
	if( ch == '7' )
		{
		if( sgetc( stream ) != '-' )
			return( FALSE );
		ch = sgetc( stream );
		if( ch != 'm' && ch != 's' )
			return( FALSE );
		if( ch == 'm' )
			{
			/* "pkcs7-mime" */
			if( cryptStatusError( sread( stream, buffer, 4 ) ) || \
				memcmp( buffer, "mime", 4 ) )
				return( FALSE );
			}
		else
			/* "pkcs7-signature" */
			if( cryptStatusError( sread( stream, buffer, 8 ) ) || \
				memcmp( buffer, "ignature", 8 ) )
				return( FALSE );
		}
	else
		if( ch == '1' )
			{
			/* "pkcs10" */
			if( sgetc( stream ) != '0' )
				return( FALSE );
			}
		else
			return( FALSE );
	if( !skipToNextToken( stream ) )
		return( FALSE );
	ch = sgetc( stream );
	if( ch == '\n' || ch == '\r' )
		{
		/* If that's all there is, return */
		sungetc( stream );
		skipEOL( stream );
		return( TRUE );
		}

	/* Check for an optional old-style name attribute */
	if( ch == 'n' )
		{
		/* name= */
		if( cryptStatusError( sread( stream, buffer, 4 ) ) || \
			memcmp( buffer, "ame=", 4 ) )
			return( FALSE );
		skipWhitespace( stream );
		if( !skipCurrentToken( stream ) )
			return( FALSE );
		ch = sgetc( stream );
		sungetc( stream );
		if( ch == '\n' || ch == '\r' )
			{
			/* If that's all there is, return */
			skipEOL( stream );
			return( TRUE );
			}
		}

	/* Check for an SMIME type */
	if( cryptStatusError( sread( stream, buffer, 11 ) ) || \
		memcmp( buffer, "smime-type=", 11 ) )
		return( FALSE );
	skipWhitespace( stream );
	ch = sgetc( stream );
	if( ch == 's' )
		{
		/* signed-data */
		if( cryptStatusError( sread( stream, buffer, 10 ) ) || \
			memcmp( buffer, "igned-data", 10 ) )
			return( FALSE );
		}
	else
		{
		/* certs-only */
		if( ch != 'c' )
			return( FALSE );
		if( cryptStatusError( sread( stream, buffer, 9 ) ) || \
			memcmp( buffer, "erts-only", 9 ) )
			return( FALSE );
		}

	return( skipLine( stream ) );
	}

static BOOLEAN parseContentDisposition( STREAM *stream )
	{
	char buffer[ 64 ];
	int ch;

	/* Look for "attachment" */
	skipWhitespace( stream );
	ch = sgetc( stream );
	if( ch == 'a' )
		{
		/* attachment */
		if( cryptStatusError( sread( stream, buffer, 9 ) ) || \
			memcmp( buffer, "ttachment", 9 ) )
			return( FALSE );
		}
	else
		{
		/* inline */
		if( ch != 'i' )
			return( FALSE );
		if( cryptStatusError( sread( stream, buffer, 5 ) ) || \
			memcmp( buffer, "nline", 5 ) )
			return( FALSE );
		}
	return( TRUE );
	}

static BOOLEAN parseContentTransferEncoding( STREAM *stream )
	{
	char buffer[ 64 ];

	/* Look for "base64" */
	skipWhitespace( stream );
	if( cryptStatusError( sread( stream, buffer, 6 ) ) || \
		memcmp( buffer, "base64", 6 ) )
		return( FALSE );
	return( skipLine( stream ) );
	}

/* Check an S/MIME header.  Returns the length of the header */

int smimeCheckHeader( const char *data, const int dataLength )
	{
	STREAM stream;
	BOOLEAN seenType = FALSE, seenDisposition = FALSE;
	BOOLEAN seenDescription = FALSE, seenTransferEncoding = FALSE;
	BOOLEAN dataOK = TRUE;
	char buffer[ 64 ];
	int ch;

	sMemConnect( &stream, data, dataLength );

	/* Sometimes the object can be preceded by a few blank lines - we're
	   fairly lenient with this */
	do
		ch = sgetc( &stream );
	while( ch == '\r' || ch == '\n' );

	/* Make sure there's a MIME content-type header there */
	if( ch != 'C' )
		{
		sMemDisconnect( &stream );
		return( 0 );
		}
	while( ch != '\r' && ch != '\n' )
		{
		/* Check for the different types of content header which are
		   allowed */
		if( cryptStatusError( sread( &stream, buffer, 7 ) ) || \
			memcmp( buffer, "ontent-", 7 ) )
			dataOK = FALSE;
		ch = sgetc( &stream );
		if( ch != 'D' && ch != 'T' )
			dataOK = FALSE;
		if( ch == 'D' )
			{
			ch = sgetc( &stream );
			if( ch == 'i' )
				{
				/* "Disposition:" */
				if( cryptStatusError( sread( &stream, buffer, 10 ) ) || \
					memcmp( buffer, "sposition:", 10 ) || seenDisposition )
					dataOK = FALSE;
				seenDisposition = TRUE;
				if( dataOK )
					dataOK = parseContentDisposition( &stream );
				}
			else
				{
				/* "Description:" */
				if( ch != 'e' )
					dataOK = FALSE;
				if( cryptStatusError( sread( &stream, buffer, 10 ) ) || \
					memcmp( buffer, "scription:", 10 ) || seenDescription )
					dataOK = FALSE;
				seenDescription = TRUE;
				if( dataOK )
					dataOK = skipLine( &stream );
				}
			}
		else
			{
			ch = sgetc( &stream );
			if( ch == 'y' )
				{
				/* "Type:" */
				if( cryptStatusError( sread( &stream, buffer, 4 ) ) || \
					memcmp( buffer, "ype:", 4 ) || seenType )
					dataOK = FALSE;
				seenType = TRUE;
				if( dataOK )
					dataOK = parseContentType( &stream );
				}
			else
				{
				/* "Transfer-Encoding:" */
				if( ch != 'r' )
					dataOK = FALSE;
				if( cryptStatusError( sread( &stream, buffer, 16 ) ) || \
					memcmp( buffer, "ansfer-Encoding:", 16 ) || \
					seenTransferEncoding )
					dataOK = FALSE;
				seenTransferEncoding = TRUE;
				if( dataOK )
					dataOK = parseContentTransferEncoding( &stream );
				}
			}
		if( !dataOK || cryptStatusError( sGetStatus( &stream ) ) )
			{
			sMemDisconnect( &stream );
			return( 0 );
			}
		}

	/* Skip trailing blank lines */
	do
		ch = sgetc( &stream );
	while( ch == '\r' || ch == '\n' );
	sungetc( &stream );

	ch = stell( &stream );
	sMemDisconnect( &stream );
	return( cryptStatusError( ch ) ? 0 : ch );
	}

/* Encode a block of binary data into the base64 format, returning the total
   number of output bytes */

int base64encode( char *outBuffer, const void *inBuffer, const int count,
				  const CRYPT_CERTTYPE_TYPE certType )
	{
	int srcIndex = 0, destIndex = 0, lineCount = 0, remainder = count % 3;
	BYTE *inBufferPtr = ( BYTE * ) inBuffer;

	/* If it's a certificate object, add the header */
	if( certType != CRYPT_CERTTYPE_NONE )
		{
		strcpy( outBuffer, headerTbl[ certType ] );
		destIndex = strlen( headerTbl[ certType ] );
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
		strcpy( outBuffer + destIndex + EOL_LEN, trailerTbl[ certType ] );
		destIndex += strlen( trailerTbl[ certType ] );
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
		   CRYPT_ICERTFORMAT_SMIME_CERTIFICATE what we end up with depends on
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
			if( format == CRYPT_ICERTFORMAT_SMIME_CERTIFICATE && \
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
			if( ( format == CRYPT_ICERTFORMAT_SMIME_CERTIFICATE && \
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

int base64decodeLen( const char *data, const int dataLength )
	{
	STREAM stream;
	int ch, length;

	/* Skip ahead until we find the end of the decodable data */
	sMemConnect( &stream, data, dataLength );
	do
		ch = sgetc( &stream );
	while( decode( ch ) != BERR );
	length = stell( &stream ) - 1;
	sMemDisconnect( &stream );

	/* Return a rough estimate of how much room the decoded data will occupy.
	   This ignores the EOL size so it always overestimates, but a strict
	   value isn't necessary since the user never sees it anyway */
	return( ( length * 3 ) / 4 );
	}

int base64encodeLen( const int dataLength,
					 const CRYPT_CERTTYPE_TYPE certType )
	{
	int length = roundUp( ( dataLength * 4 ) / 3, 4 );

	/* Calculate extra length due to EOL's */
	length += ( ( roundUp( dataLength, BINARY_LINESIZE ) / BINARY_LINESIZE ) * EOL_LEN );

	/* Return the total length due to delimiters */
	return( strlen( headerTbl[ certType ] ) + length + \
			strlen( trailerTbl[ certType ] ) );
	}
