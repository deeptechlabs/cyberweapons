/****************************************************************************
*																			*
*					cryptlib Generic Smart Card Reader Routines				*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "scard.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../keymgmt/asn1.h"
  #include "scard.h"
#else
  #include "crypt.h"
  #include "keymgmt/asn1.h"
  #include "misc/scard.h"
#endif /* Compiler-specific includes */

#if defined( __MSDOS16__ ) && defined( __TURBOC__ ) && ( __TURBOC__ <= 0x200 )
  #undef getCommParams
#endif /* Kludge for TC 2.0 */

/****************************************************************************
*																			*
*						 		Utility Routines							*
*																			*
****************************************************************************/

/* The default comms settings */

#ifdef __WINDOWS__
  #define DEFAULT_PORT			2
  #define DEFAULT_PORTNAME		"COM2"
#else
  #define DEFAULT_PORT			1
  #define DEFAULT_PORTNAME		"/dev/ttyS1"
#endif /* OS-specific comm port name */

static const COMM_PARAMS defaultParams = { DEFAULT_PORT, DEFAULT_PORTNAME,
										   9600, 8, COMM_PARITY_NONE, 1 };

/* Decode a string contains comms parameters into a COMM_PARAMS structure */

#define skipWhitespace( string )	while( isspace( *string ) ) string++

BOOLEAN getCommParams( COMM_PARAMS *commParams, const char *commParamStr,
					   const BOOLEAN longFormOK )
	{
	char *strPtr = ( char * ) commParamStr;
	long longVal;
	int value;

	/* Set up the default parameters */
	memcpy( commParams, &defaultParams, sizeof( COMM_PARAMS ) );
	if( commParamStr == NULL )
		return( TRUE );

	/* Decode the comms port.  This should always be present */
#if defined( __WINDOWS__ )
	if( strnicmp( strPtr, "COM", 3 ) )
		return( FALSE );
	value = atoi( strPtr + 3 );
	if( value < 1 || value > 4 )
		return( FALSE );
	commParams->port = value - 1;
	strPtr += 4;
#elif defined( __UNIX__ )
	while( *strPtr && *strPtr != ',' )
		*strPtr++;	/* Skip the serial device name */
#endif /* OS-dependant comm port processing */
	value = ( int ) ( strPtr - ( char * ) commParamStr );
	if( value > CRYPT_MAX_TEXTSIZE - 1 )
		return( FALSE );
	strncpy( commParams->portName, commParamStr, value );
	commParams->portName[ value ] = '\0';

	/* Check whether this is the short form of the parameter string */
	skipWhitespace( strPtr );
	if( !*strPtr )
		return( TRUE );	/* Short form, we're done */
	if( !longFormOK || *strPtr++ != ',' )
		return( FALSE );
	skipWhitespace( strPtr );

	/* Decode the comms device parameters */
	longVal = atol( strPtr );
	if( longVal != 9600 && longVal != 19200 && longVal != 38400L )
		return( FALSE );
	commParams->baudRate = longVal;
	while( isdigit( *strPtr ) )
		strPtr++;	/* Skip baud rate */
	skipWhitespace( strPtr );
	if( *strPtr++ != ',' )
		return( FALSE );
	skipWhitespace( strPtr );
	value = atoi( strPtr );
	if( value < 7 || value > 8 )
		return( FALSE );
	commParams->dataBits = value;
	strPtr++;	/* Skip data bits value */
	skipWhitespace( strPtr );
	if( *strPtr++ != ',' )
		return( FALSE );
	skipWhitespace( strPtr );
	value = toupper( *strPtr );
	strPtr++;		/* toupper() has side-effects on some systems */
	value = ( value == 'N' ) ? COMM_PARITY_NONE : \
			( value == 'E' ) ? COMM_PARITY_EVEN : \
			( value == 'O' ) ? COMM_PARITY_ODD : CRYPT_ERROR;
	if( value == CRYPT_ERROR )
		return( FALSE );
	commParams->parity = value;
	skipWhitespace( strPtr );
	if( *strPtr++ != ',' )
		return( FALSE );
	skipWhitespace( strPtr );
	value = atoi( strPtr );
	if( value < 0 || value > 2 )
		return( FALSE );
	commParams->stopBits = value;
	strPtr++;	/* Skip stop bits value */
	skipWhitespace( strPtr );
	if( *strPtr )
		return( FALSE );

	return( TRUE );
	}

/* ATR values for various cards */

typedef struct {
	const BYTE *atr;				/* ATR for card */
	const BYTE *atrMask;			/* Mask for bytes to ignore */
	const int atrLength;			/* Length of ATR */
	const SCARD_TYPE type;			/* Card type */
	} ATR_VALUE;

static const ATR_VALUE atrTable[] = {
	{ ( const BYTE * ) "\x03\x19\x5B\xFF\x7B\xFB\xFF",
		NULL, 7, SCARD_TB1000 },
	{ ( const BYTE * ) "\x03\x59\x58\xFF\x2B\x6F",
		NULL, 6, SCARD_TB98S },
	{ ( const BYTE * ) "\x3B\x02\x14\x50",
		NULL, 4, SCARD_MULTIFLEX },
	{ ( const BYTE * ) "\x3B\x23\x00\x35\x11\x80",
		NULL, 6, SCARD_PAYFLEX1K },
	{ ( const BYTE * ) "\x3B\x24\x00\x80\x72\x94",
		NULL, 6, SCARD_MPCOS_3DES },
	{ ( const BYTE * ) "\x3B\x27\x00\x80\x65\xA2",
		NULL, 6, SCARD_GPK2000 },
	{ ( const BYTE * ) "\x3B\x32\x15\x00\x06\x80",
		NULL, 6, SCARD_MULTIFLEX },	/* MultiFlex3K-G3, 8K */
	{ ( const BYTE * ) "\x3B\x85\x40\x64\xCA\xFE\x01\x90\x00",
		NULL, 9, SCARD_CAFE },
	{ ( const BYTE * ) "\x3B\x88\x01\x50\x43\x31\x36\x54\x34\x7F\xFF\x46",
		NULL, 12, SCARD_RG200 },
	{ ( const BYTE * ) "\x3B\x8B\x81\x31\x40\x34\x53\x4D\x41\x52\x54\x53\x43\x4F\x50\x45\x31\x6D",
		NULL, 18, SCARD_SMARTSCOPE1 },
	{ ( const BYTE * ) "\x3B\x8B\x81\x31\x40\x34\x53\x4D\x41\x52\x54\x53\x43\x4F\x50\x45\x33\x6F",
		NULL, 18, SCARD_SMARTSCOPE3 },
	{ ( const BYTE * ) "\x3B\xB0\x11\x00\x81\31",
		NULL, 6, SCARD_SIGNASURE },
	{ ( const BYTE * ) "\x3B\xBE\x11\x00\x00",
		NULL, 5, SCARD_ACOS1 },
	{ ( const BYTE * ) "\x3B\xBE\x18\x00\x81\x31\x20\x53\x50\x4B\x20\x32",
		NULL, 12, SCARD_STARCOS },
	{ ( const BYTE * ) "\x3B\xE2\x00\x00\x40\x20\x49\x03",
		NULL, 8, SCARD_CRYPTOFLEX },
	{ ( const BYTE * ) "\x3B\xEB\x00\x00\x81\x31\x42\x45\x4E\x4C\x43\x68\x69\x70\x70\x65\x72\x30\x31\x0A",
		NULL, 20, SCARD_CHIPPER },
	{ ( const BYTE * ) "\x3B\xFA\x11\x00\x02\x40\x20\x41\xC0\x03\xF8\x03\x03\x00\x00\x90\x00",
	  ( const BYTE * ) "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x00\x01\x01\x01\x01",
		17, SCARD_DX },
	{ ( const BYTE * ) "\x3B\xEF\x00\xFF\x81\x31\x50\x45\x65\x63\x08\x04\x13\xFF\xFF\xFF\xFF\x01\x50\x02\x01\x01\x31\xCE",
		NULL, 24, SCARD_GELDKARTE },
	{ ( const BYTE * ) "\x3F\x05\xDC\x20\xFC\x00\x01",
		NULL, 7, SCARD_DIGICASH },
	{ ( const BYTE * ) "\x3F\x67\x25\x00\x2A\x20\x00\x40\x68\x9F\x00",
		NULL, 11, SCARD_CHIPKNIP1 },
	{ ( const BYTE * ) "\x3F\x67\x25\x00\x2A\x20\x00\x41\x68\x90\x00",
		NULL, 11, SCARD_CHIPKNIP2_CC60 },
	{ ( const BYTE * ) "\x3F\x67\x25\x00\x2A\x20\x00\x6F\x68\x90\x00",
		NULL, 11, SCARD_CHIPKNIP2_CC1000 },
	{ ( const BYTE * ) "\x3F\x67\x2F\x00\x11\x14\x00\x03\x68\x90\x00",
		NULL, 11, SCARD_WAFERCARD },
	{ ( const BYTE * ) "\x3F\x6C\x00\x00\x24\xA0\x30\x00\xFF\x00\x00\x01\x00\x04\x90\x00",
		NULL, 16, SCARD_COS },
	{ NULL, NULL, 0 }
	};

/* Determine the card type based on the ATR */

int getCardType( const BYTE *atr, const int atrLength )
	{
	int i;

	for( i = 0; atrTable[ i ].atr != NULL; i++ )
		{
		const BYTE *atrMask = atrTable[ i ].atrMask;
		int length = atrTable[ i ].atrLength;

		if( length != atrLength )
			continue;	/* Quick check for length match */
		if( atrMask == NULL && !memcmp( atr, atrTable[ i ].atr, length ) )
			return( atrTable[ i ].type );
		else
			{
			int j;

			/* There's a mask for the ATR, compare only the bytes which
			   aren't masked out */
			for( j = 0; j < length; j++ )
				if( atrTable[ i ].atrMask && \
					atrTable[ i ].atr[ j ] != atr[ j ] )
					break;
			if( j == length )
				return( atrTable[ i ].type );
			}
		}

	return( CRYPT_ERROR );
	}

/* Map a text string to a reader-specific magic number */

int stringToValue( const STRINGMAP_INFO *stringmapInfo, const char *string )
	{
	int i;

	for( i = 0; stringmapInfo[ i ].string != NULL; i++ )
		if( !stricmp( stringmapInfo[ i ].string, string ) )
			return( stringmapInfo[ i ].value );

	return( CRYPT_ERROR );
	}
