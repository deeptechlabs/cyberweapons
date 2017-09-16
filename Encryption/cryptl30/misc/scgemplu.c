/****************************************************************************
*																			*
*					cryptlib Gemplus Smart Card Reader Routines				*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

/* This file contains its own version of the various Gemplus definitions and
   values to avoid potential copyright problems with redistributing the
   Gemplus header files */

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

/* The default reader and card name */

#define DEFAULT_READER		"GCR400"
#define DEFAULT_CARD		"Auto"

/* The various card protocol types we know about.  If the card type is
   CARDTYPE_NONE we fall back to I2C, which will sometimes work OK, or fail
   on the card types we can't do anything useful with anyway */

enum { CARDTYPE_NONE, CARDTYPE_I2C = 0x06, CARDTYPE_ISO = 0x02,
	   CARDTYPE_FASTISO = 0x12 };

/* Various constants */

#define COMMAND_LEN			4		/* Size of APDU command */
#ifdef __WIN16__
  #define MAX_RESET_LEN		33		/* Max.no.of ATR bytes */
#else
  #define MAX_RESET_LEN		36		/* Max.no.of ATR bytes */
#endif /* __WIN16__ */
#define MAX_DUMMY_SESSION	( 100 - MAX_RESET_LEN )

/* The Gemplus handle is a 16-bit value starting at 0, however the reader
   handle is a nonzero integer, so we use the following macro to convert from
   the reader handle to the Gemplus handle */

#define MK_GEMPLUS( x )		( ( short ) ( x ) - 1 )
#define MK_HANDLE( x )		( ( x ) + 1 )

/* Serial port types */

#define G_SERIAL			0		/* Serial port connection type */
#define G_COM1				1		/* COM1 */
#define G_COM2				2		/* COM2 */
#define G_COM3				3		/* COM3 */
#define G_COM4				4		/* COM4 */
#define GRI1_1				0x11	/* COM1, card 1 */
#define GRI1_2				0x21	/* COM1, card 2 */
#define GRI2_1				0x12	/* COM2, card 1 */
#define GRI2_2				0x22	/* COM2, card 2 */
#define GRI3_1				0x13	/* COM3, card 1 */
#define GRI3_2				0x23	/* COM3, card 2 */
#define GRI4_1				0x14	/* COM4, card 1 */
#define GRI4_2				0x24	/* COM4, card 2 */

/* Serial port parameters */

typedef struct {
#ifdef __WIN16__
	WORD port;						/* Comms port */
	LONG baudRate;					/* Baud rate */
	WORD itNumber;					/* Interrupt, always 0xFF */
#else
	LONG port;						/* Comms port */
	LONG baudRate;					/* Baud rate */
	LONG itNumber;					/* Interrupt, always 0xFF */
#endif /* __WIN16__ */
	} COM_SERIAL;

/* Card reader channel parameters.  This is a cut down form of the full
   version which handles comms types other than serial.  Note that the
   connection type is declared in a word-size specific manner, the Gemplus
   definitions use a typedef which may or may not end up with the correct
   type depending on the compiler */

typedef struct {
#ifdef __WIN16__
	WORD ifdType;					/* Reader type */
	LONG ifdBaudRate;				/* Baud rate */
	WORD ifdMode;					/* Connection type, G_SERIAL */
#else
	LONG ifdType;					/* Reader type */
	LONG ifdBaudRate;				/* Baud rate */
	LONG ifdMode;					/* Connection type, G_SERIAL */
#endif /* __WIN16__ */
	COM_SERIAL serial;				/* Serial comms parameters */
	} G4_CHANNEL_PARAM;

/* Card session parameters */

typedef struct {
#ifdef __WIN16__
	WORD iccType;					/* Card type */
	LONG apduLenMax;				/* Max.APDU length supported by card */
	WORD resetLen;					/* ATR length */
	WORD histLen;					/* No.of hist.bytes in ATR buf */
	WORD histOffset;				/* Offset of first hist.byte in ATR buf */
#else
	LONG iccType;					/* Card type */
	LONG apduLenMax;				/* Max.APDU length supported by card */
	LONG resetLen;					/* ATR length */
	LONG histLen;					/* No.of hist.bytes in ATR buf */
	LONG histOffset;				/* Offset of first hist.byte in ATR buf */
#endif /* __WIN16__ */
	BYTE atr[ MAX_RESET_LEN ];		/* ATR data */
	BYTE dummy[ MAX_DUMMY_SESSION ];/* For future use */
	} G4_SESSION_PARAM;

/* APDU command and command response */

typedef struct {
	BYTE command[ COMMAND_LEN ];	/* Command */
	LONG lengthIn;					/* Data bytes in */
	BYTE *dataIn;					/* Data bytes */
	LONG lengthExpected;			/* Maximum expected response length */
	} G4_APDU_COMM;

typedef struct {
	LONG lengthOut;					/* Data bytes out */
	BYTE *dataOut;					/* Data bytes */
#ifdef __WIN16__
	WORD status;					/* Status */
#else
	LONG status;					/* Status */
#endif /* __WIN16__ */
	} G4_APDU_RESP;

/* Magic ID's for various reader and card types.  The Gemplus header files
   include a whole range of unknown and peculiar types, only the ones which
   make sense are included here, and of those only the card types ISOCARD,
   FASTISOCARD, and I2C are used (the rest are special-purpose cards which
   aren't useful for much of anything) */

const static STRINGMAP_INFO readerIDtable[] = {
	{ "GCR200", 0x03 }, { "GCR400FD A", 0x03 }, { "GCR400FD B", 0x05 },
	{ "GCR400", 0x04 }, { "GCR500", 0x05 }, { "GCI400DC", 0x05 },
	{ "GCR610", 0x06 }, { "GCR680", 0x07 }, { "GCR420", 0x08 },
	{ "GPR", 0x0C }, { "GPR400", 0x0D }, { "GCM AUTO", 0x20 },
	{ "GCM CONN", 0x21 }, { "IFD140", 0xFF }, { "IFD140 200", 0xFF },
	{ "IFD140 400", 0xFD }, { "IFD220", 0xFE }, { NULL, 0 }
	};

const static STRINGMAP_INFO cardIDtable[] = {
	{ "AUTO", CARDTYPE_NONE },
	{ "ISO", CARDTYPE_ISO }, { "COS", CARDTYPE_ISO },
									/* ISO 7816-3 T=0,T=1, 3.6864 MHz clock */
	{ "FASTISO", CARDTYPE_FASTISO },/* ISO 7816-3, 7.3728 MHz clock */
	{ "I2C", CARDTYPE_I2C },		/* I2C memory card */
	{ "GPM103", 0x07 },				/* GPM 103 */
	{ "GPM256", 0x03 },				/* GPM 256 */
	{ "GPM271", 0x0E },				/* GPM 271 */
	{ "GPM276", 0x0D },				/* GPM 276 */
	{ "GPM416", 0x04 }, { "GPM896", 0x04 },
									/* GPM 416/896 in standard mode */
	{ "GPM416R", 0x14 }, { "GPM896R", 0x14 },
									/* GPM 416/896 in personalization mode */
	{ "GPM2K", 0x09 },				/* GPM 2K/SLE4432/PCB2032 */
	{ "GPM8K", 0x08 },				/* GPM 8K/SLE4418 */
	{ "GAM", 0x10 }, { "GAM144", 0x10 },	/* GAM 144 */
	{ "GAM226", 0x0F },				/* GAM 226 */
	{ "GSM1K", 0xF4 }, { "GSM4K", 0xF6 },	/* GSM cards */
	{ NULL, 0 }
	};

/****************************************************************************
*																			*
*						 		Init/Shutdown Routines						*
*																			*
****************************************************************************/

/* Global function pointers.  These are necessary because the functions need
   to be dynamically linked since not all systems contain the necessary
   DLL's.  Explicitly linking to them will make cryptlib unloadable on most
   systems */

#define NULL_HINSTANCE	( HINSTANCE ) NULL

#ifdef __WIN16__
  #define GEMPLUS_API	__far __pascal
#else
  #define GEMPLUS_API	__stdcall
#endif /* __WIN16__ */

static HINSTANCE hScard = NULL_HINSTANCE;

typedef short ( GEMPLUS_API *G4_CLOSECHANNEL )( const WORD channelNo );
typedef short ( GEMPLUS_API *G4_CLOSESESSION )( const WORD channelNo );
typedef short ( GEMPLUS_API *G4_EXCHANGEAPDU )( const WORD channelNo,
												G4_APDU_COMM *apduComm,
												G4_APDU_RESP *apduResp );
typedef short ( GEMPLUS_API *G4_IFDEXCHANGE )( const WORD channelNo,
											   const LONG timeout,
											   const LONG sendLength,
											   const BYTE *sendBuffer,
											   LONG *readLength,
											   const BYTE *readBuffer );
typedef short ( GEMPLUS_API *G4_LOCKCHANNEL )( const WORD channelNo );
typedef short ( GEMPLUS_API *G4_OPENCHANNEL )( const G4_CHANNEL_PARAM *channel );
typedef short ( GEMPLUS_API *G4_OPENSESSION )( const WORD channelNo,
											   const G4_SESSION_PARAM *session );
typedef short ( GEMPLUS_API *G4_UNLOCKCHANNEL )( const WORD channelNo );
static G4_CLOSECHANNEL pG4_CloseChannel = NULL;
static G4_CLOSESESSION pG4_CloseSession = NULL;
static G4_EXCHANGEAPDU pG4_ExchangeAPDU = NULL;
static G4_IFDEXCHANGE pG4_IFDExchange = NULL;
static G4_LOCKCHANNEL pG4_LockChannel = NULL;
static G4_OPENCHANNEL pG4_OpenChannel = NULL;
static G4_OPENSESSION pG4_OpenSession = NULL;
static G4_UNLOCKCHANNEL pG4_UnlockChannel = NULL;

/* Depending on whether we're running under Win16 or Win32 we load the card
   driver under a different name */

#ifdef __WIN16__
  #define GEMPLUS_LIBNAME	"WGCR40.DLL"
#else
  #define GEMPLUS_LIBNAME	"W32GCR40.DLL"
#endif /* __WIN16__ */

/* Dynamically load and unload any necessary smart card drivers */

void scardInitGemplus( void )
	{
#ifdef __WIN16__
	UINT errorMode;
#endif /* __WIN16__ */
	static BOOLEAN initCalled = FALSE;

	/* If we've previously tried to init the drivers, don't try it again */
	if( initCalled )
		return;
	initCalled = TRUE;

	/* Obtain a handle to the smart card driver module */
#ifdef __WIN16__
	errorMode = SetErrorMode( SEM_NOOPENFILEERRORBOX );
	hScard = LoadLibrary( GEMPLUS_LIBNAME );
	SetErrorMode( errorMode );
	if( hScard == NULL_HINSTANCE )
		return;
#else
	if( ( hScard = LoadLibrary( GEMPLUS_LIBNAME ) ) == NULL_HINSTANCE )
		return;
#endif /* __WIN32__ */

	/* Now get pointers to the functions */
	pG4_CloseChannel = ( G4_CLOSECHANNEL ) GetProcAddress( hScard, "G4_CloseChannel" );
	pG4_CloseSession = ( G4_CLOSESESSION ) GetProcAddress( hScard, "G4_CloseSession" );
	pG4_ExchangeAPDU = ( G4_EXCHANGEAPDU ) GetProcAddress( hScard, "G4_ExchangeApdu" );
	pG4_IFDExchange = ( G4_IFDEXCHANGE ) GetProcAddress( hScard, "G4_IFDExchange" );
	pG4_LockChannel = ( G4_LOCKCHANNEL ) GetProcAddress( hScard, "G4_LockChannel" );
	pG4_OpenChannel = ( G4_OPENCHANNEL ) GetProcAddress( hScard, "G4_OpenChannel" );
	pG4_OpenSession = ( G4_OPENSESSION ) GetProcAddress( hScard, "G4_OpenSession" );
	pG4_UnlockChannel = ( G4_UNLOCKCHANNEL ) GetProcAddress( hScard, "G4_UnlockChannel" );

	/* Make sure we got valid pointers for every card function */
	if( pG4_CloseChannel == NULL || pG4_CloseSession == NULL ||
		pG4_ExchangeAPDU == NULL || pG4_IFDExchange == NULL ||
		pG4_LockChannel == NULL || pG4_OpenChannel == NULL ||
		pG4_OpenSession == NULL || pG4_UnlockChannel == NULL )
		{
		/* Free the library reference and reset the handle */
		FreeLibrary( hScard );
		hScard = NULL_HINSTANCE;
		}
	}

void scardEndGemplus( void )
	{
	if( hScard != NULL_HINSTANCE )
		FreeLibrary( hScard );
	hScard = NULL_HINSTANCE;
	}

/****************************************************************************
*																			*
*						 		Utility Routines							*
*																			*
****************************************************************************/

/* The service routine used for card presence detection.  In theory we should
   use G4_ICCDetection() for this, but the way it works is so braindamaged
   that it's completely useless: When called, it blocks until a card status
   change occurs, at which point it calls the callback routine with a value
   or 0 or 1 to indicate the card presence, and then returns to the caller.
   Even the Gemplus sample code includes a comment that this routine
   shouldn't be used.

   Because of this, we instead use G4_IFDExchange() to send a ROS/OROS card
   presence command to the reader and use the result of that.  Since this
   needs to be done periodically, we register the monitoring routine as a
   cryptlib  kernel service */

static int gemplusCardDetection( int serviceValue, void *servicePtr )
	{
	SCARD_INFO *scardInfo = ( SCARD_INFO * ) servicePtr;
	BYTE buffer[ 5 ];
	short readerHandle = MK_GEMPLUS( scardInfo->readerHandle );
	long length = 5;
	int status;

	/* Send a ROS/OROS command to the reader to query the card presence.  If
	   the card has been removed, the third bit of the second byte returned
	   will be zero */
	status = pG4_IFDExchange( readerHandle, 500, 2, "\x24\x03", &length,
							  buffer );
	if( status >= 0 && ( buffer[ 1 ] & 4 ) )
		;
#if 0
		krnlSendBroadcast( RESOURCE_TYPE_CRYPT, RESOURCE_MESSAGE_PARTIAL_DESTROY,
						   NULL, 0 );
#endif

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Reader Init/Shutdown Routines					*
*																			*
****************************************************************************/

/* Close a previously-opened session with the reader.  We have to have this
   before initReader() since it may be called by initReader() if the init
   process fails */

static void shutdownReader( SCARD_INFO *scardInfo )
	{
	short readerHandle = MK_GEMPLUS( scardInfo->readerHandle );

	/* Deregister the card status monitoring routine */
// Corresponding register function not fully implemented yet
//	deregisterServiceRoutine( scardInfo->serviceID );

	/* Close the session with the card */
	pG4_CloseSession( readerHandle );

	/* Unlock the channel and clean up */
	pG4_UnlockChannel( readerHandle );
	pG4_CloseChannel( readerHandle );
	scardInfo->readerHandle = 0;
	}

/* Open a session with a reader */

static int initReader( SCARD_INFO *scardInfo, const char *readerName,
					   const char *cardName, const COMM_PARAMS *commParams )
	{
	G4_CHANNEL_PARAM channelParam;
	G4_SESSION_PARAM sessionParam;
	WORD readerHandle;
	int readerType, status;
	char *readerNamePtr = ( char * ) readerName;
	char *cardNamePtr = ( char * ) cardName;

	/* If there are no reader or card type given, use the default values */
	if( *readerName == '\0' )
		readerNamePtr = DEFAULT_READER;
	if( cardNamePtr == NULL )
		cardNamePtr = DEFAULT_CARD;

	/* Determine the reader and card magic ID to use */
	readerType = stringToValue( readerIDtable, readerNamePtr );
	if( readerType == CRYPT_ERROR )
		return( CRYPT_ARGERROR_STR1 );	/* Unknown reader type */
	scardInfo->cardType = stringToValue( cardIDtable, cardNamePtr );
	if( readerType == CRYPT_ERROR )
		return( CRYPT_ARGERROR_STR2 );	/* Unknown card type */

	/* Set up the channel parameters */
	channelParam.ifdType = readerType;
	channelParam.ifdBaudRate = 38400;
	channelParam.ifdMode = G_SERIAL;
	channelParam.serial.port = ( commParams->port == 1 ) ? G_COM1 : \
							   ( commParams->port == 2 ) ? G_COM2 : \
							   ( commParams->port == 3 ) ? G_COM3 : G_COM4;
	channelParam.serial.baudRate = 38400;
	channelParam.serial.itNumber = 0xFF;

	/* Open the connection to the reader and lock it for exclusive use */
	readerHandle = pG4_OpenChannel( &channelParam );
	if( ( short int ) readerHandle < 0 )
		{
		*scardInfo->errorCode = ( short int ) readerHandle;
		return( CRYPT_ERROR_OPEN );
		}
	pG4_LockChannel( readerHandle );
	scardInfo->readerHandle = MK_HANDLE( readerHandle );

	/* Open the session to the card in the reader.  This gets kind of
	   complicated because of the weird emulation of ISO cards which the
	   Gemplus reader performs when it finds an I2C card.  Instead of
	   completely emulating an ISO card, it performs only partial emulation,
	   and requires the caller to explicitly inform the reader that the card
	   is an I2C one, even though the reader can tell this itself.

	   One artifact of this is that instead of returning a full ATR and
	   encoding the fact that the card is an I2C one in the ATR, the reader
	   returns only a partial ATR, or an error code if the indicated card
	   type is incorrect.  To make things worse, it treats anything which
	   doesn't respond with a proper ATR as an I2C card, so that (for
	   example) a mag stripe card will return the same response as an I2C
	   card.

	   To work around this, we first try the access for an ISO card, which
	   only succeeds if a full ATR is returned.  If that fails, we retry the
	   access for an I2C card.  This always succeeds (provided a card is
	   present and everything else is in order), we have to wait until the
	   user tries to read or write data before we can detect any type of
	   problem */
	memset( &sessionParam, 0, sizeof( G4_SESSION_PARAM ) );
	sessionParam.iccType = ( scardInfo->cardType == CARDTYPE_NONE ) ? \
						   CARDTYPE_ISO : scardInfo->cardType;
	status = pG4_OpenSession( readerHandle, &sessionParam );
	if( status < 0 && scardInfo->cardType == CARDTYPE_NONE )
		{
		/* If we were trying a blind read with an ISO card, retry it with an
		   I2C card.  Trying to read an I2C card with the ISO protocol tends
		   to return either -450 (parameter out of range, which is odd since
		   it's a host status code) or -4 (card removed), however this may
		   vary between cards so we can't explicitly check for this */
		memset( &sessionParam, 0, sizeof( G4_SESSION_PARAM ) );
		sessionParam.iccType = CARDTYPE_I2C;
		status = pG4_OpenSession( readerHandle, &sessionParam );

		/* Check that the reader returned the correct pseudo-ATR for an I2C
		   card.  The reader always appears to return this pseudo-ATR (even
		   for things like mag stripe cards) so this check probably has no
		   effect */
		if( status == 0 && ( sessionParam.resetLen != 2 || \
							 sessionParam.atr[ 0 ] != 0x3B ) )
			status = -3;	/* Gemplus "Card not supported" code */
		}
	if( status < 0 )
		{
		*scardInfo->errorCode = status;
		shutdownReader( scardInfo );
		return( CRYPT_ERROR_OPEN );
		}
	if( scardInfo->cardType == CARDTYPE_NONE )
		scardInfo->cardType = sessionParam.iccType;

	/* Register the card status monitoring routine */
// Not fully implemented yet
//	scardInfo->serviceID = registerServiceRoutine( NULL,
//											gemplusCardDetection, 0 );
/*!!!!!!!!!!!!!!!!!!*/
{
BYTE buffer[ 5 ];
long length = 5;
#if 0
int status =	// -211, not supported, W32GCR40.DLL, 14/11/96
	pG4_ICCDetection( readerHandle, 500, gemplusCallback, hInst );
#endif /* 0 */
status =
	pG4_IFDExchange( readerHandle, 1000, 1, "\x2A", &length, buffer );
status =
	pG4_IFDExchange( readerHandle, 2000, 7, "\x2B\x80Hello", &length, buffer );
status =
	pG4_IFDExchange( readerHandle, 1000, 1, "\x29", &length, buffer );
if( length );
}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Card Read/Write Routines						*
*																			*
****************************************************************************/

/* Exchange an APDU with the card */

static int exchangeAPDU( const WORD readerHandle, const BYTE *isoCode,
						 const BYTE *dataIn, const int lengthIn,
						 const BYTE *dataOut, const int lengthOut )
	{
	G4_APDU_RESP apduResp;
	G4_APDU_COMM apduComm;

	/* Set up the APDU and send it to the card */
	memset( &apduComm, 0, sizeof( G4_APDU_COMM ) );
	memcpy( apduComm.command, isoCode, 4 );
	apduComm.lengthIn = lengthIn;
	apduComm.dataIn = ( BYTE * ) dataIn;
	apduComm.lengthExpected = lengthOut;
	memset( &apduResp, 0, sizeof( G4_APDU_RESP ) );
	apduResp.dataOut = ( BYTE * ) dataOut;
	return( pG4_ExchangeAPDU( readerHandle, &apduComm, &apduResp ) );
	}

/* I2C cards can generally only read/write I2C_STRIDE bytes at a time,
   so we need to break any data we're writing into chunks before we pass
   it to exchangeAPDU() */

static int writeI2C( const WORD readerHandle, const BYTE *isoCommand,
					 const BYTE *data, const int length )
	{
	BYTE isoCode[ 4 ];
	int i, status;

	memset( isoCode, 0, 4 );
	memcpy( isoCode, isoCommand, 2 );
	for( i = 0; i < length; i += I2C_STRIDE )
		{
		int dataLength = min( length - i, I2C_STRIDE );

		isoCode[ 2 ] = i >> I2C_STRIDE;
		isoCode[ 3 ] = i & 0xFF;
		status = exchangeAPDU( readerHandle, isoCode, data + i, dataLength,
							   NULL, 0 );
		if( status )
			break;
		}

	return( status );
	}

static int readI2C( const WORD readerHandle, const BYTE *isoCommand,
					BYTE *data, const int startPos, const int length )
	{
	BYTE isoCode[ 4 ];
	int status, i;

	memset( isoCode, 0, 4 );
	memcpy( isoCode, isoCommand, 2 );
	for( i = 0; i < length; i += I2C_STRIDE )
		{
		int dataLength = min( length - i, I2C_STRIDE );
		int dataPos = startPos + i;

		isoCode[ 2 ] = dataPos >> I2C_STRIDE;
		isoCode[ 3 ] = dataPos & 0xFF;
		status = exchangeAPDU( readerHandle, isoCode, NULL, 0,
							   data + i, dataLength );
		if( status )
			break;
		}

	return( status );
	}

/* Write a byte at a given position.  This is used to test whether the card
   can write data at this position (that is, whether it has the storage
   capacity to write to this point) */

static int writeTest( const WORD readerHandle, const int offset )
	{
	BYTE isoCode[ 4 ];

	isoCode[ 0 ] = 0x00;
	isoCode[ 1 ] = 0xD0;
	isoCode[ 2 ] = ( offset >> 8 ) & 0xFF;
	isoCode[ 3 ] = offset & 0xFF;
	return( exchangeAPDU( readerHandle, isoCode, "", 1, NULL, 0 ) );
	}

/* Read the data header from the card */

static int readCardHeader( const WORD readerHandle, BYTE *data,
						   const BOOLEAN isI2C )
	{
	int length, status;

	/* Read enough data from the card that we can determine how much more we
	   have to read.  I2C cards often have a maximum read length of
	   I2C_STRIDE bytes, so we make this the amount we read */
	if( isI2C )
		status = readI2C( readerHandle, "\x00\xB0", data, 0, I2C_STRIDE );
	else
		status = exchangeAPDU( readerHandle, "\x00\x00\x00\x00", NULL, 0,
							   data, I2C_STRIDE );
	if( status )
		return( CRYPT_ERROR_READ );
	length = getObjectLength( data, I2C_STRIDE );
	return( length );
	}

/* Erase a card */

static int eraseCard( const WORD readerHandle, const BOOLEAN isI2C )
	{
	BYTE buffer[ 16384 ];
	int length, status;

	/* Read the length information from the card */
	length = readCardHeader( readerHandle, buffer, isI2C );
	if( cryptStatusError( length ) )
		{
		/* If the call fails because there's no cryptlib data on the card, we
		   just try and write as much as possible */
		if( length != CRYPT_ERROR_BADDATA )
			return( length );
		length = 16384;
		}

	/* Create a zero-filled buffer of the appropriate length to use for
	   overwriting the data on the card */
	if( length > 16384 )
		length = 16384;
	memset( buffer, 0, length );

	/* Write the data to the card */
	if( isI2C )
		{
		status = writeI2C( readerHandle, "\x00\xD0", buffer, length );
		if( length == 16384 && status == -311 )
			/* If the write fails with a -311 error code, we tried to write
			   more data than the card can store.  If this was a generic
			   "write as much as possible" write then this isn't an error,
			   since we've erased the entire card */
			status = CRYPT_OK;
		}
	else
		status = exchangeAPDU( readerHandle, "\x00\x00\x00\x00", buffer,
							   length, NULL, 0 );

	return( status );
	}

/* Write data to a card */

static int writeData( SCARD_INFO *scardInfo, const BYTE *data,
					  const int length )
	{
	const WORD readerHandle = MK_GEMPLUS( scardInfo->readerHandle );
	const BOOLEAN isI2C = ( scardInfo->cardType == CARDTYPE_I2C ) ? \
						  TRUE : FALSE;
	int status;

	/* If it's an I2C card we have to tell the reader to use the pseudo-
	   7816-4 protocol which is used to talk to the cards */
	if( isI2C )
		{
		/* Send a "define card type" command to the reader */
		status = exchangeAPDU( readerHandle, "\x00\x02\x06\x00", NULL, 0, NULL, 0 );
		if( status < 0 )
			{
			*scardInfo->errorCode = status;
			return( CRYPT_ERROR_WRITE );
			}
		}

	/* If we've been passed a null data record, we need to overwrite the data
	   on the card */
	if( data == NULL )
		status = eraseCard( readerHandle, isI2C );
	else
		{
		/* Try and write a single byte at the maximum data position to see
		   whether the card has the necessary capacity */
		if( writeTest( readerHandle, length - 1 ) == -311 )
			/* If the write fails with a -311 error code, we tried to write
			   more data than the card can store, which we turn into a
			   CRYPT_ERROR_OVERFLOW error */
			return( CRYPT_ERROR_OVERFLOW );

		/* Write the data to the card */
		if( isI2C )
			status = writeI2C( readerHandle, "\x00\xD0", data, length );
		else
			status = exchangeAPDU( readerHandle, "\x00\x00\x00\x00", data,
								   length, NULL, 0 );
		}
	if( status )
		{
		/* If we tried to write cryptlib data to the card and it failed,
		   try to erase what was written */
		if( data != NULL )
			eraseCard( readerHandle, isI2C );

		*scardInfo->errorCode = status;
		return( CRYPT_ERROR_WRITE );
		}

	return( CRYPT_OK );
	}

/* Read data from a card */

static int readData( SCARD_INFO *scardInfo, BYTE *data )
	{
	const WORD readerHandle = MK_GEMPLUS( scardInfo->readerHandle );
	const BOOLEAN isI2C = ( scardInfo->cardType == CARDTYPE_I2C ) ? \
						  TRUE : FALSE;
	int length, status;

	/* If it's an I2C card we have to tell the reader to use the pseudo-
	   7816-4 protocol which is used to talk to the cards */
	if( isI2C )
		{
		/* Send a "define card type" command to the reader */
		status = exchangeAPDU( readerHandle, "\x00\x02\x06\x00", NULL, 0, NULL, 0 );
		if( status < 0 )
			{
			*scardInfo->errorCode = status;
			return( CRYPT_ERROR_READ );
			}
		}

	/* Read enough data from the card that we can determine how much more we
	   have to read */
	length = readCardHeader( readerHandle, data, isI2C );
	if( cryptStatusError( length ) )
		return( length );

	/* Read the data from the card */
	if( isI2C )
		status = readI2C( readerHandle, "\x00\xB0", data + I2C_STRIDE, I2C_STRIDE,
						  length - I2C_STRIDE );
	else
		status = exchangeAPDU( readerHandle, "\x00\x00\x00\x00", NULL, 0,
							   data + I2C_STRIDE, length - I2C_STRIDE );
	if( status < 0 )
		{
		*scardInfo->errorCode = status;
		return( CRYPT_ERROR_READ );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Card Access Routines							*
*																			*
****************************************************************************/

/* Set up the function pointers to the access methods */

int setAccessMethodGemplus( SCARD_INFO *scardInfo )
	{
#ifdef __WINDOWS__
	/* Load the Gemplus driver DLL's if they aren't already loaded */
	if( hScard == NULL_HINSTANCE )
		{
		scardInitGemplus();
		if( hScard == NULL_HINSTANCE )
			return( CRYPT_ERROR_OPEN );
		}
#endif /* __WINDOWS__ */

	scardInfo->initReader = initReader;
	scardInfo->shutdownReader = shutdownReader;
	scardInfo->readData = readData;
	scardInfo->writeData = writeData;

	return( CRYPT_OK );
	}
