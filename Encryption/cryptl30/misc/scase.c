/****************************************************************************
*																			*
*					cryptlib ASE Smart Card Reader Routines					*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

/* This file contains its own version of the various ASE definitions and
   values to avoid potential copyright problems with redistributing the ASE
   header files */

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

/* Constants */

#define MAIN_SOCKET			0x03	/* Use reader main socket */
#define SECONDARY_SOCKET	0x02	/* Use reader secondary socket */

#define CARD_POWER_UP		0x01	/* Fire up the card */
#define CARD_RESET			0x10	/* Reset the card */

#define MEM_CARD_DATA		0x10	/* Write data only */
#define MEM_CARD_PROTECT	0x13	/* Write data and protect it */

#define PROTOCOL_CPU7816_AUTODETECT	0x0000FFFF
#define PROTOCOL_CPU7816_T0		0x00000001
#define PROTOCOL_CPU7816_T1		0x00000002
#define PROTOCOL_CPU7816_T14	0x00004000
#define PROTOCOL_MEM7816_AUTODETECT	0x00FF0000
#define PROTOCOL_MEM7816_2BUS	0x00010000
#define PROTOCOL_MEM7816_3BUS	0x00020000
#define PROTOCOL_MEM7816_I2C	0x00400000
#define PROTOCOL_MEM_I2C		0x01000000
#define PROTOCOL_MEM_XI2C		0x02000000

/* Data types */

#define ASEAPI		__stdcall
typedef DWORD ASERESULT;
typedef HANDLE HASEREADER, FAR *LPHASEREADER;
typedef HANDLE HASECARD, FAR *LPHASECARD;

/* Data structures */

typedef struct {
	BOOL bMainCardPresence;			/* Main card present */
	BOOL bSecondCardPresence;		/* Secondary card present */
	} ASEREADERSTATE, FAR *LPASEREADERSTATE;

typedef struct {
	WORD address;					/* Start address */
	WORD mode;						/* Mode of operation */
	WORD length;					/* Length */
	} ASEIO_MEM, FAR *LPASEIO_MEM;

typedef struct {
	BYTE SW1, SW2, Cla, Ins, P1, P2, P3;/* T=0 command info */
	} ASEIO_T0, FAR *LPASEIO_T0;

typedef struct {
	BYTE NAD;						/* Node address length */
	BYTE Len;						/* Data length */
	} ASEIO_T1, FAR *LPASEIO_T1;

/* Function prototypes */

ASERESULT ASEAPI ASECardPowerOff( HASECARD hAseCard );
ASERESULT ASEAPI ASECardPowerOn( HASEREADER hAseReader, WORD wSocket,
								 WORD wAction, DWORD dwPreferedProtocol,
								 LPDWORD lpdwActiveProtocol,
								 LPHASECARD phAseCard );
ASERESULT ASEAPI ASEGetReaderStatus( HASEREADER hAseReader,
									 LPASEREADERSTATE lpReaderState );
ASERESULT ASEAPI ASEMemCardRead( HASECARD hAseCard, LPASEIO_MEM lpIORequest,
								 LPBYTE lpchDataBuffer, LPWORD lpwDataLength );
ASERESULT ASEAPI ASEMemCardWrite( HASECARD hAseCard, LPASEIO_MEM lpIORequest,
								  LPBYTE lpchDataBuffer );
ASERESULT ASEAPI ASEReaderClose( HASEREADER hAseReader );
ASERESULT ASEAPI ASEReaderOpenByName( LPCSTR lpszAseReaderName,
									  LPHASEREADER lphAseReader );
ASERESULT ASEAPI ASEReaderOpenByPort( LPCSTR lpszPortName,
									  LPHASEREADER lphAseReader );
ASERESULT ASEAPI ASET0CardRead( HASECARD hAseCard, LPASEIO_T0 lpIORequest,
								LPBYTE lpchDataBuffer, LPWORD lpwDataLength );
ASERESULT ASEAPI ASET0CardWrite( HASECARD hAseCard, LPASEIO_T0 lpIORequest,
								 LPBYTE lpchDataBuffer );
ASERESULT ASEAPI ASET1CardTransact( HASECARD hAseCard, LPASEIO_T1 lpIORequest,
									LPBYTE lpbWriteDataBuffer,
									LPBYTE lpbReadDataBuffer,
									LPWORD lpwReadDataLength );

/* Error codes */

#define ASEERR_SUCCESS						0x00000000
#define	ASEERR_FAIL							0x00010000
#define ASEERR_READER_ALREADY_OPEN			0x00020000
#define ASEERR_TIMEOUT						0x00030000
#define ASEERR_WRONG_READER_NAME			0x00040000
#define ASEERR_READER_OPEN_ERROR			0x00050000
#define ASEERR_READER_COMM_ERROR			0x00060000
#define ASEERR_MAX_READERS_ALREADY_OPEN		0x00070000
#define ASEERR_INVALID_READER_HANDLE		0x00080000
#define ASEERR_SYSTEM_ERROR					0x00090000
#define ASEERR_INVALID_SOCKET				0x000A0000
#define ASEERR_OPERATION_TIMEOUT			0x000B0000
#define ASEERR_OPERATION_CANCELED			0x000C0000
#define ASEERR_INVALID_PARAMETERS			0x000D0000
#define ASEERR_PROTOCOL_NOT_SUPPORTED		0x000E0000
#define ASEERR_CARD_COMM_ERROR				0x000F0000
#define ASEERR_CARD_NOT_PRESENT				0x00100000
#define ASEERR_CARD_NOT_POWERED				0x00110000
#define ASEERR_IFSD_OVERFLOW				0x00120000
#define ASEERR_CARD_INVALID_PARAMETER		0x00130000
#define	ASEERR_INVALID_CARD_HANDLE			0x00140000
#define ASEERR_NOT_INSTALLED				0x00150000
#define ASEERR_COMMAND_NOT_SUPPORTED		0x00160000
#define ASEERR_MEMORY_CARD_ERROR			0x00170000
#define ASEERR_NO_RTC						0x00180000
#define ASEERR_WRONG_ACTIVE_PROTOCOL		0x00190000
#define ASEERR_NO_READER_AT_PORT			0x002A0000
#define ASEERR_CARD_ALREADY_POWERED			0x002B0000
#define ASEERR_NO_HL_CARD_SUPPORT			0x002C0000
#define ASEERR_CANT_LOAD_CARD_DLL			0x002D0000
#define ASEERR_WRONG_PASSWORD				0x002E0000
#define ASEWRN_SERIAL_NUMBER_MISMATCH		0x01000000

/* Magic ID's for various protocol types */

const static STRINGMAP_INFO protocolIDtable[] = {
	{ "Auto", PROTOCOL_CPU7816_AUTODETECT },
	{ "T0", PROTOCOL_CPU7816_T0 }, { "T1", PROTOCOL_CPU7816_T1 },
	{ "T14", PROTOCOL_CPU7816_T14 },
	{ "Memory Auto", PROTOCOL_MEM7816_AUTODETECT },
	{ "2-Wire", PROTOCOL_MEM7816_2BUS }, { "3-Wire", PROTOCOL_MEM7816_3BUS },
	{ "I2C", PROTOCOL_MEM_I2C }, { "XI2C", PROTOCOL_MEM_XI2C },
	{ NULL, 0 }
	};

/****************************************************************************
*																			*
*						 		Init/Shutdown Routines						*
*																			*
****************************************************************************/

#ifdef __WINDOWS__

/* Global function pointers.  These are necessary because the functions need
   to be dynamically linked since not all systems contain the necessary
   DLL's.  Explicitly linking to them will make cryptlib unloadable on most
   systems */

#define NULL_HINSTANCE	( HINSTANCE ) NULL

static HINSTANCE hScard = NULL_HINSTANCE;

typedef ASERESULT ( ASEAPI *ASECARDPOWEROFF )( HASECARD hAseCard );
typedef ASERESULT ( ASEAPI *ASECARDPOWERON )( HASEREADER hAseReader,
						WORD wSocket, WORD wAction, DWORD dwPreferedProtocol,
						LPDWORD lpdwActiveProtocol, LPHASECARD phAseCard );
typedef ASERESULT ( ASEAPI *ASEMEMCARDREAD )( HASECARD hAseCard,
						LPASEIO_MEM lpIORequest, LPBYTE lpchDataBuffer,
						LPWORD lpwDataLength );
typedef ASERESULT ( ASEAPI *ASEMEMCARDWRITE )( HASECARD hAseCard,
						LPASEIO_MEM lpIORequest, LPBYTE lpchDataBuffer );
typedef ASERESULT ( ASEAPI *ASEREADERCLOSE )( HASEREADER hAseReader );
typedef ASERESULT ( ASEAPI *ASEREADEROPENBYNAME )( LPCSTR lpszAseReaderName,
												   LPHASEREADER lphAseReader );
typedef ASERESULT ( ASEAPI *ASEREADEROPENBYPORT )( LPCSTR lpszPortName,
												   LPHASEREADER lphAseReader );
typedef ASERESULT ( ASEAPI *ASET0CARDREAD )( HASECARD hAseCard,
						LPASEIO_T0 lpIORequest, LPBYTE lpchDataBuffer,
						LPWORD lpwDataLength );
typedef ASERESULT ( ASEAPI *ASET0CARDWRITE )( HASECARD hAseCard,
						LPASEIO_T0 lpIORequest, LPBYTE lpchDataBuffer );
typedef ASERESULT ( ASEAPI *ASET1CARDTRANSACT )( HASECARD hAseCard,
						LPASEIO_T1 lpIORequest, LPBYTE lpbWriteDataBuffer,
						LPBYTE lpbReadDataBuffer, LPWORD lpwReadDataLength );
static ASECARDPOWEROFF pASECardPowerOff = NULL;
static ASECARDPOWERON pASECardPowerOn = NULL;
static ASEMEMCARDREAD pASEMemCardRead = NULL;
static ASEMEMCARDWRITE pASEMemCardWrite = NULL;
static ASEREADERCLOSE pASEReaderClose = NULL;
static ASEREADEROPENBYNAME pASEReaderOpenByName = NULL;
static ASEREADEROPENBYPORT pASEReaderOpenByPort = NULL;
static ASET0CARDREAD pASET0CardRead = NULL;
static ASET0CARDWRITE pASET0CardWrite = NULL;
static ASET1CARDTRANSACT pASET1CardTransact = NULL;

/* The use of dynamically bound function pointers vs statically linked
   functions requires a bit of sleight of hand since we can't give the
   pointers the same names as prototyped functions.  To get around this we
   redefine the actual function names to the names of the pointers */

#define ASECardPowerOff			pASECardPowerOff
#define ASECardPowerOn			pASECardPowerOn
#define ASEMemCardRead			pASEMemCardRead
#define ASEMemCardWrite			pASEMemCardWrite
#define ASEReaderClose			pASEReaderClose
#define ASEReaderOpenByName		pASEReaderOpenByName
#define ASEReaderOpenByPort		pASEReaderOpenByPort
#define ASET0CardRead			pASET0CardRead
#define ASET0CardWrite			pASET0CardWrite
#define ASET1CardTransact		pASET1CardTransact

/* Depending on whether we're running under Win16 or Win32 we load the card
   driver under a different name */

#ifdef __WIN16__
  #define SCARD_LIBNAME	"ASE.DLL"
#else
  #define SCARD_LIBNAME	"ASE32.DLL"
#endif /* __WIN16__ */

/* Dynamically load and unload any necessary smart card drivers */

void scardInitASE( void )
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
	hScard = LoadLibrary( SCARD_LIBNAME );
	SetErrorMode( errorMode );
	if( hScard == NULL_HINSTANCE )
		return;
#else
	if( ( hScard = LoadLibrary( SCARD_LIBNAME ) ) == NULL_HINSTANCE )
		return;
#endif /* __WIN32__ */

	/* Now get pointers to the functions */
	pASECardPowerOff = ( ASECARDPOWEROFF ) GetProcAddress( hScard, "ASECardPowerOff" );
	pASECardPowerOn = ( ASECARDPOWERON ) GetProcAddress( hScard, "ASECardPowerOn" );
	pASEMemCardRead = ( ASEMEMCARDREAD ) GetProcAddress( hScard, "ASEMemCardRead" );
	pASEMemCardWrite = ( ASEMEMCARDWRITE ) GetProcAddress( hScard, "ASEMemCardWrite" );
	pASEReaderClose = ( ASEREADERCLOSE ) GetProcAddress( hScard, "ASEReaderClose" );
	pASEReaderOpenByName = ( ASEREADEROPENBYNAME ) GetProcAddress( hScard, "ASEReaderOpenByName" );
	pASEReaderOpenByPort = ( ASEREADEROPENBYPORT ) GetProcAddress( hScard, "ASEReaderOpenByPort" );
	pASET0CardRead = ( ASET0CARDREAD ) GetProcAddress( hScard, "ASET0CardRead" );
	pASET0CardWrite = ( ASET0CARDWRITE ) GetProcAddress( hScard, "ASET0CardWrite" );
	pASET1CardTransact = ( ASET1CARDTRANSACT ) GetProcAddress( hScard, "ASET1CardTransact" );

	/* Make sure we got valid pointers for every card function */
	if( pASECardPowerOn == NULL || pASECardPowerOff == NULL ||
		pASEMemCardRead == NULL || pASEMemCardWrite == NULL ||
		pASEReaderClose == NULL || pASEReaderOpenByName == NULL ||
		pASEReaderOpenByPort == NULL || pASET0CardRead == NULL ||
		pASET0CardWrite == NULL || pASET1CardTransact == NULL )
		{
		/* Free the library reference and reset the handle */
		FreeLibrary( hScard );
		hScard = NULL_HINSTANCE;
		}
	}

void scardEndASE( void )
	{
	if( hScard != NULL_HINSTANCE )
		FreeLibrary( hScard );
	hScard = NULL_HINSTANCE;
	}
#endif /* __WINDOWS__ */

/****************************************************************************
*																			*
*						 		Utility Routines							*
*																			*
****************************************************************************/

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
	if( scardInfo->cardType )
		{
		ASECardPowerOff( ( HASECARD ) scardInfo->cardHandle );
		scardInfo->cardType = 0;
		}
	ASEReaderClose( ( HASEREADER ) scardInfo->readerHandle );
	scardInfo->readerHandle = 0;
	}

/* Open a session with a reader */

static int initReader( SCARD_INFO *scardInfo, const char *readerName,
					   const char *cardName, const COMM_PARAMS *commParams )
	{
	int protocol, status;

	/* Determine the card protocol to use */
	if( cardName == NULL )
		protocol = PROTOCOL_CPU7816_AUTODETECT;
	else
		protocol = stringToValue( protocolIDtable, cardName );
	if( protocol == CRYPT_ERROR )
		return( CRYPT_ARGERROR_STR2 );	/* Unknown protocol type */

	/* Initialise the reader based on its name or port */
	if( readerName != NULL )
		status = ASEReaderOpenByName( readerName, 
							( LPHASEREADER ) &scardInfo->readerHandle );
	else
		status = ASEReaderOpenByPort( commParams->portName,
							( LPHASEREADER ) &scardInfo->readerHandle );
	if( status != ASEERR_SUCCESS )
		{
		*scardInfo->errorCode = status;
		return( CRYPT_ERROR_OPEN );
		}

	/* Fire up the card */
	status = ASECardPowerOn( ( HASEREADER ) scardInfo->readerHandle, 
							 MAIN_SOCKET, CARD_POWER_UP, protocol, 
							 &scardInfo->cardType,
							 ( LPHASECARD ) &scardInfo->cardHandle );
	if( status != ASEERR_SUCCESS )
		{
		shutdownReader( scardInfo );
		*scardInfo->errorCode = status;
		return( CRYPT_ERROR_OPEN );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Card Read/Write Routines						*
*																			*
****************************************************************************/

/* Low-level read/write routines */

static int cardWrite( const SCARD_INFO *scardInfo, const BYTE *data,
					  const int position, const int length )
	{
	int status;

	/* Write the data using the appropriate function */
	if( scardInfo->cardType == PROTOCOL_MEM7816_2BUS || \
		scardInfo->cardType == PROTOCOL_MEM7816_3BUS || \
		scardInfo->cardType == PROTOCOL_MEM7816_I2C || \
		scardInfo->cardType == PROTOCOL_MEM_I2C || \
		scardInfo->cardType == PROTOCOL_MEM_XI2C )
		{
		ASEIO_MEM memRequest = { 0, MEM_CARD_DATA, length };

		status = ASEMemCardWrite( ( HASECARD ) scardInfo->cardHandle, 
								  &memRequest, ( LPBYTE ) data );
		}
	else
		if( scardInfo->cardType == PROTOCOL_CPU7816_T0 )
			{
			ASEIO_T0 ioRequest = { 0 };

			status = ASET0CardWrite( ( HASECARD ) scardInfo->cardHandle, 
									 &ioRequest, ( LPBYTE ) data );
			}
		else
			{
			ASEIO_T1 ioRequest = { 0, 0 };
			BYTE writeBuffer[ 10 ];
			WORD dataLength = ( WORD ) length;

			status = ASET1CardTransact( ( HASECARD ) scardInfo->cardHandle, 
										&ioRequest, writeBuffer, 
										( LPBYTE ) data, &dataLength );
			}

	return( status );
	}

static int cardRead( const SCARD_INFO *scardInfo, BYTE *data,
					 const int position, const int length )
	{
	WORD dataLength = ( WORD ) length;
	int status;

	/* Write the data using the appropriate function */
	if( scardInfo->cardType == PROTOCOL_MEM7816_2BUS || \
		scardInfo->cardType == PROTOCOL_MEM7816_3BUS || \
		scardInfo->cardType == PROTOCOL_MEM7816_I2C || \
		scardInfo->cardType == PROTOCOL_MEM_I2C || \
		scardInfo->cardType == PROTOCOL_MEM_XI2C )
		{
		ASEIO_MEM memRequest = { 0, MEM_CARD_DATA, length };

		status = ASEMemCardRead( ( HASECARD ) scardInfo->cardHandle, 
								 &memRequest, data, &dataLength );
		}
	else
		if( scardInfo->cardType == PROTOCOL_CPU7816_T0 )
			{
			ASEIO_T0 ioRequest = { 0 };

			status = ASET0CardRead( ( HASECARD ) scardInfo->cardHandle, 
									&ioRequest, data, &dataLength );
			}
		else
			{
			ASEIO_T1 ioRequest = { 0, length };
			BYTE readBuffer[ 10 ];

			dataLength = 10;
			status = ASET1CardTransact( ( HASECARD ) scardInfo->cardHandle, 
										&ioRequest, data, readBuffer, &dataLength );
			}

	return( status );
	}

/* Erase a card */

static int eraseCard( const SCARD_INFO *scardInfo )
	{
	BYTE buffer[ 16384 ];
	int length, status;

	/* Read the length information from the card */
	cardRead( scardInfo, buffer, 0, 8 );
	length = getObjectLength( buffer, 8 );
	if( cryptStatusError( length ) )
		/* If the call fails because there's no cryptlib data on the card, we
		   just try and write as much as possible */
		length = 16384;
	else
		if( length > 16384 )
			length = 16384;

	/* Write the zero-filled buffer to the card */
	memset( buffer, 0, length );
	status = cardWrite( scardInfo, buffer, 0, length );
	if( length == 16384 && status == ASEERR_MEMORY_CARD_ERROR )
		/* If the write failed with a memory card error, we tried to write
		   more data than the card can store.  If this was a generic "write
		   as much as possible" write then this isn't an error, since we've
		   erased the entire card */
		status = ASEERR_SUCCESS;

	return( status );
	}

/* Write data to a card */

static int writeData( SCARD_INFO *scardInfo, const BYTE *data,
					  const int length )
	{
	int status;

	/* If we've been passed a null data record, we need to overwrite the data
	   on the card */
	if( data == NULL )
		status = eraseCard( scardInfo );
	else
		{
		/* Try and write a single byte at the maximum data position to see
		   whether the card has the necessary capacity */
		if( cardWrite( scardInfo, "\x00", length - 1, 1 ) == ASEERR_MEMORY_CARD_ERROR )
			/* If the write fails with a memory card error code, we tried to
			   write more data than the card can store, which we turn into a
			   CRYPT_ERROR_OVERFLOW error */
			return( CRYPT_ERROR_OVERFLOW );

		/* Write the data to the card */
		status = cardWrite( scardInfo, data, 0, length );
		}
	if( status != ASEERR_SUCCESS )
		{
		/* If we tried to write cryptlib data to the card and it failed,
		   try to erase what was written */
		if( data != NULL )
			eraseCard( scardInfo );

		*scardInfo->errorCode = status;
		return( CRYPT_ERROR_WRITE );
		}

	return( CRYPT_OK );
	}

/* Read data from a card */

static int readData( SCARD_INFO *scardInfo, BYTE *data )
	{
	int length, status;

	/* Read the data using the appropriate protocol.  First we read enough
	   data from the card that we can determine how much more we have to
	   read, then we read the rest */
	status = cardRead( scardInfo, data, 0, 16 );
	if( status == ASEERR_SUCCESS )
		{
		length = getObjectLength( data, 16 );
		status = cardRead( scardInfo, data + 16, 16, length - 16 );
		}
	if( status != ASEERR_SUCCESS )
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

int setAccessMethodASE( SCARD_INFO *scardInfo )
	{
#ifdef __WINDOWS__
	/* Load the ASE driver DLL if it isn't already loaded */
	if( hScard == NULL_HINSTANCE )
		{
		scardInitASE();
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
