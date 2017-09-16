/****************************************************************************
*																			*
*					cryptlib Towitoko Smart Card Reader Routines			*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

#include <stdio.h>
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

#ifdef __WINDOWS__
  #ifdef __WIN16__
	#define SCARD_API	FAR PASCAL _export
  #else
	#define SCARD_API	__stdcall
  #endif /* Windows version-specific entry types */
#else
  #define SCARD_API
#endif /* OS-specific entry types */

/* The size of the buffer used to receive information from the card
   server */

#define BUFFER_SIZE		256

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

typedef long ( SCARD_API *SCARDCOMMAND )( const long *handle, const char *Cmd,
			   const long *CmdLen, const char *DataIn, const long *DataInLen, 
			   char *DataOut, long *DataOutLen );
SCARDCOMMAND pSCardCommand;

/* The use of dynamically bound function pointers vs statically linked
   functions requires a bit of sleight of hand since we can't give the
   pointers the same names as prototyped functions.  To get around this we
   redefine the actual function names to the names of the pointers */

#define SCardCommand		pSCardCommand

/* Sometimes all we need to send is a simple control command with no 
   params, the following macro does this for us */

#define SCardControl( command )	\
		SCardCommand( &hInstance, command, 0, NULL, 0, NULL, NULL )

/* Depending on whether we're running under Win16 or Win32 we load the card
   driver under a different name */

#ifdef __WIN16__
  #define SCARD_LIBNAME	"SCARD.DLL"
#else
  #define SCARD_LIBNAME	"SCARD32.DLL"
#endif /* __WIN16__ */

/* Dynamically load and unload any necessary smart card drivers */

void scardInitTowitoko( void )
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
	SCardCommand = ( SCARDCOMMAND ) GetProcAddress( hScard,"SCardComand" );

	/* Make sure we got valid pointers for every card function */
	if( SCardCommand == NULL )
		{
		/* Free the library reference and reset the handle */
		FreeLibrary( hScard );
		hScard = NULL_HINSTANCE;
		}
	}

void scardEndTowitoko( void )
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

/* Get info from the driver/device/card */

static int getInfo( const char *string, char *buffer )
	{
	long hInstance = 0;
	int outLen = BUFFER_SIZE, status;

	status = SCardCommand( &hInstance, string, 0, NULL, 0, buffer, &outLen );
	if( outLen >= 0 && outLen < BUFFER_SIZE )
		buffer[ outLen ] = '\0';
	return( status );
	}

/* Get information on a card reader error */

static void getErrorInfo( SCARD_INFO *scardInfo )
	{
	char buffer[ 255 ];
	long hInstance = 0;
	int outLen = 255;

	SCardCommand( &hInstance, "System,Info,ErrCode", 0, NULL, 0, buffer, &outLen );
	*scardInfo->errorCode = atoi( buffer );
	outLen = 255;
	SCardCommand( &hInstance, "System,Info,ErrText", 0, NULL, 0, buffer, &outLen );
	strncpy( scardInfo->errorMessage, buffer, outLen );
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
	long hInstance = 0;

	/* Turn off the LED */
	SCardControl( "Device,SetLed,0" );

	scardInfo->readerHandle = 0;
	}

/* Open a session with a reader */

static int initReader( SCARD_INFO *scardInfo, const char *readerName,
					   const char *cardName, const COMM_PARAMS *commParams )
	{
	char buffer[ BUFFER_SIZE ];
	long hInstance;
	int status;

	UNUSED( cardName );
	UNUSED( commParams );

	if( *readerName == '\0' )
		status = SCardControl( "Device,Select,-1" );
	else
		{
		strcpy( buffer, "Device,Select," );
		strcat( buffer, readerName );
		status = SCardControl( buffer );
		}
	if( status == CRYPT_OK )
		{
		/* Driver bug: Unless we insert a small delay at this point, the
		   driver status call will always return an error */
		Sleep( 250 );

		/* The select only goes to the driver, make sure the reader 
		   responded */
		status = getInfo( "Device,Info,Status", buffer );
		if( status || stricmp( buffer, "valid" ) )
			status = CRYPT_ERROR;
		}
	if( status )
		{
		getErrorInfo( scardInfo );
		return( CRYPT_ERROR_OPEN );
		}
	status = getInfo( "Card,Info,Status", buffer );
	if( status || \
		!( stricmp( buffer, "error" ) && stricmp( buffer, "invalid" ) ) )
		{
		SCardControl( "Device,SetLed,1" );		/* Red LED */
		return( CRYPT_OK );
		}

	/* We've got a card in the reader, make sure it's a known one (for now 
	   we only treat I2C and full ISO 7816 cards as "known") */
	scardInfo->readerHandle = 1;	/* Clear error value */
	status = getInfo( "Card,Info,Type", buffer );
	if( status || \
		( stricmp( buffer, "cpu" ) && strnicmp( buffer, "i2c", 3 ) ) )
		{
		SCardControl( "Device,SetLed,3" );	/* Yellow LED */
		return( CRYPT_OK );
		}

	/* Remember the card type and indicate that all is OK */
	if( !strnicmp( buffer, "i2c", 3 ) )
		scardInfo->cardType = TRUE;		/* Mark as an I2C memory card */
	SCardControl( "Device,SetLed,2" );	/* Green LED */

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Card Read/Write Routines						*
*																			*
****************************************************************************/

/* Write data to a card */

static int writeData( SCARD_INFO *scardInfo, const BYTE *data,
					  const int length )
	{
	BYTE *bufPtr = ( BYTE * ) data;
	char buffer[ BUFFER_SIZE ], eraseBuffer[ 8192 ];
	long hInstance = 0;
	int cardSize, dataLength = length, status;

	/* We only handle memory cards for now */
	if( !scardInfo->cardType )
		return( CRYPT_ERROR_WRITE );

	/* Make sure there's enough room on the card */
	status = getInfo( "Card,Info,MemSize", buffer );
	if( status )
		{
		getErrorInfo( scardInfo );
		return( CRYPT_ERROR_WRITE );
		}
	cardSize = atoi( buffer );
	if( !cardSize || cardSize < length )
		return( CRYPT_ERROR_OVERFLOW );

	/* If there's no length given, it's a special-case call to erase the
	   card */
	if( !length )
		{
		/* Create a zero-filled buffer of the appropriate length to use for
		   overwriting the data on the card */
		dataLength = min( cardSize, 16384 );
		memset( eraseBuffer, 0, dataLength );
		bufPtr = eraseBuffer;
		}

	/* Write the data to the card */
	sprintf( buffer, "Card,MemWrite,0,%d", dataLength );
	status = SCardCommand( &hInstance, buffer, 0, bufPtr, &dataLength, 
						   NULL, 0 );
	if( status )
		{
		getErrorInfo( scardInfo );
		return( CRYPT_ERROR_WRITE );
		}

	return( CRYPT_OK );
	}

/* Read data from a card */

static int readData( SCARD_INFO *scardInfo, BYTE *data )
	{
	char buffer[ BUFFER_SIZE ];
	long hInstance = 0, length = I2C_STRIDE;
	int status;

	/* Read enough data from the card that we can determine how much more we
	   have to read */
	status = SCardCommand( &hInstance, "Card,MemRead,0,8", 0, NULL, 0,
						   data, &length );
	if( status )
		{
		getErrorInfo( scardInfo );
		return( CRYPT_ERROR_READ );
		}
	length = getObjectLength( data, I2C_STRIDE );
	if( cryptStatusError( length ) )
		return( length );

	/* Read the remaining data from the card.  Since the Towitoko driver 
	   caches reads, we don't have to worry about optimising the read to
	   avoid unnecessarily re-reading the first I2C_STRIDE bytes */
	sprintf( buffer, "Card,MemRead,0,%d", length );
	status = SCardCommand( &hInstance, buffer, 0, NULL, 0, data, &length );
	if( status )
		{
		getErrorInfo( scardInfo );
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

int setAccessMethodTowitoko( SCARD_INFO *scardInfo )
	{
#ifdef __WINDOWS__
	/* Load the Towitoko driver DLL if it isn't already loaded */
	if( hScard == NULL_HINSTANCE )
		{
		scardInitTowitoko();
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
