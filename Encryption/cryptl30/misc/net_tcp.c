/****************************************************************************
*																			*
*						cryptlib TCP/IP Interface Routines					*
*						Copyright Peter Gutmann 1998-1999					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <time.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "net.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "net.h"
#else
  #include "crypt.h"
  #include "misc/net.h"
#endif /* Compiler-specific includes */

#ifdef NET_TCP

/****************************************************************************
*																			*
*						 		Init/Shutdown Routines						*
*																			*
****************************************************************************/

#ifdef DYNAMIC_LOAD

/* Global function pointers.  These are necessary because the functions need
   to be dynamically linked since not all systems contain the necessary
   libraries */

INSTANCE_HANDLE hTCP;

TCP4UCLEANUP Tcp4uCleanup;
TCP4UERRORSTRING Tcp4uErrorString;
TCP4UINIT Tcp4uInit;
TCPCLOSE pTcpClose;
TCPCONNECT pTcpConnect;
TCPRECV pTcpRecv;
TCPSEND pTcpSend;
HTTP4UGETFILEEX Http4uGetFileEx;
HTTP4USETTIMEOUT Http4uSetTimeout;

/* Dynamically load and unload any necessary TCP/IP libraries */

#ifdef __WINDOWS__
  #ifdef __WIN16__
	#define TCP_LIBNAME	"tcp4w.dll"
  #else
	#define TCP_LIBNAME	"tcp4w32.dll"
  #endif /* __WIN16__ */
#else
  #define TCP_LIBNAME	"libtcp4u.so"
#endif /* OS-specific TCP/IP library naming */

void netInitTCP( void )
	{
#ifdef __WIN16__
	UINT errorMode;
#endif /* __WIN16__ */

	/* Obtain a handle to the module containing the TCP/IP functions */
#ifdef __WIN16__
	errorMode = SetErrorMode( SEM_NOOPENFILEERRORBOX );
	hTCP = DynamicLoad( TCP_LIBNAME );
	SetErrorMode( errorMode );
	if( hTCP < HINSTANCE_ERROR )
		{
		hTCP = NULL_INSTANCE;
		return;
		}
#else
	if( ( hTCP = DynamicLoad( TCP_LIBNAME ) ) == NULL_INSTANCE )
		return;
#endif /* OS-specific dynamic load */

	/* Now get pointers to the functions */
	Tcp4uCleanup = ( TCP4UCLEANUP ) DynamicBind( hTCP, "Tcp4uCleanup" );
	Tcp4uErrorString = ( TCP4UERRORSTRING ) DynamicBind( hTCP, "Tcp4uErrorString" );
	Tcp4uInit = ( TCP4UINIT ) DynamicBind( hTCP, "Tcp4uInit" );
	TcpClose = ( TCPCLOSE ) DynamicBind( hTCP, "TcpClose" );
	TcpConnect = ( TCPCONNECT ) DynamicBind( hTCP, "TcpConnect" );
	TcpRecv = ( TCPRECV ) DynamicBind( hTCP, "TcpRecv" );
	TcpSend = ( TCPSEND ) DynamicBind( hTCP, "TcpSend" );

	Http4uGetFileEx = ( HTTP4UGETFILEEX ) DynamicBind( hTCP, "Http4uGetFileEx" );
	if( Http4uGetFileEx == NULL )
		/* The version without the 4u is possibly a typo which may be fixed 
		   in future versions so we check for both */
		Http4uGetFileEx = ( HTTP4UGETFILEEX ) DynamicBind( hTCP, "HttpGetFileEx" );
	Http4uSetTimeout = ( HTTP4USETTIMEOUT ) DynamicBind( hTCP, "Http4uSetTimeout" );

	/* Make sure we got valid pointers for every TCP/IP function */
	if( Tcp4uCleanup == NULL || Tcp4uErrorString == NULL || \
		Tcp4uInit == NULL || TcpClose == NULL || TcpConnect == NULL || \
		TcpRecv == NULL || TcpSend == NULL || Http4uGetFileEx == NULL || \
		Http4uSetTimeout == NULL )
		{
		/* Free the library reference and reset the handle */
		DynamicUnload( hTCP );
		hTCP = NULL_INSTANCE;
		return;
		}

	/* Initialise the Winsock code */
	if( Tcp4uInit() != TCP4U_SUCCESS )
		{
		/* Free the library reference and reset the handle */
		DynamicUnload( hTCP );
		hTCP = NULL_INSTANCE;
		}
	}

void netEndTCP( void )
	{
	if( hTCP != NULL_INSTANCE )
		{
		Tcp4uCleanup();
		DynamicUnload( hTCP );
		}
	hTCP = NULL_INSTANCE;
	}
#else

void netInitTCP( void )
	{
	Tcp4uInit();
	}

void netEndTCP( void )
	{
	Tcp4uCleanup();
	}
#endif /* DYNAMIC_LOAD */

/****************************************************************************
*																			*
*						 		Keyset Access Routines						*
*																			*
****************************************************************************/

/* Map a Tcp4u status to a cryptlib one */

int Tcp4MapError( int status )
	{
	switch( status )
		{
		case HTTP4U_SUCCESS:
			return( CRYPT_OK );

		case HTTP4U_CANCELLED:
		case HTTP4U_INSMEMORY:
			return( CRYPT_ERROR_MEMORY );

		case HTTP4U_BAD_URL:
		case HTTP4U_HOST_UNKNOWN:
		case HTTP4U_TCP_CONNECT:
		case HTTP4U_TCP_FAILED:
			return( CRYPT_ERROR_OPEN );

		case HTTP4U_BAD_REQUEST:
		case HTTP4U_FORBIDDEN:
		case HTTP4U_MOVED:
		case HTTP4U_NO_CONTENT:
		case HTTP4U_NOT_FOUND:
		case HTTP4U_PROTOCOL_ERROR:
			return( CRYPT_ERROR_READ );

		case HTTP4U_OVERFLOW:
			return( CRYPT_ERROR_OVERFLOW );
		}
	return( CRYPT_ERROR_FAILED );
	}
#endif /* NET_TCP */
