/****************************************************************************
*																			*
*						 cryptlib CMP Session Management					*
*						Copyright Peter Gutmann 1999-2000					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc.h"
  #include "session.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../misc/net.h"
  #include "../session/session.h"
#else
  #include "crypt.h"
  #include "misc/net.h"
  #include "session/session.h"
#endif /* Compiler-specific includes */

#ifdef NET_TCP

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Map a Tcp4u status to a cryptlib one */

static int mapError( SESSION_INFO *sessionInfoPtr, int status )
	{
	/* Remember the error code and message */
	sessionInfoPtr->errorCode = status;
	strncpy( sessionInfoPtr->errorMessage, Tcp4uErrorString( status ),
			 MAX_ERRMSG_SIZE - 1 );
	sessionInfoPtr->errorMessage[ MAX_ERRMSG_SIZE - 1 ] = '\0';

	return( Tcp4MapError( status ) );
	}

/****************************************************************************
*																			*
*								Init/Shutdown Functions						*
*																			*
****************************************************************************/

/* Prepare a CMP session */

static int initFunction( SESSION_INFO *sessionInfoPtr )
	{
	return( CRYPT_OK );
	}

/* Close a previously-opened CMP session */

static void shutdownFunction( SESSION_INFO *sessionInfoPtr )
	{
	SOCKET socket = sessionInfoPtr->socket;

	if( sessionInfoPtr->socket != CRYPT_ERROR )
		TcpClose( &socket );
	sessionInfoPtr->socket = CRYPT_ERROR;
	}

/* Connect to a CMP server */

static int connectFunction( SESSION_INFO *sessionInfoPtr )
	{
	SOCKET socket;
	unsigned short port = sessionInfoPtr->serverPort;
	int status;

	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE,
					 &sessionInfoPtr->timeout, 
					 CRYPT_OPTION_SESSION_TIMEOUT );

	/* Make sure we have all the required resources */
	if( sessionInfoPtr->sshUserNameLength == 0 )
		{
		setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_USERNAME, 
					  CRYPT_ERRTYPE_ATTR_ABSENT );
		return( CRYPT_ERROR_NOTINITED );
		}
	if( sessionInfoPtr->sshPasswordLength == 0 )
		{
		setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_PASSWORD, 
					  CRYPT_ERRTYPE_ATTR_ABSENT );
		return( CRYPT_ERROR_NOTINITED );
		}

	/* Connect to the remote server */
	status = TcpConnect( &socket, sessionInfoPtr->serverName, NULL, &port );
	if( status != TCP4U_SUCCESS )
		return( mapError( sessionInfoPtr, status ) );

#if 0
	/* Initialise the handshake info and begin the handshake */
	status = initHandshakeInfo( &handshakeInfo );
	if( cryptStatusOK( status ) )
		status = beginHandshake( sessionInfoPtr, &handshakeInfo, socket );
	if( cryptStatusError( status ) )
		{
		destroyHandshakeInfo( &handshakeInfo );
		TcpClose( &socket );
		return( status );
		}

	/* Exchange a key with the server */
	status = exchangeKeys( sessionInfoPtr, &handshakeInfo, socket );
	if( cryptStatusError( status ) )
		{
		destroySecurityContexts( sessionInfoPtr );
		destroyHandshakeInfo( &handshakeInfo );
		TcpClose( &socket );
		return( status );
		}

	/* Complete the handshake */
	status = completeHandshake( sessionInfoPtr, &handshakeInfo, socket );
	destroyHandshakeInfo( &handshakeInfo );
	if( cryptStatusError( status ) )
		{
		destroySecurityContexts( sessionInfoPtr );
		TcpClose( &socket );
		return( status );
		}
#endif

	/* We're done, remember the state info */
	sessionInfoPtr->socket = socket;

	return( status );
	}

/****************************************************************************
*																			*
*						Control Information Management Functions			*
*																			*
****************************************************************************/

int setAccessMethodCMP( SESSION_INFO *sessionInfoPtr )
	{
#ifdef DYNAMIC_LOAD
	/* Make sure the TCP/IP interface has been initialised */
	if( hTCP == NULL_INSTANCE )
		return( CRYPT_ERROR_OPEN );
#endif /* DYNAMIC_LOAD */

	/* Set the access method pointers */
	sessionInfoPtr->initFunction = initFunction;
	sessionInfoPtr->shutdownFunction = shutdownFunction;
	sessionInfoPtr->connectFunction = connectFunction;

	return( CRYPT_OK );
	}
#endif /* NET_TCP */
