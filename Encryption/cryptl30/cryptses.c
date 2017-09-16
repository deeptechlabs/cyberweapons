/****************************************************************************
*																			*
*						cryptlib Secure Session Routines					*
*						Copyright Peter Gutmann 1998-1999					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "session.h"
#else
  #include "session/session.h"
#endif /* Compiler-specific includes */

/* Some session types aren't supported on some platforms so we alias the 
   calls out */

#ifndef NET_TCP
  #define setAccessMethodSSL( x )		CRYPT_ARGERROR_NUM1
  #define setAccessMethodSSH( x )		CRYPT_ARGERROR_NUM1
  #define setAccessMethodCMP( x )		CRYPT_ARGERROR_NUM1
#endif /* NET_TCP */

/****************************************************************************
*																			*
*							General Session API Functions					*
*																			*
****************************************************************************/

/* Handle data sent to or read from a session object */

static int processGetAttribute( SESSION_INFO *sessionInfoPtr,
                                void *messageDataPtr, const int messageValue )
	{
	int *valuePtr = ( int * ) messageDataPtr;

    /* Handle the various information types */
    switch( messageValue )
		{
		case CRYPT_ATTRIBUTE_BUFFERSIZE:
			*valuePtr = sessionInfoPtr->sendBufSize;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_SERVER_PORT:
			*valuePtr = sessionInfoPtr->serverPort;
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( 0 );		/* Get rid of compiler warning */
	}

static int processSetAttribute( SESSION_INFO *sessionInfoPtr,
                                void *messageDataPtr, const int messageValue )
	{
	const int value = *( int * ) messageDataPtr;
	int status;

	switch( messageValue )
		{
		case CRYPT_ATTRIBUTE_BUFFERSIZE:
			assert( !sessionInfoPtr->sessionOpen );
			sessionInfoPtr->sendBufSize = value;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_ACTIVE:
			assert( !sessionInfoPtr->sessionOpen );
			if( value == FALSE )
				return( CRYPT_OK );	/* Noop */
			if( sessionInfoPtr->sendBuffer == NULL )
				{
				assert( sessionInfoPtr->sendBufSize >= MIN_BUFFER_SIZE && \
						sessionInfoPtr->receiveBufSize >= MIN_BUFFER_SIZE );

				/* Allocate the send and receive buffers */
				if( ( sessionInfoPtr->sendBuffer = \
						malloc( sessionInfoPtr->sendBufSize ) ) == NULL )
					return( CRYPT_ERROR_MEMORY );
				if( ( sessionInfoPtr->receiveBuffer = \
						malloc( sessionInfoPtr->receiveBufSize ) ) == NULL )
					{
					free( sessionInfoPtr->sendBuffer );
					sessionInfoPtr->sendBuffer = NULL;
					return( CRYPT_ERROR_MEMORY );
					}
				}
			status = sessionInfoPtr->connectFunction( sessionInfoPtr );
			if( cryptStatusOK( status ) )
				{
				/* Notify the kernel that the session key context is 
				   attached to the session object.  This is an internal 
				   object used only by the session object so we tell the 
				   kernel not to increment its reference count when it 
				   attaches it */
				krnlSendMessage( sessionInfoPtr->objectHandle, 
								 RESOURCE_IMESSAGE_SETDEPENDENT, 
								 &sessionInfoPtr->iCryptInContext, FALSE );

				/* Remember that the session has been successfully 
				   established */
				sessionInfoPtr->sessionOpen = TRUE;
				}
			return( status );
			
		case CRYPT_SESSINFO_SERVER_PORT:
			sessionInfoPtr->serverPort = value;
			return( CRYPT_OK );

		default:
			assert( NOTREACHED );
		}

	assert( NOTREACHED );
	return( 0 );		/* Get rid of compiler warning */
	}

static int processGetAttributeS( SESSION_INFO *sessionInfoPtr,
								 void *messageDataPtr, const int messageValue )
	{
	RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;

	/* Handle the various information types */
	switch( messageValue )
		{
		case CRYPT_SESSINFO_USERNAME:
			if( !sessionInfoPtr->sshUserNameLength )
				return( CRYPT_ERROR_NOTINITED );
			return( attributeCopy( msgData, sessionInfoPtr->sshUserName,
								   sessionInfoPtr->sshUserNameLength ) );
		
		case CRYPT_SESSINFO_SERVER:
			if( !strlen( sessionInfoPtr->serverName ) )
				return( CRYPT_ERROR_NOTINITED );
			return( attributeCopy( msgData, sessionInfoPtr->serverName,
								   strlen( sessionInfoPtr->serverName ) ) );
		}

	assert( NOTREACHED );
	return( 0 );		/* Get rid of compiler warning */
	}

static int processSetAttributeS( SESSION_INFO *sessionInfoPtr,
								 void *messageDataPtr, const int messageValue )
    {
    RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;

    /* Handle the various information types */
    switch( messageValue )
		{
		case CRYPT_SESSINFO_USERNAME:
			assert( msgData->length < CRYPT_MAX_TEXTSIZE );
			memcpy( sessionInfoPtr->sshUserName, msgData->data, 
					msgData->length );
			sessionInfoPtr->sshUserNameLength = msgData->length;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_PASSWORD:
			assert( msgData->length < CRYPT_MAX_TEXTSIZE );
			memcpy( sessionInfoPtr->sshPassword, msgData->data, 
					msgData->length );
			sessionInfoPtr->sshPasswordLength = msgData->length;
			return( CRYPT_OK );

		case CRYPT_SESSINFO_SERVER:
			assert( msgData->length < MAX_URL_SIZE );
			memcpy( sessionInfoPtr->serverName, msgData->data, 
					msgData->length );
			sessionInfoPtr->serverName[ msgData->length ] = 0;
			return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( 0 );		/* Get rid of compiler warning */
	}

/* Handle a message sent to a session object */

static int sessionMessageFunction( const CRYPT_SESSION cryptSession,
								   const RESOURCE_MESSAGE_TYPE message,
								   void *messageDataPtr,
								   const int messageValue )
	{
	SESSION_INFO *sessionInfoPtr;

	getCheckInternalResource( cryptSession, sessionInfoPtr, OBJECT_TYPE_SESSION );

	/* Process destroy object messages */
	if( message == RESOURCE_MESSAGE_DESTROY )
		{
		/* Shut down the session if required */
		if( sessionInfoPtr->sessionOpen && \
			sessionInfoPtr->shutdownFunction != NULL )
			sessionInfoPtr->shutdownFunction( sessionInfoPtr );

		/* Clear and free state information if necessary */
		if( sessionInfoPtr->sendBuffer != NULL )
			{
			zeroise( sessionInfoPtr->sendBuffer, 
					 sessionInfoPtr->sendBufSize );
			free( sessionInfoPtr->sendBuffer );
			}
		if( sessionInfoPtr->receiveBuffer != NULL )
			{
			zeroise( sessionInfoPtr->receiveBuffer, 
					 sessionInfoPtr->receiveBufSize );
			free( sessionInfoPtr->receiveBuffer );
			}

		/* Clean up any session-related crypto objects if necessary */
		if( sessionInfoPtr->iKeyexCryptContext != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iKeyexCryptContext,
							  RESOURCE_IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->iKeyexAuthContext != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iKeyexAuthContext,
							  RESOURCE_IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->iCryptInContext != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iCryptInContext,
							  RESOURCE_IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->iCryptOutContext != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iCryptOutContext,
							  RESOURCE_IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->iAuthInContext != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iAuthInContext,
							  RESOURCE_IMESSAGE_DECREFCOUNT );
		if( sessionInfoPtr->iAuthOutContext != CRYPT_ERROR )
			krnlSendNotifier( sessionInfoPtr->iAuthOutContext,
							  RESOURCE_IMESSAGE_DECREFCOUNT );

		/* Delete the objects locking variables and the object itself */
		unlockResource( sessionInfoPtr );
		deleteResourceLock( sessionInfoPtr );
		zeroise( sessionInfoPtr, sizeof( SESSION_INFO ) );
		free( sessionInfoPtr );

		return( CRYPT_OK );
		}

	/* Process attribute get/set/delete messages */
	if( isAttributeMessage( message ) )
		{
		int status = CRYPT_ERROR;

		assert( message == RESOURCE_MESSAGE_SETATTRIBUTE || \
				message == RESOURCE_MESSAGE_SETATTRIBUTE_S || \
				message == RESOURCE_MESSAGE_GETATTRIBUTE_S );

		if( message == RESOURCE_MESSAGE_SETATTRIBUTE )
			status = processSetAttribute( sessionInfoPtr, messageDataPtr,
										  messageValue );
		if( message == RESOURCE_MESSAGE_SETATTRIBUTE_S )
			status = processSetAttributeS( sessionInfoPtr, messageDataPtr,
										   messageValue );
		if( message == RESOURCE_MESSAGE_GETATTRIBUTE_S )
			status = processGetAttributeS( sessionInfoPtr, messageDataPtr,
										   messageValue );

		unlockResourceExit( sessionInfoPtr, status );
		}

	/* Process messages which lock/unlock an object for exclusive use */
	if( message == RESOURCE_MESSAGE_LOCK )
		/* Exit without unlocking the object.  Any other threads trying to
		   use the object after this point will be blocked */
		return( CRYPT_OK );
	if( message == RESOURCE_MESSAGE_UNLOCK )
		{
		/* "Wenn drei Leute in ein Zimmer reingehen und fuenf kommen raus,
		   dann muessen erst mal zwei wieder reingehen bis das Zimmer leer
		   ist" */
		unlockResource( sessionInfoPtr );	/* Undo RESOURCE_MESSAGE_LOCK lock */
		unlockResourceExit( sessionInfoPtr, CRYPT_OK );
		}

	/* Process object-specific messages */
	if( message == RESOURCE_MESSAGE_ENV_PUSHDATA )
		{
		RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
		int status;

		assert( sessionInfoPtr->sessionOpen );
		assert( sessionInfoPtr->socket != CRYPT_ERROR );
		assert( sessionInfoPtr->sendBuffer != NULL );

		status = sessionInfoPtr->putDataFunction( sessionInfoPtr,
											msgData->data, msgData->length );
		if( cryptStatusError( status ) )
			unlockResourceExit( sessionInfoPtr, status );
		msgData->length = status;
		unlockResourceExit( sessionInfoPtr, CRYPT_OK );
		}
	if( message == RESOURCE_MESSAGE_ENV_POPDATA )
		{
		RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
		int status;

		assert( sessionInfoPtr->sessionOpen );
		assert( sessionInfoPtr->socket != CRYPT_ERROR );
		assert( sessionInfoPtr->receiveBuffer != NULL );

		status = sessionInfoPtr->getDataFunction( sessionInfoPtr,
											msgData->data, msgData->length );
		if( cryptStatusError( status ) )
			unlockResourceExit( sessionInfoPtr, status );
		msgData->length = status;
		unlockResourceExit( sessionInfoPtr, CRYPT_OK );
		}

	assert( NOTREACHED );
	return( 0 );		/* Get rid of compiler warning */
	}

/* Open a session.  This is a low-level function encapsulated by createSession()
   and used to manage error exits */

static int openSession( CRYPT_SESSION *iCryptSession,
						const CRYPT_FORMAT_TYPE formatType,
						SESSION_INFO **sessionInfoPtrPtr )
	{
	SESSION_INFO *sessionInfoPtr;
	int status;

	/* Clear the return values */
	*iCryptSession = CRYPT_ERROR;
	*sessionInfoPtrPtr = NULL;

	/* Wait for any async driver binding to complete */
	waitSemaphore( SEMAPHORE_DRIVERBIND );

	/* Create the session object */
	status = krnlCreateObject( ( void ** ) &sessionInfoPtr, 
							   OBJECT_TYPE_SESSION, SUBTYPE_ANY, 
							   sizeof( SESSION_INFO ), 0, 0, 
							   sessionMessageFunction );
	if( cryptStatusError( status ) )
		return( status );
	initResourceLock( sessionInfoPtr );
	lockResource( sessionInfoPtr );
	*sessionInfoPtrPtr = sessionInfoPtr;
	*iCryptSession = sessionInfoPtr->objectHandle = status;
	sessionInfoPtr->type = formatType;

	/* Set up any internal objects to contain invalid handles */
	sessionInfoPtr->iKeyexCryptContext = \
		sessionInfoPtr->iKeyexAuthContext = CRYPT_ERROR;
	sessionInfoPtr->iCryptInContext = \
		sessionInfoPtr->iCryptOutContext = CRYPT_ERROR;
	sessionInfoPtr->iAuthInContext = \
		sessionInfoPtr->iAuthOutContext = CRYPT_ERROR;

	/* Set up the access information for the session and initialise it */
	switch( formatType )
		{
		case CRYPT_FORMAT_SSH:
			status = setAccessMethodSSH( sessionInfoPtr );
			break;

		case CRYPT_FORMAT_SSL:
			status = setAccessMethodSSL( sessionInfoPtr );
			break;

		case CRYPT_FORMAT_CMP:
			status = setAccessMethodCMP( sessionInfoPtr );
			break;

		default:
			assert( NOTREACHED );
		}
	assert( sessionInfoPtr->initFunction != NULL );
	assert( sessionInfoPtr->connectFunction != NULL );
	assert( sessionInfoPtr->getDataFunction != NULL );
	assert( sessionInfoPtr->putDataFunction != NULL );
	if( cryptStatusOK( status ) )
		status = sessionInfoPtr->initFunction( sessionInfoPtr );
	return( status );
	}

int createSession( CREATEOBJECT_INFO *createInfo, const void *auxDataPtr, 
				   const int auxValue )
	{
	CRYPT_SESSION iCryptSession;
	SESSION_INFO *sessionInfoPtr;
	int initStatus, status;

	assert( auxDataPtr == NULL );
	assert( auxValue == 0 );

	/* Perform basic error checking */
	if( createInfo->arg1 < CRYPT_FORMAT_FIRST_SESSION || \
		createInfo->arg1 > CRYPT_FORMAT_LAST_SESSION )
		return( CRYPT_ARGERROR_NUM1 );

	/* Pass the call on to the lower-level open function */
	initStatus = openSession( &iCryptSession, createInfo->arg1, 
							  &sessionInfoPtr );
	if( sessionInfoPtr == NULL )
		return( initStatus );	/* Create object failed, return immediately */
	if( cryptStatusError( initStatus ) )
		/* The session open failed, make sure the object gets destroyed when
		   we notify the kernel that the setup process is complete */
		krnlSendNotifier( iCryptSession, RESOURCE_IMESSAGE_DESTROY );

	/* We've finished setting up the object-type-specific info, tell the
	   kernel the object is ready for use */
	unlockResource( sessionInfoPtr );
	status = krnlSendMessage( iCryptSession, RESOURCE_IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusError( initStatus ) || cryptStatusError( status ) )
		return( cryptStatusError( initStatus ) ? initStatus : status );
	createInfo->cryptHandle = iCryptSession;
	return( CRYPT_OK );
	}
