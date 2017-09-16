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

/****************************************************************************
*																			*
*							General Session API Functions					*
*																			*
****************************************************************************/

/* Handle a message sent to a session object */

static int sessionMessageFunction( const CRYPT_SESSION cryptSession,
								   const RESOURCE_MESSAGE_TYPE message,
								   void *messageDataPtr,
								   const int messageValue,
								   const int errorCode )
	{
	SESSION_INFO *sessionInfoPtr;
	int status = errorCode;

	UNUSED( messageDataPtr );
	if( messageValue );		/* Get rid of compiler warning */
	getCheckInternalResource( cryptSession, sessionInfoPtr, RESOURCE_TYPE_SESSION );

	/* Process destroy object messages */
	if( message == RESOURCE_MESSAGE_DESTROY )
		{
		/* Clear and free secure state information if necessary */
		if( sessionInfoPtr->secureState != NULL )
			krnlMemfree( sessionInfoPtr->secureState );

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

		/* We've finished deleting the objects data, mark it as partially
		   destroyed, which ensures that any further attempts to access it
		   fail.  This avoids a race condition where other threads may try
		   to use the partially-destroyed object after we unlock it but
		   before we finish destroying it, note that we set the urgent flag
		   to ensure that the status change is processed immediately rather
		   than being queued until after the current (destroy) message has
		   been processed */
		status = CRYPT_SIGNALLED;
		krnlSendMessage( cryptSession,
						 RESOURCE_MESSAGE_SETPROPERTY | RESOURCE_MESSAGE_URGENT,
						 &status, RESOURCE_MESSAGE_PROPERTY_STATUS, 0 );

		/* Delete the objects locking variables and the object itself */
		unlockResource( sessionInfoPtr );
		deleteResourceLock( sessionInfoPtr );
		zeroise( sessionInfoPtr, sizeof( SESSION_INFO ) );
		free( sessionInfoPtr );

		return( CRYPT_OK );
		}

	/* Process the increment/decrement object reference count message */
	if( message == RESOURCE_MESSAGE_INCREFCOUNT )
		{
		/* Increment the objects reference count */
		sessionInfoPtr->refCount++;

		status = CRYPT_OK;
		}
	if( message == RESOURCE_MESSAGE_DECREFCOUNT )
		{
		/* If we're already at a single reference, destroy the object */
		if( !sessionInfoPtr->refCount )
			krnlSendNotifier( cryptSession, RESOURCE_IMESSAGE_DESTROY );
		else
			/* Decrement the objects reference count */
			sessionInfoPtr->refCount--;

		status = CRYPT_OK;
		}

	unlockResourceExit( sessionInfoPtr, status );
	}

/* Create/destroy a session object */

static int createSession( CRYPT_SESSION *session,
						  const CRYPT_FORMAT_TYPE sessionType )
	{
	SESSION_INFO *sessionInfoPtr;
	void *secureState;
	int status;

	/* Perform basic error checking */
	if( checkBadPtrWrite( session, sizeof( CRYPT_SESSION ) ) )
		return( CRYPT_BADPARM1 );
	*session = CRYPT_ERROR;
	if( sessionType != CRYPT_FORMAT_SSH )
		return( CRYPT_BADPARM2 );

	/* Allocate the secure session state memory */
	status = krnlMemalloc( &secureState, STATE_SIZE_SSH );
	if( cryptStatusError( status ) )
		return( status );

	/* Create the session object */
	krnlCreateObject( status, sessionInfoPtr, RESOURCE_TYPE_SESSION,
					  sizeof( SESSION_INFO ), 0, sessionMessageFunction );
	if( cryptStatusError( status ) )
		{
		krnlMemfree( &secureState );
		return( status );
		}
	*session = status;
	sessionInfoPtr->type = sessionType;
	sessionInfoPtr->secureState = secureState;

	/* Set up any internal objects to contain invalid handles */
	sessionInfoPtr->iKeyexCryptContext = \
		sessionInfoPtr->iKeyexAuthContext = CRYPT_ERROR;
	sessionInfoPtr->iCryptInContext = \
		sessionInfoPtr->iCryptOutContext = CRYPT_ERROR;
	sessionInfoPtr->iAuthInContext = \
		sessionInfoPtr->iAuthOutContext = CRYPT_ERROR;

	/* Set up the session management function pointers */
	if( sessionType == CRYPT_FORMAT_SSH )
		{
		int sshAddInfo( SESSION_INFO *sessionInfoPtr,
						const CRYPT_SESSINFO_TYPE sessionInfo,
						const void *value, const int valueLength );
		int sshGetData( SESSION_INFO *sessionInfoPtr,
						const CRYPT_SESSIONDATA_TYPE type, void *data,
						int *length );
		int sshAddData( SESSION_INFO *sessionInfoPtr, const void *data );

		sessionInfoPtr->addInfo = sshAddInfo;
		sessionInfoPtr->getData = sshGetData;
		sessionInfoPtr->addData = sshAddData;
		}

	unlockResourceExit( sessionInfoPtr, CRYPT_OK );
	}

CRET cryptCreateSession( CRYPT_SESSION CPTR session,
						 const CRYPT_FORMAT_TYPE sessionType )
	{
	return( createSession( session, sessionType ) );
	}

CRET cryptDestroySession( const CRYPT_SESSION session )
	{
	return( cryptDestroyObject( session ) );
	}

/****************************************************************************
*																			*
*							Session Management Functions					*
*																			*
****************************************************************************/

/* Add control information to a session object */

CRET cryptAddSessionComponentNumeric( const CRYPT_SESSION session,
									  const CRYPT_SESSINFO_TYPE sessionInfoType,
									  const int sessionInfo )
	{
	SESSION_INFO *sessionInfoPtr;
	RESOURCE_MESSAGE_CHECK_TYPE checkType = RESOURCE_MESSAGE_CHECK_NONE;
	RESOURCE_TYPE objectType = RESOURCE_TYPE_CRYPT;
	int status = CRYPT_OK;

	/* Perform basic error checking */
	getCheckResource( session, sessionInfoPtr, RESOURCE_TYPE_SESSION,
					  CRYPT_BADPARM1 );

	/* In general we can't add new control information once we've set up a
	   session */
#if 0
	if( sessionInfoPtr->state != STATE_PRESESSION )
		unlockResourceExit( sessionInfoPtr, status );
#endif

	/* Since the information may not be used for quite some time after it's
	   added, we do some preliminary checking here to allow us to return an
	   error code immediately rather than from some deeply-buried function an
	   indeterminate time in the future */
	switch( sessionInfoType )
		{
		case CRYPT_SESSINFO_KEY_ENCRYPTION:
			checkType = RESOURCE_MESSAGE_CHECK_PKC_DECRYPT;
			if( sessionInfoPtr->iKeyexCryptContext != CRYPT_ERROR )
				status = CRYPT_INITED;
			else
				sessionInfoPtr->isHost = TRUE;
			break;

		case CRYPT_SESSINFO_KEY_AUTHENTICATION:
			checkType = RESOURCE_MESSAGE_CHECK_PKC_DECRYPT;
			if( sessionInfoPtr->iKeyexAuthContext != CRYPT_ERROR )
				status = CRYPT_INITED;
			else
				sessionInfoPtr->isHost = TRUE;
			break;

		default:
			status = CRYPT_BADPARM2;
		}
	if( cryptStatusError( status ) )
		unlockResourceExit( envelopeInfoPtr, status );
	if( checkType != RESOURCE_MESSAGE_CHECK_NONE )
		{
		int type;

		/* Check the object as appropriate */
		status = krnlSendMessage( sessionInfo, RESOURCE_MESSAGE_CHECK, NULL,
								  checkType, CRYPT_BADPARM3 );
		if( cryptStatusError( status ) )
			unlockResourceExit( sessionInfoPtr, status );

		/* Make sure the object is of the correct type */
		status = krnlSendMessage( sessionInfo, RESOURCE_MESSAGE_GETPROPERTY,
					&type, RESOURCE_MESSAGE_PROPERTY_TYPE, CRYPT_BADPARM3 );
		if( cryptStatusError( status ) )
			unlockResourceExit( sessionInfoPtr, status );
#if 0
		if( envInfoType == CRYPT_ENVINFO_SIGNATURE || \
			envInfoType == CRYPT_ENVINFO_PUBLICKEY || \
			envInfoType == CRYPT_ENVINFO_PRIVATEKEY )
			{
			/* Public-key objects can be encryption contexts or certificates */
			if( type != objectType && type != RESOURCE_TYPE_CERTIFICATE )
				status = CRYPT_BADPARM3;

			/* If we're using CMS enveloping, the object must have a cert of
			   the correct type associated with it */
			if( cryptStatusOK( status ) && \
				( envelopeInfoPtr->type == CRYPT_FORMAT_CMS || \
				  envelopeInfoPtr->type == CRYPT_FORMAT_SMIME ) )
				{
				int certType;

				status = cryptGetCertComponentNumeric( envInfo,
										CRYPT_CERTINFO_CERTTYPE, &certType );
				if( cryptStatusError( status ) ||
					( certType != CRYPT_CERTTYPE_CERTIFICATE && \
					  certType != CRYPT_CERTTYPE_CERTCHAIN ) )
					status = CRYPT_BADPARM3;
				}
			}
		else
#endif
			if( type != objectType )
				status = CRYPT_BADPARM3;
		}
	if( cryptStatusError( status ) )
		unlockResourceExit( sessionInfoPtr, status );

	/* Add it to the session object */
	status = sessionInfoPtr->addInfo( sessionInfoPtr, sessionInfoType,
									  &sessionInfo, 0 );
	unlockResourceExit( sessionInfoPtr, status );
	}

/* Add an information datagram to a session */

CRET cryptAddSessionData( void CPTR data, const CRYPT_SESSION session )
	{
	SESSION_INFO *sessionInfoPtr;
	int status = CRYPT_OK;

	/* Perform basic error checking */
	if( checkBadPtrRead( data, 16 ) )
		return( CRYPT_BADPARM1 );
	getCheckResource( session, sessionInfoPtr, RESOURCE_TYPE_SESSION,
					  CRYPT_BADPARM2 );

	/* Add the datagram to the session object */
	status = sessionInfoPtr->addData( sessionInfoPtr, data );
	unlockResourceExit( sessionInfoPtr, status );
	}

/* Get an information datagram from a session */

CRET cryptGetSessionData( void CPTR data, int CPTR dataLength,
						  const CRYPT_SESSIONDATA_TYPE sessionDataType,
						  const CRYPT_SESSION session )
	{
	SESSION_INFO *sessionInfoPtr;
	int status = CRYPT_OK;

	/* Perform basic error checking */
	if( checkBadPtrWrite( data, 16 ) )
		return( CRYPT_BADPARM1 );
	memset( data, 0, 16 );
	if( checkBadPtrWrite( dataLength, sizeof( int ) ) )
		return( CRYPT_BADPARM2 );
	*dataLength = 0;
	if( sessionDataType <= CRYPT_SESSIONDATA_NONE || \
		sessionDataType >= CRYPT_SESSIONDATA_LAST )
		return( CRYPT_BADPARM3 );
	getCheckResource( session, sessionInfoPtr, RESOURCE_TYPE_SESSION,
					  CRYPT_BADPARM4 );

	/* Get the datagram from the session object */
	status = sessionInfoPtr->getData( sessionInfoPtr, sessionDataType,
									  data, dataLength );
	if( status == CRYPT_BADPARM2 )
		status = CRYPT_BADPARM3;	/* Map to correct error value */
	unlockResourceExit( sessionInfoPtr, status );
	}
