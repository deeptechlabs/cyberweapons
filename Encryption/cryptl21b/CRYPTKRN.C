/****************************************************************************
*																			*
*							cryptlib Security Kernel						*
*						Copyright Peter Gutmann 1992-1998					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypt.h"

/* The initialisation state and a lock to protect it.  The object
   management functions check the state before they do anything and return
   CRYPT_INITED if cryptlib hasn't been initialised.  Since everything in
   cryptlib depends on the creation of objects, any attempts to use cryptlib
   without it being properly initialised are caught.

   Reading the isInitialised flag presents something of a chicken-and-egg
   problem since the read should be protected by the intialisation mutex, but
   we can't try and grab it unless the mutex has been initialised.  If we
   just read the flag directly and rely on the object map mutex to protect
   access we run into a potential race condition on shutdown:

	thread1							thread2

	inited = T						read inited = T
	inited = F, destroy objects
									lock objects, die

   The usual way to avoid this is to perform an interlocked mutex lock in
   the same way as the krnlGetXXXObject() macros, but this isn't possible
   here since the initialisation mutex may not be initialised.  Under Win32
   it's set by DllMain() */

DECLARE_LOCKING_VARS( initialisation )
BOOLEAN isInitialised = FALSE;

/****************************************************************************
*																			*
*							Object Management Functions						*
*																			*
****************************************************************************/

/* A structure to store the details of a message sent to an object */

typedef struct {
	int resourceHandle;				/* Handle to send message to */
	RESOURCE_MESSAGE_TYPE message;	/* Message to send */
	void *messageDataPtr;
	int messageValue;				/* Message parameters */
	int messageErrorCode;			/* Default message error code */
	} RESOURCE_MESSAGE;

/* The size of the message queue.  This defines the maximum nesting depth of
   messages sent by an object.  Because of the way krnlSendMessage() handles
   message processing, it's extremely difficult to ever have more than two or
   three messages in the queue unless an object starts recursively sending
   itself messages */

#define MESSAGE_QUEUE_SIZE	10

/* The table to map external object handles to object data */

RESOURCE_INFO *resourceTable;
int resourceTableSize = 1024;
DECLARE_LOCKING_VARS( resourceMap )

/* We need to be very careful with how we create new objects because if we
   just allocate handles sequentially and reuse handles as soon as possible,
   an existing object could be signalled and a new one created in its place
   without the caller or owning object realizing that they're now working
   with a different object.  Unix systems handle this by always incrementing
   pids and assuming there won't be any problems when they wrap, we do the
   same thing but in addition allocate handles in a non-sequential manner
   using an LFSR to step through the object table.  There's no strong reason
   for this, but it only costs a few extra clocks so we may as well do it */

static int lfsrMask = 0x400, lfsrPoly = 0x409;
static int lfsrPolyTable[] = { 0x805, 0x1053, 0x201B, 0x402B, 0x8003 };

static int lfsr( int value )
	{
	/* Get the next value: Multiply by x and reduce by the polynomial */
	value <<= 1;
	if( value & lfsrMask )
		value ^= lfsrPoly;
	return( value );
	}

/* Create and destroy the object table */

static int initResources( void )
	{
	/* Allocate and clear the object table */
	if( ( resourceTable = calloc( resourceTableSize,
								  sizeof( RESOURCE_INFO ) ) ) == NULL )
		return( CRYPT_NOMEM );

	/* Initialize any data structures required to make the object table
	   thread-safe */
	initGlobalResourceLock( resourceMap );

	return( CRYPT_OK );
	}

static int destroyResources( void )
	{
	int resourceHandle, status = CRYPT_OK;

	/* Lock the object table to ensure other threads don't try to access
	   it */
	lockGlobalResource( resourceMap );

	/* Delete every entry in the table */
	for( resourceHandle = 0; resourceHandle < resourceTableSize;
		 resourceHandle++ )
		if( resourceTable[ resourceHandle ].resource != NULL )
			{
			krnlSendMessage( resourceHandle, RESOURCE_IMESSAGE_DESTROY, NULL, 0, 0 );
			status = CRYPT_ORPHAN;
			}

	/* Delete the table itself */
	zeroise( resourceTable, resourceTableSize * sizeof( RESOURCE_INFO ) );
	free( resourceTable );

	/* Destroy any data structures required to make the object table
	   thread-safe */
	unlockGlobalResource( resourceMap );
	deleteGlobalResourceLock( resourceMap );

	return( status );
	}

/* Add an entry to the object table.  This is an internal function called
   by krnlCreateObject() and should never be called directly from user code
   since it requires the object table to be locked */

static int findFreeResource( int value )
	{
	int oldValue = value;

	/* Make sure the initial object handle state is valid */
	if( !value )
		value = ( ( int ) time( NULL ) ) & ( lfsrMask - 1 );

	/* Step through the entire table looking for a free entry */
	do
		{
		value = lfsr( value );
		if( resourceTable[ value ].resource == NULL )
			break;
		}
	while( value != oldValue );

	return( value );
	}

int addResource( const RESOURCE_TYPE type, const int resourceSize,
				 const int flags,
				 int ( *messageFunction )( const int resource,
										   const RESOURCE_MESSAGE_TYPE message,
										   void *messageDataPtr,
										   const int messageValue,
										   const int errorCode ) )
	{
	void *resource;
	static int resourceHandle = 0, lfsrPolyTableIndex = 0;
	int oldResourceHandle = resourceHandle, status = CRYPT_OK;

	/* Search the table for a free entry */
	resourceHandle = findFreeResource( resourceHandle );

	/* If the table is full, expand it */
	if( resourceHandle == oldResourceHandle )
		{
		int oldSize = resourceTableSize;

		/* Expand the table */
		resourceTableSize += 1024;
		if( ( resourceTable = realloc( resourceTable,
					resourceTableSize * sizeof( RESOURCE_INFO ) ) ) == NULL )
			status = CRYPT_NOMEM;
		else
			memset( resourceTable + ( oldSize * sizeof( RESOURCE_INFO ) ),
					0, 1024 * sizeof( RESOURCE_INFO ) );

		/* Add the new object at the end of the existing table */
		lfsrMask <<= 1;
		lfsrPoly = lfsrPolyTable[ lfsrPolyTableIndex++ ];
		resourceHandle = findFreeResource( resourceHandle );
		}

	/* Allocate the new object and add it to the table */
	if( cryptStatusOK( status ) )
		{
		/* Allocate memory for the object */
		if( flags & RESOURCE_FLAG_SECUREMALLOC )
			status = krnlMemalloc( &resource, resourceSize );
		else
			if( ( resource = malloc( resourceSize ) ) == NULL )
				status = CRYPT_NOMEM;

		/* Set up the object table entry */
		if( cryptStatusOK( status ) )
			{
			memset( resource, 0, resourceSize );
			resourceTable[ resourceHandle ].resource = resource;
			resourceTable[ resourceHandle ].type = type;
			if( flags & RESOURCE_FLAG_INTERNAL )
				resourceTable[ resourceHandle ].isInternal = TRUE;
			resourceTable[ resourceHandle ].messageFunction = messageFunction;
			setResourceOwnership( &resourceTable[ resourceHandle ], CRYPT_UNUSED );
			}
		}

	return( cryptStatusOK( status ) ? resourceHandle : status );
	}

/* Get/set object properties.  We differentiate between a small number of
   user-accessible properties such as the objects owner, and properties which
   are only accessible by cryptlib.  The user-accessible properties can be
   locked, which makes them immutable (at least to being explicitly set, they
   can still be implicitly altered, for example setting a new object owner
   decrements the forwardable counter) and also unreadable by the user */

static int getProperty( const int resourceHandle, void *messageDataPtr,
						const int messageValue )
	{
	const RESOURCE_INFO *resourceInfoPtr = &resourceTable[ resourceHandle ];

	switch( messageValue )
		{
		/* User-accessible properties */
		case RESOURCE_MESSAGE_PROPERTY_FORWARDABLE:
			if( resourceInfoPtr->isLocked )
				return( CRYPT_NOPERM );
			*( ( int * ) messageDataPtr ) = resourceInfoPtr->forwardCount;
			break;

		case RESOURCE_MESSAGE_PROPERTY_LOCKED:
			/* We allow this to be read since its value can be determined
			   anyway with a read */
			*( ( BOOLEAN * ) messageDataPtr ) = resourceInfoPtr->isLocked;
			break;

		case RESOURCE_MESSAGE_PROPERTY_OWNER:
			/* We allow this to be read since its value can be determined
			   anyway with a read */
			*( ( int * ) messageDataPtr ) = getResourceOwnership( resourceInfoPtr );
			break;

		/* Internal properties */
		case RESOURCE_MESSAGE_PROPERTY_INTERNAL:
			*( ( BOOLEAN * ) messageDataPtr ) = resourceInfoPtr->isInternal;
			break;

		case RESOURCE_MESSAGE_PROPERTY_STATUS:
			*( ( int * ) messageDataPtr ) = resourceInfoPtr->status;
			break;

		case RESOURCE_MESSAGE_PROPERTY_TYPE:
			*( ( int * ) messageDataPtr ) = resourceInfoPtr->type;
			break;

		default:
			return( CRYPT_ERROR );	/* Internal error, should never happen */
		}

	return( CRYPT_OK );
	}

static int setProperty( const int resourceHandle, void *messageDataPtr,
						const int messageValue )
	{
	RESOURCE_INFO *resourceInfoPtr = &resourceTable[ resourceHandle ];

	switch( messageValue )
		{
		/* User-accessible properties */
		case RESOURCE_MESSAGE_PROPERTY_FORWARDABLE:
			if( resourceInfoPtr->isLocked )
				return( CRYPT_NOPERM );
			if( *( ( int * ) messageDataPtr ) > 1000 )
				return( CRYPT_BADDATA );
			resourceInfoPtr->forwardCount = *( ( int * ) messageDataPtr );
			break;

		case RESOURCE_MESSAGE_PROPERTY_LOCKED:
			if( resourceInfoPtr->isLocked )
				return( CRYPT_NOPERM );
			resourceInfoPtr->isLocked = *( ( BOOLEAN * ) messageDataPtr ) ? \
										TRUE : FALSE;
			break;

		case RESOURCE_MESSAGE_PROPERTY_OWNER:
			/* If the object is locked this property can still be changed
			   until the forwarding count drops to zero (otherwise locking
			   the object would prevent any forwarding).  If the object isn't
			   locked, we don't touch the forwarding count since the new
			   owner can just reset it, this matches the expected behaviour
			   where an object which hasn't had a count explicitly set is
			   infinitely forwardable */
			if( resourceInfoPtr->isLocked && \
				resourceInfoPtr->forwardCount <= 0 )
				return( CRYPT_NOPERM );
			setResourceOwnership( resourceInfoPtr, *( ( int * ) messageDataPtr ) );
			if( resourceInfoPtr->isLocked )
				resourceInfoPtr->forwardCount--;
			break;

		/* Internal properties */
		case RESOURCE_MESSAGE_PROPERTY_INTERNAL:
			resourceInfoPtr->isInternal = *( ( BOOLEAN * ) messageDataPtr );
			break;

		case RESOURCE_MESSAGE_PROPERTY_STATUS:
			/* If we're resetting the object status from CRYPT_BUSY to
			   CRYPT_OK, notify the object in case there's any extra
			   processing to be done */
			if( resourceInfoPtr->status == CRYPT_BUSY && \
				*( ( int * ) messageDataPtr ) == CRYPT_OK )
				{
				/* If the notification returns an error, the object is still
				   performing some sort of processing (eg cleanup/shutdown),
				   don't reset the status (it'll be done later when the
				   object is ready) */
				if( resourceInfoPtr->messageFunction( resourceHandle,
						RESOURCE_MESSAGE_CHANGENOTIFY, messageDataPtr,
						RESOURCE_MESSAGE_PROPERTY_STATUS, CRYPT_ERROR ) == CRYPT_OK )
					resourceInfoPtr->status = *( ( int * ) messageDataPtr );
				}
			else
				resourceInfoPtr->status = *( ( int * ) messageDataPtr );
			break;

		default:
			return( CRYPT_ERROR );	/* Internal error, should never happen */
		}

	return( CRYPT_OK );
	}

/* Sometimes we need to notify objects of an external event.  The following
   functions allow us to send the message to an invidual object, and every
   object of a given type - they work a bit like the Windows SendMessage()
   functions.  For the broadcast, we adopt a somewhat brute-force approach
   and just step through the object table since the broadcast function is
   virtually never called, which doesn't make it worthwhile to maintain a
   queue of objects to broadcast the message to.

   The basic krnlSendMessage() function maintains a message queue to ensure
   there are no problems if a message sent to an object results in it sending
   another message to itself.  If a message for a given object is already
   present in the message queue, the new message is appended after the
   existing one and the function returns immediately.  This ensures that the
   message isn't processed until the earlier message(s) for that object have
   been processed.  If the message is for a different object, it is prepended
   to the queue and processed immediately.  This ensures that messages sent
   by objects to subordinate objects are processed before the messages for
   the objects themselves.  Overall, an object won't be sent a new message
   until the current one has been processed.

   We distinguish between two message types, one-shot messages (which inform
   an object of a fixed event has occurred, for example a destroy object
   message), and repeatable messages (which modify an object in a certain way
   for example an increment reference count message).  The main distinction
   is that duplicate one-shot messages can be deleted while duplicate
   repeatable messages can't.

   The mesage processing algorithm is as follows:

	find pos in queue starting from the back;
	if( message is one-shot and already in queue )
		return;
	insert message at ( pos ) ? pos + 1 : 0;
	if( pos )
		return;
	do
		queue[ 0 ]->function();
		delete queue[ 0 ];
	while( qPos && queue[ 0 ].type == type );

   For a sequence of messages A1 -> B1, B1 -> A2, B2, C, the processing
   sequence is:

	A1
	A1->fn();
		B1,A1
		B1->fn();
			B1,A1,A2, return
			B1,B2,A1,A2, return
			C,B1,B2,A1,A2
			C->fn();
			dequeue C;
			B1,B2,A1,A1
			dequeue B1;
		B2,A1,A2
		B2->fn();
		dequeue B2;
		dequeue A1;
	A2->fn();

   This processing order ensures that messages to the same object are
   processed in the order sent, and messages to different objects are
   guaranteed to complete before the message for the sending object.  In
   effect the message handling is like SendMessage() for other objects, and
   PostMessage() for the self object, so the current object can queue a
   series of events for processing and guarantee execution in the order the
   events are posted.

   In some cases there can be a need to process a message immediately.  In
   this case the caller can set the RESOURCE_MESSAGE_URGENT flag which
   ensures that a change to an objects property takes effect immediately.
   This can be used for example to move an object into the signalled state
   once its internal data is destroyed but before the object itself is
   destroyed, which ensures that any further attempts to access it fail
   rather than trying to use the partially-destroyed object */

int krnlSendMessage( const int resourceHandle,
					 const RESOURCE_MESSAGE_TYPE message,
					 void *messageDataPtr, const int messageValue,
					 const int errorCode )
	{
	static RESOURCE_MESSAGE resourceMessage[ MESSAGE_QUEUE_SIZE ];
	static int queueEnd = 0;	/* Points past last queue element */
	const BOOLEAN isUrgent = ( message & RESOURCE_MESSAGE_URGENT ) ? TRUE : FALSE;
	const int localErrorCode = ( errorCode ) ? errorCode : CRYPT_ERROR;
	int localMessage = message, pos, i, status = CRYPT_OK;

	/* Lock the object table to ensure other threads don't try to access
	   it.  Note that if we're called from destroyResources() or
	   krnlSendBroadcast() the object table is already locked so the locking
	   facility must be reentrant */
	lockGlobalResource( resourceMap );

	/* Make sure the message is being sent to a valid resource and that the
	   resource is externally visible and accessible to the caller if
	   required by the message */
	if( resourceHandle < 0 || resourceHandle >= resourceTableSize || \
		resourceTable[ resourceHandle ].resource == NULL || \
		( localMessage < RESOURCE_MESSAGE_LAST && \
		  ( resourceTable[ resourceHandle ].isInternal || \
			!checkResourceOwnership( resourceTable[ resourceHandle ] ) ) ) )
		{
		unlockGlobalResource( resourceMap );
		return( localErrorCode );
		}

	/* Map the message into the standard message range if necessary and check
	   that it's valid */
	localMessage &= ~RESOURCE_MESSAGE_URGENT;
	if( localMessage >= RESOURCE_MESSAGE_LAST )
		localMessage -= RESOURCE_IMESSAGE_DESTROY - RESOURCE_MESSAGE_DESTROY;
	if( localMessage <= RESOURCE_MESSAGE_NONE || \
		localMessage >= RESOURCE_MESSAGE_LAST )
		{
		unlockGlobalResource( resourceMap );
		return( CRYPT_ERROR );	/* Internal error, should never happen */
		}
	if( ( localMessage == RESOURCE_MESSAGE_GETPROPERTY || \
		  localMessage == RESOURCE_MESSAGE_SETPROPERTY ) && \
		( messageValue <= RESOURCE_MESSAGE_PROPERTY_NONE ||
		  messageValue >= RESOURCE_MESSAGE_PROPERTY_LAST ) )
		{
		unlockGlobalResource( resourceMap );
		return( CRYPT_ERROR );	/* Internal error, should never happen */
		}

	/* Make sure a non-control message won't be sent to an object in a non-
	   normal state */
	if( localMessage > RESOURCE_MESSAGE_LAST_CONTROL && \
		resourceTable[ resourceHandle ].status != CRYPT_OK )
		{
		status = resourceTable[ resourceHandle ].status;

		unlockGlobalResource( resourceMap );
		return( status );
		}

	/* If the message has the urgent flag set, process it immediately */
	if( isUrgent )
		{
		if( localMessage == RESOURCE_MESSAGE_GETPROPERTY )
			status = getProperty( resourceHandle, messageDataPtr, messageValue );
		else
			status = setProperty( resourceHandle, messageDataPtr, messageValue );
		unlockGlobalResource( resourceMap );
		return( status );
		}

	/* Make sure we don't overflow the queue */
	if( queueEnd >= MESSAGE_QUEUE_SIZE )
		{
		/* This cryptlib object is not responding to messages... now all we
		   need is GPF's */
		unlockGlobalResource( resourceMap );
		return( CRYPT_ERROR );	/* Internal error, should never happen */
		}

	/* Check whether a message to this object is already present in the
	   queue */
	for( pos = queueEnd - 1; pos >= 0; pos-- )
		if( resourceMessage[ pos ].resourceHandle == resourceHandle )
			break;

	/* If the message is a one-shot message and is already present, don't
	   enqueue it a second time */
	if( localMessage == RESOURCE_MESSAGE_DESTROY )
		for( i = pos; i >= 0 && \
				resourceMessage[ i ].resourceHandle == resourceHandle; i-- )
			if( resourceMessage[ i ].message == localMessage )
			{
			/* No need to enqueue the same message a second time */
			unlockGlobalResource( resourceMap );
			return( CRYPT_OK );
			}

	/* Enqueue the message */
	pos++;		/* Insert after current position */
	for( i = queueEnd - 1; i >= pos; i-- )
		resourceMessage[ i + 1 ] = resourceMessage[ i ];
	resourceMessage[ pos ].resourceHandle = resourceHandle;
	resourceMessage[ pos ].message = localMessage;
	resourceMessage[ pos ].messageDataPtr = messageDataPtr;
	resourceMessage[ pos ].messageValue = messageValue;
	resourceMessage[ pos ].messageErrorCode = localErrorCode;
	queueEnd++;
	if( pos++ )
		{
		/* Already present, defer processing */
		unlockGlobalResource( resourceMap );
		return( CRYPT_OK );
		}

	/* While there are more messages for this object present, dequeue them
	   and dispatch them.  Since messages will only be enqueued if
	   krnlSendMessage() is called recursively, we only dequeue messages for
	   the current object in this loop.  Queued messages for other objects
	   will be handled at a different level of recursion */
	do
		{
		/* If we're handling a queue of messages, one of the messages may
		   result in the destruction of an object which is referenced in a
		   later message.  If the object doesn't exist any more, we don't try
		   to process the message for it but just silently dequeue the
		   message.  This effect is obtained through the messageFunction and
		   message type checks below */
		const RESOURCE_INFO *resourceInfoPtr = &resourceTable[ resourceHandle ];

		/* Send the message.  If the message is an object property
		   manipulation message, we call internal handlers (the objects
		   handler never sees the message).  If the message is a destroy
		   object message, we have to include some special-case code to
		   remove it from the object table since the objects message handler
		   can't do this itself */
		if( resourceMessage->message == RESOURCE_MESSAGE_GETPROPERTY )
			status = getProperty( resourceHandle, resourceMessage->messageDataPtr,
								  resourceMessage->messageValue );
		else
			if( resourceMessage->message == RESOURCE_MESSAGE_SETPROPERTY )
				status = setProperty( resourceHandle, resourceMessage->messageDataPtr,
									  resourceMessage->messageValue );
			else
				{
				if( resourceInfoPtr->messageFunction != NULL )
					status = resourceInfoPtr->messageFunction( resourceHandle,
						resourceMessage->message, resourceMessage->messageDataPtr,
						resourceMessage->messageValue, resourceMessage->messageErrorCode );
				if( resourceMessage->message == RESOURCE_MESSAGE_DESTROY )
					zeroise( &resourceTable[ resourceHandle ], sizeof( RESOURCE_INFO ) );
				}

		/* Dequeue the message */
		for( i = 1; i < queueEnd; i++ )
			resourceMessage[ i - 1 ] = resourceMessage[ i ];
		zeroise( &resourceMessage[ queueEnd - 1 ], sizeof( RESOURCE_MESSAGE ) );
		queueEnd--;
		}
	while( queueEnd && resourceMessage->resourceHandle == resourceHandle );

	/* Unlock the object table to allow access by other threads */
	unlockGlobalResource( resourceMap );

	return( status );
	}

void krnlSendBroadcast( const RESOURCE_TYPE type,
						const RESOURCE_MESSAGE_TYPE message,
						void *messageDataPtr, const int messageValue,
						const int errorCode )
	{
	int resourceHandle;

	/* Lock the object table to ensure other threads don't try to access
	   it */
	lockGlobalResource( resourceMap );

	/* Send the notification to every object of the appropriate type in the
	   table */
	for( resourceHandle = 0; resourceHandle < resourceTableSize;
		 resourceHandle++ )
		if( resourceTable[ resourceHandle ].type == type )
			krnlSendMessage( resourceHandle, message, messageDataPtr,
							 messageValue, errorCode );

	/* Unlock the object table to allow access by other threads */
	unlockGlobalResource( resourceMap );
	}

/****************************************************************************
*																			*
*								Semaphore Functions							*
*																			*
****************************************************************************/

/* Under multithreaded OS's, we often need to wait for certain events before
   we can continue (for example when asynchronously accessing system
   resources anything which depends on the resource being available needs to
   wait for the access to complete).  The following functions abstract this
   handling, basically what they do is provide a lightweight semaphore
   mechanism which is used before checking a system synchronisation object.
   This works a bit like the Win32 Enter/LeaveCriticalSection() routines,
   which perform a quick check on a user-level lock and only call the
   kernel-level handler if necessary (in most cases this isn't necessary) */

typedef struct {
	SEMAPHORE_HANDLE object;/* Handle to system synchronisation object */
	BOOLEAN isSet;			/* Whether semaphore is set */
	BOOLEAN isBusy;			/* Whether semaphore is being waited on */
	} SEMAPHORE_INFO;

/* The table to map external semaphore handles to semaphore information */

SEMAPHORE_INFO semaphoreInfo[ SEMAPHORE_LAST ];
DECLARE_LOCKING_VARS( semaphore )

/* Create and destroy the semaphore table */

static void initSemaphores( void )
	{
	/* Clear the semaphore table */
	memset( semaphoreInfo, 0, sizeof( semaphoreInfo ) );

	/* Initialize any data structures required to make the semaphore table
	   thread-safe */
	initGlobalResourceLock( semaphore );
	}

static void endSemaphores( void )
	{
	/* Destroy any data structures required to make the semaphore table
	   thread-safe */
	deleteGlobalResourceLock( semaphore );
	}

/* Set and clear a semaphore */

void setSemaphore( const SEMAPHORE_TYPE semaphore, 
				   const SEMAPHORE_HANDLE object )
	{
	/* Lock the semaphore table to ensure other threads don't try to access
	   it */
	lockGlobalResource( semaphore );

	/* Initialise this semaphore */
	memset( &semaphoreInfo[ semaphore ], 0, sizeof( SEMAPHORE_INFO ) );
	semaphoreInfo[ semaphore ].object = object;
	semaphoreInfo[ semaphore ].isSet = TRUE;

	/* Unlock the semaphore table to allow access by other threads */
	unlockGlobalResource( semaphore );
	}

void clearSemaphore( const SEMAPHORE_TYPE semaphore )
	{
	/* Lock the semaphore table to ensure other threads don't try to access
	   it */
	lockGlobalResource( semaphore );

	/* Clear this semaphore */
	memset( &semaphoreInfo[ semaphore ], 0, sizeof( SEMAPHORE_INFO ) );

	/* Unlock the semaphore table to allow access by other threads */
	unlockGlobalResource( semaphore );
	}

/* Wait for a semaphore.  This occurs in two phases, first we extract the
   information we need from the semaphore table, then we unlock it and wait
   on the semaphore if necessary.  This is necessary because the wait can
   take an indeterminate amount of time and we don't want to tie up the other
   semaphores while this occurs.  Note that this type of waiting on local
   (rather than system) semaphores where possible greatly improves
   performance, in some cases the wait on a signalled system semaphore can
   take several seconds whereas waiting on the local semaphore only takes a
   few ms */

void waitSemaphore( const SEMAPHORE_TYPE semaphore )
	{
	SEMAPHORE_HANDLE object = 0;

	/* Lock the semaphore table, extract the information we need, and unlock
	   it again */
	lockGlobalResource( semaphore );
	if( semaphoreInfo[ semaphore ].isSet && \
		!semaphoreInfo[ semaphore ].isBusy )
		{
		/* The semaphore is set and not in use, extract the information we
		   require and mark is as being in use */
		object = semaphoreInfo[ semaphore ].object;
		semaphoreInfo[ semaphore ].isBusy = TRUE;
		}
	unlockGlobalResource( semaphore );

	/* If the semaphore wasn't set or is in use, exit now */
	if( object == 0 )
		return;

	/* Wait on the object */
#ifdef __WIN32__
	WaitForSingleObject( object, INFINITE );
#endif /* __WIN32__ */
	}

/****************************************************************************
*																			*
*							Service Routine Functions						*
*																			*
****************************************************************************/

/* Under multithreaded OS's, we can have background service routines running
   which perform various tasks.  In order to avoid having (potentially)
   dozens of different threads all whirring away, we provide the ability to
   register a service routine which gets called from a single worker thread.
   This is like a Win32 fiber, except that we provide extra functionality to
   handle resource and object locking when the service routine applies to a
   particular resource or object */

typedef struct {
	void ( *serviceDispatchFunction )( const int object,
									   void ( *serviceFunction )( void *info ) );
	void ( *serviceFunction )( void *info );
	int object;						/* Handle to object */
	int serviceID;					/* Unique ID for this service */
	} SERVICE_INFO;

/* The time interval between service dispatching, and the total number of
   services */

#define SERVICE_DISPATCH_INTERVAL	5
#define MAX_SERVICES				16

/* The table to map external semaphore handles to semaphore information */

SERVICE_INFO serviceInfo[ MAX_SERVICES ];
int serviceInfoLast, serviceUniqueID;
DECLARE_LOCKING_VARS( service )

/* Create and destroy the service table */

static void initServices( void )
	{
	/* Clear the service table */
	memset( serviceInfo, 0, sizeof( serviceInfo ) );
	serviceInfoLast = 0;

	/* Initialize any data structures required to make the service table
	   thread-safe */
	initGlobalResourceLock( service );
	}

static void endServices( void )
	{
	/* Destroy any data structures required to make the service table
	   thread-safe */
	deleteGlobalResourceLock( service );
	}

/* Register and deregister a service function */

int registerServiceRoutine( void ( *serviceDispatchFunction )
	( const int object, void ( *serviceFunction )( void *info ) ),
	void ( *serviceFunction )( void *info ), const int object )
	{
	int retVal;

	/* Lock the service table to ensure other threads don't try to access
	   it */
	lockGlobalResource( service );

	/* Add this service to the service table */
	if( serviceInfoLast >= MAX_SERVICES )
		return( CRYPT_ERROR );	/* Internal error, should never happen */
	serviceInfo[ serviceInfoLast ].serviceDispatchFunction = \
													serviceDispatchFunction;
	serviceInfo[ serviceInfoLast ].serviceFunction = serviceFunction;
	serviceInfo[ serviceInfoLast++ ].object = object;
	retVal = serviceUniqueID++;

	/* Unlock the service table to allow access by other threads */
	unlockGlobalResource( service );

	return( retVal );
	}

void deregisterServiceRoutine( const int serviceID )
	{
	int i;

	/* Lock the service table to ensure other threads don't try to access
	   it */
	lockGlobalResource( service );

	/* Find this service in the service table */
	for( i = 0; i < serviceInfoLast; i++ )
		if( serviceID == serviceInfo[ i ].serviceID )
			break;
	if( i == serviceInfoLast )
		return;		/* Internal error, should never happen */

	/* Move everything else down, removing this service from the table */
	if( i == serviceInfoLast - 1 )
		/* This is the last entry, clear it */
		memset( &serviceInfo[ i ], 0, sizeof( SERVICE_INFO ) );
	else
		memmove( &serviceInfo[ i ], &serviceInfo[ i + 1 ], \
				 ( serviceInfoLast - i ) - 1 );
	serviceInfoLast--;

	/* Unlock the service table to allow access by other threads */
	unlockGlobalResource( service );
	}

/* Service dispatch function */

void serviceDispatch( void )
	{
	BOOLEAN doContinue = TRUE;
	int index = 0;

	do
		{
		void ( *serviceDispatchFunction )( const int object,
										   void ( *serviceFunction )( void *info ) );
		void ( *serviceFunction )( void *info );
		int object;

		/* Obtain information on the next service routine to call.  We have
		   to release the lock on the service table before we can call the
		   service routine to avoid a potential deadlock situation when the
		   object is locked and tries to deregister the service, and the
		   service table is locked and the dispatch routine tries to access
		   the object */
		lockGlobalResource( service );
		if( index >= serviceInfoLast )
			/* We've run out of service routines, exit */
			doContinue = FALSE;
		else
			{
			/* Remember the details on the service routine to call */
			serviceDispatchFunction = serviceInfo[ index ].serviceDispatchFunction;
			serviceFunction = serviceInfo[ index ].serviceFunction;
			object = serviceInfo[ index ].object;
			}
		unlockGlobalResource( service );

		/* If there is a service routine to call, call it */
		if( doContinue )
			serviceDispatchFunction( object, serviceFunction );
		}
	while( doContinue );

	/* "You hurt Al?" / "I'm hurt real bad.  Sleepy time?" / "Sleepy time" */
#ifdef __WIN32__
	Sleep( SERVICE_DISPATCH_INTERVAL * 1000 );
#endif /* __WIN32__ */
	}

/* Example dispatch function:

int serviceDispatchFunction( const int object,
							 void ( *serviceFunction )( void *info ) )
	{
	KEYSET *keysetInfoPtr;

	getCheckResource( object, keysetInfoPtr, RESOURCE_TYPE_KEYSET,
					  CRYPT_ERROR );
	serviceFunction( keysetInfoPtr );
	unlockResourceExit( keysetInfoPtr, status );
	}
*/

/****************************************************************************
*																			*
*						Secure Memory Allocation Functions					*
*																			*
****************************************************************************/

/* To support page locking we need to store some additional information with
   the memory block.  We do this by reserving an extra memory block at the
   start of the allocated block and saving the information there.

   The information stored in the extra block is a flag indicating whether the
   block is pagelocked (so we can call the unlock function when we free it),
   the size of the block, and pointers to the next and previous pointers in
   the list of allocated blocks (this is used by the thread which walks the
   block list touching each one) */

#if INT_MAX <= 32767
  #define MEMLOCK_HEADERSIZE	16
#else
  #define MEMLOCK_HEADERSIZE	32
#endif /* 16-bit systems */

typedef struct {
	BOOLEAN isLocked;				/* Whether this block is locked */
	int size;						/* Size of the block (including the size
									   of the MEMLOCK_INFO) */
	void *next, *prev;				/* Next, previous memory block */
	} MEMLOCK_INFO;

/* The start and end of the list of allocated blocks, and a lock to protect
   it */

DECLARE_LOCKING_VARS( allocation )
static MEMLOCK_INFO *allocatedListHead, *allocatedListTail;

#ifdef __UNIX__

/* Since the function prototypes for the SYSV/POSIX mlock() call are stored
   all over the place depending on the Unix version, we usually have to
   prototype it ourselves here rather than trying to guess its location */

#if defined( __osf__ )
  #include <sys/mman.h>
#elif defined( sun )
  #include <sys/types.h>
#else
  int mlock( void *address, size_t length );
  int munlock( void *address, size_t length );
#endif /* Unix-variant-specific includes */

/* Under many Unix variants the SYSV/POSIX mlock() call can be used, but only
   by the superuser.  OSF/1 has mlock(), but this is defined to the
   nonexistant memlk() so we need to special-case it out.  Aches, A/UX, PHUX,
   Linux < 1.3.something, and Ultrix don't even pretend to have mlock().
   Many systems also have plock(), but this is pretty crude since it locks
   all data, and also has various other shortcomings.  Finally, PHUX has
   datalock(), which is just a plock() variant */

#if ( defined( __osf__ ) || defined( _AIX ) || defined( __hpux ) || \
	  defined( _M_XENIX ) || defined( __ultrix ) || defined( __aux ) || \
	  ( defined( __linux ) && OSVERSION < 2 ) )
  #define NO_MLOCK
#endif /* Unix OS-specific defines */

#endif /* __UNIX__ */

#if defined( __MSDOS__ ) && defined( __DJGPP__ )
  #include <dpmi.h>
  #include <go32.h>
#endif /* __MSDOS__ && __DJGPP__ */

/* A secure version of malloc() and free() which perform page locking if
   necessary and zeroise memory before it is freed */

int krnlMemalloc( void **pointer, int size )
	{
	MEMLOCK_INFO *memBlockPtr;
	BYTE *memPtr;

	/* Try and allocate the memory */		/* Shadu yu liktumkunushi */
	if( ( memPtr = malloc( size + MEMLOCK_HEADERSIZE ) ) == NULL )
		{									/* Shadu yu liklakunushi */
		*pointer = NULL;					/* Shadu yu lini yix kunushi */
		return( CRYPT_NOMEM );				/* Shadu yu li yixsi kunushi */
		}									/* Shadu yu lite kunushi */
	memset( memPtr, 0, size + MEMLOCK_HEADERSIZE );	/* Shadu yu lini kunushi */
	memBlockPtr = ( MEMLOCK_INFO * ) memPtr;/* Shadu yu linir kunushi */
	memBlockPtr->isLocked = FALSE;			/* Shadu yu likattin kunushi */
	memBlockPtr->size = size + MEMLOCK_HEADERSIZE;	/* Shadu yu dannu elikunu limqut */
	*pointer = memPtr + MEMLOCK_HEADERSIZE;	/* Ina zumri ya lu yu tapparrasama! */

	/* If the OS supports paging, try to lock the pages in memory */
#ifdef __WIN16__
	/* Under Windows 3.x there's no support for memory locking, so we simply
	   return an error code for a forced lock */
	if( getOptionNumeric( CRYPT_OPTION_MISC_FORCELOCK ) )
		{
		free( memPtr );
		*pointer = NULL;
		return( CRYPT_NOSECURE );
		}
#endif /* __WIN16__ */

#if defined( __WIN32__ ) && !defined( NT_DRIVER )
	/* Under Win95 the VirtualLock() function is implemented as
	   `return( TRUE )' ("Thank Microsoft kids" - "Thaaaanks Bill").  Under
	   NT the function does actually work, but with a number of caveats
	   which MS never tell you about.  The main one is that VirtualLock() 
	   only guarantees that the memory won't be paged while a thread in the
	   process is running.  When all threads are preempted the memory is still
	   a target for paging.  This means that on a loaded system a process
	   which was idle for some time could have the memory unlocked by the
	   system and swapped out to disk (actually with NT's somewhat strange
	   paging strategy and gradual creeping takeover of free memory for disk
	   buffers, it can get paged even on a completely unloaded system).  In
	   addition the locking is done on a per-page basis, so that unlocking a
	   region which shares a page with another locked region means that both
	   reqions are unlocked.  Since VirtualLock() doesn't do reference
	   counting (emulating the underlying MMU page locking even though it
	   doesn't seem to use the MMU to lock pages, or at least does something
	   odd to make sure they can still be paged when locked), the only way
	   around this is to walk the chain of allocated blocks and not unlock a
	   block if there's another block allocated on the same page.  Ick.

	   For the NT kernel driver, the memory is always allocated from the non-
	   paged pool so there's no need for these gyrations */
	if( VirtualLock( memPtr, memBlockPtr->size ) )
		memBlockPtr->isLocked = TRUE;
	else
		if( getOptionNumeric( CRYPT_OPTION_MISC_FORCELOCK ) )
			{
			free( memPtr );
			*pointer = NULL;
			return( CRYPT_NOSECURE );
			}
#endif /* __WIN32__ && !NT_DRIVER */

#if defined( __MSDOS__ ) && defined( __DJGPP__ )
	/* Under 32-bit MSDOS use the DPMI-functions to lock the memory */
	if( _go32_dpmi_lock_data( memPtr, memBlockPtr->size ) == 0)
		memBlockPtr->isLocked = TRUE;
	else
		if( getOptionNumeric( CRYPT_OPTION_MISC_FORCELOCK ) )
			{
			free( memPtr );
			*pointer = NULL;
			return( CRYPT_NOSECURE );
			}
#endif /* __MSDOS__ && __DJGPP__ */

#ifdef __UNIX__
  #ifndef NO_MLOCK
	if( !mlock( memPtr, memBlockPtr->size ) )
		memBlockPtr->isLocked = TRUE;
	else
  #endif /* NO_MLOCK */
		if( getOptionNumeric( CRYPT_OPTION_MISC_FORCELOCK ) )
			{
			free( memPtr );
			*pointer = NULL;
			return( CRYPT_NOSECURE );
			}
#endif /* __UNIX__ */

#ifdef __BEOS__
	/* Under BeOS, we could lock an area into memory while we're creating it,
	   but not afterwards.  In addition malloc() works in a pooled area, and
	   we can't just lock whatever page we want, only the whole area.  The
	   POSIX compatibility does not at this point support mlock(), so there's
	   not much we can do (yet) */
	if( getOptionNumeric( CRYPT_OPTION_MISC_FORCELOCK ) )
		{
		free( memPtr );
		*pointer = NULL;
		return( CRYPT_NOSECURE );
		}
#endif /* __BEOS__ */

#if defined( __MAC__ )
	/* The Mac has two functions for locking memory, HoldMemory() (which
	   makes the memory ineligible for paging) and LockMemory() (which makes
	   it ineligible for paging and also immovable).  We use HoldMemory()
	   since it's slightly more friendly, but really critical applications
	   could use LockMemory() */
	if( !HoldMemory( memPtr, memBlockPtr->size ) )
		memBlockPtr->isLocked = TRUE;
	else
		if( getOptionNumeric( CRYPT_OPTION_MISC_FORCELOCK ) )
			{
			free( memPtr );
			*pointer = NULL;
			return( CRYPT_NOSECURE );
			}
#endif /* __MAC__ */

	/* Lock the allocation information to ensure other threads don't try to
	   access it */
	lockGlobalResource( allocation );

	/* If the allocation list is empty, make this the new list */
	if( allocatedListHead == NULL )
		allocatedListHead = allocatedListTail = memBlockPtr;
	else
		{
		/* Insert the element in the end of the list */
		allocatedListTail->next = memBlockPtr;
		memBlockPtr->prev = allocatedListTail;
		allocatedListTail = memBlockPtr;
		}

	/* Unlock the allocation table to allow access by other threads */
	unlockGlobalResource( allocation );

	return( CRYPT_OK );
	}

/* A safe free function which scrubs memory and zeroes the pointer.

	"You will softly and suddenly vanish away
	 And never be met with again"	- Lewis Carroll,
									  "The Hunting of the Snark" */

void krnlMemfree( void **pointer )
	{
	MEMLOCK_INFO *memBlockPtr, *nextBlockPtr, *prevBlockPtr;
	BYTE *memPtr = ( BYTE * ) *pointer;

	/* Make sure we're not trying to free unallocated memory */
	if( memPtr == NULL )
		return;

	/* Get a pointer to the blocks header */
	memPtr -= MEMLOCK_HEADERSIZE;
	memBlockPtr = ( MEMLOCK_INFO * ) memPtr;
	nextBlockPtr = memBlockPtr->next;
	prevBlockPtr = memBlockPtr->prev;

	/* Lock the allocation resource to ensure other threads don't try to
	   access them */
	lockGlobalResource( allocation );

	/* Unlink the block from the allocation list */
	if( memBlockPtr == allocatedListHead )
		allocatedListHead = nextBlockPtr;	/* Delete from start */
	else
		prevBlockPtr->next = nextBlockPtr;	/* Delete from middle or end */
	if( nextBlockPtr != NULL )
		nextBlockPtr->prev = prevBlockPtr;
	if( memBlockPtr == allocatedListTail )
		allocatedListTail = prevBlockPtr;

#if defined( __WIN32__ ) && !defined( NT_DRIVER )
	/* Because VirtualLock() works on a per-page basis, we can't unlock a
	   memory block if there's another locked block on the same page.  The
	   only way to manage this is to walk the block list checking to see
	   whether there's another block allocated on the same page.  Although in
	   theory this could make freeing memory rather slow, in practice there
	   are only a small number of allocated blocks to check so it's
	   relatively quick, especially compared to the overhead imposed by the
	   lethargic VC++ allocator.  The only real disadvantage is that the
	   allocation resources remain locked while we do the free, but this
	   isn't any worse than the overhead of touchAllocatedPages().

	   Note that the following code is nonportable in that it assumes
	   sizeof( long ) == sizeof( void * ), but this is currently the case on
	   Wintel hardware.  It also assumes that an allocated block will never
	   cover more than two pages, which is also always the case */
	if( memBlockPtr->isLocked )
		{
		MEMLOCK_INFO *currentBlockPtr;
		long block1PageAddress, block2PageAddress;

		/* Calculate the addresses of the page(s) in which the memory block
		   resides */
		block1PageAddress = getPageStartAddress( memBlockPtr );
		block2PageAddress = getPageEndAddress( memBlockPtr, memBlockPtr->size );
		if( block1PageAddress == block2PageAddress )
			block2PageAddress = 0;

		/* Walk down the block list checking whether the page(s) contain
		   another locked block */
		for( currentBlockPtr = allocatedListHead; currentBlockPtr != NULL;
			 currentBlockPtr = currentBlockPtr->next )
			{
			const long currentPage1Address = getPageStartAddress( currentBlockPtr );
			long currentPage2Address = getPageEndAddress( currentBlockPtr, currentBlockPtr->size );

			if( currentPage1Address == currentPage2Address )
				currentPage2Address = 0;

			/* There's another block allocated on either of the pages, don't
			   unlock it */
			if( block1PageAddress == currentPage1Address || \
				block1PageAddress == currentPage2Address )
				{
				block1PageAddress = 0;
				if( !block2PageAddress )
					break;
				}
			if( block2PageAddress == currentPage1Address || \
				block2PageAddress == currentPage2Address )
				{
				block2PageAddress = 0;
				if( !block1PageAddress )
					break;
				}
			}

		/* Finally, if either page needs unlocking, do so.  The supplied size
		   is irrelevant since the entire page the memory is on is unlocked */
		if( block1PageAddress )
			VirtualUnlock( ( void * ) block1PageAddress, 16 );
		if( block2PageAddress )
			VirtualUnlock( ( void * ) block2PageAddress, 16 );
		}
#endif /* __WIN32__ && !NT_DRIVER */

	/* Unlock the allocation resources to allow access by other threads */
	unlockGlobalResource( allocation );

	/* If the memory is locked, unlock it now */
#if defined( __UNIX__ ) && !defined( NO_MLOCK )
	if( memBlockPtr->isLocked )
		munlock( memPtr, memBlockPtr->size );
#endif /* __UNIX__ && !NO_MLOCK */

#if defined( __MSDOS__ ) && defined( __DJGPP__ )
	/* Under 32-bit MSDOS we *could* use the DPMI-functions to unlock the
	   memory, but as many DPMI hosts implement page locking in a binary form
	   (no lock count maintained), we don't actually unlock anything at all.
	   Note that this may lead to a shortage of virtual memory in long-
	   running applications */
#endif /* __MSDOS__ && __DJGPP__ */

#if defined( __MAC__ )
	if( memBlockPtr->isLocked )
		UnholdMemory( memPtr, memBlockPtr->size );
#endif /* __MAC__ */

	/* Zeroise the memory (including the memlock info), free it, and zero
	   the pointer */
	zeroise( memPtr, memBlockPtr->size );
	free( memPtr );
	*pointer = NULL;
	}

/* Determine the size of a krnlMemalloc()'d memory block */

int krnlMemsize( const void *pointer )
	{
	MEMLOCK_INFO *memBlockPtr;
	BYTE *memPtr = ( BYTE * ) pointer;

	/* Make sure it's a valid pointer */
	if( memPtr == NULL )
		return( 0 );

	/* Find out how big the memory block is */
	memPtr -= MEMLOCK_HEADERSIZE;
	memBlockPtr = ( MEMLOCK_INFO * ) memPtr;
	return( memBlockPtr->size - MEMLOCK_HEADERSIZE );
	}

/* Walk the allocated block list touching each page.  In most cases we don't
   need to explicitly touch the page since the allocated blocks are almost
   always smaller than the MMU's page size and simply walking the list
   touches them, but in some rare cases we need to explicitly touch each
   page */

static void touchAllocatedPages( void )
	{
	MEMLOCK_INFO *memBlockPtr;

	/* Lock the allocation resource to ensure other threads don't try to
	   access them */
	lockGlobalResource( allocation );

	/* Walk down the list (which implicitly touches each page).  If the
	   allocated region is larger than 4K, explicitly touch each 4K page.
	   This assumes a page size of 4K which is usually true (and difficult
	   to determine otherwise), in any case it doesn't make much difference
	   since nothing ever allocates more than two 4K pages */
	for( memBlockPtr = allocatedListHead; memBlockPtr != NULL;
		 memBlockPtr = memBlockPtr->next )
		{
		if( memBlockPtr->size > 4096 )
			{
			BYTE *memPtr = ( BYTE * ) memBlockPtr + 4096;
			int memSize = memBlockPtr->size;

			/* Touch each page.  The rather convoluted expression is to try
			   and stop it from being optimised away - it always evaluates to
			   true since we only get here if allocatedListHead != NULL, but
			   hopefully the compiler won't be able to figure that out */
			while( memSize > 4096 )
				{
				if( *memPtr || allocatedListHead != NULL )
					memPtr += 4096;
				memSize -= 4096;
				}
			}
		}

	/* Unlock the allocation resources to allow access by other threads */
	unlockGlobalResource( allocation );
	}

/* Create and destroy the secure allocation information */

static void initAllocation( void )
	{
	/* Clear the list head and tail pointers */
	allocatedListHead = allocatedListTail = NULL;

	/* Initialize any data structures required to make the allocation thread-
	   safe */
	initGlobalResourceLock( allocation );
	}

static void endAllocation( void )
	{
	/* Destroy any data structures required to make the allocation thread-
	   safe */
	deleteGlobalResourceLock( allocation );
	}

/****************************************************************************
*																			*
*						Initialisation Management Functions					*
*																			*
****************************************************************************/

/* Begin and end initialisation by locking or unlocking the initialisation
   mutex and checking or setting the flag which determines whether we're
   initialised or not */

BOOLEAN beginInitialisation( const BOOLEAN checkState )
	{
	/* Lock the initialisation mutex to make sure other threads don't try to
	   access it */
	lockGlobalResource( initialisation );

	/* If we're already initialised or shut down, don't to anything */
	if( isInitialised == checkState )
		{
		unlockGlobalResource( initialisation );
		return( FALSE );
		}
	return( TRUE );
	}

void endInitialisation( const BOOLEAN newState )
	{
	isInitialised = newState;
	unlockGlobalResource( initialisation );
	}

/* General internal function initialisation and shutdown */

int initInternalFunctions( void )
	{
	int status;

	initAllocation();
	initSemaphores();
	initServices();
	status = initResources();
	if( cryptStatusError( status ) )
		{
		endServices();
		endSemaphores();
		endAllocation();
		}
	return( status );
	}

int endInternalFunctions( void )
	{
	int status;

	status = destroyResources();
	endServices();
	endSemaphores();
	endAllocation();
	return( status );
	}
