/****************************************************************************
*																			*
*							cryptlib Security Kernel						*
*						Copyright Peter Gutmann 1992-1999					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypt.h"
#include "cryptacl.h"

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
static BOOLEAN isInitialised = FALSE;

/* Some messages communicate standard data values which are used again and 
   again so we predefine values for these which can be used globally */

const int messageValueTrue = TRUE;
const int messageValueFalse = FALSE;
const int messageValueCryptOK = CRYPT_OK;
const int messageValueCryptError = CRYPT_ERROR;
const int messageValueCryptSignalled = CRYPT_ERROR_SIGNALLED;
const int messageValueCryptUnused = CRYPT_UNUSED;
const int messageValueCryptUseDefault = CRYPT_USE_DEFAULT;
const int messageValueCursorFirst = CRYPT_CURSOR_FIRST;
const int messageValueCursorNext = CRYPT_CURSOR_NEXT;
const int messageValueCursorPrevious = CRYPT_CURSOR_PREVIOUS;
const int messageValueCursorLast = CRYPT_CURSOR_LAST;

/****************************************************************************
*																			*
*						Object Definitions and Information					*
*																			*
****************************************************************************/

/* Macros to perform validity checks on objects and handles.  These checks 
   are:

	isValidHandle(): Whether a handle is a valid index into the object table.
	isValidObject(): Whether a handle refers to an object in the table.
	isFreeObject(): Whether a handle refers to an empty entry in the table.
	isInternalObject(): Whether an object is an internal object.
	isInvalidObjectState(): Whether an object is in an invalid (error) state.
	isInUse(): Whether an object is currently in use (processing a message).
	itInHighState(): Whether an object is in the 'high' security state.
	isValidMessage(): Whether a message type is valid.
	isValidType(): Whether an object type is valid */

#define isValidHandle( handle ) \
	( ( handle ) >= 0 && ( handle ) < objectTableSize )
#define isValidObject( handle ) \
	( isValidHandle( handle ) && objectTable[ ( handle ) ].objectPtr != NULL )
#define isFreeObject( handle ) \
	( isValidHandle( handle ) && objectTable[ ( handle ) ].objectPtr == NULL )
#define isInternalObject( handle ) \
	( objectTable[ handle ].flags & OBJECT_FLAG_INTERNAL )
#define isInvalidObjectState( handle ) \
	( objectTable[ ( handle ) ].flags & OBJECT_FLAGMASK_STATUS )
#define isInUse( handle ) \
	( objectTable[ ( handle ) ].inUse )
#define isInHighState( handle ) \
	( objectTable[ ( handle ) ].flags & OBJECT_FLAG_HIGH )
#define isValidMessage( message ) \
	( ( message ) > RESOURCE_MESSAGE_NONE && \
	  ( message ) < RESOURCE_MESSAGE_LAST )
#define isValidType( type ) \
	( ( type ) > OBJECT_TYPE_NONE && ( type ) < OBJECT_TYPE_LAST )

/* Macros to test whether a message falls into a certain class.  These tests 
   are:

	isGlobalOptionMessage(): Whether a message is intended for a systemwide 
					config option.
	isIncomingAttributeMessage(): Whether a message represents an incoming
					attribute.
	isOutgoingAttributeMessage(): Whether a message represents an outgoing
					attribute */

#define isGlobalOptionMessage( handle, message, value ) \
	( ( objectHandle ) == CRYPT_UNUSED && isAttributeMessage( localMessage ) && \
		isOptionAttribute( messageValue ) )
#define isIncomingAttributeMessage( message ) \
	( ( message ) == RESOURCE_MESSAGE_SETATTRIBUTE || \
	  ( message ) == RESOURCE_MESSAGE_SETATTRIBUTE_S )
#define isOutgoingAttributeMessage( message ) \
	( ( message ) == RESOURCE_MESSAGE_GETATTRIBUTE || \
	  ( message ) == RESOURCE_MESSAGE_GETATTRIBUTE_S )

/* A macro to turn an abnormal status indicated in an objects flags into a
   status code.  The values are prioritised so notinited > signalled > busy */

#define getObjectStatusValue( flags ) \
		( ( flags & OBJECT_FLAG_NOTINITED ) ? CRYPT_ERROR_NOTINITED : \
		  ( flags & OBJECT_FLAG_SIGNALLED ) ? CRYPT_ERROR_SIGNALLED : \
		  ( flags & OBJECT_FLAG_BUSY ) ? CRYPT_ERROR_BUSY : CRYPT_OK )

/* Macros to handle pre- and postconditions in functions.  By default these 
   are mapped directly to assertions, but they can be remapped for use by an 
   external verifier if USE_EXTERNAL_CHECKER is defined (typically this means
   turning them into nops for ADL) */

#ifndef USE_EXTERNAL_CHECKER
  #define PRE( x )		assert( x )		/* Precondition */
  #define INV( x )		assert( x )		/* Invariant */
  #define POST( x )		assert( x )		/* Postcondition */
#endif /* USE_EXTERNAL_CHECKER */

/* The allocation size of the object table.  In memory-starved environments
   we limit the size, in general these are embedded systems or single-tasking
   OS's which aren't going to need many objects anyway */

#ifdef __MSDOS16__
  #define OBJECT_TABLE_ALLOCSIZE	128
#else
  #define OBJECT_TABLE_ALLOCSIZE	1024
#endif /* Memory-starved environments */

/* The table to map external object handles to object data */

OBJECT_INFO *objectTable;
int objectTableSize;
DECLARE_LOCKING_VARS( objectTable )

/* A template used to initialise object table entries.  Some of the entries 
   are either object handles which have to be set to CRYPT_ERROR or values 
   for which 0 is significant (so they're set to CRYPT_UNUSED), because of 
   this we can't just memset the entry to all zeroes */

static const OBJECT_INFO objectTemplate = { 
	OBJECT_TYPE_NONE, NULL,		/* Type and data pointer */
	OBJECT_FLAG_INTERNAL | OBJECT_FLAG_NOTINITED,	/* Flags */
	0, 0,						/* Action flags, and subtype */
	CRYPT_UNUSED, CRYPT_UNUSED,	/* Forward count, usage count */
	0, 0,						/* Reference count, in use flag */
	NULL,						/* Message function */
	CRYPT_ERROR, CRYPT_ERROR	/* Dependent objects */
	};

/* The object allocation state data and a template used to initialise it.  
   This controls the allocation of handles to newly-created objects.  The 
   first NO_SYSTEM_OBJECTS handles are system objects which exist with 
   fixed handles, the remainder are allocated pseudorandomly under the 
   control of an LFSR (see the comments further down for more details on 
   this) */

typedef struct {
	int lfsrMask, lfsrPoly;		/* LFSR state values */
	int lfsrPolyTableIndex;		/* Current position in LFSR polynomial table */
	int objectHandle;			/* Current object handle */
	} OBJECT_STATE_INFO;
	
static const OBJECT_STATE_INFO objectStateTemplate = {
	OBJECT_TABLE_ALLOCSIZE,		/* Mask for LFSR output */
	0x409,						/* LFSR polynomial */
	0,							/* Next LFSR polynomial to use */
	-1							/* Initial-1'th object handle */
	};
static OBJECT_STATE_INFO objectStateInfo;

/* Create and destroy the object table.  The destroy process is handled in 
   two stages, the first one which is called fairly early in the shutdown
   process to destroy any remaining objects, and the second which is called
   at the end of the shutdown when the kernel data is being deleted.  This 
   is because some of the objects are tied to things like external devices,
   and deleting them at the end when everything else has been shut down 
   isn't possible */

static int initResources( void )
	{
	int i;

	/* Allocate and initialise the object table */
	objectTable = malloc( OBJECT_TABLE_ALLOCSIZE * sizeof( OBJECT_INFO ) );
	if( objectTable == NULL )
		return( CRYPT_ERROR_MEMORY );
	for( i = 0; i < OBJECT_TABLE_ALLOCSIZE; i++ )
		objectTable[ i ] = objectTemplate;
	objectTableSize = OBJECT_TABLE_ALLOCSIZE;
	objectStateInfo = objectStateTemplate;

	/* Postconditions */
	POST( objectTable != NULL );
	POST( objectTableSize == OBJECT_TABLE_ALLOCSIZE );
	POST( objectStateInfo.lfsrMask == OBJECT_TABLE_ALLOCSIZE && \
		  objectStateInfo.lfsrPoly == 0x409 && \
		  objectStateInfo.lfsrPolyTableIndex == 0 && \
		  objectStateInfo.objectHandle == SYSTEM_OBJECT_HANDLE - 1 );

	/* Initialize any data structures required to make the object table
	   thread-safe */
	initGlobalResourceLock( objectTable );

	return( CRYPT_OK );
	}

static int destroySelectedObjects( const int currentDepth )
	{
	int objectHandle, status = CRYPT_OK;

	for( objectHandle = NO_SYSTEM_OBJECTS; objectHandle < objectTableSize; 
		 objectHandle++ )
		{
		const int dependentObject = \
						objectTable[ objectHandle ].dependentObject;
		int depth = 1;

		/* If there's nothing there, continue */
		if( objectTable[ objectHandle ].objectPtr == NULL )
			continue;

		/* There's an object still present, determine its nesting depth.  
		   Dependent devices are terminal so we only follow the path down for 
		   dependent objects */
		if( dependentObject != CRYPT_ERROR )
			depth = \
				( objectTable[ dependentObject ].dependentObject != CRYPT_ERROR || \
				  objectTable[ dependentObject ].dependentDevice != CRYPT_ERROR ) ? \
				3 : 2;
		else
			if( objectTable[ objectHandle ].dependentDevice != CRYPT_ERROR )
				depth = 2;

		/* If the nesting level of the object matches the current level, 
		   destroy it.  "For death is come up into our windows, and it is 
		   entered into our palaces, to cut off the children from the without" 
		   -- Jeremiah 9:21 */
		if( depth >= currentDepth )
			{
			krnlSendNotifier( objectHandle, RESOURCE_IMESSAGE_DESTROY );
			status = CRYPT_ERROR_INCOMPLETE;
			}
		}
	
	return( status );
	}

int destroyObjects( void )
	{
	int depth, objectHandle, status = CRYPT_OK;

	/* Lock the object table to ensure other threads don't try to access
	   it */
	lockGlobalResource( objectTable );

	/* Delete every standard entry in the table.  This is rather more complex
	   than just rumbling through deleting each object we find since some 
	   objects have dependent objects underneath them, and deleting the 
	   lower-level object causes problems when we later delete their parents
	   (the code handles it cleanly, but we get a kernel trap warning us that 
	   we're trying to delete a non-present object).  Because of this we have
	   to delete the objects in order of depth, first all three-level objects
	   (eg cert -> context -> device), then all two-level objects, and 
	   finally all one-level objects.  This means we can never delete another
	   object out from under a dependent object */
	for( depth = 3; depth > 0; depth-- )
		{
		int localStatus = destroySelectedObjects( depth );

		if( cryptStatusError( localStatus ) )
			status = localStatus;
		}

	/* Destroy the system objects, which are all one-level objects.  This is 
	   done explicitly here because the dispatcher checks to make sure 
	   they're never destroyed through a standard message, which indicates a 
	   programming error */
	for( objectHandle = 0; objectHandle < NO_SYSTEM_OBJECTS; objectHandle++ )
		{
		if( objectTable[ objectHandle ].messageFunction != NULL )
			objectTable[ objectHandle ].messageFunction( objectHandle, 
										RESOURCE_MESSAGE_DESTROY, NULL, 0 );
		objectTable[ objectHandle ] = objectTemplate;
		}

	/* Unlock the object table to allow access by other threads */
	unlockGlobalResource( objectTable );

	return( status );
	}

static void endResources( void )
	{
	/* Hinc igitur effuge */
	lockGlobalResource( objectTable );
	zeroise( objectTable, objectTableSize * sizeof( OBJECT_INFO ) );
	free( objectTable );
	objectTable = NULL;
	unlockGlobalResource( objectTable );
	deleteGlobalResourceLock( objectTable );
	}

/****************************************************************************
*																			*
*							Object Creation/Destruction						*
*																			*
****************************************************************************/

/* Create a new object.  This function has to be very careful about locking
   to ensure that another thread can't manipulate the newly-created object
   while it's in an indeterminate state.  To accomplish this it locks the
   object table and tries to create the new object.  If this succeeds it sets
   the objects status to CRYPT_ERROR_NOTINITED pending completion of the 
   objects initialisation by the caller, unlocks the object table, and 
   returns control to the caller.  While the object is in this state, the 
   kernel will allow it to process only two message types, either a 
   notification from the caller that the init stage is complete (which sets 
   the objects state to CRYPT_OK), or a destroy object message, which sets 
   its state to CRYPT_ERROR_SIGNALLED pending arrival of the init complete 
   notification, whereupon the object is immediately destroyed.  The state 
   diagram for this is:
									 State
						  Notinited			Signalled
			--------+-------------------+-----------------
			-> OK	| state -> OK,		| Msg -> Destroy
					| ret( OK )			|
	Msg.	Destroy	| state -> Sig'd,	| state -> Sig'd,
					| ret( OK )			| ret( OK )
			CtrlMsg	| process as usual	| process as usual
			NonCtrl	| ret( Notinited )	| ret( Sig'd )

   The initialisation process for an object is therefore:

	status = krnlCreateObject( ... );
	if( cryptStatusError( status ) )
		return( status );
	initResourceLock();
	lockResource();

	// Complete object-specific initialisation
	initStatus = ...;

	unlockResource();
	status = krnlSendMessage( ..., state -> CRYPT_OK );
	return( ( cryptStatusError( initStatus ) ? initStatus : status );

   If the object is destroyed during the object-specific initialisation 
   (either by the init code when an error is encountered or due to an 
   external signal), the destroy is deferred until the change state message
   at the end occurs.  If a destroy is pending, the change state is converted
   to a destroy and the newly-created object is destroyed.

   This mechanism ensures that the object table is only locked for a very 
   short time (typically for only a few lines of executed code in the create
   object function) so that slow initialisation (for example of keyset 
   objects associated with network links) can't block other objects.

   The locking is complicated by the fact that the object table and lock may
   not have been initialised yet, so we also need to check the initialisation
   lock before we try to lock or use the object table.  Even this can create
   problems since the initialisation lock may not have been set up yet, but
   we can't really fix that.  In any case under Win32 it's OK since the mutex
   is set up by DllMain(), and under most Unixen the storage for the mutex is
   set to all-zero which is equivalent to an initialised mutex.

   In addition to the locking, we need to be careful with how we create new 
   objects because if we just allocate handles sequentially and reuse handles 
   as soon as possible, an existing object could be signalled and a new one 
   created in its place without the caller or owning object realizing that 
   they're now working with a different object.  Unix systems handle this by 
   always incrementing pids and assuming there won't be any problems when 
   they wrap, we do the same thing but in addition allocate handles in a non-
   sequential manner using an LFSR to step through the object table.  There's 
   no strong reason for this, but it only costs a few extra clocks so we may 
   as well do it */

static int findFreeResource( int value )
	{
	int oldValue = value;

	/* Preconditions */
	PRE( isValidHandle( value ) );

	/* Make sure the initial LFSR state is valid */
	if( !value )
		value = ( ( int ) time( NULL ) ) & ( objectStateInfo.lfsrMask - 1 );

	/* Step through the entire table looking for a free entry */
	do
		{
		/* Get the next value: Multiply by x and reduce by the polynomial */
		value <<= 1;
		if( value & objectStateInfo.lfsrMask )
			value ^= objectStateInfo.lfsrPoly;
		}
	while( objectTable[ value ].objectPtr != NULL && \
		   value != oldValue );

	/* Postconditions */
	POST( isValidHandle( value ) );
	POST( isFreeObject( value ) || value == oldValue );

	return( value );
	}

int krnlCreateObject( void **objectDataPtr, const OBJECT_TYPE type, 
					  const int subType, const int objectSize, 
					  const int createObjectFlags, const int actionFlags,
					  RESOURCE_MESSAGE_FUNCTION messageFunction )
	{
	OBJECT_INFO objectInfo;
	int oldObjectHandle = objectStateInfo.objectHandle;

	/* Preconditions */
	PRE( objectDataPtr != NULL );
	PRE( isValidType( type ) );
	PRE( objectSize > 16 && objectSize < 16384 );
	PRE( !( createObjectFlags & \
			~( CREATEOBJECT_FLAG_SECUREMALLOC | CREATEOBJECT_FLAG_DUMMY ) ) );
	PRE( actionFlags < ACTION_PERM_LAST );
	PRE( messageFunction != NULL );

	*objectDataPtr = NULL;

	/* Allocate memory for the object and set up the object table entry.  The
	   object is always created as an internal object, it's up to the caller 
	   to make it externally visible.  Since this step doesn't access the 
	   object table, we do it outside the locked section */
	if( createObjectFlags & CREATEOBJECT_FLAG_SECUREMALLOC )
		{
		int status = krnlMemalloc( objectDataPtr, objectSize );
		if( cryptStatusError( status ) )
			return( status );
		}
	else
		if( ( *objectDataPtr = malloc( objectSize ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
	memset( *objectDataPtr, 0, objectSize );
	objectInfo = objectTemplate;
	objectInfo.objectPtr = *objectDataPtr;
	objectInfo.type = type;
	objectInfo.subType = subType;
	objectInfo.actionFlags = actionFlags;
	objectInfo.messageFunction = messageFunction;
	setObjectOwnership( &objectInfo, CRYPT_UNUSED );

	/* Make sure the kernel has been initialised, and if it has lock the 
	   object table for exclusive access */
	lockGlobalResource( initialisation ); 
	if( !isInitialised ) 
		{ 
		unlockGlobalResource( initialisation ); 
		return( CRYPT_ERROR_NOTINITED );
		} 
	lockGlobalResource( objectTable ); 
	unlockGlobalResource( initialisation ); 

	/* The first objects created are internal objects with predefined 
	   handles.  At the moment there's only one of these (the randomness
	   pseudo-device) which always has handle zero, if more fixed objects 
	   were used we would ratchet up through the fixed handles until we 
	   reached the last fixed object, whereupon we would allocate handles 
	   normally */
	if( objectStateInfo.objectHandle < NO_SYSTEM_OBJECTS - 1 )
		{
		PRE( type == OBJECT_TYPE_DEVICE );
		objectStateInfo.objectHandle++;
		POST( isValidHandle( objectStateInfo.objectHandle ) && \
			  objectStateInfo.objectHandle < NO_SYSTEM_OBJECTS );
		}
	else
		/* Search the table for a free entry */
		objectStateInfo.objectHandle = \
					findFreeResource( objectStateInfo.objectHandle );

	/* If the table is full, expand it */
	if( objectStateInfo.objectHandle == oldObjectHandle )
		{
		static const int lfsrPolyTable[] = \
							{ 0x805, 0x1053, 0x201B, 0x402B, 0x8003 };
		OBJECT_INFO *newTable;
		int i;

		/* Expand the table */
		newTable = malloc( ( objectTableSize + OBJECT_TABLE_ALLOCSIZE ) * \
						   sizeof( OBJECT_INFO ) );
		if( newTable == NULL )
			{
			unlockGlobalResource( objectTable ); 
			return( CRYPT_ERROR_MEMORY );
			}

		/* Copy the information across to the new table, set up the newly-
		   allocated entries, and clear the old table */
		memcpy( newTable, objectTable, 
				objectTableSize * sizeof( OBJECT_INFO ) );
		for( i = 0; i < OBJECT_TABLE_ALLOCSIZE; i++ )
			newTable[ objectTableSize + i ] = objectTemplate;
		zeroise( objectTable, objectTableSize * sizeof( OBJECT_INFO ) );
		free( objectTable );
		objectTable = newTable;
		objectTableSize += OBJECT_TABLE_ALLOCSIZE;

		/* Add the new object at the end of the existing table */
		objectStateInfo.lfsrMask <<= 1;
		objectStateInfo.lfsrPoly = \
					lfsrPolyTable[ objectStateInfo.lfsrPolyTableIndex++ ];
		objectStateInfo.objectHandle = \
					findFreeResource( objectStateInfo.objectHandle );
		}

	/* Set up the new object entry in the table */
	objectTable[ objectStateInfo.objectHandle ] = objectInfo;

	/* Postconditions */
	POST( isValidObject( objectStateInfo.objectHandle ) );

	unlockGlobalResource( objectTable );
	return( objectStateInfo.objectHandle );
	}

/****************************************************************************
*																			*
*							Internal Message Handlers						*
*																			*
****************************************************************************/

/* Update an action permission.  This implements a ratchet which only allows
   permissions to be made more restrictive after they've initially been set,
   so once a permission is set to a given level it can't be set to a less
   restrictive level (ie it's a write-up policy) */

static int updateActionPerms( int currentPerm, const int newPerm )
	{
	int permMask = ACTION_PERM_MASK, i;

	/* For each permission, update its value of the new setting is more 
	   restrictive than the current one.  Since smaller values are more
	   restrictive, we can do a simple range comparison and replace the
	   existing value if it's larger than the new one */
	for( i = 0; i < ACTION_PERM_COUNT; i++ )
		{
		if( ( newPerm & permMask ) < ( currentPerm & permMask ) )
			currentPerm = ( currentPerm & ~permMask ) | ( newPerm & permMask );
		permMask <<= 2;
		}	
	
	return( currentPerm );
	}

/* Get/set object property attributes.  We differentiate between a small 
   number of user-accessible properties such as the objects owner, and 
   properties which are only accessible by cryptlib.  The user-accessible 
   properties can be locked, which makes them immutable (at least to being 
   explicitly set, they can still be implicitly altered, for example setting 
   a new object owner decrements the forwardable counter) and also unreadable
   by the user */

static int getPropertyAttribute( const int objectHandle, 
								 const CRYPT_ATTRIBUTE_TYPE attribute,
								 void *messageDataPtr )
	{
	const OBJECT_INFO *objectInfoPtr = &objectTable[ objectHandle ];
	int *valuePtr = ( int * ) messageDataPtr;

	/* Preconditions */
	PRE( isValidObject( objectHandle ) );
	PRE( attribute == CRYPT_PROPERTY_OWNER || \
		 attribute == CRYPT_PROPERTY_FORWARDABLE || \
		 attribute == CRYPT_PROPERTY_LOCKED || \
		 attribute == CRYPT_PROPERTY_USAGECOUNT || \
		 attribute == CRYPT_PROPERTY_ENCRYPTONLY || \
		 attribute == CRYPT_PROPERTY_DECRYPTONLY || \
		 attribute == CRYPT_IATTRIBUTE_TYPE || \
		 attribute == CRYPT_IATTRIBUTE_STATUS || \
		 attribute == CRYPT_IATTRIBUTE_INTERNAL || \
		 attribute == CRYPT_IATTRIBUTE_ACTIONPERMS );
	PRE( messageDataPtr != NULL );

	switch( attribute )
		{
		/* User-accessible properties */
		case CRYPT_PROPERTY_OWNER:
			/* We allow this to be read since its value can be determined
			   anyway with a trial access */
			*valuePtr = ( int ) getObjectOwnership( objectInfoPtr );
			break;

		case CRYPT_PROPERTY_FORWARDABLE:
			if( objectInfoPtr->flags & OBJECT_FLAG_LOCKED )
				return( CRYPT_ERROR_PERMISSION );
			*valuePtr = objectInfoPtr->forwardCount;
			break;

		case CRYPT_PROPERTY_LOCKED:
			/* We allow this to be read since its value can be determined
			   anyway with a trial write */
			*( ( BOOLEAN * ) messageDataPtr ) = \
						( objectInfoPtr->flags & OBJECT_FLAG_LOCKED ) ? \
						TRUE : FALSE;
			break;

		case CRYPT_PROPERTY_USAGECOUNT:
			*valuePtr = objectInfoPtr->usageCount;
			break;

		/* Internal properties */
		case CRYPT_IATTRIBUTE_TYPE :
			*valuePtr = objectInfoPtr->type;
			break;

		case CRYPT_IATTRIBUTE_STATUS:
			*valuePtr = objectInfoPtr->flags & OBJECT_FLAGMASK_STATUS;
			break;

		case CRYPT_IATTRIBUTE_INTERNAL:
			*( ( BOOLEAN * ) messageDataPtr ) = \
					( objectInfoPtr->flags & OBJECT_FLAG_INTERNAL ) ? \
					TRUE : FALSE;
			break;

		case CRYPT_IATTRIBUTE_ACTIONPERMS:
			*valuePtr = objectInfoPtr->actionFlags;
			break;
		
		default:
			assert( NOTREACHED );
		}

	return( CRYPT_OK );
	}

static int setPropertyAttribute( const int objectHandle, 
								 const CRYPT_ATTRIBUTE_TYPE attribute,
								 void *messageDataPtr )
	{
	OBJECT_INFO *objectInfoPtr = &objectTable[ objectHandle ];
	const int value = *( ( int * ) messageDataPtr );

	/* Preconditions */
	PRE( isValidObject( objectHandle ) );
	PRE( attribute == CRYPT_PROPERTY_OWNER || \
		 attribute == CRYPT_PROPERTY_FORWARDABLE || \
		 attribute == CRYPT_PROPERTY_LOCKED || \
		 attribute == CRYPT_PROPERTY_USAGECOUNT || \
		 attribute == CRYPT_PROPERTY_ENCRYPTONLY || \
		 attribute == CRYPT_PROPERTY_DECRYPTONLY || \
		 attribute == CRYPT_IATTRIBUTE_STATUS || \
		 attribute == CRYPT_IATTRIBUTE_INTERNAL || \
		 attribute == CRYPT_IATTRIBUTE_ACTIONPERMS );
	PRE( messageDataPtr != NULL );
	PRE( objectHandle >= NO_SYSTEM_OBJECTS || \
		 attribute == CRYPT_IATTRIBUTE_STATUS );

	switch( attribute )
		{
		/* User-accessible properties */
		case CRYPT_PROPERTY_OWNER:
			/* This property can still be changed (even if the object is
			   locked) until the forwarding count drops to zero, otherwise 
			   locking the object would prevent any forwarding) */
			if( objectInfoPtr->forwardCount != CRYPT_UNUSED )
				{
				if( objectInfoPtr->forwardCount <= 0 )
					return( CRYPT_ERROR_PERMISSION );
				objectInfoPtr->forwardCount--;
				}
			setObjectOwnership( objectInfoPtr, value );
			break;

		case CRYPT_PROPERTY_FORWARDABLE:
			if( objectInfoPtr->flags & OBJECT_FLAG_LOCKED )
				return( CRYPT_ERROR_PERMISSION );
			objectInfoPtr->forwardCount = value;
			break;

		case CRYPT_PROPERTY_LOCKED:
			/* Precondition: This property can only be set to true */
			PRE( *( ( BOOLEAN * ) messageDataPtr ) );

			objectInfoPtr->flags |= OBJECT_FLAG_LOCKED;
			break;

		case CRYPT_PROPERTY_USAGECOUNT:
			if( ( objectInfoPtr->flags & OBJECT_FLAG_LOCKED ) || \
				( objectInfoPtr->usageCount != CRYPT_UNUSED ) )
				return( CRYPT_ERROR_PERMISSION );
			objectInfoPtr->usageCount = value;
			break;

		/* Internal properties */
		case CRYPT_IATTRIBUTE_STATUS:
			/* We're clearing an error/abnormal state or setting the object
			   to the busy state */
			PRE( value == CRYPT_OK || value == CRYPT_ERROR_BUSY );

			if( isInvalidObjectState( objectHandle ) )
				{
				/* If the object is in an abnormal state, we can only (try to)
				   return it back to the normal state after the problem is 
				   resolved */
				PRE( value == CRYPT_OK );

				/* If we're resetting the object status from busy to OK, 
				   notify the object in case there's any extra processing to 
				   be done */
				if( objectInfoPtr->flags & OBJECT_FLAG_BUSY )
					{
					/* Precondition: Only contexts can be busy */
					PRE( objectInfoPtr->type == OBJECT_TYPE_CONTEXT );

					/* If the notification returns an error, the object is 
					   still performing some sort of processing (eg cleanup/
					   shutdown), don't reset the status (it'll be done later 
					   when the object is ready) */
					if( objectInfoPtr->messageFunction( objectHandle,
								RESOURCE_MESSAGE_CHANGENOTIFY, messageDataPtr,
								CRYPT_IATTRIBUTE_STATUS ) == CRYPT_OK )
						objectInfoPtr->flags &= ~OBJECT_FLAG_BUSY;
					break;
					}

				/* If we're processing a notification from the caller that 
				   the object init is complete and the object was destroyed 
				   while it was being created (which sets its state to 
				   CRYPT_ERROR_SIGNALLED), tell the caller to convert the 
				   message to a destroy object message unless it's the system 
				   object, which can't be explicitly destroyed.  In this case 
				   we just return an error so the cryptlib init fails */
				if( objectInfoPtr->flags & OBJECT_FLAG_SIGNALLED )
					return( ( objectHandle < NO_SYSTEM_OBJECTS ) ? 
							CRYPT_ERROR_SIGNALLED : OK_SPECIAL );

				/* We're transitioning the object to the initialised state */
				PRE( objectInfoPtr->flags & OBJECT_FLAG_NOTINITED );
				objectInfoPtr->flags &= ~OBJECT_FLAG_NOTINITED;
				break;
				}

			/* Inner precondition: The object is in a valid state */
			PRE( !isInvalidObjectState( objectHandle ) );

			/* We're setting the object's busy flag because it's about to 
			   perform an async op */
			if( value == CRYPT_ERROR_BUSY )
				objectInfoPtr->flags |= OBJECT_FLAG_BUSY;
			break;

		case CRYPT_IATTRIBUTE_INTERNAL:
			if( *( ( BOOLEAN * ) messageDataPtr ) )
				objectInfoPtr->flags |= OBJECT_FLAG_INTERNAL;
			else
				objectInfoPtr->flags &= ~OBJECT_FLAG_INTERNAL;
			break;

		case CRYPT_IATTRIBUTE_ACTIONPERMS:
			objectInfoPtr->actionFlags = \
					updateActionPerms( objectInfoPtr->actionFlags, value );
			break;

		default:
			assert( NOTREACHED );
		}

	return( CRYPT_OK );
	}

/* Get/set option attributes */

int setOption( const CRYPT_ATTRIBUTE_TYPE option, const int value );
int setOptionString( const CRYPT_ATTRIBUTE_TYPE option, const char *value,
					 const int valueLength );
int getOption( const CRYPT_ATTRIBUTE_TYPE option );
char *getOptionString( const CRYPT_ATTRIBUTE_TYPE option );

static int getOptionAttribute( const RESOURCE_MESSAGE_TYPE message, 
							   const CRYPT_ATTRIBUTE_TYPE attribute,
							   void *messageDataPtr )
	{
	/* Preconditions */
	PRE( message == RESOURCE_MESSAGE_GETATTRIBUTE || \
		 message == RESOURCE_MESSAGE_GETATTRIBUTE_S );
	PRE( isOptionAttribute( attribute ) );
	PRE( messageDataPtr != NULL );

	/* String get can never fail */
	if( message == RESOURCE_MESSAGE_GETATTRIBUTE_S )
		{
		RESOURCE_DATA *msgData = messageDataPtr;
		const char *retVal = getOptionString( attribute );

		if( !*retVal )
			{
			msgData->length = 0;
			return( CRYPT_OK );
			}
		return( attributeCopy( msgData, retVal, strlen( retVal ) ) );
		}

	/* Numeric get can never fail */
	*( ( int * ) messageDataPtr ) = getOption( attribute );
	return( CRYPT_OK );
	}
	
static int setOptionAttribute( const RESOURCE_MESSAGE_TYPE message, 
							   const CRYPT_ATTRIBUTE_TYPE attribute,
							   const void *messageDataPtr )
	{
	/* Preconditions */
	PRE( message == RESOURCE_MESSAGE_SETATTRIBUTE || \
		 message == RESOURCE_MESSAGE_SETATTRIBUTE_S );
	PRE( isOptionAttribute( attribute ) );
	PRE( messageDataPtr != NULL );

	if( message == RESOURCE_MESSAGE_SETATTRIBUTE_S )
		{
		const RESOURCE_DATA *msgData = messageDataPtr;

		return( setOptionString( attribute, msgData->data, 
								 msgData->length ) );
		}

	return( setOption( attribute, *( ( int * ) messageDataPtr ) ) );
	}

/* Increment/decrement the reference count for an object.  This adjusts the
   reference count as appropriate and sends destroy messages if the reference 
   count goes negative */

static int incRefCount( const int objectHandle, const int dummy1, 
						const void *dummy2 )
	{
	/* Preconditions */
	PRE( isValidObject( objectHandle ) );

	/* Increment an objects reference count */
	objectTable[ objectHandle ].referenceCount++;
	
	/* Postcondition */
	POST( objectTable[ objectHandle ].referenceCount >= 1 );

	return( CRYPT_OK );
	}

static int decRefCount( const int objectHandle, const int dummy1, 
						const void *dummy2 )
	{
	/* Preconditions */
	PRE( isValidObject( objectHandle ) );

	/* Decrement an objects reference count */
	if( objectTable[ objectHandle ].referenceCount )
		{
		objectTable[ objectHandle ].referenceCount--;

		/* Postconditions */
		POST( objectTable[ objectHandle ].referenceCount >= 0 );

		return( CRYPT_OK );
		}

	/* We're already at a single reference, destroy the object.  Since this 
	   may take some time, we unlock the object map around the call */
	unlockGlobalResource( objectTable );
	krnlSendNotifier( objectHandle, RESOURCE_IMESSAGE_DESTROY );
	lockGlobalResource( objectTable );

	/* Postconditions - none.  We can't be sure the object has been destroyed
	   at this point since the message will have been enqueued */

	return( CRYPT_OK );
	}

/* Get/set dependent objects for an object */

static int getDependentObject( const int objectHandle, 
							   const int targetType,
							   const void *messageDataPtr )
	{
	int *valuePtr = ( int * ) messageDataPtr, localObjectHandle;

	/* Preconditions */
	PRE( isValidObject( objectHandle ) );
	PRE( isValidType( targetType ) );
	PRE( messageDataPtr != NULL );

	/* Clear return value */
	*valuePtr = CRYPT_ERROR;

	localObjectHandle = findTargetType( objectHandle, targetType );
	if( cryptStatusError( localObjectHandle ) )
		{
		/* Postconditions */
		POST( *valuePtr == CRYPT_ERROR ); 

		return( CRYPT_ARGERROR_OBJECT );
		}
	*valuePtr = localObjectHandle;

	/* Postconditions */
	POST( isValidObject( *valuePtr ) && \
		  *valuePtr >= NO_SYSTEM_OBJECTS );

	return( CRYPT_OK );
	}

static int setDependentObject( const int objectHandle, 
							   const int incReferenceCount,
							   const void *messageDataPtr )
	{
	const int dependentObject = *( ( int * ) messageDataPtr );
	int *objectHandlePtr;

	/* Preconditions */
	PRE( isValidObject( objectHandle ) );
	PRE( incReferenceCount == TRUE || incReferenceCount == FALSE );
	PRE( isValidHandle( dependentObject ) );

	/* Determine which dependent object value to update based on its type */
	if( !isValidObject( dependentObject ) )
		return( CRYPT_ERROR );	/* Obj.was signalled after message sent */
	objectHandlePtr = \
		( objectTable[ dependentObject ].type == OBJECT_TYPE_DEVICE ) ? \
		&objectTable[ objectHandle ].dependentDevice : \
		&objectTable[ objectHandle ].dependentObject;

	/* Inner precondition */
	PRE( *objectHandlePtr == CRYPT_ERROR );

	/* Update the dependent objects reference count if required and record 
	   the new status in the object table.  Dependent objects can be 
	   established in one of two ways, by taking an existing object and 
	   attaching it to another object (which increments its reference count, 
	   since it's now being referred to by the original owner and by the 
	   object it's  attached to), or by creating a new object and attaching 
	   it to another object (which doesn't increment the reference count 
	   since it's only referred to by the controlling object).  An example of 
	   the former operation is adding a context from a cert request to a cert 
	   (the cert request is referenced by both the caller and the cert), an 
	   example of the latter operation is attaching a data-only cert to a 
	   context (the cert is only referenced by the context) */
	if( incReferenceCount )
		incRefCount( dependentObject, 0, NULL );
	*objectHandlePtr = dependentObject;

	/* Certs and contexts have special relationships in that the cert can 
	   constrain the use of the context beyond its normal level.  When we
	   attach a cert to a context, we have to find the way in which the cert 
	   constrains the context and adjust the contexts action ACL as
	   appropriate.  In contrast when we attach a context to a cert we don't
	   change the contexts action ACL until the context/cert pair is re-
	   instantiated (eg by writing it to a keyset and then re-reading it, 
	   which instantiates it as a context with a cert attached).  The reason
	   for this is that the cert key usage may constrain the context in a way
	   which renders its use impossible (for example creating an encryption-
	   only self-signed cert would be impossible), or the context may be
	   associated with multiple mutually-exclusive certs (one signature-only,
	   one encryption-only), or the key usage in the cert may not be set 
	   until after the context is attached, or any number of other variations.
	   Because of this a cert -> context attach (done when instantiating a
	   context+cert object pair) imposes the cert constraint on the context,
	   but a context -> cert attach (done when creating a cert object) 
	   doesn't impose them.
	   
	   Because a key with a certificate attached indicates that it's 
	   (probably) being used for some function which involves interaction 
	   with a relying party (ie that it probably has more value than a raw 
	   key with no strings attached), we set the action permission to 
	   ACTION_PERM_NONE_EXTERNAL rather than allowing ACTION_PERM_ALL to both 
	   ensure that it's only used in a safe manner via the cryptlib internal
	   mechanisms, and to make sure that it's not possible to utilize the 
	   signature/encryption duality of some algorithms to create a signature 
	   where it's been disallowed */
	if( objectTable[ objectHandle ].type == OBJECT_TYPE_CONTEXT && \
		objectTable[ dependentObject ].type == OBJECT_TYPE_CERTIFICATE )
		{
		int actionFlags = 0;

		/* For each action type, enable its continued use only if the cert 
		   allows it.  The actions specified as ACTION_PERM_ALL will remain
		   unchanged (since we can only further constrain existing usage), 
		   ACTION_PERM_NONE_EXTERNAL will be constrained if they're currently
		   ACTION_PERM_ALL, and all other actions will be disabled */
		if( !cryptStatusError( krnlSendMessage( dependentObject, 
				RESOURCE_IMESSAGE_CHECK, NULL, RESOURCE_MESSAGE_CHECK_PKC_SIGN ) ) )
			actionFlags |= \
				MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_SIGN, ACTION_PERM_NONE_EXTERNAL ) | \
				MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_SIGCHECK, ACTION_PERM_NONE_EXTERNAL );
		if( !cryptStatusError( krnlSendMessage( dependentObject, 
				RESOURCE_IMESSAGE_CHECK, NULL, RESOURCE_MESSAGE_CHECK_PKC_ENCRYPT ) ) )
			actionFlags |= \
				MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_ENCRYPT, ACTION_PERM_NONE_EXTERNAL ) | \
				MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_DECRYPT, ACTION_PERM_NONE_EXTERNAL );
		if( !cryptStatusError( krnlSendMessage( dependentObject, 
				RESOURCE_IMESSAGE_CHECK, NULL, RESOURCE_MESSAGE_CHECK_PKC_KA_EXPORT ) ) )
			actionFlags |= \
				MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_ENCRYPT, ACTION_PERM_NONE_EXTERNAL );
		if( !cryptStatusError( krnlSendMessage( dependentObject, 
				RESOURCE_IMESSAGE_CHECK, NULL, RESOURCE_MESSAGE_CHECK_PKC_KA_IMPORT ) ) )
			actionFlags |= \
				MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_DECRYPT, ACTION_PERM_NONE_EXTERNAL );
		krnlSendMessage( objectHandle, RESOURCE_IMESSAGE_SETATTRIBUTE, 
						 &actionFlags, CRYPT_IATTRIBUTE_ACTIONPERMS );
		}

	/* Postconditions */
	POST( ( isValidObject( *objectHandlePtr ) && \
			*objectHandlePtr >= NO_SYSTEM_OBJECTS ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*									Misc									*
*																			*
****************************************************************************/

/* Find the ACL for an object attribute */

static const ATTRIBUTE_ACL *findAttributeACL( const CRYPT_ATTRIBUTE_TYPE attribute,
											  const BOOLEAN isInternalMessage )
	{
	/* Perform a hardcoded binary search for the attribute ACL, this minimises
	   the number of comparisons necessary to find a match */
	if( attribute < CRYPT_CTXINFO_LAST )
		{
		if( attribute < CRYPT_GENERIC_LAST )
			{
			if( attribute > CRYPT_PROPERTY_FIRST && \
				attribute < CRYPT_PROPERTY_LAST )
				return( &propertyACL[ attribute - CRYPT_PROPERTY_FIRST - 1 ] );
			if( attribute > CRYPT_GENERIC_FIRST && \
				attribute < CRYPT_GENERIC_LAST )
				return( &genericACL[ attribute - CRYPT_GENERIC_FIRST - 1 ] );
			}
		else
			{
			if( attribute > CRYPT_OPTION_FIRST && \
				attribute < CRYPT_OPTION_LAST )
				return( &optionACL[ attribute - CRYPT_OPTION_FIRST - 1 ] );
			if( attribute > CRYPT_CTXINFO_FIRST && \
				attribute < CRYPT_CTXINFO_LAST )
				return( &contextACL[ attribute - CRYPT_CTXINFO_FIRST - 1 ] );
			}
		}
	else
		{
		if( attribute < CRYPT_KEYSETINFO_LAST )
			{
			if( attribute > CRYPT_CERTINFO_FIRST && \
				attribute < CRYPT_CERTINFO_LAST )
				{
				/* Certificate attributes are split into subranges so we have to
				   adjust the offsets to get the right ACL */
				if( attribute < CRYPT_CERTINFO_FIRST_EXTENSION )
					{
					if( attribute > CRYPT_CERTINFO_FIRST_CERTINFO && \
						attribute < CRYPT_CERTINFO_LAST_CERTINFO )
						return( &certificateACL[ attribute - CRYPT_CERTINFO_FIRST_CERTINFO - 1 ] );
					if( attribute > CRYPT_CERTINFO_FIRST_NAME && \
						attribute < CRYPT_CERTINFO_LAST_NAME )
						return( &certNameACL[ attribute - CRYPT_CERTINFO_FIRST_NAME - 1 ] );
					}
				else
					{
					if( attribute > CRYPT_CERTINFO_FIRST_EXTENSION && \
						attribute < CRYPT_CERTINFO_LAST_EXTENSION )
						return( &certExtensionACL[ attribute - CRYPT_CERTINFO_FIRST_EXTENSION - 1 ] );
					if( attribute > CRYPT_CERTINFO_FIRST_CMS && \
						attribute < CRYPT_CERTINFO_LAST_CMS )
						return( &certSmimeACL[ attribute - CRYPT_CERTINFO_FIRST_CMS - 1 ] );
					}
				}
			if( attribute > CRYPT_KEYSETINFO_FIRST && \
				attribute < CRYPT_KEYSETINFO_LAST )
				return( &keysetACL[ attribute - CRYPT_KEYSETINFO_FIRST - 1 ] );
			}
		else
			{
			if( attribute > CRYPT_DEVINFO_FIRST && \
				attribute < CRYPT_DEVINFO_LAST )
				return( &deviceACL[ attribute - CRYPT_DEVINFO_FIRST - 1 ] );
			if( attribute > CRYPT_ENVINFO_FIRST && \
				attribute < CRYPT_ENVINFO_LAST )
				return( &envelopeACL[ attribute - CRYPT_ENVINFO_FIRST - 1 ] );
			if( attribute > CRYPT_SESSINFO_FIRST && \
				attribute < CRYPT_SESSINFO_LAST )
				return( &sessionACL[ attribute - CRYPT_SESSINFO_FIRST - 1 ] );

			/* If it's an external message then the internal attributes don't exist */
			if( isInternalMessage && \
				attribute > CRYPT_IATTRIBUTE_FIRST && \
				attribute < CRYPT_IATTRIBUTE_LAST )
				return( &internalACL[ attribute - CRYPT_IATTRIBUTE_FIRST - 1 ] );
			}
		}

	return( NULL );
	}

/****************************************************************************
*																			*
*									Message Routing							*
*																			*
****************************************************************************/

/* Find the ultimate target of an object attribute manipulation message by
   walking down the chain of controlling->dependent objects.  This routes 
   messages to objects as follows:

		  |			Object
	Target|	CTX		CRT		DEV		ENV
	------+----------------------------
	CTX	  |	 x		obj		 -		obj
	CRT	  |	obj		 x		 -		obj
	DEV	  |	dev		obj		 x		obj
	ENV	  |	 -		 -		 -		 x

   This means that a message targeted at a device and send to a certificate
   will be routed to the certs dependent object (which would typically be a
   context).  The device message targeted at the context would be routed to
   the context's dependent device, which is it's final destination */

static int findTargetType( const int originalObjectHandle, const int targets )
	{
	const OBJECT_TYPE target = targets & 0xFF;
	const OBJECT_TYPE altTarget = targets >> 8;
	int objectHandle = originalObjectHandle;
	int iterations = 0;

	/* Preconditions */
	PRE( isValidObject( objectHandle ) );
	PRE( isValidType( target ) );
	PRE( altTarget == OBJECT_TYPE_NONE || isValidType( altTarget ) );

	/* Route the request through any dependent objects as required until we
	   reach the required target object type.  "And thou shalt make 
	   loops..." -- Exodus 24:6 */
	while( objectHandle != CRYPT_ERROR && \
		   objectTable[ objectHandle ].type != target )
		{
		/* Loop invariants.  "Fifty loops thou shalt make" -- Exodus 24:7 
		   (some of the OT verses shouldn't be taken too literally, 
		   apparently the 50 used here merely means "many" as in "more than 
		   one or two" in the same way that "40 days and nights" is now
		   generally taken as meaning "Lots, but that's as far as we're
		   prepared to count") */
		INV( isValidObject( objectHandle ) );
		INV( iterations++ < 5 );

		/* Try sending the message to the primary target */
		if( target == OBJECT_TYPE_DEVICE && \
			objectTable[ objectHandle ].dependentDevice != CRYPT_ERROR )
			objectHandle = objectTable[ objectHandle ].dependentDevice;
		else
			objectHandle = objectTable[ objectHandle ].dependentObject;

		/* If there's no match for the primary target, try matching the 
		   secondary one */
		if( objectHandle == CRYPT_ERROR && altTarget != OBJECT_TYPE_NONE )
			if( altTarget == OBJECT_TYPE_DEVICE && \
				objectTable[ objectHandle ].dependentDevice != CRYPT_ERROR )
				objectHandle = objectTable[ objectHandle ].dependentDevice;
			else
				objectHandle = objectTable[ objectHandle ].dependentObject;
		}

	/* Postcondition */
	POST( objectHandle == CRYPT_ERROR || isValidObject( objectHandle ) );
	
	return( ( objectHandle == CRYPT_ERROR ) ? \
			CRYPT_ARGERROR_OBJECT : objectHandle );
	}

static int findCompareMessageTarget( const int originalObjectHandle, 
									 const int messageValue )
	{
	OBJECT_TYPE targetType = OBJECT_TYPE_NONE;
	int objectHandle = originalObjectHandle;

	/* Preconditions */
	PRE( isValidObject( objectHandle ) );
	PRE( messageValue == RESOURCE_MESSAGE_COMPARE_HASH || \
		 messageValue == RESOURCE_MESSAGE_COMPARE_KEYID || \
		 messageValue == RESOURCE_MESSAGE_COMPARE_ISSUERANDSERIALNUMBER || \
		 messageValue == RESOURCE_MESSAGE_COMPARE_FINGERPRINT );

	/* Determine the ultimate target type for the message.  We don't check for
	   keysets, envelopes and sessions as dependent objects since this never 
	   occurs */
	switch( messageValue )
		{
		case RESOURCE_MESSAGE_COMPARE_HASH:
		case RESOURCE_MESSAGE_COMPARE_KEYID:
			targetType = OBJECT_TYPE_CONTEXT;
			break;

		case RESOURCE_MESSAGE_COMPARE_ISSUERANDSERIALNUMBER:
		case RESOURCE_MESSAGE_COMPARE_FINGERPRINT:
			targetType = OBJECT_TYPE_CERTIFICATE;
			break;

		default:
			assert( NOTREACHED );
		}

	/* Route the message through to the appropriate object */
	objectHandle = findTargetType( objectHandle, targetType );

	/* Postcondition */
	POST( objectHandle == CRYPT_ARGERROR_OBJECT || \
		  isValidObject( objectHandle ) );

	return( objectHandle );
	}

/* Sometimes a message is explicitly non-routable (ie it has to be sent
   directly to the appropriate target object).  The following function checks
   that the target object is one of the required types */

static int checkTargetType( const int objectHandle, const int targets )
	{
	const OBJECT_TYPE target = targets & 0xFF;
	const OBJECT_TYPE altTarget = targets >> 8;

	/* Precondition */
	PRE( isValidObject( objectHandle ) );
	PRE( isValidType( target ) );
	PRE( altTarget == OBJECT_TYPE_NONE || isValidType( altTarget ) );

	/* Check whether the object matches the required type.  We don't have to
	   check whether the alternative target has a value or not since the
	   object can never be a OBJECT_TYPE_NONE */
	if( objectTable[ objectHandle ].type != target && \
		objectTable[ objectHandle ].type != altTarget )
		return( CRYPT_ERROR );

	/* Postcondition */
	POST( objectTable[ objectHandle ].type == target || \
		  objectTable[ objectHandle ].type == altTarget );

	return( objectHandle );
	}

/****************************************************************************
*																			*
*							Message Pre-dispatch Handlers					*
*																			*
****************************************************************************/

/* If it's a destroy object message, adjust the reference counts of any 
   dependent objects and set the objects state to signalled.  We have to do 
   this before we send the destroy message to the object in order that any 
   further attempts to access it will fail.  This avoids a race condition 
   where other threads may try to use the partially-destroyed object after 
   the object handler unlocks it but before it and the kernel finish 
   destroying it */

static int preDispatchSignalDependentObjects( const int objectHandle,
											  const RESOURCE_MESSAGE_TYPE message, 
											  const void *messageDataPtr,
											  const int messageValue,
											  const void *auxInfo )
	{
	OBJECT_INFO *objectInfoPtr = &objectTable[ objectHandle ];

	/* Precondition */
	PRE( isValidObject( objectHandle ) );

	if( objectInfoPtr->dependentDevice != CRYPT_ERROR )
		decRefCount( objectInfoPtr->dependentDevice, 0, NULL );
	if( objectInfoPtr->dependentObject != CRYPT_ERROR )
		decRefCount( objectInfoPtr->dependentObject, 0, NULL );
	objectInfoPtr->flags |= OBJECT_FLAG_SIGNALLED;

	/* Postcondition */
	POST( objectInfoPtr->flags & OBJECT_FLAG_SIGNALLED );

	return( CRYPT_OK );
	}

/* If it's an attribute get/set/delete, check the access conditions for the 
   object and the message parameters */

static int preDispatchCheckAttributeAccess( const int objectHandle,
											const RESOURCE_MESSAGE_TYPE message, 
											const void *messageDataPtr,
											const int messageValue, 
											const void *auxInfo )
	{
	static const OBJECT_INFO optionObjectInfo = \
							{ OBJECT_TYPE_NONE + 1, NULL, 0, 0, ST_ANY };
	const ATTRIBUTE_ACL *attributeACL = ( ATTRIBUTE_ACL * ) auxInfo;
	const OBJECT_INFO *objectInfo = ( objectHandle == CRYPT_UNUSED ) ? \
							&optionObjectInfo : &objectTable[ objectHandle ];
	const RESOURCE_MESSAGE_TYPE localMessage = message & RESOURCE_MESSAGE_MASK;
	const int isHigh = ( objectInfo->flags & OBJECT_FLAG_HIGH ) ? TRUE : FALSE;
	int requiredAccess = \
		isIncomingAttributeMessage( localMessage ) ? \
			( ( isHigh ) ? ACCESS_FLAG_H_W : ACCESS_FLAG_W ) : \
		isOutgoingAttributeMessage( localMessage ) ? \
			( ( isHigh ) ? ACCESS_FLAG_H_R : ACCESS_FLAG_R ) : \
			( ( isHigh ) ? ACCESS_FLAG_H_D : ACCESS_FLAG_D );
	const BOOLEAN isInternalMessage = \
			( message & RESOURCE_MESSAGE_INTERNAL ) ? TRUE : FALSE;
	const RESOURCE_DATA *msgData = messageDataPtr;
	const int *valuePtr = messageDataPtr;

	/* Preconditions */
	PRE( isValidType( objectInfo->type ) );
	PRE( isAttributeMessage( localMessage ) );
	PRE( isAttribute( messageValue ) || isInternalAttribute( messageValue ) );
	PRE( localMessage == RESOURCE_MESSAGE_DELETEATTRIBUTE || \
		 messageDataPtr != NULL );
	PRE( attributeACL != NULL && attributeACL->attribute == messageValue );

	/* If it's an internal message, use the internal access permssions */
	if( isInternalMessage )
		requiredAccess = MK_ACCESS_INTERNAL( requiredAccess );

	/* Make sure that the attribute is valid for this object subtype */
	if( !( attributeACL->objectSubType & objectInfo->subType ) )
		return( CRYPT_ARGERROR_VALUE );

	/* Make sure this type of access is valid for this attribute */
	if( !( attributeACL->access & requiredAccess ) )
		{
		/* If it's an internal-only attribute being accessed through an 
		   external message, it isn't visible to the user so we return
		   an attribute value error */
		if( !( attributeACL->access & ACCESS_MASK_EXTERNAL ) && \
			!isInternalMessage )
			return( CRYPT_ARGERROR_VALUE );

		/* It is visible, return a standard permission error */
		return( CRYPT_ERROR_PERMISSION );
		}

	/* Inner precondition: The attribute is externally visible or it's an 
	   internal message, this type of access is allowed */
	PRE( ( attributeACL->access & ACCESS_MASK_EXTERNAL ) || isInternalMessage );
	PRE( attributeACL->access & requiredAccess );

	/* If it's a delete attribute message, there's no attribute data being
	   communicated */
	if( localMessage == RESOURCE_MESSAGE_DELETEATTRIBUTE )
		{
		assert( messageDataPtr == NULL );
		return( CRYPT_OK );
		}

	/* Make sure the attribute type matches the supplied value type.  This is
	   a general type check which checks that the caller has used the correct
	   message type rather than a check of the message data itself */
	switch( attributeACL->valueType )
		{
		case VALUE_BOOLEAN:
		case VALUE_NUMERIC:
			/* Inner precondition: If it's an internal message, it must be
			   a numeric value.  We assert this before the general check to
			   ensure we throw an exception rather than just returning an 
			   error code */
			PRE( !isInternalMessage || \
				 localMessage == RESOURCE_MESSAGE_GETATTRIBUTE || \
				 localMessage == RESOURCE_MESSAGE_SETATTRIBUTE );

			/* Must be a numeric value */
			if( localMessage == RESOURCE_MESSAGE_GETATTRIBUTE_S || \
				localMessage == RESOURCE_MESSAGE_SETATTRIBUTE_S )
				return( CRYPT_ARGERROR_VALUE );
			break;

		case VALUE_OBJECT:
			/* Inner precondition: If it's an internal message, it must be
			   a numeric value.  We assert this before the general check to
			   ensure we throw an exception rather than just returning an 
			   error code */
			PRE( !isInternalMessage || \
				 localMessage == RESOURCE_MESSAGE_GETATTRIBUTE || \
				 localMessage == RESOURCE_MESSAGE_SETATTRIBUTE );

			/* Must be a numeric value */
			if( localMessage == RESOURCE_MESSAGE_GETATTRIBUTE_S || \
				localMessage == RESOURCE_MESSAGE_SETATTRIBUTE_S )
				return( CRYPT_ARGERROR_VALUE );

			/* If we're sending the data back to the caller, we can't check
			   it yet */
			if( localMessage == RESOURCE_MESSAGE_GETATTRIBUTE )
				break;

			/* Inner precondition: We're sending data to the object */
			PRE( localMessage == RESOURCE_MESSAGE_SETATTRIBUTE );

			/* Must contain a valid object handle */
			if( !isValidObject( *valuePtr ) )
				return( CRYPT_ARGERROR_NUM1 );
			if( !isInternalMessage && ( isInternalObject( *valuePtr ) || \
				!checkObjectOwnership( objectTable[ *valuePtr ] ) ) )
				return( CRYPT_ARGERROR_NUM1 );
			break;

		case VALUE_STRING:
			/* Inner precondition: If it's an internal message, it must be
			   a valid string value or a null value if we're obtaining a 
			   length (some internal data can be arbitrarily large so we 
			   don't check its length).  We assert this before the general 
			   check to ensure we throw an exception rather than just 
			   returning an error code */
			PRE( !isInternalMessage || \
				 ( ( localMessage == RESOURCE_MESSAGE_GETATTRIBUTE_S || \
					 localMessage == RESOURCE_MESSAGE_SETATTRIBUTE_S ) && \
				   ( ( localMessage == RESOURCE_MESSAGE_GETATTRIBUTE_S && \
					   msgData->data == NULL && msgData->length == 0 ) || \
					 ( msgData->data != NULL && msgData->length >= 1 && \
					   ( msgData->length < 16384 || \
					     messageValue == CRYPT_IATTRIBUTE_CERTSET || \
						 messageValue == CRYPT_IATTRIBUTE_ENC_CERT || \
						 messageValue == CRYPT_IATTRIBUTE_ENC_CERTCHAIN || \
						 messageValue == CRYPT_IATTRIBUTE_TEXT_CERT || \
						 messageValue == CRYPT_IATTRIBUTE_TEXT_CERTCHAIN || \
						 messageValue == CRYPT_IATTRIBUTE_RANDOM || \
						 messageValue == CRYPT_IATTRIBUTE_CONFIGDATA ) ) ) ) );

			/* Must be a string value */
			if( localMessage == RESOURCE_MESSAGE_GETATTRIBUTE || \
				localMessage == RESOURCE_MESSAGE_SETATTRIBUTE )
				return( CRYPT_ARGERROR_VALUE );

			/* If we're sending the data back to the caller, we can't check
			   it yet */
			if( localMessage == RESOURCE_MESSAGE_GETATTRIBUTE_S )
				break;

			/* Inner precondition: We're sending data to the object */
			PRE( localMessage == RESOURCE_MESSAGE_SETATTRIBUTE_S );

			break;

		case VALUE_TIME:
			/* Inner precondition: If it's an internal message, it must be
			   a string value corresponding to a time_t.  We assert this 
			   before the general check to ensure we throw an exception 
			   rather than just returning an error code */
			PRE( !isInternalMessage || \
				 ( ( localMessage == RESOURCE_MESSAGE_GETATTRIBUTE_S || \
					 localMessage == RESOURCE_MESSAGE_SETATTRIBUTE_S ) && \
				   msgData->data != NULL && \
				   msgData->length == sizeof( time_t ) ) );

			/* Must be a string value */
			if( localMessage == RESOURCE_MESSAGE_GETATTRIBUTE || \
				localMessage == RESOURCE_MESSAGE_SETATTRIBUTE )
				return( CRYPT_ARGERROR_VALUE );

			/* If we're sending the data back to the caller, we can't check
			   it yet */
			if( localMessage == RESOURCE_MESSAGE_GETATTRIBUTE_S )
				break;

			/* Inner precondition: We're sending data to the object */
			PRE( localMessage == RESOURCE_MESSAGE_SETATTRIBUTE_S );

			/* Must contain a time_t in a sensible range (the time value is
			   1993, the start date for X.509v2 (this is more of a 
			   consistency check than a real requirement)) */
			if( *( ( time_t * ) msgData->data ) < 0x2B3C0000L )
				return( CRYPT_ARGERROR_STR1 );
			if( msgData->length != sizeof( time_t ) )
				return( CRYPT_ARGERROR_NUM1 );
			break;

		default:
			assert( NOTREACHED );
		}

#if 0	/* Subrange check */
	ATTRIBUTE_ACL *subrangePtr;

	while( subrangePtr->lowRange != RANGE_EXT_MARKER )
		if( subrangePtr->lowRange < value && \
			subrangePtr->highRange > value )
			return( CRYPT_OK );
	return( CRYPT_ERROR );
#endif /* 0 */

	return( CRYPT_OK );
	}

/* It's a context action message, check the access conditions for the object */

static int preDispatchCheckActionAccess( const int objectHandle,
										 const RESOURCE_MESSAGE_TYPE message, 
										 const void *messageDataPtr,
										 const int messageValue, 
										 const void *dummy )
	{
	const OBJECT_INFO *objectInfoPtr = &objectTable[ objectHandle ];
	const RESOURCE_MESSAGE_TYPE localMessage = message & RESOURCE_MESSAGE_MASK;
	int requiredLevel, actualLevel;

	PRE( isValidObject( objectHandle ) );
	PRE( isActionMessage( localMessage ) );

	/* If the object is in the low state, it can't be used for any action */
	if( !isInHighState( objectHandle ) )
		return( CRYPT_ERROR_NOTINITED );

	/* If the object is in the high state, it can't receive another message 
	   of the kind which causes the state change */
	if( localMessage == RESOURCE_MESSAGE_CTX_GENKEY )
		return( CRYPT_ERROR_INITED );

	/* If there's a usage count set for the object and it's gone to zero, it 
	   can't be used any more */
	if( objectInfoPtr->usageCount != CRYPT_UNUSED && \
		objectInfoPtr->usageCount <= 0 )
		return( CRYPT_ERROR_PERMISSION );

	/* Determine the required level for access.  Like protection rings, the
	   lower the value, the higher the privilege level.  Level 3 is all-access,
	   level 2 is internal-access only, level 1 is no access, and level 0 is
	   not-available (eg encryption for hash contexts) */
	requiredLevel = \
		objectInfoPtr->actionFlags & MK_ACTION_PERM( localMessage, ACTION_PERM_MASK );

	/* Make sure the action is enabled at the required level */
	if( message & RESOURCE_MESSAGE_INTERNAL )
		/* It's an internal message, the minimal permissions will do */
		actualLevel = MK_ACTION_PERM( localMessage, ACTION_PERM_NONE_EXTERNAL );
	else
		/* It's an external message, we need full permissions for access */
		actualLevel = MK_ACTION_PERM( localMessage, ACTION_PERM_ALL );
	if( requiredLevel < actualLevel )
		{
		/* The required level is less than the actual level (eg level 2 
		   access attempted from level 3), return more detailed information 
		   about the problem */
		return( ( ( requiredLevel >> ACTION_PERM_SHIFT( localMessage ) ) == ACTION_PERM_NONE ) ? \
				CRYPT_ERROR_NOTAVAIL : CRYPT_ERROR_PERMISSION );
		}

	/* Postcondition */
	POST( localMessage != RESOURCE_MESSAGE_CTX_GENKEY );
	POST( isInHighState( objectHandle ) );
	POST( objectInfoPtr->usageCount == CRYPT_UNUSED || \
		  objectInfoPtr->usageCount > 0 );
	POST( requiredLevel >= actualLevel );

	return( CRYPT_OK );
	}

/* It's a mechanism action message, check the access conditions for the mechanism
   objects */

static int preDispatchCheckMechanismWrapAccess( const int objectHandle,
												const RESOURCE_MESSAGE_TYPE message, 
												const void *messageDataPtr,
												const int messageValue, 
												const void *dummy )
	{
	const RESOURCE_MESSAGE_TYPE localMessage = message & RESOURCE_MESSAGE_MASK;
	const MECHANISM_WRAP_INFO *mechanismInfo = \
		( MECHANISM_WRAP_INFO * ) messageDataPtr;

	/* Precondition */
	PRE( isValidObject( objectHandle ) );
	PRE( localMessage == RESOURCE_MESSAGE_DEV_EXPORT || \
		 localMessage == RESOURCE_MESSAGE_DEV_IMPORT );
	PRE( messageDataPtr != NULL );
	PRE( messageValue == MECHANISM_PKCS1 || \
		 messageValue == MECHANISM_CMS || \
		 messageValue == MECHANISM_KEA || \
		 messageValue == MECHANISM_PRIVATEKEYWRAP );

	/* Mechanism checking in the kernel hasn't been implemented in order to 
	   get the 3.0 beta out before the end of the millenium, these checks are
	   currently all performed in lib_sign.c and lib_keyx.c where the 
	   mechanisms are invoked */
	switch( messageValue )
		{
		case MECHANISM_PKCS1:
			break;

		case MECHANISM_CMS:
			break;

		case MECHANISM_KEA:
			break;

		case MECHANISM_PRIVATEKEYWRAP:
			/* Wrap context must be internal */
			break;

		default:
			assert( NOTREACHED );
		}

	return( CRYPT_OK );
	}

static int preDispatchCheckMechanismSignAccess( const int objectHandle,
												const RESOURCE_MESSAGE_TYPE message, 
												const void *messageDataPtr,
												const int messageValue, 
												const void *dummy )
	{
	const RESOURCE_MESSAGE_TYPE localMessage = message & RESOURCE_MESSAGE_MASK;
	const MECHANISM_SIGN_INFO *mechanismInfo = \
		( MECHANISM_SIGN_INFO * ) messageDataPtr;

	/* Precondition */
	PRE( isValidObject( objectHandle ) );
	PRE( localMessage == RESOURCE_MESSAGE_DEV_SIGN || \
		 localMessage == RESOURCE_MESSAGE_DEV_SIGCHECK );
	PRE( messageDataPtr != NULL );
	PRE( messageValue == MECHANISM_PKCS1 );

	/* Mechanism checking in the kernel hasn't been implemented in order to 
	   get the 3.0 beta out before the end of the millenium, these checks are
	   currently all performed in lib_sign.c and lib_keyx.c where the 
	   mechanisms are invoked */
	switch( messageValue )
		{
		case MECHANISM_PKCS1:
			break;

		default:
			assert( NOTREACHED );
		}

	return( CRYPT_OK );
	}

static int preDispatchCheckMechanismDeriveAccess( const int objectHandle,
												  const RESOURCE_MESSAGE_TYPE message, 
												  const void *messageDataPtr,
												  const int messageValue, 
												  const void *dummy )
	{
	const RESOURCE_MESSAGE_TYPE localMessage = message & RESOURCE_MESSAGE_MASK;
	const MECHANISM_DERIVE_INFO *mechanismInfo = \
		( MECHANISM_DERIVE_INFO * ) messageDataPtr;

	/* Precondition */
	PRE( isValidObject( objectHandle ) );
	PRE( localMessage == RESOURCE_MESSAGE_DEV_DERIVE );
	PRE( messageDataPtr != NULL );
	PRE( messageValue == MECHANISM_PKCS5 || \
		 messageValue == MECHANISM_SSL || \
		 messageValue == MECHANISM_TLS );

	/* Mechanism checking in the kernel hasn't been implemented in order to 
	   get the 3.0 beta out before the end of the millenium, these checks are
	   currently all performed in lib_sign.c and lib_keyx.c where the 
	   mechanisms are invoked */
	switch( messageValue )
		{
		case MECHANISM_PKCS5:
			break;

		case MECHANISM_SSL:
			break;

		case MECHANISM_TLS:
			break;

		default:
			assert( NOTREACHED );
		}

	return( CRYPT_OK );
	}

/* If it's a state change trigger message, make sure that the object isn't
   already in the high state */

static int preDispatchCheckState( const int objectHandle,
								  const RESOURCE_MESSAGE_TYPE message, 
								  const void *messageDataPtr,
								  const int messageValue, const void *dummy )
	{
	/* Precondition */
	PRE( isValidObject( objectHandle ) );

	if( isInHighState( objectHandle ) )
		return( CRYPT_ERROR_PERMISSION );

	/* Postcondition */
	POST( !isInHighState( objectHandle ) );

	return( CRYPT_OK );
	}

/* Check the access conditions for a message containing a handle or optional 
   handle as the message parameter */

static int preDispatchCheckParamHandle( const int objectHandle,
										const RESOURCE_MESSAGE_TYPE message,
										const void *messageDataPtr,
										const int messageValue, const void *dummy )
	{
	const BOOLEAN isInternalMessage = \
			( message & RESOURCE_MESSAGE_INTERNAL ) ? TRUE : FALSE;

	/* Make sure the sig.check object is valid and accessible */
	if( !isValidObject( messageValue ) )
		return( CRYPT_ARGERROR_NUM1 );
	if( !isInternalMessage && ( isInternalObject( messageValue ) || \
		!checkObjectOwnership( objectTable[ messageValue ] ) ) )
		return( CRYPT_ARGERROR_NUM1 );

	return( CRYPT_OK );
	}

static int preDispatchCheckParamHandleOpt( const int objectHandle,
										   const RESOURCE_MESSAGE_TYPE message,
										   const void *messageDataPtr,
										   const int messageValue, 
										   const void *dummy )
	{
	const BOOLEAN isInternalMessage = \
			( message & RESOURCE_MESSAGE_INTERNAL ) ? TRUE : FALSE;

	/* If the handle is CRYPT_UNUSED, we're OK */
	if( messageValue == CRYPT_UNUSED )
		return( CRYPT_OK );

	/* Make sure the object is valid and accessible */
	if( !isValidObject( messageValue ) )
		return( CRYPT_ARGERROR_NUM1 );
	if( !isInternalMessage && ( isInternalObject( messageValue ) || \
		!checkObjectOwnership( objectTable[ messageValue ] ) ) )
		return( CRYPT_ARGERROR_NUM1 );

	return( CRYPT_OK );
	}

/* Perform a combined check of the object and the handle */

static int preDispatchCheckStateParamHandle( const int objectHandle,
											 const RESOURCE_MESSAGE_TYPE message,
										 	 const void *messageDataPtr,
											 const int messageValue, 
											 const void *dummy )
	{
	const BOOLEAN isInternalMessage = \
			( message & RESOURCE_MESSAGE_INTERNAL ) ? TRUE : FALSE;

	/* Precondition */
	PRE( isValidObject( objectHandle ) );

	if( isInHighState( objectHandle ) )
		return( CRYPT_ERROR_PERMISSION );

	/* Make sure the sig.check object is valid and accessible */
	if( !isValidObject( messageValue ) )
		return( CRYPT_ARGERROR_NUM1 );
	if( !isInternalMessage && ( isInternalObject( messageValue ) || \
		!checkObjectOwnership( objectTable[ messageValue ] ) ) )
		return( CRYPT_ARGERROR_NUM1 );

	/* Postcondition */
	POST( !isInHighState( objectHandle ) );
	POST( isValidObject( messageValue ) );

	return( CRYPT_OK );
	}

/* It's data being pushed or popped, make sure it's a valid data quantity */

static int preDispatchCheckData( const int objectHandle,
								 const RESOURCE_MESSAGE_TYPE message,
								 const void *messageDataPtr,
								 const int messageValue, 
								 const void *dummy )
	{
	const RESOURCE_DATA *msgData = messageDataPtr;

	/* Precondition */
	PRE( isValidObject( objectHandle ) );
	PRE( messageDataPtr != NULL );
	PRE( messageValue == 0 );

	/* Make sure it's either a flush (buffer = NULL, length = 0) 
	   or valid data */
	if( msgData->data == NULL )
		{
		if( message != RESOURCE_MESSAGE_ENV_PUSHDATA || \
			msgData->length != 0 )
			return( CRYPT_ARGERROR_STR1 );
		}
	else
		if( msgData->length <= 0 )
			return( CRYPT_ARGERROR_STR1 );

	/* Postcondition */
	POST( ( message == RESOURCE_MESSAGE_ENV_PUSHDATA && \
			msgData->data == NULL && msgData->length == 0 ) || \
		  ( msgData->data != NULL && msgData->length > 0 ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Message Post-Dispatch Handlers					*
*																			*
****************************************************************************/

/* If there's a dependent object with a given relationship to the controlling 
   object, forward the message.  In practice the only dependencies are those
   of PKC contexts paired with certs, for which a message sent to one (eg a
   check message such as "is this suitable for signing?") needs to be 
   forwarded to the other */

static int postDispatchForwardToDependentObject( const int objectHandle,
												 const RESOURCE_MESSAGE_TYPE message,
												 const int messageValue,
												 const void *auxInfo )
	{
	const RESOURCE_MESSAGE_TYPE localMessage = message & RESOURCE_MESSAGE_MASK;
	const OBJECT_INFO *objectInfoPtr = &objectTable[ objectHandle ];
	const int dependentObject = objectInfoPtr->dependentObject;
	const OBJECT_TYPE objectType = objectTable[ objectHandle ].type;
	const OBJECT_TYPE dependentType = ( dependentObject != CRYPT_ERROR ) ? \
							objectTable[ dependentObject ].type : CRYPT_ERROR;
	int status;

	/* Precondition */
	PRE( isValidObject( objectHandle ) );
	PRE( localMessage == RESOURCE_MESSAGE_CHECK || \
		 localMessage == RESOURCE_MESSAGE_LOCK || \
		 localMessage == RESOURCE_MESSAGE_UNLOCK );
	PRE( isValidObject( dependentObject ) || dependentObject == CRYPT_ERROR );

	/* If there's no relationship between the objects, don't do anything */
	if( !( objectType == OBJECT_TYPE_CONTEXT && \
		   dependentType == OBJECT_TYPE_CERTIFICATE ) && \
		!( objectType == OBJECT_TYPE_CERTIFICATE && \
		   dependentType == OBJECT_TYPE_CONTEXT ) )
		return( CRYPT_OK );

	/* Postcondition */
	POST( isValidObject( dependentObject ) );

	/* Forward the message to the dependent object.  We have to make the 
	   message internal since the dependent objects may be internal-only */
	unlockGlobalResource( objectTable );
	if( localMessage == RESOURCE_MESSAGE_CHECK )
		{
		/* Inner precondition: It's a valid check message */
		PRE( localMessage == RESOURCE_MESSAGE_CHECK );
		PRE( messageValue > RESOURCE_MESSAGE_CHECK_NONE && \
			 messageValue < RESOURCE_MESSAGE_CHECK_LAST );

		status = krnlSendMessage( dependentObject, RESOURCE_IMESSAGE_CHECK, 
								  NULL, messageValue );
		}
	else
		{
		/* Inner precondition: It's an object lock or unlock message */
		PRE( localMessage == RESOURCE_MESSAGE_LOCK || \
			 localMessage == RESOURCE_MESSAGE_UNLOCK );

		status = krnlSendNotifier( dependentObject, 
									MKINTERNAL( localMessage ) );
		}
	lockGlobalResource( objectTable );
	return( status );
	}

/* Some objects can only perform given number of actions before they self-
   destruct, if there's a usage count set we update it */

static int postDispatchUpdateUsageCount( const int objectHandle,
										 const RESOURCE_MESSAGE_TYPE message, 
										 const int messageValue,
										 const void *auxInfo )
	{
	OBJECT_INFO *objectInfoPtr = &objectTable[ objectHandle ];

	/* Precondition */
	PRE( isValidObject( objectHandle ) && \
		 objectInfoPtr->type == OBJECT_TYPE_CONTEXT );
	PRE( objectInfoPtr->usageCount == CRYPT_UNUSED || \
		 objectInfoPtr->usageCount > 0 );

	/* If there's an active usage count present, update it */
	if( objectInfoPtr->usageCount != CRYPT_UNUSED )
		objectInfoPtr->usageCount--;
	
	/* Postcondition */
	POST( objectInfoPtr->usageCount == CRYPT_UNUSED || \
		  objectInfoPtr->usageCount >= 0 );
	return( CRYPT_OK );
	}

/* Certain messages can trigger changes in the object state from the low to 
   the high security level.  These changes are enforced by the kernel and 
   can't be bypassed or controlled by the object itself.  Once one of these 
   messages is successfully processed, we change the objects state so that 
   further accesses are handled by the kernel based on the new state 
   established by the message being processed successfully.  Since the object 
   is still marked as busy at this stage, other messages arriving before the 
   following state change can't bypass the kernel checks since they won't be 
   processed until the object is marked as non-busy later on */

static int postDispatchChangeState( const int objectHandle,
									const RESOURCE_MESSAGE_TYPE message, 
									const int messageValue,
									const void *auxInfo )
	{
	/* Precondition */
	PRE( isValidObject( objectHandle ) );
	PRE( !isInHighState( objectHandle ) );

	/* The state change message was successfully processed, the object is now 
	   in the high state */
	objectTable[ objectHandle ].flags |= OBJECT_FLAG_HIGH;
	
	/* Postcondition */
	POST( isInHighState( objectHandle ) );
	return( CRYPT_OK );
	}

static int postDispatchChangeStateOpt( const int objectHandle,
									   const RESOURCE_MESSAGE_TYPE message, 
									   const int messageValue,
									   const void *auxInfo )
	{
	const ATTRIBUTE_ACL *attributeACL = ( ATTRIBUTE_ACL * ) auxInfo;

	/* Precondition */
	PRE( isValidObject( objectHandle ) );

	/* If it's an attribute which triggers a state, change the state */
	if( attributeACL->flags & ATTRIBUTE_FLAG_TRIGGER )
		{
		/* Inner precondition: We shouldn't already be in the high state */
		PRE( !isInHighState( objectHandle ) );

		objectTable[ objectHandle ].flags |= OBJECT_FLAG_HIGH;
		}

	/* Postcondition */
	POST( !( attributeACL->flags & ATTRIBUTE_FLAG_TRIGGER ) || \
		  isInHighState( objectHandle ) );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Message Dispatching							*
*																			*
****************************************************************************/

/* Each message type has certain properties such as whether it's routable,
   which object types it applies to, what checks are performed on it, whether
   it's processed by the kernel or dispatched to an object, etc etc.  These
   are all defined in the following table.

   In addition to the usual checks, we also make various assertions about the
   parameters we're passed.  Note that these don't check user data (that's
   checked programmatically and an error code returned) but values passed by
   cryptlib code */

typedef enum {
	PARAMTYPE_NONE_NONE,	/* Data = 0, value = 0 */
	PARAMTYPE_NONE_ANY,		/* Data = 0, value = any */
	PARAMTYPE_NONE_CHECKTYPE,/* Data = 0, value = check type */
	PARAMTYPE_DATA_NONE,	/* Data, value = 0 */
	PARAMTYPE_DATA_ANY,		/* Data, value = any */
	PARAMTYPE_DATA_BOOLEAN,	/* Data, value = boolean */
	PARAMTYPE_DATA_LENGTH,	/* Data, value >= 0 */
	PARAMTYPE_DATA_OBJTYPE,	/* Data, value = object type */
	PARAMTYPE_DATA_MECHTYPE,/* Data, value = mechanism type */
	PARAMTYPE_DATA_COMPARETYPE/* Data, value = compare type */
	} PARAMCHECK_TYPE;
   
/* Symbolic defines for message handling types, used to make it clearer 
   what's going on

	PRE_DISPATCH	- Action before message is dispatched
	POST_DISPATCH	- Action after message is dispatched
	HANDLE_INTERNAL	- Message handled by the kernel */

#define PRE_DISPATCH( function )	preDispatch##function
#define POST_DISPATCH( function )	NULL, postDispatch##function
#define PRE_POST_DISPATCH( preFunction, postFunction ) \
		preDispatch##preFunction, postDispatch##postFunction
#define HANDLE_INTERNAL( function )	NULL, NULL, function

/* The handling information, declared in the order in which it's applied */

typedef struct MH {
	/* The message type, used for consistency checking */
	const RESOURCE_MESSAGE_TYPE messageType;

	/* Message routing information if the message is routable.  If the target 
	   is implicitly determined via the message value, the routing target is 
	   OBJECT_TYPE_NONE; if the target is explicitly determined, the routing 
	   target is identified in the target.  If the routing function is null, 
	   the message isn't routed */
	const OBJECT_TYPE routingTarget;	/* Target type if routable */
	int ( *routingFunction )( const int objectHandle, const int arg );

	/* Object type checking information: Object subtypes for which this 
	   message is valid (for object-type-specific message) */
	const int objectSubType;			/* Object subtype for which msg.valid */

	/* Message type checking information used to assertion-check the function 
	   preconditions */
	const PARAMCHECK_TYPE paramCheck;	/* Parameter check assertion type */

	/* Pre- and post-message-dispatch handlers.  These perform any additional
	   checking and processing which may be necessary before and after a 
	   message is dispatched to an object */
	int ( *preDispatchFunction )( const int objectHandle, 
								  const RESOURCE_MESSAGE_TYPE message, 
								  const void *messageDataPtr,
								  const int messageValue, const void *auxInfo );
	int ( *postDispatchFunction )( const int objectHandle, 
								   const RESOURCE_MESSAGE_TYPE message,
								   const int messageValue, const void *auxInfo );

	/* Message processing information.  If the internal handler function is 
	   non-null, it's handled by the  kernel */
	int ( *internalHandlerFunction )( const int objectHandle, const int arg1,
									  const void *arg2 );
	} MESSAGE_HANDLING_INFO;

static const MESSAGE_HANDLING_INFO messageHandlingInfo[] = {
	{ RESOURCE_MESSAGE_NONE, ROUTE_NONE, 0, PARAMTYPE_NONE_NONE },

	/* Control messages.  These messages aren't routed, are valid for all 
	   object types and subtypes, take no (or minimal) parameters, and are 
	   handled by the kernel */
	{ RESOURCE_MESSAGE_DESTROY,			/* Destroy the object */
	  ROUTE_NONE, ST_ANY,
	  PARAMTYPE_NONE_NONE,
	  PRE_DISPATCH( SignalDependentObjects ) },
	{ RESOURCE_MESSAGE_INCREFCOUNT,		/* Increment object ref.count */
	  ROUTE_NONE, ST_ANY,
	  PARAMTYPE_NONE_NONE,
	  HANDLE_INTERNAL( incRefCount ) },
	{ RESOURCE_MESSAGE_DECREFCOUNT,		/* Decrement object ref.count */
	  ROUTE_NONE, ST_ANY,
	  PARAMTYPE_NONE_NONE,
	  HANDLE_INTERNAL( decRefCount ) },
	{ RESOURCE_MESSAGE_GETDEPENDENT,	/* Get dependent object */
	  ROUTE_NONE, ST_ANY,
	  PARAMTYPE_DATA_OBJTYPE,
	  HANDLE_INTERNAL( getDependentObject ) },
	{ RESOURCE_MESSAGE_SETDEPENDENT,	/* Set dependent object (eg ctx->dev) */
	  ROUTE_NONE, ST_ANY,
	  PARAMTYPE_DATA_BOOLEAN,
	  HANDLE_INTERNAL( setDependentObject ) },

	/* Attribute messages.  These messages are implicitly routed by attribute
	   type, more specific checking is performed using the attribute ACL's */
	{ RESOURCE_MESSAGE_GETATTRIBUTE,	/* Get numeric object attribute */
	  ROUTE_IMPLICIT, ST_ANY,
	  PARAMTYPE_DATA_ANY,
	  PRE_DISPATCH( CheckAttributeAccess ) },
	{ RESOURCE_MESSAGE_GETATTRIBUTE_S,	/* Get string object attribute */
	  ROUTE_IMPLICIT, ST_ANY,
	  PARAMTYPE_DATA_ANY,
	  PRE_DISPATCH( CheckAttributeAccess ) },
	{ RESOURCE_MESSAGE_SETATTRIBUTE,	/* Set numeric object attribute */
	  ROUTE_IMPLICIT, ST_ANY,
	  PARAMTYPE_DATA_ANY,
	  PRE_POST_DISPATCH( CheckAttributeAccess, ChangeStateOpt ) },
	{ RESOURCE_MESSAGE_SETATTRIBUTE_S,	/* Set string object attribute */
	  ROUTE_IMPLICIT, ST_ANY,
	  PARAMTYPE_DATA_ANY,
	  PRE_POST_DISPATCH( CheckAttributeAccess, ChangeStateOpt ) },
	{ RESOURCE_MESSAGE_DELETEATTRIBUTE,	/* Delete object attribute */
	  ROUTE_IMPLICIT, ST_CTX_ANY | ST_CERT_ANY,
	  PARAMTYPE_NONE_ANY, 
	  PRE_DISPATCH( CheckAttributeAccess ) },

	/* General messages to objects */
	{ RESOURCE_MESSAGE_COMPARE,			/* Compare objs.or obj.properties */
	  ROUTE_SPECIAL( findCompareMessageTarget ), ST_CTX_ANY | ST_CERT_ANY,
	  PARAMTYPE_DATA_COMPARETYPE },
	{ RESOURCE_MESSAGE_CLONE,			/* Clone the object.  Only valid for ctx's */
	  ROUTE_FIXED( OBJECT_TYPE_CONTEXT ), ST_CTX_CONV | ST_CTX_HASH,
	  PARAMTYPE_DATA_NONE },			/* for now so we restrict it accordingly */
	{ RESOURCE_MESSAGE_CHECK,			/* Check object info */
	  ROUTE_NONE, ST_ANY,
	  PARAMTYPE_NONE_CHECKTYPE,
	  POST_DISPATCH( ForwardToDependentObject ) },
	{ RESOURCE_MESSAGE_LOCK,			/* Lock object for exclusive use */
	  ROUTE_NONE, ST_ANY,
	  PARAMTYPE_NONE_NONE,
	  POST_DISPATCH( ForwardToDependentObject ) },
	{ RESOURCE_MESSAGE_UNLOCK,			/* Unlock object */
	  ROUTE_NONE, ST_ANY,
	  PARAMTYPE_NONE_NONE,
	  POST_DISPATCH( ForwardToDependentObject ) },

	/* Messages sent from the kernel to object message handlers.  These 
	   messages are sent directly to the object from inside the kernel in
	   response to a control message, so we set the checking to disallow
	   everything to catch any which arrive from outside */
	{ RESOURCE_MESSAGE_CHANGENOTIFY,	/* Notification of obj.status chge.*/
	  ROUTE_NONE, 0, PARAMTYPE_NONE_NONE },

	/* Object-type-specific messages */
	{ RESOURCE_MESSAGE_CTX_ENCRYPT,		/* Context: Action = encrypt */
	  ROUTE( OBJECT_TYPE_CONTEXT ), ST_CTX_CONV | ST_CTX_PKC,
	  PARAMTYPE_DATA_LENGTH, 
	  PRE_POST_DISPATCH( CheckActionAccess, UpdateUsageCount ) },
	{ RESOURCE_MESSAGE_CTX_DECRYPT,		/* Context: Action = decrypt */
	  ROUTE( OBJECT_TYPE_CONTEXT ), ST_CTX_CONV | ST_CTX_PKC,
	  PARAMTYPE_DATA_LENGTH, 
	  PRE_POST_DISPATCH( CheckActionAccess, UpdateUsageCount ) },
	{ RESOURCE_MESSAGE_CTX_SIGN,		/* Context: Action = sign */
	  ROUTE( OBJECT_TYPE_CONTEXT ), ST_CTX_PKC,
	  PARAMTYPE_DATA_LENGTH, 
	  PRE_POST_DISPATCH( CheckActionAccess, UpdateUsageCount ) },
	{ RESOURCE_MESSAGE_CTX_SIGCHECK,	/* Context: Action = sigcheck */
	  ROUTE( OBJECT_TYPE_CONTEXT ), ST_CTX_PKC,
	  PARAMTYPE_DATA_LENGTH, 
	  PRE_POST_DISPATCH( CheckActionAccess, UpdateUsageCount ) },
	{ RESOURCE_MESSAGE_CTX_HASH,		/* Context: Action = hash */
	  ROUTE( OBJECT_TYPE_CONTEXT ), ST_CTX_HASH | ST_CTX_MAC,
	  PARAMTYPE_DATA_LENGTH, 
	  PRE_POST_DISPATCH( CheckActionAccess, UpdateUsageCount ) },
	{ RESOURCE_MESSAGE_CTX_GENKEY,		/* Context: Generate a key */
	  ROUTE( OBJECT_TYPE_CONTEXT ), ST_CTX_CONV | ST_CTX_PKC | ST_CTX_MAC,
	  PARAMTYPE_DATA_BOOLEAN,
	  PRE_POST_DISPATCH( CheckState, ChangeState ) },
	{ RESOURCE_MESSAGE_CTX_GENIV,		/* Context: Generate an IV */
	  ROUTE( OBJECT_TYPE_CONTEXT ), ST_CTX_CONV,
	  PARAMTYPE_NONE_NONE },
	{ RESOURCE_MESSAGE_CRT_SIGN,		/* Cert: Action = sign cert */
	  ROUTE( OBJECT_TYPE_CERTIFICATE ), ST_CERT_ANY_CERT | ST_CERT_CRL,
	  PARAMTYPE_NONE_ANY, 
	  PRE_POST_DISPATCH( CheckStateParamHandle, ChangeState ) },
	{ RESOURCE_MESSAGE_CRT_SIGCHECK,	/* Cert: Action = check/verify cert */
	  ROUTE( OBJECT_TYPE_CERTIFICATE ), ST_CERT_ANY_CERT | ST_CERT_CRL,
	  PARAMTYPE_NONE_ANY, 
	  PRE_DISPATCH( CheckParamHandleOpt ) },
	{ RESOURCE_MESSAGE_DEV_QUERYCAPABILITY,/* Device: Query capability */
	  ROUTE_FIXED( OBJECT_TYPE_DEVICE ), ST_ANY,
	  PARAMTYPE_DATA_ANY },
	{ RESOURCE_MESSAGE_DEV_EXPORT,		/* Device: Action = export key */
	  ROUTE( OBJECT_TYPE_DEVICE ), ST_ANY,
	  PARAMTYPE_DATA_MECHTYPE,
	  PRE_DISPATCH( CheckMechanismWrapAccess ) },
	{ RESOURCE_MESSAGE_DEV_IMPORT,		/* Device: Action = import key */
	  ROUTE( OBJECT_TYPE_DEVICE ), ST_ANY,
	  PARAMTYPE_DATA_MECHTYPE,
	  PRE_DISPATCH( CheckMechanismWrapAccess ) },
	{ RESOURCE_MESSAGE_DEV_SIGN,		/* Device: Action = sign */
	  ROUTE( OBJECT_TYPE_DEVICE ), ST_ANY,
	  PARAMTYPE_DATA_MECHTYPE,
	  PRE_DISPATCH( CheckMechanismSignAccess ) },
	{ RESOURCE_MESSAGE_DEV_SIGCHECK,	/* Device: Action = sig.check */
	  ROUTE( OBJECT_TYPE_DEVICE ), ST_ANY,
	  PARAMTYPE_DATA_MECHTYPE,
	  PRE_DISPATCH( CheckMechanismSignAccess ) },
	{ RESOURCE_MESSAGE_DEV_DERIVE,		/* Device: Action = derive key */
	  ROUTE( OBJECT_TYPE_DEVICE ), ST_ANY,
	  PARAMTYPE_DATA_MECHTYPE,
	  PRE_DISPATCH( CheckMechanismDeriveAccess ) },
	{ RESOURCE_MESSAGE_DEV_CREATEOBJECT,/* Device: Create object */
	  ROUTE_FIXED( OBJECT_TYPE_DEVICE ), ST_ANY,
	  PARAMTYPE_DATA_OBJTYPE },
	{ RESOURCE_MESSAGE_ENV_PUSHDATA,	/* Envelope: Push data */
	  ROUTE_FIXED_ALT( OBJECT_TYPE_ENVELOPE, OBJECT_TYPE_SESSION ), ST_ANY,
	  PARAMTYPE_DATA_NONE,
	  PRE_DISPATCH( CheckData ) },
	{ RESOURCE_MESSAGE_ENV_POPDATA,		/* Envelope: Pop data */
	  ROUTE_FIXED_ALT( OBJECT_TYPE_ENVELOPE, OBJECT_TYPE_SESSION ), ST_ANY,
	  PARAMTYPE_DATA_NONE,
	  PRE_DISPATCH( CheckData ) },
	{ RESOURCE_MESSAGE_KEY_GETKEY,		/* Keyset: Instantiate ctx/cert */
	  ROUTE_FIXED_ALT( OBJECT_TYPE_KEYSET, OBJECT_TYPE_DEVICE ), ST_ANY,
	  PARAMTYPE_DATA_NONE },
	{ RESOURCE_MESSAGE_KEY_SETKEY,		/* Keyset: Add ctx/cert */
	  ROUTE_FIXED_ALT( OBJECT_TYPE_KEYSET, OBJECT_TYPE_DEVICE ), ST_ANY,
	  PARAMTYPE_DATA_ANY, 
	  PRE_DISPATCH( CheckParamHandle ) },
	{ RESOURCE_MESSAGE_KEY_DELETEKEY,	/* Keyset: Delete key */
	  ROUTE_FIXED_ALT( OBJECT_TYPE_KEYSET, OBJECT_TYPE_DEVICE ), ST_ANY,
	  PARAMTYPE_DATA_NONE },
	{ RESOURCE_MESSAGE_KEY_GETNEXTCERT,	/* Keyset: Get certs in cert chain */
	  ROUTE_FIXED_ALT( OBJECT_TYPE_KEYSET, OBJECT_TYPE_DEVICE ), ST_ANY,
	  PARAMTYPE_DATA_NONE }
	};

/* To manage messages sent to objects this we maintain a message queue to 
   ensure that there are no problems if a message sent to an object results 
   in it sending another message to itself.  If a message for a given object 
   is already present in the queue, the new message is appended after the 
   existing one and the function returns immediately.  This ensures that the
   message isn't processed until the earlier message(s) for that object have
   been processed.  If the message is for a different object, it is prepended
   to the queue and processed immediately.  This ensures that messages sent
   by objects to subordinate objects are processed before the messages for
   the objects themselves.  Overall, an object won't be sent a new message
   until the current one has been processed.

   The message processing algorithm is as follows:

	find pos in queue starting from the back;
	insert message at ( pos ) ? pos + 1 : 0;
	if( pos )
		return;
	do
		queue[ 0 ]->function();
		delete queue[ 0 ];
	while( qPos && queue[ 0 ].object == object );

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
   PostMessage() for the same object, so the current object can queue a
   series of events for processing and guarantee execution in the order the
   events are posted.

   In some cases there can be a need to process a message immediately.  In
   this case the caller can set the RESOURCE_MESSAGE_URGENT flag which
   ensures that a change to an objects property takes effect immediately.
   This can be used for example to move an object into the signalled state
   once its internal data is destroyed but before the object itself is
   destroyed, which ensures that any further attempts to access it fail
   rather than trying to use the partially-destroyed object.

   To avoid the bottleneck of a single message queue, we maintain a
   scoreboard of objects which are currently processing messages.  In an
   object isn't busy and the message isn't of a special type such as
   RESOURCE_MESSAGE_DESTROY, we dispatch the message immediately rather than
   queueing it.
   
   In some cases an object (a controlling object) will receive a message 
   which isn't directly intended for it but which is appropriate for a 
   dependent object (for example a "read DN" message sent to a context would 
   be appropriate for an attached certificate object).  Typically the 
   controlling object would forward the message, however this ties up both 
   the controlling and dependent object, and it gets worse with long chains 
   of dependent objects (eg envelope -> context -> device).  To alleviate 
   this problem, the kernel implements a stunt box (in the CDC6600, not the
   TTY, sense) which reroutes messages intended for dependent objects 
   directly to them instead of having the controlling object do this itself.
   This means that instead of:

	msg -> krn
		   krn -> O1
				  O1  -> krn
						 krn -> O2
						 krn <-
				  O1  <-
		   krn <-

   which ties up both objects, the message would be:

    msg -> krn
		   krn => O1		// Get dependent object
		   krn <=
		   krn -> O2
		   krn <-

   which would only tie up one object at a time.  In fact we can do even 
   better than this by storing the handles of dependent objects in the object 
   table, bypassing the intermediate objects entirely.  This has the 
   additional advantage that it won't block if an intermediate object is busy, 
   which requires complex handling in order to resume the forwarding process 
   at a later point.  The resulting message flow is:

	msg -> krn
		   krn -> O2
		   krn <- */

/* A structure to store the details of a message sent to an object */

typedef struct {
	int objectHandle;				/* Handle to send message to */
	const MESSAGE_HANDLING_INFO *handlingInfoPtr;/* Message handling info */
	RESOURCE_MESSAGE_TYPE message;
	const void *messageDataPtr;
	int messageValue;				/* Message parameters */
	} MESSAGE_QUEUE_DATA;

/* The size of the message queue.  This defines the maximum nesting depth of
   messages sent by an object.  Because of the way krnlSendMessage() handles
   message processing, it's extremely difficult to ever have more than two or
   three messages in the queue unless an object starts recursively sending
   itself messages */

#define MESSAGE_QUEUE_SIZE	16

/* Message queue implementation */

static MESSAGE_QUEUE_DATA messageQueue[ MESSAGE_QUEUE_SIZE ];
static int queueEnd = 0;	/* Points past last queue element */

static BOOLEAN enqueueMessage( const int objectHandle, 
							   const MESSAGE_HANDLING_INFO *handlingInfoPtr,
							   const RESOURCE_MESSAGE_TYPE message,
							   const void *messageDataPtr, 
							   const int messageValue )
	{
	int queuePos, i;

	/* Precondition */
	PRE( isValidObject( objectHandle ) );
	PRE( handlingInfoPtr != NULL );
	PRE( isValidMessage( message & RESOURCE_MESSAGE_MASK ) );

	/* Make sure we don't overflow the queue (this cryptlib object is not 
	   responding to messages... now all we need is GPF's) */
	PRE( queueEnd < MESSAGE_QUEUE_SIZE );

	/* Check whether a message to this object is already present in the
	   queue */
	for( queuePos = queueEnd - 1; queuePos >= 0; queuePos-- )
		if( messageQueue[ queuePos ].objectHandle == objectHandle )
			break;

	/* Postcondition: queuePos = -1 if not present, position in queue if 
	   present */
	POST( queuePos == -1 || ( queuePos >= 0 && queuePos < queueEnd ) );

	/* Enqueue the message */
	queuePos++;		/* Insert after current position */
	for( i = queueEnd - 1; i >= queuePos; i-- )
		messageQueue[ i + 1 ] = messageQueue[ i ];
	messageQueue[ queuePos ].objectHandle = objectHandle;
	messageQueue[ queuePos ].handlingInfoPtr = handlingInfoPtr;
	messageQueue[ queuePos ].message = message;
	messageQueue[ queuePos ].messageDataPtr = messageDataPtr;
	messageQueue[ queuePos ].messageValue = messageValue;
	queueEnd++;
	if( queuePos )
		/* A message for this object is already present, tell the caller to 
		   defer processing */
		return( FALSE );

	return( TRUE );
	}

static void dequeueMessage( const int messagePosition )
	{
	int i;

	PRE( messagePosition >= 0 && messagePosition < queueEnd );

	/* Move the remaining messages down and clear the last entry */
	for( i = messagePosition; i < queueEnd - 1; i++ )
		messageQueue[ i ] = messageQueue[ i + 1 ];
	zeroise( &messageQueue[ queueEnd - 1 ], sizeof( MESSAGE_QUEUE_DATA ) );
	queueEnd--;
	}

static void dequeueAllMessages( const int objectHandle )
	{
	int i;

	/* Dequeue all messags for a given object */
	for( i = 0; i < queueEnd; i++ )
		if( messageQueue[ i ].objectHandle == objectHandle )
			{
			dequeueMessage( i );
			i--;	/* Compensate for dequeued message */
			}
	}

static BOOLEAN getNextMessage( const int objectHandle, 
							   MESSAGE_QUEUE_DATA *messageQueueInfo )
	{
	int i;

	/* Find the next message for this object.  Since other messages can have
	   come and gone in the meantime, we have to scan from the start each
	   time */
	for( i = 0; i < queueEnd; i++ )
		if( messageQueue[ i ].objectHandle == objectHandle )
			{
			*messageQueueInfo = messageQueue[ i ];
			dequeueMessage( i );
			return( TRUE );
			}

	return( FALSE );
	}

/* Send a message to an object */

int krnlSendMessage( const int objectHandle,
					 const RESOURCE_MESSAGE_TYPE message,
					 void *messageDataPtr, const int messageValue )
	{
	const ATTRIBUTE_ACL *attributeACL = NULL;
	const MESSAGE_HANDLING_INFO *handlingInfoPtr;
	MESSAGE_QUEUE_DATA enqueuedMessageData;
	const BOOLEAN isInternalMessage = \
			( message & RESOURCE_MESSAGE_INTERNAL ) ? TRUE : FALSE;
	RESOURCE_MESSAGE_TYPE localMessage = message & RESOURCE_MESSAGE_MASK;
	int localObjectHandle = objectHandle, status = CRYPT_OK;

	/* Preconditions.  For external messages we don't provide any assertions 
	   at this point since they're coming straight from the user and could
	   contain any values, and for internal messages we only trap on 
	   programming errors (thus for example isValidHandle() vs 
	   isValidObject(), since this would trap if a message is sent to a
	   destroyed object) */
	PRE( isValidMessage( localMessage ) );
	PRE( !isInternalMessage || isValidHandle( objectHandle ) || \
		 isGlobalOptionMessage( objectHandle, localMessage, messageValue ) );

	/* Get the information we need to handle this message */
	handlingInfoPtr = &messageHandlingInfo[ localMessage ];

	/* Inner preconditions now that we have the handling information: Message
	   parameters must be within the allowed range (again, this traps on
	   programming errors only) */
	PRE( ( handlingInfoPtr->paramCheck == PARAMTYPE_NONE_NONE && \
		   messageDataPtr == NULL && messageValue == 0 ) ||
		 ( handlingInfoPtr->paramCheck == PARAMTYPE_NONE_ANY && \
		   messageDataPtr == NULL ) ||
		 ( handlingInfoPtr->paramCheck == PARAMTYPE_NONE_CHECKTYPE && \
		   messageDataPtr == NULL && \
		   ( messageValue > RESOURCE_MESSAGE_CHECK_NONE && \
			 messageValue < RESOURCE_MESSAGE_CHECK_LAST ) ) ||
		 ( handlingInfoPtr->paramCheck == PARAMTYPE_DATA_NONE && \
		   messageDataPtr != NULL && messageValue == 0 ) ||
		 ( handlingInfoPtr->paramCheck == PARAMTYPE_DATA_ANY && \
		   messageDataPtr != NULL ) ||
		 ( handlingInfoPtr->paramCheck == PARAMTYPE_DATA_BOOLEAN && \
		   messageDataPtr != NULL && \
		   ( messageValue == FALSE || messageValue == TRUE ) ) ||
		 ( handlingInfoPtr->paramCheck == PARAMTYPE_DATA_LENGTH && \
		   messageDataPtr != NULL && messageValue >= 0 ) ||
		 ( handlingInfoPtr->paramCheck == PARAMTYPE_DATA_OBJTYPE && \
		   messageDataPtr != NULL && \
		   ( messageValue > OBJECT_TYPE_NONE && messageValue < OBJECT_TYPE_LAST ) ) ||
		 ( handlingInfoPtr->paramCheck == PARAMTYPE_DATA_MECHTYPE && \
		   messageDataPtr != NULL && \
		   ( messageValue > MECHANISM_NONE && messageValue < MECHANISM_LAST ) ) ||
		 ( handlingInfoPtr->paramCheck == PARAMTYPE_DATA_COMPARETYPE && \
		   messageDataPtr != NULL && \
		   ( messageValue > RESOURCE_MESSAGE_COMPARE_NONE && \
			 messageValue < RESOURCE_MESSAGE_COMPARE_LAST ) ) );

	/* If it's an object-manipulation message, get the attribute's mandatory 
	   ACL.  Since this doesn't require access to any object information, we 
	   can do this before we lock the object table */
	if( isAttributeMessage( localMessage ) && \
		( attributeACL = findAttributeACL( messageValue, isInternalMessage ) ) == NULL )
		return( CRYPT_ARGERROR_VALUE );

	/* Inner precondition: If it's an attribute-manipulation message, we have 
	   a valid ACL for the attribute present */
	PRE( !isAttributeMessage( localMessage ) || attributeACL != NULL );

	/* Config options can be applied globally, in which case no object handle
	   is given.  Since these don't affect any objects, we process them 
	   outside the object table lock */
	if( isGlobalOptionMessage( objectHandle, localMessage, messageValue ) )
		{
		/* Inner precondition: It's an attribute manipulation message and
		   there's a handler available for it */
		PRE( isAttributeMessage( localMessage ) );
		PRE( handlingInfoPtr->preDispatchFunction != NULL );

		/* Process the option.  Note that we don't call the post-dispatch
		   handler since it doesn't apply to options (it manages an objects
		   state which isn't applicable to CRYPT_UNUSED) */
		status = handlingInfoPtr->preDispatchFunction( CRYPT_UNUSED, 
						message, messageDataPtr, messageValue, attributeACL );
		if( cryptStatusOK( status ) )
			{
			if( localMessage == RESOURCE_MESSAGE_SETATTRIBUTE || \
				localMessage == RESOURCE_MESSAGE_SETATTRIBUTE_S )
				status = setOptionAttribute( localMessage, messageValue, 
											 messageDataPtr );
			else
				status = getOptionAttribute( localMessage, messageValue, 
											 messageDataPtr );
			}

		return( status );
		}

	/* Lock the object table to ensure other threads don't try to access
	   it */
	lockGlobalResource( objectTable );

	/* The first line of defence: Make sure the message is being sent to a 
	   valid object and that the object is externally visible and accessible
	   to the caller if required by the message.  The checks performed are:

		if( handle does not correspond to an object )
			error;
		if( message is external )
			{
			if( object is internal )
				error;
			if( object isn't owned by calling thread )
				error;
			}
	
	   The error condition reported in all of these cases is that the object 
	   handle isn't valid */
	if( !isValidObject( objectHandle ) )
		status = CRYPT_ARGERROR_OBJECT;
	else
		if( !isInternalMessage && \
			( isInternalObject( objectHandle ) || \
			  !checkObjectOwnership( objectTable[ objectHandle ] ) ) )
			status = CRYPT_ARGERROR_OBJECT;
	if( cryptStatusError( status ) )
		{
		unlockGlobalResource( objectTable );
		return( status );
		}

	/* Inner precondition now that the outer check is past: It's a valid 
	   object, and the system object can never be explicitly destroyed or 
	   have its refCount altered */
	PRE( isValidObject( objectHandle ) );
	PRE( objectHandle >= NO_SYSTEM_OBJECTS || \
		 ( localMessage != RESOURCE_MESSAGE_DESTROY && \
		   localMessage != RESOURCE_MESSAGE_DECREFCOUNT && \
		   localMessage != RESOURCE_MESSAGE_INCREFCOUNT ) );

	/* If this message is routable, find its target object */
	if( handlingInfoPtr->routingFunction != NULL )
		{
		/* If it's implicitly routed, route it based on the attribute type */
		if( isImplicitRouting( handlingInfoPtr->routingTarget ) )
			{
			if( attributeACL->routingFunction != NULL )
				localObjectHandle = attributeACL->routingFunction( objectHandle, 
											attributeACL->routingTarget );
			}
		else
			/* It's explicitly or directly routed, route it based on the 
			   message type or fixed-target type */
			localObjectHandle = handlingInfoPtr->routingFunction( objectHandle, 
						isExplicitRouting( handlingInfoPtr->routingTarget ) ? \
						messageValue : handlingInfoPtr->routingTarget );
		if( cryptStatusError( localObjectHandle ) )
			{
			unlockGlobalResource( objectTable );
			return( CRYPT_ARGERROR_OBJECT );
			}
		}

	/* Now that the message has been routed to its intended target, make sure
	   it's valid for the target object subtype */
	if( !( objectTable[ localObjectHandle ].subType & \
		   handlingInfoPtr->objectSubType ) )
		{
		unlockGlobalResource( objectTable );
		return( CRYPT_ARGERROR_OBJECT );
		}

	/* If this message is processed internally, handle it now.  These 
	   messages aren't affected by the object's state so they're always
	   processed */
	if( handlingInfoPtr->internalHandlerFunction != NULL || \
		( attributeACL != NULL && \
		  attributeACL->flags & ATTRIBUTE_FLAG_PROPERTY ) )
		{
		if( handlingInfoPtr->preDispatchFunction != NULL ) 
			status = handlingInfoPtr->preDispatchFunction( localObjectHandle, 
									message, messageDataPtr, messageValue,
									attributeACL );
		if( cryptStatusOK( status ) )
			{
			/* Precondition: Either the message as a whole is internally 
			   handled or it's a property attribute */
			PRE( handlingInfoPtr->internalHandlerFunction == NULL || \
				 attributeACL == NULL );

			/* If it's an object property attribute (which is handled by the
			   kernel), get or set its value */
			if( handlingInfoPtr->internalHandlerFunction == NULL )
				{
				PRE( handlingInfoPtr->messageType == RESOURCE_MESSAGE_GETATTRIBUTE || \
					 handlingInfoPtr->messageType == RESOURCE_MESSAGE_SETATTRIBUTE );

				if( handlingInfoPtr->messageType == RESOURCE_MESSAGE_GETATTRIBUTE )
					status = getPropertyAttribute( objectHandle, messageValue, 
												   messageDataPtr );
				else
					status = setPropertyAttribute( objectHandle, messageValue, 
												   messageDataPtr );
				}
			else
				/* It's a kernel-handled message, process it */
				status = handlingInfoPtr->internalHandlerFunction( \
							localObjectHandle, messageValue, messageDataPtr );
			}
		if( status != OK_SPECIAL )
			{
			/* The message was processed normally, exit */
			unlockGlobalResource( objectTable );
			return( status );
			}

		/* The object has entered an invalid state (for example it was 
		   signalled while it was being initialised) and can't be used any 
		   more, destroy it.  We do this by converting the message into a
		   destroy object message, but leaving the original message data in
		   place so later code can determine what triggered the event */
		localMessage = RESOURCE_MESSAGE_DESTROY;
		handlingInfoPtr = &messageHandlingInfo[ RESOURCE_MESSAGE_DESTROY ];
		status = CRYPT_OK;
		}

	/* If the object isn't already processing a message and the message isn't
	   a special type such as RESOURCE_MESSAGE_DESTROY, dispatch it
	   immediately rather than enqueueing it for later dispatch - this 
	   scoreboard mechanism greatly reduces the load on the queue */
	if( !isInUse( localObjectHandle ) && \
		localMessage != RESOURCE_MESSAGE_DESTROY )
		{
		/* If the object isn't in a valid state, we can't do anything with it.
		   There are no messages which can be sent to it at this point, get/
		   set property messages have already been handled earlier and the
		   destroy message isn't handled here */
		if( isInvalidObjectState( localObjectHandle ) )
			{
			unlockGlobalResource( objectTable );
			return( getObjectStatusValue( \
							objectTable[ localObjectHandle ].flags ) );
			}

		/* Inner precondition: The object is in a valid state */
		PRE( !isInvalidObjectState( localObjectHandle ) );

		/* Mark the object as busy so that we have it available for our 
		   exclusive use and further messages to it will be enqueued, 
		   dispatch the message with the object table unlocked, and mark 
		   the object as non-busy again */
		objectTable[ localObjectHandle ].inUse++;
		if( handlingInfoPtr->preDispatchFunction != NULL ) 
			status = handlingInfoPtr->preDispatchFunction( localObjectHandle, 
									message, messageDataPtr, messageValue,
									attributeACL );
		if( cryptStatusOK( status ) )
			{
			unlockGlobalResource( objectTable );
			status = objectTable[ localObjectHandle ].messageFunction( \
										localObjectHandle, localMessage, 
										messageDataPtr, messageValue );
			lockGlobalResource( objectTable );
			}
		if( cryptStatusOK( status ) && \
			handlingInfoPtr->postDispatchFunction != NULL )
			status = handlingInfoPtr->postDispatchFunction( localObjectHandle, 
									message, messageValue, attributeACL );
		objectTable[ localObjectHandle ].inUse--;

		unlockGlobalResource( objectTable );
		return( status );
		}

	/* Enqueue the message */
	if( !enqueueMessage( localObjectHandle, handlingInfoPtr, message,
						 messageDataPtr, messageValue ) )
		{
		/* A message for this object is already present in the queue, defer 
		   processing until later */
		unlockGlobalResource( objectTable );
		return( CRYPT_OK );
		}

	/* While there are more messages for this object present, dequeue them
	   and dispatch them.  Since messages will only be enqueued if
	   krnlSendMessage() is called recursively, we only dequeue messages for
	   the current object in this loop.  Queued messages for other objects
	   will be handled at a different level of recursion */
	while( getNextMessage( localObjectHandle, &enqueuedMessageData ) )
		{
		const MESSAGE_HANDLING_INFO *handlingInfoPtr = enqueuedMessageData.handlingInfoPtr;
		RESOURCE_MESSAGE_TYPE enqueuedMessage = enqueuedMessageData.message;
		const void *enqueuedMessageDataPtr = enqueuedMessageData.messageDataPtr;
		const int enqueuedMessageValue = enqueuedMessageData.messageValue;

		/* If there's a problem with the object, initiate special processing.
		   There are two exceptions to this, one is a destroy message sent to
		   a busy object, the other is a destroy message which started out as 
		   a different type of message (that is, it was converted into a 
		   destroy object message due to the object being in an invalid 
		   state).  Both of these types are let through */
		if( isInvalidObjectState( localObjectHandle ) && \
			!( handlingInfoPtr->messageType == RESOURCE_MESSAGE_DESTROY && \
			    ( enqueuedMessageDataPtr != NULL || \
				  ( objectTable[ objectHandle  ].flags & OBJECT_FLAG_BUSY ) ) ) )
			{
			/* If it's a destroy object message being sent to an object in 
			   the process of being created, set the state to signalled and 
			   continue.  The object will be destroyed when the caller 
			   notifies the kernel that the init is complete */
			if( handlingInfoPtr->messageType == RESOURCE_MESSAGE_DESTROY && \
				( objectTable[ objectHandle ].flags & OBJECT_FLAG_NOTINITED ) )
				{
				objectTable[ objectHandle  ].flags |= OBJECT_FLAG_SIGNALLED;
				status = CRYPT_OK;
				}
			else
				{
				/* Remove all further messages for this object and return
				   to the caller */
				dequeueAllMessages( localObjectHandle );
				status = getObjectStatusValue( objectTable[ objectHandle ].flags );
				}
			continue;
			}

		/* Inner precondition: The object is in a valid state or it's a 
		   destroy message to a busy object or a destroy message which was 
		   converted from a different message type */
		PRE( !isInvalidObjectState( localObjectHandle ) || \
			 ( handlingInfoPtr->messageType == RESOURCE_MESSAGE_DESTROY && \
			   ( enqueuedMessageDataPtr != NULL || \
				 ( objectTable[ objectHandle  ].flags & OBJECT_FLAG_BUSY ) ) ) );

		/* Dispatch the message with the object table unlocked.  The object is
		   already marked as being in use so we don't have to do it again */
		if( handlingInfoPtr->preDispatchFunction != NULL ) 
			status = handlingInfoPtr->preDispatchFunction( localObjectHandle, 
							enqueuedMessage, enqueuedMessageDataPtr, 
							enqueuedMessageValue, attributeACL );
		if( cryptStatusOK( status ) )
			{
			unlockGlobalResource( objectTable );
			status = objectTable[ localObjectHandle ].messageFunction( \
							localObjectHandle, handlingInfoPtr->messageType, 
							( void * ) enqueuedMessageDataPtr, enqueuedMessageValue );
			lockGlobalResource( objectTable );
			}
		if( cryptStatusOK( status ) && \
			handlingInfoPtr->postDispatchFunction != NULL )
			status = handlingInfoPtr->postDispatchFunction( localObjectHandle, 
							enqueuedMessage, enqueuedMessageValue,
							attributeACL );

		/* If we ran into a problem, dequeue all further messages for this 
		   object (this causes getNextMessage() to fail and we drop out of 
		   the loop) */
		if( cryptStatusError( status ) )
			dequeueAllMessages( localObjectHandle );
		else
			/* If the message is a destroy object message, we have to 
			   explicitly remove it from the object table and dequeue all 
			   further messages for it since the objects message handler 
			   can't do this itself */
			if( handlingInfoPtr->messageType == RESOURCE_MESSAGE_DESTROY )
				{
				objectTable[ localObjectHandle ] = objectTemplate;
				dequeueAllMessages( localObjectHandle );
				}
		}

	/* Unlock the object table to allow access by other threads */
	unlockGlobalResource( objectTable );

	return( status );
	}

void krnlSendBroadcast( const OBJECT_TYPE type,
						const RESOURCE_MESSAGE_TYPE message,
						void *messageDataPtr, const int messageValue )
	{
	int objectHandle;

	/* Lock the object table to ensure other threads don't try to access
	   it */
	lockGlobalResource( objectTable );

	/* Send the notification to every object of the appropriate type in the
	   table */
	for( objectHandle = 0; objectHandle < objectTableSize;
		 objectHandle++ )
		if( objectTable[ objectHandle ].type == type )
			{
			unlockGlobalResource( objectTable );
			krnlSendMessage( objectHandle, message, messageDataPtr,
							 messageValue );
			lockGlobalResource( objectTable );
			}

	/* Unlock the object table to allow access by other threads */
	unlockGlobalResource( objectTable );
	}

/****************************************************************************
*																			*
*								Semaphore Functions							*
*																			*
****************************************************************************/

/* Under multithreaded OS's, we often need to wait for certain events before
   we can continue (for example when asynchronously accessing system
   objects anything which depends on the object being available needs to
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
   handle object and object locking when the service routine applies to a
   particular object or object */

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

	/* Preconditions */
	PRE( serviceInfoLast >= 0 && serviceInfoLast < MAX_SERVICES );

	/* Add this service to the service table */
	serviceInfo[ serviceInfoLast ].serviceDispatchFunction = \
													serviceDispatchFunction;
	serviceInfo[ serviceInfoLast ].serviceFunction = serviceFunction;
	serviceInfo[ serviceInfoLast++ ].object = object;
	retVal = serviceUniqueID++;

	/* Postconditions */
	PRE( serviceInfoLast >= 0 && serviceInfoLast < MAX_SERVICES );
	POST( serviceUniqueID >= 0 && serviceUniqueID < INT_MAX );

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

	/* Preconditions */
	PRE( serviceInfoLast >= 0 && serviceInfoLast < MAX_SERVICES );

	/* Find this service in the service table */
	for( i = 0; i < serviceInfoLast; i++ )
		if( serviceID == serviceInfo[ i ].serviceID )
			break;
	assert( i < serviceInfoLast );

	/* Move everything else down, removing this service from the table */
	if( i == serviceInfoLast - 1 )
		/* This is the last entry, clear it */
		memset( &serviceInfo[ i ], 0, sizeof( SERVICE_INFO ) );
	else
		memmove( &serviceInfo[ i ], &serviceInfo[ i + 1 ], \
				 ( serviceInfoLast - i ) - 1 );
	serviceInfoLast--;

	/* Postconditions */
	PRE( serviceInfoLast >= 0 && serviceInfoLast < MAX_SERVICES );

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

	getCheckResource( object, keysetInfoPtr, OBJECT_TYPE_KEYSET,
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
#ifdef __BEOS__
	area_id areaID;					/* Needed for page locking under BeOS */
#endif /* __BEOS__ */
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

#if defined( __MAC__ )
  #include <Memory.h>
#endif /* __MAC__ */

#if defined( __WIN32__ ) && defined( _DEBUG ) && !defined( NT_DRIVER )
  #include <crtdbg.h>	/* For heap checking in debug version */
#endif /* __WIN32__ && _DEBUG && !NT_DRIVER */

/* A secure version of malloc() and free() which perform page locking if
   necessary and zeroise memory before it is freed */

int krnlMemalloc( void **pointer, int size )
	{
	MEMLOCK_INFO *memBlockPtr;
	BYTE *memPtr;
	int forceLock;

	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
					 &forceLock, CRYPT_OPTION_MISC_FORCELOCK );

	/* Try and allocate the memory */
#ifdef __BEOS__
	/* Under BeOS we have to allocate a locked area, we can't lock it after
	   the event.  create_area(), like most of the low-level memory access
	   functions provided by different OS's, functions at the page level, so
	   we round the size up to the page size.  We can mitigate the 
	   granularity somewhat by specifying lazy locking, which means that the
	   page isn't locked until it's committed.

	   BeOS areas are a bit of a security tradeoff because they're globally
	   visible(!!!) through the use of find_area(), so any other process in 
	   the system can find them.  They can always find the apps malloc() 
	   arena anyway because of this, but putting data directly into areas
	   makes an attackers task somewhat easier, OTOH we make it harder again
	   by making all the areas anonymous.  In general the risk of data being
	   swapped and analysed later is a lot greater than that of an attacker
	   getting a trojan running on the system, so we use areas */
	area_id areadID;

	areadID = create_area( NULL, &memPtr, B_ANY_ADDRESS, 
						   roundUp( size + MEMLOCK_HEADERSIZE, B_PAGE_SIZE ),
						   B_LAZY_LOCK, B_READ_AREA | B_WRITE_AREA );
	if( areadID != B_NO_ERROR )
#else
	if( ( memPtr = malloc( size + MEMLOCK_HEADERSIZE ) ) == NULL )
#endif /* __BEOS__ */						/* Shadu yu liktumkunushi */
		{									/* Shadu yu liklakunushi */
		*pointer = NULL;					/* Shadu yu lini yix kunushi */
		return( CRYPT_ERROR_MEMORY );		/* Shadu yu li yixsi kunushi */
		}									/* Shadu yu lite kunushi */
	memset( memPtr, 0, size + MEMLOCK_HEADERSIZE );	/* Shadu yu lini kunushi */
	memBlockPtr = ( MEMLOCK_INFO * ) memPtr;/* Shadu yu linir kunushi */
	memBlockPtr->isLocked = FALSE;			/* Shadu yu likattin kunushi */
	memBlockPtr->size = size + MEMLOCK_HEADERSIZE;	/* Shadu yu dannu elikunu limqut */
#ifdef __BEOS__								/* Ina zumri ya lu yu tapparrasama! */
	memBlockPtr->areaID = areaID;
#endif /* __BEOS__ */
	*pointer = memPtr + MEMLOCK_HEADERSIZE;

	/* If the OS supports paging, try to lock the pages in memory */
#if defined( __WIN16__ )
	/* Under Windows 3.x there's no support for memory locking, so we simply
	   return an error code for a forced lock */
	if( forceLock )
		{
		free( memPtr );
		*pointer = NULL;
		return( CRYPT_ERROR_NOSECURE );
		}
#elif defined( __WIN32__ ) && !defined( NT_DRIVER )
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
		if( forceLock )
			{
			free( memPtr );
			*pointer = NULL;
			return( CRYPT_ERROR_NOSECURE );
			}
#elif defined( __MSDOS__ ) && defined( __DJGPP__ )
	/* Under 32-bit MSDOS use the DPMI-functions to lock the memory */
	if( _go32_dpmi_lock_data( memPtr, memBlockPtr->size ) == 0)
		memBlockPtr->isLocked = TRUE;
	else
		if( forceLock )
			{
			free( memPtr );
			*pointer = NULL;
			return( CRYPT_ERROR_NOSECURE );
			}
#elif defined( __UNIX__ )
  #ifndef NO_MLOCK
	if( !mlock( memPtr, memBlockPtr->size ) )
		memBlockPtr->isLocked = TRUE;
	else
  #endif /* NO_MLOCK */
		if( forceLock )
			{
			free( memPtr );
			*pointer = NULL;
			return( CRYPT_ERROR_NOSECURE );
			}
#elif defined( __MAC__ )
	/* The Mac has two functions for locking memory, HoldMemory() (which
	   makes the memory ineligible for paging) and LockMemory() (which makes
	   it ineligible for paging and also immovable).  We use HoldMemory()
	   since it's slightly more friendly, but really critical applications
	   could use LockMemory() */
	if( !HoldMemory( memPtr, memBlockPtr->size ) )
		memBlockPtr->isLocked = TRUE;
	else
		if( forceLock )
			{
			free( memPtr );
			*pointer = NULL;
			return( CRYPT_ERROR_NOSECURE );
			}
#endif /* Systems which support memory locking */

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

#if defined( __WIN32__ ) && defined( _DEBUG ) && !defined( NT_DRIVER )
	/* Sanity check to detect memory chain corruption */
	assert( _CrtIsValidHeapPointer( memBlockPtr ) );
	assert( memBlockPtr->next == NULL );
	assert( allocatedListHead == allocatedListTail || \
			_CrtIsValidHeapPointer( memBlockPtr->prev ) );
#endif /* __WIN32__ && !NT_DRIVER */

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

	/* Lock the allocation object to ensure other threads don't try to
	   access them */
	lockGlobalResource( allocation );

#if defined( __WIN32__ ) && defined( _DEBUG ) && !defined( NT_DRIVER )
	/* Sanity check to detect memory chain corruption */
	assert( _CrtIsValidHeapPointer( memBlockPtr ) );
	assert( memBlockPtr->next == NULL || \
			_CrtIsValidHeapPointer( memBlockPtr->next ) );
	assert( memBlockPtr->prev == NULL || \
			_CrtIsValidHeapPointer( memBlockPtr->prev ) );
#endif /* __WIN32__ && !NT_DRIVER */

	/* Unlink the block from the allocation list */
	nextBlockPtr = memBlockPtr->next;
	prevBlockPtr = memBlockPtr->prev;
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
	   allocation objects remain locked while we do the free, but this
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

	/* Unlock the allocation object to allow access by other threads */
	unlockGlobalResource( allocation );

	/* If the memory is locked, unlock it now */
#if defined( __UNIX__ ) && !defined( NO_MLOCK )
	if( memBlockPtr->isLocked )
		munlock( memPtr, memBlockPtr->size );
#elif defined( __MSDOS__ ) && defined( __DJGPP__ )
	/* Under 32-bit MSDOS we *could* use the DPMI-functions to unlock the
	   memory, but as many DPMI hosts implement page locking in a binary form
	   (no lock count maintained), we don't actually unlock anything at all.
	   Note that this may lead to a shortage of virtual memory in long-
	   running applications */
#elif defined( __MAC__ )
	if( memBlockPtr->isLocked )
		UnholdMemory( memPtr, memBlockPtr->size );
#elif defined( __BEOS__ )
	delete_area( memBlockPtr->areadID );
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

	/* Lock the allocation object to ensure other threads don't try to
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

	/* Unlock the allocation object to allow access by other threads */
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
	int i, status;

	/* Perform a consistency check on various things which need to be set
	   up in a certain way for things to work properly (the context message
	   sequencing is checked indirectly further down as well, but the check 
	   done here is more explicit) */
	assert( objectTemplate.type == OBJECT_TYPE_NONE );
	assert( objectTemplate.flags == \
			( OBJECT_FLAG_INTERNAL | OBJECT_FLAG_NOTINITED ) );
	assert( objectTemplate.actionFlags == 0 );
	assert( objectTemplate.subType == 0 );
	assert( objectTemplate.forwardCount == CRYPT_UNUSED );
	assert( objectTemplate.usageCount == CRYPT_UNUSED );
	assert( objectTemplate.dependentDevice == CRYPT_ERROR );
	assert( objectTemplate.dependentObject == CRYPT_ERROR );
	assert( RESOURCE_MESSAGE_CTX_DECRYPT == RESOURCE_MESSAGE_CTX_ENCRYPT + 1 );
	assert( RESOURCE_MESSAGE_CTX_SIGN == RESOURCE_MESSAGE_CTX_DECRYPT + 1 );
	assert( RESOURCE_MESSAGE_CTX_SIGCHECK == RESOURCE_MESSAGE_CTX_SIGN + 1 );
	assert( RESOURCE_MESSAGE_CTX_HASH == RESOURCE_MESSAGE_CTX_SIGCHECK + 1 );
	assert( RESOURCE_MESSAGE_CTX_GENKEY == RESOURCE_MESSAGE_CTX_HASH + 1 );

	/* Perform a consistency check on the attribute ACL's */
	for( i = 0; i < CRYPT_PROPERTY_LAST - CRYPT_PROPERTY_FIRST - 1; i++ )
		assert( propertyACL[ i ].attribute == i + CRYPT_PROPERTY_FIRST + 1 );
	assert( propertyACL[ i ].attribute == CRYPT_ERROR );
	for( i = 0; i < CRYPT_GENERIC_LAST - CRYPT_GENERIC_FIRST - 1; i++ )
		assert( genericACL[ i ].attribute == i + CRYPT_GENERIC_FIRST + 1 );
	assert( genericACL[ i ].attribute == CRYPT_ERROR );
	for( i = 0; i < CRYPT_OPTION_LAST - CRYPT_OPTION_FIRST - 1; i++ )
		assert( optionACL[ i ].attribute == i + CRYPT_OPTION_FIRST + 1 );
	assert( optionACL[ i ].attribute == CRYPT_ERROR );
	for( i = 0; i < CRYPT_CTXINFO_LAST - CRYPT_CTXINFO_FIRST - 1; i++ )
		assert( contextACL[ i ].attribute == i + CRYPT_CTXINFO_FIRST + 1 );
	assert( contextACL[ i ].attribute == CRYPT_ERROR );
	for( i = 0; i < CRYPT_CERTINFO_LAST_CERTINFO - CRYPT_CERTINFO_FIRST_CERTINFO - 1; i++ )
		assert( certificateACL[ i ].attribute == i + CRYPT_CERTINFO_FIRST_CERTINFO + 1 );
	assert( certificateACL[ i ].attribute == CRYPT_ERROR );
	for( i = 0; i < CRYPT_CERTINFO_LAST_NAME - CRYPT_CERTINFO_FIRST_NAME - 1; i++ )
		assert( certNameACL[ i ].attribute == i + CRYPT_CERTINFO_FIRST_NAME + 1 );
	assert( certNameACL[ i ].attribute == CRYPT_ERROR );
	for( i = 0; i < CRYPT_CERTINFO_LAST_EXTENSION - CRYPT_CERTINFO_FIRST_EXTENSION - 1; i++ )
		assert( certExtensionACL[ i ].attribute == i + CRYPT_CERTINFO_FIRST_EXTENSION + 1 );
	assert( certExtensionACL[ i ].attribute == CRYPT_ERROR );
	for( i = 0; i < CRYPT_CERTINFO_LAST_CMS - CRYPT_CERTINFO_FIRST_CMS - 1; i++ )
		assert( certSmimeACL[ i ].attribute == i + CRYPT_CERTINFO_FIRST_CMS + 1 );
	assert( certSmimeACL[ i ].attribute == CRYPT_ERROR );
	for( i = 0; i < CRYPT_KEYSETINFO_LAST - CRYPT_KEYSETINFO_FIRST - 1; i++ )
		assert( keysetACL[ i ].attribute == i + CRYPT_KEYSETINFO_FIRST + 1 );
	assert( keysetACL[ i ].attribute == CRYPT_ERROR );
	for( i = 0; i < CRYPT_DEVINFO_LAST - CRYPT_DEVINFO_FIRST - 1; i++ )
		assert( deviceACL[ i ].attribute == i + CRYPT_DEVINFO_FIRST + 1 );
	assert( deviceACL[ i ].attribute == CRYPT_ERROR );
	for( i = 0; i < CRYPT_ENVINFO_LAST - CRYPT_ENVINFO_FIRST - 1; i++ )
		assert( envelopeACL[ i ].attribute == i + CRYPT_ENVINFO_FIRST + 1 );
	assert( envelopeACL[ i ].attribute == CRYPT_ERROR );
	for( i = 0; i < CRYPT_SESSINFO_LAST - CRYPT_SESSINFO_FIRST - 1; i++ )
		assert( sessionACL[ i ].attribute == i + CRYPT_SESSINFO_FIRST + 1 );
	assert( sessionACL[ i ].attribute == CRYPT_ERROR );
	for( i = 0; i < CRYPT_IATTRIBUTE_LAST - CRYPT_IATTRIBUTE_FIRST - 1; i++ )
		assert( internalACL[ i ].attribute == i + CRYPT_IATTRIBUTE_FIRST + 1 );
	assert( internalACL[ i ].attribute == CRYPT_ERROR );

	/* Perform a consistency check on the message handling information */
	for( i = 0; i < RESOURCE_MESSAGE_LAST; i++ )
		assert( messageHandlingInfo[ i ].messageType == i );

	/* Perform a consistency check on various internal values and constants */
	assert( ACTION_PERM_COUNT == 6 );

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
	isInitialised = TRUE;
	return( status );
	}

void endInternalFunctions( void )
	{
	endResources();
	endServices();
	endSemaphores();
	endAllocation();
	}
