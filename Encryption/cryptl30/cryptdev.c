/****************************************************************************
*																			*
*						 cryptlib Crypto Device Routines					*
*						Copyright Peter Gutmann 1997-1999					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "device.h"
#else
  #include "misc/device.h"
#endif /* Compiler-specific includes */

/* When we get random data from a device, we run the (practical) FIPS 140 
   tests over the output to make sure it's really random (at least as far
   as the tests can tell us).  If the data fails the test, we get more and
   try again.  The following value defines how many times we retry before
   giving up */

#define NO_ENTROPY_FAILURES	5

/* Some device types aren't supported on some platforms, so we replace a
   call to the mapping function with an error code */

#ifndef __WINDOWS__
  #define setDeviceFortezza( x )		CRYPT_ARGERROR_NUM1
#endif /* !__WINDOWS__ */
#ifndef DEV_PKCS11
  #define setDevicePKCS11( x, y, z )	CRYPT_ARGERROR_NUM1
#endif /* !DEV_PKCS11 */

/* Prototypes for functions in crypt.c */

const void FAR_BSS *findCapabilityInfo( const void FAR_BSS *capabilityInfoPtr,
										const CRYPT_ALGO cryptAlgo );
void copyCapabilityInfo( const void FAR_BSS *capabilityInfoPtr,
						 CRYPT_QUERY_INFO *cryptQueryInfo );

/* Prototypes for functions in cryptmis.c */

BOOLEAN checkEntropy( const BYTE *data, const int dataLength );

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Initialise and down any devices we're working with */

void deviceInitFortezza( void );
void deviceEndFortezza( void );
void deviceInitPKCS11( void );
void deviceEndPKCS11( void );

void initDevices( void )
	{
#if defined( __WINDOWS__ ) && !defined( NT_DRIVER )
	deviceInitFortezza();
#endif /* __WINDOWS__ && !NT_DRIVER */
#ifdef DEV_PKCS11
	deviceInitPKCS11();
#endif /* DEV_PKCS11 */
	}

void shutdownDevices( void )
	{
#if defined( __WINDOWS__ ) && !defined( NT_DRIVER )
	deviceEndFortezza();
#endif /* __WINDOWS__ && !NT_DRIVER */
#ifdef DEV_PKCS11
	deviceEndPKCS11();
#endif /* DEV_PKCS11 */
	}

/* Get a random data block with FIPS 140 checking */

static int getRandomData( DEVICE_INFO *deviceInfoPtr, void *data, 
						  const int length )
	{
	int i;

	/* Get random data from the device and check it using the FIPS 140
	   tests */
	for( i = 0; i < NO_ENTROPY_FAILURES; i++ )
		{
		int status;

		status = deviceInfoPtr->getRandomFunction( deviceInfoPtr, data, 
												   length );
		if( cryptStatusOK( status ) && checkEntropy( data, length ) )
			return( CRYPT_OK );
		}

	/* We couldn't get anything which passed the FIPS 140 tests, we can't
	   go any further */
	zeroise( data, length );
	assert( NOTREACHED );
	return( CRYPT_ERROR_RANDOM );
	}

/****************************************************************************
*																			*
*								Device API Functions						*
*																			*
****************************************************************************/

/* Default object creation routines used when the device code doesn't set
   anything up */

int createContext( CREATEOBJECT_INFO *createInfo, const void *auxDataPtr, 
				   const int auxValue );

static const CREATEOBJECT_FUNCTION_INFO defaultCreateFunctions[] = {
	{ OBJECT_TYPE_CONTEXT, createContext }, 
	{ OBJECT_TYPE_NONE, NULL }
	};

/* Handle a message sent to a device object */

static int deviceMessageFunction( const CRYPT_DEVICE cryptDevice,
								  const RESOURCE_MESSAGE_TYPE message,
								  void *messageDataPtr,
								  const int messageValue )
	{
	DEVICE_INFO *deviceInfoPtr;

	getCheckInternalResource( cryptDevice, deviceInfoPtr, OBJECT_TYPE_DEVICE );

	/* Process the destroy object message */
	if( message == RESOURCE_MESSAGE_DESTROY )
		{
		/* Shut down the device if required */
		if( deviceInfoPtr->flags & DEVICE_ACTIVE && \
			deviceInfoPtr->shutdownDeviceFunction != NULL )
			deviceInfoPtr->shutdownDeviceFunction( deviceInfoPtr );

		/* Delete the objects locking variables and the object itself */
		unlockResource( deviceInfoPtr );
		deleteResourceLock( deviceInfoPtr );
		zeroise( deviceInfoPtr, sizeof( DEVICE_INFO ) );
		free( deviceInfoPtr );

		return( CRYPT_OK );
		}

	/* Process attribute get/set/delete messages */
	if( message == RESOURCE_MESSAGE_SETATTRIBUTE )
		{
		int status;

		/* If it's an initialisation message, there's nothing to do */
		if( messageValue == CRYPT_IATTRIBUTE_INITIALISED )
			unlockResourceExit( deviceInfoPtr, CRYPT_OK );

		/* Send the control information to the device */
		status = deviceInfoPtr->controlFunction( deviceInfoPtr, messageValue,
								NULL, *( ( int * ) messageDataPtr ), NULL, 0 );
		unlockResourceExit( deviceInfoPtr, status );
		}
	if( message == RESOURCE_MESSAGE_SETATTRIBUTE_S )
		{
		const RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
		int status;

		/* Make sure the device which can handle device control attributes */
		if( deviceInfoPtr->controlFunction == NULL )
			unlockResourceExit( deviceInfoPtr, CRYPT_ARGERROR_VALUE );

		/* If it's a PIN attribute, make sure that a login is actually
		   required for the device */
		if( ( messageValue == CRYPT_DEVINFO_AUTHENT_USER || \
			  messageValue == CRYPT_DEVINFO_AUTHENT_SUPERVISOR ) && \
			!( deviceInfoPtr->flags & DEVICE_NEEDSLOGIN ) )
			unlockResourceExit( deviceInfoPtr, CRYPT_ERROR_INITED );

		/* If it's a PIN attribute, make sure the supplied PIN is valid */
		if( messageValue == CRYPT_DEVINFO_INITIALISE || \
			messageValue == CRYPT_DEVINFO_AUTHENT_USER || \
			messageValue == CRYPT_DEVINFO_AUTHENT_SUPERVISOR || \
			messageValue == CRYPT_DEVINFO_SET_AUTHENT_USER || \
			messageValue == CRYPT_DEVINFO_SET_AUTHENT_SUPERVISOR || \
			messageValue == CRYPT_DEVINFO_ZEROISE )
			if( msgData->length < deviceInfoPtr->minPinSize || \
				msgData->length > deviceInfoPtr->maxPinSize )
				unlockResourceExit( deviceInfoPtr, CRYPT_ARGERROR_NUM1 );

		/* Send the control information to the device */
		status = deviceInfoPtr->controlFunction( deviceInfoPtr, messageValue,
									msgData->data, msgData->length, NULL, 0 );
		unlockResourceExit( deviceInfoPtr, status );
		}
	if( message == RESOURCE_MESSAGE_GETATTRIBUTE )	
		{
		int *valuePtr = ( int * ) messageDataPtr;

		switch( messageValue )
			{
			case CRYPT_ATTRIBUTE_ERRORTYPE:
				*valuePtr = deviceInfoPtr->errorType;
				break;

			case CRYPT_ATTRIBUTE_ERRORLOCUS:
				*valuePtr = deviceInfoPtr->errorLocus;
				break;
			
			case CRYPT_ATTRIBUTE_INT_ERRORCODE:
				*valuePtr = deviceInfoPtr->errorCode;
				break;

			default:
				assert( NOTREACHED );
			}
		unlockResourceExit( deviceInfoPtr, CRYPT_OK );
		}
	if( message == RESOURCE_MESSAGE_GETATTRIBUTE_S )
		{
		RESOURCE_DATA *msgData = ( RESOURCE_DATA * ) messageDataPtr;
		int status = CRYPT_ERROR_NOTAVAIL;

		switch( messageValue )
			{
			case CRYPT_ATTRIBUTE_INT_ERRORMESSAGE:
				status = attributeCopy( msgData, deviceInfoPtr->errorMessage,
										strlen( deviceInfoPtr->errorMessage ) );
				break;

			case CRYPT_IATTRIBUTE_RANDOM:
				if( deviceInfoPtr->getRandomFunction != NULL )
					status = getRandomData( deviceInfoPtr, msgData->data, 
											msgData->length );
				break;

			case CRYPT_IATTRIBUTE_RANDOM_NZ:
				if( deviceInfoPtr->getRandomFunction != NULL )
					{
					BYTE randomBuffer[ 128 ], *outBuffer = msgData->data;
					int count = msgData->length;

					/* The extraction of data is a little complex because we 
					   don't know how much data we'll need (as a rule of 
					   thumb it'll be size + ( size / 256 ) bytes, but in a 
					   worst-case situation we could need to draw out 
					   megabytes of data), so we copy out 128 bytes worth at 
					   a time (a typical value for a 1K bit key) and keep 
					   going until we've filled the output requirements */
					while( count )
						{
						int i;

						/* Copy as much as we can from the randomness pool */
						status = getRandomData( deviceInfoPtr, randomBuffer, 
												128 );
						if( cryptStatusError( status ) )
							break;
						for( i = 0; count && i < 128; i++ )
							if( randomBuffer[ i ] )
								{
								*outBuffer++ = randomBuffer[ i ];
								count--;
								}
						}
					zeroise( randomBuffer, 128 );
					if( cryptStatusError( status ) )	
						zeroise( msgData->data, msgData->length );
					}
				break;
			
			default:
				assert( NOTREACHED );
			}

		unlockResourceExit( deviceInfoPtr, status );
		}

	/* Process action messages */
	if( isMechanismActionMessage( message ) )
		{
		MECHANISM_FUNCTION mechanismFunction = NULL;
		int status;

		/* Find the function to handle this action and mechanism */
		if( deviceInfoPtr->mechanismFunctions != NULL )
			{
			int index = 0;

			while( deviceInfoPtr->mechanismFunctions[ index ].action != RESOURCE_MESSAGE_NONE )
				{
				if( deviceInfoPtr->mechanismFunctions[ index ].action == message && \
					deviceInfoPtr->mechanismFunctions[ index ].mechanism == messageValue )
					{
					mechanismFunction = \
						deviceInfoPtr->mechanismFunctions[ index ].function;
					break;
					}
				index++;
				}
			}
		if( mechanismFunction == NULL )
			{
			/* If the message has been sent to a device other than the system
			   object, try forwarding it to the system object */
			unlockResource( deviceInfoPtr );
			if( cryptDevice != SYSTEM_OBJECT_HANDLE )
				return( krnlSendMessage( SYSTEM_OBJECT_HANDLE, message,
										 messageDataPtr, messageValue ) );
			return( CRYPT_ERROR_NOTAVAIL );
			}

		/* If the message has been sent to the system object, unlock it to 
		   allow it to be used by others and dispatch the message */
		if( cryptDevice == SYSTEM_OBJECT_HANDLE )
			{
			unlockResource( deviceInfoPtr );
			return( mechanismFunction( NULL, messageDataPtr ) );
			}

		/* Send the message to the device */
		status = mechanismFunction( deviceInfoPtr, messageDataPtr );
		unlockResourceExit( deviceInfoPtr, status );
		}

	/* Process messages which check a device.  In some cases a device can act 
	   as a keyset, so if the device could store keys of this type we report 
	   it as being an appropriate keyset */
	if( message == RESOURCE_MESSAGE_CHECK )
		{
		if( ( messageValue == RESOURCE_MESSAGE_CHECK_PKC_ENCRYPT || \
			  messageValue == RESOURCE_MESSAGE_CHECK_PKC_DECRYPT || \
			  messageValue == RESOURCE_MESSAGE_CHECK_PKC_SIGCHECK || \
			  messageValue == RESOURCE_MESSAGE_CHECK_PKC_SIGN ) && \
			( deviceInfoPtr->type == CRYPT_DEVICE_FORTEZZA || \
			  deviceInfoPtr->type == CRYPT_DEVICE_PKCS11 ) )
			unlockResourceExit( deviceInfoPtr, CRYPT_OK );

		unlockResourceExit( deviceInfoPtr, CRYPT_ARGERROR_OBJECT );
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
		unlockResource( deviceInfoPtr );/* Undo RESOURCE_MESSAGE_LOCK lock */
		unlockResourceExit( deviceInfoPtr, CRYPT_OK );
		}

	/* Process object-specific messages */
	if( message == RESOURCE_MESSAGE_KEY_GETKEY )
		{
		MESSAGE_KEYMGMT_INFO *getkeyInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;
		int status = CRYPT_ERROR_NOTAVAIL;

		/* Create a context via an object in the device */
		if( deviceInfoPtr->getItemFunction != NULL )
			status = deviceInfoPtr->getItemFunction( deviceInfoPtr,
								&getkeyInfo->cryptHandle, getkeyInfo->keyIDtype,
								getkeyInfo->keyID, getkeyInfo->keyIDlength, 
								NULL, 0, getkeyInfo->flags );

		unlockResourceExit( deviceInfoPtr, status );
		}
	if( message == RESOURCE_MESSAGE_KEY_SETKEY )
		{
		CRYPT_CERTTYPE_TYPE type;
		int isInited = FALSE, status;

		/* Make sure it's the correct type of certificate object and that 
		   it's ready for use */
		status = krnlSendMessage( messageValue, RESOURCE_IMESSAGE_GETATTRIBUTE, 
								  &type, CRYPT_CERTINFO_CERTTYPE );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( messageValue, 
									  RESOURCE_IMESSAGE_GETATTRIBUTE, 
									  &isInited, CRYPT_CERTINFO_IMMUTABLE );
		if( cryptStatusError( status ) || \
			( type != CRYPT_CERTTYPE_CERTIFICATE && \
			  type != CRYPT_CERTTYPE_CERTCHAIN ) || !isInited )
			unlockResourceExit( deviceInfoPtr, CRYPT_ARGERROR_NUM1 );

		/* Update the device with the cert */
		if( deviceInfoPtr->setItemFunction != NULL )
			status = deviceInfoPtr->setItemFunction( deviceInfoPtr,
													 messageValue );

		unlockResourceExit( deviceInfoPtr, status );
		}
	if( message == RESOURCE_MESSAGE_KEY_DELETEKEY )
		{
		MESSAGE_KEYMGMT_INFO *deletekeyInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;
		int status = CRYPT_ERROR_NOTAVAIL;

		/* Delete an object in the device */
		if( deviceInfoPtr->deleteItemFunction != NULL )
			status = deviceInfoPtr->deleteItemFunction( deviceInfoPtr,
							deletekeyInfo->keyIDtype, deletekeyInfo->keyID, 
							deletekeyInfo->keyIDlength );

		unlockResourceExit( deviceInfoPtr, status );
		}
	if( message == RESOURCE_MESSAGE_KEY_GETNEXTCERT )
		{
		MESSAGE_KEYMGMT_INFO *getnextcertInfo = \
								( MESSAGE_KEYMGMT_INFO * ) messageDataPtr;
		int status = CRYPT_ERROR_NOTAVAIL;

		assert( getnextcertInfo->auxInfoLength == sizeof( int ) );

		/* Fetch a cert in a cert chain from the device */
		if( deviceInfoPtr->getNextCertFunction != NULL )
			status = deviceInfoPtr->getNextCertFunction( deviceInfoPtr,
						&getnextcertInfo->cryptHandle, getnextcertInfo->auxInfo,
						getnextcertInfo->keyIDtype, getnextcertInfo->keyID, 
						getnextcertInfo->keyIDlength, getnextcertInfo->flags );

		unlockResourceExit( deviceInfoPtr, status );
		}
	if( message == RESOURCE_MESSAGE_DEV_QUERYCAPABILITY )
		{
		const void FAR_BSS *capabilityInfoPtr;
		CRYPT_QUERY_INFO *queryInfo = ( CRYPT_QUERY_INFO * ) messageDataPtr;

		/* Find the information for this algorithm and return the appropriate
		   information */
		capabilityInfoPtr = findCapabilityInfo( deviceInfoPtr->capabilityInfo, 
												messageValue );
		if( capabilityInfoPtr == NULL )
			unlockResourceExit( deviceInfoPtr, CRYPT_ERROR_NOTAVAIL );
		copyCapabilityInfo( capabilityInfoPtr, queryInfo );

		unlockResourceExit( deviceInfoPtr, CRYPT_OK );
		}
	if( message == RESOURCE_MESSAGE_DEV_CREATEOBJECT )
		{
		CREATEOBJECT_FUNCTION createObjectFunction = NULL;
		const void *auxInfo = NULL;
		int status;

		assert( messageValue > OBJECT_TYPE_NONE && \
				messageValue < OBJECT_TYPE_LAST );

		/* If the device can't have objects created within it, complain */
		if( deviceInfoPtr->flags & DEVICE_READONLY )
			unlockResourceExit( deviceInfoPtr, CRYPT_ERROR_PERMISSION );

		/* Find the function to handle this object */
		if( deviceInfoPtr->createObjectFunctions != NULL )
			{
			int index = 0;

			while( deviceInfoPtr->createObjectFunctions[ index ].type != OBJECT_TYPE_NONE )
				{
				if( deviceInfoPtr->createObjectFunctions[ index ].type == messageValue )
					{
					createObjectFunction  = \
						deviceInfoPtr->createObjectFunctions[ index ].function;
					break;
					}
				index++;
				}
			}
		if( createObjectFunction  == NULL )
			unlockResourceExit( deviceInfoPtr, CRYPT_ERROR_NOTAVAIL );

		/* Get any auxiliary info we may need to create the object */
		if( messageValue == OBJECT_TYPE_CONTEXT )
			auxInfo = deviceInfoPtr->capabilityInfo;

		/* If the message has been sent to the system object, unlock it to 
		   allow it to be used by others and dispatch the message */
		if( cryptDevice == SYSTEM_OBJECT_HANDLE )
			{
			unlockResource( deviceInfoPtr );
			status = createObjectFunction( messageDataPtr, auxInfo, 0 );
			}
		else
			{
			/* Send the message to the device.  We can't unlock the device
			   info before we call the create object function because there
			   may be auxiliary info held in the device object which we need
			   to ensure the existence of */
			status = createObjectFunction( messageDataPtr, auxInfo, 
										   CREATEOBJECT_FLAG_DUMMY );
			unlockResource( deviceInfoPtr );
			}
		if( cryptStatusError( status ) )
			return( status );

/* The following is a kludge for now, since it's not certain whether the 
   system object should have dependent objects (this doesn't affect the way
   the code works, it's purely a design issue) */
if( cryptDevice != SYSTEM_OBJECT_HANDLE )
		/* Make the newly-created object a dependent object of the device */
		krnlSendMessage( ( ( CREATEOBJECT_INFO * ) messageDataPtr )->cryptHandle, 
						 RESOURCE_IMESSAGE_SETDEPENDENT, ( void * ) &cryptDevice, 
						 TRUE );
		return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR_NOTAVAIL );	/* Get rid of compiler warning */
	}

/* Open a device.  This is a common function called to create both the 
   internal system device objects and general devices */

static int openDevice( CRYPT_DEVICE *device,
					   const CRYPT_DEVICE_TYPE deviceType,
					   const char *name, const int nameLength, 
					   DEVICE_INFO **deviceInfoPtrPtr )
	{
	DEVICE_INFO *deviceInfoPtr;
	int status;

	/* Clear the return values */
	*device = CRYPT_ERROR;
	*deviceInfoPtrPtr = NULL;

	/* Create the device object and connect it to the device */
	status = krnlCreateObject( ( void ** ) &deviceInfoPtr, 
							   OBJECT_TYPE_DEVICE, SUBTYPE_ANY,
							   sizeof( DEVICE_INFO ), 0, 0, 
							   deviceMessageFunction );
	if( cryptStatusError( status ) )
		return( status );
	initResourceLock( deviceInfoPtr ); 
	lockResource( deviceInfoPtr ); 
	*deviceInfoPtrPtr = deviceInfoPtr;
	*device = deviceInfoPtr->objectHandle = status;
	deviceInfoPtr->type = deviceType;

	/* Set up the access information for the device and connect to it */
	switch( deviceType )
		{
		case CRYPT_DEVICE_NONE:
			status = setDeviceSystem( deviceInfoPtr );
			break;

		case CRYPT_DEVICE_FORTEZZA:
			status = setDeviceFortezza( deviceInfoPtr );
			break;

		case CRYPT_DEVICE_PKCS11:
			status = setDevicePKCS11( deviceInfoPtr, name, nameLength );
			break;

		default:
			assert( NOTREACHED );
		}
	if( cryptStatusOK( status ) )
		status = deviceInfoPtr->initDeviceFunction( deviceInfoPtr, name, 
													nameLength );
	if( cryptStatusOK( status ) && \
		deviceInfoPtr->createObjectFunctions == NULL )
		/* The device-specific code hasn't set up anything, use the default 
		   create-object functions (which just create encryption contexts 
		   using the device capability information) */
		deviceInfoPtr->createObjectFunctions = defaultCreateFunctions;

	return( status );
	}

/* Create a device object */

int createDevice( CREATEOBJECT_INFO *createInfo, const void *auxDataPtr,
				  const int auxValue )
	{
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfoPtr;
	int initStatus, status;

	assert( auxDataPtr == NULL );
	assert( auxValue == 0 );

	/* Perform basic error checking */
	if( createInfo->arg1 <= CRYPT_DEVICE_NONE || \
		createInfo->arg1 >= CRYPT_DEVICE_LAST )
		return( CRYPT_ARGERROR_NUM1 );
	if( createInfo->arg1 == CRYPT_DEVICE_PKCS11 && \
		createInfo->strArgLen1 <= 2 )
		return( CRYPT_ARGERROR_STR1 );

	/* Wait for any async device driver binding to complete */
	waitSemaphore( SEMAPHORE_DRIVERBIND );

	/* Pass the call on to the lower-level open function */
	initStatus = openDevice( &iCryptDevice, createInfo->arg1, 
							 createInfo->strArg1, createInfo->strArgLen1,
							 &deviceInfoPtr );
	if( deviceInfoPtr == NULL )
		return( initStatus );	/* Create object failed, return immediately */
	if( cryptStatusError( initStatus ) )
		/* The device open failed, make sure the object gets destroyed when 
		   we notify the kernel that the setup process is complete */
		krnlSendNotifier( iCryptDevice, RESOURCE_IMESSAGE_DESTROY );

	/* We've finished setting up the object-type-specific info, tell the 
	   kernel the object is ready for use */
	unlockResource( deviceInfoPtr );
	status = krnlSendMessage( iCryptDevice, RESOURCE_IMESSAGE_SETATTRIBUTE, 
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusError( initStatus ) || cryptStatusError( status ) )
		return( cryptStatusError( initStatus ) ? initStatus : status );
	createInfo->cryptHandle = iCryptDevice;
	return( CRYPT_OK );
	}

/* Create the internal system object.  This is somewhat special in that it 
   can't be destroyed through a normal message (it can only be done from one 
   place in the kernel) so if the open fails we don't use the normal 
   signalling mechanism to destroy it but simply return an error code to the 
   caller, which causes the cryptlib init to fail and destroys the object 
   when the kernel shuts down */

int createSystemObject( void )
	{
	CRYPT_DEVICE iSystemObject;
	DEVICE_INFO *deviceInfoPtr;
	int status;

	/* Pass the call on to the lower-level open function */
	status = openDevice( &iSystemObject, CRYPT_DEVICE_NONE, NULL, 0,
						 &deviceInfoPtr );
	if( deviceInfoPtr == NULL )
		return( status );	/* Create object failed, return immediately */
	if( cryptStatusError( status ) )
		{
		/* The device open failed, we'd normally have to signal the device 
		   object to destroy itself when the init completes, however we don't 
		   have the privileges to do this so we just pass the error code back 
		   to the caller which causes the cryptlib init to fail */
		unlockResource( deviceInfoPtr );
		return( status );
		}
	assert( iSystemObject == SYSTEM_OBJECT_HANDLE );

	/* We've finished setting up the object-type-specific info, tell the 
	   kernel the object is ready for use */
	unlockResource( deviceInfoPtr );
	return( krnlSendMessage( iSystemObject, RESOURCE_IMESSAGE_SETATTRIBUTE, 
							 MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS ) );
	}

/* Peform an extended control function on the device */

C_RET cryptDeviceControlEx( C_IN CRYPT_DEVICE device,
							C_IN CRYPT_ATTRIBUTE_TYPE controlType,
							C_IN void C_PTR data1, C_IN int data1Length,
							C_IN void C_PTR data2, C_IN int data2Length )
	{
	DEVICE_INFO *deviceInfoPtr;
	int status;

	/* Perform basic error checking */
	getCheckResource( device, deviceInfoPtr, OBJECT_TYPE_DEVICE,
					  CRYPT_ERROR_PARAM1 );
	if( controlType != CRYPT_DEVINFO_SET_AUTHENT_USER && \
		controlType != CRYPT_DEVINFO_SET_AUTHENT_SUPERVISOR )
		unlockResourceExit( deviceInfoPtr, CRYPT_ERROR_PARAM2 );
	if( data1 == NULL )
		unlockResourceExit( deviceInfoPtr, CRYPT_ERROR_PARAM3 );
	if( data1Length < 0 )
		unlockResourceExit( deviceInfoPtr, CRYPT_ERROR_PARAM4 );
	if( data2 == NULL )
		unlockResourceExit( deviceInfoPtr, CRYPT_ERROR_PARAM5 );
	if( data2Length < 0 )
		unlockResourceExit( deviceInfoPtr, CRYPT_ERROR_PARAM6 );

	/* Make sure the PIN sizes are valid */
	if( data1Length < deviceInfoPtr->minPinSize || \
		data1Length > deviceInfoPtr->maxPinSize )
		unlockResourceExit( deviceInfoPtr, CRYPT_ERROR_PARAM4 );
	if( data2Length < deviceInfoPtr->minPinSize || \
		data2Length > deviceInfoPtr->maxPinSize ) 
		unlockResourceExit( deviceInfoPtr, CRYPT_ERROR_PARAM6 );

	/* Send the control information to the device */
	status = deviceInfoPtr->controlFunction( deviceInfoPtr, controlType,
											 data1, data1Length,
											 data2, data2Length );
	unlockResourceExit( deviceInfoPtr, status );
	}
