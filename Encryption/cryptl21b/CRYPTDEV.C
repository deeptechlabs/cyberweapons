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

/* Some device types aren't supported on some platforms, so we replace a
   call to the mapping function with an error code.  PKCS #11 is actually
   supported on platforms other than Win32, but drivers for these are
   virtually nonexistant, if anyone does manage to locate any we'll leave
   it to them to enable their use */

#ifndef __WINDOWS__
  #define setDeviceCEI( x )				CRYPT_BADPARM2
  #define setDeviceFortezza( x )		CRYPT_BADPARM2
#endif /* !__WINDOWS__ */
#ifndef __WIN32__
  #define setDevicePKCS11( x, y )		CRYPT_BADPARM2
#endif /* __WIN32__ */

/* Prototypes for functions in crypt.c */

void copyCapabilityInfo( const void FAR_BSS *capabilityInfoPtr,
						 CRYPT_QUERY_INFO *cryptQueryInfo );

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Initialise and down any devices we're working with */

void deviceInitCEI( void );
void deviceEndCEI( void );
void deviceInitFortezza( void );
void deviceEndFortezza( void );
void deviceInitPKCS11( void );
void deviceEndPKCS11( void );

void initDevices( void )
	{
#if defined( __WINDOWS__ ) && !defined( NT_DRIVER )
	deviceInitCEI();
	deviceInitFortezza();
  #ifdef __WIN32__
	deviceInitPKCS11();
  #endif /* __WIN32__ */
#endif /* __WINDOWS__ && !NT_DRIVER */
	}

void shutdownDevices( void )
	{
#if defined( __WINDOWS__ ) && !defined( NT_DRIVER )
	deviceEndCEI();
	deviceEndFortezza();
  #ifdef __WIN32__
	deviceEndPKCS11();
  #endif /* __WIN32__ */
#endif /* __WINDOWS__ && !NT_DRIVER */
	}

/****************************************************************************
*																			*
*								Device API Functions						*
*																			*
****************************************************************************/

/* Handle a message sent to a device object */

static int deviceMessageFunction( const CRYPT_DEVICE cryptDevice,
								  const RESOURCE_MESSAGE_TYPE message,
								  void *messageDataPtr,
								  const int messageValue,
								  const int errorCode )
	{
	DEVICE_INFO *deviceInfoPtr;
	int status = errorCode;

	getCheckInternalResource( cryptDevice, deviceInfoPtr, RESOURCE_TYPE_DEVICE );

	/* Process the destroy object message */
	if( message == RESOURCE_MESSAGE_DESTROY )
		{
		/* Delete all objects created via this device */
		krnlSendBroadcast( RESOURCE_TYPE_CRYPT,
						   RESOURCE_MESSAGE_PARTIAL_DESTROY, NULL, 0, 0 );

		/* We've finished deleting the objects data, mark it as partially
		   destroyed, which ensures that any further attempts to access it
		   fail.  This avoids a race condition where other threads may try
		   to use the partially-destroyed object after we unlock it but
		   before we finish destroying it, note that we set the urgent flag
		   to ensure that the status change is processed immediately rather
		   than being queued until after the current (destroy) message has
		   been processed */
		status = CRYPT_SIGNALLED;
		krnlSendMessage( cryptDevice,
						 RESOURCE_MESSAGE_SETPROPERTY | RESOURCE_MESSAGE_URGENT,
						 &status, RESOURCE_MESSAGE_PROPERTY_STATUS, 0 );

		/* Delete the objects locking variables and the object itself */
		unlockResource( deviceInfoPtr );
		deleteResourceLock( deviceInfoPtr );
		zeroise( deviceInfoPtr, sizeof( DEVICE_INFO ) );
		free( deviceInfoPtr );

		return( CRYPT_OK );
		}

	/* Process the increment/decrement object reference count message */
	if( message == RESOURCE_MESSAGE_INCREFCOUNT )
		{
		/* Increment the objects reference count */
		deviceInfoPtr->refCount++;

		status = CRYPT_OK;
		}
	if( message == RESOURCE_MESSAGE_DECREFCOUNT )
		{
		/* If we're already at a single reference, destroy the object */
		if( !deviceInfoPtr->refCount )
			krnlSendNotifier( cryptDevice, RESOURCE_IMESSAGE_DESTROY );
		else
			/* Decrement the objects reference count */
			deviceInfoPtr->refCount--;

		status = CRYPT_OK;
		}

	/* Process messages which get data from the object */
	if( message == RESOURCE_MESSAGE_GETDATA )
		{
		RESOURCE_DATA_EX *msgDataEx = ( RESOURCE_DATA_EX * ) messageDataPtr;

		status = CRYPT_OK;

		switch( messageValue )
			{
			case RESOURCE_MESSAGE_DATA_DEVICE:
				*( ( int * ) messageDataPtr ) = cryptDevice;
				status = CRYPT_OK;
				break;

			case RESOURCE_MESSAGE_DATA_ERRORINFO:
				msgDataEx->length1 = deviceInfoPtr->errorCode;
				if( msgDataEx->data2 != NULL )
					strcpy( msgDataEx->data1, deviceInfoPtr->errorMessage );
				msgDataEx->length2 = strlen( deviceInfoPtr->errorMessage ) + 1;
				break;

			case RESOURCE_MESSAGE_DATA_RANDOM:
				if( deviceInfoPtr->getRandomFunction == NULL )
					status = errorCode;
				else
					status = deviceInfoPtr->getRandomFunction( deviceInfoPtr,
											messageDataPtr, messageValue );
				break;

			default:
				status = errorCode;
			}
		}

	/* Process messages which lock/unlock an object for exclusive use */
	if( message == RESOURCE_MESSAGE_LOCK )
		/* Exit without unlocking the object.  Any other threads trying to
		   use the object after this point will be blocked */
		return( CRYPT_OK );
	if( message == RESOURCE_MESSAGE_UNLOCK )
		{
		/* "Wenn drei Leute in ein Zimmer reingehen und fuenf kommen raus,
			dann muessen erst mal zwei wieder reingehen bis das Zimmer lehr
			ist" */
		unlockResource( deviceInfoPtr );/* Undo RESOURCE_MESSAGE_LOCK lock */
		status = CRYPT_OK;
		}

	/* Process object-specific messages */
	if( message == RESOURCE_MESSAGE_DEV_GETCONTEXT )
		{
		RESOURCE_DATA_EX *msgDataEx = ( RESOURCE_DATA_EX * ) messageDataPtr;

		/* Create a context via a named data object in the device */
		if( deviceInfoPtr->instantiateNamedObjectFunction == NULL )
			status = errorCode;
		else
			status = deviceInfoPtr->instantiateNamedObjectFunction( deviceInfoPtr,
										msgDataEx->data1, msgDataEx->data2,
										msgDataEx->length2 );
		}

	unlockResourceExit( deviceInfoPtr, status );
	}

/* Open a device.  This is a common function called by the cryptDeviceOpen()
   functions */

static int openDevice( CRYPT_DEVICE *device,
					   const CRYPT_DEVICE_TYPE deviceType,
					   const char *param1, const char *param2,
					   const char *param3, const char *param4,
					   DEVICE_INFO **deviceInfoPtrPtr )
	{
	DEVICE_INFO *deviceInfoPtr;
	int status;

	/* Clear the return values */
	*device = CRYPT_ERROR;
	*deviceInfoPtrPtr = NULL;

	/* Wait for any async device driver binding to complete */
	waitSemaphore( SEMAPHORE_DRIVERBIND );

	/* Create the device object and connect it to the device */
	krnlCreateObject( status, deviceInfoPtr, RESOURCE_TYPE_DEVICE,
					  sizeof( DEVICE_INFO ), 0, deviceMessageFunction );
	if( cryptStatusError( status ) )
		return( status );
	*deviceInfoPtrPtr = deviceInfoPtr;
	*device = status;
	deviceInfoPtr->type = deviceType;
	deviceInfoPtr->objectHandle = status;

	/* If it's a smart card, try and open a session to the card */
	if( deviceType == CRYPT_DEVICE_SMARTCARD )
		{
		COMM_PARAMS commParams;

		/* Set up the pointers to the error information in the encapsulating
		   object */
		deviceInfoPtr->deviceScard.errorCode = &deviceInfoPtr->errorCode;
		deviceInfoPtr->deviceScard.errorMessage = deviceInfoPtr->errorMessage;

		/* Set up the appropriate access method pointers */
		if( !stricmp( param1, "ASE" ) )
			status = setAccessMethodASE( &deviceInfoPtr->deviceScard );
		else
		if( !stricmp( param1, "Auto" ) )
			status = setAccessMethodAuto( &deviceInfoPtr->deviceScard );
		else
		if( !stricmp( param1, "Gemplus" ) )
			status = setAccessMethodGemplus( &deviceInfoPtr->deviceScard );
		else
		if( !stricmp( param1, "Towitoko" ) )
			status = setAccessMethodTowitoko( &deviceInfoPtr->deviceScard );
		else
			status = CRYPT_BADPARM3;
		if( cryptStatusError( status ) )
			return( CRYPT_BADPARM3 );

		/* Set up the comms params if they're present */
		status = getCommParams( &commParams, param4, FALSE );
		if( status == CRYPT_BADPARM )
			status = CRYPT_BADPARM6;	/* Map to correct error code */
		if( cryptStatusError( status ) )
			return( status );

		/* Open a session to the reader and card.  If an error occurs we need
		   to map the scInitReader()-relative status codes to
		   cryptDeviceOpenEx()-relative codes */
		status = deviceInfoPtr->deviceScard.initReader( &deviceInfoPtr->deviceScard,
											  param2, param3, &commParams );
		if( cryptStatusError( status ) )
			return( ( status == CRYPT_BADPARM2 ) ? CRYPT_BADPARM4 : \
					( status == CRYPT_BADPARM3 ) ? CRYPT_BADPARM5 : status );

		return( status );
		}

	/* It's a specific type of device, set up the access information for it
	   and connect to it */
	switch( deviceType )
		{
		case CRYPT_DEVICE_CEI:
			status = setDeviceCEI( deviceInfoPtr );
			break;

		case CRYPT_DEVICE_FORTEZZA:
			status = setDeviceFortezza( deviceInfoPtr );
			break;

		case CRYPT_DEVICE_PKCS11:
			status = setDevicePKCS11( deviceInfoPtr, param1 );
			if( status == CRYPT_BADPARM2 )
				status = CRYPT_BADPARM3;	/* Map to correct value */
			break;

		default:
			status = CRYPT_ERROR;	/* Internal error, should never happen */
		}
	if( cryptStatusOK( status ) )
		status = deviceInfoPtr->initDeviceFunction( deviceInfoPtr );

	return( status );
	}

/* Open and close a device */

CRET cryptDeviceOpenEx( CRYPT_DEVICE CPTR device,
						const CRYPT_DEVICE_TYPE deviceType,
						const char CPTR param1, const char CPTR param2,
						const char CPTR param3, const char CPTR param4 )
	{
	DEVICE_INFO *deviceInfoPtr;
	int status;

	/* Perform basic error checking */
	if( checkBadPtrRead( device, sizeof( CRYPT_DEVICE ) ) )
		return( CRYPT_BADPARM1 );
	if( deviceType <= CRYPT_DEVICE_NONE || deviceType >= CRYPT_DEVICE_LAST )
		return( CRYPT_BADPARM2 );
	if( ( deviceType == CRYPT_DEVICE_SMARTCARD || \
		  deviceType == CRYPT_DEVICE_PKCS11 ) && \
		checkBadPtrRead( param1, 2 ) )
		return( CRYPT_BADPARM3 );

	/* Pass the call on to the lower-level open function */
	status = openDevice( device, deviceType, param1, param2, param3, param4,
						 &deviceInfoPtr );
	if( deviceInfoPtr == NULL )
		return( status );	/* Create object failed, return immediately */
	if( cryptStatusError( status ) )
		{
		/* The device was opened in an incomplete state, destroy it before
		   returning */
		unlockResource( deviceInfoPtr );
		krnlSendNotifier( *device, RESOURCE_IMESSAGE_DESTROY );
		*device = CRYPT_ERROR;
		return( status );
		}

	unlockResourceExit( deviceInfoPtr, CRYPT_OK );
	}

CRET cryptDeviceOpen( CRYPT_DEVICE CPTR device,
					  const CRYPT_DEVICE_TYPE deviceType,
					  const char CPTR name )
	{
	return( cryptDeviceOpenEx( device, deviceType, name, NULL, NULL, NULL ) );
	}

CRET cryptDeviceClose( const CRYPT_DEVICE device )
	{
	return( cryptDestroyObject( device ) );
	}

/* Get information on a given encryption capability */

CRET cryptDeviceQueryCapability( const CRYPT_DEVICE device,
								 const CRYPT_ALGO cryptAlgo,
								 const CRYPT_MODE cryptMode,
								 CRYPT_QUERY_INFO CPTR cryptQueryInfo )
	{
	DEVICE_INFO *deviceInfoPtr;
	const void FAR_BSS *capabilityInfo;
	int status;

	/* Perform basic error checking */
	getCheckResource( device, deviceInfoPtr, RESOURCE_TYPE_DEVICE,
					  CRYPT_BADPARM1 );
	if( cryptAlgo < CRYPT_ALGO_NONE || cryptAlgo >= CRYPT_ALGO_LAST )
		return( CRYPT_BADPARM2 );
	if( ( cryptMode < CRYPT_MODE_NONE || cryptMode >= CRYPT_MODE_LAST ) && \
		cryptMode != CRYPT_UNUSED )
		return( CRYPT_BADPARM3 );
	if( cryptQueryInfo != NULL )
		{
		if( checkBadPtrWrite( cryptQueryInfo, sizeof( CRYPT_QUERY_INFO ) ) )
			return( CRYPT_BADPARM4 );
		memset( cryptQueryInfo, 0, sizeof( CRYPT_QUERY_INFO ) );
		}

	/* Find the information for this algorithm and return the appropriate
	   information */
	status = deviceInfoPtr->findCapabilityFunction( deviceInfoPtr,
									&capabilityInfo, cryptAlgo, cryptMode );
	if( cryptStatusError( status ) || cryptQueryInfo == NULL )
		return( status );
	copyCapabilityInfo( capabilityInfo, cryptQueryInfo );
	return( CRYPT_OK );
	}

/* Create an encryption context via the device */

CRET cryptDeviceCreateContext( const CRYPT_DEVICE device,
							   CRYPT_CONTEXT CPTR cryptContext,
							   const CRYPT_ALGO cryptAlgo,
							   const CRYPT_MODE cryptMode )
	{
	DEVICE_INFO *deviceInfoPtr;
	int status;

	/* Perform basic error checking */
	getCheckResource( device, deviceInfoPtr, RESOURCE_TYPE_DEVICE,
					  CRYPT_BADPARM1 );
	if( checkBadPtrWrite( cryptContext, sizeof( CRYPT_CONTEXT ) ) )
		unlockResourceExit( deviceInfoPtr, CRYPT_BADPARM2 );
	*cryptContext = CRYPT_ERROR;
	if( cryptAlgo < CRYPT_ALGO_NONE || cryptAlgo >= CRYPT_ALGO_LAST )
		return( CRYPT_BADPARM3 );
	if( cryptMode < CRYPT_MODE_NONE || cryptMode >= CRYPT_MODE_LAST )
		return( CRYPT_BADPARM4 );

	/* Create the context via the device */
	status = deviceInfoPtr->createContextFunction( deviceInfoPtr,
										cryptContext, cryptAlgo, cryptMode );
	unlockResourceExit( deviceInfoPtr, status );
	}

/* Peform a control function on the device */

CRET cryptDeviceControlEx( const CRYPT_DEVICE device,
						   const CRYPT_DEVICECONTROL_TYPE controlType,
						   const void CPTR data1, const int data1Length,
						   const void CPTR data2, const int data2Length )
	{
	DEVICE_INFO *deviceInfoPtr;
	int status;

	/* Perform basic error checking */
	getCheckResource( device, deviceInfoPtr, RESOURCE_TYPE_DEVICE,
					  CRYPT_BADPARM1 );
	if( controlType < CRYPT_DEVICECONTROL_NONE || \
		controlType >= CRYPT_DEVICECONTROL_LAST )
		return( CRYPT_BADPARM2 );
	if( data1 == NULL )
		{
		if( data1Length != CRYPT_UNUSED )
			return( CRYPT_BADPARM4 );
		}
	else
		if( data1Length < 0 )
			return( CRYPT_BADPARM4 );
	if( data2 == NULL )
		{
		if( data2Length != CRYPT_UNUSED )
			return( CRYPT_BADPARM4 );
		}
	else
		if( data2Length < 0 )
			return( CRYPT_BADPARM4 );

	/* Perform any additional parameter checking.  We do this before doing
	   anything else to allow better error reporting */
	if( controlType == CRYPT_DEVICECONTROL_INITIALISE || \
		controlType == CRYPT_DEVICECONTROL_AUTH_USER || \
		controlType == CRYPT_DEVICECONTROL_AUTH_SUPERVISOR || \
		controlType == CRYPT_DEVICECONTROL_SET_AUTH_USER || \
		controlType == CRYPT_DEVICECONTROL_SET_AUTH_SUPERVISOR || \
		controlType == CRYPT_DEVICECONTROL_ZEROISE )
		{
		/* Make sure the PIN size is valid */
		if( data1Length < deviceInfoPtr->minPinSize || \
			data1Length > deviceInfoPtr->maxPinSize )
			return( CRYPT_BADPARM4 );
		if( ( controlType == CRYPT_DEVICECONTROL_SET_AUTH_USER || \
			  controlType == CRYPT_DEVICECONTROL_SET_AUTH_SUPERVISOR ) && \
			( data1Length < deviceInfoPtr->minPinSize || \
			  data1Length > deviceInfoPtr->maxPinSize ) )
			return( CRYPT_BADPARM6 );
		}


	/* Send the control information to the device */
	status = deviceInfoPtr->controlFunction( deviceInfoPtr, controlType,
											 data1, data1Length,
											 data2, data2Length );
	unlockResourceExit( deviceInfoPtr, status );
	}

CRET cryptDeviceControl( const CRYPT_DEVICE device,
						 const CRYPT_DEVICECONTROL_TYPE controlType,
						 const void CPTR data, const int dataLength )
	{
	return( cryptDeviceControlEx( device, controlType, data, dataLength,
								  NULL, CRYPT_UNUSED ) );
	}
