/****************************************************************************
*																			*
*							cryptlib Core Routines							*
*						Copyright Peter Gutmann 1992-1999					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypt.h"

/* Prototypes for functions in cryptcap.c */

int initCapabilities( const BOOLEAN doSelfTest );

/* Prototypes for functions in cryptkrn.c */

BOOLEAN beginInitialisation( const BOOLEAN checkState );
void endInitialisation( const BOOLEAN newState );
int initInternalFunctions( void );
int endInternalFunctions( void );

/* Prototypes for functions in cryptcfg.c */

void initConfig( void );
void endConfig( void );

/* Prototypes for functions in cryptcrt.c */

int initTrustInfo( void );
void endTrustInfo( void );

/* Prototypes for functions in lib_rand.c */

int initRandom( void );
void endRandom( void );

/****************************************************************************
*																			*
*							Error Reporting Routines						*
*																			*
****************************************************************************/

/* Get extended information on the last error encountered */

CRET cryptGetErrorInfo( const CRYPT_HANDLE cryptHandle, int CPTR errorCode,
						char CPTR errorString, int CPTR errorStringLength )
	{
	RESOURCE_DATA_EX msgDataEx;
	int status;

	/* Perform basic error checking */
	if( checkBadPtrWrite( errorCode, sizeof( int ) ) )
		return( CRYPT_BADPARM2 );
	*errorCode = CRYPT_ERROR;
	if( errorString != NULL )
		{
		if( checkBadPtrWrite( errorString, CRYPT_MAX_TEXTSIZE ) )
			return( CRYPT_BADPARM3 );	/* Buffer should be at least this big */
		*errorString = '\0';
		}
	if( checkBadPtrWrite( errorStringLength, sizeof( int ) ) )
		return( CRYPT_BADPARM4 );
	*errorStringLength = CRYPT_ERROR;

	/* Get the error info.  The length field of the first ( data, length )
	   pair in the message receives the error code, the second pair receives
	   the error string */
	setResourceDataEx( &msgDataEx, NULL, 0, errorString, 0 );
	status = krnlSendMessage( cryptHandle, RESOURCE_MESSAGE_GETDATA,
							  &msgDataEx, RESOURCE_MESSAGE_DATA_ERRORINFO,
							  CRYPT_BADPARM1 );
	if( cryptStatusError( status ) )
		return( status );
	*errorCode = msgDataEx.length1;
	*errorStringLength = msgDataEx.length2;

	return( status );
	}

/* Get the error message corresponding to a given error code */

CRET cryptGetErrorMessage( const int error, char CPTR message,
						   int CPTR messageLength )
	{
	static struct { const int error; const char *string; } errorStrings[] = {
		/* Internal errors */
		{ CRYPT_ERROR, "Nonspecific error" },
		{ CRYPT_SELFTEST, "Failed self-test" },

		/* Error in parameters passed to function */
		{ CRYPT_BADPARM, "Generic bad argument to function" },
		{ CRYPT_BADPARM1, "Bad argument, parameter 1" },
		{ CRYPT_BADPARM2, "Bad argument, parameter 2" },
		{ CRYPT_BADPARM3, "Bad argument, parameter 3" },
		{ CRYPT_BADPARM4, "Bad argument, parameter 4" },
		{ CRYPT_BADPARM5, "Bad argument, parameter 5" },
		{ CRYPT_BADPARM6, "Bad argument, parameter 6" },
		{ CRYPT_BADPARM7, "Bad argument, parameter 7" },
		{ CRYPT_BADPARM8, "Bad argument, parameter 8" },
		{ CRYPT_BADPARM9, "Bad argument, parameter 9" },
		{ CRYPT_BADPARM10, "Bad argument, parameter 10" },

		/* Errors due to insufficient resources */
		{ CRYPT_NOMEM, "Out of memory" },
		{ CRYPT_NOTINITED, "Data has not been initialised" },
		{ CRYPT_INITED, "Data has already been initialised" },
		{ CRYPT_NOSECURE, "Operation not available at requested security level" },
		{ CRYPT_NOALGO, "Algorithm unavailable" },
		{ CRYPT_NOMODE, "Encryption mode unavailable" },
		{ CRYPT_NOKEY, "Key not initialised" },
		{ CRYPT_NOIV, "IV not initialised" },
		{ CRYPT_NORANDOM, "No reliable random data available" },

		/* Security violations */
		{ CRYPT_NOTAVAIL, "Operation not available for this argument" },
		{ CRYPT_NOPERM, "No permission to perform this operation" },
		{ CRYPT_WRONGKEY, "Incorrect key used to decrypt data" },
		{ CRYPT_INCOMPLETE, "Operation incomplete/still in progress" },
		{ CRYPT_COMPLETE, "Operation complete/can't continue" },
		{ CRYPT_ORPHAN, "Contexts remained allocated" },
		{ CRYPT_BUSY, "Resource in use by asynchronous operation" },
		{ CRYPT_SIGNALLED, "Resource destroyed by external event" },

		/* High-level function errors */
		{ CRYPT_OVERFLOW, "Too much data supplied to function" },
		{ CRYPT_UNDERFLOW, "Not enough data supplied to function" },
		{ CRYPT_PKCCRYPT, "Public-key en/decryption failed" },
		{ CRYPT_BADDATA, "Bad data format in object" },
		{ CRYPT_BADSIG, "Bad signature on data" },
		{ CRYPT_INVALID, "Invalid/inconsistent information" },

		/* Data access function errors */
		{ CRYPT_DATA_OPEN, "Cannot open data object" },
		{ CRYPT_DATA_READ, "Cannot read item from data object" },
		{ CRYPT_DATA_WRITE, "Cannot write item to data object" },
		{ CRYPT_DATA_NOTFOUND, "Requested item not found in data object" },
		{ CRYPT_DATA_DUPLICATE, "Item already present in data object" },

		/* Data enveloping errors */
		{ CRYPT_ENVELOPE_RESOURCE, "Need resource to proceed" },
		{ 1000, NULL }
		};
	int i;

	/* Perform basic error checking */
	if( message != NULL )
		*message = '\0';
	if( checkBadPtrWrite( messageLength, sizeof( int ) ) )
		return( CRYPT_BADPARM3 );
	*messageLength = CRYPT_ERROR;

	/* Try and map the error code to an error message */
	for( i = 0; errorStrings[ i ].error != 1000; i++ )
		if( errorStrings[ i ].error == error )
			{
			*messageLength = strlen( errorStrings[ i ].string ) + 1;
			if( message != NULL )
				{
				if( checkBadPtrWrite( messageLength, *messageLength ) )
					return( CRYPT_BADPARM2 );
				strcpy( message, errorStrings[ i ].string );
				}
			return( CRYPT_OK );
			}

	return( CRYPT_BADPARM1 );
	}

/****************************************************************************
*																			*
*							Startup/Shutdown Routines						*
*																			*
****************************************************************************/

/* Initialisation/shutdown functions for other parts of the library */

int gfInit( void );	/* Redefine here to avoid pulling in ECC headers */
void gfQuit( void );
void initReaders( void );
void shutdownReaders( void );
void initDevices( void );
void shutdownDevices( void );
void initDBX( void );
void shutdownDBX( void );

/* Under various OS's we bind to a number of drivers at runtime.  We can
   either do this sychronously or, under Win32, asynchronously (depending on
   the setting of a config option).  By default we use the async init since
   it speeds up the startup.  Synchronisation is achieved by having the open/
   init functions in the modules which require the drivers call
   waitSemaphore() on the driver binding semaphore, which blocks until the
   drivers are bound if an async bind is in progress, or returns immediately
   if no bind is in progress */

#if defined( __WIN32__ ) && !defined( NT_DRIVER )

#include <process.h>

void threadedBind( void *dummy )
	{
	UNUSED( dummy );

	initDBX();
	initReaders();
	initDevices();
	clearSemaphore( SEMAPHORE_DRIVERBIND );
	_endthread();
	}

static void bindDrivers( void )
	{
	/* Bind the drivers asynchronously or synchronously depending on the
	   config option setting */
	if( getOptionNumeric( CRYPT_OPTION_MISC_ASYNCINIT ) )
		{
		HANDLE hThread;

		/* Fire up the thread.  Note the use of _beginthread() rather than
		   _beginthreadex(), since we want the thread to close its own
		   handle when it terminates */
		hThread = ( HANDLE ) _beginthread( &threadedBind, 0, NULL );
		if( hThread )
			{
			setSemaphore( SEMAPHORE_DRIVERBIND, hThread );
			return;
			}
		}
	initDBX();
	initReaders();
	}

static void unbindDrivers( void )
	{
	/* Shut down any external interfaces after making sure that the 
	   initalisation ran to completion */
	waitSemaphore( SEMAPHORE_DRIVERBIND );
	shutdownDBX();
	shutdownReaders();
	shutdownDevices();
	}
#else

static void bindDrivers( void )
	{
	initDBX();
	initReaders();
	initDevices();
	}

static void unbindDrivers( void )
	{
	shutdownDBX();
	shutdownReaders();
	shutdownDevices();
	}
#endif /* __WIN32__ && !NT_DRIVER */

/* Initialise and shut down the encryption library */

static int initCrypt( const BOOLEAN doSelfTest )
	{
	int initLevel = 0, status = CRYPT_OK;

	/* If the Win32 version is being compiled as a static .LIB (not
	   recommended) we need to perform initialisation here.  Note that in
	   this form the library is no longer thread-safe */
#if defined( __WIN32__ ) && defined( STATIC_LIB )
	static DWORD dwPlatform = ( DWORD ) CRYPT_ERROR;

	/* Figure out which OS we're running under */
	if( dwPlatform == CRYPT_ERROR )
		{
		OSVERSIONINFO osvi = { sizeof( osvi ) };

		GetVersionEx( &osvi );
		dwPlatform = osvi.dwPlatformId;
		isWin95 = ( dwPlatform == VER_PLATFORM_WIN32_WINDOWS ) ? TRUE : FALSE;

		/* Check for Win32s just in case someone tries to load the DLL under
		   it */
		if( dwPlatform == VER_PLATFORM_WIN32s )
			return( CRYPT_ERROR );
		}

	/* Set up the library initialisation lock */
	initGlobalResourceLock( initialisation );
#endif /* __WIN32__ && STATIC_LIB */

	/* If we've already been initialised, don't do anything */
	if( !beginInitialisation( TRUE ) )
		return( CRYPT_OK );

	/* VisualAge C++ doesn't set the TZ correctly */
#if defined( __IBMC__ ) || defined( __IBMCPP__ )
	tzset();
#endif /* VisualAge C++ */

	/* Set up the initial hardwired configuration options, the internal
	   resources (semaphores, message functions, and the object table), and
	   the randomness routines */
	initConfig();
	status = initInternalFunctions();
	if( cryptStatusOK( status ) )
		{
		initLevel++;	/* Internal functions initialised */
		status = initCapabilities( doSelfTest );
		if( cryptStatusOK( status ) )
			status = initRandom();
		}
	if( cryptStatusOK( status ) )
		{
		initLevel++;	/* Random data pool initialised */
#if 0	/* Not used in this version */
		gfInit();
#endif /* 0 */
		}
	if( cryptStatusOK( status ) )
		{
		initLevel++;	/* ECC functions intialised */

		/* Read the config options and initialise the certificate trust info.
		   (we have to initialise the trust info first because reading the
		   config options typically also reads in any saved trust
		   information).  We ignore any return codes at this point because we
		   don't want all of cryptlib to fail because of a misplaced
		   punctuation mark in a config file - if there's a problem we fall
		   back to internal defaults */
		initTrustInfo();
		cryptReadOptions();

		/* Bind the various drivers we use */
		bindDrivers();
		}

	/* If anything failed, shut down the internal functions and services
	   before we exit */
	if( !cryptStatusOK( status ) )
		{
		if( initLevel >= 3 )
			endTrustInfo();
		if( initLevel >= 2 )
			endRandom();
		if( initLevel >= 1 )
			endInternalFunctions();
		endConfig();
		endInitialisation( FALSE );
		return( status );
		}

	/* Unlock the initialisation state */
	endInitialisation( TRUE );
	return( CRYPT_OK );
	}

CRET cryptInit( void )
	{
	return( initCrypt( FALSE ) );
	}

CRET cryptInitEx( void )
	{
	return( initCrypt( TRUE ) );
	}

CRET cryptEnd( void )
	{
	int status;

	/* If we've already been shut down, don't do anything */
	if( !beginInitialisation( FALSE ) )
		return( CRYPT_OK );

	/* Shut down the ECC library */
#if 0	/* Not used in this version */
	gfQuit();
#endif /* 0 */

	/* Unbind the various drivers we use */
	unbindDrivers();

	/* Clean up all resources */
	endTrustInfo();
	endRandom();
	status = endInternalFunctions();
	endConfig();

	/* Unlock the initialisation state */
	endInitialisation( FALSE );

	/* If the Win32 version is being compiled as a static .LIB, we need to
	   perform the cleanup here.  Note that in this form the library is no
	   longer thread-safe */
#if defined( __WIN32__ ) && defined( STATIC_LIB )
	/* Delete the library initialisation lock */
	deleteGlobalResourceLock( initialisation );
#endif /* __WIN32__ && STATIC_LIB */

	return( status );
	}

/****************************************************************************
*																			*
*						OS-Specific Support Routines						*
*																			*
****************************************************************************/

#if defined( __WINDOWS__ ) && !defined( NT_DRIVER )

/* WinMain() and WEP() under Win16 are intended for DLL initialisation,
   however it isn't possible to reliably do anything terribly useful in these
   routines.  The reason for this is that the WinMain/WEP functions are
   called by the windows module loader which has a very limited workspace
   which can cause peculiar behaviour for some functions (allocating/freeing
   memory and loading other modules from these routines is unreliable), the
   order in which WinMain() and WEP() will be called for a set of DLL's is
   unpredictable (sometimes WEP doesn't seem to be called at all), and they
   can't be tracked by a standard debugger.  This is why MS have
   xxxRegisterxxx() and xxxUnregisterxxx() functions in their DLL's.

   Under Win16 on a Win32 system this isn't a problem because the module
   loader has been rewritten to work properly, but it isn't possible to get
   reliable performance under pure Win16, so the DLL entry/exit routines here
   do almost nothing, with the real work being done in cryptInit()/
   cryptEnd() */

#ifdef __WIN16__

HWND hInst;

int CALLBACK LibMain( HINSTANCE hInstance, WORD wDataSeg, WORD wHeapSize, \
					  LPSTR lpszCmdLine )
	{
	/* Remember the proc instance for later */
	hInst = hInstance;

	return( TRUE );
	}

int CALLBACK WEP( int nSystemExit )
	{
	switch( nSystemExit )
		{
		case WEP_SYSTEM_EXIT:
			/* System is shutting down */
			break;

		case WEP_FREE_DLL:
			/* DLL reference count = 0, DLL-only shutdown */
			break;
		}

	return( TRUE );
	}

#else

HANDLE hInst;
BOOLEAN isWin95;

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved )
	{
	static DWORD dwPlatform = ( DWORD ) CRYPT_ERROR;

	UNUSED( lpvReserved );

	switch( fdwReason )
		{
		case DLL_PROCESS_ATTACH:
			/* Remember the instance handle */
			hInst = hinstDLL;

			/* Figure out which OS we're running under */
			if( dwPlatform == CRYPT_ERROR )
				{
				OSVERSIONINFO osvi = { sizeof( osvi ) };

				GetVersionEx( &osvi );
				dwPlatform = osvi.dwPlatformId;
				isWin95 = ( dwPlatform == VER_PLATFORM_WIN32_WINDOWS ) ? \
							TRUE : FALSE;

				/* Check for Win32s just in case someone tries to load the
				   DLL under it */
				if( dwPlatform == VER_PLATFORM_WIN32s )
					return( FALSE );
				}

			/* Set up the library initialisation lock */
			initGlobalResourceLock( initialisation );
			break;

		case DLL_PROCESS_DETACH:
			/* Delete the library initialisation lock */
			deleteGlobalResourceLock( initialisation );
			break;

		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
			break;
		}

	return( TRUE );
	}
#endif /* __WIN16__ */
#endif /* __WINDOWS__ && !NT_DRIVER */
