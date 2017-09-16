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

/* Prototypes for functions in cryptkrn.c */

BOOLEAN beginInitialisation( const BOOLEAN checkState );
void endInitialisation( const BOOLEAN newState );
int initInternalFunctions( void );
int destroyObjects( void );
void endInternalFunctions( void );

/* Prototypes for functions in cryptcfg.c */

void initConfig( void );
void readConfig( void );
void endConfig( void );

/* Prototypes for functions in cryptcrt.c */

int initTrustInfo( void );
void endTrustInfo( void );

/* Prototypes for functions in cryptdev.c */

int createSystemObject( void );

/****************************************************************************
*																			*
*							Startup/Shutdown Routines						*
*																			*
****************************************************************************/

/* Initialisation/shutdown functions for other parts of the library */

void initDevices( void );
void shutdownDevices( void );
void initKeysets( void );
void shutdownKeysets( void );

/* There isn't any good place to put the networking init/shutdown code so we
   handle it ourselves here */

void netInitTCP( void );
void netEndTCP( void );

void initNetworking( void )
	{
#ifdef NET_TCP
	netInitTCP();
#endif /* NET_TCP */
	}

void shutdownNetworking( void )
	{
#ifdef NET_TCP
	netEndTCP();
#endif /* NET_TCP */
	}

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

	initKeysets();
	initDevices();
	initNetworking();
	clearSemaphore( SEMAPHORE_DRIVERBIND );
	_endthread();
	}

static void bindDrivers( void )
	{
	int asyncInit;

	/* Bind the drivers asynchronously or synchronously depending on the
	   config option setting */
	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
					 &asyncInit, CRYPT_OPTION_MISC_ASYNCINIT );
	if( asyncInit )
		{
		HANDLE hThread;

		/* Fire up the thread.  Note the use of _beginthread() rather than
		   _beginthreadex(), since we want the thread to close its own
		   handle when it terminates */
		hThread = ( HANDLE ) _beginthread( threadedBind, 0, NULL );
		if( hThread )
			{
			setSemaphore( SEMAPHORE_DRIVERBIND, hThread );
			return;
			}
		}
	initKeysets();
	initDevices();
	initNetworking();
	}

static void unbindDrivers( void )
	{
	/* Shut down any external interfaces after making sure that the 
	   initalisation ran to completion */
	waitSemaphore( SEMAPHORE_DRIVERBIND );
	shutdownKeysets();
	shutdownDevices();
	shutdownNetworking();
	}
#else

static void bindDrivers( void )
	{
	initKeysets();
	initDevices();
	initNetworking();
	}

static void unbindDrivers( void )
	{
	shutdownKeysets();
	shutdownDevices();
	shutdownNetworking();
	}
#endif /* __WIN32__ && !NT_DRIVER */

/* Test the kernel mechanisms to make sure everything's working as expected */

static BOOLEAN testKernelMechanisms( void )
	{
	CREATEOBJECT_INFO createInfo;
	RESOURCE_DATA msgData;
	CRYPT_CONTEXT cryptContext;
	static const BYTE key[] = { 0x10, 0x46, 0x91, 0x34, 0x89, 0x98, 0x01, 0x31 };
	BYTE buffer[ 8 ];
	int value, status;

	/* Verify object creation */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_DES );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( FALSE );
	cryptContext = createInfo.cryptHandle;

	/* Verify inability to access internal object using external message */
	if( krnlSendMessage( cryptContext, RESOURCE_MESSAGE_GETATTRIBUTE, 
						 &value, CRYPT_CTXINFO_ALGO ) != CRYPT_ARGERROR_OBJECT )
		{
		krnlSendNotifier( cryptContext, RESOURCE_IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}
	
	/* Verify inability to perform state=high operation on state=low object */
	if( krnlSendMessage( cryptContext, RESOURCE_IMESSAGE_CTX_ENCRYPT, 
						 buffer, 8 ) != CRYPT_ERROR_NOTINITED )
		{
		krnlSendNotifier( cryptContext, RESOURCE_IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	/* Verify ability to transition state=low object to state=high */
	setResourceData( &msgData, ( void * ) key, 8 );
	status = krnlSendMessage( cryptContext, RESOURCE_IMESSAGE_SETATTRIBUTE_S, 
							  &msgData, CRYPT_CTXINFO_KEY );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( cryptContext, RESOURCE_IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	/* Verify inability to perform state=low operations on state=high object.
	   These also test things like trying to load/generate a key into a non-
	   crypto context or non-native context since they're protected by the 
	   same state=high check in the kernel */
	status = krnlSendMessage( cryptContext, RESOURCE_IMESSAGE_SETATTRIBUTE_S, 
							  &msgData, CRYPT_CTXINFO_KEY );
	if( status == CRYPT_ERROR_PERMISSION )
		status = krnlSendMessage( cryptContext, RESOURCE_IMESSAGE_CTX_GENKEY, 
								  MESSAGE_VALUE_DEFAULT, FALSE );
	if( status != CRYPT_ERROR_PERMISSION )
		{
		krnlSendNotifier( cryptContext, RESOURCE_IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	/* Verify inability to perform disallowed action externally but still
	   perform it internally.  Note that the object does become very briefly 
	   visible externally at this point, but there's nothing which can be 
	   done with it */
	value = \
		MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_ENCRYPT, ACTION_PERM_NONE_EXTERNAL ) | \
		MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_DECRYPT, ACTION_PERM_NONE_EXTERNAL );
	krnlSendMessage( cryptContext, RESOURCE_IMESSAGE_SETATTRIBUTE, &value, 
					 CRYPT_IATTRIBUTE_ACTIONPERMS );
	krnlSendMessage( createInfo.cryptHandle, RESOURCE_IMESSAGE_SETATTRIBUTE,
					 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_INTERNAL );
	if( krnlSendMessage( cryptContext, RESOURCE_MESSAGE_CTX_ENCRYPT, 
						 buffer, 8 ) != CRYPT_ERROR_PERMISSION || \
		krnlSendMessage( cryptContext, RESOURCE_IMESSAGE_CTX_ENCRYPT, 
						 buffer, 8 ) != CRYPT_OK )
		{
		krnlSendNotifier( cryptContext, RESOURCE_IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	/* Verify ability to use object with a finite usage count and inability 
	   to exceed the usage count */
	value = 1;
	status = krnlSendMessage( cryptContext, RESOURCE_IMESSAGE_SETATTRIBUTE,
							  &value, CRYPT_PROPERTY_USAGECOUNT );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( cryptContext, RESOURCE_IMESSAGE_CTX_ENCRYPT, 
								  buffer, 8 );
	if( cryptStatusError( status ) || \
		krnlSendMessage( cryptContext, RESOURCE_IMESSAGE_CTX_ENCRYPT, 
						 buffer, 8 ) != CRYPT_ERROR_PERMISSION )
		{
		krnlSendNotifier( cryptContext, RESOURCE_IMESSAGE_DECREFCOUNT );
		return( FALSE );
		}

	krnlSendNotifier( cryptContext, RESOURCE_IMESSAGE_DECREFCOUNT );
	return( TRUE );
	}

/* Initialise and shut down the system */

static int initCrypt( void )
	{
	int initLevel = 0, status;

	/* If the Win32 version is being compiled as a static .LIB (not
	   recommended) we need to perform initialisation here.  Note that in
	   this form cryptlib is no longer thread-safe */
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
	   the randomness pseudo-device */
	initConfig();
	status = initInternalFunctions();
	if( cryptStatusOK( status ) )
		{
		/* Internal functions initialised, create the system object */
		initLevel++;
		status = createSystemObject();
		}
	if( cryptStatusOK( status ) )
		{
		/* System object created, read the config options and initialise the 
		   certificate trust info (we have to initialise the trust info first 
		   because reading the config options typically also reads in any 
		   saved trust information).  We ignore any return codes at this 
		   point because we don't want all of cryptlib to fail because of a 
		   problem in the config file - if there's a problem we fall back to 
		   internal defaults */
		initLevel++;
		initTrustInfo();
		readConfig();
		bindDrivers();
		}

	/* Everything's set up, verify that the kernel's security mechanisms
	   are working as required */
	if( cryptStatusOK( status ) )
		testKernelMechanisms();

	/* If anything failed, shut down the internal functions and services
	   before we exit - this can only happens under exception circumstances,
	   because of this and because undoing the async.driver bind is rather 
	   complex we don't bother with this (the OS will undo it anyway when 
	   we're unloaded) */
	if( !cryptStatusOK( status ) )
		{
		if( initLevel >= 2 )
			{
			endTrustInfo();
			destroyObjects();
			}
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

C_RET cryptInit( void )
	{
	return( initCrypt() );
	}

C_RET cryptEnd( void )
	{
	int status;

	/* If we've already been shut down, don't do anything */
	if( !beginInitialisation( FALSE ) )
		return( CRYPT_OK );

	/* Clean up all resources.  The order in which the cleanup is performed
	   is based on dependencies of one layer of services upon lower layers:

		trustInfo -> cert/context objects
		random -> device objects
		device objects -> drivers

	   and everything relies on the kernel itself which is shut down by the
	   endInternalFunctions() call */
	endTrustInfo();
	status = destroyObjects();
	unbindDrivers();
	endInternalFunctions();
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
*						Client/Server Interface Routines					*
*																			*
****************************************************************************/

/* If we're running in our own address space (either in another VM or on
   separate hardware), we need to have some sort of client/server mechanism 
   to communicate with processes running in the applications address space.  
   The following section implements the server-side interface for various 
   environments */

#ifdef USE_CLIENT_SERVER

/* Prototypes for functions in cryptsvr.c */

// Currently it's all done locally (cryptsvr_client calls cryptsvr_server
// directly), someone else can fight with these daemons...

#if defined( __UNIX__ )

#include <sys/un.h>

#define DAEMON_NAME			"cryptd"
#define DAEMON_SOCKET_NAME	"/dev/crypt"
#define DAEMON_NO_THREADS	10

int getUserData( XXX YYYhandle, void *buffer, int length? )
	{
	int status;

// read(), write() might get an EINTR if the process is blocked in one of 
// these and catches a signal at that point, see p.124.
	status = read( YYYhandle, buffer, length );
	if( status == EWOULDBLOCK )
		; // Read timed out, return error?  Assume the client has stalled.
	}

/* Per-thread main function */

static MUTEX acceptMutex;			/* Mutex for accept() */
static int sockfd;					/* Socket for accept() */
static BOOLEAN doShutdown = FALSE;	/* Signal for threads to shut down */
static int activeThreads = 0;		/* No.of currently active threads */

THREADFUNC_DEFINE( threadedMain, dummy )
	{
	while( TRUE )
		{
		int connfd;

		/* Some implementations don't handle threads blocking in accept() too
		   well, and in any case managing the thundering herd in user space 
		   is a lot more efficient than doing it in the kernel, so we 
		   explicitly manage locking ourselves with a mutex.  
		   
		   If we've been told to shut down, we don't try the accept() but 
		   just drop through to the shutdown check afterwards.  This 
		   decrements the activeThreads counter, the last thread out turns 
		   off the lights.  The way the shutdown works is that the accept()
		   fails (due to the socket being closed) and the thread falls out of
		   the accept lock/unlock, at which point either it passes into the
		   shutdown lock/unlock and exits or (rarely) it gets preempted and 
		   the next thread passes through the accept lock/unlock.  In the 
		   most extreme case the accept mutex pileup moves down to the exit 
		   mutex, but in either case all threads eventually terminate.  The
		   only time the daemon might shut down improperly is if a thread is
		   in the middle of a long-running keygen and keeps everything else
		   active.  There isn't really any clean way to handle this, and in
		   any case if the system is about to shut down there probably won't
		   be anything left running to pick up the pieces */
		MUTEX_LOCK( &acceptMutex );
		if( !doShutdown )
			connfd = accept( sockfd, NULL, 0 );
		MUTEX_UNLOCK (&acceptMutex );
		if( doShutdown )
			{
			MUTEX_LOCK( &acceptMutex );
			activeThreads--;
			if( !activeThreads )
				cryptEnd();
			MUTEX_UNLOCK (&acceptMutex );
			THREAD_EXIT();
			}

		if( connfd == -1 )
			{
			/* If we got zapped by a signal, continue where we left off */
			if( errno == EINTR )
				continue;

			/* If we got caught by a RST for an established connection before 
			   accept() got called, the connection will be aborted, in which
			   case we just continue */
			if( errno == ECONNABORTED )
				continue;
			
// Now what?
			}

		/* Get the request type and make sure it's valid */
		/* ... */

		/* Dispatch the request */
		status = dispatchRequest( request.UserDefined, request.RequestID );

		/* Clean up */
		close( connfd );
		}
	}

/* Set up the daemon and fire up the thread pool */

void sigTermFunction( int dummy )
	{
	/* Signal all active threads to die and close the socket, which forces
	   accept() to fail, guaranteeing that a thread doesn't remain blocked
	   in the call */
	doShutdown = TRUE;
	close( socket );
	}

int main( int argc, char *argv[] )
	{
	THREAD threadPool[ DAEMON_NO_THREADS ];
	const struct rlimit rl = { 0, 0 };
	struct sockaddr_un sockAddr;
	struct timeval tv;
	char *socketName, *errorString = NULL;
	int fd, status;

	/* Start logging our status */
	openlog( DAEMON_NAME, 0, LOG_DAEMON );
	syslog( LOG_INFO, DAEMON_NAME "started" );

// Should we be doing logging this early?
	/* Check that everything is OK */
	if( argc > 2 )
		errorString = "usage: " DAEMON_NAME " <server socket pathname>";
	else
		{
		socketName = ( argc == 2 ) ? argv[ 1 ] : DAEMON_SOCKET_NAME;
		if( strlen( socketName > 100 )
			errorString = DAEMON_NAME ": Socket pathname too long";
		else
			if( access( socketName, F_OK )
				errorString = DAEMON_NAME ": Socket already exists";
		}
	if( errorString != NULL )
		{
		syslog( LOG_ERR, errorString );
		closelog();
		exit( EXIT_FAILURE );
		}

	/* Turn ourselves into a daemon by forking a new process and killing its 
	   parent.  After this sequence of operations, we're a daemon owned by 
	   init */
	if( ( status = fork() ) < 0 )
		{
		syslog( LOG_ERR, "%m" );
		closelog();
		exit( EXIT_FAILURE );
		}
	if( status )
		exit( EXIT_SUCCESS ); /* Exit if we're the parent */

// Is setsid() portable enough?  What does it do to our privs?  Can we still
// call mlock() after this?
#if 1
	/* Create a new session with ourselves as the session leader and no
	   controlling TTY, ignore SIGHUP, and fork again.  This is necessary
	   because when a session leader without a controlling terminal opens a
	   terminal device, it gets assigned as its controlling TTY.  By forking
	   a second time, we make sure the child is no longer a session leader.
	   The reason we need to ignore SIGHUP is because when the first-level
	   child (the session leader) exits, the second-level child (just another
	   process in the session) will be SIGHUP'd */
	setsid();
	signal( SIGHUP, SIG_IGN );
	if( ( status = fork() ) != 0 )
		exit( EXIT_SUCCESS );
#else
	/* Detach ourselves from the controlling TTY to avoid interruptions and
	   move into our own process group to avoid mass murders */
	fd = open( "/dev/tty", O_RDWR );
	ioctl( fd, TIOCNOTTY, 0 );
	close( fd );
	setpgrp( 0, getpid() );
#endif /* 1 */

	/* Close all inherited file descriptors */
	for( fd = getdtablesize() - 1; fd >= 0; fd-- )
		close( fd );

	/* Move to a (safe) standard directory, set our umask to make sure our 
	   files are kept private (although the cryptlib streams module does this 
	   anyway), and point the stdin, stdout, and stderr streams to the null 
	   device in case library routines try and do any I/O */
	chdir( "/tmp" );
	umask( 0177 );      /* Owner RW access only */
	fd = open( "/dev/null", O_RDWR );   /* stdin = 0 */
	dup( fd );                          /* stdout = 1 */
	dup( fd );                          /* stderr = 2 */

	/* Make sure we can never dump core (we really, *really* don't want to do
	   this) */
	setrlimit( RLIMIT_CORE, &rl );

	/* Go catatonic */
	signal( SIG_IGN, SIGHUP );

	/* Create a domain socket and wait for connections */
	memset( sockAddr, 0, sizeof( struct sockaddr_un ) );
	strcpy( sockAddr.sun_path, socketName );
	status = sockfd = socket( AF_LOCAL, SOCK_STREAM, 0 );
	if( status != -1 )
		status = bind( sockfd, ( SA * ) &sockAddr, SUN_LEN( &sockAddr ) );
	if( status != -1 )
		status = listen( sockfd, 5 );
	if( status == -1 )
		{
		syslog( LOG_ERR, "%m" );
		closelog();
		exit( EXIT_FAILURE );
		}
	
	/* Set the socket timeout to 5 seconds to make sure we don't block 
	   forever if a client hangs */
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	setsockopt( sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, 
				sizeof( struct timeval ) );
	setsockopt( sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, 
				sizeof( struct timeval ) );

	/* Initialise the crypto code */
	status = cryptInitEx();
	if( cryptStatusError( status ) )
		{
		syslog( LOG_ERR, "Crypto initialisation failed" );
		closelog();
		exit( EXIT_FAILURE );
		}

	/* Make sure that if we get killed by init, we shut down cleanly */
	signal( sigTermFunction, SIGTERM );

	/* Start up the thread pool.  We hold the accept() mutex while we're
	   doing this to ensure that it's an all-or-nothing start, in other
	   words that there are no threads accepting commands while there's
	   still a chance that the init could be aborted */
	MUTEX_INIT( &acceptMutex );
	MUTEX_LOCK( &acceptMutex );
	for( i = 0; i < DAEMON_NO_THREADS; i++ )
		{
		status = THREAD_CREATE( &threadMain, NULL );
		if( THREAD_STATUS( status ) != CRYPT_OK )
			break;
		activeThreads++;
		}
	if( cryptStatusError( status ) )
		{
		/* Signal any threads which got started to terminate immediately */
		doShutdown = TRUE;
		close( socket );
		MUTEX_UNLOCK (&acceptMutex );

		syslog( LOG_ERR, "Thread pool initialisation failed" );
		closelog();
		exit( EXIT_FAILURE );
		}
	MUTEX_UNLOCK (&acceptMutex );

	/* We're ready to talk, make the socket path accessible to others (the
	   umask will have made it inaccessible, which is fine since we don't
	   want anyone poking messages at us while we're initialising) */
	chmod( socketName, 0666 );

	/* Everything is done by the threads, so we just twiddle our thumbs */
	while( TRUE )
		pause();

	/* Clean up */
	MUTEX_DESTROY( &acceptMutex );
	exit( EXIT_SUCCESS );	
	}

#elif defined( __WINDOWS__ )

#define SERVICE_NAME			"cryptd"
#define SERVICE_DISPLAY_NAME	"cryptlib Server"
#define SERVICE_PATH			"%SystemRoot%\\System32\\cryptd.exe"

SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE hServiceStatus;

/* Service control handler */

void WINAPI Handler( DWORD fdwControl )
	{
	switch( fdwControl )
		{
		case SERVICE_CONTROL_STOP:
			serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
			break;

		case SERVICE_CONTROL_SHUTDOWN:
			break;

		case SERVICE_CONTROL_INTERROGATE:
			; /* Fall through */
		}

	SetServiceStatus( hServiceStatus, &serviceStatus );
	}

/* Service-specific and generic main functions */

void WINAPI ServiceMain( DWORD dwArgc, LPTSTR *lpszArgv )
	{
	static const SERVICE_STATUS serviceStatusTemplate = {
		SERVICE_WIN32_OWN_PROCESS, SERVICE_START_PENDING, 
		SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN, 0, 0, 0, 0
		};
	int status;

	/* Register the service control handler and tell the SCM what we're 
	   doing */
	if( ( hServiceStatus = RegisterServiceCtrlHandler( SERVICE_NAME, 
													   Handler ) ) == 0 )
		return;
	serviceStatus = serviceStatusTemplate;
	SetServiceStatus( hServiceStatus, &serviceStatus );

	/* Initialise cryptlib */
	status = cryptInitEx();
	if( cryptStatusError( status ) )
		{
		serviceStatus.dwCurrentState = SERVICE_STOPPED;
		serviceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
		serviceStatus.dwServiceSpecificExitCode = status;
		SetServiceStatus( hServiceStatus, &serviceStatus );
		return;
		}
	serviceStatus.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus( hServiceStatus, &serviceStatus );
	}

int main( int argc, char *argv[] )
	{
	static const SERVICE_TABLE_ENTRY serviceTable[] = {
		{ TEXT( SERVICE_NAME ), ServiceMain }, { NULL, NULL } };

	if( argc > 2 )
		{
		puts( "Usage: "SERVICE_NAME " <install> <remove>" );
		exit( EXIT_FAILURE );
		}
	if( argc == 2 )
		{
		/* Handle service installation */
		if( !stricmp( argv[ 1 ], "install" ) )
			{
			SC_HANDLE schSCM, schService;

			/* Try and install the service */
			schSCM = OpenSCManager( NULL, NULL, SC_MANAGER_CREATE_SERVICE );
			if( schSCM == NULL )
				{
				perror( SERVICE_NAME );
				exit( EXIT_FAILURE );
				}
			schService = CreateService( schSCM, TEXT( SERVICE_NAME ),
							TEXT( SERVICE_DISPLAY_NAME ), SERVICE_ALL_ACCESS, 
//							SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
// For debugging we make it demand-start
							SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
							SERVICE_ERROR_NORMAL, SERVICE_PATH, NULL, NULL, 
							NULL, NULL, NULL );
			if( schService == NULL )
				{
				CloseServiceHandle( schSCM );
				if( GetLastError() == ERROR_SERVICE_EXISTS )
					puts( "The service is already installed.  To reinstall, "
						  "stop the service with\n'net stop " SERVICE_NAME "', "
						  "remove the current service with\n'" SERVICE_NAME " "
						  "remove', and rerun the install." );
				else
					perror( SERVICE_NAME );
				exit( EXIT_FAILURE );
				}
			CloseServiceHandle( schService );
			CloseServiceHandle( schSCM );

			puts( SERVICE_NAME " service successfully installed." );
			exit( EXIT_SUCCESS );
			}

		/* Handle service removal */
		if( !stricmp( argv[ 1 ], "remove" ) )
			{
			SC_HANDLE schSCM, schService;
			SERVICE_STATUS removeServiceStatus;

			/* Open the service */
			schSCM = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );
			if( schSCM == NULL )
				{
				perror( SERVICE_NAME );
				exit( EXIT_FAILURE );
				}
			schService = OpenService( schSCM, SERVICE_NAME, DELETE );
			if( schService == NULL )
				{
				CloseServiceHandle( schSCM );
				perror( SERVICE_NAME );
				exit( EXIT_FAILURE );
				}

			/* If the service is currently running, stop it before we try to
			   remove it.  Note that we use ControlService() to determine its
			   status rather than QueryServiceStatus() since the former 
			   returns the actual state while the latter only returns the 
			   state last reported to the SCM, which means the service could 
			   already be stopped without the SCM realising it (probably one 
			   of the reasons why it seems to take ages to stop even the 
			   simplest service) */
			ControlService( schService, SERVICE_CONTROL_INTERROGATE, 
							&removeServiceStatus );
			if( removeServiceStatus.dwCurrentState != SERVICE_STOPPED )
				{
				printf( "Stopping " SERVICE_DISPLAY_NAME );
				ControlService( schService, SERVICE_CONTROL_STOP, 
								&removeServiceStatus );
				do
					{
					putchar( '.' );
					Sleep( 1000 );
					ControlService( schService, SERVICE_CONTROL_INTERROGATE, 
									&removeServiceStatus );
					}
				while( removeServiceStatus.dwCurrentState == SERVICE_STOP_PENDING );
				}
			if( removeServiceStatus.dwCurrentState != SERVICE_STOPPED )
				{
				puts( "Couldn't stop " SERVICE_DISPLAY_NAME "." );
				CloseServiceHandle( schSCM );
				exit( EXIT_FAILURE );
				}

			/* The service is stopped, remove it */
			DeleteService( schService );
			CloseServiceHandle( schService );
			CloseServiceHandle( schSCM );

			puts( SERVICE_NAME " service successfully removed." );
			exit( EXIT_SUCCESS );
			}

		printf( "Unknown argument '%s'.\n", argv[ 1 ] );
		exit( EXIT_FAILURE );
		}

	/* Pass control on to the service's main().  Since this is a 
	   SERVICE_WIN32_OWN_PROCESS, we don't have to specify a name for it or
	   worry about much else */
	StartServiceCtrlDispatcher( serviceTable );
	}

#elif defined( __IBM4758__ )

#include <scc_err.h>
#include <scc_int.h>

void main( void )	/* Because the docs say so, that's why */
	{
	const static sccAgentID_t agentID = { "\x06\x00", "cryptlib\x00\x00\x00", 0x21, 0x00, 0x00 };
	sccRequestHeader_t request;
	long status;
	int initStatus;

	/* Register ourselves with the SCC manager */
	status = sccSignOn( ( sccAgentID_t * ) &agentID, NULL );
	if( status != PPDGood )
		exit( status );

	/* If we're running in debug mode, we have to make sure we don't start
	   running before the debugger can attach to the process.  The following
	   infinite loop just yields our timeslice back to the OS, to move past
	   it set a breakpoint on the i++ and then use 'Jump to location' to
	   break out of the loop */
#ifdef _DEBUG
	{
	long i = 0, j = 1;

	while( j )
		{
		CPYield();
		i++; if( !i ) j++;	/* Confound the optimiser */
		}
	}
#endif /* _DEBUG */

	/* Initialise cryptlib.  Normally this is done in response to a user
	   request, however we can do it when the device is started so that
	   everything's ready when the user needs it.  In the spirit of FIPS 140, 
	   we call cryptInitEx() rather than plain cryptInit() (this isn't that 
	   bad since many capabilities aren't present, all the slow stuff is 
	   being done in hardware, and the device isn't restarted that often 
	   anyway) */
	cryptInitEx();
	
	while( TRUE )
		{
		/* Wait for a request from the host system */
		status = sccGetNextHeader( &request, 0, SVCWAITFOREVER );
		if( status != PPDGood )
			break;
		
		/* Dispatch the message.  This just calls the built-in command 
		   dispatcher with the request type (ie the cryptlib function being
		   called) and a reference to the data source.  Once the request has 
		   been handled, the status value is passed back to the caller */
		status = dispatchRequest( request.UserDefined, request.RequestID );
		sccEndRequest( request.RequestID, 0, NULL, 0, status );
		}
	
	/* Clean up */
	cryptEnd();
	exit( PPDGood );
	}
#endif /* Client-server server-side code */

#endif /* USE_CLIENT_SERVER */

/****************************************************************************
*																			*
*						OS-Specific Support Routines						*
*																			*
****************************************************************************/

#if defined( __WINDOWS__ ) && !( defined( NT_DRIVER ) )

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

#elif defined( USE_CLIENT_SERVER )

/* If we're running as a service, it can't be Win95 so we just hardcode this 
   to FALSE */

BOOLEAN isWin95 = FALSE;

#else

BOOLEAN isWin95;

DEFINE_LOCKING_VARS( initialisation )

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved )
	{
	static DWORD dwPlatform = ( DWORD ) CRYPT_ERROR;

	UNUSED( hinstDLL );
	UNUSED( lpvReserved );

	switch( fdwReason )
		{
		case DLL_PROCESS_ATTACH:
			/* Figure out which OS we're running under */
			if( dwPlatform == ( DWORD ) CRYPT_ERROR )
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
