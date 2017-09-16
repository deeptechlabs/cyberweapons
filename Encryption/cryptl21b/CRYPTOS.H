/****************************************************************************
*																			*
*							cryptlib OS-specific Macros  					*
*						Copyright Peter Gutmann 1992-1999					*
*																			*
****************************************************************************/

#ifndef _CRYPTOS_DEFINED

#define _CRYPTOS_DEFINED

/* Check the validity of a pointer passed to a cryptlib function.  Usually
   the best we can do is check that it's not null, but some OS's allow for
   better checking than this, for example that it points to a block of
   readable or writeable memory */

#if defined( __WIN32__ )
  #define checkBadPtrRead( ptr, size )	IsBadReadPtr( ptr, size )
  #define checkBadPtrWrite( ptr, size )	IsBadWritePtr( ptr, size )
#endif /* __WIN32__ */

/* When working with secure memory we need to take the OS page size into
   account.  The following macro obtains the OS page size */

#if defined( __WIN32__ )
  /* This assumes Intel hardware, which is virtually always the case */
  #define getPageSize()			4096
#elif defined( __UNIX__ )
  #if defined( __hpux ) || defined( _M_XENIX ) || defined( __aux )
	#define getPageSize()		4096
  #else
	#define getPageSize()		getpagesize()
  #endif /* Unix variant-specific brokenness */
#endif /* OS-specifc page size determination */

/* Get the start address of a page and, given an address in a page and a
   size, determine on which page the data ends.  These are used to determine
   which pages a memory block covers.

   These macros have portability problems since they assume that
   sizeof( long ) == sizeof( void * ), but there's no easy way to avoid this
   since for some strange reason C doesn't allow the perfectly sensible use
   of logical operations on addresses */

#define getPageStartAddress( address ) \
			( ( long ) ( address ) & ~( getPageSize() - 1 ) )
#define getPageEndAddress( address, size ) \
			getPageStartAddress( ( long ) address + ( size ) - 1 )

/****************************************************************************
*																			*
*								Resource Handling Macros					*
*																			*
****************************************************************************/

/* In multithreaded environments we need to protect the information inside
   cryptlib data structures from access by other threads while we use it.
   The following macros handle this resource protection when we enter and
   exit cryptlib functions.  The initResourceLock() and deleteResourceLock()
   macros initialise the data structure needed to perform the resource
   locking */

#if defined( __WIN32__ ) && !defined( NT_DRIVER )					/* NT */

#include <process.h>	/* For begin/endthreadex */

/* Declare the variables required to handle the resource locking for internal
   data structures */

#define DECLARE_RESOURCE_LOCKING_VARS \
		CRITICAL_SECTION criticalSection; \
		BOOLEAN criticalSectionInitialised;

/* Initialise and delete the locking variables */

#define initResourceLock( resource ) \
		InitializeCriticalSection( &( resource )->criticalSection ); \
		( resource )->criticalSectionInitialised = TRUE
#define deleteResourceLock( resource ) \
		if( ( resource )->criticalSectionInitialised ) \
			{ \
			DeleteCriticalSection( &( resource )->criticalSection ); \
			( resource )->criticalSectionInitialised = FALSE; \
			}

/* Lock and unlock a resource using the locking variables */

#define lockResource( resource ) \
		EnterCriticalSection( &( resource )->criticalSection )
#define unlockResource( resource ) \
		LeaveCriticalSection( &( resource )->criticalSection )

/* Some variables are protected by global resource locks (for example the
   internal data structures are accessed through a global resource map which
   maps handles to resource information).  Before we can read or write these
   variables in a multithreaded environment we need to lock them so they
   won't be accessed or modified by other threads.  The following macros
   provide this locking capability */

#define DECLARE_LOCKING_VARS( name ) \
		CRITICAL_SECTION name##CriticalSection; \
		BOOLEAN name##CriticalSectionInitialised = FALSE;

#define DEFINE_LOCKING_VARS( name ) \
		extern CRITICAL_SECTION name##CriticalSection; \
		extern BOOLEAN name##CriticalSectionInitialised;

#define initGlobalResourceLock( name ) \
		if( !name##CriticalSectionInitialised ) \
			{ \
			InitializeCriticalSection( &name##CriticalSection ); \
			name##CriticalSectionInitialised = TRUE; \
			}
#define deleteGlobalResourceLock( name ) \
		if( name##CriticalSectionInitialised ) \
			{ \
			DeleteCriticalSection( &name##CriticalSection ); \
			name##CriticalSectionInitialised = FALSE; \
			}
#define lockGlobalResource( name ) \
		EnterCriticalSection( &name##CriticalSection )
#define unlockGlobalResource( name ) \
		LeaveCriticalSection( &name##CriticalSection )

/* Some resources are owned by one thread and can't be accessed by any other
   threads.  The following macros provide facilities to declare the thread
   ID variables and check that the current thread is allowed to access this
   resource.

   There are two functions we can call to get the current thread ID,
   GetCurrentThread() and GetCurrentThreadID().  These are actually implemented
   as the same function (once you get past the outer wrapper), and the times
   for calling either are identical - a staggering 10 us per call on a P5/166.
   The only difference between the two is that GetCurrentThread() returns a per-
   process pseudohandle while GetCurrentThreadID() returns a systemwide,
   unique handle.  We use GetCurrentThreadID() because it returns a DWORD
   which is easier to manage since it's equivalent to an int */

#define DECLARE_OWNERSHIP_VARS		DWORD resourceOwner;

#define getCurrentIdentity()		GetCurrentThreadId()

/* The types used for handles to threads and system synchronisation objects */

#define THREAD_HANDLE				HANDLE
#define SEMAPHORE_HANDLE			HANDLE

/* Define a thread function */

#define THREADFUNC_DEFINE( name, arg ) \
									unsigned __stdcall name( void *arg )

/* Create a thread and check that the creation succeeded */

#define THREAD_CREATE( function, arg ) \
								_beginthreadex( NULL, 0, ( function ), \
									( arg ), 0, ( unsigned * ) &dummy );
#define THREAD_STATUS( status )	( !( status ) ? CRYPT_ERROR : CRYPT_OK )
#define THREAD_EXIT()			_endthreadex( 0 ); return( 0 )

/* The lock for the internal data structures is used throughout the library
   so we make it globally visible */

extern CRITICAL_SECTION resourceCriticalSection;

#elif defined( __WIN32__ ) && defined( NT_DRIVER )		/* NT kernel drvr */

/* Declare the variables required to handle the resource locking for internal
   data structures */

#define DECLARE_RESOURCE_LOCKING_VARS \
		KMUTEX criticalSection; \
		BOOLEAN criticalSectionInitialised;

/* Initialise and delete the locking variables */

#define initResourceLock( resource ) \
		KeInitializeMutex( &( resource )->criticalSection, 1 ); \
		( resource )->criticalSectionInitialised = TRUE

#define deleteResourceLock( resource )

/* Lock and unlock a resource using the locking variables */

#define lockResource( resource ) \
		KeWaitForMutexObject( &( resource )->criticalSection, Executive, \
							  KernelMode, FALSE, NULL )

#define unlockResource( resource ) \
		KeReleaseMutex( &( resource )->criticalSection, FALSE )

/* Some variables are protected by global resource locks (for example the
   internal data structures are accessed through a global resource map which
   maps handles to resource information).  Before we can read or write these
   variables in a multithreaded environment we need to lock them so they
   won't be accessed or modified by other threads.  The following macros
   provide this locking capability */

#define DECLARE_LOCKING_VARS( name ) \
		KMUTEX name##CriticalSection; \
		BOOLEAN name##CriticalSectionInitialised = FALSE;

#define DEFINE_LOCKING_VARS( name ) \
		extern KMUTEX name##CriticalSection;

#define initGlobalResourceLock( name ) \
		if( !name##CriticalSectionInitialised ) \
			{ \
			KeInitializeMutex( &name##CriticalSection, 1 ); \
			name##CriticalSectionInitialised = TRUE; \
			}
#define deleteGlobalResourceLock( name )

#define lockGlobalResource( name ) \
		KeWaitForMutexObject( &name##CriticalSection, Executive, \
							  KernelMode, FALSE, NULL )
#define unlockGlobalResource( name ) \
		KeReleaseMutex( &name##CriticalSection, FALSE )

/* The types used for handles to threads and system synchronisation objects */

#define THREAD_HANDLE				HANDLE
#define SEMAPHORE_HANDLE			HANDLE

/* The lock for the internal data structures is used throughout the library
   so we make it globally visible */

extern KMUTEX resourceCriticalSection;

#elif defined( __OS2__ )								/* OS/2 */

#define INCL_DOSSEMAPHORES
#define INCL_DOSMISC
#define INCL_DOSFILEMGR
#define INCL_DOSMISC
#define INCL_DOSDATETIME
#define INCL_DOSPROCESS
#define INCL_WINWINDOWMGR
#define INCL_WINSYS
#include <os2.h>
ULONG DosGetThreadID( void );

/* Declare the variables required to handle the resource locking for internal
   data structures */

#define DECLARE_RESOURCE_LOCKING_VARS \
		HMTX mutex; \
		BOOLEAN mutexInitialised;

/* Initialise and delete the locking variables */

#define initResourceLock( resource ) \
		DosCreateMutexSem( NULL, &( resource )->mutex, 0L, FALSE ); \
		( resource )->mutexInitialised = TRUE
#define deleteResourceLock( resource ) \
		if( ( resource )->mutexInitialised ) \
			{ \
			DosCloseMutexSem( ( resource )->mutex ); \
			( resource )->mutexInitialised = FALSE; \
			}

/* Lock and unlock a resource using the locking variables */

#define lockResource( resource ) \
		DosRequestMutexSem( ( resource )->mutex, ( ULONG ) SEM_INDEFINITE_WAIT )
#define unlockResource( resource ) \
		DosReleaseMutexSem( ( resource )->mutex )

/* Some variables are protected by global resource locks (for example the
   internal data structures are accessed through a global resource map which
   maps handles to resource information).  Before we can read or write these
   variables in a multithreaded environment we need to lock them so they
   won't be accessed or modified by other threads.  The following macros
   provide this locking capability */

#define DECLARE_LOCKING_VARS( name ) \
		HMTX name##Mutex; \
		BOOLEAN name##MutexInitialised = FALSE;

#define DEFINE_LOCKING_VARS( name ) \
		extern HMTX name##Mutex;

#define initGlobalResourceLock( name ) \
		if( !name##MutexInitialised ) \
			{ \
			DosCreateMutexSem( NULL, &name##Mutex, 0L, FALSE ); \
			name##MutexInitialised = TRUE; \
			}
#define deleteGlobalResourceLock( name ) \
		if( name##MutexInitialised ) \
			{ \
			DosCloseMutexSem( name##Mutex ); \
			name##MutexInitialised = FALSE; \
			}
#define lockGlobalResource( name ) \
		DosRequestMutexSem( name##Mutex, ( ULONG ) SEM_INDEFINITE_WAIT )
#define unlockGlobalResource( name ) \
		DosReleaseMutexSem( name##Mutex )

/* Some resources are owned by one thread and can't be accessed by any other
   threads.  The following macros provide facilities to declare the thread
   ID variables and check that the current thread is allowed to access this
   resource */

#define DECLARE_OWNERSHIP_VARS	TID resourceOwner;

#define getCurrentIdentity()	DosGetThreadID()

/* The types used for handles to threads and system synchronisation objects */

#define THREAD_HANDLE			TID
#define SEMAPHORE_HANDLE		HEV

/* Define a thread function */

#define THREADFUNC_DEFINE( name, arg ) \
									void _Optlink name( void *arg )

/* Create a thread and check that the creation succeeded */

#define THREAD_CREATE( function, arg ) \
								_beginthread( ( function ), NULL, 8192, \
											  ( arg ) )
#define THREAD_STATUS( status )	( ( status ) == -1 ? CRYPT_ERROR : CRYPT_OK )
#define THREAD_EXIT()			_endthread()

/* The lock for the internal data structures is used throughout the library
   so we make it globally visible */

extern HMTX resourceMutex;

#elif defined( __UNIX__ ) && defined( USE_THREADS )		/* Unix threads */

/* Various Unix variants provide different threading implementations.  The
   following defines are used to map the abstract thread operations to the
   appropriate low-level primitives.

   Most of the mutex implementations are non-reentrant, which means that re-
   locking a mutex leads to deadlock (nice design, guys).  Some
   implementations can fix this by setting a mutex attribute to ensure it
   doesn't deadlock:

	pthread_mutexattr_settype( attr, PTHREAD_MUTEX_RECURSIVE );

   but this isn't universal.  To fix the problem, we provide a check using
   mutex_trylock() which doesn't re-lock the mutex if it's already locked.
   This works as follows:

	// Try and lock the mutex
	if( mutex_trylock( mutex ) == error )
		{
		// The mutex is already locked, if someone else has it locked, we
		// block until it becomes available
		if( thread_self() != mutex_owner )
			mutex_lock( mutex );
		}
	mutex_owner = thread_self();

	// ....

	// Since we don't do true nested locking, we may have already been
	// unlocked, don't try and unlock a second time
	if( mutex_owner != nil )
		{
		mutex_owner = nil;
		mutex_unlock( mutex );
		} */

#if defined( sun )			/* Solaris threads */

#include <thread.h>
#include <synch.h>

#define MUTEX					mutex_t
#define MUTEX_INIT( mutex )		mutex_init( mutex, USYNC_THREAD, NULL )
#define MUTEX_DESTROY			mutex_destroy
#define MUTEX_LOCK				mutex_lock
#define MUTEX_TRYLOCK			mutex_trylock
#define MUTEX_UNLOCK			mutex_unlock

#define THREAD					thread_t
#define THREAD_SELF				thr_self
#define THREAD_CREATE( function, arg ) \
								thr_create( NULL, 0, function, arg, 0, &dummy ); 
#define THREAD_STATUS( status )	( ( status ) ? CRYPT_ERROR : CRYPT_OK )
#define THREAD_EXIT()			thr_exit( ( void * ) 0 )

#elif defined( __Mach__ )	/* Mach threads */

#include <thread.h>

#define MUTEX					mutex_t
#define MUTEX_INIT( mutex )		mutex_init( mutex )
#define MUTEX_DESTROY			mutex_clear
#define MUTEX_LOCK				mutex_lock
#define MUTEX_TRYLOCK			mutex_try_lock
#define MUTEX_UNLOCK			mutex_unlock

#define THREAD					cthread_t
#define THREAD_SELF				cthread_self
#define THREAD_CREATE( function, arg ) \
								cthread_create( &dummy, NULL, function, arg ); 
#define THREAD_STATUS( status )	( ( status ) ? CRYPT_ERROR : CRYPT_OK )
#define THREAD_EXIT()			cthread_exit( ( void * ) 0 )

#else						/* DECthreads, LinuxThreads */

#include <pthread.h>

#define MUTEX					pthread_mutex_t
#define MUTEX_INIT( mutex )		pthread_mutex_init( mutex, NULL )
#define MUTEX_DESTROY			pthread_mutex_destroy
#define MUTEX_LOCK				pthread_mutex_lock
#define MUTEX_TRYLOCK			pthread_mutex_trylock
#define MUTEX_UNLOCK			pthread_mutex_unlock

#define THREAD					pthread_t
#define THREAD_SELF				pthread_self
#define THREAD_CREATE( function, arg ) \
								pthread_create( &dummy, NULL, function, arg ); 
#define THREAD_STATUS( status )	( ( status ) ? CRYPT_ERROR : CRYPT_OK )
#define THREAD_EXIT()			pthread_exit( ( void * ) 0 )

#endif /* Unix variant-specific threading primitives */

/* Declare the variables required to handle the resource locking for internal
   data structures */

#define DECLARE_RESOURCE_LOCKING_VARS \
		MUTEX mutex; \
		BOOLEAN mutexInitialised; \
		THREAD mutexOwner;

/* Initialise and delete the locking variables */

#define initResourceLock( resource ) \
		MUTEX_INIT( &( resource )->mutex ); \
		( resource )->mutexInitialised = TRUE; \
		( resource )->mutexOwner = CRYPT_ERROR;
#define deleteResourceLock( resource ) \
		if( ( resource )->mutexInitialised ) \
			{ \
			MUTEX_DESTROY( &( resource )->mutex ); \
			( resource )->mutexInitialised = FALSE; \
			}

/* Lock and unlock a resource using the locking variables */

#define lockResource( resource ) \
		if( MUTEX_TRYLOCK( &( resource )->mutex ) && \
			THREAD_SELF() != ( resource )->mutexOwner ) \
			MUTEX_LOCK( &( resource )->mutex ); \
		( resource )->mutexOwner = THREAD_SELF()
#define unlockResource( resource ) \
		if( ( resource )->mutexOwner != CRYPT_ERROR ) \
			{ \
			( resource )->mutexOwner = CRYPT_ERROR; \
			MUTEX_UNLOCK( &( resource )->mutex ); \
			}

/* Some variables are protected by global resource locks (for example the
   internal data structures are accessed through a global resource map which
   maps handles to resource information).  Before we can read or write these
   variables in a multithreaded environment we need to lock them so they
   won't be accessed or modified by other threads.  The following macros
   provide this locking capability.

   In some very unusual cases (see the initialistion handling code for
   details) it's possible that an attempt might be made to lock a mutex
   before it's been initialised (this can only happen due to a programming
   error by the caller, unfortunately it can't always be caught reliably).
   Setting the mutex to { 0 } is, in most threading implementations,
   equivalent to initialising it normally, so we do this to catch most
   occurences of the problem */

#define DECLARE_LOCKING_VARS( name ) \
		MUTEX name##Mutex = { 0 }; \
		BOOLEAN name##MutexInitialised = FALSE; \
		THREAD name##MutexOwner = CRYPT_ERROR;

#define DEFINE_LOCKING_VARS( name ) \
		extern MUTEX name##Mutex; \
		extern THREAD name##MutexOwner;

#define initGlobalResourceLock( name ) \
		if( !name##MutexInitialised ) \
			{ \
			MUTEX_INIT( &name##Mutex ); \
			name##MutexInitialised = TRUE; \
			name##MutexOwner = CRYPT_ERROR; \
			}
#define deleteGlobalResourceLock( name ) \
		if( name##MutexInitialised ) \
			{ \
			MUTEX_DESTROY( &name##Mutex ); \
			name##MutexInitialised = FALSE; \
			}
#define lockGlobalResource( name ) \
		if( MUTEX_TRYLOCK( &name##Mutex ) && \
			THREAD_SELF() != name##MutexOwner ) \
			MUTEX_LOCK( &name##Mutex ); \
		name##MutexOwner = THREAD_SELF();
#define unlockGlobalResource( name ) \
		name##MutexOwner = CRYPT_ERROR; \
		MUTEX_UNLOCK( &name##Mutex )

/* Some resources are owned by one thread and can't be accessed by any other
   threads.  The following macros provide facilities to declare the thread
   ID variables and check that the current thread is allowed to access this
   resource */

#define DECLARE_OWNERSHIP_VARS	THREAD resourceOwner;

#define getCurrentIdentity()	THREAD_SELF()

/* The types used for handles to threads and system synchronisation objects */

#define THREAD_HANDLE			THREAD
#define SEMAPHORE_HANDLE		THREAD

/* Define a thread function */

#define THREADFUNC_DEFINE( name, arg ) \
									void *name( void *arg )

/* The lock for the internal data structures is used throughout the library
   so we make it globally visible */

extern MUTEX resourceMutex;

#endif /* OS-specific resource locking and ownership handling */

#endif /* _CRYPTOS_DEFINED */
