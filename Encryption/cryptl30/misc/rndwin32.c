/****************************************************************************
*																			*
*						  Win32 Randomness-Gathering Code					*
*	Copyright Peter Gutmann, Matt Thomlinson and Blake Coverett 1996-1999	*
*																			*
****************************************************************************/

/* This module is part of the cryptlib continuously seeded pseudorandom
   number generator.  For usage conditions, see lib_rand.c.

   From the "Peter giveth and Microsoft taketh away" department: The default 
   NT setup has Everyone:Read permissions for the
   \\HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\PerfLib
   key, which is the key for the performance counters.  This means that 
   everyone on the network can read your machine's performance counters,
   significantly reducing their usefulness (although, since they contain a
   snapshot only, network users will never see exactly what you're seeing).
   To fix this problem, delete the Everyone:Read ACL and replace it with
   Interactive:Read, which only allows access to locally logged on users.
   This means an attacker will have to go to the effort of planting a trojan
   to get your crypto keys rather than getting them over the net */

/* General includes */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef INC_CHILD
  #include "../crypt.h"
  #include "random.h"
#else
  #include "crypt.h"
  #include "misc/random.h"
#endif /* Compiler-specific includes */

/* OS-specific includes */

#include <tlhelp32.h>
#include <winperf.h>
#include <winioctl.h>
#include <process.h>

/* The number of bytes to read from the PIII RNG and serial-port RNG on each 
   slow poll */

#define PIIIRNG_BYTES		64
#define SERIALRNG_BYTES		64

/* A mapping from CryptoAPI to standard data types */

#define HCRYPTPROV			HANDLE

/* Handles to various randomness objects */

static HANDLE hAdvAPI32;	/* Handle to misc.library */
static HANDLE hNetAPI32;	/* Handle to networking library */
static HANDLE hThread;		/* Background polling thread handle */
static HANDLE hComm;		/* Handle to serial RNG */
static HCRYPTPROV hProv;	/* Handle to Intel RNG CSP */

/* Intel Chipset CSP type and name */

#define PROV_INTEL_SEC	22
#define INTEL_DEF_PROV	"Intel Hardware Cryptographic Service Provider"

/* Type definitions for function pointers to call CryptoAPI functions */

typedef BOOL ( WINAPI *CRYPTACQUIRECONTEXT )( HCRYPTPROV *phProv, 
											  LPCTSTR pszContainer, 
											  LPCTSTR pszProvider, DWORD dwProvType, 
											  DWORD dwFlags );
typedef BOOL ( WINAPI *CRYPTGENRANDOM )( HCRYPTPROV hProv, DWORD dwLen, 
										 BYTE *pbBuffer ); 
typedef BOOL ( WINAPI *CRYPTRELEASECONTEXT )( HCRYPTPROV hProv, DWORD dwFlags );

/* Global function pointers. These are necessary because the functions need
   to be dynamically linked since older versions of Win95 and NT don't contain
   them */

static CRYPTACQUIRECONTEXT pCryptAcquireContext = NULL;
static CRYPTGENRANDOM pCryptGenRandom = NULL;
static CRYPTRELEASECONTEXT pCryptReleaseContext = NULL;

/* Open a connection to a serial-based RNG */

static int openSerialRNG( const char *port, const char *settings )
	{
	COMMPROP commProp;
	DWORD bytesRead;
	DCB dcb;
	char buffer[ 10 ];

	/* Open the serial port device and set the port parameters.  We need to
	   call GetCommState() before we call BuildCommDCB() because 
	   BuildCommDCB() doesn't touch the DCB fields not affected by the 
	   config string, so that they're left with garbage values which causes
	   SetCommState() to fail */
	hComm = CreateFile( port, GENERIC_READ, 0, NULL, OPEN_EXISTING, 
						FILE_ATTRIBUTE_NORMAL, NULL );
	if( hComm == ( HANDLE ) -1 )
		{
		hComm = NULL;
		return( CRYPT_ERROR ) ;
		}
	GetCommState( hComm, &dcb );
	BuildCommDCB( settings, &dcb );
	dcb.fRtsControl = RTS_CONTROL_HANDSHAKE;
	if( !SetCommState( hComm, &dcb ) )
		{
		CloseHandle( hComm );
		hComm = NULL;
		return( CRYPT_ERROR );
		}

	/* Set the timeout to return immediately in case there's nothing
	   plugged in */
	commProp.wPacketLength = sizeof( COMMPROP );
	GetCommProperties( hComm, &commProp );
	if( commProp.dwProvCapabilities & PCF_INTTIMEOUTS )
		{
		COMMTIMEOUTS timeouts;

		/* Wait 10ms between chars and per char (which will work even with 
		   a 1200bps generator), and 100ms overall (we need to make this 
		   fairly short since we don't want to have a long delay every
		   time the library is started up if the RNG is unplugged) */
		GetCommTimeouts( hComm, &timeouts );
		timeouts.ReadIntervalTimeout = 10;
		timeouts.ReadTotalTimeoutMultiplier = 10;
		timeouts.ReadTotalTimeoutConstant = 100;
		SetCommTimeouts( hComm, &timeouts );
		}

	/* The RNG can take awhile to get started so we wait 1/4s before trying
	   to read anything */
	PurgeComm( hComm, PURGE_RXABORT | PURGE_RXCLEAR );
	Sleep( 250 );

	/* Try and read a few bytes to make sure there's something there */
	PurgeComm( hComm, PURGE_RXABORT | PURGE_RXCLEAR );
	if( !ReadFile( hComm, buffer, 10, &bytesRead, NULL ) || bytesRead != 10 )
		{
		CloseHandle( hComm );
		hComm = NULL;
		return( CRYPT_ERROR );
		}

	return( CRYPT_OK );
	}

/* The shared Win32 fast poll routine */

void fastPoll( void )
	{
	static BOOLEAN addedFixedItems = FALSE;
	BYTE buffer[ RANDOM_BUFSIZE ];
	FILETIME  creationTime, exitTime, kernelTime, userTime;
	DWORD minimumWorkingSetSize, maximumWorkingSetSize;
	LARGE_INTEGER performanceCount;
	MEMORYSTATUS memoryStatus;
	HANDLE handle;
	POINT point;
	int quality = 34, bufIndex = 0;	/* Quality = int( 33 1/3 % ) */

	/* Get various basic pieces of system information: Handle of active 
	   window, handle of window with mouse capture, handle of clipboard owner
	   handle of start of clpboard viewer list, pseudohandle of current 
	   process, current process ID, pseudohandle of current thread, current 
	   thread ID, handle of desktop window, handle  of window with keyboard 
	   focus, whether system queue has any events, cursor position for last 
	   message, 1 ms time for last message, handle of window with clipboard 
	   open, handle of process heap, handle of procs window station, types of 
	   events in input queue, and milliseconds since Windows was started */
	addRandom( buffer, &bufIndex, GetActiveWindow() );
	addRandom( buffer, &bufIndex, GetCapture() );
	addRandom( buffer, &bufIndex, GetClipboardOwner() );
	addRandom( buffer, &bufIndex, GetClipboardViewer() );
	addRandom( buffer, &bufIndex, GetCurrentProcess() );
	addRandom( buffer, &bufIndex, GetCurrentProcessId() );
	addRandom( buffer, &bufIndex, GetCurrentThread() );
	addRandom( buffer, &bufIndex, GetCurrentThreadId() );
	addRandom( buffer, &bufIndex, GetDesktopWindow() );
	addRandom( buffer, &bufIndex, GetFocus() );
	addRandom( buffer, &bufIndex, GetInputState() );
	addRandom( buffer, &bufIndex, GetMessagePos() );
	addRandom( buffer, &bufIndex, GetMessageTime() );
	addRandom( buffer, &bufIndex, GetOpenClipboardWindow() );
	addRandom( buffer, &bufIndex, GetProcessHeap() );
	addRandom( buffer, &bufIndex, GetProcessWindowStation() );
	addRandom( buffer, &bufIndex, GetQueueStatus( QS_ALLEVENTS ) );
	addRandom( buffer, &bufIndex, GetTickCount() );

	/* Get multiword system information: Current caret position, current 
	   mouse cursor position */
	GetCaretPos( &point );				
	addRandomString( buffer, &bufIndex, &point, sizeof( POINT ) );
	GetCursorPos( &point );				
	addRandomString( buffer, &bufIndex, &point, sizeof( POINT ) );

	/* Get percent of memory in use, bytes of physical memory, bytes of free
	   physical memory, bytes in paging file, free bytes in paging file, user
	   bytes of address space, and free user bytes */
	memoryStatus.dwLength = sizeof( MEMORYSTATUS );
	GlobalMemoryStatus( &memoryStatus );
	addRandomString( buffer, &bufIndex, &memoryStatus, sizeof( MEMORYSTATUS ) );

	/* Get thread and process creation time, exit time, time in kernel mode,
	   and time in user mode in 100ns intervals */
	handle = GetCurrentThread();
	GetThreadTimes( handle, &creationTime, &exitTime, &kernelTime, &userTime );
	addRandomString( buffer, &bufIndex, &creationTime, sizeof( FILETIME ) );
	addRandomString( buffer, &bufIndex, &exitTime, sizeof( FILETIME ) );
	addRandomString( buffer, &bufIndex, &kernelTime, sizeof( FILETIME ) );
	addRandomString( buffer, &bufIndex, &userTime, sizeof( FILETIME ) );
	handle = GetCurrentProcess();
	GetProcessTimes( handle, &creationTime, &exitTime, &kernelTime, &userTime );
	addRandomString( buffer, &bufIndex, &creationTime, sizeof( FILETIME ) );
	addRandomString( buffer, &bufIndex, &exitTime, sizeof( FILETIME ) );
	addRandomString( buffer, &bufIndex, &kernelTime, sizeof( FILETIME ) );
	addRandomString( buffer, &bufIndex, &userTime, sizeof( FILETIME ) );

	/* Get the minimum and maximum working set size for the current process */
	GetProcessWorkingSetSize( handle, &minimumWorkingSetSize,
							  &maximumWorkingSetSize );
	addRandom( buffer, &bufIndex, minimumWorkingSetSize );
	addRandom( buffer, &bufIndex, maximumWorkingSetSize );

	/* The following are fixed for the lifetime of the process so we only
	   add them once */
	if( !addedFixedItems )
		{
		STARTUPINFO startupInfo;

		/* Get name of desktop, console window title, new window position and
		   size, window flags, and handles for stdin, stdout, and stderr */
		startupInfo.cb = sizeof( STARTUPINFO );
		GetStartupInfo( &startupInfo );
		addRandomString( buffer, &bufIndex, &startupInfo, sizeof( STARTUPINFO ) );
		addedFixedItems = TRUE;
		}

	/* The performance of QPC varies depending on the architecture it's
	   running on and on the OS.  Under NT it reads the CPU's 64-bit timstamp
	   counter (at least on a Pentium and newer '486's, it hasn't been tested
	   on anything without a TSC), under Win95 it reads the 1.193180 MHz PIC
	   timer.  There are vague mumblings in the docs that it may fail if the
	   appropriate hardware isn't available (possibly '386's or MIPS machines
	   running NT), but who's going to run NT on a '386? */
	if( QueryPerformanceCounter( &performanceCount ) )
		addRandomString( buffer, &bufIndex, &performanceCount, 
						 sizeof( LARGE_INTEGER ) );
	else
		/* Millisecond accuracy at best... */
		addRandom( buffer, &bufIndex, GetTickCount() );

	/* Flush any remaining data through */
	addRandomString( buffer, &bufIndex, NULL, 0 );
	krnlSendMessage( SYSTEM_OBJECT_HANDLE, RESOURCE_IMESSAGE_SETATTRIBUTE,
					 &quality, CRYPT_IATTRIBUTE_RANDOM_QUALITY );
	}

/* Type definitions for function pointers to call Toolhelp32 functions */

typedef BOOL ( WINAPI *MODULEWALK )( HANDLE hSnapshot, LPMODULEENTRY32 lpme );
typedef BOOL ( WINAPI *THREADWALK )( HANDLE hSnapshot, LPTHREADENTRY32 lpte );
typedef BOOL ( WINAPI *PROCESSWALK )( HANDLE hSnapshot, LPPROCESSENTRY32 lppe );
typedef BOOL ( WINAPI *HEAPLISTWALK )( HANDLE hSnapshot, LPHEAPLIST32 lphl );
typedef BOOL ( WINAPI *HEAPFIRST )( LPHEAPENTRY32 lphe, DWORD th32ProcessID, DWORD th32HeapID );
typedef BOOL ( WINAPI *HEAPNEXT )( LPHEAPENTRY32 lphe );
typedef HANDLE ( WINAPI *CREATESNAPSHOT )( DWORD dwFlags, DWORD th32ProcessID );

/* Global function pointers. These are necessary because the functions need
   to be dynamically linked since only the Win95 kernel currently contains
   them.  Explicitly linking to them will make the program unloadable under
   NT */

static CREATESNAPSHOT pCreateToolhelp32Snapshot = NULL;
static MODULEWALK pModule32First = NULL;
static MODULEWALK pModule32Next = NULL;
static PROCESSWALK pProcess32First = NULL;
static PROCESSWALK pProcess32Next = NULL;
static THREADWALK pThread32First = NULL;
static THREADWALK pThread32Next = NULL;
static HEAPLISTWALK pHeap32ListFirst = NULL;
static HEAPLISTWALK pHeap32ListNext = NULL;
static HEAPFIRST pHeap32First = NULL;
static HEAPNEXT pHeap32Next = NULL;

static void slowPollWin95( void )
	{
	BYTE buffer[ RANDOM_BUFSIZE ];
	PROCESSENTRY32 pe32;
	THREADENTRY32 te32;
	MODULEENTRY32 me32;
	HEAPLIST32 hl32;
	HANDLE hSnapshot;
	int quality = 100, bufIndex = 0;

	/* Initialize the Toolhelp32 function pointers if necessary */
	if( pCreateToolhelp32Snapshot == NULL )
		{
		HANDLE hKernel = NULL;

		/* Obtain the module handle of the kernel to retrieve the addresses
		   of the Toolhelp32 functions */
		if( ( hKernel = GetModuleHandle( "KERNEL32.DLL" ) ) == NULL )
			return;

		/* Now get pointers to the functions */
		pCreateToolhelp32Snapshot = ( CREATESNAPSHOT ) GetProcAddress( hKernel,
													"CreateToolhelp32Snapshot" );
		pModule32First = ( MODULEWALK ) GetProcAddress( hKernel,
													"Module32First" );
		pModule32Next = ( MODULEWALK ) GetProcAddress( hKernel,
													"Module32Next" );
		pProcess32First = ( PROCESSWALK ) GetProcAddress( hKernel,
													"Process32First" );
		pProcess32Next = ( PROCESSWALK ) GetProcAddress( hKernel,
													"Process32Next" );
		pThread32First = ( THREADWALK ) GetProcAddress( hKernel,
													"Thread32First" );
		pThread32Next = ( THREADWALK ) GetProcAddress( hKernel,
													"Thread32Next" );
		pHeap32ListFirst = ( HEAPLISTWALK ) GetProcAddress( hKernel,
													"Heap32ListFirst" );
		pHeap32ListNext = ( HEAPLISTWALK ) GetProcAddress( hKernel,
													"Heap32ListNext" );
		pHeap32First = ( HEAPFIRST ) GetProcAddress( hKernel,
													"Heap32First" );
		pHeap32Next = ( HEAPNEXT ) GetProcAddress( hKernel,
													"Heap32Next" );

		/* Make sure we got valid pointers for every Toolhelp32 function */
		if( pModule32First == NULL || pModule32Next == NULL || \
			pProcess32First == NULL || pProcess32Next == NULL || \
			pThread32First == NULL || pThread32Next == NULL || \
			pHeap32ListFirst == NULL || pHeap32ListNext == NULL || \
			pHeap32First == NULL || pHeap32Next == NULL || \
			pCreateToolhelp32Snapshot == NULL )
			{
			/* Mark the main function as unavailable in case for future
			   reference */
			pCreateToolhelp32Snapshot = NULL;
			return;
			}
		}

	/* Take a snapshot of everything we can get to which is currently
	   in the system */
	hSnapshot = pCreateToolhelp32Snapshot( TH32CS_SNAPALL, 0 );
	if( !hSnapshot )
		return;

	/* Walk through the local heap */
	hl32.dwSize = sizeof( HEAPLIST32 );
	if( pHeap32ListFirst( hSnapshot, &hl32 ) )
		do
			{
			HEAPENTRY32 he32;

			/* First add the information from the basic Heaplist32
			   structure */
			addRandomString( buffer, &bufIndex, &hl32, sizeof( HEAPLIST32 ) );

			/* Now walk through the heap blocks getting information
			   on each of them */
			he32.dwSize = sizeof( HEAPENTRY32 );
			if( pHeap32First( &he32, hl32.th32ProcessID, hl32.th32HeapID ) )
				do
					addRandomString( buffer, &bufIndex, &he32, 
									 sizeof( HEAPENTRY32 ) );
				while( pHeap32Next( &he32 ) );
			}
		while( pHeap32ListNext( hSnapshot, &hl32 ) );

	/* Walk through all processes */
	pe32.dwSize = sizeof( PROCESSENTRY32 );
	if( pProcess32First( hSnapshot, &pe32 ) )
		do
			addRandomString( buffer, &bufIndex, &pe32, 
							 sizeof( PROCESSENTRY32 ) );
		while( pProcess32Next( hSnapshot, &pe32 ) );

	/* Walk through all threads */
	te32.dwSize = sizeof( THREADENTRY32 );
	if( pThread32First( hSnapshot, &te32 ) )
		do
			addRandomString( buffer, &bufIndex, &te32, 
							 sizeof( THREADENTRY32 ) );
	while( pThread32Next( hSnapshot, &te32 ) );

	/* Walk through all modules associated with the process */
	me32.dwSize = sizeof( MODULEENTRY32 );
	if( pModule32First( hSnapshot, &me32 ) )
		do
			addRandomString( buffer, &bufIndex, &me32, 
							 sizeof( MODULEENTRY32 ) );
	while( pModule32Next( hSnapshot, &me32 ) );

	/* Clean up the snapshot */
	CloseHandle( hSnapshot );

	/* Flush any remaining data through */
	addRandomString( buffer, &bufIndex, NULL, 0 );
	krnlSendMessage( SYSTEM_OBJECT_HANDLE, RESOURCE_IMESSAGE_SETATTRIBUTE,
					 &quality, CRYPT_IATTRIBUTE_RANDOM_QUALITY );
	}

/* Perform a thread-safe slow poll for Windows 95.  The following function
   *must* be started as a thread */

unsigned __stdcall threadSafeSlowPollWin95( void *dummy )
	{
	UNUSED( dummy );

	slowPollWin95();
	_endthreadex( 0 );
	return( 0 );
	}

/* Type definitions for function pointers to call NetAPI32 functions */

typedef DWORD ( WINAPI *NETSTATISTICSGET )( LPWSTR szServer, LPWSTR szService,
											DWORD dwLevel, DWORD dwOptions,
											LPBYTE *lpBuffer );
typedef DWORD ( WINAPI *NETAPIBUFFERSIZE )( LPVOID lpBuffer, LPDWORD cbBuffer );
typedef DWORD ( WINAPI *NETAPIBUFFERFREE )( LPVOID lpBuffer );

/* Global function pointers. These are necessary because the functions need
   to be dynamically linked since only the WinNT kernel currently contains
   them.  Explicitly linking to them will make the program unloadable under
   Win95 */

static NETSTATISTICSGET pNetStatisticsGet = NULL;
static NETAPIBUFFERSIZE pNetApiBufferSize = NULL;
static NETAPIBUFFERFREE pNetApiBufferFree = NULL;

/* When we query the performance counters, we allocate an initial buffer and
   then reallocate it as required until RegQueryValueEx() stops returning
   ERROR_MORE_DATA.  The following values define the initial buffer size and
   step size by which the buffer is increased */

#define PERFORMANCE_BUFFER_SIZE		65536	/* Start at 64K */
#define PERFORMANCE_BUFFER_STEP		16384	/* Step by 16K */

static void slowPollWinNT( void )
	{
	static int isWorkstation = CRYPT_ERROR;
	static int cbPerfData = PERFORMANCE_BUFFER_SIZE;
	RESOURCE_DATA msgData;
	PPERF_DATA_BLOCK pPerfData;
	HANDLE hDevice;
	LPBYTE lpBuffer;
	DWORD dwSize, status;
	int nDrive;

	/* Find out whether this is an NT server or workstation if necessary */
	if( isWorkstation == CRYPT_ERROR )
		{
		HKEY hKey;

		if( RegOpenKeyEx( HKEY_LOCAL_MACHINE,
						  "SYSTEM\\CurrentControlSet\\Control\\ProductOptions",
						  0, KEY_READ, &hKey ) == ERROR_SUCCESS )
			{
			BYTE szValue[ 32 ];
			dwSize = sizeof( szValue );

			isWorkstation = TRUE;
			status = RegQueryValueEx( hKey, "ProductType", 0, NULL,
									  szValue, &dwSize );
			if( status == ERROR_SUCCESS && stricmp( szValue, "WinNT" ) )
				/* Note: There are (at least) three cases for ProductType:
				   WinNT = NT Workstation, ServerNT = NT Server, LanmanNT =
				   NT Server acting as a Domain Controller */
				isWorkstation = FALSE;

			RegCloseKey( hKey );
			}
		}

	/* Initialize the NetAPI32 function pointers if necessary */
	if( hNetAPI32 == NULL )
		{
		/* Obtain a handle to the module containing the Lan Manager functions */
		if( ( hNetAPI32 = LoadLibrary( "NETAPI32.DLL" ) ) != NULL )
			{
			/* Now get pointers to the functions */
			pNetStatisticsGet = ( NETSTATISTICSGET ) GetProcAddress( hNetAPI32,
														"NetStatisticsGet" );
			pNetApiBufferSize = ( NETAPIBUFFERSIZE ) GetProcAddress( hNetAPI32,
														"NetApiBufferSize" );
			pNetApiBufferFree = ( NETAPIBUFFERFREE ) GetProcAddress( hNetAPI32,
														"NetApiBufferFree" );

			/* Make sure we got valid pointers for every NetAPI32 function */
			if( pNetStatisticsGet == NULL ||
				pNetApiBufferSize == NULL ||
				pNetApiBufferFree == NULL )
				{
				/* Free the library reference and reset the static handle */
				FreeLibrary( hNetAPI32 );
				hNetAPI32 = NULL;
				}
			}
		}

	/* Get network statistics.  Note: Both NT Workstation and NT Server by
	   default will be running both the workstation and server services.  The
	   heuristic below is probably useful though on the assumption that the
	   majority of the network traffic will be via the appropriate service.
	   In any case the network statistics return almost no randomness */
	if( hNetAPI32 &&
		pNetStatisticsGet( NULL,
						   isWorkstation ? L"LanmanWorkstation" : L"LanmanServer",
						   0, 0, &lpBuffer ) == 0 )
		{
		pNetApiBufferSize( lpBuffer, &dwSize );
		setResourceData( &msgData, lpBuffer, dwSize );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, RESOURCE_IMESSAGE_SETATTRIBUTE_S,
						 &msgData, CRYPT_IATTRIBUTE_RANDOM );
		pNetApiBufferFree( lpBuffer );
		}

	/* Get disk I/O statistics for all the hard drives */
	for( nDrive = 0;; nDrive++ )
		{
		DISK_PERFORMANCE diskPerformance;
		char szDevice[ 24 ];

		/* Check whether we can access this device */
		sprintf( szDevice, "\\\\.\\PhysicalDrive%d", nDrive );
		hDevice = CreateFile( szDevice, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
							  NULL, OPEN_EXISTING, 0, NULL );
		if( hDevice == INVALID_HANDLE_VALUE )
			break;

		/* Note: This only works if you have turned on the disk performance
		   counters with 'diskperf -y'.  These counters are off by default */
		if( DeviceIoControl( hDevice, IOCTL_DISK_PERFORMANCE, NULL, 0,
							 &diskPerformance, sizeof( DISK_PERFORMANCE ),
							 &dwSize, NULL ) )
			{
			setResourceData( &msgData, &diskPerformance, dwSize );
			krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							 RESOURCE_IMESSAGE_SETATTRIBUTE_S, &msgData, 
							 CRYPT_IATTRIBUTE_RANDOM );
			}
		CloseHandle( hDevice );
		}

	/* Wait for any async keyset driver binding to complete.  You may be
	   wondering what this call is doing here... the reason it's necessary is
	   because RegQueryValueEx() will hang indefinitely if the async driver
	   bind is in progress.  The problem occurs in the dynamic loading and
	   linking of driver DLL's, which work as follows:

		hDriver = LoadLibrary( DRIVERNAME );
		pFunction1 = ( TYPE_FUNC1 ) GetProcAddress( hDriver, NAME_FUNC1 );
		pFunction2 = ( TYPE_FUNC1 ) GetProcAddress( hDriver, NAME_FUNC2 );

	   If RegQueryValueEx() is called while the GetProcAddress()'s are in
	   progress, it will hang indefinitely.  This is probably due to some
	   synchronisation problem in the NT kernel where the GetProcAddress() 
	   calls affect something like a module reference count or function 
	   reference count while RegQueryValueEx() is trying to take a snapshot 
	   of the statistics, which include the reference counts.  Because of 
	   this, we have to wait until any async driver bind has completed 
	   before we can call RegQueryValueEx() */
	waitSemaphore( SEMAPHORE_DRIVERBIND );

	/* Get information from the system performance counters.  This can take
	   a few seconds to do.  In some environments the call to
	   RegQueryValueEx() can produce an access violation at some random time
	   in the future, adding a short delay after the following code block
	   makes the problem go away.  This problem is extremely difficult to
	   reproduce, I haven't been able to get it to occur despite running it
	   on a number of machines.  The best explanation for the problem is that
	   on the machine where it did occur, it was caused by an external driver
	   or other program which adds its own values under the
	   HKEY_PERFORMANCE_DATA key.  The NT kernel calls the required external
	   modules to map in the data, if there's a synchronisation problem the
	   external module would write its data at an inappropriate moment,
	   causing the access violation.  A low-level memory checker indicated
	   that ExpandEnvironmentStrings() in KERNEL32.DLL, called an
	   interminable number of calls down inside RegQueryValueEx(), was
	   overwriting memory (it wrote twice the allocated size of a buffer to a
	   buffer allocated by the NT kernel).  This may be what's causing the
	   problem, but since it's in the kernel there isn't much which can be
	   done.

	   In addition to these problems the code in RegQueryValueEx() which
	   estimates the amount of memory required to return the performance
	   counter information isn't very accurate, since it always returns a
	   worst-case estimate which is usually nowhere near the actual amount
	   required.  For example it may report that 128K of memory is required,
	   but only return 64K of data */
	pPerfData = ( PPERF_DATA_BLOCK ) malloc( cbPerfData );
	while( pPerfData != NULL )
		{
		dwSize = cbPerfData;
		status = RegQueryValueEx( HKEY_PERFORMANCE_DATA, "Global", NULL,
								  NULL, ( LPBYTE ) pPerfData, &dwSize );
		if( status == ERROR_SUCCESS )
			{
			if( !memcmp( pPerfData->Signature, L"PERF", 8 ) )
				{
				int quality = 100, status;

				setResourceData( &msgData, pPerfData, dwSize );
				status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								RESOURCE_IMESSAGE_SETATTRIBUTE_S, &msgData, 
								CRYPT_IATTRIBUTE_RANDOM );
				if( cryptStatusOK( status ) )
					krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								RESOURCE_IMESSAGE_SETATTRIBUTE, &quality, 
								CRYPT_IATTRIBUTE_RANDOM_QUALITY );
				}
			free( pPerfData );
			pPerfData = NULL;
			}
		else
			if( status == ERROR_MORE_DATA )
				{
				cbPerfData += PERFORMANCE_BUFFER_STEP;
				pPerfData = ( PPERF_DATA_BLOCK ) realloc( pPerfData, cbPerfData );
				}
		}

	/* Although this isn't documented in the Win32 API docs, it's necessary 
	   to explicitly close the HKEY_PERFORMANCE_DATA key after use (it's 
	   implicitly opened on the first call to RegQueryValueEx()).  If this 
	   isn't done then any system components which provide performance data
	   can't be removed or changed while the handle remains active */
	RegCloseKey( HKEY_PERFORMANCE_DATA );
	}

/* Perform a thread-safe slow poll for Windows NT.  The following function
   *must* be started as a thread */

unsigned __stdcall threadSafeSlowPollWinNT( void *dummy )
	{
	UNUSED( dummy );

	slowPollWinNT();
	_endthreadex( 0 );
	return( 0 );
	}

/* Perform a generic slow poll.  This starts the OS-specific poll in a
   separate thread */

void slowPoll( void )
	{
	unsigned threadID;

	/* If there's a PIII RNG present, read data from it */
	if( hProv != NULL )
		{
		BYTE buffer[ PIIIRNG_BYTES ];

		/* Read 128 bytes from the serial PIII.  We don't rely on this for
		   all our randomness requirements in case it's broken in some way */
		if( pCryptGenRandom( hProv, PIIIRNG_BYTES, buffer ) )
			{
			RESOURCE_DATA msgData;
			int quality = 90;

			setResourceData( &msgData, buffer, PIIIRNG_BYTES );
			krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							 RESOURCE_IMESSAGE_SETATTRIBUTE_S, &msgData, 
							 CRYPT_IATTRIBUTE_RANDOM );
			krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							 RESOURCE_IMESSAGE_SETATTRIBUTE, &quality, 
							 CRYPT_IATTRIBUTE_RANDOM_QUALITY );
			zeroise( buffer, PIIIRNG_BYTES );
			}
		}			

	/* If there's a serial-port RNG present, read data from it */
	if( hComm != NULL )
		{
		BYTE buffer[ SERIALRNG_BYTES ];
		DWORD bytesRead;

		/* Read 128 bytes from the serial RNG.  We don't rely on this for
		   all our randomness requirements in case it's broken in some way */
		PurgeComm( hComm, PURGE_RXABORT | PURGE_RXCLEAR );
		if( ReadFile( hComm, buffer, SERIALRNG_BYTES, &bytesRead, NULL ) && \
			bytesRead == SERIALRNG_BYTES )
			{
			RESOURCE_DATA msgData;
			int quality = 90;

			setResourceData( &msgData, buffer, SERIALRNG_BYTES );
			krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							 RESOURCE_IMESSAGE_SETATTRIBUTE_S, &msgData, 
							 CRYPT_IATTRIBUTE_RANDOM );
			krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							 RESOURCE_IMESSAGE_SETATTRIBUTE, &quality, 
							 CRYPT_IATTRIBUTE_RANDOM_QUALITY );
			zeroise( buffer, SERIALRNG_BYTES );
			}
		}

	/* Start a threaded slow poll.  If a slow poll is already running, we
	   just return since there isn't much point in running two of them at the
	   same time */
	if( !hThread )
		if( isWin95 )
			hThread = ( HANDLE ) _beginthreadex( NULL, 0, &threadSafeSlowPollWin95,
												 NULL, 0, &threadID );
		else
			hThread = ( HANDLE ) _beginthreadex( NULL, 0, &threadSafeSlowPollWinNT,
												 NULL, 0, &threadID );
	}

/* Wait for the randomness gathering to finish.  Anything that requires the
   gatherer process to have completed gathering entropy should call
   waitforRandomCompletion(), which will block until the background process
   completes */

void waitforRandomCompletion( void )
	{
	if( hThread )
		{
		WaitForSingleObject( hThread, INFINITE );
		CloseHandle( hThread );
		hThread = NULL;
		}
	}

/* Initialise and clean up any auxiliary randomness-related objects */

void initRandomPolling( void )
	{
	RESOURCE_DATA msgData;
	char serialPortString[ CRYPT_MAX_TEXTSIZE + 1 ];
	char serialParamString[ CRYPT_MAX_TEXTSIZE + 1 ];

	/* Reset the various module and object handles */
	hAdvAPI32 = hNetAPI32 = hThread = hComm = hProv = NULL;

	setResourceData( &msgData, serialPortString, CRYPT_MAX_TEXTSIZE );
	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE_S, 
					 &msgData, CRYPT_OPTION_DEVICE_SERIALRNG );
	serialPortString[ msgData.length ] = '\0';
	setResourceData( &msgData, serialParamString, CRYPT_MAX_TEXTSIZE );
	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE_S, 
					 &msgData, CRYPT_OPTION_DEVICE_SERIALRNG_PARAMS );
	serialParamString[ msgData.length ] = '\0';

	/* Try and connect to the PIII RNG CSP if it's present */
	if( ( hAdvAPI32 = GetModuleHandle( "ADVAPI32.DLL" ) ) != NULL )
		{
		/* Now get pointers to the functions */
		pCryptAcquireContext = ( CRYPTACQUIRECONTEXT ) GetProcAddress( hAdvAPI32,
													"CryptAcquireContext" );
		pCryptGenRandom = ( CRYPTGENRANDOM ) GetProcAddress( hAdvAPI32,
													"CryptGenRandom" );
		pCryptReleaseContext = ( CRYPTRELEASECONTEXT ) GetProcAddress( hAdvAPI32,
													"CryptReleaseContext" );

		/* Make sure we got valid pointers for every CryptoAPI function and 
		   that the required CSP is present */
		if( pCryptAcquireContext == NULL || \
			pCryptGenRandom == NULL || pCryptReleaseContext == NULL || \
			!pCryptAcquireContext( &hProv, NULL, INTEL_DEF_PROV, 
								   PROV_INTEL_SEC, 0 ) )
			{
			hAdvAPI32 = NULL;
			hProv = NULL;
			}
		}

	/* If there's a serial-port RNG configured, try and initialise it */
	if( *serialPortString && *serialParamString )
		openSerialRNG( serialPortString, serialParamString );
	}

void endRandomPolling( void )
	{
	if( hThread )
		CloseHandle( hThread );
	if( hNetAPI32 )
		{
		FreeLibrary( hNetAPI32 );
		hNetAPI32 = NULL;
		}
	if( hProv != NULL )
		{
		pCryptReleaseContext( hProv, 0 );
		hProv = NULL;
		}
	if( hComm != NULL )
		{
		CloseHandle( hComm );
		hComm = NULL;
		}
	}
