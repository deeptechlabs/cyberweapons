/****************************************************************************
*																			*
*						Macintosh Randomness-Gathering Code					*
*						 Copyright Peter Gutmann 1997-1999					*
*																			*
****************************************************************************/

/* This module is part of the cryptlib continuously seeded pseudorandom
   number generator.  For usage conditions, see lib_rand.c */

/* Mac threads are cooperatively scheduled (so they're what Win32 calls
   fibers rather than true threads) and there isn't any real equivalent of a
   mutex (only critical sections which prevent any other thread from being
   scheduled, which defeats the point of multithreading), so we don't support
   this pseudo-threading for randomness polling.  If proper threading were
   available, we'd use NewThread()/DisposeThread() to create/destroy the
   background randomness-polling thread */

/* General includes */

#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#include "random.h"

/* OS-specific includes */
/* Filled in by Matthijs van Duin */

#include <Power.h>
#include <Sound.h>
#include <Threads.h>
#include <Events.h>
#include <Scrap.h>
#include <MacTypes.h>
#include <Serial.h>
#include <Processes.h>
#include <Disks.h>
#include <OSUtils.h>
#include <Start.h>
#include <AppleTalk.h>
#include <DeskBus.h>
#include <Retrace.h>
#include <SCSI.h>
#include <SpeechSynthesis.h>
#include <Resources.h>
#include <Script.h>

void fastPoll( void )
	{
	BYTE buffer[ RANDOM_BUFSIZE ];
/*	BatteryTimeRec batteryTimeInfo;
*/	SMStatus soundStatus;
	ThreadID threadID;
	ThreadState threadState;
	EventRecord eventRecord;
	Point point;
	WindowPtr windowPtr;
	PScrapStuff scrapInfo;
	UnsignedWide usSinceStartup;
	BYTE dataBuffer[ 2 ];
	short driverRefNum;
	long dateTime;
	int quality = 10, count, dummy, bufIndex = 0;
	NumVersion version;

	/* Get the status of the last alert, how much battery time is remaining
	   and the voltage from all batteries, the internal battery status, the
	   current date and time and time since system startup in ticks, the
	   application heap limit and current and heap zone, free memory in the
	   current and system heap, microseconds since system startup, whether
	   QuickDraw has finished drawing, modem status, SCSI status
	   information, maximum block allocatable without compacting, available
	   stack space, the last QuickDraw error code */
/*	addRandom( buffer, &bufIndex, GetAlertStage() );
	count = BatteryCount();
	while( count-- )
		{
		addRandom( buffer, &bufIndex, GetBatteryVoltage( count ) );
		GetBatteryTimes( count, &batteryTimeInfo );
		addRandomString( buffer, &bufIndex, &batteryTimeInfo, 
						 sizeof( BatteryTimeRec ) );
		}
	if( !BatteryStatus( buffer, dataBuffer + 1 ) )
		addRandom( buffer, &bufIndex, dataBuffer );
*/	GetDateTime( &dateTime );
	addRandom( buffer, &bufIndex, dateTime );
	addRandom( buffer, &bufIndex, TickCount() );
	addRandom( buffer, &bufIndex, GetApplLimit() );
	addRandom( buffer, &bufIndex, GetZone() );
	addRandom( buffer, &bufIndex, SystemZone() );
	addRandom( buffer, &bufIndex, FreeMem() );
	addRandom( buffer, &bufIndex, FreeMemSys() );
/*	MicroSeconds( &usSinceStartup );
	addRandomString( buffer, &bufIndex, &usSinceStartup, 
					 sizeof( UnsignedWide ) ); */
	addRandom( buffer, &bufIndex, QDDone( NULL ) );
/*	ModemStatus( dataBuffer );
	addRandom( buffer, &bufIndex, dataBuffer[ 0 ] );
*/	addRandom( buffer, &bufIndex, SCSIStat() );
	addRandom( buffer, &bufIndex, MaxBlock() );
	addRandom( buffer, &bufIndex, StackSpace() );
	addRandom( buffer, &bufIndex, QDError() );

	/* Get the event code and message, time, and mouse location for the next
	   event in the event queue and the OS event queue */
	if( EventAvail( everyEvent, &eventRecord ) )
		addRandomString( buffer, &bufIndex, &eventRecord, 
						 sizeof( EventRecord ) );
	if( OSEventAvail( everyEvent, &eventRecord ) )
		addRandomString( buffer, &bufIndex, &eventRecord, 
						 sizeof( EventRecord ) );

	/* Get all sorts of information such as device-specific info, grafport
	   information, visible and clipping region, pattern, pen, text, and
	   colour information, and other details, on the topmost window.  Also
	   get the window variant.  If there's a colour table record, add the
	   colour table as well */
	if( ( windowPtr = FrontWindow() ) != NULL )
		{
/*		CTabHandle colourHandle; */

		addRandomString( buffer, &bufIndex, windowPtr, sizeof( GrafPort ) );
		addRandom( buffer, &bufIndex, GetWVariant( windowPtr ) );
/*		if( GetAuxWin( windowPtr, colourHandle ) )
			{
			CTabPtr colourPtr;

			HLock( colourHandle );
			colourPtr = *colourHandle;
			addRandomString( buffer, &bufIndex, colourPtr, 
							 sizeof( ColorTable ) );
			HUnlock( colourHandle );
			} */
		}

	/* Get mouse-related such as the mouse button status and mouse position,
	   information on the window underneath the mouse */
	addRandom( buffer, &bufIndex, Button() );
	GetMouse( &point );
	addRandomString( buffer, &bufIndex, &point, sizeof( Point ) );
	FindWindow( point, &windowPtr );
	if( windowPtr != NULL )
		addRandomString( buffer, &bufIndex, windowPtr, sizeof( GrafPort ) );

	/* Get the size, handle, and location of the desk scrap/clipboard */
	scrapInfo = InfoScrap();
	addRandomString( buffer, &bufIndex, scrapInfo, sizeof( ScrapStuff ) );

	/* Get information on the current thread */
	threadID = kCurrentThreadID; /*GetThreadID( &threadID ); */
	GetThreadState( threadID, &threadState );
	addRandomString( buffer, &bufIndex, &threadState, sizeof( ThreadState ) );

	/* Get the sound mananger status.  This gets the number of allocated
	   sound channels and the current CPU load from these channels */
	SndManagerStatus( sizeof( SMStatus ), &soundStatus );
	addRandomString( buffer, &bufIndex, &soundStatus, sizeof( SMStatus ) );

	/* Get the speech manager version and status */
/*	version = SpeechManagerVersion();
	addRandomString( buffer, &bufIndex, &version, sizeof( NumVersion ) );
	addRandom( buffer, &bufIndex, SpeechBusy() );
*/
	/* Get the status of the serial port.  This gets information on recent
	   errors, read and write pending status, and flow control values */
/*	if( !OpenDriver( "\p.AIn", &driverRefNum ) )
		{
		SerStaRec serialStatus;

		SetStatus( driverRefNum, &serialStatus );
		addRandomString( buffer, &bufIndex, &serialStatus, 
						 sizeof( SerStaRec ) );
		}
	if( !OpenDriver( "\p.AOut", &driverRefNum ) )
		{
		SerStaRec serialStatus;

		SetStatus( driverRefNum, &serialStatus );
		addRandomString( buffer, &bufIndex, &serialStatus, 
						 sizeof( SerStaRec ) );
		}
*/
	/* Flush any remaining data through */
	addRandomString( buffer, &bufIndex, NULL, 0 );
	krnlSendMessage( SYSTEM_OBJECT_HANDLE, RESOURCE_IMESSAGE_SETATTRIBUTE,
					 &quality, CRYPT_IATTRIBUTE_RANDOM_QUALITY );
	}

void slowPoll( void )
	{
	BYTE buffer[ RANDOM_BUFSIZE ];
	ProcessSerialNumber psn;
	GDHandle deviceHandle;
	GrafPtr currPort;
	QElemPtr queuePtr;
	QHdrPtr queueHdr;
	static BOOLEAN addedFixedItems = FALSE;
	int quality = 100, bufIndex = 0;

	/* Walk through the list of graphics devices adding information about
	   a device (IM VI 21-21) */
	deviceHandle = GetDeviceList();
	while( deviceHandle != NULL )
		{
		GDHandle currentHandle = deviceHandle;
		GDPtr devicePtr;

		HLock( currentHandle );
		devicePtr = *currentHandle;
		deviceHandle = devicePtr->gdNextGD;
		addRandomString( buffer, &bufIndex, devicePtr, sizeof( GDevice ) );
		HUnlock( currentHandle );
		}

	/* Walk through the list of processes adding information about each
	   process, including the name and serial number of the process, file and
	   resource information, memory usage information, the name of the
	   launching process, launch time, and accumulated CPU time (IM VI 29-17) */
	psn.highLongOfPSN = 0;
	psn.lowLongOfPSN = kNoProcess;
	while( !GetNextProcess( &psn ) )
		{
		ProcessInfoRec infoRec;
		GetProcessInformation( &psn, &infoRec );
		addRandomString( buffer, &bufIndex, &infoRec, 
						 sizeof( ProcessInfoRec ) );
		}

	/* Get the command type, trap address, and parameters for all commands in
	   the file I/O queue.  The parameters are quite complex and are listed
	   on page 117 of IM IV, and include reference numbers, attributes, time
	   stamps, length and file allocation information, finder info, and large
	   amounts of other volume and filesystem-related data */
	if( ( queueHdr = GetFSQHdr() ) != NULL )
		queuePtr = queueHdr->qHead;
		while( queuePtr != NULL )
			{
			/* The queue entries are variant records of variable length so we
			   need to adjust the length parameter depending on the record
			   type */
			addRandomString( buffer, &bufIndex, queuePtr, 32 ); /* dunno how big.. */
			queuePtr = queuePtr->qLink;
			}
	/* The following are fixed for the lifetime of the process so we only
	   add them once */
	if( !addedFixedItems )
		{
		Str255 appName, volName;
		GDHandle deviceHandle;
		Handle appHandle;
		DrvSts driveStatus;
		MachineLocation machineLocation;
		ProcessInfoRec processInfo;
		QHdrPtr vblQueue;
		SysEnvRec sysEnvirons;
		SysPPtr pramPtr;
		DefStartRec startupInfo;
		DefVideoRec videoInfo;
		DefOSRec osInfo;
		XPPParmBlkPtr appleTalkParams;
		char *driverNames[] = {
			"\p.AIn", "\p.AOut", "\p.AppleCD", "\p.ATP", "\p.BIn", "\p.BOut", "\p.MPP",
			"\p.Print", "\p.Sony", "\p.Sound", "\p.XPP", NULL
			};
		int count, dummy, i, node, net, vRefNum, script, volume;

		/* Get the current font family ID, node ID of the local AppleMumble
		   router, caret blink delay, CPU speed, double-click delay, sound
		   volume, application and system heap zone, the number of resource
		   types in the application, the number of sounds voices available,
		   the FRef of the current resource file, volume of the sysbeep,
		   primary line direction, computer SCSI disk mode ID, timeout before
		   the screen is dimmed and before the computer is put to sleep,
		   number of available threads in the thread pool, whether hard drive
		   spin-down is disabled, the handle to the i18n resources, timeout
		   time for the internal HDD, */
		addRandom( buffer, &bufIndex, GetAppFont() );
		addRandom( buffer, &bufIndex, GetBridgeAddress() );
		addRandom( buffer, &bufIndex, GetCaretTime() );
/*		addRandom( buffer, &bufIndex, GetCPUSpeed() );
*/		addRandom( buffer, &bufIndex, GetDblTime() );
		GetSysBeepVolume( &volume );
		addRandom( buffer, &bufIndex, volume );
		GetDefaultOutputVolume( &volume );
		addRandom( buffer, &bufIndex, volume );
		addRandom( buffer, &bufIndex, ApplicationZone() );
		addRandom( buffer, &bufIndex, SystemZone() );
		addRandom( buffer, &bufIndex, CountTypes() );
/*				CountVoices( &count ); ** seems to crash
		addRandom( buffer, &bufIndex, count ); */
/*		addRandom( buffer, &bufIndex, CurrResFile );  ** Doesn't exist */
		GetSysBeepVolume( &count );
		addRandom( buffer, &bufIndex, count );
		addRandom( buffer, &bufIndex, GetSysDirection() );
/*		addRandom( buffer, &bufIndex, GetSCSIDiskModeAddress() );
		addRandom( buffer, &bufIndex, GetDimmingTimeout() );
		addRandom( buffer, &bufIndex, GetSleepTimeout() );
*/		GetFreeThreadCount( kCooperativeThread, &count );
		addRandom( buffer, &bufIndex, count );
/*		addRandom( buffer, &bufIndex, IsSpindownDisabled() );
*/		addRandom( buffer, &bufIndex, GetIntlResource( 0 ) );
		GetTimeout( &count );
		addRandom( buffer, &bufIndex, count );

		/* Get the number of documents/files which were selected when the app
		   started and for each document get the vRefNum, name, type, and
		   version -- OBSOLETE
		CountAppFiles( &dummy, &count );
		addRandom( buffer, &bufIndex, count );
		while( count )
			{
			AppFile theFile;
			GetAppFiles( count, &theFile );
			addRandomString( buffer, &bufIndex, &theFile, sizeof( AppFile ) );
			count--;
			}
		*/
		/* Get the apps name, resource file reference number, and handle to
		   the finder information -- OBSOLETE
		GetAppParams( appName, appHandle, &count );
		addRandomString( buffer, &bufIndex, appName, sizeof( Str255 ) );
		addRandom( buffer, &bufIndex, appHandle );
		addRandom( buffer, &bufIndex, count );
		*/
		/* Get all sorts of statistics such as physical information, disk and
		   write-protect present status, error status, and handler queue
		   information, on floppy drives attached to the system.  Also get
		   the volume name, volume reference number and number of bytes free,
		   for the volume in the drive */
		if( !DriveStatus( 1, &driveStatus ) )
			addRandomString( buffer, &bufIndex, &driveStatus, sizeof (DrvSts) );
		if( !GetVInfo( 1, volName, &vRefNum, &count ) )
			{
			addRandomString( buffer, &bufIndex, volName, sizeof( Str255 ) );
			addRandom( buffer, &bufIndex, vRefNum );
			addRandom( buffer, &bufIndex, count );
			}
		if( !DriveStatus( 2, &driveStatus ) )
			addRandomString( buffer, &bufIndex, &driveStatus, sizeof (DrvSts) );
		if( !GetVInfo( 2, volName, &vRefNum, &count ) )
			{
			addRandomString( buffer, &bufIndex, volName, sizeof( Str255 ) );
			addRandom( buffer, &bufIndex, vRefNum );
			addRandom( buffer, &bufIndex, count );
			}

		/* Get information on the head and tail of the vertical retrace
		   queue */
		if( ( vblQueue = GetVBLQHdr() ) != NULL )
			addRandomString( buffer, &bufIndex, vblQueue, sizeof( QHdr ) );

		/* Get the parameter RAM settings */
		pramPtr = GetSysPPtr();
		addRandomString( buffer, &bufIndex, pramPtr, sizeof( SysParmType ) );

		/* Get information about the machines geographic location */
		ReadLocation( &machineLocation );
		addRandomString( buffer, &bufIndex, &machineLocation, 
						 sizeof( MachineLocation ) );

		/* Get information on current graphics devices including device
		   information such as dimensions and cursor information, and a
		   number of handles to device-related data blocks and functions, and
		   information about the dimentions and contents of the devices pixel
		   image as well as the images resolution, storage format, depth, and
		   colour usage */
		deviceHandle = GetDeviceList();
		do
			{
			GDPtr gdPtr;

			addRandom( buffer, &bufIndex, deviceHandle );
			HLock( deviceHandle );
			gdPtr = ( GDPtr * ) *deviceHandle;
			addRandomString( buffer, &bufIndex, gdPtr, sizeof( GDevice ) );
			addRandomString( buffer, &bufIndex, gdPtr->gdPMap, 
							 sizeof( PixMap ) );
			HUnlock( deviceHandle );
			}
		while( ( deviceHandle = GetNextDevice( deviceHandle ) ) != NULL );

		/* Get the current system environment, including the machine and
		   system software type, the keyboard type, where there's a colour
		   display attached, the AppleTalk driver version, and the VRefNum of
		   the system folder */
		SysEnvirons( curSysEnvVers, &sysEnvirons );
		addRandomString( buffer, &bufIndex, &sysEnvirons, sizeof( SysEnvRec ) );

		/* Get the AppleTalk node ID and network number for this machine */
		if( GetNodeAddress( &node, &net ) )
			{
			addRandom( buffer, &bufIndex, node );
			addRandom( buffer, &bufIndex, net );
			}

		/* Get information on each device connected to the ADB including the
		   device handler ID, the devices ADB address, and the address of the
		   devices handler and storage area */
		count = CountADBs();
		while( count-- )
			{
			ADBDataBlock adbInfo;

			GetIndADB( &adbInfo, count );
			addRandomString( buffer, &bufIndex, &adbInfo, 
							 sizeof( ADBDataBlock ) );
			}

		/* Open the most common device types and get the general device
		   status information and (if possible) device-specific status.  The
		   general device information contains the device handle and flags,
		   I/O queue information, event information, and other driver-related
		   details */

/* Try something like this again.. and ur a dead man, Peter ;-)
      -xmath
*/

/*		for( count = 0; driverNames[ count ] != NULL; count++ )
			{
			AuxDCEHandle dceHandle;
			short driverRefNum;

			** Try and open the driver **
			if( OpenDriver( driverNames[ count ], &driverRefNum ) )
				continue;

			** Get a handle to the driver control information (this could
			   also be done with GetDCtlHandle()) **
			Status( driverRefNum, 1, &dceHandle );
			HLock( dceHandle );
			addRandomString( buffer, &bufIndex, *dceHandle, 
							 sizeof( AuxDCE ) );
			HUnlock( dceHandle );
			CloseDriver( driverRefNum );
			}
*/

		/* Get the name and volume reference number for the current volume */
		GetVol( volName, &vRefNum );
		addRandomString( buffer, &bufIndex, volName, sizeof( Str255 ) );
		addRandom( buffer, &bufIndex, vRefNum );

		/* Get the time information, attributes, directory information and
		   bitmap, volume allocation information, volume and drive
		   information, pointers to various pieces of volume-related
		   information, and details on path and directory caches, for each
		   volume */
		if( ( queueHdr = GetVCBQHdr() ) != NULL )
			queuePtr = queueHdr->qHead;
			while ( queuePtr != NULL )
				{
				addRandomString( buffer, &bufIndex, queuePtr, sizeof( VCB ) );
				queuePtr = queuePtr->qLink;
				}

		/* Get the driver reference number, FS type, and media size for each
		   drive */
		if( ( queueHdr = GetDrvQHdr() ) != NULL )
			queuePtr = queueHdr->qHead;
			while ( queuePtr != NULL )
				{
				addRandomString( buffer, &bufIndex, queuePtr, 
								 sizeof( DrvQEl ) );
				queuePtr = queuePtr->qLink;
				}

		/* Get global script manager variables and vectors, including the
		   globals changed count, font, script, and i18n flags, various
		   script types, and cache information */
		for( count = 0; count < 30; count++ )
			addRandom( buffer, &bufIndex, GetScriptManagerVariable( count ) );

		/* Get the script code for the font script the i18n script, and for
		   each one add the changed count, font, script, i18n, and display
		   flags, resource ID's, and script file information */
		script = FontScript();
		addRandom( buffer, &bufIndex, script );
		for( count = 0; count < 30; count++ )
			addRandom( buffer, &bufIndex, GetScriptVariable( script, count ) );
		script = IntlScript();
		addRandom( buffer, &bufIndex, script );
		for( count = 0; count < 30; count++ )
			addRandom( buffer, &bufIndex, GetScriptVariable( script, count ) );

		/* Get the device ID, partition, slot number, resource ID, and driver
		   reference number for the default startup device */
		GetDefaultStartup( &startupInfo );
		addRandomString( buffer, &bufIndex, &startupInfo, 
						 sizeof( DefStartRec ) );

		/* Get the slot number and resource ID for the default video device */
		GetVideoDefault( &videoInfo );
		addRandomString( buffer, &bufIndex, &videoInfo, 
						 sizeof( DefVideoRec ) );

		/* Get the default OS type */
		GetOSDefault( &osInfo );
		addRandomString( buffer, &bufIndex, &osInfo, sizeof( DefOSRec ) );

		/* Get the AppleTalk command block and data size and number of
		   sessions */
		ASPGetParms( &appleTalkParams, FALSE );
		addRandomString( buffer, &bufIndex, &appleTalkParams, 
						 sizeof( XPPParamBlock ) );

		addedFixedItems = TRUE;
		}

	/* Flush any remaining data through */
	addRandomString( buffer, &bufIndex, NULL, 0 );
	krnlSendMessage( SYSTEM_OBJECT_HANDLE, RESOURCE_IMESSAGE_SETATTRIBUTE,
					 &quality, CRYPT_IATTRIBUTE_RANDOM_QUALITY );
	}
