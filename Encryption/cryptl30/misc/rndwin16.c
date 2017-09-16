/****************************************************************************
*																			*
*							Win16 Randomness-Gathering Code					*
*						   Copyright Peter Gutmann 1996-1999				*
*																			*
****************************************************************************/

/* This module is part of the cryptlib continuously seeded pseudorandom
   number generator.  For usage conditions, see lib_rand.c */

/* General includes */

#include <stdlib.h>
#include <string.h>
#include "../crypt.h"
#include "random.h"

/* OS-specific includes */

#include <stress.h>
#include <toolhelp.h>

void fastPoll( void )
	{
	BYTE buffer[ RANDOM_BUFSIZE ];
	SYSHEAPINFO sysHeapInfo;
	MEMMANINFO memManInfo;
	TIMERINFO timerInfo;
	POINT point;
	int quality = 25, bufIndex = 0;

	/* Get various basic pieces of system information: Handle of the window 
	   with mouse capture, handle of window with input focus, amount of 
	   space in global heap, whether system queue has any events, cursor 
	   position for last message, 55 ms time for last message, number of 
	   active tasks, 55 ms time since Windows started, current mouse cursor 
	   position, current caret position */
	addRandom( buffer, &bufIndex, GetCapture() );
	addRandom( buffer, &bufIndex, GetFocus() );
	addRandom( buffer, &bufIndex, GetFreeSpace( 0 ) );
	addRandom( buffer, &bufIndex, GetInputState() );
	addRandom( buffer, &bufIndex, GetMessagePos() );
	addRandom( buffer, &bufIndex, GetMessageTime() );
	addRandom( buffer, &bufIndex, GetNumTasks() );
	addRandom( buffer, &bufIndex, GetTickCount() );
	GetCursorPos( &point );
	addRandomString( buffer, &bufIndex, &point, sizeof( POINT ) );
	GetCaretPos( &point );
	addRandomString( buffer, &bufIndex, &point, sizeof( POINT ) );

	/* Get the largest free memory block, number of lockable pages, number of
	   unlocked pages, number of free and used pages, and number of swapped
	   pages */
	memManInfo.dwSize = sizeof( MEMMANINFO );
	MemManInfo( &memManInfo );
	addRandomString( buffer, &bufIndex, &memManInfo, sizeof( MEMMANINFO ) );

	/* Get the execution times of the current task and VM to approximately
	   1ms resolution */
	timerInfo.dwSize = sizeof( TIMERINFO );
	TimerCount( &timerInfo );
	addRandomString( buffer, &bufIndex, &timerInfo, sizeof( TIMERINFO ) );

	/* Get the percentage free and segment of the user and GDI heap */
	sysHeapInfo.dwSize = sizeof( SYSHEAPINFO );
	SystemHeapInfo( &sysHeapInfo );
	addRandomString( buffer, &bufIndex, &sysHeapInfo, sizeof( SYSHEAPINFO ) );

	/* Flush any remaining data through */
	addRandomString( buffer, &bufIndex, NULL, 0 );
	krnlSendMessage( SYSTEM_OBJECT_HANDLE, RESOURCE_IMESSAGE_SETATTRIBUTE,
					 &quality, CRYPT_IATTRIBUTE_RANDOM_QUALITY );
	}

/* The slow poll can get *very* slow because of the overhead involved in
   obtaining the necessary information.  On a moderately loaded system there
   are often 500+ objects on the global heap and 50+ modules, so we limit
   the number checked to a reasonable level to make sure we don't spend
   forever polling.  We give the global heap walk the most leeway since this
   provides the best source of randomness */

void slowPoll( void )
	{
	BYTE buffer[ RANDOM_BUFSIZE ];
	MODULEENTRY moduleEntry;
	GLOBALENTRY globalEntry;
	TASKENTRY taskEntry;
	int quality = 100, count, bufIndex = 0;

	/* Walk the global heap getting information on each entry in it.  This
	   retrieves the objects linear address, size, handle, lock count, owner,
	   object type, and segment type */
	count = 0;
	globalEntry.dwSize = sizeof( GLOBALENTRY );
	if( GlobalFirst( &globalEntry, GLOBAL_ALL ) )
		do
			{
			addRandomString( buffer, &bufIndex, &globalEntry, 
							 sizeof( GLOBALENTRY ) );
			count++;
			}
		while( count < 70 && GlobalNext( &globalEntry, GLOBAL_ALL ) );

	/* Walk the module list getting information on each entry in it.  This
	   retrieves the module name, handle, reference count, executable path,
	   and next module */
	count = 0;
	moduleEntry.dwSize = sizeof( MODULEENTRY );
	if( ModuleFirst( &moduleEntry ) )
		do
			{
			addRandomString( buffer, &bufIndex, &moduleEntry, 
							 sizeof( MODULEENTRY ) );
			count++;
			}
		while( count < 20 && ModuleNext( &moduleEntry ) );

	/* Walk the task list getting information on each entry in it.  This
	   retrieves the task handle, parent task handle, instance handle, stack
	   segment and offset, stack size, number of pending events, task queue,
	   and the name of module executing the task.  We also call TaskGetCSIP()
	   for the code segment and offset of each task if it's safe to do so
	   (note that this call can cause odd things to happen in debuggers and
	   runtime code checkers because of the way TaskGetCSIP() is implemented) */
	count = 0;
	taskEntry.dwSize = sizeof( TASKENTRY );
	if( TaskFirst( &taskEntry ) )
		do
			{
			addRandomString( buffer, &bufIndex, &taskEntry, 
							 sizeof( TASKENTRY ) );
			if( taskEntry.hTask != GetCurrentTask() )
				addRandom( buffer, &bufIndex, 
						   TaskGetCSIP( taskEntry.hTask ) );
			count++;
			}
		while( count < 100 && TaskNext( &taskEntry ) );

	/* Flush any remaining data through */
	addRandomString( buffer, &bufIndex, NULL, 0 );
	krnlSendMessage( SYSTEM_OBJECT_HANDLE, RESOURCE_IMESSAGE_SETATTRIBUTE,
					 &quality, CRYPT_IATTRIBUTE_RANDOM_QUALITY );
	}
