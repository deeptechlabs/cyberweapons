/****************************************************************************
*																			*
*						  BeOS Randomness-Gathering Code					*
*			Copyright Peter Gutmann and Osma Ahvenlampi 1996-1999			*
*																			*
****************************************************************************/

/* This module is part of the cryptlib continuously seeded pseudorandom
   number generator.  For usage conditions, see lib_rand.c */

/* General includes */

#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#include "misc/random.h"

/* These get defined by the Be headers */

#undef min
#undef max

#include <fcntl.h>
#include <sys/time.h>
#include <kernel/OS.h>
#include <kernel/image.h>

void fastPoll( void )
	{
	BYTE buffer[ RANDOM_BUFSIZE ];
	struct timeval tv;
	system_info info;
	bigtime_t idleTime;
	uint32 value;
	int quality = 5, bufIndex = 0;

	gettimeofday( &tv, NULL );
	addRandom( buffer, &bufIndex, tv.tv_sec );
	addRandom( buffer, &bufIndex, tv.tv_usec );

	/* Get the number of microseconds since the user last provided any input
	   to any part of the system, the state of keyboard shift keys */
	idleTime = idle_time();
	addRandomString( buffer, &bufIndex, &idleTime, sizeof( bigtime_t ) );
	value = modifiers();
	addRandom( buffer, &bufIndex, value );

	/* Get various fixed values (the 64-bit machine ID, CPU count and type(s),
	   clock speed, platform type, etc) and variable resources (number of in-
	   use pages, semaphores, ports, threads, teams, number of page faults,
	   and number of microseconds the CPU has been active) */
	get_system_info( &info );
	addRandomString( buffer, &bufIndex, &info, sizeof( info ) );

	/* Flush any remaining data through */
	addRandomString( buffer, &bufIndex, NULL, 0 );
	krnlSendMessage( SYSTEM_OBJECT_HANDLE, RESOURCE_IMESSAGE_SETATTRIBUTE,
					 &quality, CRYPT_IATTRIBUTE_RANDOM_QUALITY );
	}

#define DEVRANDOM_BITS		4096

void slowPoll( void )
	{
	BYTE buffer[ RANDOM_BUFSIZE ];
	key_info keyInfo;
	team_info teami;
	thread_info threadi;
	area_info areai;
	port_info porti;
	sem_info semi;
	image_info imagei;
	double temperature;
	long n;
	int quality = 100, fd, value, bufIndex = 0;

	if( ( fd = open( "/dev/urandom", O_RDONLY ) ) >= 0 )
		{
		RESOURCE_DATA msgData;
		BYTE buffer[ DEVRANDOM_BITS / 8 ];

		/* Read data from /dev/urandom, which won't block (although the
		   quality of the noise is lesser). */
		read( fd, buffer, DEVRANDOM_BITS / 8 );
		setResourceData( &msgData, buffer, DEVRANDOM_BITS / 8 );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, RESOURCE_IMESSAGE_SETATTRIBUTE_S,
						 &msgData, CRYPT_IATTRIBUTE_RANDOM );
		zeroise( buffer, DEVRANDOM_BITS / 8 );
		close( fd );

		krnlSendMessage( SYSTEM_OBJECT_HANDLE, RESOURCE_IMESSAGE_SETATTRIBUTE,
						 &quality, CRYPT_IATTRIBUTE_RANDOM_QUALITY );
		return;
		}

	/* Get the state of all keys on the keyboard and various other
	   system states */
	if( get_key_info( &keyInfo ) == B_NO_ERROR )
		addRandomString( buffer, &bufIndex, &keyInfo, sizeof( key_info ) );
	value = is_computer_on();	/* Returns 1 if computer is on */
	addRandom( buffer, &bufIndex, value );
	temperature = is_computer_on_fire();	/* MB temp.if on fire */
	addRandomString( buffer, &bufIndex, &temperature, sizeof( double ) );

	/* Get information on all running teams (thread groups, ie applications).
	   This returns the team ID, number of threads, images, and areas, 
	   debugger port and thread ID, program args, and uid and gid */
	for( n = 0; get_nth_team_info( n, &teami ) == B_NO_ERROR; n++ )
		addRandomString( buffer, &bufIndex, &teami, sizeof( teami ) );

	/* Get information on all running threads.  This returns the thread ID,
	   team ID, thread name and state (eg running, suspended, asleep, 
	   blocked), the thread priority, elapsed user and kernel time, and 
	   thread stack information */
	for( n = 0; get_nth_thread_info( 0, n, &threadi ) == B_NO_ERROR; n++ )
		{
		addRandom( buffer, &bufIndex, has_data( threadi.thread ) );
		addRandomString( buffer, &bufIndex, &threadi, sizeof( threadi ) );
		}

	/* Get information on all memory areas (chunks of virtual memory).  This
	   returns the area ID, name, size, locking scheme and protection bits,
	   ID of the owning team, start address, number of resident bytes, copy-
	   on-write count, an number of pages swapped in and out */
	for( n = 0; get_nth_area_info( 0, n, &areai ) == B_NO_ERROR; n++ )
		addRandomString( buffer, &bufIndex, &areai, sizeof( areai ) );

	/* Get information on all message ports.  This returns the port ID, ID of
	   the owning team, message queue length, number of messages in the
	   queue, and total number of messages processed */
	for( n = 0; get_nth_port_info( 0, n, &porti ) == B_NO_ERROR; n++ )
		addRandomString( buffer, &bufIndex, &porti, sizeof( porti ) );

	/* Get information on all semaphores.  This returns the semaphore and
	   owning team ID, the name, thread count, and the ID of the last thread
	   which acquired the semaphore */
	for( n = 0; get_nth_sem_info( 0, n, &semi ) == B_NO_ERROR; n++ )
		addRandomString( buffer, &bufIndex, &semi, sizeof( semi ) );

	/* Get information on all images (code blocks, eg applications, shared
	   libraries, and add-on images (DLL's on steroids).  This returns the
	   image ID and type (app, library, or add-on), the order in which the
	   image was loaded compared to other images, the address of the init
	   and shutdown routines, the device and node where the image lives, 
	   and the image text and data sizes) */
	for( n = 0; get_nth_image_info( 0, n, &imagei ) == B_NO_ERROR; n++ )
		addRandomString( buffer, &bufIndex, &imagi, sizeof( imagi ) );

	/* Get information on all storage devices.  This returns the device 
	   number, root inode, various device parameters such as I/O block size,
	   and the number of free and used blocks and inodes */
	value = 0;
	while( next_dev( &value ) >= 0 )
		{
		fs_info fsInfo;

		if( fs_stat_dev( value, &fsInfo ) == B_NO_ERROR )
			addRandomString( buffer, &bufIndex, &fsInfo, sizeof( fs_info ) );
		}

	/* Flush any remaining data through */
	addRandomString( buffer, &bufIndex, NULL, 0 );
	krnlSendMessage( SYSTEM_OBJECT_HANDLE, RESOURCE_IMESSAGE_SETATTRIBUTE,
					 &quality, CRYPT_IATTRIBUTE_RANDOM_QUALITY );
	}
