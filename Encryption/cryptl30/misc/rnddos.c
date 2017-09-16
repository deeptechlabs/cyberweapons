/****************************************************************************
*																			*
*						  MSDOS Randomness-Gathering Code					*
*						 Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

/* This module is part of the cryptlib continuously seeded pseudorandom
   number generator.  For usage conditions, see lib_rand.c */

/* General includes */

#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#include "misc/random.h"

/* OS-specific includes */

#include <fcntl.h>
#include <io.h>
#include <time.h>

void fastPoll( void )
	{
	RESOURCE_DATA msgData;
	time_t timeStamp = time( NULL );

	/* There's not much we can do under DOS, we rely entirely on the
	   /dev/random read for information */
	setResourceData( &msgData, &timeStamp, sizeof( time_t ) );
	krnlSendMessage( OBJECT_HANDLE_RANDOM, RESOURCE_IMESSAGE_SETATTRIBUTE_S,
						 &msgData, CRYPT_IATTRIBUTE_RANDOM );
	}

void slowPoll( void )
	{
	RESOURCE_DATA msgData;
	BYTE buffer[ 128 ];
	int quality = 100, fd, count, total;

	/* Read 128 bytes from /dev/random and add it to the buffer.  Since DOS
	   doesn't swap we don't need to be as careful about copying data to
	   temporary buffers as we usually are.  We also have to use unbuffered
	   I/O, since the high-level functions will read BUFSIZ bytes at once
	   from the input, comletely draining the driver of any randomness */
	if( ( fd = open( "/dev/random$", O_RDONLY | O_BINARY) ) == -1 &&
		( fd = open( "/dev/random", O_RDONLY | O_BINARY) ) == -1 )
		return;
	for( total = 0; total < sizeof( buffer ); )
		{
		count = read( fd, buffer + total, sizeof( buffer ) - total );
		if( count <= 0 )
			break;
		total += count;
		}
	close( fd );
	setResourceData( &msgData, buffer, total );
	krnlSendMessage( SYSTEM_OBJECT_HANDLE, RESOURCE_IMESSAGE_SETATTRIBUTE_S,
						 &msgData, CRYPT_IATTRIBUTE_RANDOM );
	zeroise( buffer, sizeof( buffer ) );
	krnlSendMessage( SYSTEM_OBJECT_HANDLE, RESOURCE_IMESSAGE_SETATTRIBUTE,
					 &quality, CRYPT_IATTRIBUTE_RANDOM_QUALITY );
	}
