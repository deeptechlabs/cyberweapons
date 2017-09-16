/****************************************************************************
*																			*
*						VM/CMS Randomness-Gathering Code					*
*						  Copyright Peter Gutmann 1999						*
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

void fastPoll( void )
	{
	RESOURCE_DATA msgData;
	time_t timeStamp = time( NULL );

	/* There's not much we can do under VM */
	setResourceData( &msgData, &timeStamp, sizeof( time_t ) );
	krnlSendMessage( SYSTEM_OBJECT_HANDLE, RESOURCE_IMESSAGE_SETATTRIBUTE_S,
					 &msgData, CRYPT_IATTRIBUTE_RANDOM );
	}

void slowPoll( void )
	{
	RESOURCE_DATA msgData;
	BYTE buffer[ 128 ];
	int quality = 1, total = 128;

	/* Kludge something here */
	setResourceData( &msgData, buffer, total );
	krnlSendMessage( SYSTEM_OBJECT_HANDLE, RESOURCE_IMESSAGE_SETATTRIBUTE_S,
					 &msgData, CRYPT_IATTRIBUTE_RANDOM );
	zeroise( buffer, sizeof( buffer ) );
	krnlSendMessage( SYSTEM_OBJECT_HANDLE, RESOURCE_IMESSAGE_SETATTRIBUTE,
					 &quality, CRYPT_IATTRIBUTE_RANDOM_QUALITY );
	}
