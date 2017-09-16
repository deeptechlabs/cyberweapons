/****************************************************************************
*																			*
*				Tandem NonStop Kernel Randomness-Gathering Code				*
*							Copyright XYPRO 1998-1999						*
*																			*
****************************************************************************/

/* This module is part of the cryptlib continuously seeded pseudorandom
   number generator.  For usage conditions, see lib_rand.c */

/* General includes */

#pragma nolist

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <cextdecs>
#include <tal.h>
#include "crypt.h"
#include "random.h"
#include <time.h>
#pragma list

struct p_info_list
	{
	long SwappablePages;
	long FreePages;
	long CurrentLockedMemory;
	long HighLockedmemory;
	unsigned long PageFaults;
	long ScansPerMemoryManagerCall;
	unsigned long MemoryClockCycles;
	short MemoryPressure;
	short MemoryQueueLength;
	long long ElapsedTime;
	long long BusyTime;
	long long InterruptTime;
	short ProcessorQueueLength;
	unsigned long Dispatches;
	long long SendBusy;
	long long DiskCacheHits;
	long long DiskIOs;
	short ProcessorQueueState1;
	short ProcessorQueueState2;
	long long ProcessorQueueState;
	short MemoryQueueState1;
	short MemoryQueueState2;
	long long MemoryQueueState;
	unsigned long SequencedSends;
	unsigned long UnsequencedSends;
	unsigned long PagesCreated;
	long long InterpreterBusy;
	long InterpreterTransitions;
	unsigned long Transactions;
	long long AcceleratedTime;
	long SegmentsInUse;
	};

short random_nsk_cpustats( char *p_pBuffer, short p_nCount )
	{
	short error, i;
	short index, nParam, j;
	char t;
	long lCPUStatus, lCPUMask;
	short nCPU;
	short nAttribList[] = {
		7, 8, 9, 11, 12, 13, 14, 15, 16, 18, 19, 21, 22, 23,29,
		36, 37, 38, 39, 40, 41, 43, 44, 45, 46, 50, 58
		};
	short nAttribCount = sizeof( nAttribList ) / sizeof( nAttribList[ 0 ] );
	short nValueMaxLen = sizeof( struct p_info_list ) / 2;
	short nValueLen;
	struct p_info_list PInfoList;

	lCPUMask = 0x8000;
	lCPUStatus = PROCESSORSTATUS();

	nCPU = i = 0;
	while ( i < p_nCount )
		{
		/* Find next cpu with up status */
		do
			{
			lCPUMask >>= 1;
			nCPU++;
			if( nCPU >= 16 )
				{
				nCPU = 0;
				lCPUMask = 0x8000;
				}
			}
		while( ( lCPUStatus & lCPUMask ) == 0 );

		error = PROCESSOR_GETINFOLIST_ (                /* nodename */
                                        ,               /* length */
                                        ,nCPU           /* cpu */
                                        ,nAttribList
                                        ,nAttribCount
                                        ,(short *)&PInfoList
                                        ,nValueMaxLen
                                        ,&nValueLen
                                        );
		if( error != 0 )
			{
			return error;
			}
		if( i < p_nCount )
			p_pBuffer[ i++ ] = ( char )( PInfoList.FreePages % 256 );
		if( i < p_nCount )
			p_pBuffer[ i++ ] = ( char )( PInfoList.PageFaults % 256 );
		if( i < p_nCount )
			p_pBuffer[ i++ ] = ( char )( PInfoList.ElapsedTime % 256 );
		if( i < p_nCount )
			p_pBuffer[ i++ ] = ( char )( PInfoList.BusyTime % 256 );
		if( i < p_nCount )
			p_pBuffer[ i++ ] = ( char )( PInfoList.InterruptTime % 256 );
		if( i < p_nCount )
			p_pBuffer[ i++ ] = ( char )( PInfoList.Dispatches % 256 );
		if( i < p_nCount )
			p_pBuffer[ i++ ] = ( char )( PInfoList.SendBusy % 256 );
		if( i < p_nCount )
			p_pBuffer[ i++ ] = ( char )( PInfoList.DiskCacheHits % 256 );
		if( i < p_nCount )
			p_pBuffer[ i++ ] = ( char )( PInfoList.DiskIOs % 256 );
		if( i < p_nCount )
			p_pBuffer[ i++ ] = ( char )( PInfoList.ProcessorQueueState % 256 );
		if( i < p_nCount )
			p_pBuffer[ i++ ] = ( char )( PInfoList.MemoryQueueState % 256 );
		if( i < p_nCount )
			p_pBuffer[ i++ ] = ( char )( PInfoList.SequencedSends % 256 );
		if( i < p_nCount )
			p_pBuffer[ i++ ] = ( char )( PInfoList.UnsequencedSends % 256 );
		if( i < p_nCount )
			p_pBuffer[ i++ ] = ( char )( PInfoList.PagesCreated % 256 );
		if( i < p_nCount )
			p_pBuffer[ i++ ] = ( char )( PInfoList.SegmentsInUse % 256 );
		}

	/* Randomly change the sequence */
	lCPUMask = 0x8000;

	nCPU = nParam = 0;
	for( i = 0; i < p_nCount - 1; i++ )
		{
		if( nParam % 5 == 0 )
			{
			nParam = 0;

			/* Find next cpu with up status */
			do
				{
				lCPUMask >>= 1;
				nCPU++;
				if( nCPU >= 16 )
					{
					nCPU = 0;
					lCPUMask = 0x8000;
					}
				}
			while( ( lCPUStatus & lCPUMask ) == 0 );

			error = PROCESSOR_GETINFOLIST_ (                /* nodename */
                                            ,               /* length */
                                            ,nCPU           /* cpu */
                                            ,nAttribList
                                            ,nAttribCount
                                            ,(short *)&PInfoList
                                            ,nValueMaxLen
                                            ,&nValueLen
                                            );
			if( error != 0 )
				{
				return error;
				}
			}

		switch( nParam )
			{
			case 0:
				index = (short)(PInfoList.ElapsedTime % (p_nCount - i));
				break;
			case 1:
				index = (short)(PInfoList.BusyTime % (p_nCount - i));
				break;
			case 2:
				index = (short)(PInfoList.InterruptTime % (p_nCount - i));
				break;
			case 3:
				index = (short)(PInfoList.Dispatches % (p_nCount - i));
				break;
			case 4:
				index = (short)(PInfoList.SendBusy % (p_nCount - i));
				break;
			default:
				;
			}

      /* 0      index  p_nCount-i-1             p_nCount-1
         !        !          !                       !
        -----------------------------------------------
        | |      | |        | | |                   | |
        -----------------------------------------------
                                \--------\/----------/
                                     Moved Bytes
                                                                */
		t = p_pBuffer[ index ];
		memmove( &p_pBuffer[ index ], &p_pBuffer[ index + 1 ],
				 p_nCount - i - index - 1 );
        p_pBuffer[ p_nCount - i - 1 ] = t;
        nParam++;
		}

	return 0;
	}

void fastPoll( void )
	{
	addRandomLong( time( NULL ) );
	}

void slowPoll( void )
	{
	BYTE buffer[ 128 ];
	long long value1;
	long long value2;
	unsigned char *buffer2;
	int total;
	short count;
	int i1,i2;

	count = sizeof(buffer);
	i1 = random_nsk_cpustats( buffer, count );
	if( ! i1 )
		{
		total = count;
		}
	else
		{
      /*
         since cpu stats failed use low 8 bits of current time
         time is accurate to 10^-6 seconds
      */
      buffer2 = (unsigned char *)&value1;
      for ( total=0; total < count; total++ )
      {
         value1 = JULIANTIMESTAMP();
         i1 = buffer2[7] & 0xf;
         for ( i2=0; i2 < i1; i2++ )
         {
            value1 = JULIANTIMESTAMP();
         }
         buffer[total] = buffer2[7];
		}
		}

	/* Add the data to the randomness pool */
	randomizeAddPos();
	addRandomBuffer( buffer, count );
	zeroise( buffer, NO_CPU_SAMPLES );

	/* Remember that we've got some randomness we can use */
	randomInfo.randomStatus = CRYPT_OK;
	}

-----------------------------------------------------------------

	/* Read the low 8 bits of the CPU time used timer, which is incremented
	   every 1us if the CPU is busy.  This randomness sampling works a bit
	   like the AT&T truerand generator by sampling the 1us timer in software
	   with the read granularity being about 1ms depending on system load.
	   Even reading the timer changes its value, since it uses CPU time */
	for( count = 0; count < NO_CPU_SAMPLES; count++ )
		{
		TIME( timerData );
		buffer[ count ] = timerData[ 5 ];
		}

--

OK, here's how I think it should work:

BYTE buffer[ 1024 ];	/* Or whatever size you need */
short nAttribList[] = { 1, 2, 3, 4, ... };

foreach nCPU
  {
  error = PROCESSOR_GETINFOLIST_ (                /* nodename */
                                  ,               /* length */
                                  ,nCPU           /* cpu */
                                  ,nAttribList
                                  ,<whatever the attribute count is>
                                  ,buffer
                                  ,nValueMaxLen
                                        ,&nValueLen
                                        );
