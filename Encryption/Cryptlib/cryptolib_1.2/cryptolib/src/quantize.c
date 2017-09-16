/*
 * Simple Unix time quantization package
 * {mab,lacy}@research.att.com
 * v1.0 - 12/95
 *
 * WIN32 port v0.1 fod@brd.ie 12/95  
 *
 * TESTED ONLY UNDER SUNOS 4.x and BSDI 2.0.  
 *
 * WIN32 port TESTED ONLY UNDER WINDOWS '95
 *   (further testing recommended)
 *   Requires Winmm.lib
 *
 * This is unsupported software.  Use at own risk.  
 * Test carefully on new platforms.
 */
/*
 * The authors of this software are Matt Blaze and Jack Lacy
 *              Copyright (c) 1995 by AT&T Bell Laboratories.
 *
 * WIN32 port by Frank O'Dwyer
 *              Copyright (c) 1995 by Rainbow Diamond Limited
 *
 * Permission to use, copy, and modify this software without fee is
 * hereby granted, provided that this entire notice is included in all
 * copies of any software which is or includes a copy or modification
 * of this software and in all copies of the supporting documentation
 * for such software.
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTY.  IN PARTICULAR, NEITHER THE AUTHORS NOR AT&T 
 * NOR RAINBOW DIAMOND LIMITED MAKE ANY REPRESENTATION OR WARRANTY 
 * OF ANY KIND CONCERNING THE MERCHANTABILITY OF THIS SOFTWARE OR 
 * ITS FITNESS FOR ANY PARTICULAR PURPOSE.
 */

/*
 * WARNING: This package will provide quantized cpu consumption only
 * subject to the limitations of the OS on which it is run.  It will
 * fail in extreme cases (e.g., very very heavy load and very slow
 * machines (e.g., .001 MIPS).  Understand its limits before you use
 * it.
 *
 * Note that start_quantize takes MILLISECONDS, not microseconds.  See
 * quantize.3 for details.
 *
 * To prevent timing attacks (e.g., Kocher) in most PK crypto
 * applications in most applications on most cpus, surrounding the
 * call to the functions that use the secret with
 *	start_quantize(100);
 * and
 *	end_quantize();
 * will do reasonably well.
 */

#include "libcrypt.h"

#ifdef WIN32
#include <windows.h>
#endif

#ifndef NO_QUANTIZE
#include <signal.h>
#include <setjmp.h>

#ifndef WIN32
#include <sys/time.h>
#endif
#include <stdio.h>

static set_quant_interrupt();

#ifdef WIN32
#define REZ 1  /* millisecond -- higher values improve 
                  performance.  Lower values improve resolution */
static volatile long quant_quantum=0;
static volatile int waiting=0;
static UINT theTimer;
static TIMECAPS timeCaps;
static int inited=0;

#else /* !WIN32 */

static jmp_buf quant_end;
static long quant_quantum=0;
#endif

#ifdef WIN32
static void CALLBACK
quant_interrupt(UINT uID, UINT uMsg, DWORD dwUser, DWORD dw1,DWORD dw2)
{
	/* can't longjmp out of win interrupt handler, so
	   we use a pseudo semaphore */
	if (waiting)
		waiting=0;
} 

#else /* !WIN32 */

static void quant_interrupt()
{
	long nquantum;

	nquantum = quant_quantum;
	if (nquantum != 0)
		set_quant_interrupt(nquantum);
	else
		longjmp(quant_end, 1);
}
#endif

static set_quant_interrupt(microsecs)
     long microsecs;
{
#ifdef WIN32
	/* NOTE: this sets up a periodic timer, unlike the UNIX code which
	         sets up a one shot timer.	TIME_ONESHOT can be used to
			 get more UNIX-like behaviour */
	if ((theTimer=timeSetEvent(microsecs/1000, REZ, quant_interrupt,
				   0, TIME_PERIODIC))==(unsigned int)NULL)
		return -1;
	else 
		return 0;
#else /* !WIN32 */
	struct itimerval it, oit;
	
	timerclear(&it.it_interval);
	it.it_value.tv_sec = microsecs/1000000;
	it.it_value.tv_usec = microsecs%1000000;
	(void) signal(SIGVTALRM, quant_interrupt);
	return setitimer(ITIMER_VIRTUAL, &it, &oit);
#endif
}

#ifdef WIN32
/* determine timing resolution capabilities */
static int initTimeCaps()
{
	if (!inited) {
		/* get timer resolutions - once only */
		if (timeGetDevCaps(&timeCaps, sizeof(timeCaps))
		    ==TIMERR_NOERROR) {
			inited=1;
		}
		else 
			return -1;
	}
	return 0;
}
#endif

_TYPE(int) start_quantize(quantum)
     int quantum;	/* millisecs */
{
#ifdef WIN32
	/* check quantum range */
	if (initTimeCaps()==-1 || 
		quantum < (long)timeCaps.wPeriodMin || 
		quantum > (long)timeCaps.wPeriodMax)
		return -1;

	/* set time resolution */

	if (timeBeginPeriod(timeCaps.wPeriodMin)!=TIMERR_NOERROR)
		return -1;

	waiting=0;
#else /* !WIN32 */
	if (quantum <= 0)
		return -1;
#endif
	quant_quantum = (quantum * 1000) + 1; /* microsecs */
	return set_quant_interrupt(quant_quantum);
}

_TYPE(int) end_quantize()
{
#ifdef WIN32
	if (quant_quantum == 0)
		return -1; /* start_quantize never called */
	waiting=1;
	while(waiting)	                            
		;
	if (timeKillEvent(theTimer) !=TIMERR_NOERROR ||
		timeEndPeriod(timeCaps.wPeriodMin)!=TIMERR_NOERROR)
		return -1;
	else
		return 0;
#else /* !WIN32 */
	if (setjmp(quant_end))
		return 0;
	if (quant_quantum == 0)
		return -1; /* start_quantize never called */
	quant_quantum = 0; /* we return at next quantum */
	while (1)
		;

 	return -1; /* should never happen */
#endif
}

_TYPE(int) min_quantum()
{
#ifdef WIN32
	if (initTimeCaps()<0) {
		return -1;
	} else 
		return (timeCaps.wPeriodMin);
#else /* !WIN32 */
	return 10; /* arbitrary assumption - at least 10 msec
	                 quantum is available to UNIX */
#endif
}

#else /* NO_QUANTIZE */
#include <stdio.h>

_TYPE(int) start_quantize(quantum)
     int quantum;
{
	fprintf(stderr,"Warning: QUANTIZE not available\n");
	fflush(stderr);
	return -1;

}

_TYPE(int) end_quantize()
{
	return -1;
}

_TYPE(int) min_quantum()
{
	return -1;
}

#endif
