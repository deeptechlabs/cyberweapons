/*
 * This is version 1.2 of CryptoLib
 *
 * The authors of this software are Jack Lacy, Don Mitchell and Matt Blaze
 *              Copyright (c) 1991, 1992, 1993, 1994, 1995 by AT&T.
 * Permission to use, copy, and modify this software without fee
 * is hereby granted, provided that this entire notice is included in
 * all copies of any software which is or includes a copy or
 * modification of this software and in all copies of the supporting
 * documentation for such software.
 *
 * NOTE:
 * Some of the algorithms in cryptolib may be covered by patents.
 * It is the responsibility of the user to ensure that any required
 * licenses are obtained.
 *
 *
 * SOME PARTS OF CRYPTOLIB MAY BE RESTRICTED UNDER UNITED STATES EXPORT
 * REGULATIONS.
 *
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTY.  IN PARTICULAR, NEITHER THE AUTHORS NOR AT&T MAKE ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY
 * OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR PURPOSE.
 */
#include <wtypes.h>
#include <winbase.h>
#include <windef.h>
#include <winnt.h>
#include <winuser.h>
#include <process.h>
#include "libcrypt.h"

volatile unsigned long count, ocount, randbuf;
volatile int dontstop;
char outbuf[1024], *bufp;

static void counter() {
	while (dontstop)
		count++;
	_endthread();
}


static unsigned long roulette() {
	unsigned long thread;

	count = 0;
	dontstop= 1;
	while ((thread = _beginthread((void *)counter, 1024, NULL)) < 0)
		;

	Sleep(16);
	dontstop = 0;
	Sleep(1);

	count ^= (count>>3) ^ (count>>6) ^ (ocount);
	count &= 0x7;
	ocount = count;
	randbuf = (randbuf<<3) ^ count;
	return randbuf;
}


_TYPE( unsigned long ) truerand() {

	roulette();
	roulette();
	roulette();
	roulette();
	roulette();
	roulette();
	roulette();
	roulette();
	roulette();
	roulette();
	return roulette();
}

#ifdef RAND_DEBUG
int WINAPI WinMain(HINSTANCE hins, HINSTANCE hprevins, LPSTR cmdline, int cmdshow)
{
	int i, j;
	unsigned char randbuf[1024];
	FILE *fp;

#ifdef nodef
	bufp = outbuf;
	memset(outbuf, 0, 1024);
	for (i=0; i<25; i++)
		bufp += sprintf(bufp, "%08lx\n", truerand());
	MessageBox(NULL, outbuf, "TEST", MB_ABORTRETRYIGNORE);
	return 1;
#endif

	fp = fopen("/users/lacy/newrand.out","wb");
	
	for (i=0; i<1024; i++) {
		for (j=0; j<1024; j++) {
			randbuf[j] = (unsigned char)(truebyte() & 0xff);
		}
		fwrite(randbuf, 1, 1024, fp);
	}
	fclose(fp);

	return 1;
}
#endif
