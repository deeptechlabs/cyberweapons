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

#include "libcrypt.h"
#include <stdlib.h>
#ifdef DLLEXPORT
#include <windows.h>
#include <process.h>
#endif

#define CHARS 04
#define STDOUT stdout
#define STDERR stderr

/*extern void fprintf(FILE *, char *, ...);*/

#ifdef K_AND_R
_TYPE( void ) handle_exception(type, exception)
  ExceptionType type;
  char *exception;
#else
_TYPE( void ) handle_exception(ExceptionType type, char *exception)
#endif
{
#ifdef DLLEXPORT
	if (type == CRITICAL) {
		MessageBox((HWND)NULL, exception, "Critical", MB_OK);
		PostQuitMessage(1);
		
	}
	MessageBox((HWND)NULL, exception, "Not Critical", MB_OK);
	return;
	
#else
	if (type == CRITICAL) {
		(void) fprintf(STDERR, "CRITICAL EXCEPTION: %s exiting.\n", exception);
		exit(1);
	}
	else {
		(void) fprintf(STDERR, "WARNING: %s\n", exception);
		return;
	}
#endif
}

#ifdef K_AND_R
_TYPE( int )
bigsprint(big, buf)
  BigInt big;
  unsigned char *buf;
#else
_TYPE( int ) bigsprint(BigInt big,
		       unsigned char *buf)
#endif
{
	int i, len;
	unsigned char *bp = buf;

	len = 0;
	
	for (i=LENGTH(big)-1; i>=0; i--) {
		len += (int)sprintf((char *)bp, "%08lx", NUM(big)[i]);
		bp += 8;
	}
	*bp = '\0';
	return len;
}


#ifdef K_AND_R
_TYPE( void )
fBigPrint(a, fp)
  BigInt a;
  FILE *fp;
#else
_TYPE( void ) fBigPrint(BigInt a,
			FILE *fp)
#endif
{
	int i;
	
	if (SIGN(a) == NEG)
		(void) fprintf(fp, "-");
	
	(void) fprintf(fp, "%lx", NUM(a)[LENGTH(a)-1]);
	for (i = (int)(LENGTH(a) - 2); i >= 0; --i)
		(void) fprintf(fp, "%08lx", NUM(a)[i]);
	(void) fprintf(fp, "\n");
}

#if !defined(MSVC15)

#ifdef K_AND_R
_TYPE( void )
bigprint(a)
  BigInt a;
#else
_TYPE( void ) bigprint(BigInt a)
#endif
{
	fBigPrint(a, STDOUT);
}

#endif
