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

/*
 *  These are the CryptoLib memory allocation interfaces.
 *  If a DLL is being built, DLLEXPORT should be defined
 *  and standard malloc is not used.
 *
 *  Jack Lacy  AT&T Bell Labs 1995
 */

#include "libcrypt.h"
#include <sys/types.h>

#define MEMCOPY(SRC, DST, LEN) memcpy(DST, SRC, (int)LEN)
#define MEMCMP(SRC, DST, LEN) memcmp(DST, SRC, (int)LEN)
#define MEMZERO(DST, LEN) memset(DST, 0, (int)LEN)

#ifdef DLLEXPORT
_TYPE( HGLOBAL )
clib_malloc(int size)
{
	return GlobalAlloc(GHND, (size_t)size);
}

_TYPE( HGLOBAL )
clib_realloc(HGLOBAL handle, int size)
{
	return GlobalReAlloc(handle, (size_t)size, GHND);
}

_TYPE( void )
clib_free(HGLOBAL handle)
{
	GlobalUnlock(handle);
	GlobalFree(handle);
}

#else

#ifdef K_AND_R
_TYPE( long * )
clib_malloc(size)
  int size;
#else
_TYPE( long * )
clib_malloc(int size)
#endif
{
	return (long *)malloc((size_t)size);
}

#ifdef K_AND_R
_TYPE( long * )
clib_realloc(buf, size)
  unsigned char *buf;
  int size;
#else
_TYPE( long * )
clib_realloc(unsigned char *buf, int size)
#endif
{
	return (long *)realloc(buf, (size_t)size);
}

#ifdef K_AND_R
_TYPE( void )
clib_free(buf)
  unsigned char *buf;
#else
_TYPE( void )
clib_free(unsigned char *buf)
#endif
{
	free((char *)buf);
}

#endif

#ifdef K_AND_R
_TYPE( void )
clib_memcpy(src, dst, length)
  unsigned char *src;
  unsigned char *dst;
  int length;
#else
_TYPE( void )
clib_memcpy(unsigned char *src, unsigned char *dst, int length)
#endif
{
	MEMCOPY(src, dst, length);
}

#ifdef K_AND_R
_TYPE( int )
clib_memcmp(src, dst, length)
  unsigned char *src;
  unsigned char *dst;
  int length;
#else
_TYPE( int )
clib_memcmp(unsigned char *src, unsigned char *dst, int length)
#endif
{
	return MEMCMP(src, dst, length);
}

#ifdef K_AND_R
_TYPE( void )
clib_memzero(dst, length)
  unsigned char *dst;
  int length;
#else
_TYPE( void )
clib_memzero(unsigned char *dst, int length)
#endif
{
	MEMZERO(dst, length);
}
