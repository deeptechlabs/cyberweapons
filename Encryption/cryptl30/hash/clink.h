/*
 * clink.h
 *
 * This software was written by Leonard Janke (janke@unixg.ubc.ca)
 * in 1996-7 and is entered, by him, into the public domain.
 */

#ifndef _CLINK_H
#define _CLINK_H

typedef unsigned long u32;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __WIN32__
void __cdecl RIPEMD128Transform(u32* H, const u32* X);
void __cdecl RIPEMD160Transform(u32* H, const u32* X);
#else
void RIPEMD128Transform(u32* H, const u32* X);
void RIPEMD160Transform(u32* H, const u32* X);
#endif /* __WIN32__ */

#ifdef __cplusplus
}
#endif

#endif
